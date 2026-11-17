// Test-key witnesses: local secp256k1 keys stand in for Reclaim witnesses and
// sign provider claim data. Checks the zkFetch attestor accepts evidence signed
// by the witness address it pins, offline and deterministically, and rejects
// evidence from any other witness.

import { buildAttestor } from '@thoth/attestor';
import { type Claim, claimToMessage, type FlatMessage } from '@thoth/core/claim';
import {
  assertEvidenceMatchesPolicy,
  deriveClaimFromEvidence,
  parsedEvidenceView,
  ZK_FETCH_CLAIM_CONTEXT_KEY,
  type ZkFetchEvidence,
  type ZkFetchPolicy,
  zkFetchClaimContextDigestOf,
  zkFetchPolicyHashOf,
  zkFetchPolicySchema,
  zkFetchSubjectHashOf,
} from '@thoth/zk-tls';
import { createZkFetchDefinition, zkFetchAttestor } from '@thoth/zk-tls/attestor';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { disclosureRules } from './helpers/helper.js';
import { type Observation, type TestWitness, testWitness } from './helpers/witness.js';

/** The app id every claim in this suite is for. */
const APP_ID = new Uint8Array(32).fill(0xa1);

const alice = testWitness(`0x${'11'.repeat(32)}`);
const bob = testWitness(`0x${'22'.repeat(32)}`);

const policy: ZkFetchPolicy = {
  allowedHosts: ['api.example.com'],
  slots: [
    { slot: 0, name: 'balance', parse: 'int' },
    { slot: 1, name: 'score', parse: 'float', optional: true },
  ],
  bodyPolicy: 'ignored',
  ...disclosureRules('balance', 'score'),
};

/** The holder every claim in this suite is proposed with. */
const HOLDER = new Uint8Array(32).fill(0xc1);

/** The observation window every claim in this suite is proposed with. */
const WINDOW = { windowStart: 1_786_000_000n, windowEnd: 1_786_000_010n };

const PARAMETERS = {
  url: 'https://api.example.com/v1/account',
  method: 'GET',
  body: '',
  ...disclosureRules('balance', 'score'),
};

/**
 * The claim context digest a client signs for `activePolicy`, the request,
 * {@link HOLDER} and {@link WINDOW}.
 */
const digestOf = (
  parameters: Observation['parameters'] = PARAMETERS,
  activePolicy: ZkFetchPolicy = policy,
): string =>
  zkFetchClaimContextDigestOf({
    policy: activePolicy,
    request: {
      url: String(parameters.url),
      method: String(parameters.method),
      body: String(parameters.body),
    },
    holder: HOLDER,
    ...WINDOW,
  });

/** Sign an observation whose context carries {@link digestOf} its parameters. */
const observe = (
  witness: TestWitness,
  overrides: Partial<Observation> = {},
  activePolicy: ZkFetchPolicy = policy,
): Promise<ZkFetchEvidence> => {
  const parameters = overrides.parameters ?? PARAMETERS;
  return witness.sign({
    values: { balance: '0', score: '7.6' },
    timestampS: 1_786_000_000,
    parameters,
    context: {
      intent: 'ab'.repeat(32),
      [ZK_FETCH_CLAIM_CONTEXT_KEY]: digestOf(parameters, activePolicy),
    },
    ...overrides,
  });
};

const makeAttestor = (id: string, witnessAddress: string) =>
  zkFetchAttestor({
    id,
    keyPair: {
      publicKey: id,
      signer: { sign: (message: FlatMessage): string => `sig:${message.join(',')}` },
    },
    witnessAddress,
  });

const aliceAttestor = makeAttestor('attestor-alice', alice.address);
const bobAttestor = makeAttestor('attestor-bob', bob.address);

const attestWith = async (
  attestor: typeof aliceAttestor,
  evidence: ZkFetchEvidence,
  window: { windowStart: bigint; windowEnd: bigint } = WINDOW,
  claimOverrides: Partial<Claim<number>> = {},
  activePolicy: ZkFetchPolicy = policy,
) => {
  const derived = deriveClaimFromEvidence({
    verified: parsedEvidenceView(evidence),
    policy: activePolicy,
    appId: APP_ID,
    holder: HOLDER,
    valueSlots: 3,
    ...window,
  });
  const claim = { ...derived, ...claimOverrides };
  return attestor.attest({ policy: activePolicy, evidence, claim } as unknown as Parameters<
    typeof attestor.attest
  >[0]);
};

// Restore every spy even when its test fails, so one failure does not cascade.
afterEach(() => {
  vi.restoreAllMocks();
});

describe('test-key witness', () => {
  it('reuses one attestor and key across claim sizes and applications', async () => {
    const evidence = await observe(alice);
    for (const [size, appByte] of [
      [2, 0xa2],
      [5, 0xa5],
    ] as const) {
      const attestation = await attestWith(aliceAttestor, evidence, WINDOW, {
        appId: new Uint8Array(32).fill(appByte),
        present: [true, true, ...Array<boolean>(size - 2).fill(false)],
        values: [0n, 8n, ...Array<bigint>(size - 2).fill(0n)],
      });
      expect(attestation.publicKey).toBe('attestor-alice');
      expect(attestation.claim.appId).toEqual(new Uint8Array(32).fill(appByte));
      expect(attestation.claim.values).toHaveLength(size);
      expect(attestation.claim.values.slice(2)).toEqual(Array<bigint>(size - 2).fill(0n));
      expect(attestation.claim.present.slice(2)).toEqual(Array<boolean>(size - 2).fill(false));
      expect(attestation.signature).toBe(`sig:${attestation.message.join(',')}`);
      expect(attestation.message).toHaveLength(14 + 2 * size);
    }
  });

  it.each([
    { present: [true, true], values: [0n, 8n, 0n] },
    { present: [true, true, false], values: [0n, 8n] },
  ])('rejects unequal slot arrays before proof verification, case %#', async (claimOverrides) => {
    await expect(
      attestWith(
        aliceAttestor,
        { ...(await observe(alice)), signatureHex: '0x00' },
        WINDOW,
        claimOverrides,
      ),
    ).rejects.toThrow(/present must have one flag per value/);
  });

  it('rejects a policy slot outside the requested count before proof verification', async () => {
    await expect(
      attestWith(aliceAttestor, { ...(await observe(alice)), signatureHex: '0x00' }, WINDOW, {
        present: [true],
        values: [0n],
      }),
    ).rejects.toThrow(/policy slot 1 is out of the claim's 1 value slots/);
  });

  it('signs unused positions as absent and zero despite caller-supplied contents', async () => {
    const attestation = await attestWith(aliceAttestor, await observe(alice), WINDOW, {
      present: [true, true, true],
      values: [0n, 8n, 999n],
    });
    expect(attestation.claim.present).toEqual([true, true, false]);
    expect(attestation.claim.values).toEqual([0n, 8n, 0n]);
    expect(attestation.message.slice(13)).toEqual([0n, 1n, 1n, 0n, 0n, 8n, 0n]);
    expect(attestation.signature).toBe(`sig:${attestation.message.join(',')}`);
  });

  it.each([
    { present: [true, true, false], values: [999n, 8n, 0n] },
    { present: [false, true, false], values: [0n, 8n, 0n] },
  ])('rejects unsupported contents in measured positions, case %#', async (claimOverrides) => {
    await expect(
      attestWith(aliceAttestor, await observe(alice), WINDOW, claimOverrides),
    ).rejects.toThrow(/claim slot 0 does not match the disclosed value/);
  });

  it('derives the Ethereum address of its key', () => {
    // The well-known address of secp256k1 key 0x11…11.
    expect(alice.address).toBe('0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a');
    expect(bob.address).not.toBe(alice.address);
  });

  it('produces evidence carrying the chosen values, observation time, parameters and context', async () => {
    const evidence = await observe(alice, { timestampS: 1_786_000_123 });
    expect(evidence.attestorAddress).toBe(alice.address);
    expect(evidence.claim.timestampS).toBe(1_786_000_123);
    expect(JSON.parse(evidence.claim.parameters)).toMatchObject({
      url: 'https://api.example.com/v1/account',
      method: 'GET',
    });
    const context = JSON.parse(evidence.claim.context);
    expect(context.intent).toBe('ab'.repeat(32));
    expect(context.extractedParameters).toEqual({ balance: '0', score: '7.6' });
  });

  it('is deterministic across runs', async () => {
    // RFC 6979 signing: the same observation always yields this signature.
    expect((await observe(alice, { context: { intent: 'ab'.repeat(32) } })).signatureHex).toBe(
      '0xc17c840172f282180b663314f7db5a79e41b5950a7c69cab83c56bd46a76728145175c0909bc6bbf365e878b4eebc2c0525bd5601d52d79eb9c537e1530536211c',
    );
  });

  it('is accepted and signed by the attestor whose witness it is', async () => {
    const attestation = await attestWith(aliceAttestor, await observe(alice));
    expect(attestation.claim.windowStart).toBe(WINDOW.windowStart);
    expect(attestation.claim.windowEnd).toBe(WINDOW.windowEnd);
    expect(attestation.claim.appId).toEqual(APP_ID);
    expect(attestation.claim.policyHash).toEqual(zkFetchPolicyHashOf(policy));
    // A present zero stays present.
    expect(attestation.claim.present).toEqual([true, true, false]);
    expect(attestation.claim.values).toEqual([0n, 8n, 0n]);
    expect(attestation.signature).toMatch(/^sig:/);
  });

  it('signs the subject hash of the request its witness observed', async () => {
    const attestation = await attestWith(aliceAttestor, await observe(alice));
    expect(attestation.claim.subjectHash).toEqual(
      zkFetchSubjectHashOf({ method: 'GET', url: 'https://api.example.com/v1/account', body: '' }),
    );
  });

  it('rejects a proposal about another subject', async () => {
    const other = zkFetchSubjectHashOf({ method: 'GET', url: 'https://api.example.com/v1/other' });
    await expect(
      attestWith(aliceAttestor, await observe(alice), WINDOW, { subjectHash: other }),
    ).rejects.toThrow(/subjectHash does not match/);
  });

  it('rejects a proposal for another holder than the witness signed', async () => {
    const sign = vi.spyOn(aliceAttestor.signer, 'sign');
    await expect(
      attestWith(aliceAttestor, await observe(alice), WINDOW, {
        holder: new Uint8Array(32).fill(0xc2),
      }),
    ).rejects.toThrow(/claim context digest/);
    expect(sign).not.toHaveBeenCalled();
  });

  it('rejects a proposal for another window than the witness signed', async () => {
    // The observation still falls inside the swapped window.
    await expect(
      attestWith(aliceAttestor, await observe(alice), {
        windowStart: WINDOW.windowStart,
        windowEnd: WINDOW.windowEnd + 10n,
      }),
    ).rejects.toThrow(/claim context digest/);
  });

  it('signs the claim context digest the witness signed as the salt', async () => {
    const attestation = await attestWith(aliceAttestor, await observe(alice));
    expect(Buffer.from(attestation.claim.salt).toString('hex')).toBe(digestOf());
  });

  it('rejects a proposal with another salt than the witness signed', async () => {
    const sign = vi.spyOn(aliceAttestor.signer, 'sign');
    await expect(
      attestWith(aliceAttestor, await observe(alice), WINDOW, {
        salt: new Uint8Array(32).fill(0xee),
      }),
    ).rejects.toThrow(/salt/);
    expect(sign).not.toHaveBeenCalled();
  });

  it.each([
    ['an array it owns', () => HOLDER.slice()],
    [
      'an array over shared memory',
      () => {
        const holder = new Uint8Array(new SharedArrayBuffer(32));
        holder.set(HOLDER);
        return holder;
      },
    ],
  ])('signs the holder it checked when the caller changes %s after verify', async (_, holderOf) => {
    const holder = holderOf();
    const { verify } = aliceAttestor.definition;
    // Change the caller's holder after every check has passed, before the signature.
    vi.spyOn(aliceAttestor.definition, 'verify').mockImplementation(async (input) => {
      await verify(input);
      holder.fill(0xee);
    });
    const attestation = await attestWith(aliceAttestor, await observe(alice), WINDOW, { holder });
    expect(attestation.claim.holder).toEqual(HOLDER);
    expect(attestation.message).toEqual(claimToMessage(attestation.claim));
  });

  it('rejects evidence whose signed context carries no claim context digest', async () => {
    await expect(
      attestWith(aliceAttestor, await observe(alice, { context: { intent: 'ab'.repeat(32) } })),
    ).rejects.toThrow(/claim context digest/);
  });

  it('is rejected when signed by another witness', async () => {
    await expect(attestWith(aliceAttestor, await observe(bob))).rejects.toThrow(
      /not this attestor's witness/,
    );
  });

  it("rejects another witness's evidence in the definition's verify, before proof verification", async () => {
    const definition = createZkFetchDefinition({ witnessAddress: alice.address });
    const evidence = await observe(bob);
    const claim = deriveClaimFromEvidence({
      verified: parsedEvidenceView(evidence),
      policy,
      appId: APP_ID,
      holder: HOLDER,
      valueSlots: 3,
      ...WINDOW,
    });
    // A malformed signature would fail proof verification; the witness check must fire first.
    await expect(
      definition.verify({ policy, evidence: { ...evidence, signatureHex: '0x00' }, claim }),
    ).rejects.toThrow(/not this attestor's witness/);
    await expect(definition.verify({ policy, evidence, claim })).rejects.toThrow(
      /not this attestor's witness/,
    );
  });

  it('pins the witness when the definition is paired with buildAttestor', async () => {
    const attestor = buildAttestor({
      id: 'attestor-generic',
      definition: createZkFetchDefinition({
        witnessAddress: `0x${alice.address.slice(2).toUpperCase()}`,
      }),
      keyPair: { publicKey: 'attestor-generic', signer: { sign: () => 'sig' } },
      // The generic `attest` from the `@thoth/attestor` README: no witness check of its own.
      attest: async (definition, signer, input) => {
        const parsed = {
          policy: definition.policy.parse(input.policy),
          evidence: definition.evidence.parse(input.evidence),
          claim: definition.claim.parse(input.claim),
        };
        await definition.verify(parsed);
        const message = definition.message(parsed.claim);
        const signature = await signer.sign(message);
        return { claim: parsed.claim, message, publicKey: 'attestor-generic', signature };
      },
    });
    await expect(
      attestWith(attestor as unknown as typeof aliceAttestor, await observe(bob)),
    ).rejects.toThrow(/not this attestor's witness/);
    const attestation = await attestWith(
      attestor as unknown as typeof aliceAttestor,
      await observe(alice),
    );
    expect(attestation.publicKey).toBe('attestor-generic');
  });

  it.each(['alice', `0X${'ab'.repeat(20)}`, `0x${'ab'.repeat(19)}`])(
    'rejects the witness address %s',
    (witnessAddress) => {
      expect(() => createZkFetchDefinition({ witnessAddress })).toThrow(
        /witnessAddress must be 0x and 40 hex digits/,
      );
    },
  );

  it('rejects evidence whose disclosure rules differ from the policy', async () => {
    const distancePolicy = zkFetchPolicySchema.parse({
      allowedHosts: ['api.example.com'],
      slots: [{ slot: 0, name: 'distance', parse: 'float' }],
      bodyPolicy: 'ignored',
      responseMatches: [{ type: 'regex', value: '"distance":\\s*(?<distance>[\\d.]+)' }],
      responseRedactions: [{ regex: '"distance":\\s*[\\d.]+' }],
    }) as ZkFetchPolicy;
    // The witness signs a plan that captures another numeric field under the
    // policy's group name — the wrong-field substitution attack.
    const attack = await observe(alice, {
      values: { distance: '999' },
      parameters: {
        url: 'https://api.example.com/v1/account',
        method: 'GET',
        body: '',
        responseMatches: [{ type: 'regex', value: '"moving_time":\\s*(?<distance>[\\d.]+)' }],
        responseRedactions: [{ regex: '"moving_time":\\s*[\\d.]+' }],
      },
    });
    const sign = vi.spyOn(aliceAttestor.signer, 'sign');
    await expect(attestWith(aliceAttestor, attack, WINDOW, {}, distancePolicy)).rejects.toThrow(
      /disclosure rules/,
    );
    expect(sign).not.toHaveBeenCalled();
  });

  it('rejects evidence whose responseRedactions differ from the policy', async () => {
    const distancePolicy = zkFetchPolicySchema.parse({
      allowedHosts: ['api.example.com'],
      slots: [{ slot: 0, name: 'distance', parse: 'float' }],
      bodyPolicy: 'ignored',
      responseMatches: [{ type: 'regex', value: '"distance":\\s*(?<distance>[\\d.]+)' }],
      responseRedactions: [{ regex: '"distance":\\s*[\\d.]+' }],
    }) as ZkFetchPolicy;
    const divergent = await observe(alice, {
      values: { distance: '12.4' },
      parameters: {
        url: 'https://api.example.com/v1/account',
        method: 'GET',
        body: '',
        responseMatches: [{ type: 'regex', value: '"distance":\\s*(?<distance>[\\d.]+)' }],
        responseRedactions: [{ regex: '"moving_time":\\s*\\d+' }],
      },
    });
    await expect(attestWith(aliceAttestor, divergent, WINDOW, {}, distancePolicy)).rejects.toThrow(
      /disclosure rules/,
    );
  });

  it('accepts evidence whose disclosure rules are spelled differently', async () => {
    const distance = { type: 'regex', value: '"distance":\\s*(?<distance>[\\d.]+)' };
    const movingTime = { type: 'regex', value: '"moving_time":\\s*(?<movingTime>\\d+)' };
    const activePolicy: ZkFetchPolicy = {
      allowedHosts: ['api.example.com'],
      slots: [{ slot: 0, name: 'distance', parse: 'float' }],
      bodyPolicy: 'ignored',
      responseMatches: [distance, movingTime],
      responseRedactions: [{ regex: '"distance":\\s*[\\d.]+' }],
    };
    const evidence = await observe(
      alice,
      {
        values: { distance: '12.4' },
        parameters: {
          url: 'https://api.example.com/v1/account',
          method: 'GET',
          body: '',
          responseMatches: [movingTime, distance],
          responseRedactions: [{ jsonPath: '', xPath: '', regex: '"distance":\\s*[\\d.]+' }],
        },
      },
      activePolicy,
    );
    const attestation = await attestWith(aliceAttestor, evidence, WINDOW, {}, activePolicy);
    expect(attestation.claim.values[0]).toBe(12n);
  });

  it('accepts evidence whose rules are keyed the way Reclaim signs them', async () => {
    const distance = { value: '"distance":\\s*(?<distance>[\\d.]+)', type: 'regex' } as const;
    const movingTime = { value: '"moving_time"', type: 'contains' } as const;
    const redactions = [{ regex: '"distance":\\s*[\\d.]+', jsonPath: '' }, { jsonPath: '$.b' }];
    const activePolicy: ZkFetchPolicy = {
      allowedHosts: ['api.example.com'],
      slots: [{ slot: 0, name: 'distance', parse: 'float' }],
      bodyPolicy: 'ignored',
      responseMatches: [distance, movingTime],
      responseRedactions: redactions,
    };
    // The helper signs the parameters with sorted keys, as the witness does.
    const evidence = await observe(
      alice,
      {
        values: { distance: '12.4' },
        parameters: {
          url: 'https://api.example.com/v1/account',
          method: 'GET',
          body: '',
          responseMatches: [distance, movingTime],
          responseRedactions: redactions,
        },
      },
      activePolicy,
    );
    const attestation = await attestWith(aliceAttestor, evidence, WINDOW, {}, activePolicy);
    expect(attestation.claim.values[0]).toBe(12n);
  });

  it('accepts evidence that omits responseRedactions under a policy with none', async () => {
    const activePolicy: ZkFetchPolicy = {
      allowedHosts: ['api.example.com'],
      slots: [{ slot: 0, name: 'balance', parse: 'int' }],
      bodyPolicy: 'ignored',
      responseMatches: [{ type: 'regex', value: '(?<balance>.*)' }],
      responseRedactions: [],
    };
    const evidence = await observe(
      alice,
      {
        values: { balance: '7' },
        parameters: {
          url: 'https://api.example.com/v1/account',
          method: 'GET',
          body: '',
          responseMatches: [{ type: 'regex', value: '(?<balance>.*)' }],
        },
      },
      activePolicy,
    );
    const attestation = await attestWith(aliceAttestor, evidence, WINDOW, {}, activePolicy);
    expect(attestation.claim.values[0]).toBe(7n);
  });

  it('rejects evidence whose rules carry a field the policy cannot declare', async () => {
    const activePolicy: ZkFetchPolicy = {
      allowedHosts: ['api.example.com'],
      slots: [{ slot: 0, name: 'balance', parse: 'int' }],
      bodyPolicy: 'ignored',
      responseMatches: [{ type: 'regex', value: '(?<balance>.*)' }],
      responseRedactions: [],
    };
    const inverted = await observe(alice, {
      values: { balance: '7' },
      parameters: {
        url: 'https://api.example.com/v1/account',
        method: 'GET',
        body: '',
        responseMatches: [{ type: 'regex', value: '(?<balance>.*)', invert: true }],
        responseRedactions: [],
      },
    });
    await expect(attestWith(aliceAttestor, inverted, WINDOW, {}, activePolicy)).rejects.toThrow(
      /disclosure rules/,
    );
  });

  // A template, or a `{{` Reclaim reads as a wildcard, in each signed request field.
  it.each([
    { url: 'https://{{x}}.api.example.com/v1/account' },
    { url: 'https://{{x}}@api.example.com/v1/account' },
    { url: 'https://api.example.com/v1/%7B%7Bx%7D%7D' },
    { url: 'https://api.example.com/v1/{%7Bx}%7D' },
    { url: 'https://api.example.com/v1/%7B{x%7D}' },
    { url: 'https://api.example.com/v1/{\n{x}}' },
    { url: 'https://api.example.com/v1/{\t{x}}' },
    { url: 'https://api.example.com/v1/%7B\r%7Bx%7D%7D' },
    { url: 'https://api.example.com/v1/%\n7B%\n7Bx}}' },
    { url: 'https://api.example.com/v1/%7b%7bx%7d%7d' },
    { url: 'https://api.example.com/v1/{{}}' },
    { body: '{"user":"{{}}"}' },
    { body: '{"user":"{{x}}"}' },
    { geoLocation: '{{x}}' },
    { proxySessionId: '{{x}}' },
  ])('refuses a {{param}} template in the signed request, case %#', async (templated) => {
    const evidence = await observe(alice, {
      parameters: {
        url: 'https://api.example.com/v1/account',
        method: 'GET',
        body: '',
        ...disclosureRules('balance', 'score'),
        paramValues: { x: 'evil.example/' },
        ...templated,
      },
    });
    const sign = vi.spyOn(aliceAttestor.signer, 'sign');
    await expect(attestWith(aliceAttestor, evidence)).rejects.toThrow(/\{\{param\}\} templates/);
    expect(sign).not.toHaveBeenCalled();
  });

  // A `*` in the signed URL is a redaction marker the caller controls, so it leaves the sent
  // path or query byte unbound. `%2A` is the spelling Reclaim compares as literal bytes.
  it.each(['https://api.example.com/users/*/stats', 'https://api.example.com/v1/account?select=*'])(
    'refuses a starred signed request URL, case %#',
    async (url) => {
      const evidence = await observe(alice, { parameters: { ...PARAMETERS, url } });
      // The client runs this same check before contacting an attestor.
      expect(() => assertEvidenceMatchesPolicy(parsedEvidenceView(evidence), policy)).toThrow(
        /url cannot contain \*/,
      );
      const sign = vi.spyOn(aliceAttestor.signer, 'sign');
      await expect(attestWith(aliceAttestor, evidence)).rejects.toThrow(/url cannot contain \*/);
      expect(sign).not.toHaveBeenCalled();
    },
  );

  it('accepts a signed URL that spells a literal * as %2A', async () => {
    const url = 'https://api.example.com/users/%2A/stats';
    const evidence = await observe(alice, { parameters: { ...PARAMETERS, url } });
    expect(assertEvidenceMatchesPolicy(parsedEvidenceView(evidence), policy)).toBe(
      'api.example.com',
    );
    await expect(attestWith(aliceAttestor, evidence)).resolves.toBeDefined();
  });

  it('is rejected when the claim identifier does not match its signed content', async () => {
    const evidence = await observe(alice);
    const forged = {
      ...evidence,
      claim: { ...evidence.claim, identifier: `0x${'ab'.repeat(32)}` },
    };
    await expect(attestWith(aliceAttestor, forged)).rejects.toThrow(/identifier/);
  });

  it('is rejected when it claims another witness address', async () => {
    const forged = { ...(await observe(bob)), attestorAddress: alice.address };
    await expect(attestWith(aliceAttestor, forged)).rejects.toThrow(/Invalid claim signature/);
  });

  it('lets witnesses observing inside the window sign one message', async () => {
    const aliceAttestation = await attestWith(aliceAttestor, await observe(alice));
    const bobAttestation = await attestWith(
      bobAttestor,
      await observe(bob, { timestampS: 1_786_000_010 }),
    );
    expect(bobAttestation.message).toEqual(aliceAttestation.message);
  });

  it('rejects a window that starts after its own observation', async () => {
    await expect(
      attestWith(aliceAttestor, await observe(alice), {
        windowStart: 1_786_000_001n,
        windowEnd: 1_786_000_010n,
      }),
    ).rejects.toThrow(/outside the claim window/);
  });

  it('rejects a window that ends before its own observation', async () => {
    await expect(
      attestWith(bobAttestor, await observe(bob, { timestampS: 1_786_000_010 }), {
        windowStart: 1_786_000_000n,
        windowEnd: 1_786_000_009n,
      }),
    ).rejects.toThrow(/outside the claim window/);
  });

  it('derives one message whatever witness produced the observation', async () => {
    const aliceClaim = deriveClaimFromEvidence({
      verified: parsedEvidenceView(await observe(alice)),
      policy,
      appId: APP_ID,
      holder: HOLDER,
      valueSlots: 3,
      ...WINDOW,
    });
    const bobClaim = deriveClaimFromEvidence({
      verified: parsedEvidenceView(await observe(bob)),
      policy,
      appId: APP_ID,
      holder: HOLDER,
      valueSlots: 3,
      ...WINDOW,
    });
    expect(claimToMessage(bobClaim)).toEqual(claimToMessage(aliceClaim));
  });

  it('derives the same claim when only the signed context changes', async () => {
    const deriveClaim = async (overrides: Partial<Observation> = {}) =>
      deriveClaimFromEvidence({
        verified: parsedEvidenceView(await observe(alice, overrides)),
        policy,
        appId: APP_ID,
        holder: HOLDER,
        valueSlots: 3,
        ...WINDOW,
      });
    const context = { intent: 'cd'.repeat(32), [ZK_FETCH_CLAIM_CONTEXT_KEY]: digestOf() };
    expect(claimToMessage(await deriveClaim({ context }))).toEqual(
      claimToMessage(await deriveClaim()),
    );
  });
});
