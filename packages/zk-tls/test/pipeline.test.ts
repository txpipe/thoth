// End-to-end tests over the package's shipped entry points (`@thoth/zk-tls/attestor`
// and `@thoth/zk-tls/client`): verify a real witnessed Reclaim proof, derive and
// collect a threshold attestation from agreeing operators, and assert the
// kind's rejection paths.
//
// Signature verification uses `examples/demo-attestation/fixtures/` — a
// genuine, offline-verifiable HTTPS fetch witnessed by a Reclaim witness. The
// client flow fakes each operator's witness at the prover interface with a
// test key, since it must sign the intent-bound context the client builds.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Attestor, KeyPair } from '@thoth/attestor';
import { descriptorOf } from '@thoth/attestor';
import type { AttestorTransport, SignatureVerifier, TrustedSet } from '@thoth/client';
import { buildTrustedSet } from '@thoth/client';
import type { FlatMessage } from '@thoth/core/claim';
import { claimToMessage } from '@thoth/core/claim';
import {
  INTENT_CONTEXT_KEY,
  intentDigestOf,
  intentOf,
  type ZkFetchDefinition,
  type ZkFetchPolicy,
  zkFetchClaimSchema,
  zkFetchEvidenceSchema,
} from '@thoth/zk-tls';
import { verifyZkFetchProof, zkFetchAttestor } from '@thoth/zk-tls/attestor';
import {
  addressFromWitnessId,
  toCanonicalEvidence,
  type ZkFetchProver,
  zkFetchClient,
} from '@thoth/zk-tls/client';
import { describe, expect, it } from 'vitest';
import { type TestWitness, testWitness } from './helpers/witness.js';

const THIS_DIR = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = join(
  THIS_DIR,
  '..',
  '..',
  '..',
  'examples',
  'demo-attestation',
  'fixtures',
  'fixture-github-attestor-core-x-0m.json',
);
const fixture = JSON.parse(readFileSync(FIXTURE_PATH, 'utf-8')) as Record<string, unknown>;

const w0 = testWitness(`0x${'11'.repeat(32)}`);
const w1 = testWitness(`0x${'22'.repeat(32)}`);
const OBSERVED_AT = 1_786_000_000;
const INTENT = {
  holder: new Uint8Array(32).fill(0xaa),
  windowStart: BigInt(OBSERVED_AT - 60),
  windowEnd: BigInt(OBSERVED_AT + 60),
};

const policy = (
  slots: ZkFetchPolicy['slots'] = [{ slot: 0, name: 'stars', parse: 'int', optional: true }],
): ZkFetchPolicy => ({
  allowedHosts: ['api.github.com'],
  maxWindowSeconds: 120,
  slots,
});

/**
 * A prover backed by a test witness: it signs the request it is handed
 * (including the intent-bound context), observing `values` at `url`.
 */
const witnessProver = (
  witness: TestWitness,
  values: Record<string, string> = { stars: '0' },
  url?: string,
): ZkFetchProver => ({
  prove: (request) =>
    witness.sign({
      values,
      timestampS: OBSERVED_AT,
      parameters: {
        url: url ?? request.url,
        method: request.method ?? 'GET',
        body: request.body ?? '',
      },
      context: request.context,
    }),
});

type FakePublicKey = { id: string };
type FakeSignature = string;

const fakeSign = (id: string, message: FlatMessage): FakeSignature => `sig:${id}:${message.join()}`;

const fakeKey = (id: string): KeyPair<FakePublicKey, FakeSignature, FlatMessage> => ({
  publicKey: { id },
  signer: { sign: (message: FlatMessage): FakeSignature => fakeSign(id, message) },
});

const fakeVerifier: SignatureVerifier<FakePublicKey, FakeSignature> = {
  verify: (publicKey, message, signature) => signature === fakeSign(publicKey.id, message),
};

/** Serialize a payload for substring checks: bigints and bytes become strings. */
const dump = (value: unknown): string =>
  JSON.stringify(value, (_key, v: unknown) =>
    typeof v === 'bigint' ? v.toString() : v instanceof Uint8Array ? Buffer.from(v).toString() : v,
  );

describe('addressFromWitnessId', () => {
  it('decodes a plain 40-hex witness id', () => {
    expect(addressFromWitnessId('c340fc267cacbb9e3101adced0c7728f7e63b63d')).toBe(
      '0xc340fc267cacbb9e3101adced0c7728f7e63b63d',
    );
  });

  it('decodes a hex-encoded utf-8 address witness id', () => {
    const encoded = Buffer.from('0xc340fc267cacbb9e3101adced0c7728f7e63b63d').toString('hex');
    expect(addressFromWitnessId(encoded)).toBe('0xc340fc267cacbb9e3101adced0c7728f7e63b63d');
  });

  it('rejects an undecodable witness id', () => {
    expect(() => addressFromWitnessId('nope')).toThrow(/cannot decode/);
  });
});

describe('toCanonicalEvidence', () => {
  it('shapes a raw transformProof shell into canonical evidence', () => {
    const evidence = toCanonicalEvidence({
      claimData: fixture.claim as never,
      identifier: '0xabc',
      signatures: [`0x2a${'00'.repeat(64)}`],
      witnesses: [{ id: 'c340fc267cacbb9e3101adced0c7728f7e63b63d', url: 'wss://x' }],
      responseText: 'HTTP/1.1 200 OK',
    });
    expect(evidence.attestorAddress).toBe('0xc340fc267cacbb9e3101adced0c7728f7e63b63d');
    expect(evidence.signatureHex).toBe(`0x2a${'00'.repeat(64)}`);
    expect(evidence.responseText).toBe('HTTP/1.1 200 OK');
  });

  it('throws when the raw proof carries no signature or witness', () => {
    expect(() =>
      toCanonicalEvidence({
        claimData: fixture.claim as never,
        identifier: '0xabc',
        signatures: [],
        witnesses: [],
      }),
    ).toThrow(/no signature or witness/);
  });
});

describe('verifyZkFetchProof', () => {
  it('re-verifies a genuine witnessed proof offline', async () => {
    const evidence = zkFetchEvidenceSchema.parse(fixture);
    const verified = await verifyZkFetchProof(evidence);
    expect(verified.identifier).toBe(evidence.claim.identifier);
    expect(verified.disclosedValues).toHaveProperty('data');
  });

  it('rejects an invalid signature', async () => {
    const evidence = zkFetchEvidenceSchema.parse(fixture);
    const tampered = { ...evidence, signatureHex: `0x${'00'.repeat(65)}` };
    await expect(verifyZkFetchProof(tampered)).rejects.toThrow();
  });
});

describe('zkFetch claim schema', () => {
  it('parses a derived claim into bigint values', () => {
    const claim = zkFetchClaimSchema.parse({
      version: 1,
      kind: 1,
      policyDigest: new Uint8Array(32),
      requestBinding: new Uint8Array(32),
      holder: new Uint8Array(32),
      nonce: new Uint8Array(32),
      windowStart: 1_786_122_944,
      windowEnd: 1_786_123_000,
      present: [true, false],
      values: [12, 0],
    });
    expect(claim.values).toEqual([12n, 0n]);
    expect(claim.present).toEqual([true, false]);
    expect(claim.windowEnd).toBe(1_786_123_000n);
  });

  it('rejects a 32-byte field of the wrong length', () => {
    expect(() =>
      zkFetchClaimSchema.parse({
        version: 1,
        kind: 1,
        policyDigest: new Uint8Array(31),
        requestBinding: new Uint8Array(32),
        holder: new Uint8Array(32),
        nonce: new Uint8Array(32),
        windowStart: 0,
        windowEnd: 0,
        present: [],
        values: [],
      }),
    ).toThrow(/32 bytes/);
  });

  it('rejects a window outside the circuit Uint<32> range', () => {
    expect(() =>
      zkFetchClaimSchema.parse({
        version: 1,
        kind: 1,
        policyDigest: new Uint8Array(32),
        requestBinding: new Uint8Array(32),
        holder: new Uint8Array(32),
        nonce: new Uint8Array(32),
        windowStart: 0,
        windowEnd: 2n ** 32n,
        present: [],
        values: [],
      }),
    ).toThrow(/Uint<32>/);
  });
});

/** Await a rejected attest call and return its per-operator errors as strings. */
const reasons = async (attempt: Promise<unknown>): Promise<string[]> => {
  const error = await attempt.then(
    () => {
      throw new Error('expected the attest call to reject');
    },
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(AggregateError);
  expect(String(error)).toMatch(/threshold of 2 not met/);
  return (error as AggregateError).errors.map(String);
};

describe('zkFetch attestor + client', () => {
  const attestors = ['attestor-0', 'attestor-1', 'attestor-2'].map((id, i) =>
    zkFetchAttestor({
      id,
      keyPair: fakeKey(id),
      registryIndex: i,
      witnessAddress: (i === 1 ? w1 : w0).address,
    }),
  );
  const byId = new Map(attestors.map((a) => [a.id, a]));
  const trusted = buildTrustedSet(attestors.map(descriptorOf));

  type Tamper = (id: string, attestation: FakeAttestation) => FakeAttestation;
  type FakeAttestation = Awaited<
    ReturnType<Attestor<ZkFetchDefinition, FakePublicKey, FakeSignature>['attest']>
  >;

  /** An in-process transport; records every payload and can delay or tamper. */
  const transportOf = (
    options: { delays?: Record<string, number>; tamper?: Tamper } = {},
  ): AttestorTransport<ZkFetchDefinition, FakePublicKey, FakeSignature> & {
    sent: unknown[];
  } => {
    const sent: unknown[] = [];
    return {
      sent,
      async request(attestor, input) {
        sent.push(input);
        const instance = byId.get(attestor.id);
        if (!instance) {
          throw new Error(`transport: unknown attestor ${attestor.id}`);
        }
        await new Promise((resolve) => setTimeout(resolve, options.delays?.[attestor.id] ?? 0));
        const attestation = await instance.attest(
          input as Parameters<
            Attestor<ZkFetchDefinition, FakePublicKey, FakeSignature>['attest']
          >[0],
        );
        return options.tamper ? options.tamper(attestor.id, attestation) : attestation;
      },
    };
  };

  const operators = (
    values: [Record<string, string>, Record<string, string>] = [{ stars: '0' }, { stars: '0' }],
  ) => ({
    'attestor-0': {
      prover: witnessProver(w0, values[0]),
      witnessAddress: w0.address,
    },
    'attestor-1': {
      prover: witnessProver(w1, values[1]),
      witnessAddress: w1.address,
    },
  });

  const clientOf = (
    overrides: Partial<
      Parameters<typeof zkFetchClient.init<3, FakePublicKey, FakeSignature>>[0]
    > = {},
  ) =>
    zkFetchClient.init({
      trusted,
      transport: transportOf(),
      policy: policy(),
      valueSlots: 3,
      threshold: 2,
      verifier: fakeVerifier,
      operators: operators(),
      ...overrides,
    });

  const REQUEST = { url: 'https://api.github.com/repos/x', method: 'GET' } as const;

  it('returns a threshold attestation from two agreeing witnesses', async () => {
    const { claim, message, collected } = await clientOf({
      operators: operators([{ stars: '42' }, { stars: '42' }]),
    }).attest(REQUEST, INTENT);
    expect(claim).toMatchObject({ holder: INTENT.holder, present: [true, false, false] });
    expect(claim.values).toEqual([42n, 0n, 0n]);
    expect(message).toEqual(claimToMessage(claim));
    expect(message).toHaveLength(14);
    expect(collected.map((c) => c.registryIndex)).toEqual([0, 1]);
    for (const c of collected) {
      expect(c.attestation.message).toEqual(message);
    }
  });

  it('binds both witnessed sessions to one fresh intent', async () => {
    const contexts: Record<string, unknown>[] = [];
    const recording = (witness: TestWitness): ZkFetchProver => ({
      prove: (request) => {
        contexts.push({ ...request.context });
        return witnessProver(witness).prove(request);
      },
    });
    const client = clientOf({
      operators: {
        'attestor-0': { prover: recording(w0), witnessAddress: w0.address },
        'attestor-1': { prover: recording(w1), witnessAddress: w1.address },
      },
    });
    const first = await client.attest(REQUEST, INTENT);
    const second = await client.attest(REQUEST, INTENT);
    expect(contexts[0]?.[INTENT_CONTEXT_KEY]).toBe(intentDigestOf(intentOf(first.claim)));
    expect(contexts[1]?.[INTENT_CONTEXT_KEY]).toBe(contexts[0]?.[INTENT_CONTEXT_KEY]);
    expect(first.claim.nonce).not.toEqual(second.claim.nonce);
  });

  it('orders signatures by registry slot whatever order responses arrive in', async () => {
    const { collected } = await clientOf({
      transport: transportOf({ delays: { 'attestor-0': 30 } }),
      operators: {
        'attestor-1': operators()['attestor-1'],
        'attestor-0': operators()['attestor-0'],
      },
    }).attest(REQUEST, INTENT);
    expect(collected.map((c) => c.registryIndex)).toEqual([0, 1]);
  });

  it('never counts an invalid signature toward the threshold', async () => {
    const client = clientOf({
      transport: transportOf({
        tamper: (id, attestation) =>
          id === 'attestor-1' ? { ...attestation, signature: 'forged' } : attestation,
      }),
    });
    expect(await reasons(client.attest(REQUEST, INTENT))).toEqual([
      expect.stringMatching(/attestor-1.*did not return a valid attestation/),
    ]);
  });

  it('counts two responses from the same registry slot once', async () => {
    const [first, second] = attestors.map(descriptorOf);
    if (first === undefined || second === undefined) {
      throw new Error('fixture: expected two attestors');
    }
    const shared: TrustedSet<ZkFetchDefinition, FakePublicKey> = {
      attestors: [first, { ...second, registryIndex: first.registryIndex }],
    };
    // Both attestors answer validly; the shared slot alone keeps the count at 1.
    expect(await reasons(clientOf({ trusted: shared }).attest(REQUEST, INTENT))).toEqual([]);
  });

  it('never combines signatures over different messages', async () => {
    const client = clientOf({ operators: operators([{ stars: '42' }, { stars: '7' }]) });
    // Both attestors answer validly, each over its own witness's reading.
    expect(await reasons(client.attest(REQUEST, INTENT))).toEqual([]);
  });

  it('sends no secret header to a signer or into an error', async () => {
    const SECRET = 'Bearer top-secret-token';
    const transport = transportOf({
      tamper: (id, attestation) =>
        id === 'attestor-1' ? { ...attestation, signature: 'forged' } : attestation,
    });
    const error = await clientOf({ transport })
      .attest({ ...REQUEST, secretHeaders: { authorization: SECRET } }, INTENT)
      .catch((e: unknown) => e);
    expect(transport.sent).toHaveLength(2);
    expect(dump(transport.sent)).not.toContain(SECRET);
    expect(error).toBeInstanceOf(Error);
    expect(
      dump({ error: String(error), errors: (error as AggregateError).errors?.map(String) }),
    ).not.toContain(SECRET);
  });

  it('does not expose a secret from a prover exception', async () => {
    const secret = 'Bearer hidden-token';
    const leaking: ZkFetchProver = {
      prove: () => Promise.reject(new Error('token=hidden-token')),
    };
    const error = await clientOf({
      operators: { ...operators(), 'attestor-0': { prover: leaking, witnessAddress: w0.address } },
    })
      .attest({ ...REQUEST, secretHeaders: { authorization: secret } }, INTENT)
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AggregateError);
    expect(
      dump({ error: String(error), errors: (error as AggregateError).errors?.map(String) }),
    ).not.toContain('hidden-token');
  });

  it('refuses evidence from a witness other than the pinned one', async () => {
    const client = clientOf({
      operators: {
        ...operators(),
        'attestor-1': {
          prover: witnessProver(w0),
          witnessAddress: w1.address,
        },
      },
    });
    expect(await reasons(client.attest(REQUEST, INTENT))).toEqual([
      expect.stringMatching(/did not return a valid attestation/),
    ]);
  });

  it('refuses an operator outside the trusted set at init', () => {
    expect(() =>
      clientOf({ operators: { ...operators(), ghost: operators()['attestor-0'] } }),
    ).toThrow(/not in the trusted set/);
  });

  it('refuses a threshold the operators cannot meet at init', () => {
    expect(() => clientOf({ threshold: 3 })).toThrow(/threshold 3/);
  });

  it('refuses when the policy does not fit the evidence (host)', async () => {
    const hostile = clientOf({ policy: { ...policy(), allowedHosts: ['evil.example'] } });
    expect(await reasons(hostile.attest(REQUEST, INTENT))).toEqual([
      expect.stringMatching(/did not return a valid attestation/),
      expect.stringMatching(/did not return a valid attestation/),
    ]);
  });

  it('refuses evidence for a different origin than requested', async () => {
    const client = clientOf({
      operators: {
        ...operators(),
        'attestor-1': {
          prover: witnessProver(w1, undefined, 'https://other.example/x'),
          witnessAddress: w1.address,
        },
      },
    });
    expect(await reasons(client.attest(REQUEST, INTENT))).toEqual([
      expect.stringMatching(/did not return a valid attestation/),
    ]);
  });

  it('refuses evidence observed outside the intent window', async () => {
    const late = clientOf().attest(REQUEST, {
      ...INTENT,
      windowStart: BigInt(OBSERVED_AT + 1),
      windowEnd: BigInt(OBSERVED_AT + 60),
    });
    expect(await reasons(late)).toEqual([
      expect.stringMatching(/did not return a valid attestation/),
      expect.stringMatching(/did not return a valid attestation/),
    ]);
  });

  it('refuses a policy slot beyond the claim length at init', () => {
    expect(() =>
      clientOf({ policy: policy([{ slot: 5, name: 'stars', parse: 'int', optional: true }]) }),
    ).toThrow(/out of the claim's 3 value slots/);
  });

  it('signs a derived claim and attests only what was disclosed', async () => {
    const { claim } = await clientOf({ operators: operators([{}, {}]) }).attest(REQUEST, INTENT);
    expect(claim.values).toEqual([0n, 0n, 0n]);
    expect(claim.present).toEqual([false, false, false]);
  });
});
