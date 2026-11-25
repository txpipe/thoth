// End-to-end tests over the package's shipped entry points (`@txpipe/thoth-zk-tls/attestor`
// and `@txpipe/thoth-zk-tls/client`): verify a real witnessed Reclaim proof, derive and
// collect the N-of-M attestation set, and assert the kind's rejection paths.
//
// Uses `examples/demo-attestation/fixtures/` — a genuine, offline-verifiable
// HTTPS fetch witnessed by a Reclaim witness (no network needed).
import type { AttestorTransport } from '@txpipe/thoth-client';
import { buildTrustedSet } from '@txpipe/thoth-client';
import type { FlatMessage } from '@txpipe/thoth-core/claim';
import { claimToMessage } from '@txpipe/thoth-core/claim';
import { filled, padded32 } from '@txpipe/thoth-test-utils/bytes';
import {
  collectedSlots,
  type FakePublicKey,
  type FakeSignature,
  fakeKeyPair,
  fakeVerifier,
  inMemoryTransport,
  trustedSetOf,
} from '@txpipe/thoth-test-utils/harness';
import { disclosureRules } from '@txpipe/thoth-test-utils/zk-fetch';
import {
  assertEvidenceMatchesPolicy,
  parsedEvidenceView,
  ZK_FETCH_CLAIM_CONTEXT_KEY,
  type ZkFetchDefinition,
  type ZkFetchEvidence,
  type ZkFetchPolicy,
  zkFetchBodyHashOf,
  zkFetchClaimContextDigestOf,
  zkFetchClaimSchema,
  zkFetchEvidenceSchema,
  zkFetchPolicyHashOf,
  zkFetchSubjectHashOf,
} from '@txpipe/thoth-zk-tls';
import { verifyZkFetchProof, zkFetchAttestor } from '@txpipe/thoth-zk-tls/attestor';
import {
  addressFromWitnessId,
  EvidenceTooDeepError,
  SecretHeaderError,
  toCanonicalEvidence,
  type ZkFetchAttestorFailure,
  type ZkFetchProver,
  ZkFetchProverError,
  type ZkFetchRequest,
  ZkFetchThresholdError,
  zkFetchClient,
} from '@txpipe/thoth-zk-tls/client';
import { describe, expect, it, vi } from 'vitest';
import { ZodError } from 'zod';
import {
  APP_ID,
  countingTransport,
  DEFAULT_TIMESTAMP_S,
  FIXTURE,
  HOLDER,
  policyWithSlots,
  sampleClaimInput,
} from './helpers/helper.js';
import { type TestWitness, testWitness } from './helpers/witness.js';

const fixture = FIXTURE;

const policy = (
  slots: ZkFetchPolicy['slots'] = [{ slot: 0, name: 'data', parse: 'float', optional: true }],
): ZkFetchPolicy => policyWithSlots(slots);

const verifier = fakeVerifier();

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
  it('leaves non-canonical evidence unchanged when verifying it', async () => {
    const evidence = zkFetchEvidenceSchema.parse(fixture);
    evidence.claim.context = JSON.stringify(JSON.parse(evidence.claim.context), null, 2);
    const original = structuredClone(evidence);
    const before = parsedEvidenceView(evidence);

    const verified = await verifyZkFetchProof(evidence);

    expect(evidence).toEqual(original);
    expect(verified).toEqual(before);
    expect(await verifyZkFetchProof(evidence)).toEqual(before);
  });

  it('re-verifies a genuine witnessed proof offline', async () => {
    const evidence = zkFetchEvidenceSchema.parse(fixture);
    const verified = await verifyZkFetchProof(evidence);
    expect(verified.claim.identifier).toBe(evidence.claim.identifier);
    expect(verified.disclosedValues).toHaveProperty('data');
  });

  it('rejects an invalid signature', async () => {
    const evidence = zkFetchEvidenceSchema.parse(fixture);
    const tampered = { ...evidence, signatureHex: `0x${'00'.repeat(65)}` };
    await expect(verifyZkFetchProof(tampered)).rejects.toThrow();
  });
});

describe('assertEvidenceMatchesPolicy over the recorded fixture', () => {
  it('accepts the genuine Reclaim evidence under the policy disclosure rules', () => {
    const evidence = zkFetchEvidenceSchema.parse(fixture);
    expect(assertEvidenceMatchesPolicy(parsedEvidenceView(evidence), policy())).toBe(
      'api.github.com',
    );
  });
});

describe('zkFetch claim schema', () => {
  it('rejects an appId, policyHash subjectHash, holder or salt that is not 32 bytes', () => {
    const claim = sampleClaimInput({ present: [true], values: [12] });
    expect(() => zkFetchClaimSchema.parse({ ...claim, appId: new Uint8Array(31) })).toThrow(
      /expected 32 bytes/,
    );
    expect(() => zkFetchClaimSchema.parse({ ...claim, policyHash: new Uint8Array(33) })).toThrow(
      /expected 32 bytes/,
    );
    expect(() => zkFetchClaimSchema.parse({ ...claim, holder: new Uint8Array(31) })).toThrow(
      /expected 32 bytes/,
    );
    expect(() => zkFetchClaimSchema.parse({ ...claim, salt: new Uint8Array(31) })).toThrow(
      /expected 32 bytes/,
    );
    expect(() => zkFetchClaimSchema.parse({ ...claim, subjectHash: new Uint8Array(16) })).toThrow(
      /expected 32 bytes/,
    );
  });

  it('parses a derived claim into bigint values', () => {
    const claim = zkFetchClaimSchema.parse(
      sampleClaimInput({ present: [true, false], values: [12, 0] }),
    );
    expect(claim.values).toEqual([12n, 0n]);
    expect(claim.present).toEqual([true, false]);
  });
});

describe('zkFetch attestor + client', () => {
  const aliceWitness = testWitness(`0x${'33'.repeat(32)}`);
  const bobWitness = testWitness(`0x${'44'.repeat(32)}`);
  const carolWitness = testWitness(`0x${'55'.repeat(32)}`);
  const witnessById: Record<string, TestWitness> = {
    'attestor-0': aliceWitness,
    'attestor-1': bobWitness,
    'attestor-2': carolWitness,
  };
  const ids = Object.keys(witnessById);

  const attestors = Object.entries(witnessById).map(([id, witness]) =>
    zkFetchAttestor({
      id,
      keyPair: fakeKeyPair(id),
      witnessAddress: witness.address,
    }),
  );
  // The app assigns each attestor its registry slot; here `attestor-i` sits at slot `i`.
  const trustedWith = (slots: readonly number[], registrySize = 3) =>
    trustedSetOf(buildTrustedSet, attestors, { registrySize, slots });
  const trusted = trustedWith([0, 1, 2]);
  const transport: AttestorTransport<ZkFetchDefinition, FakePublicKey, FakeSignature> =
    inMemoryTransport(attestors);

  const BASE_TIMESTAMP_S = DEFAULT_TIMESTAMP_S;

  // Each witness signs the request it receives, the caller's context included;
  // values mirror the old fixture's unparseable `data`, so the `data` slot
  // stays unpresent.
  const observe = (
    witness: TestWitness,
    request: ZkFetchRequest,
    overrides: {
      url?: string;
      timestampS?: number;
      values?: Readonly<Record<string, string>>;
    } = {},
  ) =>
    witness.sign({
      values: overrides.values ?? { data: 'HTTP/1.1 200 OK' },
      timestampS: overrides.timestampS ?? BASE_TIMESTAMP_S,
      parameters: {
        url: overrides.url ?? request.url,
        method: request.method ?? 'GET',
        body: request.body ?? '',
        // The client binds the policy's rules to the request it proves.
        responseMatches: request.responseMatches ?? disclosureRules('data').responseMatches,
        responseRedactions: request.responseRedactions ?? [],
      },
      context: request.context,
    });

  const proversWith = (
    overrides: {
      url?: () => string;
      timestampS?: (id: string) => number | undefined;
      values?: (id: string) => Readonly<Record<string, string>> | undefined;
      onProve?: (id: string, request: ZkFetchRequest) => void;
    } = {},
  ): Record<string, ZkFetchProver> =>
    Object.fromEntries(
      Object.entries(witnessById).map(([id, witness]) => [
        id,
        {
          prove: (request: ZkFetchRequest) => {
            overrides.onProve?.(id, request);
            return observe(witness, request, {
              url: overrides.url?.(),
              timestampS: overrides.timestampS?.(id),
              values: overrides.values?.(id),
            });
          },
        } satisfies ZkFetchProver,
      ]),
    );

  const provers = proversWith();

  const clientWith = (
    overrides: {
      policy?: ZkFetchPolicy;
      transport?: AttestorTransport<ZkFetchDefinition, FakePublicKey, FakeSignature>;
      provers?: Record<string, ZkFetchProver>;
      appId?: Uint8Array;
      trusted?: typeof trusted;
      byteSlots?: number;
    } = {},
  ) =>
    zkFetchClient.init({
      trusted: overrides.trusted ?? trusted,
      verifier,
      transport: overrides.transport ?? transport,
      policy: overrides.policy ?? policy(),
      appId: overrides.appId ?? APP_ID,
      valueSlots: 3,
      byteSlots: overrides.byteSlots ?? 0,
      provers: overrides.provers ?? provers,
    });

  /** The holder and window a claim is proved for. */
  const binding = (holder = HOLDER) => ({
    holder,
    windowStart: BigInt(BASE_TIMESTAMP_S),
    windowEnd: BigInt(BASE_TIMESTAMP_S + 60),
  });
  const options = () => ({
    ...binding(),
    expiresAt: Date.now() + 60_000,
    threshold: 2,
    attestorTimeoutMs: 5_000,
  });
  const collectionRequest = { url: 'https://api.github.com/repos/x', method: 'GET' as const };
  const hanging = <T>(): Promise<T> => new Promise<T>(() => {});

  describe("the 'bytes' slot through the client", () => {
    // The shared disclosure rules expose one extracted value (`data`); the
    // byte slot consumes it. V = 3 numeric slots, then one byte value at 3.
    const bytePolicy = (optional = false): ZkFetchPolicy =>
      policy([{ slot: 3, name: 'data', parse: 'bytes', optional }]);

    const withData = (value: string | undefined, optional = false) =>
      clientWith({
        policy: bytePolicy(optional),
        byteSlots: 1,
        provers: proversWith({
          values: (): Readonly<Record<string, string>> =>
            value === undefined ? {} : { data: value },
        }),
      });

    it('derives the same byte value across attestors and collects a threshold', async () => {
      const { claim, collected } = await withData('abc').collect(collectionRequest, options());
      expect(collected).toHaveLength(2);
      expect(claim.present).toEqual([false, false, false, true]);
      expect(claim.byteValues[0]).toEqual(padded32('abc'));
    });

    it('derives distinct byte values for distinct identifiers', async () => {
      const a = await withData('abc').collect(collectionRequest, options());
      const b = await withData('xyz').collect(collectionRequest, options());
      expect(a.claim.byteValues[0]).not.toEqual(b.claim.byteValues[0]);
    });

    it('rejects an over-long identifier for a required byte slot', async () => {
      await expect(withData('a'.repeat(33)).collect(collectionRequest, options())).rejects.toThrow(
        /threshold not reached/,
      );
    });

    it('signs an absent optional byte slot unpresent', async () => {
      const { claim } = await withData(undefined, true).collect(collectionRequest, options());
      expect(claim.present).toEqual([false, false, false, false]);
      expect(claim.byteValues[0]).toEqual(new Uint8Array(32));
    });

    it('derives two byte values at byteSlots = 2 and collects a threshold', async () => {
      const twoBytePolicy = policy([
        { slot: 3, name: 'first', parse: 'bytes' },
        { slot: 4, name: 'second', parse: 'bytes' },
      ]);
      const { claim, collected } = await clientWith({
        policy: twoBytePolicy,
        byteSlots: 2,
        provers: proversWith({ values: () => ({ first: 'abc', second: 'xyz' }) }),
      }).collect(collectionRequest, options());
      expect(collected).toHaveLength(2);
      expect(claim.present).toEqual([false, false, false, true, true]);
      expect(claim.byteValues[0]).toEqual(padded32('abc'));
      expect(claim.byteValues[1]).toEqual(padded32('xyz'));
    });

    it('decodes a hex slot and collects a threshold', async () => {
      const hexPolicy = policy([{ slot: 3, name: 'data', parse: 'hex', length: 2 }]);
      const { claim, collected } = await clientWith({
        policy: hexPolicy,
        byteSlots: 1,
        provers: proversWith({ values: () => ({ data: '0xABCD' }) }),
      }).collect(collectionRequest, options());
      expect(collected).toHaveLength(2);
      expect(claim.present).toEqual([false, false, false, true]);
      expect(claim.byteValues[0]?.slice(0, 2)).toEqual(Uint8Array.from([0xab, 0xcd]));
      expect(claim.byteValues[0]?.slice(2)).toEqual(new Uint8Array(30));
    });

    it('rejects a required slot that misses its pinned length', async () => {
      const pinnedPolicy = policy([{ slot: 3, name: 'data', parse: 'hex', length: 3 }]);
      await expect(
        clientWith({
          policy: pinnedPolicy,
          byteSlots: 1,
          provers: proversWith({ values: () => ({ data: 'abcd' }) }),
        }).collect(collectionRequest, options()),
      ).rejects.toThrow(/threshold not reached/);
    });
  });

  describe("the 'int' rule through the client", () => {
    it('derives an odd-length hex integer into a numeric slot and collects a threshold', async () => {
      const intPolicy = policy([{ slot: 0, name: 'blockNumber', parse: 'int' }]);
      const { claim, collected } = await clientWith({
        policy: intPolicy,
        provers: proversWith({ values: () => ({ blockNumber: '0x1938381' }) }),
      }).collect(collectionRequest, options());
      expect(collected).toHaveLength(2);
      expect(claim.present).toEqual([true, false, false]);
      expect(claim.values).toEqual([26_444_673n, 0n, 0n]);
    });
  });

  it('collects a threshold of distinct registry slots in one call', async () => {
    const result = await clientWith().collect(collectionRequest, options());
    expect(collectedSlots(result)).toEqual([0, 1]);
    expect(
      result.collected.every((entry) =>
        entry.attestation.message.every((value, i) => value === result.message[i]),
      ),
    ).toBe(true);
  });

  it.each([
    {
      rules: {
        responseMatches: [{ type: 'regex' as const, value: '"moving_time":\\s*(?<data>[\\d.]+)' }],
      },
      pattern: /responseMatches/,
    },
    {
      rules: { responseRedactions: [{ regex: '"moving_time":\\s*\\d+' }] },
      pattern: /responseRedactions/,
    },
  ])(
    'refuses a request whose disclosure rules differ from the policy before any prover runs',
    async ({ rules, pattern }) => {
      const probe = { called: 0 };
      const client = clientWith({
        provers: proversWith({
          onProve: () => {
            probe.called += 1;
          },
        }),
      });
      const divergent = { ...collectionRequest, ...rules };
      await expect(client.proveReq(divergent, binding())).rejects.toThrow(pattern);
      await expect(client.collect(divergent, options())).rejects.toMatchObject({
        name: 'ZkFetchThresholdError',
        reason: 'invalid-options',
        cause: expect.objectContaining({ message: expect.stringMatching(pattern) }),
      });
      expect(probe.called).toBe(0);
    },
  );

  it('proves with the policy disclosure rules even when the request omits them', async () => {
    const seen = { request: undefined as ZkFetchRequest | undefined };
    const client = clientWith({
      provers: proversWith({
        onProve: (_id, request) => {
          seen.request = request;
        },
      }),
    });
    await client.proveReq(collectionRequest, binding());
    expect(seen.request?.responseMatches).toEqual(policy().responseMatches);
    expect(seen.request?.responseRedactions).toEqual(policy().responseRedactions);

    // Supplying the policy's rules verbatim is accepted, not refused.
    const supplied = policy();
    const explicit = await client.proveReq(
      {
        ...collectionRequest,
        responseMatches: supplied.responseMatches,
        responseRedactions: supplied.responseRedactions,
      },
      binding(),
    );
    expect(explicit.claim.values).toHaveLength(3);
  });

  it('collects a healthy subset when an attestor observes a different value', async () => {
    const client = clientWith({
      provers: proversWith({
        values: (id) => ({ data: id === 'attestor-0' ? '99' : '42' }),
      }),
    });
    const result = await client.collect(collectionRequest, options());
    expect(collectedSlots(result)).toEqual([1, 2]);
    expect(result.claim.values[0]).toBe(42n);
  });

  it('falls back when a selected witness is down without exposing its error', async () => {
    const result = await clientWith({
      provers: {
        ...provers,
        'attestor-0': {
          prove: async () => {
            throw new Error('Bearer private-token');
          },
        },
      },
    }).collect(
      { ...collectionRequest, secretHeaders: { authorization: 'Bearer private-token' } },
      options(),
    );
    expect(collectedSlots(result)).toEqual([1, 2]);
    expect(result.failures).toEqual([{ registryIndex: 0, reason: 'evidence' }]);
    expect(JSON.stringify(result.failures)).not.toContain('private-token');
  });

  it.each(['transport', 'no-match'] as const)(
    'reports a prover %s failure under its own reason',
    async (reason) => {
      const failing = new ZkFetchProverError(reason, { cause: new Error('remote detail') });
      const client = clientWith({
        provers: {
          ...provers,
          'attestor-0': {
            prove: async () => {
              throw failing;
            },
          },
        },
      });
      const result = await client.collect(collectionRequest, options());
      expect(collectedSlots(result)).toEqual([1, 2]);
      expect(result.failures).toEqual([{ registryIndex: 0, reason }]);
      await expect(client.proveReq(collectionRequest, binding())).rejects.toBe(failing);
    },
  );

  it('keeps a prover reason only from the proving step, and only a known one', async () => {
    const unknown = new ZkFetchProverError('transport');
    Object.defineProperty(unknown, 'reason', { value: 'remote detail' });
    const client = clientWith({
      provers: {
        ...provers,
        'attestor-0': {
          prove: async () => {
            throw unknown;
          },
        },
      },
      transport: {
        request: async (attestor, input) => {
          if (attestor.id === 'attestor-1') {
            throw new ZkFetchProverError('transport');
          }
          return transport.request(attestor, input);
        },
      },
    });
    const error = await client.collect(collectionRequest, options()).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ZkFetchThresholdError);
    const { failures } = error as ZkFetchThresholdError;
    expect([...failures].sort((a, b) => a.registryIndex - b.registryIndex)).toEqual([
      { registryIndex: 0, reason: 'evidence' },
      { registryIndex: 1, reason: 'attestation' },
    ]);
  });

  /** `json` with the secret echoed inside 5000 levels of escaped JSON arrays. */
  const deeplyNestedSecret = (json: string): string =>
    JSON.stringify({
      ...JSON.parse(json),
      echo: `${'['.repeat(5000)}"Bearer\\u0020private-token"${']'.repeat(5000)}`,
    });

  it.each([
    {
      encoding: 'plain',
      reason: 'secret',
      secret: 'Bearer private-token',
      encode: (json: string) => json,
    },
    {
      encoding: 'JSON-escaped',
      reason: 'secret',
      secret: 'Bearer "private-token"\n',
      encode: (json: string) => json,
    },
    {
      encoding: 'Unicode-escaped',
      reason: 'secret',
      secret: 'Bearer private-token',
      encode: (json: string) => json.replace('private-token', '\\u0070rivate-token'),
    },
    {
      encoding: 'percent-encoded',
      reason: 'secret',
      secret: 'Bearer private-token',
      encode: (json: string) => json.replace('Bearer private-token', 'Bearer%20private-token'),
    },
    {
      encoding: 'deeply-nested',
      // The scan overflows before it can find the secret; EvidenceTooDeepError
      // is not a SecretHeaderError, so `collect` reports an evidence failure.
      reason: 'evidence',
      secret: 'Bearer private-token',
      encode: deeplyNestedSecret,
    },
  ])('never forwards evidence carrying a $encoding secret header value', async (leak) => {
    const counter = countingTransport(transport);
    const client = clientWith({
      provers: {
        ...provers,
        'attestor-0': {
          prove: async (request) => {
            const evidence = await observe(aliceWitness, request);
            const context = { ...JSON.parse(evidence.claim.context), echo: leak.secret };
            evidence.claim.context = leak.encode(JSON.stringify(context));
            return evidence;
          },
        },
      },
      transport: counter.transport,
    });
    const result = await client.collect(
      { ...collectionRequest, secretHeaders: { authorization: leak.secret } },
      options(),
    );
    expect(collectedSlots(result)).toEqual([1, 2]);
    expect(result.failures).toEqual([{ registryIndex: 0, reason: leak.reason }]);
    expect(counter.contacted('attestor-0')).toBe(false);
  });

  it('checks secret headers a prover cannot change through its own request', async () => {
    const counter = countingTransport(transport);
    const client = clientWith({
      provers: {
        ...provers,
        'attestor-0': {
          prove: async (request) => {
            const evidence = await observe(aliceWitness, request);
            const context = { ...JSON.parse(evidence.claim.context), echo: 'Bearer private-token' };
            evidence.claim.context = JSON.stringify(context);
            (request.secretHeaders as Record<string, string>).authorization = 'changed';
            return evidence;
          },
        },
      },
      transport: counter.transport,
    });
    const result = await client.collect(
      { ...collectionRequest, secretHeaders: { authorization: 'Bearer private-token' } },
      options(),
    );
    expect(result.failures).toEqual([{ registryIndex: 0, reason: 'secret' }]);
    expect(counter.contacted('attestor-0')).toBe(false);
  });

  it('refuses a proof handle whose evidence carries a secret header value', async () => {
    const client = clientWith({
      provers: {
        ...provers,
        'attestor-0': {
          prove: async (request) => {
            const evidence = await observe(aliceWitness, request);
            const context = { ...JSON.parse(evidence.claim.context), echo: 'Bearer private-token' };
            evidence.claim.context = JSON.stringify(context);
            return evidence;
          },
        },
      },
    });
    await expect(
      client.proveReq(
        { ...collectionRequest, secretHeaders: { authorization: 'Bearer private-token' } },
        binding(),
      ),
    ).rejects.toThrow(SecretHeaderError);
  });

  it('refuses a proof handle whose evidence is too deeply nested to scan', async () => {
    const client = clientWith({
      provers: {
        ...provers,
        'attestor-0': {
          prove: async (request) => {
            const evidence = await observe(aliceWitness, request);
            evidence.claim.context = deeplyNestedSecret(evidence.claim.context);
            return evidence;
          },
        },
      },
    });
    await expect(
      client.proveReq(
        { ...collectionRequest, secretHeaders: { authorization: 'Bearer private-token' } },
        binding(),
      ),
    ).rejects.toThrow(EvidenceTooDeepError);
  });

  it.each(['prover', 'transport', 'verifier'] as const)(
    'times out a hanging %s and collects from the next attestor',
    async (step) => {
      vi.useFakeTimers();
      try {
        const client = zkFetchClient.init({
          trusted,
          policy: policy(),
          appId: APP_ID,
          valueSlots: 3,
          provers:
            step === 'prover'
              ? { ...provers, 'attestor-0': { prove: () => hanging<ZkFetchEvidence>() } }
              : provers,
          transport: {
            request: (attestor, input) =>
              step === 'transport' && attestor.id === 'attestor-0'
                ? hanging<never>()
                : transport.request(attestor, input),
          },
          verifier: {
            verify: (key: FakePublicKey, message: FlatMessage, signature: string) =>
              step === 'verifier' && key.id === 'attestor-0'
                ? hanging<boolean>()
                : verifier.verify(key, message, signature),
          },
        });
        const pending = client.collect(collectionRequest, { ...options(), attestorTimeoutMs: 100 });
        await vi.advanceTimersByTimeAsync(100);
        const result = await pending;
        expect(collectedSlots(result)).toEqual([1, 2]);
        expect(result.failures).toEqual([{ registryIndex: 0, reason: 'timeout' }]);
      } finally {
        vi.useRealTimers();
      }
    },
  );

  it('expires the deadline while a witness fetch is still pending', async () => {
    vi.useFakeTimers();
    try {
      const pending = clientWith({
        provers: { ...provers, 'attestor-0': { prove: () => hanging<ZkFetchEvidence>() } },
      }).collect(collectionRequest, { ...options(), expiresAt: Date.now() + 50 });
      const rejection = expect(pending).rejects.toMatchObject({ reason: 'expired' });
      await vi.advanceTimersByTimeAsync(50);
      await rejection;
    } finally {
      vi.useRealTimers();
    }
  }, 500);

  it('runs the initial threshold attempts concurrently and leaves spare witnesses uncontacted', async () => {
    let release: (() => void) | undefined;
    const ready = new Promise<void>((resolve) => {
      release = resolve;
    });
    const client = clientWith({
      provers: {
        'attestor-0': {
          prove: async (request) => {
            await ready;
            return observe(aliceWitness, request);
          },
        },
        'attestor-1': {
          prove: async (request) => {
            release?.();
            return observe(bobWitness, request);
          },
        },
        'attestor-2': {
          prove: async () => {
            throw new Error('spare was contacted');
          },
        },
      },
    });
    const result = await client.collect(collectionRequest, options());
    expect(collectedSlots(result)).toEqual([0, 1]);
    expect(result.failures).toEqual([]);
  }, 500);

  it.each([
    { threshold: 0 },
    { threshold: 4 },
    { threshold: 1.5 },
    { attestorTimeoutMs: 0 },
    { attestorTimeoutMs: Number.NaN },
    { expiresAt: Number.NaN },
    { holder: new Uint8Array(31) },
    { windowStart: BigInt(BASE_TIMESTAMP_S + 61) },
    { windowEnd: 2n ** 32n },
    {
      windowStart: BigInt(BASE_TIMESTAMP_S) * 1_000n,
      windowEnd: BigInt(BASE_TIMESTAMP_S + 60) * 1_000n,
    },
    { attestorIds: ['attestor-0', 'attestor-0'] },
    { attestorIds: ['unknown'] },
  ])('rejects invalid options or selection before contacting witnesses: %o', async (override) => {
    let contacted = false;
    const client = clientWith({
      provers: proversWith({
        onProve: () => {
          contacted = true;
        },
      }),
    });
    await expect(
      client.collect(collectionRequest, { ...options(), ...override }),
    ).rejects.toMatchObject({ reason: 'invalid-options' });
    expect(contacted).toBe(false);
  });

  it('refuses a millisecond window in proveReq before contacting any prover', async () => {
    let contacted = false;
    const client = clientWith({
      provers: proversWith({
        onProve: () => {
          contacted = true;
        },
      }),
    });
    const milliseconds = {
      ...binding(),
      windowStart: BigInt(BASE_TIMESTAMP_S) * 1_000n,
      windowEnd: BigInt(BASE_TIMESTAMP_S + 60) * 1_000n,
    };
    await expect(client.proveReq(collectionRequest, milliseconds)).rejects.toThrow(ZodError);
    expect(contacted).toBe(false);
  });

  it('does not count a forged signature toward an otherwise healthy threshold', async () => {
    const client = clientWith({
      transport: {
        request: async (attestor, input) => {
          const result = await transport.request(attestor, input);
          return attestor.id === 'attestor-0' ? { ...result, signature: 'forged' } : result;
        },
      },
    });
    const result = await client.collect(collectionRequest, options());
    expect(collectedSlots(result)).toEqual([1, 2]);
    expect(result.failures).toEqual([{ registryIndex: 0, reason: 'attestation' }]);
  });

  it('counts duplicate target ids only once and preserves registry placement', async () => {
    const result = await clientWith().collect(collectionRequest, {
      ...options(),
      attestorIds: ['attestor-2', 'attestor-2', 'attestor-0'],
    });
    expect(collectedSlots(result)).toEqual([0, 2]);
  });

  it('fails safely when no exact signed message reaches the threshold', async () => {
    const client = clientWith({
      provers: proversWith({
        values: (id) => ({
          data: id === 'attestor-0' ? '10' : id === 'attestor-1' ? '20' : '30',
        }),
      }),
    });
    await expect(client.collect(collectionRequest, options())).rejects.toMatchObject({
      reason: 'threshold',
      failures: [],
    });
  });

  it('rejects an already expired deadline before contacting any witness', async () => {
    let contacted = false;
    const client = clientWith({
      provers: proversWith({
        onProve: () => {
          contacted = true;
        },
      }),
    });
    await expect(
      client.collect(collectionRequest, { ...options(), expiresAt: Date.now() }),
    ).rejects.toMatchObject({ reason: 'expired' });
    expect(contacted).toBe(false);
  });

  it('does not count a verifier that blocks past the operator timeout', async () => {
    const blockingVerifier = {
      verify: (key: FakePublicKey, message: FlatMessage, signature: string) => {
        if (key.id === 'attestor-0') {
          // Blocks the event loop, so the timeout timer cannot fire first.
          const until = Date.now() + 150;
          while (Date.now() < until) {}
        }
        return verifier.verify(key, message, signature);
      },
    };
    const client = zkFetchClient.init({
      trusted,
      transport,
      verifier: blockingVerifier,
      policy: policy(),
      appId: APP_ID,
      valueSlots: 3,
      provers,
    });
    // Threshold 1, so the blocked operator runs alone and the spare starts on a fresh deadline.
    const result = await client.collect(collectionRequest, {
      ...options(),
      threshold: 1,
      attestorTimeoutMs: 100,
    });
    expect(collectedSlots(result)).toEqual([1]);
    expect(result.failures).toEqual([{ registryIndex: 0, reason: 'timeout' }]);
  });

  it('does not forward a witness result that arrives after its timeout', async () => {
    vi.useFakeTimers();
    try {
      let release: ((value: ZkFetchEvidence) => void) | undefined;
      const late = new Promise<ZkFetchEvidence>((resolve) => {
        release = resolve;
      });
      const counter = countingTransport(transport);
      const client = clientWith({
        provers: { ...provers, 'attestor-0': { prove: () => late } },
        transport: counter.transport,
      });
      const pending = client.collect(collectionRequest, { ...options(), attestorTimeoutMs: 100 });
      await vi.advanceTimersByTimeAsync(100);
      const result = await pending;
      release?.(await observe(aliceWitness, collectionRequest));
      await vi.advanceTimersByTimeAsync(0);
      expect(counter.contacted('attestor-0')).toBe(false);
      expect(collectedSlots(result)).toEqual([1, 2]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('rejects a forged attestor signature returned by the transport', async () => {
    const broken = {
      request: async (...args: Parameters<typeof transport.request>) => ({
        ...(await transport.request(...args)),
        signature: 'forged',
      }),
    };
    const proof = await clientWith({ transport: broken }).proveReq(
      { url: 'https://api.github.com/repos/x', method: 'GET' },
      binding(),
    );
    await expect(proof.attest()).rejects.toMatchObject({ reason: 'signature' });
  });

  it('rejects a wrong claim from the transport', async () => {
    const broken = {
      request: async (...args: Parameters<typeof transport.request>) => {
        const result = await transport.request(...args);
        return { ...result, claim: { ...result.claim, holder: new Uint8Array(32).fill(0xff) } };
      },
    };
    const proof = await clientWith({ transport: broken }).proveReq(
      { url: 'https://api.github.com/repos/x', method: 'GET' },
      binding(),
    );
    await expect(proof.attest()).rejects.toMatchObject({ reason: 'claim' });
  });

  const prove = () =>
    clientWith().proveReq({ url: 'https://api.github.com/repos/x', method: 'GET' }, binding());

  const evidenceOf = (
    evidences: Readonly<Record<string, ZkFetchEvidence>>,
    id: string,
  ): ZkFetchEvidence => {
    const evidence = evidences[id];
    if (evidence === undefined) {
      throw new Error(`no evidence for attestor ${id}`);
    }
    return evidence;
  };

  const requestOf = (requests: Record<string, ZkFetchRequest>, id: string): ZkFetchRequest => {
    const request = requests[id];
    if (request === undefined) {
      throw new Error(`prover for ${id} was not called`);
    }
    return request;
  };

  it('collects one agreeing attestation per pinned attestor', async () => {
    const attestment = await prove().then((proof) => proof.attest());
    expect(attestment.collected.length).toBe(3);
    expect(attestment.collected.every((c) => c.attestation.publicKey.id !== '')).toBe(true);
    const message = claimToMessage(attestment.claim);
    expect(attestment.collected.every((c) => c.attestation.message.length === message.length)).toBe(
      true,
    );
  });

  it('lets the caller select which attestors to query', async () => {
    const attestment = await prove().then((proof) => proof.attest('attestor-0', 'attestor-2'));
    expect(collectedSlots(attestment)).toEqual([0, 2]);
  });

  it("places slot-agnostic signatures at each app's own registry slots", async () => {
    // Two apps pin the same attestors at different slots of registries with different sizes.
    const [first, second] = await Promise.all(
      [trustedWith([0, 1, 2]), trustedWith([4, 0, 2], 5)].map((set) =>
        clientWith({ trusted: set })
          .proveReq({ url: 'https://api.github.com/repos/x', method: 'GET' }, binding())
          .then((proof) => proof.attest('attestor-0', 'attestor-1')),
      ),
    );
    expect(first && collectedSlots(first)).toEqual([0, 1]);
    expect(second && collectedSlots(second)).toEqual([4, 0]);
    expect(second?.collected.map((c) => c.attestation)).toEqual(
      first?.collected.map((c) => c.attestation),
    );
  });

  it('collects and sorts by app-assigned slots, not by trusted-set order', async () => {
    const result = await clientWith({ trusted: trustedWith([4, 0, 2], 5) }).collect(
      collectionRequest,
      { ...options(), threshold: 3 },
    );
    expect(collectedSlots(result)).toEqual([0, 2, 4]);
    expect(result.collected.map((entry) => entry.attestation.publicKey.id)).toEqual([
      'attestor-1',
      'attestor-2',
      'attestor-0',
    ]);
  });

  it('refuses to attest to an attestor outside the trusted set', async () => {
    await expect(prove().then((proof) => proof.attest('ghost'))).rejects.toThrow(
      /not in the trusted set/,
    );
  });

  it('refuses when the policy does not fit the evidence (host)', async () => {
    const hostile = clientWith({ policy: { ...policy(), allowedHosts: ['evil.example'] } });
    await expect(
      hostile.proveReq({ url: 'https://api.github.com/x', method: 'GET' }, binding()),
    ).rejects.toThrow(/not in allowlist/);
  });

  it('refuses a starred signed URL before any attestor is contacted', async () => {
    await expect(
      clientWith().proveReq({ url: 'https://api.github.com/repos/*', method: 'GET' }, binding()),
    ).rejects.toThrow(/url cannot contain \*/);
  });

  it('binds a pinned body end to end', async () => {
    const body = '{"q":1}';
    const url = 'https://api.github.com/repos/x';
    const client = clientWith({
      policy: { ...policy(), bodyPolicy: { sha256: zkFetchBodyHashOf(body) } },
    });
    const proof = await client.proveReq({ url, method: 'POST', body }, binding());

    expect(proof.claim.subjectHash).toEqual(zkFetchSubjectHashOf({ method: 'POST', url, body }));
    const attestment = await proof.attest();
    expect(attestment.collected).toHaveLength(3);
  });

  it('refuses a request body that does not match the pinned body', async () => {
    const client = clientWith({
      policy: { ...policy(), bodyPolicy: { sha256: zkFetchBodyHashOf('{"q":1}') } },
    });
    await expect(
      client.proveReq(
        { url: 'https://api.github.com/repos/x', method: 'POST', body: '{"q":2}' },
        binding(),
      ),
    ).rejects.toThrow(/body/);
  });

  it('refuses evidence for the requested origin but another path', async () => {
    const client = clientWith({
      provers: proversWith({
        url: () => 'https://api.github.com/repos/reclaimprotocol/attestor-core',
      }),
    });
    await expect(
      client.proveReq({ url: 'https://api.github.com/repos/x', method: 'GET' }, binding()),
    ).rejects.toThrow(/another method, path or body/);
  });

  it('refuses evidence for a different origin than requested', async () => {
    const client = clientWith({
      provers: proversWith({ url: () => 'https://api.github.com/repos/x' }),
    });
    await expect(
      client.proveReq({ url: 'https://other.example/x', method: 'GET' }, binding()),
    ).rejects.toThrow(/not the requested/);
  });

  it('refuses a prover map that does not match the trusted set at init', () => {
    expect(() =>
      zkFetchClient.init({
        trusted,
        verifier,
        transport,
        policy: policy(),
        appId: APP_ID,
        valueSlots: 3,
        provers: {},
      }),
    ).toThrow(/no prover configured for attestor/);
    expect(() =>
      zkFetchClient.init({
        trusted,
        verifier,
        transport,
        policy: policy(),
        appId: APP_ID,
        valueSlots: 3,
        provers: {
          ...provers,
          ghost: { prove: (request) => observe(aliceWitness, request) },
        },
      }),
    ).toThrow(/prover configured for unknown attestor ghost/);
  });

  it('refuses a policy slot beyond the claim length at init', () => {
    expect(() =>
      clientWith({
        policy: policy([{ slot: 5, name: 'data', parse: 'float', optional: true }]),
      }),
    ).toThrow(/out of the claim's 3 value slots/);
  });

  it('refuses an appId that is not 32 bytes at init', () => {
    expect(() => clientWith({ appId: new Uint8Array(31) })).toThrow(/appId must be 32 bytes/);
  });

  it('collects a claim for the configured app under the policy hash', async () => {
    const attestment = await prove().then((proof) => proof.attest());
    expect(attestment.claim.appId).toEqual(APP_ID);
    expect(attestment.claim.policyHash).toEqual(zkFetchPolicyHashOf(policy()));
  });

  it('collects a claim about the requested subject', async () => {
    const attestment = await prove().then((proof) => proof.attest());
    expect(attestment.claim.subjectHash).toEqual(
      zkFetchSubjectHashOf({ method: 'GET', url: 'https://api.github.com/repos/x', body: '' }),
    );
  });

  it('signs a derived claim and attests only what was disclosed', async () => {
    const proof = await prove();
    const attestment = await proof.attest();
    const { present, values } = attestment.claim;
    expect(values.length).toBe(3);
    expect(values.every((v) => v === 0n)).toBe(true);
    expect(present.every((p) => p === false)).toBe(true);
  });

  it('rejects a holder commitment of the wrong length before proving', async () => {
    await expect(
      clientWith().proveReq(
        { url: 'https://api.github.com/repos/x', method: 'GET' },
        binding(new Uint8Array(31)),
      ),
    ).rejects.toThrow(/expected 32 bytes/);
  });

  it('signs the per-call holder in every collected attestation', async () => {
    const holder = filled(0xc2);
    const proof = await clientWith().proveReq(
      { url: 'https://api.github.com/repos/x', method: 'GET' },
      binding(holder),
    );
    expect(proof.claim.holder).toEqual(holder);
    const attestment = await proof.attest();
    for (const collected of attestment.collected) {
      expect(collected.attestation.claim.holder).toEqual(holder);
      expect(collected.attestation.message).toEqual(claimToMessage(proof.claim));
    }
  });

  it('agrees on the flat message across every attestor', async () => {
    const attestment = await prove().then((proof) => proof.attest());
    const message = claimToMessage(attestment.claim);
    for (const collected of attestment.collected) {
      expect(collected.attestation.message).toEqual(message);
    }
  });

  it("proposes the caller's window to every attestor", async () => {
    const offsets: Record<string, number> = { 'attestor-0': 0, 'attestor-1': 3, 'attestor-2': 6 };
    const staggered = proversWith({
      timestampS: (id) => BASE_TIMESTAMP_S + (offsets[id] ?? 0),
    });
    const proof = await clientWith({ provers: staggered }).proveReq(collectionRequest, binding());
    expect(proof.claim.windowStart).toBe(BigInt(BASE_TIMESTAMP_S));
    expect(proof.claim.windowEnd).toBe(BigInt(BASE_TIMESTAMP_S + 60));
    const attestment = await proof.attest();
    expect(attestment.collected.length).toBe(3);
    for (const collected of attestment.collected) {
      expect(collected.attestation.message).toEqual(attestment.message);
    }
  });

  it('refuses without contacting an attestor when witnesses disagree', async () => {
    const counter = countingTransport(transport);
    const diverging = proversWith({
      values: (id) => (id === 'attestor-1' ? { data: '42' } : { data: 'HTTP/1.1 200 OK' }),
    });
    await expect(
      clientWith({ transport: counter.transport, provers: diverging }).proveReq(
        {
          url: 'https://api.github.com/repos/x',
          method: 'GET',
        },
        binding(),
      ),
    ).rejects.toThrow(/witnesses disagree/);
    expect(counter.calls()).toBe(0);
  });

  it("signs the claim context digest into every witness's context beside the caller's", async () => {
    const requests: Record<string, ZkFetchRequest> = {};
    const client = clientWith({
      provers: proversWith({
        onProve: (id, request) => {
          requests[id] = request;
        },
      }),
    });
    await client.proveReq({ ...collectionRequest, context: { label: 'commute' } }, binding());
    const digest = zkFetchClaimContextDigestOf({
      policy: policy(),
      request: collectionRequest,
      ...binding(),
    });
    for (const id of ids) {
      expect(requestOf(requests, id).context).toEqual({
        label: 'commute',
        [ZK_FETCH_CLAIM_CONTEXT_KEY]: digest,
      });
    }
  });

  it('refuses a request whose context already sets the claim context digest', async () => {
    const probe = { called: 0 };
    const client = clientWith({
      provers: proversWith({
        onProve: () => {
          probe.called += 1;
        },
      }),
    });
    const preset = { ...collectionRequest, context: { [ZK_FETCH_CLAIM_CONTEXT_KEY]: 'ab' } };
    await expect(client.proveReq(preset, binding())).rejects.toThrow(ZK_FETCH_CLAIM_CONTEXT_KEY);
    await expect(client.collect(preset, options())).rejects.toMatchObject({
      reason: 'invalid-options',
    });
    expect(probe.called).toBe(0);
  });

  it('refuses evidence signed for another holder before contacting any attestor', async () => {
    const proof = await prove();
    const counter = countingTransport(transport);
    const thief = clientWith({
      transport: counter.transport,
      provers: Object.fromEntries(
        ids.map((id) => [id, { prove: async () => evidenceOf(proof.evidences, id) }]),
      ),
    });
    const stolen = filled(0xc2);
    await expect(thief.proveReq(collectionRequest, binding(stolen))).rejects.toThrow(
      /another claim context/,
    );
    const refused = thief.collect(collectionRequest, { ...options(), holder: stolen });
    await expect(refused).rejects.toMatchObject({ reason: 'threshold' });
    const { failures } = await refused.catch(
      (error: { failures: ZkFetchAttestorFailure[] }) => error,
    );
    expect([...failures].sort((a, b) => a.registryIndex - b.registryIndex)).toEqual(
      ids.map((_, registryIndex) => ({ registryIndex, reason: 'evidence' })),
    );
    expect(counter.calls()).toBe(0);
  });

  it('refuses evidence observed outside the window before contacting any attestor', async () => {
    const counter = countingTransport(transport);
    const late = clientWith({
      transport: counter.transport,
      provers: proversWith({ timestampS: () => BASE_TIMESTAMP_S + 61 }),
    });
    await expect(late.proveReq(collectionRequest, binding())).rejects.toThrow(
      /outside the claim window/,
    );
    const refused = late.collect(collectionRequest, options());
    await expect(refused).rejects.toMatchObject({ reason: 'threshold' });
    const { failures } = await refused.catch(
      (error: { failures: ZkFetchAttestorFailure[] }) => error,
    );
    expect([...failures].sort((a, b) => a.registryIndex - b.registryIndex)).toEqual(
      ids.map((_, registryIndex) => ({ registryIndex, reason: 'evidence' })),
    );
    expect(counter.calls()).toBe(0);
  });

  it("keeps the claim context digest a prover deletes from its own request out of the others'", async () => {
    const requests: Record<string, ZkFetchRequest> = {};
    const recording = proversWith({
      onProve: (id, request) => {
        requests[id] = request;
      },
    });
    const client = clientWith({
      provers: {
        ...recording,
        'attestor-0': {
          // Deletes the digest before the other provers are called, after signing its own copy.
          prove: (request) => {
            const signed = { ...request, context: { ...request.context } };
            delete (request.context as Record<string, unknown>)[ZK_FETCH_CLAIM_CONTEXT_KEY];
            return observe(aliceWitness, signed);
          },
        },
      },
    });
    const digest = zkFetchClaimContextDigestOf({
      policy: policy(),
      request: collectionRequest,
      ...binding(),
    });
    const attestment = await (await client.proveReq(collectionRequest, binding())).attest();
    expect(attestment.collected.length).toBe(3);
    const collected = await client.collect(collectionRequest, options());
    expect(collectedSlots(collected)).toEqual([0, 1]);
    for (const id of ['attestor-1', 'attestor-2']) {
      expect(requestOf(requests, id).context).toEqual({ [ZK_FETCH_CLAIM_CONTEXT_KEY]: digest });
    }
  });
});
