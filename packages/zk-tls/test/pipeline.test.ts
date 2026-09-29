// End-to-end tests over the package's shipped entry points (`@thoth/zk-tls/attestor`
// and `@thoth/zk-tls/client`): verify a real witnessed Reclaim proof, derive and
// collect the N-of-M attestation set, and assert the kind's rejection paths.
//
// Uses `examples/demo-attestation/fixtures/` — a genuine, offline-verifiable
// HTTPS fetch witnessed by a Reclaim witness (no network needed).
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Attestor, KeyPair } from '@thoth/attestor';
import { descriptorOf } from '@thoth/attestor';
import type { AttestorTransport } from '@thoth/client';
import { buildTrustedSet } from '@thoth/client';
import type { FlatMessage } from '@thoth/core/claim';
import { claimToMessage } from '@thoth/core/claim';
import {
  type ZkFetchDefinition,
  type ZkFetchEvidence,
  type ZkFetchPolicy,
  zkFetchClaimSchema,
  zkFetchEvidenceSchema,
  zkFetchPolicyHashOf,
  zkFetchSubjectHashOf,
} from '@thoth/zk-tls';
import { verifyZkFetchProof, zkFetchAttestor } from '@thoth/zk-tls/attestor';
import {
  addressFromWitnessId,
  toCanonicalEvidence,
  type ZkFetchProver,
  type ZkFetchRequest,
  zkFetchClient,
} from '@thoth/zk-tls/client';
import { describe, expect, it } from 'vitest';
import { type TestWitness, testWitness } from './helpers/witness.js';

/** The app id every claim in this suite is for. */
const APP_ID = new Uint8Array(32).fill(0xa1);

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

const policy = (
  slots: ZkFetchPolicy['slots'] = [{ slot: 0, name: 'data', parse: 'float', optional: true }],
): ZkFetchPolicy => ({
  allowedHosts: ['api.github.com'],
  slots,
});

type FakePublicKey = { id: string };
type FakeSignature = string;

const fakeKey = (id: string): KeyPair<FakePublicKey, FakeSignature, FlatMessage> => ({
  publicKey: { id },
  signer: { sign: (message: FlatMessage): FakeSignature => `sig:${message.length}` },
});

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
    expect(verified.canonicalHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('rejects an invalid signature', async () => {
    const evidence = zkFetchEvidenceSchema.parse(fixture);
    const tampered = { ...evidence, signatureHex: `0x${'00'.repeat(65)}` };
    await expect(verifyZkFetchProof(tampered)).rejects.toThrow();
  });
});

describe('zkFetch claim schema', () => {
  it('rejects an appId, policyHash subjectHash or holder that is not 32 bytes', () => {
    const claim = {
      version: 1,
      appId: APP_ID,
      holder: new Uint8Array(32).fill(0xc1),
      policyHash: new Uint8Array(32),
      windowStart: 1_786_122_944,
      windowEnd: 1_786_122_944,
      subjectHash: new Uint8Array(32),
      present: [true],
      values: [12],
    };
    expect(() => zkFetchClaimSchema.parse({ ...claim, appId: new Uint8Array(31) })).toThrow(
      /expected 32 bytes/,
    );
    expect(() => zkFetchClaimSchema.parse({ ...claim, policyHash: new Uint8Array(33) })).toThrow(
      /expected 32 bytes/,
    );
    expect(() => zkFetchClaimSchema.parse({ ...claim, holder: new Uint8Array(31) })).toThrow(
      /expected 32 bytes/,
    );
    expect(() => zkFetchClaimSchema.parse({ ...claim, subjectHash: new Uint8Array(16) })).toThrow(
      /expected 32 bytes/,
    );
  });

  it('parses a derived claim into bigint values', () => {
    const claim = zkFetchClaimSchema.parse({
      version: 1,
      appId: APP_ID,
      holder: new Uint8Array(32).fill(0xc1),
      policyHash: new Uint8Array(32),
      windowStart: 1_786_122_944,
      windowEnd: 1_786_122_944,
      subjectHash: new Uint8Array(32),
      present: [true, false],
      values: [12, 0],
    });
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
  const witnessKeyById: Record<string, string> = {
    'attestor-0': `0x${'33'.repeat(32)}`,
    'attestor-1': `0x${'44'.repeat(32)}`,
    'attestor-2': `0x${'55'.repeat(32)}`,
  };
  const ids = Object.keys(witnessById);

  const attestors = Object.entries(witnessKeyById).map(([id, witnessKey], i) =>
    zkFetchAttestor({ id, keyPair: fakeKey(id), registryIndex: i, witnessKey }),
  );
  const byId = new Map(attestors.map((a) => [a.id, a]));
  const trusted = buildTrustedSet(attestors.map(descriptorOf));
  const transport: AttestorTransport<ZkFetchDefinition, FakePublicKey, FakeSignature> = {
    async request(attestor, input) {
      const instance = byId.get(attestor.id);
      if (!instance) {
        throw new Error(`transport: unknown attestor ${attestor.id}`);
      }
      return instance.attest(
        input as Parameters<Attestor<ZkFetchDefinition, FakePublicKey, FakeSignature>['attest']>[0],
      );
    },
  };

  const BASE_TIMESTAMP_S = 1_786_122_944;

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
      parameters: { url: overrides.url ?? request.url, method: request.method ?? 'GET', body: '' },
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
    } = {},
  ) =>
    zkFetchClient.init({
      trusted,
      transport: overrides.transport ?? transport,
      policy: overrides.policy ?? policy(),
      appId: overrides.appId ?? APP_ID,
      valueSlots: 3,
      provers: overrides.provers ?? provers,
    });

  const prove = () =>
    clientWith().proveReq(
      { url: 'https://api.github.com/repos/x', method: 'GET' },
      new Uint8Array(32).fill(0xc1),
    );

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
    expect(attestment.collected.map((c) => c.registryIndex)).toEqual([0, 2]);
  });

  it('refuses to attest to an attestor outside the trusted set', async () => {
    await expect(prove().then((proof) => proof.attest('ghost'))).rejects.toThrow(
      /not in the trusted set/,
    );
  });

  it('refuses when the policy does not fit the evidence (host)', async () => {
    const hostile = clientWith({ policy: { ...policy(), allowedHosts: ['evil.example'] } });
    await expect(
      hostile.proveReq(
        { url: 'https://api.github.com/x', method: 'GET' },
        new Uint8Array(32).fill(0xc1),
      ),
    ).rejects.toThrow(/not in allowlist/);
  });

  it('binds the evidence to the requested URL origin (same origin, other path)', async () => {
    const attestedUrl = 'https://api.github.com/repos/reclaimprotocol/attestor-core';
    const requests: Record<string, ZkFetchRequest> = {};
    const client = clientWith({
      provers: proversWith({
        url: () => attestedUrl,
        onProve: (id, request) => {
          requests[id] = request;
        },
      }),
    });
    const proof = await client.proveReq(
      { url: 'https://api.github.com/repos/x', method: 'GET' },
      new Uint8Array(32).fill(0xc1),
    );
    const expected = await observe(bobWitness, requestOf(requests, 'attestor-1'), {
      url: attestedUrl,
    });
    expect(evidenceOf(proof.evidences, 'attestor-1').claim.identifier).toBe(
      expected.claim.identifier,
    );
  });

  it('refuses evidence for a different origin than requested', async () => {
    const client = clientWith({
      provers: proversWith({ url: () => 'https://api.github.com/repos/x' }),
    });
    await expect(
      client.proveReq(
        { url: 'https://other.example/x', method: 'GET' },
        new Uint8Array(32).fill(0xc1),
      ),
    ).rejects.toThrow(/not the requested/);
  });

  it('refuses a prover map that does not match the trusted set at init', () => {
    expect(() =>
      zkFetchClient.init({
        trusted,
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
        new Uint8Array(31),
      ),
    ).rejects.toThrow(/expected 32 bytes/);
  });

  it('signs the per-call holder in every collected attestation', async () => {
    const holder = new Uint8Array(32).fill(0xc2);
    const proof = await clientWith().proveReq(
      { url: 'https://api.github.com/repos/x', method: 'GET' },
      holder,
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

  it('proposes the window spanning every observation to every attestor', async () => {
    const offsets: Record<string, number> = { 'attestor-0': 0, 'attestor-1': 3, 'attestor-2': 6 };
    const staggered = proversWith({
      timestampS: (id) => BASE_TIMESTAMP_S + (offsets[id] ?? 0),
    });
    const proof = await clientWith({ provers: staggered }).proveReq(
      {
        url: 'https://api.github.com/repos/x',
        method: 'GET',
      },
      new Uint8Array(32).fill(0xc1),
    );
    expect(proof.claim.windowStart).toBe(BigInt(BASE_TIMESTAMP_S));
    expect(proof.claim.windowEnd).toBe(BigInt(BASE_TIMESTAMP_S + 6));
    const attestment = await proof.attest();
    expect(attestment.collected.length).toBe(3);
    for (const collected of attestment.collected) {
      expect(collected.attestation.message).toEqual(attestment.message);
    }
  });

  it('refuses without contacting an attestor when witnesses disagree', async () => {
    let calls = 0;
    const counting: AttestorTransport<ZkFetchDefinition, FakePublicKey, FakeSignature> = {
      async request(attestor, input) {
        calls += 1;
        return transport.request(attestor, input);
      },
    };
    const diverging = proversWith({
      values: (id) => (id === 'attestor-1' ? { data: '42' } : { data: 'HTTP/1.1 200 OK' }),
    });
    await expect(
      clientWith({ transport: counting, provers: diverging }).proveReq(
        {
          url: 'https://api.github.com/repos/x',
          method: 'GET',
        },
        new Uint8Array(32).fill(0xc1),
      ),
    ).rejects.toThrow(/witnesses disagree/);
    expect(calls).toBe(0);
  });

  it('preserves caller context without adding replay randomness', async () => {
    const requests: Record<string, ZkFetchRequest> = {};
    const client = clientWith({
      provers: proversWith({
        onProve: (id, request) => {
          requests[id] = request;
        },
      }),
    });
    await client.proveReq(
      {
        url: 'https://api.github.com/repos/x',
        method: 'GET',
        context: { label: 'commute' },
      },
      new Uint8Array(32).fill(0xc1),
    );
    for (const id of ids) {
      expect(requestOf(requests, id).context).toEqual({ label: 'commute' });
    }
  });
});
