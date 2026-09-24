// End-to-end tests over the package's shipped entry points (`@thoth/zk-tls/attestor`
// and `@thoth/zk-tls/client`): verify a real witnessed Reclaim proof, derive and
// collect the N-of-M attestation set, and assert the kind's rejection paths.
//
// Signature verification uses `examples/demo-attestation/fixtures/` — a
// genuine, offline-verifiable HTTPS fetch witnessed by a Reclaim witness. The
// client flow fakes the witness at the prover interface with a test key, since
// it must sign the intent-bound context the client builds.
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
  INTENT_CONTEXT_KEY,
  intentDigestOf,
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
import { testWitness } from './helpers/witness.js';

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

const witness = testWitness(`0x${'11'.repeat(32)}`);
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
 * A prover backed by the test witness: it signs the request it is handed
 * (including the intent-bound context), observing `values` at `url`.
 */
const witnessProver = (
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

describe('zkFetch attestor + client', () => {
  const attestors = ['attestor-0', 'attestor-1', 'attestor-2'].map((id, i) =>
    zkFetchAttestor({
      id,
      keyPair: fakeKey(id),
      registryIndex: i,
      witnessAddress: witness.address,
    }),
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

  const prove = (
    prover = witnessProver(),
  ): ReturnType<ReturnType<typeof zkFetchClient.init>['proveReq']> =>
    zkFetchClient
      .init({ trusted, transport, policy: policy(), valueSlots: 3, prover })
      .proveReq({ url: 'https://api.github.com/repos/x', method: 'GET' }, INTENT);

  it('binds the witnessed session to a fresh intent', async () => {
    const [first, second] = await Promise.all([prove(), prove()]);
    const context = JSON.parse(first.evidence.claim.context);
    expect(context[INTENT_CONTEXT_KEY]).toBe(intentDigestOf(first.intent));
    expect(first.intent.holder).toEqual(INTENT.holder);
    expect(first.intent.nonce).not.toEqual(second.intent.nonce);
  });

  it('attests a claim in the common layout', async () => {
    const proof = await prove(witnessProver({ stars: '42' }));
    const { claim, message } = await proof.attest();
    expect(claim).toMatchObject({ ...proof.intent, present: [true, false, false] });
    expect(claim.values).toEqual([42n, 0n, 0n]);
    expect(message).toHaveLength(14);
  });

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
    const hostile = zkFetchClient.init({
      trusted,
      transport,
      policy: { ...policy(), allowedHosts: ['evil.example'] },
      valueSlots: 3,
      prover: witnessProver(),
    });
    await expect(
      hostile
        .proveReq({ url: 'https://api.github.com/x', method: 'GET' }, INTENT)
        .then((proof) => proof.attest()),
    ).rejects.toThrow(/not in allowlist/);
  });

  it('refuses evidence for a different origin than requested', async () => {
    await expect(prove(witnessProver(undefined, 'https://other.example/x'))).rejects.toThrow(
      /not the requested/,
    );
  });

  it('refuses evidence observed outside the intent window', async () => {
    const late = zkFetchClient.init({
      trusted,
      transport,
      policy: policy(),
      valueSlots: 3,
      prover: witnessProver(),
    });
    await expect(
      late
        .proveReq(
          { url: 'https://api.github.com/x' },
          { ...INTENT, windowStart: BigInt(OBSERVED_AT + 1), windowEnd: BigInt(OBSERVED_AT + 60) },
        )
        .then((proof) => proof.attest()),
    ).rejects.toThrow(/outside the intent window/);
  });

  it('refuses a policy slot beyond the claim length at init', () => {
    expect(() =>
      zkFetchClient.init({
        trusted,
        transport,
        policy: policy([{ slot: 5, name: 'stars', parse: 'int', optional: true }]),
        valueSlots: 3,
        prover: witnessProver(),
      }),
    ).toThrow(/out of the claim's 3 value slots/);
  });

  it('signs a derived claim and attests only what was disclosed', async () => {
    const proof = await prove(witnessProver({}));
    const attestment = await proof.attest();
    const { present, values } = attestment.claim;
    expect(values.length).toBe(3);
    expect(values.every((v) => v === 0n)).toBe(true);
    expect(present.every((p) => p === false)).toBe(true);
  });

  it('agrees on the flat message across every attestor', async () => {
    const attestment = await prove().then((proof) => proof.attest());
    const message = claimToMessage(attestment.claim);
    for (const collected of attestment.collected) {
      expect(collected.attestation.message).toEqual(message);
    }
  });
});
