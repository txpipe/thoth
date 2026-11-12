// The zkFetch kind manifest (`@thoth/zk-tls/thoth`): the layout a policy
// implies, and the policy hash, client and attestors it builds agreeing with
// the kind's own entries.
import { randomBytes } from 'node:crypto';
import {
  CompactTypeField,
  CompactTypeVector,
  type JubjubSchnorrSignature,
  jubjubSchnorrSign,
  jubjubSchnorrVerifyingKey,
  sampleJubjubSchnorrSk,
} from '@midnight-ntwrk/compact-runtime';
import { buildTrustedSet } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';
import type { FlatMessage } from '@thoth/core/claim';
import { holderCommitmentOf } from '@thoth/core/claim-context';
import type { JubjubKeyPair } from '@thoth/core/kind';
import type { ZkFetchPolicy } from '@thoth/zk-tls';
import { zkTls } from '@thoth/zk-tls/thoth';
import { describe, expect, it } from 'vitest';
import { DISCLOSURE_RULES } from './helpers/helper.js';

const policyWith = (slots: ZkFetchPolicy['slots']): ZkFetchPolicy => ({
  allowedHosts: ['api.github.com'],
  slots,
  bodyPolicy: 'ignored',
  ...DISCLOSURE_RULES,
});

const APP_ID = new Uint8Array(32).fill(0xa1);
const OBSERVED_AT = 1_786_122_944;

const jubjubKeyPair = (): JubjubKeyPair => {
  const sk = sampleJubjubSchnorrSk();
  return {
    publicKey: jubjubSchnorrVerifyingKey(sk),
    signer: {
      sign: (message: FlatMessage): JubjubSchnorrSignature =>
        jubjubSchnorrSign(
          new CompactTypeVector(message.length, CompactTypeField),
          [...message],
          sk,
        ),
    },
  };
};

describe('zkTls.layoutOf', () => {
  it('puts int and float slots in the numeric region and byte rules after them', () => {
    const layout = zkTls.layoutOf(
      policyWith([
        { slot: 2, name: 'owner', parse: 'bytes' },
        { slot: 0, name: 'stars', parse: 'int' },
        { slot: 3, name: 'commit', parse: 'hex', length: 20, optional: true },
        { slot: 1, name: 'score', parse: 'float', optional: true },
        { slot: 4, name: 'avatar', parse: 'base64' },
      ]),
    );
    expect(layout).toEqual({
      valueSlots: 2,
      byteSlots: 3,
      names: [
        { name: 'stars', region: 'numeric', index: 0, optional: false },
        { name: 'score', region: 'numeric', index: 1, optional: true },
        { name: 'owner', region: 'bytes', index: 0, optional: false },
        { name: 'commit', region: 'bytes', index: 1, optional: true },
        { name: 'avatar', region: 'bytes', index: 2, optional: false },
      ],
    });
  });

  it('refuses a gap, naming the unused slot and how to renumber', () => {
    const policy = policyWith([
      { slot: 0, name: 'stars', parse: 'int' },
      { slot: 1, name: 'forks', parse: 'int' },
      { slot: 3, name: 'owner', parse: 'bytes' },
    ]);
    expect(() => zkTls.layoutOf(policy)).toThrow("slot 2 is unused; renumber 'owner' from 3 to 2");
  });

  it('refuses a slot name that is a valid regex group name but not an ASCII identifier', () => {
    const policy = policyWith([
      { slot: 0, name: 'stars', parse: 'int' },
      { slot: 1, name: 'año', parse: 'int' },
    ]);
    expect(() => zkTls.layoutOf(policy)).toThrow('slot 1: name "año" is not an ASCII identifier');
  });

  it('refuses a policy the schema refuses', () => {
    expect(() => zkTls.layoutOf(policyWith([]))).toThrow();
  });
});

describe('zkTls.definition', () => {
  it("is the kind's law", () => {
    expect(zkTls.definition().kind).toBe(zkTls.law);
  });

  it('refuses to verify evidence, since only an attestor verifies', async () => {
    const definition = zkTls.definition();
    await expect(definition.verify({} as Parameters<typeof definition.verify>[0])).rejects.toThrow(
      'does not verify evidence',
    );
  });
});

describe('the zkTls manifest end to end', () => {
  const policy = policyWith([
    { slot: 0, name: 'stars', parse: 'int' },
    { slot: 1, name: 'owner', parse: 'bytes' },
  ]);

  // Build everything through the manifest alone, as the CLI does: offline
  // operators, an attestor per operator, descriptors from `definition()`, and
  // the client.
  const collect = async () => {
    const devEvidence = zkTls.devEvidence;
    if (devEvidence === undefined) throw new Error('zkTls has no devEvidence');
    const operators = devEvidence(policy, 3, {
      values: { stars: '42', owner: 'alice' },
      timestampS: OBSERVED_AT,
    });
    const built = operators.map(({ attestorConfig, prover }, i) => ({
      attestor: zkTls.attestor({ id: `dev-${i}`, keyPair: jubjubKeyPair(), ...attestorConfig }),
      prover,
    }));
    const attestors = built.map(({ attestor }) => attestor);
    const layout = zkTls.layoutOf(policy);
    const client = zkTls.client({
      trusted: buildTrustedSet({
        registrySize: attestors.length,
        attestors: attestors.map((attestor, registryIndex) => ({
          attestor: {
            id: attestor.id,
            definition: zkTls.definition(),
            publicKey: attestor.publicKey,
          },
          registryIndex,
        })),
      }),
      transport: {
        request: (descriptor, input) => {
          const attestor = attestors.find((candidate) => candidate.id === descriptor.id);
          if (attestor === undefined) throw new Error(`unknown attestor ${descriptor.id}`);
          return attestor.attest(input as Parameters<typeof attestor.attest>[0]);
        },
      },
      verifier: jubjubVerifier,
      policy,
      appId: APP_ID,
      valueSlots: layout.valueSlots,
      byteSlots: layout.byteSlots,
      provers: Object.fromEntries(built.map(({ attestor, prover }) => [attestor.id, prover])),
    });
    return client.collect(
      { url: 'https://api.github.com/repos/txpipe/dolos' },
      {
        holder: holderCommitmentOf(randomBytes(32)),
        windowStart: BigInt(OBSERVED_AT - 60),
        windowEnd: BigInt(OBSERVED_AT + 60),
        expiresAt: Date.now() + 60_000,
        threshold: 2,
        attestorTimeoutMs: 20_000,
      },
    );
  };

  it("signs the manifest's policy hash for an equivalent policy", async () => {
    const attestment = await collect();
    // Hosts in another case and order normalize to the same policy.
    const equivalent = { ...policy, allowedHosts: ['API.GitHub.com.', 'api.github.com'] };
    expect(attestment.collected.length).toBeGreaterThanOrEqual(2);
    expect(attestment.claim.policyHash).toEqual(zkTls.policyHashOf(equivalent));
    for (const { attestation } of attestment.collected) {
      expect(attestation.claim.policyHash).toEqual(zkTls.policyHashOf(equivalent));
    }
  });

  it('certifies the values every offline operator observed', async () => {
    const attestment = await collect();
    expect(attestment.claim.values).toEqual([42n]);
    expect(attestment.claim.byteValues[0]?.subarray(0, 5)).toEqual(
      new TextEncoder().encode('alice'),
    );
    expect(attestment.claim.present).toEqual([true, true]);
  });

  it('refuses an operator count that is not a positive integer', () => {
    const devEvidence = zkTls.devEvidence;
    if (devEvidence === undefined) throw new Error('zkTls has no devEvidence');
    const input = { values: {}, timestampS: OBSERVED_AT };
    expect(() => devEvidence(policy, 0, input)).toThrow('operators must be a positive integer');
    expect(() => devEvidence(policy, 1.5, input)).toThrow('operators must be a positive integer');
  });
});
