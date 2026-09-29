import {
  CompactTypeField,
  CompactTypeVector,
  jubjubSchnorrSign,
  jubjubSchnorrVerifyingKey,
} from '@midnight-ntwrk/compact-runtime';
import { buildTrustedSet, resolveAttestation } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';

const definition = {
  kind: 'reading@1',
  policy: z.object({}),
  evidence: z.object({}),
  claim: z.object({ value: z.bigint() }),
  verify: () => {},
  message: (claim: { value: bigint }) => [claim.value],
};
const claim = { value: 42n };
const message = definition.message(claim);
const publicKey = jubjubSchnorrVerifyingKey(17n);
const signature = jubjubSchnorrSign(new CompactTypeVector(1, CompactTypeField), message, 17n);
const attestor = { id: 'alice', definition, publicKey, registryIndex: 0 };
const trusted = buildTrustedSet([attestor]);
const attestation = { kind: definition.kind, claim, message, publicKey, signature };
const options = { trusted, attestor, attestation, verifier: jubjubVerifier, expectedClaim: claim };

describe('resolveAttestation', () => {
  it('accepts a valid signature and tags it with its registry slot', async () => {
    await expect(resolveAttestation(options)).resolves.toEqual({ registryIndex: 0, attestation });
  });

  it('accepts an asynchronous scheme verifier', async () => {
    await expect(
      resolveAttestation({
        ...options,
        verifier: {
          verify: async (...args) => jubjubVerifier.verify(...args),
        },
      }),
    ).resolves.toMatchObject({ registryIndex: 0 });
  });

  it('rejects a message inconsistent with the claim even without expectedMessage', async () => {
    await expect(
      resolveAttestation({ ...options, attestation: { ...attestation, message: [43n] } }),
    ).rejects.toMatchObject({ reason: 'message' });
  });

  it('rejects a different expected message', async () => {
    await expect(resolveAttestation({ ...options, expectedMessage: [43n] })).rejects.toMatchObject({
      reason: 'message',
    });
  });

  it('rejects a malformed returned claim', async () => {
    await expect(
      resolveAttestation({
        ...options,
        attestation: { ...attestation, claim: { value: '42' } as never },
      }),
    ).rejects.toMatchObject({ reason: 'claim' });
  });

  it('rejects a malformed signature', async () => {
    await expect(
      resolveAttestation({ ...options, attestation: { ...attestation, signature: {} as never } }),
    ).rejects.toMatchObject({ reason: 'signature' });
  });

  it('rejects a verifier that throws', async () => {
    await expect(
      resolveAttestation({
        ...options,
        verifier: {
          verify: async () => {
            throw new Error('invalid signature encoding');
          },
        },
      }),
    ).rejects.toMatchObject({ reason: 'signature' });
  });

  it('rejects a different public key', async () => {
    await expect(
      resolveAttestation({
        ...options,
        attestation: { ...attestation, publicKey: jubjubSchnorrVerifyingKey(18n) },
      }),
    ).rejects.toMatchObject({ reason: 'public-key' });
  });

  it('rejects an out-of-range registry slot', async () => {
    await expect(
      resolveAttestation({ ...options, attestor: { ...attestor, registryIndex: 1 } }),
    ).rejects.toMatchObject({ reason: 'registry-index' });
  });

  it('rejects a wrong returned claim even with the expected signed message', async () => {
    await expect(
      resolveAttestation({ ...options, attestation: { ...attestation, claim: { value: 43n } } }),
    ).rejects.toMatchObject({ reason: 'claim' });
  });
  it('rejects an off-chain kind different from the descriptor', async () => {
    await expect(
      resolveAttestation({ ...options, attestation: { ...attestation, kind: 'other@1' } }),
    ).rejects.toMatchObject({ reason: 'kind' });
  });
  it('rejects a forged signature with the pinned key and expected message', async () => {
    await expect(
      resolveAttestation({
        ...options,
        attestation: { ...attestation, signature: { ...signature, response: 0n } },
      }),
    ).rejects.toMatchObject({ reason: 'signature', attestorId: 'alice' });
  });
});
