import {
  CompactTypeField,
  CompactTypeVector,
  jubjubSchnorrSign,
  jubjubSchnorrVerifyingKey,
} from '@midnight-ntwrk/compact-runtime';
import { attestorOf, buildTrustedSet, resolveAttestation } from '@thoth/client';
import { AttestorNotInTrustedSetError } from '@thoth/client/errors';
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
const attestor = { id: 'alice', definition, publicKey };
const trusted = buildTrustedSet({ registrySize: 3, attestors: [{ attestor, registryIndex: 2 }] });
const member = attestorOf(trusted, 'alice');
const attestation = { claim, message, publicKey, signature };
const options = { trusted, member, attestation, verifier: jubjubVerifier, expectedClaim: claim };

// Keep the message and its valid signature fixed to isolate claim comparison.
const vetClaim = (expected: unknown, returned: unknown) => {
  const claimDefinition = { ...definition, claim: z.unknown(), message: () => message };
  const claimAttestor = { ...attestor, definition: claimDefinition };
  const claimMember = { attestor: claimAttestor, registryIndex: 2 };
  return resolveAttestation({
    ...options,
    trusted: buildTrustedSet({ registrySize: 3, attestors: [claimMember] }),
    member: claimMember,
    expectedClaim: expected,
    attestation: { ...attestation, claim: returned },
  });
};

describe('resolveAttestation', () => {
  it('accepts a valid signature and tags it with its registry slot', async () => {
    await expect(
      resolveAttestation({ ...options, attestation: structuredClone(attestation) }),
    ).resolves.toEqual({ registryIndex: 2, attestation });
  });

  it.each([
    {
      name: 'nested claims with different object key order',
      expected: { value: 42n, metadata: { present: [true, false], bytes: new Uint8Array([1, 2]) } },
      returned: { metadata: { bytes: new Uint8Array([1, 2]), present: [true, false] }, value: 42n },
    },
    { name: 'null', expected: null, returned: null },
    { name: 'empty arrays', expected: [], returned: [] },
    { name: 'empty objects', expected: {}, returned: {} },
    {
      name: 'undefined-valued own keys',
      expected: { value: undefined },
      returned: { value: undefined },
    },
  ])('accepts equal $name', async ({ expected, returned }) => {
    await expect(vetClaim(expected, returned)).resolves.toMatchObject({ registryIndex: 2 });
  });

  it.each([
    { name: 'primitive types', expected: 42n, returned: '42' },
    { name: 'null and an object', expected: null, returned: {} },
    {
      name: 'different undefined-valued keys',
      expected: { a: undefined },
      returned: { b: undefined },
    },
    { name: 'a missing key', expected: { a: 42n, b: undefined }, returned: { a: 42n } },
    { name: 'an extra key', expected: { a: 42n }, returned: { a: 42n, b: undefined } },
    {
      name: 'nested values',
      expected: { reading: { value: 42n } },
      returned: { reading: { value: 43n } },
    },
    { name: 'byte contents', expected: new Uint8Array([1, 2]), returned: new Uint8Array([1, 3]) },
    { name: 'byte lengths', expected: new Uint8Array([1, 2]), returned: new Uint8Array([1]) },
    { name: 'bytes and an array', expected: new Uint8Array([1, 2]), returned: [1, 2] },
    { name: 'array order', expected: [1n, 2n], returned: [2n, 1n] },
    { name: 'array lengths', expected: [1n, 2n], returned: [1n] },
    { name: 'an array and an object', expected: [42n], returned: { 0: 42n, length: 1 } },
    { name: 'a sparse returned array', expected: [42n], returned: new Array(1) },
    { name: 'a sparse expected array', expected: new Array(1), returned: [42n] },
    { name: 'a hole and explicit undefined', expected: [undefined], returned: new Array(1) },
  ])('rejects claims with $name', async ({ expected, returned }) => {
    await expect(vetClaim(expected, returned)).rejects.toMatchObject({ reason: 'claim' });
  });

  it('accepts an asynchronous scheme verifier', async () => {
    await expect(
      resolveAttestation({
        ...options,
        verifier: {
          verify: async (...args) => jubjubVerifier.verify(...args),
        },
      }),
    ).resolves.toMatchObject({ registryIndex: 2 });
  });

  it.each([
    { name: 'string-to-bigint', schema: z.string().transform(BigInt), input: '42' },
    { name: 'non-idempotent', schema: z.bigint().transform((value) => value + 1n), input: 41n },
  ])('vets parsed claims with a $name transform', async ({ schema, input }) => {
    const transformedDefinition = {
      ...definition,
      claim: z.object({ value: schema }),
    };
    const parsedClaim = transformedDefinition.claim.parse({ value: input });
    const transformedAttestor = { ...attestor, definition: transformedDefinition };
    const transformedMember = { attestor: transformedAttestor, registryIndex: 2 };
    const transformedOptions = {
      ...options,
      trusted: buildTrustedSet({ registrySize: 3, attestors: [transformedMember] }),
      member: transformedMember,
      expectedClaim: parsedClaim,
      attestation: { ...attestation, claim: parsedClaim },
    };

    await expect(resolveAttestation(transformedOptions)).resolves.toMatchObject({
      registryIndex: 2,
    });
    await expect(
      resolveAttestation({
        ...transformedOptions,
        attestation: { ...transformedOptions.attestation, claim: { value: 43n } },
      }),
    ).rejects.toMatchObject({ reason: 'claim' });
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

  it('rejects a member the trusted set never assigned', async () => {
    await expect(
      resolveAttestation({ ...options, member: { attestor, registryIndex: 1 } }),
    ).rejects.toBeInstanceOf(AttestorNotInTrustedSetError);
  });

  it('rejects a slot outside the on-chain registry of an unchecked set', async () => {
    const unchecked = { attestor, registryIndex: 3 };
    await expect(
      resolveAttestation({
        ...options,
        trusted: { registrySize: 3, attestors: [unchecked] },
        member: unchecked,
      }),
    ).rejects.toMatchObject({ reason: 'registry-index' });
  });

  it('rejects a wrong returned claim even with the expected signed message', async () => {
    await expect(
      resolveAttestation({ ...options, attestation: { ...attestation, claim: { value: 43n } } }),
    ).rejects.toMatchObject({ reason: 'claim' });
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

describe('buildTrustedSet', () => {
  const bob = { id: 'bob', definition, publicKey: jubjubSchnorrVerifyingKey(18n) };

  it('keeps each attestor at the slot the app assigned', () => {
    const set = buildTrustedSet({
      registrySize: 5,
      attestors: [
        { attestor, registryIndex: 4 },
        { attestor: bob, registryIndex: 1 },
      ],
    });
    expect(set.registrySize).toBe(5);
    expect(attestorOf(set, 'alice').registryIndex).toBe(4);
    expect(attestorOf(set, 'bob')).toEqual({ attestor: bob, registryIndex: 1 });
  });

  it('bounds slots by the on-chain registry size, not by the set size', () => {
    expect(() =>
      buildTrustedSet({ registrySize: 3, attestors: [{ attestor, registryIndex: 2 }] }),
    ).not.toThrow();
    expect(() =>
      buildTrustedSet({ registrySize: 2, attestors: [{ attestor, registryIndex: 2 }] }),
    ).toThrow(expect.objectContaining({ reason: 'registry-index', attestorId: 'alice' }));
  });

  it.each([-1, 0.5, Number.NaN])('rejects the malformed slot %s', (registryIndex) => {
    expect(() =>
      buildTrustedSet({ registrySize: 3, attestors: [{ attestor, registryIndex }] }),
    ).toThrow(expect.objectContaining({ reason: 'registry-index' }));
  });

  it.each([0, -1, 1.5])('rejects the registry size %s', (registrySize) => {
    expect(() =>
      buildTrustedSet({ registrySize, attestors: [{ attestor, registryIndex: 0 }] }),
    ).toThrow(expect.objectContaining({ reason: 'registry-size' }));
  });

  it('rejects an empty set', () => {
    expect(() => buildTrustedSet({ registrySize: 3, attestors: [] })).toThrow(
      expect.objectContaining({ reason: 'empty' }),
    );
  });

  it('rejects two attestors assigned the same slot', () => {
    expect(() =>
      buildTrustedSet({
        registrySize: 3,
        attestors: [
          { attestor, registryIndex: 1 },
          { attestor: bob, registryIndex: 1 },
        ],
      }),
    ).toThrow(expect.objectContaining({ reason: 'duplicate-slot', attestorId: 'bob' }));
  });

  it('rejects two ids pinning the same public key', () => {
    const alias = { ...bob, publicKey: jubjubSchnorrVerifyingKey(17n) };
    expect(() =>
      buildTrustedSet({
        registrySize: 3,
        attestors: [
          { attestor, registryIndex: 0 },
          { attestor: alias, registryIndex: 1 },
        ],
      }),
    ).toThrow(expect.objectContaining({ reason: 'duplicate-key', attestorId: 'bob' }));
  });

  it('rejects one attestor id pinned twice', () => {
    expect(() =>
      buildTrustedSet({
        registrySize: 3,
        attestors: [
          { attestor, registryIndex: 0 },
          { attestor, registryIndex: 1 },
        ],
      }),
    ).toThrow(expect.objectContaining({ reason: 'duplicate-id', attestorId: 'alice' }));
  });
});
