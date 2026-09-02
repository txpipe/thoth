// Test fixtures: claims, notary keys, and seeded valid signatures over the
// FROZEN message shape (see sign.ts). Zero-filled absent slots are the
// canonical "not present" encoding; `present` bits mark populated slots.
import { randomBytes } from 'node:crypto';
import type { A_Claim } from '../../artifacts/mock_attestation/contract/index.js';
import { pureCircuits } from '../../artifacts/mock_attestation/contract/index.js';
import type { SchnorrSignature } from './private-state.js';
import { derivePublicKey, type JubjubPoint, signClaim as signSingle } from './sign.js';

export const nowSeconds = (): bigint => BigInt(Math.floor(Date.now() / 1000));

export type NotaryKey = { sk: bigint; pk: JubjubPoint };

export const makeNotaryKey = (): NotaryKey => {
  const sk = BigInt(`0x${Buffer.from(randomBytes(31)).toString('hex')}`) % (1n << 248n);
  return { sk, pk: derivePublicKey(sk) };
};

// Build a valid `Claim` fixture. `values` is the raw vector (length 3 for this
// embedding); `present` is the bitmask (bit i = slot i populated). If any value
// is `0` it must still be marked present via `present`.
export const makeClaim = (
  overrides: Partial<Omit<A_Claim, 'values' | 'present'>> & {
    values?: bigint[];
    present?: bigint;
  } = {},
): A_Claim => {
  const values = overrides.values ?? [12345n, 0n, 0n];
  const present = overrides.present ?? (values.length > 0 ? 0b001n : 0n);
  return {
    version: 1n,
    kind: 1n,
    timestamp: nowSeconds(),
    nonce: randomBytes(32),
    evidenceHash: randomBytes(32),
    values,
    present,
    ...overrides,
  };
};

export type SignedClaim = {
  claim: A_Claim;
  signatures: SchnorrSignature[]; // valid sigs for the keys given; absent slot = dummy (never verifies)
  commitRand: Uint8Array;
};

// Dummy signature for an empty slot: identity announcement, zero response —
// it can never verify against a non-empty registry slot.
const DUMMY_SIGNATURE: SchnorrSignature = {
  announcement: { x: 0n, y: 1n },
  response: 0n,
};

// Sign a claim with the given notary keys. A `null` key yields the dummy
// signature, which never verifies.
export const signClaim = (
  claim: A_Claim,
  keys: readonly (NotaryKey | null)[],
  commitRand: Uint8Array,
): SignedClaim => {
  const signatures: SchnorrSignature[] = keys.map((key, i) =>
    key === null ? DUMMY_SIGNATURE : signSingle(key.sk, claim, `${claim.nonce[0]}-${i}`).signature,
  );
  return { claim, signatures, commitRand };
};

export const idOf = (claim: A_Claim, rand: Uint8Array): Uint8Array =>
  pureCircuits.computeId(claim, rand);

export const holderOf = (secret: Uint8Array): bigint => pureCircuits.holderOf(secret);
