// Test fixtures: claims, notary keys, and seeded valid signatures over the
// FROZEN message shape (see sign.ts). Zero-filled absent slots are the
// canonical "not present" encoding; `present[i] = true` marks slot i populated.
import { randomBytes } from 'node:crypto';
import type { A_Claim } from '../../artifacts/mock_attestation/contract/index.js';
import { pureCircuits } from '../../artifacts/mock_attestation/contract/index.js';
import type { SchnorrSignature } from './private-state.js';
import { derivePublicKey, type JubjubPoint, signClaim as signSingle } from './sign.js';
import type { SealedConfig } from './witnesses.js';

export const nowSeconds = (): bigint => BigInt(Math.floor(Date.now() / 1000));

const DAY = 86400n;

// The mock's default deploy-time seals: the policy every fixture claim is
// attested under, a 1-day maximum window and a 30-day freshness window.
export const TEST_SEALED: SealedConfig = {
  policyDigest: randomBytes(32),
  maxWindow: DAY,
  freshnessWindow: 30n * DAY,
};

// The holder secret fixture claims are bound to by default.
export const TEST_HOLDER_SECRET = randomBytes(32);

export const holderCommitment = (secret: Uint8Array): Uint8Array =>
  pureCircuits.holderCommitment(secret);

export type NotaryKey = { sk: bigint; pk: JubjubPoint };

export const makeNotaryKey = (): NotaryKey => {
  const sk = BigInt(`0x${Buffer.from(randomBytes(31)).toString('hex')}`) % (1n << 248n);
  return { sk, pk: derivePublicKey(sk) };
};

// Build a valid `Claim` fixture. `values` is the raw vector (length 3 for this
// embedding); `present` marks populated slots (present[i] = true means slot i
// was measured). If any value is `0` it must still be marked present via
// `present[i] = true`. The claim carries the sealed test policy and is bound to
// `TEST_HOLDER_SECRET`.
export const makeClaim = (
  overrides: Partial<Omit<A_Claim, 'values' | 'present'>> & {
    values?: bigint[];
    present?: boolean[];
  } = {},
): A_Claim => {
  const values = overrides.values ?? [12345n, 0n, 0n];
  const present = overrides.present ?? values.map((_, i) => i === 0);
  return {
    version: 1n,
    kind: 1n,
    policyDigest: TEST_SEALED.policyDigest,
    requestBinding: randomBytes(32),
    holder: holderCommitment(TEST_HOLDER_SECRET),
    nonce: randomBytes(32),
    windowStart: nowSeconds() - 60n,
    windowEnd: nowSeconds(),
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
