// Test fixtures: claims, notary keys, and seeded valid signatures over the
// FROZEN message shape (see sign.ts). Zero-filled absent slots are the
// canonical "not present" encoding; `present[i] = true` marks numeric slot i
// populated and `bytePresent[j] = true` marks byte slot j populated.
import { randomBytes } from 'node:crypto';
import {
  type JubjubPoint,
  type JubjubSchnorrSignature,
  jubjubSchnorrVerifyingKey,
  sampleJubjubSchnorrSk,
} from '@midnight-ntwrk/compact-runtime';
import type { A_Claim } from '../../artifacts/mock_attestation/contract/index.js';
import { pureCircuits } from '../../artifacts/mock_attestation/contract/index.js';
import type { B_Claim } from '../../artifacts/mock_attestation_bytes/contract/index.js';
import { pureCircuits as bytesPureCircuits } from '../../artifacts/mock_attestation_bytes/contract/index.js';
import { signClaim as signSingle } from './sign.js';

export const nowSeconds = (): bigint => BigInt(Math.floor(Date.now() / 1000));

/** Default mock freshness window: one day after the observation ends. */
export const DEFAULT_FRESHNESS_WINDOW = 86400n;
/** Default mock maximum observation window: five minutes. */
export const DEFAULT_MAX_WINDOW = 300n;

// The app id and the two policy hashes the mock seals at deploy. A second app
// id and a third, unsealed hash stand in for another app's claim and a laxer
// policy a requester might substitute.
const filled = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);
/** Fixed test secret; claim fixtures bind to this caller unless overridden. */
export const DEFAULT_HOLDER_SECRET = new Uint8Array(32).fill(0xc1);
export const APP_ID = filled(0xa1);
export const OTHER_APP_ID = filled(0xa2);
export const POLICY_A = filled(0xb1);
export const POLICY_B = filled(0xb2);
export const UNSEALED_POLICY = filled(0xbf);
export const ACCEPTED_POLICIES: readonly Uint8Array[] = [POLICY_A, POLICY_B];

export type NotaryKey = { sk: bigint; pk: JubjubPoint };

export const makeNotaryKey = (): NotaryKey => {
  const sk = sampleJubjubSchnorrSk();
  return { sk, pk: jubjubSchnorrVerifyingKey(sk) };
};

/** UTF-8 encode `value` and zero-pad it to 32 bytes (the `'bytes'` parse rule). */
export const padded32 = (value: string): Uint8Array => {
  const bytes = new TextEncoder().encode(value);
  if (bytes.length > 32) {
    throw new Error(`padded32: value is ${bytes.length} bytes, over the 32-byte limit`);
  }
  const padded = new Uint8Array(32);
  padded.set(bytes);
  return padded;
};

/** Default byte value fixture: `"abc"` zero-padded to 32 bytes. */
export const DEFAULT_BYTE_VALUE = padded32('abc');

// Build a valid numeric-only `Claim` fixture (length 3 for this embedding);
// `present` marks populated slots (present[i] = true means slot i was
// measured). If any value is `0` it must still be marked present via
// `present[i] = true`.
export const makeClaim = (
  overrides: Partial<Omit<A_Claim, 'values' | 'present' | 'bytePresent' | 'byteValues'>> & {
    values?: bigint[];
    present?: boolean[];
  } = {},
): A_Claim => {
  const values = overrides.values ?? [12345n, 0n, 0n];
  const present = overrides.present ?? values.map((_, i) => i === 0);
  return {
    version: 1n,
    appId: APP_ID,
    policyHash: POLICY_A,
    windowStart: nowSeconds() - 10n,
    windowEnd: nowSeconds(),
    subjectHash: randomBytes(32),
    holder: pureCircuits.holderCommitment(DEFAULT_HOLDER_SECRET),
    salt: randomBytes(32),
    values,
    present,
    bytePresent: [],
    byteValues: [],
    ...overrides,
  };
};

// Build a valid one-byte-value `Claim` fixture for the bytes mock (V = 3,
// W = 1), with the byte slot measured.
export const makeByteClaim = ({
  byteValue = DEFAULT_BYTE_VALUE,
  ...overrides
}: Partial<B_Claim> & { byteValue?: Uint8Array } = {}): B_Claim => ({
  version: 1n,
  appId: APP_ID,
  policyHash: POLICY_A,
  windowStart: nowSeconds() - 10n,
  windowEnd: nowSeconds(),
  subjectHash: randomBytes(32),
  holder: bytesPureCircuits.holderCommitment(DEFAULT_HOLDER_SECRET),
  salt: randomBytes(32),
  present: [true, false, false],
  bytePresent: [true],
  values: [12345n, 0n, 0n],
  byteValues: [byteValue],
  ...overrides,
});

// A copy of `bytes` with byte `i` inverted. Throws on an out-of-range index,
// which a typed array would otherwise ignore, leaving the copy unchanged.
export const flip = (bytes: Uint8Array, i: number): Uint8Array => {
  const byte = bytes[i];
  if (byte === undefined) {
    throw new RangeError(`flip: index ${i} out of range for ${bytes.length} bytes`);
  }
  const copy = Uint8Array.from(bytes);
  copy[i] = byte ^ 0xff;
  return copy;
};

export type SignedClaim = {
  claim: A_Claim;
  signatures: JubjubSchnorrSignature[]; // valid sigs for the keys given; absent slot = dummy (never verifies)
};

// Dummy signature for an empty slot: identity announcement, zero response —
// it can never verify against a non-empty registry slot.
export const DUMMY_SIGNATURE: JubjubSchnorrSignature = {
  announcement: { x: 0n, y: 1n },
  response: 0n,
};

// Sign a claim with the given notary keys. A `null` key yields the dummy
// signature, which never verifies.
export const signClaim = (claim: A_Claim, keys: readonly (NotaryKey | null)[]): SignedClaim => {
  const signatures: JubjubSchnorrSignature[] = keys.map((key) =>
    key === null ? DUMMY_SIGNATURE : signSingle(key.sk, claim).signature,
  );
  return { claim, signatures };
};

/** The nullifier the numeric mock vaults `claim` under. */
export const nullifierOfClaim = (claim: A_Claim): Uint8Array => pureCircuits.nullifierOf(claim);

/** The nullifier the bytes mock vaults `claim` under. */
export const nullifierOfByteClaim = (claim: B_Claim): Uint8Array =>
  bytesPureCircuits.nullifierOf(claim);

export const holderOf = (secret: Uint8Array): bigint => pureCircuits.holderOf(secret);
