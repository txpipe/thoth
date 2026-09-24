// Off-chain Jubjub-Schnorr signing with exact in-circuit parity.
//
// Mirrors the contract's verify path (schnorr.compact + attestation.compact):
//   msg  = the flat Vector<K, Field> being committed to (produced by
//          pureCircuits.message(claim) or the off-chain claimToMessage)
//   c    = pureCircuits.schnorrChallenge(ann, pk, msg) — Poseidon challenge;
//          the in-circuit `truncateChallenge` reduces it mod 2^248 (the
//          getSchnorrReduction witness supplies q, r). We reproduce the same
//          reduction here: c = cFull % 2^248.
//   s    = (k + c*sk) % JUBJUB_ORDER
//   signature = { announcement: k*G, response: s }
//
// The message is computed with the contract's own compiled pure circuit
// (`pureCircuits.message`), or supplied directly (e.g. from
// `@thoth/core/claim`'s `claimToMessage`) — never a hand-rolled encoding — so
// a signature produced here must verify in-circuit.
import { createHash } from 'node:crypto';
import { ecAdd, ecMul, ecMulGenerator } from '@midnight-ntwrk/compact-runtime';
import { type A_Claim, pureCircuits } from '../../artifacts/mock_attestation/contract/index.js';
import type { SchnorrSignature } from './private-state.js';

export const JUBJUB_ORDER = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7n;
export const TWO_248 = 1n << 248n;

export type JubjubPoint = { x: bigint; y: bigint };

// Deterministic k for reproducible fixtures; production notaries use a CSPRNG.
const hashToScalar = (seed: string): bigint => {
  const digest = createHash('sha256').update(seed, 'utf-8').digest();
  const k = BigInt(`0x${digest.toString('hex')}`) % (JUBJUB_ORDER - 1n);
  return k + 1n;
};

export const derivePublicKey = (sk: bigint): JubjubPoint => ecMulGenerator(sk);

/**
 * Sign an arbitrary flat message with the given secret key.
 *
 * The message is used as-is (not re-derived from a claim), so callers can sign
 * a message produced by `claimToMessage` (the off-chain encoder) and verify it
 * against the contract's own `buildMessage`.
 *
 * @param sk — the secret key.
 * @param msg — the flat message to commit to.
 * @param kSeed — deterministic nonce seed for reproducible fixtures.
 * @returns the derived public key plus the Schnorr signature over `msg`.
 */
export const signMessage = (
  sk: bigint,
  msg: readonly bigint[],
  kSeed = sk.toString(16),
): { pk: JubjubPoint; signature: SchnorrSignature } => {
  const pk = derivePublicKey(sk);
  const k = hashToScalar(kSeed);
  const announcement = ecMulGenerator(k);
  const cFull = pureCircuits.schnorrChallenge(announcement.x, announcement.y, pk.x, pk.y, [...msg]);
  const c = cFull % TWO_248;
  const response = (k + c * sk) % JUBJUB_ORDER;
  return { pk, signature: { announcement, response } };
};

export const signClaim = (
  sk: bigint,
  claim: A_Claim,
  kSeed = sk.toString(16),
): { pk: JubjubPoint; signature: SchnorrSignature } =>
  signMessage(sk, pureCircuits.message(claim), kSeed);

/**
 * Verify a Schnorr signature off-chain, mirroring `schnorrVerifyOk`:
 * `response·G == announcement + c·pk`, with `c` truncated to 248 bits.
 *
 * @param pk — the signer's public key.
 * @param msg — the signed flat message.
 * @param signature — the signature to check.
 * @returns whether the signature verifies.
 */
export const verifyMessage = (
  pk: JubjubPoint,
  msg: readonly bigint[],
  signature: SchnorrSignature,
): boolean => {
  const { announcement, response } = signature;
  const c =
    pureCircuits.schnorrChallenge(announcement.x, announcement.y, pk.x, pk.y, [...msg]) % TWO_248;
  const lhs = ecMulGenerator(response);
  const rhs = ecAdd(announcement, ecMul(pk, c));
  return lhs.x === rhs.x && lhs.y === rhs.y;
};
