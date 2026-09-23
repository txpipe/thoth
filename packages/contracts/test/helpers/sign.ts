// Off-chain Jubjub-Schnorr signing via the runtime's `jubjubSchnorrSign`, the
// counterpart of the stdlib `jubjubSchnorrVerify` the registry counts with
// (same pinned compact-runtime version ⇒ same challenge hash and reduction).
//
// The message is computed with the contract's own compiled pure circuit
// (`pureCircuits.message`), or supplied directly (e.g. from
// `@thoth/core/claim`'s `claimToMessage`) — never a hand-rolled encoding — so
// a signature produced here must verify in-circuit.
import {
  CompactTypeField,
  CompactTypeVector,
  type JubjubPoint,
  type JubjubSchnorrSignature,
  jubjubSchnorrSign,
  jubjubSchnorrVerifyingKey,
} from '@midnight-ntwrk/compact-runtime';
import { type A_Claim, pureCircuits } from '../../artifacts/mock_attestation/contract/index.js';

/**
 * Sign an arbitrary flat message with the given secret key.
 *
 * The message is used as-is (not re-derived from a claim), so callers can sign
 * a message produced by `claimToMessage` (the off-chain encoder) and verify it
 * against the contract's own `buildMessage`.
 *
 * @param sk — the Jubjub scalar signing key.
 * @param msg — the flat message to commit to.
 * @returns the derived public key plus the Schnorr signature over `msg`.
 */
export const signMessage = (
  sk: bigint,
  msg: readonly bigint[],
): { pk: JubjubPoint; signature: JubjubSchnorrSignature } => ({
  pk: jubjubSchnorrVerifyingKey(sk),
  signature: jubjubSchnorrSign(new CompactTypeVector(msg.length, CompactTypeField), [...msg], sk),
});

export const signClaim = (
  sk: bigint,
  claim: A_Claim,
): { pk: JubjubPoint; signature: JubjubSchnorrSignature } =>
  signMessage(sk, pureCircuits.message(claim));
