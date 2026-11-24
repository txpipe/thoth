// Off-chain Jubjub-Schnorr signing via the runtime's `jubjubSchnorrSign`, the
// counterpart of the registry's Schnorr check (`verifySignature`). Both hash
// (R, pk, msg) identically and reduce the challenge mod the Jubjub order. The
// simulator tests exercise this end to end.
//
// A claim is signed over `@thoth/core/claim`'s `claimToMessage`, the seven
// fields an attestor signs — never a hand-rolled encoding. The contract's
// `buildMessage` returns the same message as a struct, which the registry's
// challenge absorbs as those seven fields, so a signature produced here must
// verify in-circuit.
import {
  CompactTypeField,
  CompactTypeVector,
  type JubjubPoint,
  type JubjubSchnorrSignature,
  jubjubSchnorrSign,
  jubjubSchnorrVerifyingKey,
} from '@midnight-ntwrk/compact-runtime';
import { type Claim, claimToMessage } from '@thoth/core/claim';
import type { A_Claim } from '../../artifacts/mock_attestation/contract/index.js';
import type { B_Claim } from '../../artifacts/mock_attestation_bytes/contract/index.js';

/**
 * Sign an arbitrary flat message with the given secret key.
 *
 * The message is used as-is (not re-derived from a claim), so callers can sign
 * a message the contract must reject, such as one for another layout.
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

/**
 * A mock's contract claim as the kind-facing core claim: one `present` mask,
 * the numeric slots' flags, then the byte slots'.
 */
export const coreOf = (claim: A_Claim | B_Claim): Claim<number, number> => ({
  ...claim,
  present: [...claim.present, ...claim.bytePresent],
});

/** The message an attestor signs for a mock's contract claim. */
export const messageOf = (claim: A_Claim | B_Claim): bigint[] => [...claimToMessage(coreOf(claim))];

export const signClaim = (
  sk: bigint,
  claim: A_Claim | B_Claim,
): { pk: JubjubPoint; signature: JubjubSchnorrSignature } => signMessage(sk, messageOf(claim));
