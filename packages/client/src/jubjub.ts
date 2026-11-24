// Jubjub Schnorr verification over flat messages, on the Compact runtime the contracts pin.
import {
  CompactTypeField,
  CompactTypeVector,
  type JubjubPoint,
  type JubjubSchnorrSignature,
  jubjubSchnorrVerify,
  MAX_JUBJUB_SCALAR,
} from '@midnight-ntwrk/compact-runtime';
import type { FlatMessage } from '@thoth/core/claim';
import type { AttestationVerifier } from './index.js';

/**
 * Verify flat-message Jubjub Schnorr signatures with Compact runtime 0.21.0,
 * the version the contracts pin. A malformed key, message or signature fails
 * verification instead of throwing, and so does a response outside the Jubjub
 * scalar range, which the contract's signature witness rejects. The challenge
 * hashes the message's field elements in order, as the contract's registry
 * hashes its `SignedMessage`, so over `claimToMessage(claim)` it checks the
 * equation the contract checks for that claim.
 */
export const jubjubVerifier: AttestationVerifier<JubjubPoint, JubjubSchnorrSignature, FlatMessage> =
  {
    verify(publicKey, message, signature) {
      try {
        // The runtime reduces the response, so it alone would accept
        // `response + order`, a value the contract cannot take.
        if (signature.response < 0n || signature.response > MAX_JUBJUB_SCALAR) {
          return false;
        }
        return jubjubSchnorrVerify(
          new CompactTypeVector(message.length, CompactTypeField),
          [...message],
          publicKey,
          signature,
        );
      } catch {
        return false;
      }
    },
  };
