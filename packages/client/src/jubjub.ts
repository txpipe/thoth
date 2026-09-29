// Jubjub verification matching the contracts' pinned Compact runtime.
import {
  CompactTypeField,
  CompactTypeVector,
  type JubjubPoint,
  type JubjubSchnorrSignature,
  jubjubSchnorrVerify,
} from '@midnight-ntwrk/compact-runtime';
import type { FlatMessage } from '@thoth/core/claim';
import type { AttestationVerifier } from './index.js';

/**
 * Verify flat-message Jubjub Schnorr signatures with Compact runtime 0.19.0.
 * Malformed keys, messages, or signatures fail verification.
 * @see AttestationVerifier
 */
export const jubjubVerifier: AttestationVerifier<JubjubPoint, JubjubSchnorrSignature, FlatMessage> =
  {
    verify(publicKey, message, signature) {
      try {
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
