// Jubjub Schnorr verification over flat messages, on the Compact runtime the contracts pin.
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
 * Verify flat-message Jubjub Schnorr signatures with Compact runtime 0.21.0,
 * the version the contracts pin. A malformed key, message or signature fails
 * verification instead of throwing.
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
