// Shared Jubjub-Schnorr test signing helpers using `@midnight-ntwrk/compact-runtime`.
import {
  CompactTypeField,
  CompactTypeVector,
  type JubjubPoint,
  type JubjubSchnorrSignature,
  jubjubSchnorrSign,
  jubjubSchnorrVerifyingKey,
  sampleJubjubSchnorrSk,
} from '@midnight-ntwrk/compact-runtime';

/** Structural Jubjub key pair matching `@txpipe/thoth-attestor`'s `KeyPair`. */
export interface JubjubKeyPair {
  readonly publicKey: JubjubPoint;
  readonly signer: {
    sign(message: readonly bigint[]): JubjubSchnorrSignature;
  };
}

/** Sign a flat field message with the given Jubjub scalar secret key. */
export const signJubjubMessage = (sk: bigint, message: readonly bigint[]): JubjubSchnorrSignature =>
  jubjubSchnorrSign(new CompactTypeVector(message.length, CompactTypeField), [...message], sk);

/**
 * Build a Jubjub test key pair whose signer signs flat messages verified by
 * `attestor_registry.compact`. Samples a random scalar when `sk` is omitted.
 */
export const jubjubKeyPair = (sk: bigint = sampleJubjubSchnorrSk()): JubjubKeyPair => ({
  publicKey: jubjubSchnorrVerifyingKey(sk),
  signer: { sign: (message) => signJubjubMessage(sk, message) },
});
