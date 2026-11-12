// Fixed Jubjub key pairs for the test app's attestors, so its config can pin
// their public keys. Never use them to protect real value.
import { createHash } from 'node:crypto';
import {
  CompactTypeField,
  CompactTypeVector,
  type JubjubPoint,
  type JubjubSchnorrSignature,
  jubjubSchnorrSign,
  jubjubSchnorrVerifyingKey,
} from '@midnight-ntwrk/compact-runtime';

export const devKeyPair = (i: number) => {
  const digest = createHash('sha256').update(`thoth-cli-test-attestor:${i}`).digest('hex');
  const sk = BigInt(`0x${digest}`) % (1n << 248n);
  const publicKey: JubjubPoint = jubjubSchnorrVerifyingKey(sk);
  return {
    publicKey,
    signer: {
      sign: (message: readonly bigint[]): JubjubSchnorrSignature =>
        jubjubSchnorrSign(
          new CompactTypeVector(message.length, CompactTypeField),
          [...message],
          sk,
        ),
    },
  };
};
