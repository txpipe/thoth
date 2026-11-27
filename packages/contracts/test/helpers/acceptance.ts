// Pieces both cross-seam acceptance suites share: the attestors' Jubjub key
// pair and the submission the bytes mock verifies.
import type { JubjubPoint, JubjubSchnorrSignature } from '@midnight-ntwrk/compact-runtime';
import type { KeyPair } from '@txpipe/thoth-attestor';
import type { B_Claim } from '../../artifacts/mock_attestation_bytes/contract/index.js';
import { makeNotaryKey } from './fixtures.js';
import { signMessage } from './sign.js';
import type { MockAttestationBytesSim } from './sim.js';

/** A Jubjub key pair whose signer signs the flat message the registry verifies. */
export const jubjubKeyPair = (): KeyPair<JubjubPoint, JubjubSchnorrSignature> => {
  const { sk, pk } = makeNotaryKey();
  return { publicKey: pk, signer: { sign: (message) => signMessage(sk, message).signature } };
};

/** A claim and its signatures at their registry slots. */
export type Submission = {
  claim: B_Claim;
  signatures: JubjubSchnorrSignature[];
};

/** Submit `submission` to `verifyAttestation` as the holder of `holderSecret`. */
export const submit = (
  sim: MockAttestationBytesSim,
  submission: Submission,
  holderSecret: Uint8Array,
) => sim.call('verifyAttestation', { ...submission, holderSecret });
