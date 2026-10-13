// Drive: an attestor operator's zkFetch instance (`@thoth/zk-tls/attestor`) verifying the
// recorded witness evidence and signing the claim it derives, or refusing.
import { jubjubVerifier } from '@thoth/client/jubjub';
import {
  deriveClaimFromEvidence,
  parsedEvidenceView,
  zkFetchPolicyHashOf,
  zkFetchSubjectHashOf,
} from '@thoth/zk-tls';
import { verifyZkFetchProof } from '@thoth/zk-tls/attestor';
import {
  APP_ID,
  attestorNamed,
  evidence,
  HOLDER,
  main,
  OBSERVED_AT,
  policy,
  request,
  VALUE_SLOTS,
} from './common.mjs';

/** `hex` with the nibble at `i` (after `0x`) changed. */
const flipHex = (hex, i) =>
  `${hex.slice(0, i + 2)}${hex[i + 2] === '0' ? '1' : '0'}${hex.slice(i + 3)}`;

/** The claim a client proposes for the evidence: derived, as `@thoth/zk-tls` does. */
const proposal = (overrides = {}) => ({
  ...deriveClaimFromEvidence({
    verified: parsedEvidenceView(evidence),
    policy,
    appId: APP_ID,
    holder: HOLDER,
    valueSlots: VALUE_SLOTS,
    windowStart: OBSERVED_AT,
    windowEnd: OBSERVED_AT + 60n,
  }),
  ...overrides,
});

/** Ask one operator to attest; report what it signed and whether the signature verifies. */
const attest = async (input, attestor = attestorNamed('operator-a')) => {
  const { claim, message, publicKey, signature } = await attestor.attest({
    policy,
    evidence,
    claim: proposal(),
    ...input,
  });
  return {
    attestor: attestor.id,
    claim,
    messageLength: message.length,
    policyHashIsThePolicys: Buffer.from(claim.policyHash).equals(zkFetchPolicyHashOf(policy)),
    subjectHashIsTheRequests: Buffer.from(claim.subjectHash).equals(
      zkFetchSubjectHashOf({ method: request.method, url: request.url, body: '' }),
    ),
    signatureVerifies: await jubjubVerifier.verify(publicKey, message, signature),
  };
};

await main({
  verify: async () => {
    const verified = await verifyZkFetchProof(evidence);
    return {
      witness: evidence.attestorAddress,
      identifier: verified.identifier,
      observedAt: verified.claim.timestampS,
      disclosed: Object.keys(verified.disclosedValues),
    };
  },
  sign: async () => attest({}),
  'tampered-signature': async () =>
    attest({ evidence: { ...evidence, signatureHex: flipHex(evidence.signatureHex, 10) } }),
  'tampered-request': async () =>
    attest({
      evidence: {
        ...evidence,
        claim: {
          ...evidence.claim,
          parameters: evidence.claim.parameters.replace('attestor-core', 'attestor-core-fork'),
        },
      },
    }),
  'other-witness': async () => attest({}, attestorNamed('operator-x', `0x${'11'.repeat(20)}`)),
  'host-not-allowed': async () => attest({ policy: { ...policy, allowedHosts: ['example.com'] } }),
  'required-slot': async () =>
    attest({ policy: { ...policy, slots: [{ slot: 0, name: 'data', parse: 'float' }] } }),
  'window-misses': async () =>
    attest({ claim: proposal({ windowStart: OBSERVED_AT + 1n, windowEnd: OBSERVED_AT + 61n }) }),
  overclaim: async () =>
    attest({ claim: proposal({ present: [true, false, false], values: [42n, 0n, 0n] }) }),
});
