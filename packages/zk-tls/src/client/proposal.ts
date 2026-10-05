// Per-attestor steps shared by `proveReq` and `collect`.

import { resolveAttestation } from '@thoth/client';
import type { AttestorDescriptor } from '@thoth/core';
import type { Claim } from '@thoth/core/claim';
import { claimSchema } from '@thoth/core/claim';
import type { ZkFetchDefinition, ZkFetchEvidence, ZkFetchPolicy } from '../index.js';
import {
  assertEvidenceMatchesPolicy,
  claimUrl,
  deriveClaimFromEvidence,
  parsedEvidenceView,
  zkFetchEvidenceSchema,
} from '../index.js';
import type {
  ZkFetchAttestationInput,
  ZkFetchClientConfig,
  ZkFetchCollectedAttestation,
  ZkFetchRequest,
} from './index.js';

/**
 * The URL the signed evidence attests is the one the request asked for.
 *
 * A prover returns canonical evidence for the interaction it witnessed; this
 * keeps that evidence honest against the caller's request before any
 * attestation is collected. Origin (scheme + host + port) is compared, so a
 * redirect or a differing path still passes, while a mismatched host is
 * caught early.
 *
 * @param evidence — canonical evidence from the prover.
 * @param request — what the caller asked the client to prove.
 * @throws if the evidence attests a different origin than requested.
 */
const assertEvidenceMatchesRequest = (evidence: ZkFetchEvidence, request: ZkFetchRequest): void => {
  const asked = new URL(request.url).origin;
  const attested = new URL(claimUrl(evidence.claim)).origin;
  if (asked !== attested) {
    throw new Error(`prover returned evidence for ${attested}, not the requested ${asked}`);
  }
};

/**
 * Build the claim proposal the client sends to every attestor.
 *
 * Runs the policy check and derives the canonical claim. The client
 * deliberately does **not** re-verify the Reclaim ECDSA signature, and each
 * pinned attestor verifies the evidence before signing.
 * Because the claim is deterministic in the evidence, the
 * proposal is byte-identical to what each attestor will sign, so
 * `resolveAttestation` can vet each returned message against the message
 * derived from this claim.
 *
 * @typeParam V — the claim's value-slot count (the dApp contract's `#V`).
 * @param options — the evidence, the shared policy, the app id, the slot
 *   count, and the observation window every witness's evidence falls in.
 * @returns the claim to propose (and to submit, once collected).
 * @throws if the evidence is invalid, fails the policy, or does not fit the
 *   dApp's claim length.
 */
export const buildClaimProposal = async <V extends number>(options: {
  /** The evidence to attest (as produced by the prover). */
  evidence: ZkFetchEvidence;
  /** The shared policy every attestor in the set enforces. */
  policy: ZkFetchPolicy;
  /** The app the claim is for. */
  appId: Uint8Array;
  /** Per-claim holder commitment, supplied by the caller. */
  holder: Uint8Array;
  /** The claim's value-slot count (the target contract's `#V`). */
  valueSlots: V;
  /** Start of the window to sign: the earliest observation across the witnesses. */
  windowStart: bigint;
  /** End of the window to sign: the latest observation across the witnesses. */
  windowEnd: bigint;
}): Promise<Claim<V>> => {
  const { evidence, policy, appId, holder, valueSlots, windowStart, windowEnd } = options;
  const verified = parsedEvidenceView(evidence);
  assertEvidenceMatchesPolicy(verified, policy);
  const derived = deriveClaimFromEvidence({
    verified,
    policy,
    appId,
    holder,
    valueSlots,
    windowStart,
    windowEnd,
  });
  return claimSchema(valueSlots).parse(derived);
};

/**
 * Copy a request so that whoever holds the copy cannot change the original's
 * secret headers.
 *
 * @param request — the request to copy.
 * @returns a shallow copy with its own `secretHeaders` record.
 */
export const copyRequest = (request: ZkFetchRequest): ZkFetchRequest => ({
  ...request,
  secretHeaders: { ...request.secretHeaders },
});

/**
 * Prove `request` with the attestor's own witness and check the evidence.
 *
 * The prover gets its own copy, so it cannot change the request that other
 * provers or the secret header check read.
 *
 * @typeParam PK — the signature scheme's public-key type.
 * @param provers — evidence source per attestor id.
 * @param attestor — whose witness to use.
 * @param request — what the caller asked the client to prove.
 * @returns canonical evidence for the requested origin.
 * @throws if the attestor has no prover, the evidence is invalid or for
 *   another origin, or it carries a secret header value
 *   ({@link SecretHeaderError}).
 */
export const proveWith = async <PK>(
  provers: ZkFetchClientConfig<number, PK, unknown>['provers'],
  attestor: AttestorDescriptor<ZkFetchDefinition, PK>,
  request: ZkFetchRequest,
): Promise<ZkFetchEvidence> => {
  const prover = provers[attestor.id];
  if (prover === undefined) {
    throw new Error(`no prover configured for attestor ${attestor.id}`);
  }
  const evidence = zkFetchEvidenceSchema.parse(await prover.prove(copyRequest(request)));
  assertEvidenceMatchesRequest(evidence, request);
  assertNoSecretHeaders(evidence, request);
  return evidence;
};

/**
 * Ask one attestor to sign `claim` and vet the returned attestation.
 *
 * @typeParam V — the claim's value-slot count.
 * @typeParam PK — the signature scheme's public-key type.
 * @typeParam S — the signature scheme's signature type.
 * @param config — the trusted set, transport, verifier, and shared policy.
 * @param attestor — the attestor to ask.
 * @param evidence — that attestor's witness evidence.
 * @param claim — the claim proposal it must sign.
 * @returns the attestation, tagged with the attestor's registry slot.
 * @throws `AttestationMismatchError` if the key, claim, message, or signature is wrong.
 */
export const attestWith = async <V extends number, PK, S>(
  config: Pick<ZkFetchClientConfig<V, PK, S>, 'trusted' | 'transport' | 'verifier' | 'policy'>,
  attestor: AttestorDescriptor<ZkFetchDefinition, PK>,
  evidence: ZkFetchEvidence,
  claim: Claim<V>,
): Promise<ZkFetchCollectedAttestation<V, PK, S>> => {
  const { trusted, transport, verifier, policy } = config;
  // The attestor is the law: it re-parses these with its own schemas, which
  // accept the already-parsed (superset) shapes. The schemas' *input* types
  // are the looser pre-parse form, so the payload is bridged here.
  const input = { policy, evidence, claim } as unknown as ZkFetchAttestationInput;
  const attestation = await transport.request(attestor, input);
  return resolveAttestation({ trusted, attestor, attestation, verifier, expectedClaim: claim });
};

/** Whether a value carries a secret anywhere, including inside JSON-encoded strings. */
const containsSecret = (value: unknown, secrets: readonly string[]): boolean => {
  if (typeof value === 'string') {
    if (secrets.some((secret) => value.includes(secret))) {
      return true;
    }
    // Decoding catches escaped forms such as `private`.
    try {
      return containsSecret(JSON.parse(value), secrets);
    } catch {
      return false;
    }
  }
  if (typeof value === 'object' && value !== null) {
    return Object.entries(value).some(
      ([key, field]) => containsSecret(key, secrets) || containsSecret(field, secrets),
    );
  }
  return false;
};

/**
 * The evidence carried a secret header value. Carries no value itself, so it
 * is safe to surface to a caller.
 */
export class SecretHeaderError extends Error {
  constructor() {
    super('evidence carries a secret header value');
    this.name = 'SecretHeaderError';
  }
}

/**
 * The evidence carries no secret header value, before it goes to an attestor.
 *
 * Catches each value as written, percent-encoded (as echoed into a URL), and
 * JSON-escaped. A prover must still redact; no check can recognize every
 * transformation of a secret.
 *
 * @param evidence — canonical evidence from the prover.
 * @param request — the request whose `secretHeaders` must stay private.
 * @throws {@link SecretHeaderError} if the evidence carries a secret header value.
 */
const assertNoSecretHeaders = (evidence: ZkFetchEvidence, request: ZkFetchRequest): void => {
  const secrets = Object.values(request.secretHeaders ?? {})
    .filter(Boolean)
    .flatMap((secret) => [secret, encodeURIComponent(secret)]);
  if (containsSecret(evidence, secrets)) {
    throw new SecretHeaderError();
  }
};
