// Per-attestor steps shared by `proveReq` and `collect`.

import { isDeepStrictEqual } from 'node:util';
import type { TrustedAttestor } from '@txpipe/thoth-client';
import { resolveAttestation } from '@txpipe/thoth-client';
import type { AttestorDescriptor } from '@txpipe/thoth-core';
import type { Claim } from '@txpipe/thoth-core/claim';
import { bytes32Schema, claimSchema } from '@txpipe/thoth-core/claim';
import { z } from 'zod';
import type {
  ZkFetchDefinition,
  ZkFetchEvidence,
  ZkFetchPolicy,
  ZkFetchSubjectRequest,
} from '../index.js';
import {
  assertEvidenceMatchesPolicy,
  assertObservationInWindow,
  claimRequestOf,
  claimUrl,
  deriveClaimFromEvidence,
  parsedEvidenceView,
  signedClaimContextDigestOf,
  ZK_FETCH_CLAIM_CONTEXT_KEY,
  zkFetchClaimContextDigestOf,
  zkFetchEvidenceSchema,
  zkFetchSubjectHashOf,
} from '../index.js';
import { ZkFetchProverError } from '../prover-error.js';
import type {
  ZkFetchAttestationInput,
  ZkFetchClientConfig,
  ZkFetchCollectedAttestation,
  ZkFetchProveOptions,
  ZkFetchRequest,
} from './index.js';

// The claim's window is `Uint<32>`, so a wider value could never be encoded.
// Refusing it here reports it as bad options instead of after every witness
// has proved.
const MAX_WINDOW = 2n ** 32n - 1n;

/** The fields of {@link ZkFetchProveOptions}, shared with the `collect` options schema. */
export const proveOptionsShape = {
  holder: bytes32Schema,
  windowStart: z.bigint().nonnegative().max(MAX_WINDOW),
  windowEnd: z.bigint().nonnegative().max(MAX_WINDOW),
};

/**
 * The reasons a prover can report. A JS prover can set any `reason` at
 * runtime, so only these count.
 */
const PROVER_REASONS: ReadonlySet<string> = new Set<ZkFetchProverError['reason']>([
  'transport',
  'no-match',
]);

/** Whether a window starts no later than it ends. */
export const windowInOrder = (window: { windowStart: bigint; windowEnd: bigint }): boolean =>
  window.windowStart <= window.windowEnd;

/** The subject a prover signs for `request`: method and body default the way it sends them. */
const signedSubjectOf = (request: ZkFetchRequest): ZkFetchSubjectRequest => ({
  method: request.method ?? 'GET',
  url: request.url,
  body: request.body ?? '',
});

/**
 * Require the evidence to attest the request asked for: its origin (scheme,
 * host, port) and its subject (method, path, query, body). The claim context
 * digest covers the subject, so evidence for another one would be refused by
 * every attestor.
 *
 * @throws if the evidence attests another origin or subject, or its signed
 *   parameters carry no request.
 */
const assertEvidenceMatchesRequest = (evidence: ZkFetchEvidence, request: ZkFetchRequest): void => {
  const asked = new URL(request.url).origin;
  const attested = new URL(claimUrl(evidence.claim)).origin;
  if (asked !== attested) {
    throw new Error(`prover returned evidence for ${attested}, not the requested ${asked}`);
  }
  if (
    !isDeepStrictEqual(
      zkFetchSubjectHashOf(claimRequestOf(evidence.claim)),
      zkFetchSubjectHashOf(signedSubjectOf(request)),
    )
  ) {
    throw new Error('prover returned evidence for another method, path or body than requested');
  }
};

/**
 * Require the evidence to carry the claim context digest the request bound, so
 * a prover cannot hand back evidence signed for another holder or window. This
 * compares the client's own value; recomputing the digest stays the attestor's
 * job.
 *
 * @throws if the evidence's signed context is not JSON, or carries no digest
 *   or another one.
 */
const assertEvidenceMatchesClaimContext = (
  evidence: ZkFetchEvidence,
  request: ZkFetchRequest,
): void => {
  if (
    signedClaimContextDigestOf(evidence.claim) !== request.context?.[ZK_FETCH_CLAIM_CONTEXT_KEY]
  ) {
    throw new Error('prover returned evidence for another claim context than requested');
  }
};

/**
 * Build the claim proposal the client sends to every attestor.
 *
 * The claim is deterministic in the evidence, so the proposal is what each
 * attestor signs and `resolveAttestation` can check each answer against it.
 * The client does not re-verify the witness signature; each attestor does.
 *
 * @throws if the evidence is invalid, fails the policy, was observed outside
 *   the window, or does not fit the requested slot counts.
 */
export const buildClaimProposal = async <V extends number>(options: {
  evidence: ZkFetchEvidence;
  policy: ZkFetchPolicy;
  /** 32 bytes. */
  appId: Uint8Array;
  /** Per-claim holder commitment, 32 bytes. */
  holder: Uint8Array;
  /** The contract's `#V`. */
  valueSlots: V;
  /** Half the contract's `#B`. Defaults to `0`. */
  byteSlots?: number;
  /** Unix seconds. */
  windowStart: bigint;
  /** Unix seconds. */
  windowEnd: bigint;
}): Promise<Claim<V, number>> => {
  const {
    evidence,
    policy,
    appId,
    holder,
    valueSlots,
    byteSlots = 0,
    windowStart,
    windowEnd,
  } = options;
  const verified = parsedEvidenceView(evidence);
  assertEvidenceMatchesPolicy(verified, policy);
  const derived = deriveClaimFromEvidence({
    verified,
    policy,
    appId,
    holder,
    valueSlots,
    byteSlots,
    windowStart,
    windowEnd,
  });
  // Every attestor refuses it anyway; checking here fails before any attestor is contacted.
  assertObservationInWindow({ claim: derived, verified });
  return claimSchema(valueSlots, byteSlots).parse(derived);
};

/**
 * Copy a request with its own headers, `context` and disclosure rules, so a
 * prover cannot change the original's headers or claim context digest, or the
 * policy's rules, which the request's rule objects may be.
 */
export const copyRequest = (request: ZkFetchRequest): ZkFetchRequest => ({
  ...request,
  publicHeaders: request.publicHeaders && { ...request.publicHeaders },
  secretHeaders: { ...request.secretHeaders },
  context: request.context && { ...request.context },
  responseMatches: request.responseMatches?.map((match) => ({ ...match })),
  responseRedactions: request.responseRedactions?.map((redaction) => ({ ...redaction })),
});

/**
 * Return the request with the policy's disclosure rules, so every witness
 * signs the rules the policy hash commits to.
 *
 * @throws if the request carries disclosure rules other than the policy's.
 */
export const bindRequestToPolicy = (
  request: ZkFetchRequest,
  policy: ZkFetchPolicy,
): ZkFetchRequest => {
  if (
    request.responseMatches !== undefined &&
    !isDeepStrictEqual(request.responseMatches, policy.responseMatches)
  ) {
    throw new Error('request responseMatches do not match the policy');
  }
  if (
    request.responseRedactions !== undefined &&
    !isDeepStrictEqual(request.responseRedactions, policy.responseRedactions)
  ) {
    throw new Error('request responseRedactions do not match the policy');
  }
  return {
    ...copyRequest(request),
    responseMatches: [...policy.responseMatches],
    responseRedactions: [...policy.responseRedactions],
  };
};

/**
 * Return the request with the claim context digest in its context, so every
 * witness signs the holder and window its evidence is for.
 *
 * @throws if the request's context already sets {@link ZK_FETCH_CLAIM_CONTEXT_KEY}, its URL
 *   does not parse, the policy fails `zkFetchPolicySchema`, the holder is not 32
 *   bytes, or a window bound is negative.
 */
export const bindRequestToClaimContext = (
  request: ZkFetchRequest,
  policy: ZkFetchPolicy,
  binding: ZkFetchProveOptions,
): ZkFetchRequest => {
  if (request.context != null && Object.hasOwn(request.context, ZK_FETCH_CLAIM_CONTEXT_KEY)) {
    throw new Error(`request context cannot set ${ZK_FETCH_CLAIM_CONTEXT_KEY}`);
  }
  const { holder, windowStart, windowEnd } = binding;
  const digest = zkFetchClaimContextDigestOf({
    policy,
    request: signedSubjectOf(request),
    holder,
    windowStart,
    windowEnd,
  });
  return { ...request, context: { ...request.context, [ZK_FETCH_CLAIM_CONTEXT_KEY]: digest } };
};

/**
 * Prove `request` with the attestor's own witness and check the evidence.
 *
 * The prover gets its own copy, so it cannot change the request that other
 * provers or the secret header check read. A prover's error can carry the
 * witness's or the source's text, so it is replaced by one that carries only
 * its reason.
 *
 * @throws `ZkFetchProverError` with the prover's reason and no cause, if the
 *   prover throws one with a known reason.
 * @throws {@link SecretHeaderError} if the evidence carries a secret header value.
 * @throws {@link EvidenceTooDeepError} if the secret scan cannot finish because
 *   the evidence's JSON is nested too deeply.
 * @throws `ZodError` if the evidence is malformed.
 * @throws `Error` if the attestor has no prover, the prover fails otherwise, or
 *   the evidence is for another origin, subject or claim context.
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
  let proved: ZkFetchEvidence;
  try {
    proved = await prover.prove(copyRequest(request));
  } catch (error) {
    if (error instanceof ZkFetchProverError && PROVER_REASONS.has(error.reason)) {
      throw new ZkFetchProverError(error.reason);
    }
    throw new Error(`zkFetch prover for attestor ${attestor.id} failed`);
  }
  const evidence = zkFetchEvidenceSchema.parse(proved);
  assertEvidenceMatchesRequest(evidence, request);
  assertEvidenceMatchesClaimContext(evidence, request);
  assertNoSecretHeaders(evidence, request);
  return evidence;
};

/**
 * Ask one attestor to sign `claim` and vet the returned attestation.
 *
 * @returns the attestation, tagged with the member's registry slot.
 * @throws `AttestorNotInTrustedSetError` if `member` is not in `trusted`.
 * @throws `AttestationMismatchError` if the key, claim, message, or signature is wrong.
 * @throws whatever the transport throws.
 */
export const attestWith = async <V extends number, PK, S>(
  config: Pick<ZkFetchClientConfig<V, PK, S>, 'trusted' | 'transport' | 'verifier' | 'policy'>,
  member: TrustedAttestor<ZkFetchDefinition, PK>,
  evidence: ZkFetchEvidence,
  claim: Claim<V>,
): Promise<ZkFetchCollectedAttestation<V, PK, S>> => {
  const { trusted, transport, verifier, policy } = config;
  // The attestor re-parses these with its own schemas, which accept the
  // already-parsed shapes; only the schemas' input types are looser.
  const input = { policy, evidence, claim } as unknown as ZkFetchAttestationInput;
  const attestation = await transport.request(member.attestor, input);
  return resolveAttestation({ trusted, member, attestation, verifier, expectedClaim: claim });
};

/** Whether a value carries a secret anywhere, including inside JSON-encoded strings. */
const containsSecret = (value: unknown, secrets: readonly string[]): boolean => {
  if (typeof value === 'string') {
    if (secrets.some((secret) => value.includes(secret))) {
      return true;
    }
    // Decoding catches escaped forms such as `\u0070rivate`. A parse failure
    // means the string is not JSON; any other error must not read as clean.
    let decoded: unknown;
    try {
      decoded = JSON.parse(value);
    } catch (error) {
      if (!(error instanceof SyntaxError)) {
        throw error;
      }
      return false;
    }
    return containsSecret(decoded, secrets);
  }
  if (typeof value === 'object' && value !== null) {
    return Object.entries(value).some(
      ([key, field]) => containsSecret(key, secrets) || containsSecret(field, secrets),
    );
  }
  return false;
};

/** The evidence carried a secret header value. Carries no value itself. */
export class SecretHeaderError extends Error {
  constructor() {
    super('evidence carries a secret header value');
    this.name = 'SecretHeaderError';
  }
}

/**
 * The secret scan could not finish because the evidence's JSON is nested too
 * deeply. Carries no evidence value itself.
 */
export class EvidenceTooDeepError extends Error {
  /**
   * Build the error from the overflow that stopped the scan.
   *
   * @param options — `cause` is the local `RangeError`; it carries no evidence text.
   */
  constructor(options?: ErrorOptions) {
    super('evidence is nested too deeply to scan for secret header values', options);
    this.name = 'EvidenceTooDeepError';
  }
}

/**
 * Refuse evidence that carries a secret header value as written,
 * percent-encoded, or JSON-escaped. A prover must still redact; no check can
 * recognize every transformation of a secret.
 *
 * @throws {@link SecretHeaderError} if the evidence carries a secret header value.
 * @throws {@link EvidenceTooDeepError} if the scan cannot finish because the
 *   evidence's JSON is nested too deeply.
 */
const assertNoSecretHeaders = (evidence: ZkFetchEvidence, request: ZkFetchRequest): void => {
  const secrets = Object.values(request.secretHeaders ?? {})
    .filter(Boolean)
    .flatMap((secret) => [secret, encodeURIComponent(secret)]);
  let found: boolean;
  try {
    found = containsSecret(evidence, secrets);
  } catch (error) {
    if (error instanceof RangeError) {
      throw new EvidenceTooDeepError({ cause: error });
    }
    throw error;
  }
  if (found) {
    throw new SecretHeaderError();
  }
};
