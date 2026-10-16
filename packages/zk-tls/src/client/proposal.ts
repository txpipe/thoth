// Per-attestor steps shared by `proveReq` and `collect`.

import { isDeepStrictEqual } from 'node:util';
import type { TrustedAttestor } from '@thoth/client';
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
 * Require the evidence to attest the origin (scheme, host, port) the request
 * asked for. A redirect or a different path still passes.
 *
 * @throws if the evidence attests another origin.
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
 * The claim is deterministic in the evidence, so the proposal is what each
 * attestor signs and `resolveAttestation` can check each answer against it.
 * The client does not re-verify the witness signature; each attestor does.
 *
 * @throws if the evidence is invalid, fails the policy, or does not fit the
 *   requested slot counts.
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
  return claimSchema(valueSlots, byteSlots).parse(derived);
};

/** Shallow-copy a request with its own `secretHeaders`, so a holder cannot change the original's. */
export const copyRequest = (request: ZkFetchRequest): ZkFetchRequest => ({
  ...request,
  secretHeaders: { ...request.secretHeaders },
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
 * Prove `request` with the attestor's own witness and check the evidence.
 *
 * The prover gets its own copy, so it cannot change the request that other
 * provers or the secret header check read.
 *
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
 * @returns the attestation, tagged with the member's registry slot.
 * @throws `AttestationMismatchError` if the key, claim, message, or signature is wrong.
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

/** The evidence carried a secret header value. Carries no value itself. */
export class SecretHeaderError extends Error {
  constructor() {
    super('evidence carries a secret header value');
    this.name = 'SecretHeaderError';
  }
}

/**
 * Refuse evidence that carries a secret header value as written,
 * percent-encoded, or JSON-escaped. A prover must still redact; no check can
 * recognize every transformation of a secret.
 *
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
