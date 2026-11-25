// The steps both client entry points share: bind the request to the policy and the
// claim context, prove with one attestor's prover, build the claim the presentation
// supports, and ask that attestor to sign it.

import { isDeepStrictEqual } from 'node:util';
import type { CollectedAttestation, TrustedAttestor } from '@txpipe/thoth-client';
import { resolveAttestation } from '@txpipe/thoth-client';
import type { AttestationInput, AttestorDescriptor } from '@txpipe/thoth-core';
import type { Claim } from '@txpipe/thoth-core/claim';
import { bytes32Schema } from '@txpipe/thoth-core/claim';
import { z } from 'zod';
import { maskOf, type RevealedBytes } from '../http.js';
import {
  deriveTlsnClaim,
  observePresentation,
  type TlsnDefinition,
  type TlsnEvidence,
  type TlsnPolicy,
  type TlsnPresentationVerifier,
  tlsnClaimContextDigestOf,
  verifiedPresentationSchema,
} from '../index.js';
import { TLSN_CLAIM_CONTEXT_KEY, type TlsnProver, type TlsnRequest } from '../prover/index.js';
import type { TlsnClientConfig } from './index.js';

/** The holder and window fields every client entry point validates. */
export const proveOptionsShape = {
  holder: bytes32Schema,
  windowStart: z
    .bigint()
    .min(0n)
    .max(2n ** 32n - 1n),
  windowEnd: z
    .bigint()
    .min(0n)
    .max(2n ** 32n - 1n),
};

/** Whether a window's bounds are in order. */
export const windowInOrder = (window: { windowStart: bigint; windowEnd: bigint }): boolean =>
  window.windowStart <= window.windowEnd;

/** A revealed presentation byte carries a secret header value. */
export class SecretHeaderError extends Error {
  /** Build the error; it names no header and carries no value. */
  constructor() {
    super('the presentation reveals a secret header value');
    this.name = 'SecretHeaderError';
  }
}

/** A deep copy of the request, so the caller cannot change it mid-call. */
export const copyRequest = (request: TlsnRequest): TlsnRequest => structuredClone(request);

/**
 * Bind a request to the policy's disclosure rules: a request that carries its
 * own must carry exactly the policy's.
 *
 * @throws if the request carries other rules.
 */
export const bindRequestToPolicy = (request: TlsnRequest, policy: TlsnPolicy): TlsnRequest => {
  const copy = copyRequest(request);
  for (const field of ['responseMatches', 'responseRedactions'] as const) {
    if (copy[field] !== undefined && !isDeepStrictEqual(copy[field], policy[field])) {
      throw new Error(`the request's ${field} are not the policy's`);
    }
  }
  return {
    ...copy,
    responseMatches: structuredClone(policy.responseMatches),
    responseRedactions: structuredClone(policy.responseRedactions),
  };
};

/**
 * Put the claim context digest in the request's context, for the notary to sign.
 *
 * @throws if the request already sets the claim context key, or a claim input is invalid.
 */
export const bindRequestToClaimContext = (
  request: TlsnRequest,
  policy: TlsnPolicy,
  options: { holder: Uint8Array; windowStart: bigint; windowEnd: bigint },
): TlsnRequest => {
  if (request.context !== undefined && Object.hasOwn(request.context, TLSN_CLAIM_CONTEXT_KEY)) {
    throw new Error(`the request cannot set ${TLSN_CLAIM_CONTEXT_KEY}`);
  }
  const digest = tlsnClaimContextDigestOf({
    policy,
    request: {
      method: request.method ?? 'GET',
      url: request.url,
      ...(request.body === undefined ? {} : { body: request.body }),
    },
    holder: options.holder,
    windowStart: options.windowStart,
    windowEnd: options.windowEnd,
  });
  return {
    ...request,
    context: { ...request.context, [TLSN_CLAIM_CONTEXT_KEY]: Buffer.from(digest).toString('hex') },
  };
};

/**
 * Prove with the prover pinned to one attestor.
 *
 * @throws if the attestor has no prover, or whatever the prover throws.
 */
export const proveWith = async <PK>(
  provers: Readonly<Record<string, TlsnProver>>,
  attestor: AttestorDescriptor<TlsnDefinition, PK>,
  request: TlsnRequest,
): Promise<TlsnEvidence> => {
  const prover = Object.hasOwn(provers, attestor.id) ? provers[attestor.id] : undefined;
  if (prover === undefined) {
    throw new Error(`no prover for attestor ${attestor.id}`);
  }
  return prover.prove(request);
};

/** Whether any revealed run of bytes contains `needle`. */
const revealsText = (bytes: RevealedBytes, needle: Uint8Array): boolean => {
  if (needle.length === 0) return false;
  const mask = maskOf(bytes);
  // Hidden bytes become a byte no header value holds, so a match is all revealed.
  const visible = Buffer.from(bytes.data.map((byte, index) => (mask[index] === 1 ? byte : 0)));
  return visible.indexOf(Buffer.from(needle)) >= 0;
};

/**
 * Verify a presentation locally and build the claim it supports, the one an
 * honest attestor will sign.
 *
 * @throws {@link SecretHeaderError} if it reveals a secret header value.
 * @throws if it does not verify, fails the policy, signs another claim
 *   context, or was observed outside the window.
 */
export const buildClaimProposal = async (options: {
  evidence: TlsnEvidence;
  presentationVerifier: TlsnPresentationVerifier;
  request: TlsnRequest;
  policy: TlsnPolicy;
  appId: Uint8Array;
  holder: Uint8Array;
  valueSlots: number;
  byteSlots: number;
  windowStart: bigint;
  windowEnd: bigint;
}): Promise<Claim<number, number>> => {
  const { evidence, request, policy, holder, windowStart, windowEnd } = options;
  const verified = verifiedPresentationSchema.parse(
    await options.presentationVerifier.verify(evidence.presentation),
  );
  for (const value of Object.values(request.secretHeaders ?? {})) {
    const needle = new TextEncoder().encode(value);
    if (revealsText(verified.sent, needle) || revealsText(verified.received, needle)) {
      throw new SecretHeaderError();
    }
  }
  const observation = observePresentation(verified, policy);
  const expected = request.context?.[TLSN_CLAIM_CONTEXT_KEY];
  if (Buffer.from(observation.claimContext).toString('hex') !== expected) {
    throw new Error('the notary signed another claim context');
  }
  if (observation.time < windowStart || observation.time > windowEnd) {
    throw new Error('the notary observed outside the window');
  }
  return deriveTlsnClaim({
    observation,
    policy,
    appId: options.appId,
    holder,
    valueSlots: options.valueSlots,
    byteSlots: options.byteSlots,
    windowStart,
    windowEnd,
  });
};

/**
 * Ask one attestor to sign a claim and vet its answer.
 *
 * @throws `AttestationMismatchError` if the attestation fails vetting, or whatever the transport throws.
 */
export const attestWith = async <PK, S>(
  config: TlsnClientConfig<PK, S>,
  member: TrustedAttestor<TlsnDefinition, PK>,
  evidence: TlsnEvidence,
  claim: Claim<number, number>,
): Promise<CollectedAttestation<Claim<number, number>, PK, S>> => {
  const input = { policy: config.policy, evidence, claim } as unknown as AttestationInput<
    z.input<TlsnDefinition['policy']>,
    z.input<TlsnDefinition['evidence']>,
    z.input<TlsnDefinition['claim']>
  >;
  const attestation = await config.transport.request(member.attestor, input);
  return resolveAttestation({
    trusted: config.trusted,
    member,
    attestation,
    verifier: config.verifier,
    expectedClaim: claim,
  });
};
