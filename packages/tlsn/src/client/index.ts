// The tlsn@1 client, with zkFetch's client surface: prove a request once per attestor
// through that attestor's notary, then collect the N-of-M attestation set.

import type {
  AttestationVerifier,
  AttestorTransport,
  CollectedAttestation,
  TrustedSet,
} from '@txpipe/thoth-client';
import { attestorIdsOf, memberOf } from '@txpipe/thoth-client';
import type { Claim, FlatMessage } from '@txpipe/thoth-core/claim';
import { bytes32Schema, claimToMessage } from '@txpipe/thoth-core/claim';
import { z } from 'zod';
import {
  assertPolicySlotsInRange,
  TLSN_LIMITS,
  type TlsnDefinition,
  type TlsnEvidence,
  type TlsnPolicy,
  type TlsnPresentationVerifier,
  tlsnPolicySchema,
} from '../index.js';
import {
  TLSN_CLAIM_CONTEXT_KEY,
  type TlsnProver,
  type TlsnProverConfig,
  type TlsnRequest,
  tlsnProver,
} from '../prover/index.js';
import { TlsnProverError } from '../prover-error.js';
import {
  collectThreshold,
  type TlsnAttestorFailure,
  type TlsnThresholdAttestment,
  TlsnThresholdError,
  type TlsnThresholdOptions,
} from './collect.js';
import {
  attestWith,
  bindRequestToClaimContext,
  bindRequestToPolicy,
  buildClaimProposal,
  proveOptionsShape,
  proveWith,
  SecretHeaderError,
  windowInOrder,
} from './proposal.js';

export type {
  TlsnAttestorFailure,
  TlsnProver,
  TlsnProverConfig,
  TlsnRequest,
  TlsnThresholdAttestment,
  TlsnThresholdOptions,
};
export {
  SecretHeaderError,
  TLSN_CLAIM_CONTEXT_KEY,
  TlsnProverError,
  TlsnThresholdError,
  tlsnProver,
};

/** A claim this kind signs: the standard claim, with numeric and byte slots. */
export type TlsnClaim = Claim<number, number>;

/** One vetted attestation over a tlsn@1 claim. */
export type TlsnCollectedAttestation<PK, S> = CollectedAttestation<TlsnClaim, PK, S, FlatMessage>;

/** The collected attestation set for one claim. Every member signed `message`. */
export interface Attestment<PK, S> {
  readonly claim: TlsnClaim;
  /** `claimToMessage(claim)`, the message the signatures commit to. */
  readonly message: FlatMessage;
  /** One per attestor that answered. */
  readonly collected: readonly TlsnCollectedAttestation<PK, S>[];
}

/** The configuration a dApp fixes once, at `tlsnClient.init`. */
export interface TlsnClientConfig<PK, S> {
  /** The dApp's pinned attestors, from `@txpipe/thoth-client`'s `buildTrustedSet`. */
  readonly trusted: TrustedSet<TlsnDefinition, PK>;
  readonly transport: AttestorTransport<TlsnDefinition, PK, S>;
  /** Verifies attestor signatures before a response counts. */
  readonly verifier: AttestationVerifier<PK, S>;
  /** Verifies each presentation locally, so the client proposes the claim it supports. */
  readonly presentationVerifier: TlsnPresentationVerifier;
  /** The policy every attestor in the set enforces. The contract seals its hash. */
  readonly policy: TlsnPolicy;
  /** 32 bytes, signed into every claim. */
  readonly appId: Uint8Array;
  /** The contract's `#V`. */
  readonly valueSlots: number;
  /** Half the contract's `#B`: each byte value takes two halves. Defaults to `0`. */
  readonly byteSlots?: number;
  /** One evidence source per attestor id, each pointing at that attestor's own notary. */
  readonly provers: Readonly<Record<string, TlsnProver>>;
}

/** The holder and window one claim is for, fixed before any notary signs. */
export interface TlsnProveOptions {
  /**
   * Per-claim commitment from `holderCommitmentOf(secret)`, 32 bytes. Keep the
   * secret for the contract witness; use a fresh one per claim.
   */
  readonly holder: Uint8Array;
  /** Inclusive start of the signed observation window, Unix seconds, at most 2^32 - 1. */
  readonly windowStart: bigint;
  /** Inclusive end of the signed observation window, Unix seconds, at most 2^32 - 1. */
  readonly windowEnd: bigint;
}

/** The presentations and the claim they agree on, ready to send to the attestors. */
export interface TlsnClientProof<PK, S> {
  /** One presentation per attestor's notary, keyed by attestor id. */
  readonly evidences: Readonly<Record<string, TlsnEvidence>>;
  readonly claim: TlsnClaim;
  /** `claimToMessage(claim)`. */
  readonly message: FlatMessage;
  /**
   * Ask the pinned attestors to sign this claim.
   *
   * @param ids — the attestor ids to query; defaults to every pinned attestor.
   * @throws `AttestorNotInTrustedSetError` if an id is not in the trusted set.
   * @throws `AttestationMismatchError` on the first rejected attestation.
   * @throws `Error` if a target attestor has no evidence, or whatever the transport throws.
   */
  attest(...ids: string[]): Promise<Attestment<PK, S>>;
}

/** The client, ready to prove a request. */
export interface TlsnClient<PK, S> {
  /**
   * Prove through every attestor's notary and require the presentations to
   * agree on one claim before any attestor is contacted.
   *
   * @throws `ZodError` if the holder is not 32 bytes, the window is out of range or
   *   inverted, or a prover returns malformed evidence.
   * @throws {@link SecretHeaderError} if a presentation reveals a secret header value.
   * @throws {@link TlsnProverError} if a notary or the source cannot be reached, or a
   *   response fails the policy's redaction rules.
   * @throws `Error` if the request carries disclosure rules other than the policy's or
   *   sets the claim context key, a presentation fails the policy, or the
   *   presentations disagree.
   */
  proveReq(request: TlsnRequest, options: TlsnProveOptions): Promise<TlsnClientProof<PK, S>>;
  /**
   * Prove with each attestor's own notary and collect a threshold over one
   * message, under a window and holder fixed up front.
   *
   * @returns the first message to reach the threshold, attestations sorted by registry slot.
   * @throws {@link TlsnThresholdError} if the options are invalid, the request
   *   carries disclosure rules other than the policy's or sets the claim context
   *   key, the deadline expires, or no message reaches the threshold.
   */
  collect(
    request: TlsnRequest,
    options: TlsnThresholdOptions,
  ): Promise<TlsnThresholdAttestment<PK, S>>;
}

const proveOptionsSchema = z.object(proveOptionsShape).refine(windowInOrder, {
  message: 'windowStart must not be after windowEnd',
});

const sameMessage = (a: FlatMessage, b: FlatMessage): boolean =>
  a.length === b.length && a.every((value, index) => value === b[index]);

/**
 * The tlsn@1 client: prove a request once per attestor notary, then collect the
 * N-of-M attestation set from the dApp's trusted attestors. It takes the same
 * configuration and calls as `zkFetchClient`, plus a `presentationVerifier`.
 *
 * @example
 * ```ts
 * import { tlsnClient, tlsnProver } from '@txpipe/thoth-tlsn/client';
 * import { nativePresentationVerifier } from '@txpipe/thoth-tlsn/verifier';
 *
 * const client = tlsnClient.init({
 *   trusted, transport, verifier, policy, appId, valueSlots: 1,
 *   presentationVerifier: nativePresentationVerifier({ binary: 'thoth-tlsn' }),
 *   provers: { 'tlsn-1': tlsnProver({ binary: 'thoth-tlsn', notary: 'notary-1.example:7047' }) },
 * });
 * const { claim, collected } = await client.collect(request, options);
 * ```
 *
 * @throws `ZodError` if the policy, app id or slot counts fail their schemas.
 * @throws if a policy slot does not fit the claim size.
 */
export const tlsnClient = {
  init<PK, S>(supplied: TlsnClientConfig<PK, S>): TlsnClient<PK, S> {
    tlsnPolicySchema.parse(supplied.policy);
    bytes32Schema.parse(supplied.appId);
    z.number().int().positive().max(TLSN_LIMITS.valueSlots).parse(supplied.valueSlots);
    z.number()
      .int()
      .nonnegative()
      .max(TLSN_LIMITS.byteSlots)
      .parse(supplied.byteSlots ?? 0);
    assertPolicySlotsInRange(supplied.policy, supplied.valueSlots, supplied.byteSlots ?? 0);
    const config = { ...supplied, provers: { ...supplied.provers } };

    return {
      proveReq: async (request, options) => {
        const { holder, windowStart, windowEnd } = proveOptionsSchema.parse(options);
        const snapshot = bindRequestToClaimContext(
          bindRequestToPolicy(request, config.policy),
          config.policy,
          { holder, windowStart, windowEnd },
        );
        const ids = attestorIdsOf(config.trusted);
        const evidences: Record<string, TlsnEvidence> = {};
        let claim: TlsnClaim | undefined;
        for (const id of ids) {
          const { attestor } = memberOf(config.trusted, id);
          const evidence = await proveWith(config.provers, attestor, snapshot);
          const proposal = await buildClaimProposal({
            evidence,
            presentationVerifier: config.presentationVerifier,
            request: snapshot,
            policy: config.policy,
            appId: config.appId,
            holder,
            valueSlots: config.valueSlots,
            byteSlots: config.byteSlots ?? 0,
            windowStart,
            windowEnd,
          });
          if (
            claim !== undefined &&
            !sameMessage(claimToMessage(claim), claimToMessage(proposal))
          ) {
            throw new Error('the notaries saw different responses');
          }
          claim ??= proposal;
          evidences[id] = evidence;
        }
        if (claim === undefined) {
          throw new Error('the trusted set is empty');
        }
        const agreed = claim;
        return {
          evidences,
          claim: agreed,
          message: claimToMessage(agreed),
          attest: async (...targets) => {
            const collected: TlsnCollectedAttestation<PK, S>[] = [];
            for (const id of targets.length > 0 ? targets : ids) {
              const member = memberOf(config.trusted, id);
              const evidence = Object.hasOwn(evidences, id) ? evidences[id] : undefined;
              if (evidence === undefined) {
                throw new Error(`no evidence for attestor ${id}`);
              }
              collected.push(await attestWith(config, member, evidence, agreed));
            }
            collected.sort((a, b) => a.registryIndex - b.registryIndex);
            return { claim: agreed, message: claimToMessage(agreed), collected };
          },
        };
      },
      collect: (request, options) => collectThreshold(config, request, options),
    };
  },
};
