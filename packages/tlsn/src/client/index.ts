// The tlsn@1 client: bind the holder and window into a claim context digest, prove the
// request once per attestor through that attestor's notary, and collect a threshold of
// signatures over one claim.

import { isDeepStrictEqual } from 'node:util';
import type {
  AttestationVerifier,
  AttestorTransport,
  CollectedAttestation,
  TrustedAttestor,
  TrustedSet,
} from '@txpipe/thoth-client';
import { attestorIdsOf, memberOf, resolveAttestation } from '@txpipe/thoth-client';
import type { AttestationInput } from '@txpipe/thoth-core';
import type { Claim } from '@txpipe/thoth-core/claim';
import { bytes32Schema } from '@txpipe/thoth-core/claim';
import { z } from 'zod';
import {
  assertPolicySlotsInRange,
  deriveTlsnClaim,
  observePresentation,
  TLSN_LIMITS,
  type TlsnDefinition,
  type TlsnPolicy,
  type TlsnPresentationVerifier,
  tlsnClaimContextDigestOf,
  tlsnPolicySchema,
  tlsnSubjectRequestOf,
  verifiedPresentationSchema,
} from '../index.js';
import type { TlsnProver, TlsnRequest } from '../prover/index.js';

export type { TlsnProver, TlsnRequest };

/** A claim this kind signs: the standard claim, with numeric and byte slots. */
export type TlsnClaim = Claim<number, number>;

/** Why one attestor's attempt was dropped. Carries no remote error text. */
export interface TlsnAttestorFailure {
  /** The attestor's registry slot. */
  readonly registryIndex: number;
  /**
   * The step that failed: `prove` (no prover, or proving failed), `evidence`
   * (the presentation fails the policy), `claim` (this session showed other
   * values than the first one), or `attestation` (the attestor refused, or its
   * reply did not vet).
   */
  readonly reason: 'prove' | 'evidence' | 'claim' | 'attestation';
}

/** An attestment that reached the threshold, plus the attestors that failed. */
export interface TlsnAttestment<PK, S> {
  /** The claim every collected attestor signed. */
  readonly claim: TlsnClaim;
  /** The vetting results, sorted by registry slot. */
  readonly collected: readonly CollectedAttestation<TlsnClaim, PK, S>[];
  readonly failures: readonly TlsnAttestorFailure[];
}

/** No threshold was reached. Carries no evidence, claim or remote error text. */
export class TlsnThresholdError extends Error {
  /** Why the collection stopped. */
  readonly reason: 'invalid-options' | 'threshold';
  /** Attestors that failed before `collect` stopped. */
  readonly failures: readonly TlsnAttestorFailure[];

  /** Build the error from its reason and the failures so far. */
  constructor(reason: TlsnThresholdError['reason'], failures: readonly TlsnAttestorFailure[] = []) {
    super(`tlsn threshold not reached: ${reason}`);
    this.name = 'TlsnThresholdError';
    this.reason = reason;
    this.failures = [...failures];
  }
}

/** The claim inputs shared by every attestor in one `collect` call. */
export interface TlsnCollectOptions {
  /** 32-byte holder commitment from `holderCommitmentOf(secret)`; fresh per claim. */
  readonly holder: Uint8Array;
  /** Inclusive start of the observation window, Unix seconds. */
  readonly windowStart: bigint;
  /** Inclusive end of the observation window, Unix seconds. */
  readonly windowEnd: bigint;
  /** Distinct registry slots that must sign the same message. */
  readonly threshold: number;
  /** Candidate ids in contact order; defaults to the trusted set's order. */
  readonly attestorIds?: readonly string[];
}

/** What a tlsn@1 client needs to prove a request and vet its attestors. */
export interface TlsnClientConfig<PK, S> {
  /** The app's pinned attestors, each at its registry slot. */
  readonly trusted: TrustedSet<TlsnDefinition, PK>;
  /** How the client reaches a remote attestor. */
  readonly transport: AttestorTransport<TlsnDefinition, PK, S>;
  /** Signature verification for the app's scheme. */
  readonly verifier: AttestationVerifier<PK, S>;
  /** Verifies each presentation locally before an attestor sees it. */
  readonly presentationVerifier: TlsnPresentationVerifier;
  /** The policy every attestor enforces. The contract seals its hash. */
  readonly policy: TlsnPolicy;
  /** The app the claim is for, 32 bytes. */
  readonly appId: Uint8Array;
  /** The contract's numeric value count. */
  readonly valueSlots: number;
  /** The contract's byte value count. Defaults to `0`. */
  readonly byteSlots?: number;
  /** One prover per attestor id, each pointing at that attestor's own notary. */
  readonly provers: Readonly<Record<string, TlsnProver>>;
}

/** A tlsn@1 client bound to one trusted set, policy and app. */
export interface TlsnClient<PK, S> {
  /**
   * Prove `request` through each candidate attestor's notary and collect a
   * threshold of attestations over one claim.
   *
   * Every session is a separate fetch, so the attestors converge only when the
   * source returns the same values each time.
   *
   * @throws {@link TlsnThresholdError} if the options are invalid or the
   *   candidates run out before the threshold.
   * @throws if the request is not HTTPS on port 443.
   */
  collect(request: TlsnRequest, options: TlsnCollectOptions): Promise<TlsnAttestment<PK, S>>;
}

const optionsSchema = z
  .object({
    holder: bytes32Schema,
    windowStart: z.bigint().nonnegative(),
    windowEnd: z.bigint().nonnegative(),
    threshold: z.number().int().positive(),
    attestorIds: z.array(z.string()).optional(),
  })
  .refine((options) => options.windowStart <= options.windowEnd);

type Options = z.output<typeof optionsSchema>;

class AttemptError extends Error {
  readonly reason: TlsnAttestorFailure['reason'];
  constructor(reason: TlsnAttestorFailure['reason']) {
    super(`attestor attempt failed: ${reason}`);
    this.reason = reason;
  }
}

/** Run `step`, mapping any failure to `reason`. */
const step = async <T>(reason: TlsnAttestorFailure['reason'], run: () => T | Promise<T>) => {
  try {
    return await run();
  } catch {
    throw new AttemptError(reason);
  }
};

/**
 * Build a tlsn@1 client.
 *
 * @throws `ZodError` if the policy, app id or slot counts fail their schemas.
 * @throws if a policy slot does not fit the claim size.
 */
export const tlsnClient = {
  init<PK, S>(config: TlsnClientConfig<PK, S>): TlsnClient<PK, S> {
    const policy = tlsnPolicySchema.parse(config.policy);
    const appId = bytes32Schema.parse(config.appId);
    const valueSlots = z
      .number()
      .int()
      .positive()
      .max(TLSN_LIMITS.valueSlots)
      .parse(config.valueSlots);
    const byteSlots = z
      .number()
      .int()
      .nonnegative()
      .max(TLSN_LIMITS.byteSlots)
      .parse(config.byteSlots ?? 0);
    assertPolicySlotsInRange(policy, valueSlots, byteSlots);
    const { trusted, transport, verifier, presentationVerifier, provers } = config;

    return {
      collect: async (request, supplied) => {
        let options: Options;
        let candidates: TrustedAttestor<TlsnDefinition, PK>[];
        try {
          options = optionsSchema.parse(supplied);
          const ids = options.attestorIds ?? attestorIdsOf(trusted);
          candidates = [...new Set(ids)].map((id) => memberOf(trusted, id));
          if (candidates.length < options.threshold) {
            throw new Error('fewer candidates than the threshold');
          }
        } catch {
          throw new TlsnThresholdError('invalid-options');
        }
        const claimContext = tlsnClaimContextDigestOf({
          policy,
          request: tlsnSubjectRequestOf(request),
          holder: options.holder,
          windowStart: options.windowStart,
          windowEnd: options.windowEnd,
        });

        let reference: TlsnClaim | undefined;
        const attempt = async (member: TrustedAttestor<TlsnDefinition, PK>) => {
          const prover = provers[member.attestor.id];
          const evidence = await step('prove', () => {
            if (prover === undefined) throw new Error('no prover for this attestor');
            return prover.prove(request, claimContext);
          });
          const claim = await step('evidence', async () => {
            const verified = verifiedPresentationSchema.parse(
              await presentationVerifier.verify(evidence.presentation),
            );
            const observation = observePresentation(verified, policy);
            if (!isDeepStrictEqual(observation.claimContext, claimContext)) {
              throw new Error('the notary signed another claim context');
            }
            if (observation.time < options.windowStart || observation.time > options.windowEnd) {
              throw new Error('the notary observed outside the window');
            }
            return deriveTlsnClaim({
              observation,
              policy,
              appId,
              holder: options.holder,
              valueSlots,
              byteSlots,
              windowStart: options.windowStart,
              windowEnd: options.windowEnd,
            });
          });
          // The first session fixes the claim; a later one that read other values cannot
          // join its threshold.
          reference ??= claim;
          if (!isDeepStrictEqual(claim, reference)) {
            throw new AttemptError('claim');
          }
          return step('attestation', async () => {
            const input = { policy, evidence, claim } as unknown as AttestationInput<
              z.input<TlsnDefinition['policy']>,
              z.input<TlsnDefinition['evidence']>,
              z.input<TlsnDefinition['claim']>
            >;
            const attestation = await transport.request(member.attestor, input);
            return resolveAttestation({
              trusted,
              member,
              attestation,
              verifier,
              expectedClaim: claim,
            });
          });
        };

        const collected: CollectedAttestation<TlsnClaim, PK, S>[] = [];
        const failures: TlsnAttestorFailure[] = [];
        const queue = [...candidates];
        // One worker per signature still needed; a failed attempt takes the next candidate.
        const worker = async () => {
          for (let member = queue.shift(); member !== undefined; member = queue.shift()) {
            try {
              collected.push(await attempt(member));
              return;
            } catch (error) {
              failures.push({
                registryIndex: member.registryIndex,
                reason: error instanceof AttemptError ? error.reason : 'attestation',
              });
            }
          }
        };
        await Promise.all(Array.from({ length: options.threshold }, worker));
        if (collected.length < options.threshold || reference === undefined) {
          throw new TlsnThresholdError('threshold', failures);
        }
        collected.sort((a, b) => a.registryIndex - b.registryIndex);
        return { claim: reference, collected, failures };
      },
    };
  },
};
