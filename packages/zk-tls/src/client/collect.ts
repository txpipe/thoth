// `zkFetchClient.collect`: one attempt per attestor, until a threshold of
// registry slots signs the same message.

import type { TrustedAttestor, TrustedSet } from '@thoth/client';
import { attestorIdsOf, memberOf } from '@thoth/client';
import type { Claim, FlatMessage } from '@thoth/core/claim';
import { z } from 'zod';
import type { ZkFetchDefinition } from '../index.js';
import type {
  Attestment,
  ZkFetchClientConfig,
  ZkFetchCollectedAttestation,
  ZkFetchProveOptions,
  ZkFetchRequest,
} from './index.js';
import {
  attestWith,
  bindRequestToClaimContext,
  bindRequestToPolicy,
  buildClaimProposal,
  proveOptionsShape,
  proveWith,
  SecretHeaderError,
  windowInOrder,
  ZkFetchProverError,
} from './proposal.js';

/** Why one attestor's attempt was dropped. Carries no remote error text. */
export interface ZkFetchAttestorFailure {
  /** The attestor's registry slot. */
  readonly registryIndex: number;
  /**
   * What failed, and where to look:
   *
   * - `transport`: the witness was unreachable, or the TLS connection to the
   *   source, its certificate, or the network failed. Check the witness URL
   *   and that the witness can reach the source.
   * - `no-match`: the response failed the policy's `responseMatches`. Check the
   *   policy against what the source returns. A witness reports every claim it
   *   refuses this way, a refused proof or timestamp included. The client runs
   *   the same check first, so a witness that refuses what the client accepted
   *   usually runs another attestor-core version.
   * - `evidence`: proving failed otherwise, or the evidence did not fit the
   *   request, the policy, the window or the slot counts.
   * - `secret`: the evidence carried a secret header value. Check that the
   *   response does not echo the secret and the prover redacts it.
   * - `attestation`: the attestor refused, or its answer did not verify.
   * - `timeout`: the attempt passed `attestorTimeoutMs` or `expiresAt`.
   */
  readonly reason: 'transport' | 'no-match' | 'evidence' | 'secret' | 'attestation' | 'timeout';
}

/** An attestment that reached the threshold, plus the attestors that failed. */
export interface ZkFetchThresholdAttestment<V extends number, PK, S> extends Attestment<V, PK, S> {
  /** Attestors that failed. Valid signatures over another message are not failures. */
  readonly failures: readonly ZkFetchAttestorFailure[];
}

/** No threshold was reached. Carries no request, evidence, or remote error text. */
export class ZkFetchThresholdError extends Error {
  /** Why no threshold was reached. */
  readonly reason: 'invalid-options' | 'expired' | 'threshold';
  /** Attestors that failed before `collect` stopped. */
  readonly failures: readonly ZkFetchAttestorFailure[];

  /**
   * Build the error from its reason and the failures so far.
   *
   * @param options — `cause` is a local error only, never remote error text.
   */
  constructor(
    reason: ZkFetchThresholdError['reason'],
    failures: readonly ZkFetchAttestorFailure[] = [],
    options?: ErrorOptions,
  ) {
    super(`zkFetch threshold not reached: ${reason}`, options);
    this.name = 'ZkFetchThresholdError';
    this.reason = reason;
    this.failures = [...failures];
  }
}

/** The claim inputs and limits shared by every attestor in one `collect` call. */
export interface ZkFetchThresholdOptions extends ZkFetchProveOptions {
  /** Local deadline for the whole call, Unix milliseconds. Not signed. */
  readonly expiresAt: number;
  /** Distinct registry slots that must sign the same message. */
  readonly threshold: number;
  /** Time limit per attestor, covering proving, transport, and verification. */
  readonly attestorTimeoutMs: number;
  /** Candidate ids in contact order; defaults to the trusted set's order. */
  readonly attestorIds?: readonly string[];
}

const optionsSchema = z
  .object({
    ...proveOptionsShape,
    expiresAt: z.number().int(),
    threshold: z.number().int().positive(),
    // `setTimeout` fires immediately past 2^31 - 1 ms.
    attestorTimeoutMs: z
      .number()
      .int()
      .positive()
      .max(2 ** 31 - 1),
    attestorIds: z.array(z.string()).optional(),
  })
  .refine(windowInOrder);

type Options = z.output<typeof optionsSchema>;
type FailureReason = ZkFetchAttestorFailure['reason'];
type Outcome<V extends number, PK, S> =
  | {
      readonly registryIndex: number;
      readonly collected: ZkFetchCollectedAttestation<V, PK, S>;
      readonly claim: Claim<V>;
      readonly message: FlatMessage;
    }
  | { readonly registryIndex: number; readonly reason: FailureReason };

/** Rejects one attestor's attempt with a safe reason. */
class AttemptError extends Error {
  readonly reason: FailureReason;

  constructor(reason: FailureReason) {
    super(`attestor attempt failed: ${reason}`);
    this.reason = reason;
  }
}

/** The reason an error carries, or `fallback` for any other error. */
const reasonOf = (error: unknown, fallback: FailureReason): FailureReason => {
  if (error instanceof SecretHeaderError) {
    return 'secret';
  }
  if (error instanceof ZkFetchProverError) {
    return error.reason;
  }
  return fallback;
};

/** Validate the options; resolve their ids to one candidate per registry slot. */
const parseOptions = <PK>(
  trusted: TrustedSet<ZkFetchDefinition, PK>,
  supplied: ZkFetchThresholdOptions,
): { options: Options; candidates: TrustedAttestor<ZkFetchDefinition, PK>[] } => {
  try {
    const options = optionsSchema.parse(supplied);
    const ids = options.attestorIds ?? attestorIdsOf(trusted);
    // A trusted set maps ids one-to-one onto slots, so distinct ids are distinct slots.
    const candidates = [...new Set(ids)].map((id) => memberOf(trusted, id));
    if (candidates.length < options.threshold) {
      throw new Error('fewer candidate slots than the threshold');
    }
    return { options, candidates };
  } catch {
    throw new ZkFetchThresholdError('invalid-options');
  }
};

/**
 * Prove, check, and attest with one attestor, within its time limit.
 *
 * An attempt that times out keeps running in the background, because
 * Reclaim's `createClaimOnAttestor` takes no abort signal. It stops at its
 * next step, so a late result is never forwarded or counted.
 */
const runAttempt = async <V extends number, PK, S>(
  config: ZkFetchClientConfig<V, PK, S>,
  request: ZkFetchRequest,
  options: Options,
  member: TrustedAttestor<ZkFetchDefinition, PK>,
): Promise<Outcome<V, PK, S>> => {
  const { attestor, registryIndex } = member;
  const deadline = Math.min(Date.now() + options.attestorTimeoutMs, options.expiresAt);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new AttemptError('timeout')), deadline - Date.now());
  });

  /**
   * Run one step, replacing any error with `reason`. A secret-header refusal
   * and a prover's classified failure keep their own reason, so a leak or an
   * unreachable witness is not reported as a failed proof. Only the reason
   * survives, never the error's text. The clock check also catches a step that
   * blocked the event loop past the deadline.
   */
  const step = async <T>(reason: FailureReason, run: () => Promise<T>): Promise<T> => {
    let result: T;
    try {
      result = await run();
    } catch (error) {
      throw new AttemptError(reasonOf(error, reason));
    }
    if (Date.now() >= deadline) {
      throw new AttemptError('timeout');
    }
    return result;
  };

  const attempt = async () => {
    const evidence = await step('evidence', () => proveWith(config.provers, attestor, request));
    const { policy, appId, valueSlots, byteSlots } = config;
    const { holder, windowStart, windowEnd } = options;
    const claim = await step('evidence', () =>
      buildClaimProposal({
        evidence,
        policy,
        appId,
        holder,
        valueSlots,
        byteSlots,
        windowStart,
        windowEnd,
      }),
    );
    const collected = await step('attestation', () => attestWith(config, member, evidence, claim));
    return { collected, claim, message: collected.attestation.message };
  };

  try {
    const settled = await Promise.race([attempt(), timeout]);
    return { registryIndex, ...settled };
  } catch (error) {
    return { registryIndex, reason: error instanceof AttemptError ? error.reason : 'evidence' };
  } finally {
    clearTimeout(timer);
  }
};

/**
 * Collect a threshold of attestations over one exact message.
 *
 * Starts `threshold` attempts at once, and a spare only when the attempts in
 * flight cannot bring any message to the threshold any more.
 *
 * @returns the first message to reach the threshold, attestations sorted by registry slot.
 * @throws {@link ZkFetchThresholdError} if the options are invalid, the request
 *   carries disclosure rules other than the policy's or sets the claim context
 *   key, the deadline expires, or the candidates run out.
 */
export const collectThreshold = async <V extends number, PK, S>(
  config: ZkFetchClientConfig<V, PK, S>,
  request: ZkFetchRequest,
  supplied: ZkFetchThresholdOptions,
): Promise<ZkFetchThresholdAttestment<V, PK, S>> => {
  const { options, candidates } = parseOptions(config.trusted, supplied);
  // A snapshot bound to the policy's disclosure rules and the claim context,
  // so the caller cannot change the secret headers mid-call or drive witnesses
  // with other rules. An unbound request is invalid input, like invalid options.
  let snapshot: ZkFetchRequest;
  try {
    snapshot = bindRequestToClaimContext(
      bindRequestToPolicy(request, config.policy),
      config.policy,
      options,
    );
  } catch (error) {
    throw new ZkFetchThresholdError('invalid-options', [], { cause: error });
  }
  const failures: ZkFetchAttestorFailure[] = [];
  const assertUnexpired = () => {
    if (Date.now() >= options.expiresAt) {
      throw new ZkFetchThresholdError('expired', failures);
    }
  };

  const groups = new Map<string, ZkFetchCollectedAttestation<V, PK, S>[]>();
  const pending = new Map<number, Promise<Outcome<V, PK, S>>>();
  let largestGroupSize = 0;
  // `largestGroupSize + pending.size` never exceeds the threshold, so when a
  // group reaches it, no other attempt is still pending.
  const startNeeded = () => {
    while (largestGroupSize + pending.size < options.threshold) {
      const member = candidates.shift();
      if (member === undefined) {
        return;
      }
      pending.set(member.registryIndex, runAttempt(config, snapshot, options, member));
    }
  };

  assertUnexpired();
  startNeeded();
  while (pending.size > 0) {
    const outcome = await Promise.race(pending.values());
    pending.delete(outcome.registryIndex);
    if ('reason' in outcome) {
      failures.push({ registryIndex: outcome.registryIndex, reason: outcome.reason });
    } else {
      const { claim, message } = outcome;
      const key = message.join(',');
      const group = [...(groups.get(key) ?? []), outcome.collected];
      groups.set(key, group);
      if (group.length === options.threshold) {
        group.sort((a, b) => a.registryIndex - b.registryIndex);
        return { claim, message, collected: group, failures };
      }
      largestGroupSize = Math.max(largestGroupSize, group.length);
    }
    // Checked after recording the outcome, so a reached threshold is returned
    // and the expired error lists every failure.
    assertUnexpired();
    startNeeded();
  }
  throw new ZkFetchThresholdError('threshold', failures);
};
