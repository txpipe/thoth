// `tlsnClient.collect`: one attempt per attestor, until a threshold of registry slots
// signs the same message. It behaves as `zkFetchClient.collect` does.

import type { TrustedAttestor, TrustedSet } from '@txpipe/thoth-client';
import { attestorIdsOf, memberOf } from '@txpipe/thoth-client';
import type { Claim, FlatMessage } from '@txpipe/thoth-core/claim';
import { z } from 'zod';
import type { TlsnDefinition } from '../index.js';
import type { TlsnRequest } from '../prover/index.js';
import { TlsnProverError } from '../prover-error.js';
import type {
  Attestment,
  TlsnClientConfig,
  TlsnCollectedAttestation,
  TlsnProveOptions,
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
} from './proposal.js';

/** Why one attestor's attempt was dropped. Carries no remote error text. */
export interface TlsnAttestorFailure {
  /** The attestor's registry slot. */
  readonly registryIndex: number;
  /**
   * What failed: the prover's own reason (`transport` or `no-match`), a
   * revealed secret header value (`secret`), the presentation (`evidence`),
   * the attestor's answer (`attestation`), or the time limit (`timeout`).
   */
  readonly reason: TlsnProverError['reason'] | 'evidence' | 'secret' | 'attestation' | 'timeout';
}

/** An attestment that reached the threshold, plus the attestors that failed. */
export interface TlsnThresholdAttestment<PK, S> extends Attestment<PK, S> {
  /** Attestors that failed. Valid signatures over another message are not failures. */
  readonly failures: readonly TlsnAttestorFailure[];
}

/** No threshold was reached. Carries no request, evidence, or remote error text. */
export class TlsnThresholdError extends Error {
  /** Why no threshold was reached. */
  readonly reason: 'invalid-options' | 'expired' | 'threshold';
  /** Attestors that failed before `collect` stopped. */
  readonly failures: readonly TlsnAttestorFailure[];

  /**
   * Build the error from its reason and the failures so far.
   *
   * @param options — `cause` is a local error only, never remote error text.
   */
  constructor(
    reason: TlsnThresholdError['reason'],
    failures: readonly TlsnAttestorFailure[] = [],
    options?: ErrorOptions,
  ) {
    super(`tlsn threshold not reached: ${reason}`, options);
    this.name = 'TlsnThresholdError';
    this.reason = reason;
    this.failures = [...failures];
  }
}

/** The claim inputs and limits shared by every attestor in one `collect` call. */
export interface TlsnThresholdOptions extends TlsnProveOptions {
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
type FailureReason = TlsnAttestorFailure['reason'];
type Outcome<PK, S> =
  | {
      readonly registryIndex: number;
      readonly collected: TlsnCollectedAttestation<PK, S>;
      readonly claim: Claim<number, number>;
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

const PROVER_REASONS: ReadonlySet<FailureReason> = new Set<TlsnProverError['reason']>([
  'transport',
  'no-match',
]);

/**
 * The reason an error carries, or `fallback`. A prover's reason counts only
 * from the proving step and only when it is a known one, so a custom prover
 * cannot put arbitrary text into `failures`.
 */
const reasonOf = (error: unknown, fallback: FailureReason, proving: boolean): FailureReason => {
  if (error instanceof SecretHeaderError) {
    return 'secret';
  }
  if (proving && error instanceof TlsnProverError && PROVER_REASONS.has(error.reason)) {
    return error.reason;
  }
  return fallback;
};

/** Validate the options; resolve their ids to one candidate per registry slot. */
const parseOptions = <PK>(
  trusted: TrustedSet<TlsnDefinition, PK>,
  supplied: TlsnThresholdOptions,
): { options: Options; candidates: TrustedAttestor<TlsnDefinition, PK>[] } => {
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
    throw new TlsnThresholdError('invalid-options');
  }
};

/**
 * Prove, check, and attest with one attestor, within its time limit. An attempt
 * that times out is stopped by the prover's own timeout; its late result is
 * never counted.
 */
const runAttempt = async <PK, S>(
  config: TlsnClientConfig<PK, S>,
  request: TlsnRequest,
  options: Options,
  member: TrustedAttestor<TlsnDefinition, PK>,
): Promise<Outcome<PK, S>> => {
  const { attestor, registryIndex } = member;
  const deadline = Math.min(Date.now() + options.attestorTimeoutMs, options.expiresAt);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new AttemptError('timeout')), deadline - Date.now());
  });

  // Run one step, keeping only a safe reason for its failure, never the error's text.
  const step = async <T>(reason: FailureReason, run: () => Promise<T>, proving = false) => {
    let result: T;
    try {
      result = await run();
    } catch (error) {
      throw new AttemptError(reasonOf(error, reason, proving));
    }
    if (Date.now() >= deadline) {
      throw new AttemptError('timeout');
    }
    return result;
  };

  const attempt = async () => {
    const evidence = await step(
      'evidence',
      () => proveWith(config.provers, attestor, request),
      true,
    );
    const claim = await step('evidence', () =>
      buildClaimProposal({
        evidence,
        presentationVerifier: config.presentationVerifier,
        request,
        policy: config.policy,
        appId: config.appId,
        holder: options.holder,
        valueSlots: config.valueSlots,
        byteSlots: config.byteSlots ?? 0,
        windowStart: options.windowStart,
        windowEnd: options.windowEnd,
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
 * @throws {@link TlsnThresholdError} if the options are invalid, the request
 *   carries disclosure rules other than the policy's or sets the claim context
 *   key, the deadline expires, or the candidates run out.
 */
export const collectThreshold = async <PK, S>(
  config: TlsnClientConfig<PK, S>,
  request: TlsnRequest,
  supplied: TlsnThresholdOptions,
): Promise<TlsnThresholdAttestment<PK, S>> => {
  const { options, candidates } = parseOptions(config.trusted, supplied);
  let snapshot: TlsnRequest;
  try {
    snapshot = bindRequestToClaimContext(
      bindRequestToPolicy(request, config.policy),
      config.policy,
      options,
    );
  } catch (error) {
    throw new TlsnThresholdError('invalid-options', [], { cause: error });
  }
  const failures: TlsnAttestorFailure[] = [];
  const assertUnexpired = () => {
    if (Date.now() >= options.expiresAt) {
      throw new TlsnThresholdError('expired', failures);
    }
  };

  const groups = new Map<string, TlsnCollectedAttestation<PK, S>[]>();
  const pending = new Map<number, Promise<Outcome<PK, S>>>();
  let largestGroupSize = 0;
  // `largestGroupSize + pending.size` never exceeds the threshold, so when a group
  // reaches it, no other attempt is still pending.
  const startNeeded = () => {
    while (largestGroupSize + pending.size < options.threshold) {
      const member = candidates.shift();
      if (member === undefined) return;
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
    // Checked after recording the outcome, so a reached threshold is returned and
    // the expired error lists every failure.
    assertUnexpired();
    startNeeded();
  }
  throw new TlsnThresholdError('threshold', failures);
};
