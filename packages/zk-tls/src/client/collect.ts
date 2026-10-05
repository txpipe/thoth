// `zkFetchClient.collect`: one witnessed session per operator, until a
// threshold of registry slots signs the same message.

import type { TrustedSet } from '@thoth/client';
import { attestorOf } from '@thoth/client';
import { bytes32Schema } from '@thoth/core/claim';
import { z } from 'zod';
import type { ZkFetchDefinition } from '../index.js';
import type {
  Attestment,
  ZkFetchClientConfig,
  ZkFetchCollectedAttestation,
  ZkFetchRequest,
} from './index.js';
import type { Attestor } from './proposal.js';
import { attestWith, buildClaimProposal, proveWith } from './proposal.js';

/** Why an operator's session was dropped. Carries no remote error text. */
export interface ZkFetchCollectionFailure {
  /** The operator's registry slot. */
  readonly registryIndex: number;
  /** The phase that failed. */
  readonly reason: 'evidence' | 'secret' | 'attestation' | 'timeout';
}

/**
 * A threshold of attestations over one message.
 *
 * @typeParam V — the claim's value-slot count.
 * @typeParam PK — the signature scheme's public-key type.
 * @typeParam S — the signature scheme's signature type.
 */
export interface ZkFetchCollection<V extends number, PK, S> extends Attestment<V, PK, S> {
  /** Operators that failed. Valid signatures over another message are not failures. */
  readonly failures: readonly ZkFetchCollectionFailure[];
}

/** No threshold was collected. Carries no request, evidence, or remote error text. */
export class ZkFetchCollectionError extends Error {
  /** Why collection failed. */
  readonly reason: 'invalid-intent' | 'expired' | 'threshold';
  /** Operators that failed before collection stopped. */
  readonly failures: readonly ZkFetchCollectionFailure[];

  /**
   * @param reason — why collection failed.
   * @param failures — operators that failed.
   */
  constructor(
    reason: ZkFetchCollectionError['reason'],
    failures: readonly ZkFetchCollectionFailure[] = [],
  ) {
    super(`zkFetch collection failed: ${reason}`);
    this.name = 'ZkFetchCollectionError';
    this.reason = reason;
    this.failures = [...failures];
  }
}

/** The claim inputs and limits shared by every operator in one `collect` call. */
export interface ZkFetchCollectionIntent {
  /** Per-claim holder commitment, 32 bytes. */
  readonly holder: Uint8Array;
  /** Inclusive start of the signed observation window, Unix seconds. */
  readonly windowStart: bigint;
  /** Inclusive end of the signed observation window, Unix seconds. */
  readonly windowEnd: bigint;
  /** Local deadline for the whole call, Unix milliseconds. Not signed. */
  readonly expiresAt: number;
  /** Distinct registry slots that must sign the same message. */
  readonly threshold: number;
  /** Time limit per operator, covering proving, transport, and verification. */
  readonly operatorTimeoutMs: number;
  /** Candidate ids in contact order; defaults to the trusted set's order. */
  readonly attestorIds?: readonly string[];
}

const intentSchema = z
  .object({
    holder: bytes32Schema,
    windowStart: z.bigint().nonnegative(),
    windowEnd: z.bigint().max(2n ** 64n - 1n),
    expiresAt: z.number().int(),
    threshold: z.number().int().positive(),
    // `setTimeout` fires immediately past 2^31 - 1 ms.
    operatorTimeoutMs: z
      .number()
      .int()
      .positive()
      .max(2 ** 31 - 1),
    attestorIds: z.array(z.string()).optional(),
  })
  .refine(({ windowStart, windowEnd }) => windowStart <= windowEnd);

type Intent = z.output<typeof intentSchema>;
type FailureReason = ZkFetchCollectionFailure['reason'];
type Outcome<V extends number, PK, S> =
  | { readonly slot: number; readonly collected: ZkFetchCollectedAttestation<V, PK, S> }
  | { readonly slot: number; readonly reason: FailureReason };

/** Rejects an operator session with a safe reason. */
class SessionError extends Error {
  readonly reason: FailureReason;

  constructor(reason: FailureReason) {
    super(`operator session failed: ${reason}`);
    this.reason = reason;
  }
}

/** Validate the intent; resolve its ids to one candidate per registry slot. */
const parseIntent = <PK>(
  trusted: TrustedSet<ZkFetchDefinition, PK>,
  supplied: ZkFetchCollectionIntent,
): { intent: Intent; candidates: Attestor<PK>[] } => {
  try {
    const intent = intentSchema.parse(supplied);
    const ids = intent.attestorIds ?? trusted.attestors.map((attestor) => attestor.id);
    // A trusted set maps ids one-to-one onto slots, so distinct ids are distinct slots.
    const candidates = [...new Set(ids)].map((id) => attestorOf(trusted, id));
    if (candidates.length < intent.threshold) {
      throw new Error('fewer candidate slots than the threshold');
    }
    return { intent: { ...intent, holder: intent.holder.slice() }, candidates };
  } catch {
    throw new ZkFetchCollectionError('invalid-intent');
  }
};

/** Whether evidence carries a secret anywhere, including inside JSON-encoded strings. */
const containsSecret = (value: unknown, secrets: readonly string[]): boolean => {
  if (typeof value === 'string') {
    if (secrets.some((secret) => value.includes(secret))) {
      return true;
    }
    // Decoding catches escaped forms such as `\u0070rivate`.
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
 * Prove, check, and attest with one operator, within its time limit.
 *
 * A session that times out keeps running in the background, because
 * Reclaim's `createClaimOnAttestor` takes no abort signal (see the README's
 * "Threshold collection"). It stops at its next step, so a late result is
 * never forwarded or counted.
 */
const runSession = async <V extends number, PK, S>(
  config: ZkFetchClientConfig<V, PK, S>,
  request: ZkFetchRequest,
  intent: Intent,
  attestor: Attestor<PK>,
): Promise<Outcome<V, PK, S>> => {
  const slot = attestor.registryIndex;
  const deadline = Math.min(Date.now() + intent.operatorTimeoutMs, intent.expiresAt);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new SessionError('timeout')), deadline - Date.now());
  });

  /**
   * Run one step, replacing any error with `reason`. The clock check also
   * catches a step that blocked the event loop past the deadline.
   */
  const step = async <T>(reason: FailureReason, run: () => Promise<T>): Promise<T> => {
    let result: T;
    try {
      result = await run();
    } catch {
      throw new SessionError(reason);
    }
    if (Date.now() >= deadline) {
      throw new SessionError('timeout');
    }
    return result;
  };

  const session = async () => {
    const evidence = await step('evidence', () => proveWith(config.provers, attestor, request));
    const secrets = Object.values(request.secretHeaders ?? {}).filter(Boolean);
    if (containsSecret(evidence, secrets)) {
      throw new SessionError('secret');
    }
    const { policy, appId, valueSlots } = config;
    const { holder, windowStart, windowEnd } = intent;
    const claim = await step('evidence', () =>
      buildClaimProposal({ evidence, policy, appId, holder, valueSlots, windowStart, windowEnd }),
    );
    return step('attestation', () => attestWith(config, attestor, evidence, claim));
  };

  try {
    return { slot, collected: await Promise.race([session(), timeout]) };
  } catch (error) {
    return { slot, reason: error instanceof SessionError ? error.reason : 'evidence' };
  } finally {
    clearTimeout(timer);
  }
};

/**
 * Collect a threshold of attestations over one exact message.
 *
 * Starts `threshold` sessions at once, and a spare only when the sessions in
 * flight can no longer bring any message to the threshold.
 *
 * @typeParam V — the claim's value-slot count.
 * @typeParam PK — the signature scheme's public-key type.
 * @typeParam S — the signature scheme's signature type.
 * @param config — the client config, with its checked policy.
 * @param request — the request each operator's witness proves.
 * @param supplied — the caller's intent.
 * @returns the first message to reach the threshold, attestations sorted by registry slot.
 * @throws {@link ZkFetchCollectionError} if the intent is invalid, expires, or
 *   the candidates run out.
 */
export const collectThreshold = async <V extends number, PK, S>(
  config: ZkFetchClientConfig<V, PK, S>,
  request: ZkFetchRequest,
  supplied: ZkFetchCollectionIntent,
): Promise<ZkFetchCollection<V, PK, S>> => {
  const { intent, candidates } = parseIntent(config.trusted, supplied);
  const failures: ZkFetchCollectionFailure[] = [];
  const assertUnexpired = () => {
    if (Date.now() >= intent.expiresAt) {
      throw new ZkFetchCollectionError('expired', failures);
    }
  };

  const groups = new Map<string, ZkFetchCollectedAttestation<V, PK, S>[]>();
  const pending = new Map<number, Promise<Outcome<V, PK, S>>>();
  let largestGroup = 0;
  const startNeeded = () => {
    while (largestGroup + pending.size < intent.threshold) {
      const attestor = candidates.shift();
      if (attestor === undefined) {
        return;
      }
      pending.set(attestor.registryIndex, runSession(config, request, intent, attestor));
    }
  };

  assertUnexpired();
  startNeeded();
  while (pending.size > 0) {
    const outcome = await Promise.race(pending.values());
    pending.delete(outcome.slot);
    assertUnexpired();
    if ('reason' in outcome) {
      failures.push({ registryIndex: outcome.slot, reason: outcome.reason });
    } else {
      const { claim, message } = outcome.collected.attestation;
      const key = message.join(',');
      const group = [...(groups.get(key) ?? []), outcome.collected];
      groups.set(key, group);
      if (group.length === intent.threshold) {
        group.sort((a, b) => a.registryIndex - b.registryIndex);
        return { claim, message, collected: group, failures };
      }
      largestGroup = Math.max(largestGroup, group.length);
    }
    startNeeded();
  }
  throw new ZkFetchCollectionError('threshold', failures);
};
