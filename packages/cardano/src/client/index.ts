// The cardano@1 client: read the event once, derive the proposal the attestors
// check, collect a threshold of signatures, and vet every reply.

import type {
  AttestationVerifier,
  AttestorTransport,
  CollectedAttestation,
  TrustedAttestor,
  TrustedSet,
} from '@thoth/client';
import { attestorIdsOf, memberOf, resolveAttestation } from '@thoth/client';
import type { AttestationInput } from '@thoth/core';
import type { Claim } from '@thoth/core/claim';
import { bytes32Schema } from '@thoth/core/claim';
import { z } from 'zod';
import {
  CARDANO_LIMITS,
  type CardanoDefinition,
  type CardanoLocator,
  type CardanoObservation,
  type CardanoPolicy,
  cardanoClaimSchema,
  cardanoEvidenceSchema,
  cardanoObservationSchema,
  cardanoPolicySchema,
  deriveCardanoClaim,
} from '../index.js';
import { checkLocatorMatchesObservation, checkObservationMatchesPolicy } from '../output/verify.js';
import { assertPolicySlotsInRange } from '../policy.js';

/** A claim this kind signs: the standard claim, with numeric and byte slots. */
export type CardanoClaim = Claim<number, number>;

/** The unparsed input the transport forwards; the attestor parses it with its own schemas. */
export type CardanoAttestationInput = AttestationInput<
  z.input<CardanoDefinition['policy']>,
  z.input<CardanoDefinition['evidence']>,
  z.input<CardanoDefinition['claim']>
>;

/** Why one attestor's attempt was dropped. Carries no remote error text. */
export interface CardanoAttestorFailure {
  /** The attestor's registry slot. */
  readonly registryIndex: number;
  /** The step that failed. */
  readonly reason: 'attestation' | 'timeout';
}

/** An attestment that reached the threshold, plus the attestors that failed. */
export interface CardanoAttestment<PK, S> {
  /** The claim every collected attestor signed. */
  readonly claim: CardanoClaim;
  /** The vetting results, sorted by registry slot. */
  readonly collected: readonly CollectedAttestation<CardanoClaim, PK, S>[];
  /** Attestors that failed, including ones whose signature was over another message. */
  readonly failures: readonly CardanoAttestorFailure[];
}

/** No threshold was reached. Carries no evidence, claim or remote error text. */
export class CardanoThresholdError extends Error {
  /** Why the collection stopped. */
  readonly reason: 'invalid-options' | 'expired' | 'threshold';
  /** Attestors that failed before `collect` stopped. */
  readonly failures: readonly CardanoAttestorFailure[];

  /**
   * Build the error from its reason and the failures so far.
   *
   * @param options — `cause` is a local error only, never remote error text.
   */
  constructor(
    reason: CardanoThresholdError['reason'],
    failures: readonly CardanoAttestorFailure[] = [],
    options?: ErrorOptions,
  ) {
    super(`cardano threshold not reached: ${reason}`, options);
    this.name = 'CardanoThresholdError';
    this.reason = reason;
    this.failures = [...failures];
  }
}

/** The claim inputs and limits shared by every attestor in one `collect` call. */
export interface CardanoCollectOptions {
  /** 32-byte holder commitment. The holder secret stays with the app. */
  readonly holder: Uint8Array;
  /** Local deadline for the whole call, Unix milliseconds. Not signed. */
  readonly expiresAt: number;
  /** Distinct registry slots that must sign the same message. */
  readonly threshold: number;
  /** Time limit per attestor, covering transport and verification. */
  readonly attestorTimeoutMs: number;
  /** Candidate ids in contact order; defaults to the trusted set's order. */
  readonly attestorIds?: readonly string[];
}

/** What a cardano client needs to read an event and vet its attestors. */
export interface CardanoClientConfig<PK, S> {
  /** The app's pinned attestors, each at its registry slot. */
  readonly trusted: TrustedSet<CardanoDefinition, PK>;
  /** How the client reaches a remote attestor. */
  readonly transport: AttestorTransport<CardanoDefinition, PK, S>;
  /** Signature verification for the app's scheme. */
  readonly verifier: AttestationVerifier<PK, S>;
  /** The policy every attestor enforces. */
  readonly policy: CardanoPolicy;
  /** The app the claim is for, 32 bytes. */
  readonly appId: Uint8Array;
  /** The contract's numeric value count. */
  readonly valueSlots: number;
  /** The contract's byte value count. Defaults to `0`. */
  readonly byteSlots?: number;
  /** The app's own read of the event; the attestors read it again themselves. */
  readonly read: (locator: CardanoLocator) => CardanoObservation | Promise<CardanoObservation>;
}

/** A cardano client bound to one trusted set, policy and app. */
export interface CardanoClient<PK, S> {
  /**
   * Read `locator` once, derive its claim, and collect a threshold of
   * attestations over that exact claim.
   *
   * The window is not an option: it is the event block's time, which the
   * attestor derives again and refuses to change (ADR 0014).
   *
   * @returns the claim and its attestations, sorted by registry slot.
   * @throws {@link CardanoThresholdError} if the options are invalid, the
   *   deadline expires, or the candidates run out before the threshold.
   * @throws if the locator, the read or the claim derivation fails.
   */
  collect(
    locator: CardanoLocator,
    options: CardanoCollectOptions,
  ): Promise<CardanoAttestment<PK, S>>;
}

const optionsSchema = z.object({
  holder: bytes32Schema,
  expiresAt: z.number().int(),
  threshold: z.number().int().positive(),
  attestorTimeoutMs: z
    .number()
    .int()
    .positive()
    .max(2 ** 31 - 1),
  attestorIds: z.array(z.string()).optional(),
});

type Options = z.output<typeof optionsSchema>;
type FailureReason = CardanoAttestorFailure['reason'];
type CollectedOutcome<PK, S> = {
  readonly registryIndex: number;
  readonly collected: CollectedAttestation<CardanoClaim, PK, S>;
};
type Outcome<PK, S> =
  | CollectedOutcome<PK, S>
  | { readonly registryIndex: number; readonly reason: FailureReason };

/** Rejects one attestor's attempt at its deadline. */
class AttemptTimeout extends Error {}

/** Validate the collect options, mapping any failure to a safe reason. */
const parseOptions = (supplied: CardanoCollectOptions): Options => {
  try {
    return optionsSchema.parse(supplied);
  } catch {
    throw new CardanoThresholdError('invalid-options');
  }
};

/** Resolve the requested ids to one candidate per registry slot. */
const candidatesOf = <PK>(
  trusted: TrustedSet<CardanoDefinition, PK>,
  options: Options,
): TrustedAttestor<CardanoDefinition, PK>[] => {
  try {
    const ids = options.attestorIds ?? attestorIdsOf(trusted);
    // A trusted set maps ids one-to-one onto slots, so distinct ids are
    // distinct slots.
    const candidates = [...new Set(ids)].map((id) => memberOf(trusted, id));
    if (candidates.length < options.threshold) {
      throw new Error('fewer candidate slots than the threshold');
    }
    return candidates;
  } catch {
    throw new CardanoThresholdError('invalid-options');
  }
};

/**
 * Ask one attestor, vet its reply, and bound the attempt by the earlier of its
 * own timeout and the call's deadline.
 */
const runAttempt = async <PK, S>(
  config: Pick<CardanoClientConfig<PK, S>, 'trusted' | 'transport' | 'verifier' | 'policy'>,
  locator: CardanoLocator,
  claim: CardanoClaim,
  options: Options,
  member: TrustedAttestor<CardanoDefinition, PK>,
): Promise<Outcome<PK, S>> => {
  const { registryIndex } = member;
  const deadline = Math.min(Date.now() + options.attestorTimeoutMs, options.expiresAt);
  if (deadline <= Date.now()) {
    return { registryIndex, reason: 'timeout' };
  }

  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new AttemptTimeout()), deadline - Date.now());
  });

  try {
    const attempt = async () => {
      // The attestor re-parses these with its own schemas, which accept the
      // already-parsed shapes; only the schemas' input types are looser.
      const input = {
        policy: config.policy,
        evidence: locator,
        claim,
      } as unknown as CardanoAttestationInput;
      const attestation = await config.transport.request(member.attestor, input);
      return resolveAttestation({
        trusted: config.trusted,
        member,
        attestation,
        verifier: config.verifier,
        expectedClaim: claim,
      });
    };
    const collected = await Promise.race([attempt(), timeout]);
    // The timer fires at the deadline; re-check the clock so a transport that
    // resolved after the deadline but before the timer is not counted.
    if (Date.now() >= deadline) {
      return { registryIndex, reason: 'timeout' };
    }
    return { registryIndex, collected };
  } catch (error) {
    return {
      registryIndex,
      reason: error instanceof AttemptTimeout ? 'timeout' : 'attestation',
    };
  } finally {
    clearTimeout(timer);
  }
};

/**
 * Build a cardano@1 client.
 *
 * The policy, app id and value count are fixed at init; a collection reads the
 * event, checks its own read against the locator and policy, derives the
 * claim, asks the trusted attestors until a threshold signs it, and keeps only
 * the replies that equal the derived claim and verify against their pinned
 * key.
 *
 * @throws if the policy, app id or slot count fails its schema, a slot count
 *   exceeds {@link CARDANO_LIMITS}, or a policy slot does not fit the claim
 *   size, at init.
 */
export const cardanoClient = {
  init<PK, S>(config: CardanoClientConfig<PK, S>): CardanoClient<PK, S> {
    const policy = cardanoPolicySchema.parse(config.policy);
    const appId = bytes32Schema.parse(config.appId);
    const valueSlots = z
      .number()
      .int()
      .positive()
      .max(CARDANO_LIMITS.valueSlots)
      .parse(config.valueSlots);
    const byteSlots = z
      .number()
      .int()
      .nonnegative()
      .max(CARDANO_LIMITS.byteSlots)
      .parse(config.byteSlots ?? 0);
    // Same guard `deriveCardanoClaim` enforces later; fail at init instead of
    // on the first collect.
    assertPolicySlotsInRange(policy.slots, valueSlots, byteSlots);
    const { trusted, transport, verifier, read } = config;

    return {
      collect: async (locator, supplied) => {
        const options = parseOptions(supplied);
        if (Date.now() >= options.expiresAt) {
          throw new CardanoThresholdError('expired');
        }
        // The client's own input is unvalidated until here; fail with the
        // evidence schema's message instead of a provider or threshold error.
        const checkedLocator = cardanoEvidenceSchema.parse(locator);
        const candidates = candidatesOf(trusted, options);

        const observation = cardanoObservationSchema.parse(await read(checkedLocator));
        // Fail fast on a read the attestors would reject anyway; the depth is
        // the attestors' alone, since this client's tip can differ without a
        // fork.
        checkLocatorMatchesObservation(checkedLocator, observation);
        checkObservationMatchesPolicy(policy, observation);
        const claim = cardanoClaimSchema.parse(
          deriveCardanoClaim({
            policy,
            observation,
            appId,
            holder: options.holder,
            valueSlots,
            byteSlots,
          }),
        );
        if (Date.now() >= options.expiresAt) {
          throw new CardanoThresholdError('expired');
        }

        const collected: CollectedAttestation<CardanoClaim, PK, S>[] = [];
        const failures: CardanoAttestorFailure[] = [];
        const queue = [...candidates];
        // One worker per signature still needed. A worker that fails takes
        // the next candidate; a worker that succeeds ends, so no attempt runs
        // beyond the threshold.
        const worker = async () => {
          while (queue.length > 0) {
            const member = queue.shift();
            if (member === undefined) {
              return;
            }
            const outcome = await runAttempt(
              { trusted, transport, verifier, policy },
              checkedLocator,
              claim,
              options,
              member,
            );
            if ('reason' in outcome) {
              failures.push({ registryIndex: outcome.registryIndex, reason: outcome.reason });
              if (Date.now() >= options.expiresAt) {
                throw new CardanoThresholdError('expired', failures);
              }
              continue;
            }
            collected.push(outcome.collected);
            return;
          }
        };

        await Promise.all(Array.from({ length: options.threshold }, worker));
        if (collected.length < options.threshold) {
          throw new CardanoThresholdError('threshold', failures);
        }
        collected.sort((a, b) => a.registryIndex - b.registryIndex);
        return { claim, collected, failures };
      },
    };
  },
};
