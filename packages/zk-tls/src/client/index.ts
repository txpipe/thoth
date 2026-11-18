import type {
  AttestationVerifier,
  AttestorTransport,
  CollectedAttestation,
  TrustedSet,
} from '@thoth/client';
import { attestorIdsOf, memberOf } from '@thoth/client';
import type { AttestationInput } from '@thoth/core';
import type { Claim, FlatMessage } from '@thoth/core/claim';
import { claimToMessage } from '@thoth/core/claim';
import { z } from 'zod';
import type {
  ProviderClaimData,
  ZkFetchDefinition,
  ZkFetchEvidence,
  ZkFetchPolicy,
  ZkFetchResponseMatch,
  ZkFetchResponseRedaction,
} from '../index.js';
import { assertPolicySlotsInRange, zkFetchPolicySchema } from '../index.js';
import { ZkFetchProverError } from '../prover-error.js';
import type {
  ZkFetchAttestorFailure,
  ZkFetchThresholdAttestment,
  ZkFetchThresholdOptions,
} from './collect.js';
import { collectThreshold, ZkFetchThresholdError } from './collect.js';
import {
  attestWith,
  bindRequestToClaimContext,
  bindRequestToPolicy,
  buildClaimProposal,
  EvidenceTooDeepError,
  proveOptionsShape,
  proveWith,
  SecretHeaderError,
  windowInOrder,
} from './proposal.js';

export type { ZkFetchAttestorFailure, ZkFetchThresholdAttestment, ZkFetchThresholdOptions };
export { EvidenceTooDeepError, SecretHeaderError, ZkFetchProverError, ZkFetchThresholdError };

/** Byte length of a claim's `appId`. */
const APP_ID_BYTES = 32;

/** Field-wise equality of two flat messages. */
const sameMessage = (a: FlatMessage, b: FlatMessage): boolean =>
  a.length === b.length && a.every((value, i) => value === b[i]);

/**
 * What to fetch and which of its fields the evidence reveals.
 *
 * Public headers and context are visible to whoever verifies the evidence;
 * only secret headers are not.
 */
export interface ZkFetchRequest {
  /** The HTTPS URL to fetch. */
  url: string;
  /** Defaults to `GET`. */
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH';
  /** Signed into the claim's parameters. */
  body?: string;
  /** Headers revealed to the verifier. */
  publicHeaders?: Readonly<Record<string, string>>;
  /** Headers hidden from the verifier, such as authorization. */
  secretHeaders?: Readonly<Record<string, string>>;
  /**
   * Response patterns whose named groups become the disclosed values. The
   * client always proves with the policy's; a request that supplies its own
   * must carry exactly those, or it is refused before any witness is contacted.
   */
  responseMatches?: readonly ZkFetchResponseMatch[];
  /** Slices of the response revealed to the witness. The policy's, like `responseMatches`. */
  responseRedactions?: readonly ZkFetchResponseRedaction[];
  /**
   * Arbitrary context the witness signs, such as a label. The client adds the
   * claim context digest under `ZK_FETCH_CLAIM_CONTEXT_KEY`, so a request that
   * sets that key is refused.
   */
  context?: Readonly<Record<string, unknown>>;
}

/** The raw output of a zkFetch `transformProof` call, before canonicalization. */
export interface RawZkFetchProof {
  claimData: ProviderClaimData;
  /** Mirrors `claimData.identifier`. */
  identifier: string;
  /** Hex-encoded ECDSA signatures over the claim. */
  signatures: readonly string[];
  /** The values the fetch extracted, keyed by named regex group. */
  extractedParameterValues?: Readonly<Record<string, string>>;
  witnesses?: readonly { id: string; url: string }[];
  /** The HTTP transcript as the client saw it. Not witness-signed. */
  responseText?: string;
}

/** The evidence source behind the client: where the fetch happens. */
export interface ZkFetchProver {
  /**
   * Fetch `request` and return the canonical evidence it attests.
   *
   * @throws {@link ZkFetchProverError} if the witness or the source cannot be
   *   reached, or the response fails the request's disclosure rules. Only this
   *   error gives `collect` a reason other than `evidence`.
   * @throws if the fetch or the witness fails otherwise.
   */
  prove(request: ZkFetchRequest): Promise<ZkFetchEvidence>;
}

/**
 * Decode an attestor address from a witness id, which Reclaim emits either as
 * a plain 40-hex address or as hex-encoded UTF-8 of a `0x…` address.
 *
 * @returns the `0x` + 40-hex address, lowercased.
 * @throws if the id cannot be decoded as an address.
 */
export const addressFromWitnessId = (id: string): string => {
  const hex = id.replace(/^0x/, '');
  if (/^[0-9a-fA-F]{40}$/.test(hex)) {
    return `0x${hex.toLowerCase()}`;
  }
  const ascii = Buffer.from(hex, 'hex').toString('utf-8');
  if (/^0x[0-9a-fA-F]{40}$/.test(ascii)) {
    return ascii.toLowerCase();
  }
  throw new Error(`cannot decode attestor address from witness id ${id.slice(0, 16)}...`);
};

/**
 * Canonicalize raw zkFetch output into {@link ZkFetchEvidence}, the one
 * shape the attestor accepts.
 *
 * @throws if the raw proof carries no signature or witness.
 */
export const toCanonicalEvidence = (raw: RawZkFetchProof): ZkFetchEvidence => {
  const signature = raw.signatures[0];
  const witness = raw.witnesses?.[0];
  if (signature === undefined || witness === undefined) {
    throw new Error('raw zkFetch proof carries no signature or witness');
  }
  return {
    claim: raw.claimData,
    signatureHex: signature,
    attestorAddress: addressFromWitnessId(witness.id),
    responseText: raw.responseText ?? raw.extractedParameterValues?.data ?? undefined,
  };
};

/** One collected attestation for this kind, tagged with its attestor's registry slot. */
export type ZkFetchCollectedAttestation<V extends number, PK, S> = CollectedAttestation<
  Claim<V>,
  PK,
  S,
  FlatMessage
>;

/** The collected attestation set for one claim. Every member signed `message`. */
export interface Attestment<V extends number, PK, S> {
  readonly claim: Claim<V>;
  /** `claimToMessage(claim)`, the message the signatures commit to. */
  readonly message: FlatMessage;
  /** One per attestor that answered. */
  readonly collected: readonly ZkFetchCollectedAttestation<V, PK, S>[];
}

/** The configuration a dApp fixes once, at `zkFetchClient.init`. */
export interface ZkFetchClientConfig<V extends number, PK, S> {
  /** The dApp's pinned attestors, from `@thoth/client`'s `buildTrustedSet`. */
  readonly trusted: TrustedSet<ZkFetchDefinition, PK>;
  readonly transport: AttestorTransport<ZkFetchDefinition, PK, S>;
  /** Verifies attestor signatures before a response counts. */
  readonly verifier: AttestationVerifier<PK, S>;
  /**
   * The policy every attestor in the set enforces, including how the request
   * body is bound. The contract seals its hash.
   */
  readonly policy: ZkFetchPolicy;
  /** 32 bytes, signed into every claim. */
  readonly appId: Uint8Array;
  /** The contract's `#V`. */
  readonly valueSlots: V;
  /** Half the contract's `#B`: each byte value takes two halves. Defaults to `0`. */
  readonly byteSlots?: number;
  /** One evidence source per attestor id, each pointing at that attestor's own witness. */
  readonly provers: Readonly<Record<string, ZkFetchProver>>;
}

/** The witnesses' evidence and the claim they agree on, ready to send to the attestors. */
export interface ZkFetchClientProof<V extends number, PK, S> {
  /** Canonical evidence from each attestor's witness, keyed by attestor id. */
  readonly evidences: Readonly<Record<string, ZkFetchEvidence>>;
  readonly claim: Claim<V>;
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
  attest(...ids: string[]): Promise<Attestment<V, PK, S>>;
}

/** The holder and window one claim is for, fixed before any witness signs. */
export interface ZkFetchProveOptions {
  /**
   * Per-claim commitment from `holderCommitmentOf(secret)`, 32 bytes. Keep the
   * secret for the contract witness; use a fresh one per claim. Never disclose
   * the commitment on-chain: it is the only secret input to the claim's salt.
   */
  readonly holder: Uint8Array;
  /** Inclusive start of the signed observation window, Unix seconds, at most 2^32 - 1. */
  readonly windowStart: bigint;
  /** Inclusive end of the signed observation window, Unix seconds, at most 2^32 - 1. */
  readonly windowEnd: bigint;
}

const proveOptionsSchema = z.object(proveOptionsShape).refine(windowInOrder, {
  message: 'windowStart must not be after windowEnd',
});

/** The client, ready to prove a request. */
export interface ZkFetchClient<V extends number, PK, S> {
  /**
   * Fetch through every attestor's witness and require them to agree on one
   * claim before any attestor is contacted. Every witness signs the holder and
   * window through the claim context digest.
   *
   * @throws `ZodError` if the holder is not 32 bytes, the window is out of range or
   *   inverted, or a prover returns malformed evidence.
   * @throws `SecretHeaderError` if evidence carries a secret header value.
   * @throws `EvidenceTooDeepError` if the secret scan cannot finish because the
   *   evidence's JSON is nested too deeply.
   * @throws {@link ZkFetchProverError} if a witness or the source cannot be reached, or
   *   a response fails the policy's disclosure rules.
   * @throws `Error` if the request carries disclosure rules other than the policy's or
   *   sets the claim context key, a prover fails or answers for another origin, method,
   *   path or body, evidence fails the policy or does not fit the slot counts, or the
   *   witnesses disagree.
   */
  proveReq(
    request: ZkFetchRequest,
    options: ZkFetchProveOptions,
  ): Promise<ZkFetchClientProof<V, PK, S>>;
  /**
   * Prove with each attestor's own witness and collect a threshold over one
   * message, under a window and holder fixed up front.
   *
   * @returns the first message to reach the threshold, attestations sorted by registry slot.
   * @throws {@link ZkFetchThresholdError} if the options are invalid, the
   *   request carries disclosure rules other than the policy's or sets the
   *   claim context key, the deadline expires, or no message reaches the threshold.
   */
  collect(
    request: ZkFetchRequest,
    options: ZkFetchThresholdOptions,
  ): Promise<ZkFetchThresholdAttestment<V, PK, S>>;
}

/**
 * The zkFetch client: prove a request once per attestor witness, then collect
 * the N-of-M attestation set from the dApp's trusted attestors.
 *
 * @example
 * ```ts
 * import { zkFetchClient } from '@thoth/zk-tls/client';
 * import { zkFetchProver } from '@thoth/zk-tls/prover';
 *
 * // `trusted` pins attestor-a and attestor-b; each needs its own prover.
 * const client = zkFetchClient.init({
 *   trusted, transport, verifier, policy, appId, valueSlots,
 *   provers: {
 *     'attestor-a': zkFetchProver({ witnessUrl: witnessA }),
 *     'attestor-b': zkFetchProver({ witnessUrl: witnessB }),
 *   },
 * });
 * const proved = await client.proveReq(
 *   { url, method, publicHeaders },
 *   { holder, windowStart, windowEnd }, // Unix seconds
 * );
 * const attestment = await proved.attest('attestor-a', 'attestor-b');
 * ```
 */
export const zkFetchClient = {
  /**
   * Build a client from the dApp's fixed configuration.
   *
   * @throws if the policy is invalid, the appId is not 32 bytes, a policy slot
   *   is out of range or in the wrong region, or the prover map does not match
   *   the trusted set exactly.
   */
  init: <const V extends number, PK, S>(
    config: ZkFetchClientConfig<V, PK, S>,
  ): ZkFetchClient<V, PK, S> => {
    const { trusted, transport, verifier, policy, appId, valueSlots, provers } = config;
    const byteSlots = config.byteSlots ?? 0;
    const checkedPolicy = zkFetchPolicySchema.parse(policy);
    if (appId.length !== APP_ID_BYTES) {
      throw new Error(`appId must be ${APP_ID_BYTES} bytes, got ${appId.length}`);
    }
    const trustedIds = new Set(attestorIdsOf(trusted));
    for (const id of trustedIds) {
      if (provers[id] === undefined) {
        throw new Error(`no prover configured for attestor ${id}`);
      }
    }
    for (const id of Object.keys(provers)) {
      if (!trustedIds.has(id)) {
        throw new Error(`prover configured for unknown attestor ${id}`);
      }
    }
    // Same guard `deriveClaimFromEvidence` enforces later; fail at init
    // instead of on the first `attest()`.
    assertPolicySlotsInRange(checkedPolicy, valueSlots, byteSlots);
    return {
      collect: (request, options) =>
        collectThreshold({ ...config, policy: checkedPolicy }, request, options),
      proveReq: async (request, options): Promise<ZkFetchClientProof<V, PK, S>> => {
        const binding = proveOptionsSchema.parse(options);
        const signedRequest = bindRequestToClaimContext(
          bindRequestToPolicy(request, checkedPolicy),
          checkedPolicy,
          binding,
        );
        const entries = await Promise.all(
          trusted.attestors.map(async ({ attestor }) => {
            const evidence = await proveWith(provers, attestor, signedRequest);
            return [attestor.id, evidence] as const;
          }),
        );
        const evidences: Record<string, ZkFetchEvidence> = {};
        for (const [id, evidence] of entries) {
          evidences[id] = evidence;
        }
        const proposals = await Promise.all(
          entries.map(async ([id, evidence]) => {
            const claim = await buildClaimProposal({
              evidence,
              policy: checkedPolicy,
              appId,
              valueSlots,
              byteSlots,
              ...binding,
            });
            return { id, claim, message: claimToMessage(claim) };
          }),
        );
        const [first, ...rest] = proposals;
        if (first === undefined) {
          throw new Error('trusted set has no attestors');
        }
        for (const other of rest) {
          if (!sameMessage(first.message, other.message)) {
            throw new Error(`witnesses disagree: ${first.id} vs ${other.id}`);
          }
        }
        return {
          evidences,
          claim: first.claim,
          message: first.message,
          attest: async (...ids) =>
            collectAttestations({
              trusted,
              transport,
              verifier,
              evidences,
              claim: first.claim,
              message: first.message,
              policy: checkedPolicy,
              ids,
            }),
        };
      },
    };
  },
};

/** The unparsed input the transport forwards; the attestor parses it with its own schemas. */
export type ZkFetchAttestationInput = AttestationInput<
  z.input<ZkFetchDefinition['policy']>,
  z.input<ZkFetchDefinition['evidence']>,
  z.input<ZkFetchDefinition['claim']>
>;

/**
 * Ask the selected attestors to sign the shared claim and vet each answer.
 * The contract counts the threshold; the client only checks that every
 * collected attestation commits to the same message.
 *
 * @throws `AttestorNotInTrustedSetError` if an id is not in the trusted set.
 * @throws `AttestationMismatchError` on the first rejected attestation.
 * @throws `Error` if a target attestor has no evidence, or whatever the transport throws.
 */
const collectAttestations = async <V extends number, PK, S>(options: {
  trusted: TrustedSet<ZkFetchDefinition, PK>;
  transport: AttestorTransport<ZkFetchDefinition, PK, S>;
  verifier: AttestationVerifier<PK, S>;
  /** Canonical evidence per attestor id, from `proveReq`. */
  evidences: Readonly<Record<string, ZkFetchEvidence>>;
  claim: Claim<V>;
  /** `claimToMessage(claim)`. */
  message: FlatMessage;
  policy: ZkFetchPolicy;
  /** Attestor ids to query; empty means every pinned attestor. */
  ids: string[];
}): Promise<Attestment<V, PK, S>> => {
  const { trusted, evidences, claim, message, ids } = options;
  const targetIds = ids.length > 0 ? ids : attestorIdsOf(trusted);
  const collected: ZkFetchCollectedAttestation<V, PK, S>[] = [];
  for (const id of targetIds) {
    const member = memberOf(trusted, id);
    const evidence = evidences[id];
    if (evidence === undefined) {
      throw new Error(`no evidence for attestor ${id}`);
    }
    collected.push(await attestWith(options, member, evidence, claim));
  }
  return { claim, message, collected };
};
