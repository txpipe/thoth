import type {
  AttestationVerifier,
  AttestorTransport,
  CollectedAttestation,
  TrustedSet,
} from '@thoth/client';
import { attestorOf } from '@thoth/client';
import type { AttestationInput } from '@thoth/core';
import type { Claim, FlatMessage } from '@thoth/core/claim';
import { bytes32Schema, claimToMessage } from '@thoth/core/claim';
import type { z } from 'zod';
import type {
  ProviderClaimData,
  ZkFetchDefinition,
  ZkFetchEvidence,
  ZkFetchPolicy,
} from '../index.js';
import { assertPolicySlotsInRange, zkFetchPolicySchema } from '../index.js';
import type {
  ZkFetchAttestorFailure,
  ZkFetchThresholdAttestment,
  ZkFetchThresholdOptions,
} from './collect.js';
import { collectThreshold, ZkFetchThresholdError } from './collect.js';
import { assertNoSecretHeaders, attestWith, buildClaimProposal, proveWith } from './proposal.js';

export type { ZkFetchAttestorFailure, ZkFetchThresholdAttestment, ZkFetchThresholdOptions };
export { ZkFetchThresholdError };

/** Byte length of a claim's `appId`. */
const APP_ID_BYTES = 32;

/** Field-wise equality of two flat messages. */
const sameMessage = (a: FlatMessage, b: FlatMessage): boolean =>
  a.length === b.length && a.every((value, i) => value === b[i]);

/**
 * What to fetch and which of its fields the proof reveals or redacts.
 *
 * The canonical subset of the HTTP witness request the attestor's law can
 * certify: public headers are visible to whoever verifies the proof; secret
 * headers and context are not. Fields the underlying witness SDK offers but
 * the law does not model yet (e.g. `invert` matches, `hash` redactions) are
 * intentionally absent — a concrete prover may still expose its own options
 * beyond this subset.
 */
export interface ZkFetchRequest {
  /** The HTTPS URL to fetch. */
  url: string;
  /** HTTP method; defaults to `GET`. */
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH';
  /** Request body; signed into the claim's parameters. */
  body?: string;
  /** Headers revealed to the verifier. */
  publicHeaders?: Readonly<Record<string, string>>;
  /** Headers hidden from the verifier (e.g. authorization). */
  secretHeaders?: Readonly<Record<string, string>>;
  /**
   * Response patterns whose named groups become the disclosed values.
   *
   * The revealed slice is signed into every witness's claim, so it must be
   * identical across independent fetches. Whole responses carry per-request
   * headers such as rate limits, dates, and request ids, which make witnesses
   * disagree.
   */
  responseMatches?: readonly { type: 'regex' | 'contains'; value: string }[];
  /**
   * Slices of the response revealed to the witness — Reclaim's reveal
   * whitelist: everything not selected here stays hidden from the proof.
   */
  responseRedactions?: readonly { regex?: string; jsonPath?: string; xPath?: string }[];
  /** Arbitrary context signed into the claim (e.g. a label). */
  context?: Readonly<Record<string, unknown>>;
}

/**
 * The raw output of a zkFetch/transformProof call: the witness-signed claim
 * wrapped in the live-transform shell, before canonicalization.
 */
export interface RawZkFetchProof {
  /** The claim data the witness signed. */
  claimData: ProviderClaimData;
  /** Claim identifier, mirroring `claimData.identifier`. */
  identifier: string;
  /** Hex-encoded ECDSA signatures over the claim. */
  signatures: readonly string[];
  /** The values the fetch extracted, keyed by named regex group. */
  extractedParameterValues?: Readonly<Record<string, string>>;
  /** The witnesses that vouched for the proof. */
  witnesses?: readonly { id: string; url: string }[];
  /** Untrusted, client-supplied HTTP transcript; not covered by the witness signature. */
  responseText?: string;
}

/**
 * The evidence source behind the client.
 *
 * The concrete provider is where the actual fetch happens. Implementations
 * shape their output into the canonical {@link ZkFetchEvidence}; the
 * attestor accepts nothing else.
 */
export interface ZkFetchProver {
  /**
   * Fetch `request` and return the canonical evidence it attests.
   *
   * @param request — what to fetch and which fields to reveal/redact.
   * @returns canonical evidence attesting `request.url`'s origin, or throws
   *   if the fetch/attest fails.
   */
  prove(request: ZkFetchRequest): Promise<ZkFetchEvidence>;
}

/**
 * Decode an attestor address from a witness id.
 *
 * Reconciles the two id encodings Reclaim emits: plain 40-hex addresses and
 * hex-encoded UTF-8 of a `0x…` address.
 *
 * @param id — the witness id.
 * @returns the canonical `0x` + 40-hex address, lowercased.
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
 * Canonicalize raw zkFetch output into {@link ZkFetchEvidence}.
 *
 * The attestor accepts one evidence shape only.
 *
 * @param raw — a raw `transformProof`-shaped proof.
 * @returns the canonical evidence the attestor verifies.
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

/**
 * One collected attestation for this kind: an attestation tagged with the
 * registry slot its attestor answered from.
 *
 * @typeParam V — the claim's value-slot count.
 * @typeParam PK — the signature scheme's public-key type.
 * @typeParam S — the signature scheme's signature type.
 */
export type ZkFetchCollectedAttestation<V extends number, PK, S> = CollectedAttestation<
  Claim<V>,
  PK,
  S,
  FlatMessage
>;

/**
 * The collected attestation set for one claim.
 *
 * `claim`/`message` are the shared, deterministically derived claim and its
 * flat-message encoding; `collected` is one per attestor that answered. All
 * members must agree on `message` — `resolveAttestation` checks each one
 * against the message of the claim it was asked to sign, and the registry
 * counts signatures over exactly this message.
 *
 * @typeParam V — the claim's value-slot count.
 * @typeParam PK — the signature scheme's public-key type.
 * @typeParam S — the signature scheme's signature type.
 */
export interface Attestment<V extends number, PK, S> {
  /** The claim every attestor in this set signed. */
  readonly claim: Claim<V>;
  /** `claimToMessage(claim)` — the exact message the signatures commit to. */
  readonly message: FlatMessage;
  /** The collected attestations, one per answered attestor. */
  readonly collected: readonly ZkFetchCollectedAttestation<V, PK, S>[];
}

/**
 * The configuration a dApp fixes once, at `zkFetchClient.init`.
 *
 * @typeParam V — the claim's value-slot count (matches the target contract's `#V`).
 * @typeParam PK — the signature scheme's public-key type.
 * @typeParam S — the signature scheme's signature type.
 */
export interface ZkFetchClientConfig<V extends number, PK, S> {
  /** The dApp's pinned attestors (from `@thoth/client`'s `buildTrustedSet`). */
  readonly trusted: TrustedSet<ZkFetchDefinition, PK>;
  /** How the client reaches each remote attestor. */
  readonly transport: AttestorTransport<ZkFetchDefinition, PK, S>;
  /** Verifies attestor signatures before collecting responses. */
  readonly verifier: AttestationVerifier<PK, S>;
  /** The policy the attestors enforce; members of a trusted set must share it. */
  readonly policy: ZkFetchPolicy;
  /**
   * The app every claim is for, signed into the claim. 32 bytes. The target
   * contract must also seal the policy's hash (`zkFetchPolicyHashOf(policy)`).
   */
  readonly appId: Uint8Array;
  /** The claim's value-slot count (the target contract's `#V`). */
  readonly valueSlots: V;
  /**
   * Evidence source per attestor id. Each one points at that attestor's own
   * witness (e.g. `zkFetchProver({ witnessUrl })`); the dApp supplies the
   * URLs.
   */
  readonly provers: Readonly<Record<string, ZkFetchProver>>;
}

/**
 * A proof handle with pending attestation: the witnesses' evidence plus the
 * fan-out.
 *
 * @typeParam V — the claim's value-slot count.
 * @typeParam PK — the signature scheme's public-key type.
 * @typeParam S — the signature scheme's signature type.
 */
export interface ZkFetchClientProof<V extends number, PK, S> {
  /** Canonical evidence from each attestor's witness, keyed by attestor id. */
  readonly evidences: Readonly<Record<string, ZkFetchEvidence>>;
  /** The claim every witness's evidence agrees on. */
  readonly claim: Claim<V>;
  /** `claimToMessage(claim)` — the message every attestor is asked to sign. */
  readonly message: FlatMessage;
  /**
   * Ask the pinned attestors to attest this proof.
   *
   * @param ids — the attestor ids to query; defaults to every pinned attestor.
   * @returns the collected attestations, or throws on the first rejection.
   */
  attest(...ids: string[]): Promise<Attestment<V, PK, S>>;
}

/**
 * The client, ready to prove a request.
 *
 * @typeParam V — the claim's value-slot count.
 * @typeParam PK — the signature scheme's public-key type.
 * @typeParam S — the signature scheme's signature type.
 */
export interface ZkFetchClient<V extends number, PK, S> {
  /**
   * Obtain evidence for an HTTPS request from every attestor's witness.
   *
   * Replay protection keys on the signed observation, including its window
   * and disclosed values. Each witness must attest
   * `request.url`'s origin, and all of them must agree on one claim; otherwise
   * no attestor is contacted.
   *
   * @param request — what to fetch and which of its fields to reveal/redact.
   * @param holder — 32-byte per-claim commitment from `holderCommitmentOf(secret)`.
   *   Keep the secret locally for the contract witness; use a fresh secret per claim.
   * @returns a proof handle whose `attest` fan-out collects the N-of-M set.
   * @throws if the holder is not 32 bytes, a prover answers for a different
   *   origin, evidence carries a secret header value, or the witnesses
   *   disagree on the claim.
   */
  proveReq(request: ZkFetchRequest, holder: Uint8Array): Promise<ZkFetchClientProof<V, PK, S>>;
  /**
   * Prove with each attestor's own witness and collect a threshold over one message.
   *
   * @param request — the HTTPS request, including headers private to the prover.
   * @param options — the fixed holder and window, the deadline, and the limits.
   * @returns an attestment over one exact message, sorted by registry slot.
   * @throws {@link ZkFetchThresholdError} if the options are invalid, expire, or
   *   no message reaches the threshold.
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
 * ```ts
 * import { zkFetchClient } from '@thoth/zk-tls/client';
 *
 * const client = zkFetchClient.init({
 *   trusted, transport, verifier, policy, appId, valueSlots,
 *   provers: { txpipeEndpoint: zkFetchProver({ witnessUrl }) },
 * });
 * const proof = await client.proveReq({ url, method, headers }, holder);
 * const attestment = await proof.attest('txpipeEndpoint', 'eryxEndpoint', 'midnightFoundation');
 * ```
 *
 * `init` validates the policy, its slot map, and the prover map once;
 * `proveReq` shapes each prover's output through the evidence schema, binds it
 * to the requested URL, and requires every witness to agree on one claim, so
 * only canonical, matching evidence ever reaches an attestor.
 */
export const zkFetchClient = {
  /**
   * Build a client from the dApp's fixed configuration.
   *
   * @typeParam V — the claim's value-slot count.
   * @typeParam PK — the signature scheme's public-key type.
   * @typeParam S — the signature scheme's signature type.
   * @param config — trusted set, transport, verifier, policy, app id, slot count, and
   *   provers.
   * @returns a client ready to `proveReq`.
   * @throws if the policy is invalid, the appId is not 32 bytes, a policy slot
   *   exceeds `valueSlots`, or the prover map does not match the trusted set
   *   exactly.
   */
  init: <const V extends number, PK, S>(
    config: ZkFetchClientConfig<V, PK, S>,
  ): ZkFetchClient<V, PK, S> => {
    const { trusted, transport, verifier, policy, appId, valueSlots, provers } = config;
    const checkedPolicy = zkFetchPolicySchema.parse(policy);
    if (appId.length !== APP_ID_BYTES) {
      throw new Error(`appId must be ${APP_ID_BYTES} bytes, got ${appId.length}`);
    }
    const trustedIds = new Set(trusted.attestors.map((attestor) => attestor.id));
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
    // Same guard `deriveClaimFromEvidence` enforces later — fail at init
    // instead of on the first `attest()`.
    assertPolicySlotsInRange(checkedPolicy, valueSlots);
    return {
      collect: (request, options) =>
        collectThreshold({ ...config, policy: checkedPolicy }, request, options),
      proveReq: async (request, holder): Promise<ZkFetchClientProof<V, PK, S>> => {
        const checkedHolder = bytes32Schema.parse(holder).slice();
        const signedRequest: ZkFetchRequest = { ...request };
        const entries = await Promise.all(
          trusted.attestors.map(async (attestor) => {
            const evidence = await proveWith(provers, attestor, signedRequest);
            assertNoSecretHeaders(evidence, signedRequest);
            return [attestor.id, evidence] as const;
          }),
        );
        const evidences: Record<string, ZkFetchEvidence> = {};
        for (const [id, evidence] of entries) {
          evidences[id] = evidence;
        }
        // The window spans every witness's observation, so each attestor
        // finds its own inside it (ADR 0005).
        const observedAt = entries.map(([, evidence]) => evidence.claim.timestampS);
        const windowStart = BigInt(Math.min(...observedAt));
        const windowEnd = BigInt(Math.max(...observedAt));
        const proposals = await Promise.all(
          entries.map(async ([id, evidence]) => {
            const claim = await buildClaimProposal({
              evidence,
              policy: checkedPolicy,
              appId,
              holder: checkedHolder,
              valueSlots,
              windowStart,
              windowEnd,
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

/**
 * The raw (unparsed) input shape the transport forwards to an attestor. The
 * attestor is the law — it parses this with its own schemas at the other end.
 */
export type ZkFetchAttestationInput = AttestationInput<
  z.input<ZkFetchDefinition['policy']>,
  z.input<ZkFetchDefinition['evidence']>,
  z.input<ZkFetchDefinition['claim']>
>;

/**
 * Fan out one evidence/claim proposal to the selected attestors and collect
 * the N-of-M set.
 *
 * For each target attestor: resolve it in the trusted set, forward the raw
 * input over the transport, and vet the returned attestation — signing key
 * matches the descriptor, the claim matches the request, the message
 * encodes that claim, and the signature verifies. The registry's signature
 * threshold is the contract's job; the client's job is that every collected attestation
 * commits to the *same* message.
 *
 * @typeParam V — the claim's value-slot count.
 * @typeParam PK — the signature scheme's public-key type.
 * @typeParam S — the signature scheme's signature type.
 * @param options — the trusted set, transport, evidence map, shared claim and
 *   message, policy, and target ids.
 * @returns the attestment: the shared claim/message plus the collected set.
 * @throws if a target attestor has no evidence, or on the first rejected
 *   attestation (`AttestationMismatchError`).
 */
const collectAttestations = async <V extends number, PK, S>(options: {
  /** The dApp's pinned attestors. */
  trusted: TrustedSet<ZkFetchDefinition, PK>;
  /** How the client reaches each attestor. */
  transport: AttestorTransport<ZkFetchDefinition, PK, S>;
  /** Verifies the attestor signature scheme. */
  verifier: AttestationVerifier<PK, S>;
  /** Canonical evidence per attestor id, from `proveReq`. */
  evidences: Readonly<Record<string, ZkFetchEvidence>>;
  /** The shared claim every witness's evidence agreed on. */
  claim: Claim<V>;
  /** `claimToMessage(claim)`. */
  message: FlatMessage;
  /** The shared policy every attestor in the set enforces. */
  policy: ZkFetchPolicy;
  /** Attestor ids to query; empty means every pinned attestor. */
  ids: string[];
}): Promise<Attestment<V, PK, S>> => {
  const { trusted, evidences, claim, message, ids } = options;
  const targetIds = ids.length > 0 ? ids : trusted.attestors.map((a) => a.id);
  const collected: ZkFetchCollectedAttestation<V, PK, S>[] = [];
  for (const id of targetIds) {
    const attestor = attestorOf(trusted, id);
    const evidence = evidences[id];
    if (evidence === undefined) {
      throw new Error(`no evidence for attestor ${id}`);
    }
    collected.push(await attestWith(options, attestor, evidence, claim));
  }
  return { claim, message, collected };
};
