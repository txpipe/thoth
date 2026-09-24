import type { AttestorTransport, CollectedAttestation, TrustedSet } from '@thoth/client';
import { attestorOf, resolveAttestation } from '@thoth/client';
import type { AttestationInput } from '@thoth/core';
import type { Claim, FlatMessage } from '@thoth/core/claim';
import { claimSchema, claimToMessage } from '@thoth/core/claim';
import type { z } from 'zod';
import type {
  ProviderClaimData,
  ZkFetchDefinition,
  ZkFetchEvidence,
  ZkFetchIntent,
  ZkFetchPolicy,
} from '../index.js';
import {
  assertEvidenceMatchesIntent,
  assertEvidenceMatchesPolicy,
  claimUrl,
  deriveClaimFromEvidence,
  INTENT_CONTEXT_KEY,
  intentDigestOf,
  parsedEvidenceView,
  policyDigestOf,
  requestBindingOf,
  zkFetchEvidenceSchema,
  zkFetchPolicySchema,
} from '../index.js';

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
  /** Response patterns whose named groups become the disclosed values. */
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
 * What the caller supplies to build an intent; the client adds the policy
 * digest, the request binding and a random operation nonce.
 */
export interface ZkFetchIntentInput {
  /**
   * The 32-byte holder commitment, computed by the dApp from the holder secret
   * with the contract's exported pure derivation. The client never sees the
   * secret.
   */
  holder: Uint8Array;
  /** Observation window start, Unix seconds. */
  windowStart: bigint;
  /** Observation window end, Unix seconds. */
  windowEnd: bigint;
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
  /** The captured HTTP transcript, when the producer carried one. */
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
 * The URL the signed evidence attests is the one the request asked for.
 *
 * A prover returns canonical evidence for the interaction it witnessed; this
 * keeps that evidence honest against the caller's request before any
 * attestation is collected. Origin (scheme + host + port) is compared, so a
 * redirect or a differing path still passes, while a mismatched host is
 * caught early.
 *
 * @param evidence — canonical evidence from the prover.
 * @param request — what the caller asked the client to prove.
 * @throws if the evidence attests a different origin than requested.
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
 * Runs the policy and intent checks and derives the common claim. The client
 * deliberately does **not** re-verify the Reclaim ECDSA signature, and each
 * pinned attestor verifies the evidence before signing.
 * Because the claim is deterministic in the intent and the disclosures, the
 * proposal is byte-identical to what each attestor will sign, so the client
 * can precompute the expected message and vet each returned attestation
 * against it (`resolveAttestation`'s `expectedMessage`).
 *
 * @typeParam V — the claim's value-slot count (the dApp contract's `#V`).
 * @param options — the evidence, the shared policy, and the slot count.
 * @returns the claim to propose (and to submit, once collected).
 * @throws if the evidence is invalid, fails the policy, or does not fit the
 *   dApp's claim length.
 */
const buildClaimProposal = async <V extends number>(options: {
  /** The evidence to attest (as produced by the prover). */
  evidence: ZkFetchEvidence;
  /** The shared policy every attestor in the set enforces. */
  policy: ZkFetchPolicy;
  /** The intent the evidence was witnessed under. */
  intent: ZkFetchIntent;
  /** The claim's value-slot count (the target contract's `#V`). */
  valueSlots: V;
}): Promise<Claim<V>> => {
  const { evidence, policy, intent, valueSlots } = options;
  const verified = parsedEvidenceView(evidence);
  assertEvidenceMatchesPolicy(verified, policy);
  assertEvidenceMatchesIntent(verified, intent);
  const derived = deriveClaimFromEvidence({ verified, policy, intent, valueSlots });
  return claimSchema(valueSlots).parse(derived);
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
  ZkFetchDefinition['kind'],
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
 * members must agree on `message` — the client enforces that via
 * `resolveAttestation`'s `expectedMessage`, and the registry counts signatures
 * over exactly this message.
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
  /** The policy the attestors enforce; members of a trusted set must share it. */
  readonly policy: ZkFetchPolicy;
  /** The claim's value-slot count (the target contract's `#V`). */
  readonly valueSlots: V;
  /** Where evidence comes from (a fixture, or a live zkFetch provider). */
  readonly prover: ZkFetchProver;
}

/**
 * A proof handle with pending attestation: the evidence plus the fan-out.
 *
 * @typeParam V — the claim's value-slot count.
 * @typeParam PK — the signature scheme's public-key type.
 * @typeParam S — the signature scheme's signature type.
 */
export interface ZkFetchClientProof<V extends number, PK, S> {
  /** The canonical evidence the proof produced. */
  readonly evidence: ZkFetchEvidence;
  /** The intent the evidence was witnessed under. */
  readonly intent: ZkFetchIntent;
  /**
   * Ask the pinned attestors to attest this evidence.
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
   * Obtain evidence for an HTTPS request through the configured prover.
   *
   * Builds the intent (policy digest, request binding, holder, a random
   * operation nonce, and the window) and puts its digest into the signed
   * request context under `INTENT_CONTEXT_KEY`. The evidence must attest
   * `request.url`'s origin — enforced here, so a prover answering for a
   * different origin never reaches an attestor.
   *
   * @param request — what to fetch and which of its fields to reveal/redact.
   * @param intent — the holder commitment and the observation window.
   * @returns a proof handle whose `attest` fan-out collects the N-of-M set.
   */
  proveReq(
    request: ZkFetchRequest,
    intent: ZkFetchIntentInput,
  ): Promise<ZkFetchClientProof<V, PK, S>>;
}

/**
 * The zkFetch client: prove a request, then collect the N-of-M attestation
 * set from the dApp's trusted attestors.
 *
 * ```ts
 * import { zkFetchClient } from '@thoth/zk-tls/client';
 *
 * const client = zkFetchClient.init({
 *   trusted, transport, policy, valueSlots, prover,
 * });
 * const proof = await client.proveReq({ url, method }, { holder, windowStart, windowEnd });
 * const attestment = await proof.attest('txpipeEndpoint', 'eryxEndpoint', 'midnightFoundation');
 * ```
 *
 * `init` validates the policy and its slot map once; `proveReq` shapes the
 * prover's output through the evidence schema and binds it to the requested
 * URL, so only canonical, matching evidence ever reaches an attestor.
 */
export const zkFetchClient = {
  /**
   * Build a client from the dApp's fixed configuration.
   *
   * @typeParam V — the claim's value-slot count.
   * @typeParam PK — the signature scheme's public-key type.
   * @typeParam S — the signature scheme's signature type.
   * @param config — trusted set, transport, policy, slot count, and prover.
   * @returns a client ready to `proveReq`.
   * @throws if the policy is invalid or a policy slot exceeds `valueSlots`.
   */
  init: <const V extends number, PK, S>(
    config: ZkFetchClientConfig<V, PK, S>,
  ): ZkFetchClient<V, PK, S> => {
    const { trusted, transport, policy, valueSlots, prover } = config;
    const checkedPolicy = zkFetchPolicySchema.parse(policy);
    // Same guard `deriveClaimFromEvidence` enforces later — fail at init
    // instead of on the first `attest()`.
    const outOfRange = checkedPolicy.slots.find((slot) => slot.slot >= valueSlots);
    if (outOfRange !== undefined) {
      throw new Error(
        `policy slot ${outOfRange.slot} is out of the claim's ${valueSlots} value slots`,
      );
    }
    return {
      proveReq: async (request, input): Promise<ZkFetchClientProof<V, PK, S>> => {
        const intent: ZkFetchIntent = {
          policyDigest: policyDigestOf(checkedPolicy),
          requestBinding: requestBindingOf({
            method: request.method ?? 'GET',
            url: request.url,
            body: request.body ?? '',
          }),
          holder: input.holder,
          nonce: crypto.getRandomValues(new Uint8Array(32)),
          windowStart: input.windowStart,
          windowEnd: input.windowEnd,
        };
        const bound = {
          ...request,
          context: { ...request.context, [INTENT_CONTEXT_KEY]: intentDigestOf(intent) },
        };
        const evidence = zkFetchEvidenceSchema.parse(await prover.prove(bound));
        assertEvidenceMatchesRequest(evidence, request);
        return {
          evidence,
          intent,
          attest: async (...ids) =>
            collectAttestations({
              trusted,
              transport,
              evidence,
              policy: checkedPolicy,
              intent,
              valueSlots,
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
 * matches the descriptor and the signed message is the one this claim
 * deterministically produces. The registry's signature threshold is the
 * contract's job; the client's job is that every collected attestation
 * commits to the *same* message.
 *
 * @typeParam V — the claim's value-slot count.
 * @typeParam PK — the signature scheme's public-key type.
 * @typeParam S — the signature scheme's signature type.
 * @param options — the trusted set, transport, evidence, policy, slot count, and target ids.
 * @returns the attestment: the shared claim/message plus the collected set.
 * @throws on the first rejected attestation (`AttestationMismatchError`).
 */
const collectAttestations = async <V extends number, PK, S>(options: {
  /** The dApp's pinned attestors. */
  trusted: TrustedSet<ZkFetchDefinition, PK>;
  /** How the client reaches each attestor. */
  transport: AttestorTransport<ZkFetchDefinition, PK, S>;
  /** The evidence to attest. */
  evidence: ZkFetchEvidence;
  /** The shared policy every attestor in the set enforces. */
  policy: ZkFetchPolicy;
  /** The intent the evidence was witnessed under. */
  intent: ZkFetchIntent;
  /** The claim's value-slot count. */
  valueSlots: V;
  /** Attestor ids to query; empty means every pinned attestor. */
  ids: string[];
}): Promise<Attestment<V, PK, S>> => {
  const { trusted, transport, evidence, policy, intent, valueSlots, ids } = options;
  const claim = await buildClaimProposal({ evidence, policy, intent, valueSlots });
  const message = claimToMessage(claim);
  const targetIds = ids.length > 0 ? ids : trusted.attestors.map((a) => a.id);
  const collected: ZkFetchCollectedAttestation<V, PK, S>[] = [];
  for (const id of targetIds) {
    const attestor = attestorOf(trusted, id);
    // The attestor is the law: it re-parses these with its own schemas, which
    // accept the already-parsed (superset) shapes. The schemas' *input* types
    // are the looser pre-parse form, so the payload is bridged here.
    const input = { policy, evidence, claim } as unknown as ZkFetchAttestationInput;
    const attestation = await transport.request(attestor, input);
    collected.push(
      resolveAttestation({ trusted, attestor, attestation, expectedMessage: message }),
    );
  }
  return { claim, message, collected };
};
