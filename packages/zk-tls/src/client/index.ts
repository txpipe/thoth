import type {
  AttestorTransport,
  CollectedAttestation,
  SignatureVerifier,
  TrustedSet,
} from '@thoth/client';
import { attestorOf, resolveAttestation, thresholdGroup } from '@thoth/client';
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
 * Build the claim proposal the client sends to one operator's attestor.
 *
 * Runs the policy and intent checks and derives the common claim. The client
 * deliberately does **not** re-verify the Reclaim ECDSA signature: each
 * pinned attestor verifies its own witness's evidence before signing.
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
  assertEvidenceMatchesIntent(verified, intent, policy.maxWindowSeconds);
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
 * A threshold attestation: the common claim, its message, and the agreeing
 * signatures.
 *
 * Every member of `collected` signed exactly `message`, each comes from a
 * distinct registry slot, and they are sorted by slot, so the dApp can place
 * them straight into the positional registry.
 *
 * @typeParam V — the claim's value-slot count.
 * @typeParam PK — the signature scheme's public-key type.
 * @typeParam S — the signature scheme's signature type.
 */
export interface Attestment<V extends number, PK, S> {
  /** The claim every collected attestor signed. */
  readonly claim: Claim<V>;
  /** `claimToMessage(claim)` — the exact message the signatures commit to. */
  readonly message: FlatMessage;
  /** The agreeing attestations, one per registry slot, sorted by slot. */
  readonly collected: readonly ZkFetchCollectedAttestation<V, PK, S>[];
}

/**
 * One operator: the prover that runs a witnessed session through its witness,
 * and the witness address its attestor trusts.
 */
export interface ZkFetchOperator {
  /** Runs the witnessed session through this operator's witness URL. */
  readonly prover: ZkFetchProver;
  /** The witness address this operator's attestor pins; evidence from any other is refused. */
  readonly witnessAddress: string;
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
  /** How many distinct registry slots must sign the same message (the contract's `N`). */
  readonly threshold: number;
  /** Checks each returned signature before it counts toward the threshold. */
  readonly verifier: SignatureVerifier<PK, S>;
  /**
   * One operator per attestor, keyed by attestor id. Every id must be in
   * `trusted`. The client contacts the first `threshold` operators, in this
   * order.
   */
  readonly operators: Readonly<Record<string, ZkFetchOperator>>;
}

/**
 * The client, ready to attest a request.
 *
 * @typeParam V — the claim's value-slot count.
 * @typeParam PK — the signature scheme's public-key type.
 * @typeParam S — the signature scheme's signature type.
 */
export interface ZkFetchClient<V extends number, PK, S> {
  /**
   * Get a threshold attestation for an HTTPS request.
   *
   * Builds one intent (policy digest, request binding, holder, a random
   * operation nonce, and the window) and puts its digest into the signed
   * request context under `INTENT_CONTEXT_KEY`. Runs one witnessed session per
   * contacted operator concurrently, sends each operator's evidence to its
   * attestor, verifies every returned signature, and groups the results by
   * exact message.
   *
   * @param request — what to fetch and which of its fields to reveal/redact.
   *   Secret headers go to the provers only, never to an attestor.
   * @param intent — the holder commitment and the observation window.
   * @returns the threshold attestation.
   * @throws `AggregateError` if no message reaches the threshold; `errors`
   *   holds each failed operator's error.
   */
  attest(request: ZkFetchRequest, intent: ZkFetchIntentInput): Promise<Attestment<V, PK, S>>;
}

/**
 * The zkFetch client: one call runs a witnessed session per operator and
 * returns a threshold attestation from the dApp's trusted attestors.
 *
 * ```ts
 * import { zkFetchClient } from '@thoth/zk-tls/client';
 *
 * const client = zkFetchClient.init({
 *   trusted, transport, policy, valueSlots, threshold: 2, verifier,
 *   operators: {
 *     txpipe: { prover: zkFetchProver({ witnessUrl }), witnessAddress },
 *     eryx: { prover: zkFetchProver({ witnessUrl: eryxUrl }), witnessAddress: eryxAddress },
 *   },
 * });
 * const { claim, message, collected } = await client.attest(
 *   { url, method },
 *   { holder, windowStart, windowEnd },
 * );
 * ```
 *
 * `init` validates the policy, its slot map, the operators and the threshold
 * once.
 */
export const zkFetchClient = {
  /**
   * Build a client from the dApp's fixed configuration.
   *
   * @typeParam V — the claim's value-slot count.
   * @typeParam PK — the signature scheme's public-key type.
   * @typeParam S — the signature scheme's signature type.
   * @param config — trusted set, transport, policy, slot count, threshold,
   *   verifier, and operators.
   * @returns a client ready to `attest`.
   * @throws if the policy is invalid, a policy slot exceeds `valueSlots`, an
   *   operator is not in the trusted set, or the operators cannot meet the
   *   threshold.
   */
  init: <const V extends number, PK, S>(
    config: ZkFetchClientConfig<V, PK, S>,
  ): ZkFetchClient<V, PK, S> => {
    const { trusted, transport, policy, valueSlots, threshold, verifier, operators } = config;
    const checkedPolicy = zkFetchPolicySchema.parse(policy);
    // Same guard `deriveClaimFromEvidence` enforces later — fail at init
    // instead of on the first `attest()`.
    const outOfRange = checkedPolicy.slots.find((slot) => slot.slot >= valueSlots);
    if (outOfRange !== undefined) {
      throw new Error(
        `policy slot ${outOfRange.slot} is out of the claim's ${valueSlots} value slots`,
      );
    }
    const resolved = Object.entries(operators).map(([id, operator]) => ({
      attestor: attestorOf(trusted, id),
      operator,
    }));
    if (!Number.isInteger(threshold) || threshold < 1 || threshold > resolved.length) {
      throw new Error(
        `threshold ${threshold} cannot be met by ${resolved.length} configured operators`,
      );
    }
    // ponytail: contacts exactly `threshold` operators; fallback to the rest is #45.
    const contacted = resolved.slice(0, threshold);
    return {
      attest: async (request, input) => {
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
        const results = await Promise.allSettled(
          contacted.map(async ({ attestor, operator }) => {
            const evidence = zkFetchEvidenceSchema.parse(await operator.prover.prove(bound));
            assertEvidenceMatchesRequest(evidence, request);
            if (evidence.attestorAddress.toLowerCase() !== operator.witnessAddress.toLowerCase()) {
              throw new Error(`evidence for "${attestor.id}" is not from its pinned witness`);
            }
            const claim = await buildClaimProposal({
              evidence,
              policy: checkedPolicy,
              intent,
              valueSlots,
            });
            // The attestor is the law: it re-parses these with its own schemas,
            // which accept the already-parsed (superset) shapes. The schemas'
            // *input* types are the looser pre-parse form, so the payload is
            // bridged here. Secret headers never enter it.
            const payload = {
              policy: checkedPolicy,
              evidence,
              claim,
            } as unknown as ZkFetchAttestationInput;
            const attestation = await transport.request(attestor, payload);
            const collected = resolveAttestation({
              trusted,
              attestor,
              attestation,
              expectedMessage: claimToMessage(claim),
              verifier,
            });
            return { claim, collected };
          }),
        );
        const answered = results.flatMap((r) => (r.status === 'fulfilled' ? [r.value] : []));
        const collected = answered.map((a) => a.collected);
        const group = thresholdGroup(collected, threshold);
        const first = group?.[0];
        if (group === undefined || first === undefined) {
          throw new AggregateError(
            results.flatMap((r) => (r.status === 'rejected' ? [r.reason] : [])),
            `threshold of ${threshold} not met: no message was signed by ${threshold} distinct registry slots`,
          );
        }
        // Return our own proposal, not the attestor's echo of it.
        const claim = answered.find((a) => a.collected === first)?.claim ?? first.attestation.claim;
        return { claim, message: first.attestation.message, collected: group };
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
