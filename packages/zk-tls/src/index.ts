import { createHash } from 'node:crypto';
import type { AttestationInput } from '@thoth/core';
import type { Claim, ClaimInput, FlatMessage } from '@thoth/core/claim';
import { CLAIM_VERSION } from '@thoth/core/claim';
import { policyHashOf, subjectHashOf } from '@thoth/core/intent';
import { z } from 'zod';
import { hexToBytes } from './hex.js';

/**
 * Default maximum seconds between a client-proposed claim timestamp and the
 * witness's own observation; a policy may override it with
 * {@link ZkFetchPolicy.maxSkewS}.
 */
export const DEFAULT_MAX_SKEW_S = 60;

/** The zkFetch kind's law tag, also its kind identifier. */
export const ZK_FETCH_LAW = 'zk-fetch@1';

/**
 * The claim a Reclaim witness signs: a canonical, JSON-stringified record of
 * the fetch it witnessed (what was requested, matched, and redacted).
 *
 * Mirror of `@reclaimprotocol/attestor-core`'s `proto.ProviderClaimData`, kept
 * local so this package's schema is its own type source rather than an import
 * from the SDK's generated protobuf namespace.
 */
export interface ProviderClaimData {
  /** Name of the provider that generated the claim (e.g. `http`). */
  provider: string;
  /** Canonically JSON-stringified provider parameters (url, method, headers, responseMatches, responseRedactions, …). */
  parameters: string;
  /** Owner of the claim — the public key/address that requested it. */
  owner: string;
  /** Unix seconds at which the claim was made. */
  timestampS: number;
  /** Canonically JSON-stringified context (extractedParameters and friends). */
  context: string;
  /** Identifier of the claim: hash of (provider, parameters, context). */
  identifier: string;
  /** Legacy V1 beacon epoch number. */
  epoch: number;
}

/**
 * The canonical evidence shape this kind verifies.
 *
 * Produced by the zkFetch client SDK; this package requires it as-is. Both
 * sides of the kind treat evidence in any other shape as invalid.
 */
export interface ZkFetchEvidence {
  /** The signed claim data. */
  claim: ProviderClaimData;
  /** Hex-encoded ECDSA signature (65 bytes) over the claim. */
  signatureHex: string;
  /** The attestor address whose key produced the signature; `0x` + 40 hex. */
  attestorAddress: string;
  /** The captured HTTP transcript (headers + body) the claim was extracted from. */
  responseText?: string;
}

const claimDataSchema = z.object({
  provider: z.string(),
  parameters: z.string(),
  owner: z.string(),
  timestampS: z.number(),
  context: z.string(),
  identifier: z.string(),
  epoch: z.number(),
});

/**
 * Runtime validator + type source for the canonical {@link ZkFetchEvidence}.
 *
 * Unknown fields (e.g. the raw zkFetch transform shell) are stripped, so a
 * non-canonical payload either fails or normalizes to the canonical shape it
 * already carries.
 */
export const zkFetchEvidenceSchema = z.object({
  claim: claimDataSchema,
  signatureHex: z.string(),
  attestorAddress: z.string(),
  responseText: z.string().optional(),
});

/**
 * The zkFetch kind's claim schema.
 *
 * Mirror of `@thoth/core/claim`'s `claimSchema` minus the exact-length
 * constraints (see issue #26).
 */
export const zkFetchClaimSchema: z.ZodType<
  Claim<number>,
  z.core.$ZodTypeInternals<Claim<number>, ClaimInput<number>>
> = z
  .object({
    version: z.union([z.number(), z.bigint()]).default(CLAIM_VERSION),
    kind: z.union([z.number(), z.bigint()]),
    timestamp: z.union([z.number(), z.bigint()]),
    nonce: z.instanceof(Uint8Array),
    evidenceHash: z.instanceof(Uint8Array),
    present: z.array(z.boolean()),
    values: z.array(z.union([z.number(), z.bigint()])),
  })
  .transform((input) => ({
    version: BigInt(input.version),
    kind: BigInt(input.kind),
    timestamp: BigInt(input.timestamp),
    nonce: input.nonce,
    evidenceHash: input.evidenceHash,
    present: input.present,
    values: input.values.map((value) => BigInt(value)),
  })) as unknown as z.ZodType<
  Claim<number>,
  z.core.$ZodTypeInternals<Claim<number>, ClaimInput<number>>
>;

/**
 * The zkFetch kind's definition type, as produced by the attestor-side
 * `createZkFetchDefinition`. Owned here — the client only needs the *type*
 * (for its trusted set, transport, and collected-attestation types), and it
 * must be importable without pulling in the attestor's host machinery.
 *
 * @see attestor `createZkFetchDefinition` — the value that satisfies this type.
 */
export interface ZkFetchDefinition {
  /** The kind identifier, `zk-fetch@1`. */
  readonly kind: typeof ZK_FETCH_LAW;
  /** Runtime schema for the policy. */
  readonly policy: typeof zkFetchPolicySchema;
  /** Runtime schema for the evidence. */
  readonly evidence: typeof zkFetchEvidenceSchema;
  /** Runtime schema for the claim. */
  readonly claim: typeof zkFetchClaimSchema;
  /**
   * The kind's check: verify the evidence, check it against the policy, and
   * enforce the proposed claim matches the disclosures. Throws to reject.
   */
  verify(input: AttestationInput<ZkFetchPolicy, ZkFetchEvidence, Claim<number>>): Promise<void>;
  /** The wire law: encode the parsed claim into the flat signed message. */
  message(claim: Claim<number>): FlatMessage;
}

/**
 * The parsed view of evidence, used for claim derivation and policy checks.
 *
 * Everything claim derivation needs from {@link ZkFetchEvidence} — the
 * disclosed values, the canonical hash, the identifier — with none of the
 * ECDSA signature work (this builder performs no signature check; the caller
 * decides what trust to place in the result). The attestor calls it after
 * {@link verifyZkFetchProof}; the client calls it to build the deterministic
 * expected claim that its attestor responses are cross-checked against.
 */
export interface VerifiedEvidence {
  /** The claim data. */
  claim: ProviderClaimData;
  /** The address that signed the claim (lowercased). */
  attestorAddress: string;
  /** The captured HTTP transcript, when the evidence carried one. */
  responseText?: string;
  /**
   * The values the witness extracted from the response it saw, keyed by named
   * regex group. The witness computes them over the redacted transcript and the
   * claim signature covers them, so they are certifiable as they are.
   */
  disclosedValues: Readonly<Record<string, string>>;
  /** Claim identifier. */
  identifier: string;
  /** SHA-256 (hex) over the canonical serialization of the evidence artifacts. */
  canonicalHash: string;
}

/** How a disclosed string value is interpreted for a claim slot. */
export type ZkFetchParseRule = 'int' | 'float';

/**
 * One claim-slot binding: which extracted (disclosed) value feeds which
 * numeric claim slot, and how its string form is interpreted.
 *
 * `slot` becomes the index into `Claim.values`/`Claim.present`; `name` is a
 * named regex group from the proof's `responseMatches`, as disclosed by the
 * verified evidence.
 */
export interface ZkFetchSlot {
  /** Index into the claim's `values`/`present` vectors. */
  slot: number;
  /** The extracted-parameter name (named regex group) to read. */
  name: string;
  /** How the disclosed string is converted to the claim's numeric value. */
  parse: ZkFetchParseRule;
  /**
   * Whether the slot must be certifiable for the evidence to be attested.
   * A required (default) slot needs its disclosure present AND parseable; an
   * optional slot is simply signed unpresent when absent or unparseable.
   */
  optional?: boolean;
}

/**
 * The policy under which a zkFetch attestor attests.
 *
 * The rule for "this evidence may be attested": only evidence whose host is
 * allowlisted and whose disclosures cover every declared slot, within any size
 * bound.
 */
export interface ZkFetchPolicy {
  /** Hosts the attested URL may target; exact or any subdomain suffix. */
  allowedHosts: readonly string[];
  /** Map extracted (disclosed) values onto claim slots. */
  slots: readonly ZkFetchSlot[];
  /**
   * Maximum seconds between the proposed claim timestamp and this attestor's
   * own witness observation. Defaults to {@link DEFAULT_MAX_SKEW_S}.
   */
  maxSkewS?: number;
  /** Upper bound on the captured response size in bytes. */
  maxResponseBytes?: number;
  /** Claim schema version the attestor signs; must match the contract's.
   * Defaults to 1. */
  claimVersion?: bigint;
  /** Contract-facing kind code the attestor signs (1 = zkFetch); must match the contract's. Defaults to 1. */
  claimKind?: bigint;
}

/**
 * Runtime validator + type source for {@link ZkFetchPolicy}.
 *
 * Both sides parse the shared policy through it: the client at `init`, the
 * attestor before running its checks.
 */
export const zkFetchPolicySchema = z.object({
  allowedHosts: z.array(z.string()).min(1),
  slots: z
    .array(
      z.object({
        slot: z.number().int().nonnegative(),
        name: z.string().min(1),
        parse: z.enum(['int', 'float']),
        optional: z.boolean().optional(),
      }),
    )
    .min(1),
  maxSkewS: z.number().int().nonnegative().optional(),
  maxResponseBytes: z.number().int().nonnegative().optional(),
  claimVersion: z.bigint().optional(),
  claimKind: z.bigint().optional(),
});

/**
 * Hash a zkFetch policy under the `zk-fetch@1` law.
 *
 * The policy is parsed and normalized first, so policies that mean the same
 * thing hash the same: unknown keys are dropped, defaults are filled in, hosts
 * are lowercased, deduplicated and sorted, and slots are sorted by index. The
 * wire version is the policy's `claimVersion` (default 1).
 *
 * @param policy — the policy to hash.
 * @returns the 32-byte policy hash (see `@thoth/core/intent`'s `policyHashOf`).
 * @throws if the policy fails {@link zkFetchPolicySchema}.
 */
export const zkFetchPolicyHashOf = (policy: ZkFetchPolicy): Uint8Array => {
  const parsed = zkFetchPolicySchema.parse(policy);
  const claimVersion = parsed.claimVersion ?? CLAIM_VERSION;
  const normalized = {
    allowedHosts: [...new Set(parsed.allowedHosts.map((host) => host.toLowerCase()))].sort(),
    slots: parsed.slots
      .map((slot) => ({ ...slot, optional: slot.optional ?? false }))
      .sort((a, b) => a.slot - b.slot),
    maxSkewS: parsed.maxSkewS ?? DEFAULT_MAX_SKEW_S,
    maxResponseBytes: parsed.maxResponseBytes,
    claimVersion,
    claimKind: parsed.claimKind ?? 1n,
  };
  return policyHashOf(ZK_FETCH_LAW, normalized, claimVersion);
};

/** The request identity a zkFetch claim is about: the method, URL and body. */
export interface ZkFetchRequest {
  /** The HTTP method. */
  method: string;
  /** The requested URL. */
  url: string;
  /** The request body; absent means empty. */
  body?: string;
}

/**
 * The zkFetch subject struct: one SHA-256 digest per part of the request.
 *
 * Mirrors a Compact `struct { method, host, path, body: Bytes<32> }`. Keeping
 * the host apart lets an app bind the source host in-circuit while the path,
 * which may name an account, stays private.
 */
export interface ZkFetchSubject {
  /** SHA-256 of the uppercased method. */
  method: Uint8Array;
  /** SHA-256 of the URL host, lowercased, with any non-default port. */
  host: Uint8Array;
  /** SHA-256 of the URL path and query, without the fragment. */
  path: Uint8Array;
  /** SHA-256 of the body. */
  body: Uint8Array;
}

/**
 * Build the zkFetch subject struct of a request.
 *
 * @param request — the request identity.
 * @returns the subject struct.
 * @throws if the URL does not parse.
 */
export const zkFetchSubjectOf = (request: ZkFetchRequest): ZkFetchSubject => {
  const url = new URL(request.url);
  const digest = (text: string): Uint8Array =>
    new Uint8Array(createHash('sha256').update(text, 'utf-8').digest());
  return {
    method: digest(request.method.toUpperCase()),
    host: digest(url.host),
    path: digest(`${url.pathname}${url.search}`),
    body: digest(request.body ?? ''),
  };
};

/**
 * Hash the subject of a zkFetch request.
 *
 * @param request — the request identity.
 * @returns the 32-byte subject hash of {@link zkFetchSubjectOf} the request.
 * @throws if the URL does not parse.
 */
export const zkFetchSubjectHashOf = (request: ZkFetchRequest): Uint8Array => {
  const { method, host, path, body } = zkFetchSubjectOf(request);
  return subjectHashOf([method, host, path, body]);
};

const hostAllowed = (host: string, allowedHosts: readonly string[]): boolean => {
  const lower = host.toLowerCase();
  return allowedHosts.some(
    (allowed) => lower === allowed.toLowerCase() || lower.endsWith(`.${allowed.toLowerCase()}`),
  );
};

/**
 * Decode the URL a claim attests from its signed parameters.
 *
 * @param claim — the signed claim data.
 * @returns the attested URL.
 * @throws if the parameters do not carry a non-empty `url`.
 */
export const claimUrl = (claim: ProviderClaimData): string => {
  let parameters: Readonly<{ url?: string }>;
  try {
    parameters = JSON.parse(claim.parameters) as Readonly<{ url?: string }>;
  } catch {
    throw new Error('claim parameters are not valid JSON');
  }
  if (typeof parameters.url !== 'string' || parameters.url === '') {
    throw new Error('claim parameters carry no url');
  }
  return parameters.url;
};

/**
 * Read the values the witness extracted from the response it saw.
 *
 * The signature already binds `claim.context`; this parser only interprets it.
 * Reclaim redacts client-side — `responseRedactions` selects the slices the
 * witness sees and the rest of the response never reaches it — so the extracted
 * values are the witness's own computation over the redacted transcript.
 * Nothing is dropped here: the reveal whitelist already did the hiding.
 *
 * @param claim — signed claim data whose context carries `extractedParameters`.
 * @returns the certifiable disclosed values.
 */
const disclosedValuesOf = (claim: ProviderClaimData): Readonly<Record<string, string>> => {
  let context: Readonly<{ extractedParameters?: Readonly<Record<string, string>> }>;
  try {
    context = JSON.parse(claim.context) as Readonly<{
      extractedParameters?: Readonly<Record<string, string>>;
    }>;
  } catch {
    throw new Error('claim context is not valid JSON');
  }
  return context.extractedParameters ?? {};
};

/**
 * Canonically serialize a value for hashing.
 *
 * Deterministic for the plain data evidence carries; `bigint` and `Uint8Array`
 * survive so future evidence shapes hash stably too. Rejects cycles.
 */
const canonicalJson = (value: unknown): string => {
  const seen = new WeakSet<object>();
  return JSON.stringify(value, (_key, v) => {
    if (typeof v === 'bigint') {
      return `0x${v.toString(16)}`;
    }
    if (v instanceof Uint8Array) {
      return { $bytes: Buffer.from(v).toString('hex') };
    }
    if (typeof v === 'object' && v !== null) {
      if (seen.has(v)) {
        throw new Error('circular structure while canonicalizing');
      }
      seen.add(v);
    }
    return v;
  }) as string;
};

/**
 * SHA-256 of a string, hex-encoded.
 *
 * @param data — the input string.
 * @returns the lower-hex digest.
 */
const sha256Hex = (data: string): string =>
  createHash('sha256').update(data, 'utf-8').digest('hex');

/** The contract's value type is `Uint<64>`; only non-negative values below 2^64 are certifiable. */
const UINT64_MAX = 1n << 64n;

/**
 * Parse a disclosed string value into the claim's numeric slot value.
 *
 * Returns `null` when the value cannot be interpreted under the rule or falls
 * outside the wire's `Uint<64>` range `[0, 2^64)` — such a disclosure is not
 * certifiable and its slot stays unpresent, rather than the attestor guessing
 * a numeric reading or signing a value the contract can never verify.
 *
 * Exported for the attestor side's disclosure cross-check
 * (`assertClaimMatchesDisclosures`); claim derivation uses it internally.
 *
 * @param value — the disclosed string value.
 * @param rule — how to interpret it.
 * @returns the numeric value, or `null` when unparseable or out of range.
 */
export const parseDisclosedValue = (value: string, rule: ZkFetchParseRule): bigint | null => {
  switch (rule) {
    case 'int': {
      if (!/^\d+$/.test(value)) {
        return null;
      }
      const big = BigInt(value);
      return big < UINT64_MAX ? big : null;
    }
    case 'float': {
      const parsed = Number.parseFloat(value);
      if (!Number.isFinite(parsed) || parsed < 0) {
        return null;
      }
      const rounded = Math.round(parsed);
      if (rounded < 0 || rounded >= UINT64_MAX) {
        return null;
      }
      return BigInt(rounded);
    }
  }
};

/**
 * The parsed view of {@link ZkFetchEvidence} that claim derivation and policy
 * checks operate on.
 *
 * Everything needed — the disclosed values, the canonical hash, the
 * identifier — with none of the ECDSA signature work. This builder performs
 * no signature check itself: the attestor calls it *after*
 * `verifyZkFetchProof`; a caller that uses it without verifying is certifying
 * by derivation against attestors that each verified (see the client).
 *
 * @param evidence — canonicalized proof artifacts.
 * @returns the verified-evidence view.
 */
export const parsedEvidenceView = (evidence: ZkFetchEvidence): VerifiedEvidence => {
  const canonical = {
    claim: evidence.claim,
    signatureHex: evidence.signatureHex,
    attestorAddress: evidence.attestorAddress,
    responseText: evidence.responseText ?? null,
  };
  return {
    claim: evidence.claim,
    attestorAddress: evidence.attestorAddress,
    responseText: evidence.responseText,
    disclosedValues: disclosedValuesOf(evidence.claim),
    identifier: evidence.claim.identifier,
    canonicalHash: sha256Hex(canonicalJson(canonical)),
  };
};

/**
 * Derive the canonical {@link Claim} the attestor signs from parsed evidence.
 *
 * The claim reflects the evidence, not the client's proposal. `values`/`present`
 * come from the policy-declared disclosures, and `evidenceHash` is the Reclaim
 * identifier, which depends only on provider, parameters, and context, so every
 * witness derives the same identifier for the same observation. `version`/`kind`
 * come from the policy (`claimVersion`/`claimKind`, defaulting to 1). The
 * timestamp is the caller's `timestamp`, which the client proposes and the law
 * bounds against the witness's own observation. The nonce is a domain-separated
 * SHA-256 of that identifier, so one observation with one context yields the
 * same nonce from every witness, and a fresh context yields a fresh nonce. A
 * slot whose disclosure is absent stays unpresent. The evidence carries only
 * what the witness saw.
 *
 * @typeParam V — the claim's value-slot count.
 * @param options — the parsed evidence view, the policy, the slot count, and
 *   the timestamp to sign.
 * @returns the derived claim.
 * @throws if a policy slot is out of the claim's value range.
 */
export const deriveClaimFromEvidence = <V extends number>(options: {
  /** The evidence view (see {@link parsedEvidenceView}). */
  verified: VerifiedEvidence;
  /** The policy declaring the slot map. */
  policy: ZkFetchPolicy;
  /** The claim's value-slot count (the target contract's `#V`). */
  valueSlots: V;
  /** The claim timestamp to sign, proposed by the client. */
  timestamp: bigint;
}): Claim<V> => {
  const { verified, policy, valueSlots, timestamp } = options;
  const outOfRange = policy.slots.find((slot) => slot.slot >= valueSlots);
  if (outOfRange !== undefined) {
    throw new Error(
      `policy slot ${outOfRange.slot} is out of the claim's ${valueSlots} value slots`,
    );
  }
  const present = Array.from({ length: valueSlots }, () => false);
  const values = Array.from({ length: valueSlots }, () => 0n);
  for (const slot of policy.slots) {
    const raw = verified.disclosedValues[slot.name];
    if (raw === undefined) {
      continue;
    }
    const value = parseDisclosedValue(raw, slot.parse);
    if (value === null) {
      continue;
    }
    present[slot.slot] = true;
    values[slot.slot] = value;
  }
  return {
    version: policy.claimVersion ?? CLAIM_VERSION,
    kind: policy.claimKind ?? 1n,
    timestamp,
    nonce: hexToBytes(sha256Hex(`thoth:nonce:${verified.identifier}`)),
    evidenceHash: hexToBytes(verified.identifier),
    present,
    values,
  } as Claim<V>;
};

/**
 * Check evidence against the policy.
 *
 * Fails fast so the attestor does not waste work: the attested URL must be
 * HTTPS against an allowlisted host, every *required* policy slot's disclosure
 * must be certifiable (present and parseable — optional slots may be absent and
 * are signed unpresent), and the captured response must fit any size bound.
 *
 * @param verified — the evidence view (see {@link parsedEvidenceView}).
 * @param policy — the policy.
 * @returns the lowercased attested host, on success.
 * @throws with a descriptive message if a policy check fails.
 */
export const assertEvidenceMatchesPolicy = (
  verified: VerifiedEvidence,
  policy: ZkFetchPolicy,
): string => {
  const url = new URL(claimUrl(verified.claim));
  if (url.protocol !== 'https:') {
    throw new Error(`attested url must be https, got ${url.protocol}//`);
  }
  const host = url.hostname.toLowerCase();
  if (!hostAllowed(host, policy.allowedHosts)) {
    throw new Error(`attested host ${host} not in allowlist [${policy.allowedHosts.join(', ')}]`);
  }
  for (const slot of policy.slots) {
    if (slot.optional) {
      continue;
    }
    const raw = verified.disclosedValues[slot.name];
    if (raw === undefined || parseDisclosedValue(raw, slot.parse) === null) {
      throw new Error(
        `policy requires a certifiable value for "${slot.name}" but the proof did not disclose a parseable value`,
      );
    }
  }
  if (
    policy.maxResponseBytes !== undefined &&
    verified.responseText !== undefined &&
    Buffer.byteLength(verified.responseText, 'utf-8') > policy.maxResponseBytes
  ) {
    throw new Error(`captured response exceeds maxResponseBytes (${policy.maxResponseBytes})`);
  }
  return host;
};
