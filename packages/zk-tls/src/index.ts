import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import type { AttestationInput } from '@thoth/core';
import type { Claim, ClaimInput, FlatMessage } from '@thoth/core/claim';
import { bytes32Schema, CLAIM_VERSION, claimSchema } from '@thoth/core/claim';
import type { CanonicalValue } from '@thoth/core/claim-context';
import { claimContextDigestOf, policyHashOf, subjectHashOf } from '@thoth/core/claim-context';
import { z } from 'zod';
import { bytesToHex, hexToBytes } from './hex.js';

/** The zkFetch kind's law tag, also its kind identifier. */
export const ZK_FETCH_LAW = 'zk-fetch@1';

/**
 * The record a Reclaim witness signs over the fetch it witnessed.
 *
 * Mirrors `proto.ProviderClaimData` from `@reclaimprotocol/attestor-core`.
 */
export interface ProviderClaimData {
  /** The Reclaim provider, `http` for a fetch. */
  provider: string;
  /** Canonical JSON of the request: url, method, headers, body and the disclosure rules. */
  parameters: string;
  /** The public key or address that requested the claim. */
  owner: string;
  /**
   * The observation time the witness signed, Unix seconds. The request sets it; Reclaim rejects
   * it only when it is more than 10 minutes in the future.
   */
  timestampS: number;
  /** Canonical JSON of the context, including `extractedParameters`. */
  context: string;
  /** Hash of provider, parameters and context. */
  identifier: string;
  /** Reclaim's beacon epoch, signed with the claim; this kind does not read it. */
  epoch: number;
}

/** The one evidence shape this kind accepts, as the prover produces it. */
export interface ZkFetchEvidence {
  claim: ProviderClaimData;
  /** Hex-encoded 65-byte ECDSA signature over the claim. */
  signatureHex: string;
  /** The witness address whose key signed, `0x` + 40 hex. */
  attestorAddress: string;
  /** The HTTP transcript as the client saw it. Not witness-signed. */
  responseText?: string;
}

/**
 * The largest input a zkFetch attestor parses. The schemas reject anything
 * bigger before any proof check or signature runs, so an oversized request
 * costs the attestor no more than its parse.
 *
 * Every attestor of the kind enforces the same limits, so a trusted set never
 * splits on input size. String limits count UTF-16 code units.
 */
export const ZK_FETCH_LIMITS = {
  /** Numeric claim slots, `values.length`. */
  valueSlots: 64,
  /** Byte claim slots, `byteValues.length`. */
  byteSlots: 64,
  /** Entries in a policy's `allowedHosts`. */
  allowedHosts: 64,
  /** Entries in a policy's `responseMatches`. */
  responseMatches: 32,
  /** Entries in a policy's `responseRedactions`. */
  responseRedactions: 32,
  /** A host in `allowedHosts`, the DNS name limit. */
  hostLength: 253,
  /** A slot's `name`. */
  slotNameLength: 128,
  /** A response match `value`, or a redaction's `regex`, `jsonPath` or `xPath`. */
  ruleLength: 4096,
  /** The evidence's `claim.parameters`: the signed request, headers and body included. */
  parametersLength: 256 * 1024,
  /** The evidence's `claim.context`, which carries every disclosed value. */
  contextLength: 1024 * 1024,
  /** The evidence's `responseText`, the transcript as the client saw it. */
  responseTextLength: 4 * 1024 * 1024,
  /**
   * Every other evidence string: `provider`, `owner`, `identifier`,
   * `signatureHex` and `attestorAddress`.
   */
  fieldLength: 256,
} as const;

/** An evidence string with no larger limit of its own. */
const evidenceField = z.string().max(ZK_FETCH_LIMITS.fieldLength);

const claimDataSchema = z.object({
  provider: evidenceField,
  parameters: z.string().max(ZK_FETCH_LIMITS.parametersLength),
  owner: evidenceField,
  timestampS: z.number(),
  context: z.string().max(ZK_FETCH_LIMITS.contextLength),
  identifier: evidenceField,
  epoch: z.number(),
});

/**
 * Runtime validator for {@link ZkFetchEvidence}. Unknown fields are stripped,
 * and every string is capped by {@link ZK_FETCH_LIMITS}.
 */
export const zkFetchEvidenceSchema = z.object({
  claim: claimDataSchema,
  signatureHex: evidenceField,
  attestorAddress: evidenceField,
  responseText: z.string().max(ZK_FETCH_LIMITS.responseTextLength).optional(),
});

/** The most claim slots, numeric and byte together. */
const MAX_SLOTS = ZK_FETCH_LIMITS.valueSlots + ZK_FETCH_LIMITS.byteSlots;

/** The claim's slot arrays and the most entries each may have. */
const SLOT_ARRAY_LIMITS = [
  ['values', ZK_FETCH_LIMITS.valueSlots],
  ['byteValues', ZK_FETCH_LIMITS.byteSlots],
  ['present', MAX_SLOTS],
] as const;

/**
 * The zkFetch kind's claim schema.
 *
 * `claimSchema` from `@thoth/core/claim` without the fixed lengths: the slot
 * counts are `values.length` and `byteValues.length` (default `[]`), and
 * `present` needs one flag per slot. The counts are capped by
 * {@link ZK_FETCH_LIMITS}.
 */
export const zkFetchClaimSchema = z.preprocess<
  unknown,
  ReturnType<typeof claimSchema<number, number>>,
  ClaimInput<number, number>
>((input: unknown, context) => {
  // Counted before any element is parsed: the signed message has one field per
  // slot, so an uncapped count is a cheap CPU and memory attack.
  const record: Readonly<Record<string, unknown>> =
    typeof input === 'object' && input !== null ? (input as Record<string, unknown>) : {};
  for (const [key, max] of SLOT_ARRAY_LIMITS) {
    const entries = record[key];
    if (Array.isArray(entries) && entries.length > max) {
      context.addIssue({
        code: 'too_big',
        origin: 'array',
        maximum: max,
        inclusive: true,
        input: entries,
        path: [key],
        message: `${key} has ${entries.length} entries; at most ${max} allowed`,
      });
    }
  }
  return input;
}, claimSchema<number, number>());

/**
 * The zkFetch kind's definition, the value `createZkFetchDefinition` returns.
 *
 * Declared here so the client can import the type without the attestor's
 * dependencies.
 */
export interface ZkFetchDefinition {
  /** The kind identifier, `zk-fetch@1`. */
  readonly kind: typeof ZK_FETCH_LAW;
  readonly policy: typeof zkFetchPolicySchema;
  readonly evidence: typeof zkFetchEvidenceSchema;
  readonly claim: typeof zkFetchClaimSchema;
  /** The kind's check. Throws to reject. */
  verify(
    input: AttestationInput<ZkFetchPolicy, ZkFetchEvidence, Claim<number, number>>,
  ): Promise<void>;
  /** Encode the parsed claim into the flat signed message. */
  message(claim: Claim<number, number>): FlatMessage;
}

/** The parsed view of {@link ZkFetchEvidence} that claim derivation and policy checks read. */
export interface VerifiedEvidence {
  claim: ProviderClaimData;
  /** The address that signed the claim, lowercased. */
  attestorAddress: string;
  /** The HTTP transcript as the client saw it. Not witness-signed. */
  responseText?: string;
  /** The values the witness extracted, keyed by named regex group. The claim signature covers them. */
  disclosedValues: Readonly<Record<string, string>>;
  identifier: string;
  /** SHA-256 hex over the canonical serialization of the evidence. */
  canonicalHash: string;
}

/**
 * How a disclosed string becomes a claim value.
 *
 * `int` takes decimal digits; `float` takes an unsigned decimal with an
 * optional exponent and rounds halves up; both must fit `Uint<64>`. `bytes`,
 * `hex` and `base64` fill a 32-byte slot (ADR 0010). The dApp guide's
 * "Building the policy" section lists what each rule accepts.
 */
export type ZkFetchParseRule = 'int' | 'float' | 'bytes' | 'hex' | 'base64';

/** The parse rules that fill a 32-byte claim slot. */
export type ByteRule = 'bytes' | 'hex' | 'base64';

/** Whether a parse rule targets a byte slot rather than a numeric one. */
export const isByteRule = (rule: ZkFetchParseRule): rule is ByteRule =>
  rule === 'bytes' || rule === 'hex' || rule === 'base64';

/** One claim-slot binding: which disclosed value feeds which slot, and how it is parsed. */
export interface ZkFetchSlot {
  /** Index into the claim's value slots: numeric `0..V-1`, byte `V..V+W-1`. */
  slot: number;
  /** The named regex group to read from the disclosed values. */
  name: string;
  parse: ZkFetchParseRule;
  /**
   * Exact byte length the value must have, 1–32, byte rules only: the UTF-8
   * length for `bytes`, the decoded length for `hex` and `base64`.
   */
  length?: number;
  /** When true, an absent or unparseable disclosure is signed unpresent instead of rejected. */
  optional?: boolean;
}

/** One response pattern the witness applies; its named groups become disclosed values. */
export interface ZkFetchResponseMatch {
  /** `regex` extracts named groups; `contains` only guards the response. */
  type: 'regex' | 'contains';
  value: string;
}

/** One slice of the response revealed to the witness. Everything not selected stays hidden. */
export interface ZkFetchResponseRedaction {
  regex?: string;
  jsonPath?: string;
  xPath?: string;
}

/**
 * How the policy constrains the signed request body.
 *
 * `non-empty` requires a non-empty signed body, which the witness compares to
 * the sent body. `{ sha256 }` pins an exact non-empty body; the empty body's
 * hash is refused, so `sha256('')` is not a pin. `ignored` requires an empty
 * signed body and does not bind the body the witness sent; it asserts that a
 * body cannot change the endpoint's response at any layer. Under every mode a
 * signed body containing `*` is refused.
 */
export type ZkFetchBodyPolicy = 'ignored' | 'non-empty' | { readonly sha256: Uint8Array };

/** The policy a zkFetch attestor enforces. */
export interface ZkFetchPolicy {
  /** Hosts the attested URL may target: exact, or any subdomain of one. */
  allowedHosts: readonly string[];
  slots: readonly ZkFetchSlot[];
  /** The response patterns the witness must have signed. */
  responseMatches: readonly ZkFetchResponseMatch[];
  /** The reveal whitelist the witness must have signed. */
  responseRedactions: readonly ZkFetchResponseRedaction[];
  /**
   * How the signed request body is bound (see {@link ZkFetchBodyPolicy}). The
   * policy hash commits to it, so every attestor enforces the same rule.
   */
  bodyPolicy: ZkFetchBodyPolicy;
  /** The claim version the attestor signs. Defaults to 1. */
  claimVersion?: bigint;
}

// Reclaim fills `{{name}}` from caller-chosen `paramValues` before matching, so
// a templated rule signs one text and runs another.
const noTemplate = (rule: string): boolean => !/\{\{[^{}]+\}\}/.test(rule);
const TEMPLATE_ERROR = 'disclosure rules cannot use {{param}} templates';

/** A disclosure rule's text, capped by {@link ZK_FETCH_LIMITS}. */
const ruleText = z.string().max(ZK_FETCH_LIMITS.ruleLength);

/** SHA-256 of a UTF-8 string, raw bytes. */
const sha256 = (data: string): Uint8Array =>
  new Uint8Array(createHash('sha256').update(data, 'utf-8').digest());

/** The empty body's hash, which a `{ sha256 }` policy pin refuses. */
const EMPTY_BODY_SHA256 = bytesToHex(sha256(''));

/**
 * Runtime validator for {@link ZkFetchPolicy}.
 *
 * Rule entries are strict, so Reclaim's `invert` and `hash` are refused, and
 * rule texts cannot carry `{{param}}` templates. `bodyPolicy` is required; a
 * pin is 32 bytes and not the empty body's hash. Array and string sizes are
 * capped by {@link ZK_FETCH_LIMITS}.
 */
export const zkFetchPolicySchema = z.object({
  allowedHosts: z
    .array(z.string().max(ZK_FETCH_LIMITS.hostLength))
    .min(1)
    .max(ZK_FETCH_LIMITS.allowedHosts),
  slots: z
    .array(
      z
        .object({
          slot: z.number().int().nonnegative(),
          name: z.string().min(1).max(ZK_FETCH_LIMITS.slotNameLength),
          parse: z.enum(['int', 'float', 'bytes', 'hex', 'base64']),
          length: z.number().int().min(1).max(32).optional(),
          optional: z.boolean().optional(),
        })
        .superRefine((slot, context) => {
          if (slot.length !== undefined && !isByteRule(slot.parse)) {
            context.addIssue({
              code: 'custom',
              message: `'length' is only valid for byte rules, not '${slot.parse}'`,
              path: ['length'],
            });
          }
        }),
    )
    .min(1)
    .max(MAX_SLOTS),
  responseMatches: z
    .array(
      z.strictObject({
        type: z.enum(['regex', 'contains']),
        value: ruleText.min(1).refine(noTemplate, TEMPLATE_ERROR),
      }),
    )
    .min(1)
    .max(ZK_FETCH_LIMITS.responseMatches),
  responseRedactions: z
    .array(
      z.strictObject({
        regex: ruleText.refine(noTemplate, TEMPLATE_ERROR).optional(),
        jsonPath: ruleText.refine(noTemplate, TEMPLATE_ERROR).optional(),
        xPath: ruleText.refine(noTemplate, TEMPLATE_ERROR).optional(),
      }),
    )
    .max(ZK_FETCH_LIMITS.responseRedactions),
  bodyPolicy: z.union([
    z.literal('ignored'),
    z.literal('non-empty'),
    z
      .strictObject({ sha256: bytes32Schema })
      .refine((pin) => bytesToHex(pin.sha256) !== EMPTY_BODY_SHA256, {
        message: "a body pin cannot be the empty body; use bodyPolicy: 'ignored'",
      }),
  ]),
  claimVersion: z.bigint().optional(),
});

const compareStrings = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Sort rule entries by their JSON with keys sorted, so neither array order nor
 * the order a rule's keys were written in changes a hash or a comparison.
 */
const sortCanonical = <T>(entries: readonly T[]): T[] => {
  // Rules are flat records, so sorting the top-level keys is enough.
  const keyOf = (entry: T): string =>
    canonicalJson(
      entry !== null && typeof entry === 'object'
        ? Object.fromEntries(Object.entries(entry).sort(([a], [b]) => compareStrings(a, b)))
        : entry,
    );
  return [...entries].sort((a, b) => compareStrings(keyOf(a), keyOf(b)));
};

/**
 * The canonical form every disclosure-rules comparison and hash reads.
 *
 * Folds only what Reclaim folds: an absent array is empty, a redaction's absent
 * keys are empty strings, and entries are sorted. Every other field is kept,
 * so a signed rule carrying `invert` or `hash` still mismatches the policy.
 */
const normalizedRulesOf = (rules: {
  responseMatches?: unknown;
  responseRedactions?: unknown;
}): { responseMatches: CanonicalValue[]; responseRedactions: CanonicalValue[] } => {
  const matches = (rules.responseMatches ?? []) as readonly CanonicalValue[];
  const redactions = (rules.responseRedactions ?? []) as readonly CanonicalValue[];
  return {
    responseMatches: sortCanonical(matches),
    responseRedactions: sortCanonical(
      redactions.map((entry) => {
        if (entry === null || typeof entry !== 'object') {
          return entry;
        }
        const record = entry as Record<string, CanonicalValue | undefined>;
        return {
          ...record,
          regex: record.regex ?? '',
          jsonPath: record.jsonPath ?? '',
          xPath: record.xPath ?? '',
        };
      }),
    ),
  };
};

/**
 * Parse a policy into the form every hash and check reads: defaults filled,
 * hosts lowercased, deduplicated and sorted, slots sorted by index, the
 * disclosure rules canonicalized, and `bodyPolicy` carried through.
 *
 * @throws if the policy fails {@link zkFetchPolicySchema}.
 */
export const normalizePolicy = (policy: ZkFetchPolicy) => {
  const parsed = zkFetchPolicySchema.parse(policy);
  const rules = normalizedRulesOf(parsed);
  return {
    allowedHosts: [...new Set(parsed.allowedHosts.map((host) => host.toLowerCase()))].sort(),
    slots: parsed.slots
      .map((slot) => ({ ...slot, optional: slot.optional ?? false }))
      .sort((a, b) => a.slot - b.slot),
    responseMatches: rules.responseMatches,
    responseRedactions: rules.responseRedactions,
    bodyPolicy: parsed.bodyPolicy,
    claimVersion: parsed.claimVersion ?? CLAIM_VERSION,
  };
};

/**
 * Hash a policy under the `zk-fetch@1` law and its `claimVersion`.
 *
 * Policies that normalize the same hash the same (see {@link normalizePolicy}).
 *
 * @throws if the policy fails {@link zkFetchPolicySchema}.
 */
export const zkFetchPolicyHashOf = (policy: ZkFetchPolicy): Uint8Array => {
  const normalized = normalizePolicy(policy);
  return policyHashOf(ZK_FETCH_LAW, normalized, normalized.claimVersion);
};

/**
 * SHA-256 of a request body, as a policy's `bodyPolicy: { sha256 }` pin.
 *
 * The policy refuses the empty body's hash as a pin; use `'ignored'` for an
 * empty signed body.
 *
 * @throws if the body contains `*`: no signed body may carry one, so the pin
 *   could never match.
 */
export const zkFetchBodyHashOf = (body: string): Uint8Array => {
  if (body.includes('*')) {
    throw new Error('a pinned body cannot contain *');
  }
  return sha256(body);
};

/** The request a zkFetch claim is about. */
export interface ZkFetchSubjectRequest {
  method: string;
  url: string;
  /** Absent means empty. */
  body?: string;
}

/**
 * The zkFetch subject: one SHA-256 per request part, mirroring a Compact
 * `struct { method, host, path, body: Bytes<32> }`.
 *
 * The host is its own field so an app can bind the source host in-circuit
 * while the path, which may name an account, stays private (ADR 0001).
 */
export interface ZkFetchSubject {
  /** SHA-256 of the uppercased method. */
  method: Uint8Array;
  /** SHA-256 of the lowercased host, with any non-default port. */
  host: Uint8Array;
  /** SHA-256 of the path and query, without the fragment. */
  path: Uint8Array;
  /** SHA-256 of the body. */
  body: Uint8Array;
}

/**
 * Build the subject of a request.
 *
 * @throws if the URL does not parse.
 */
export const zkFetchSubjectOf = (request: ZkFetchSubjectRequest): ZkFetchSubject => {
  const url = new URL(request.url);
  return {
    method: sha256(request.method.toUpperCase()),
    host: sha256(url.host),
    path: sha256(`${url.pathname}${url.search}`),
    body: sha256(request.body ?? ''),
  };
};

/**
 * Hash the subject of a request.
 *
 * @throws if the URL does not parse.
 */
export const zkFetchSubjectHashOf = (request: ZkFetchSubjectRequest): Uint8Array => {
  const { method, host, path, body } = zkFetchSubjectOf(request);
  return subjectHashOf([method, host, path, body]);
};

/** The key under which every witness signs the claim context digest into its context. */
export const ZK_FETCH_CLAIM_CONTEXT_KEY = 'thothClaimContext';

/**
 * The claim context digest a witness signs, as lowercase hex without a prefix:
 * `claimContextDigestOf` over the policy hash, the request's subject hash, the
 * holder and the window (ADR 0011).
 *
 * @throws if the policy fails {@link zkFetchPolicySchema}, the URL does not
 *   parse, the holder is not 32 bytes, or a window bound is negative.
 */
export const zkFetchClaimContextDigestOf = (options: {
  policy: ZkFetchPolicy;
  /** The request the witness signs. */
  request: ZkFetchSubjectRequest;
  /** Per-claim holder commitment, 32 bytes. */
  holder: Uint8Array;
  /** Unix seconds. */
  windowStart: bigint;
  /** Unix seconds. */
  windowEnd: bigint;
}): string => {
  const { policy, request, holder, windowStart, windowEnd } = options;
  return bytesToHex(
    claimContextDigestOf({
      policyHash: zkFetchPolicyHashOf(policy),
      subjectHash: zkFetchSubjectHashOf(request),
      holder,
      windowStart,
      windowEnd,
    }),
  );
};

/**
 * The claim context digest the witness signed into the claim's context, as
 * lowercase hex without a prefix.
 *
 * @throws if the context is not JSON, or carries no 32-byte hex digest under
 *   {@link ZK_FETCH_CLAIM_CONTEXT_KEY}.
 */
export const signedClaimContextDigestOf = (claim: ProviderClaimData): string => {
  let signed: unknown;
  try {
    signed = (JSON.parse(claim.context) as Record<string, unknown> | null)?.[
      ZK_FETCH_CLAIM_CONTEXT_KEY
    ];
  } catch {
    throw new Error('claim context is not valid JSON');
  }
  if (typeof signed !== 'string' || !/^[0-9a-f]{64}$/.test(signed)) {
    throw new Error('the witness-signed context carries no claim context digest');
  }
  return signed;
};

const hostAllowed = (host: string, allowedHosts: readonly string[]): boolean => {
  const lower = host.toLowerCase();
  return allowedHosts.some(
    (allowed) => lower === allowed.toLowerCase() || lower.endsWith(`.${allowed.toLowerCase()}`),
  );
};

/**
 * Parse the signed parameters of a claim. Only `url` is validated; each caller
 * validates the fields it uses.
 *
 * @throws if the parameters are not JSON or carry no non-empty `url`.
 */
const claimParametersOf = (
  claim: ProviderClaimData,
): Readonly<{
  url: string;
  method?: unknown;
  body?: unknown;
  geoLocation?: unknown;
  proxySessionId?: unknown;
  responseMatches?: unknown;
  responseRedactions?: unknown;
}> => {
  let parameters: Readonly<{
    url?: unknown;
    method?: unknown;
    body?: unknown;
    geoLocation?: unknown;
    proxySessionId?: unknown;
    responseMatches?: unknown;
    responseRedactions?: unknown;
  }>;
  try {
    parameters = JSON.parse(claim.parameters) as typeof parameters;
  } catch {
    throw new Error('claim parameters are not valid JSON');
  }
  if (typeof parameters.url !== 'string' || parameters.url === '') {
    throw new Error('claim parameters carry no url');
  }
  return {
    url: parameters.url,
    method: parameters.method,
    body: parameters.body,
    geoLocation: parameters.geoLocation,
    proxySessionId: parameters.proxySessionId,
    responseMatches: parameters.responseMatches,
    responseRedactions: parameters.responseRedactions,
  };
};

/**
 * The URL a claim attests, from its signed parameters.
 *
 * @throws if the parameters are not JSON or carry no non-empty `url`.
 */
export const claimUrl = (claim: ProviderClaimData): string => claimParametersOf(claim).url;

/**
 * The request a claim attests, from its signed parameters. The subject hash
 * is taken over it (see {@link zkFetchSubjectHashOf}).
 *
 * @throws if the parameters are not JSON, lack a non-empty `url` or `method`,
 *   or carry a `body` that is not a string.
 */
export const claimRequestOf = (claim: ProviderClaimData): ZkFetchSubjectRequest => {
  const { url, method, body } = claimParametersOf(claim);
  if (typeof method !== 'string' || method === '') {
    throw new Error('claim parameters carry no method');
  }
  if (body !== undefined && typeof body !== 'string') {
    throw new Error('claim parameters carry a body that is not a string');
  }
  return body === undefined ? { method, url } : { method, url, body };
};

/**
 * The values the witness extracted, from the signed context. Reclaim redacts
 * client-side, so these are the witness's own reading of the revealed slices.
 *
 * @throws if the context is not JSON.
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

/** Deterministic JSON for hashing; `bigint` and `Uint8Array` survive. Rejects cycles. */
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

/** SHA-256 of a UTF-8 string, lower hex. */
const sha256Hex = (data: string): string => Buffer.from(sha256(data)).toString('hex');

/** The contract's value type is `Uint<64>`; only non-negative values below 2^64 are certifiable. */
const UINT64_MAX = 1n << 64n;

/** Parse an unsigned decimal, round halves up, and require a Uint<64> result. */
const parseDecimalUint64 = (value: string): bigint | null => {
  const match = /^([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/.exec(value);
  if (match?.[1] === undefined || match[0] !== value) {
    return null;
  }
  const whole = match[1];
  const fraction = match[2] ?? '';
  const exponent = BigInt(match[3] ?? '0');
  const digits = (whole + fraction).replace(/^0+/, '');
  if (digits.length === 0) {
    return 0n;
  }

  // Removing leading zeros preserves the number of digits after the decimal point.
  const integerDigitCount = BigInt(digits.length) - BigInt(fraction.length) + exponent;
  if (integerDigitCount < 0n) {
    return 0n;
  }
  // Uint<64> has at most 20 digits; reject before padding enormous exponents.
  if (integerDigitCount > 20n) {
    return null;
  }

  const position = Number(integerDigitCount);
  const integerDigits = digits.slice(0, position).padEnd(position, '0') || '0';
  const roundUp = (digits[position] ?? '0') >= '5';
  const rounded = BigInt(integerDigits) + (roundUp ? 1n : 0n);
  return rounded < UINT64_MAX ? rounded : null;
};

/** The fixed width of a claim byte value (ADR 0009). */
const BYTE_VALUE_BYTES = 32;

/**
 * Decode hex with an optional `0x`/`0X` prefix. Every other character is
 * data, so separators and whitespace make the string invalid (ADR 0010).
 */
const decodeHex = (value: string): Uint8Array | null => {
  const digits = value.replace(/^0[xX]/, '');
  if (digits.length === 0 || digits.length % 2 !== 0 || digits.length > 2 * BYTE_VALUE_BYTES) {
    return null;
  }
  if (!/^[0-9a-fA-F]+$/.test(digits)) {
    return null;
  }
  const bytes = new Uint8Array(digits.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(digits.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
};

/**
 * Decode standard or URL-safe base64 with optional `=` padding. Partial
 * padding and non-canonical trailing bits are invalid, so `AB==` cannot fold
 * into `AA==` (ADR 0010).
 */
const decodeBase64 = (value: string): Uint8Array | null => {
  const match = /^([A-Za-z0-9+/_-]+)(=*)$/.exec(value);
  const body = match?.[1];
  const padding = match?.[2] ?? '';
  if (body === undefined || padding.length > 2) {
    return null;
  }
  if (padding.length > 0 && (body.length + padding.length) % 4 !== 0) {
    return null;
  }
  const canonical = body.replace(/-/g, '+').replace(/_/g, '/');
  if (canonical.length > 43) {
    // 43 unpadded characters are the most 32 bytes can encode.
    return null;
  }
  const bytes = Buffer.from(canonical, 'base64');
  if (bytes.toString('base64').replace(/=+$/, '') !== canonical) {
    return null;
  }
  return bytes;
};

/** Pad decoded bytes into a 32-byte claim value, or `null` when over 32 bytes. */
const padTo32 = (bytes: Uint8Array): Uint8Array | null => {
  if (bytes.length > BYTE_VALUE_BYTES) {
    return null;
  }
  const padded = new Uint8Array(BYTE_VALUE_BYTES);
  padded.set(bytes);
  return padded;
};

/** Decode a disclosed string under a byte rule, unpadded; `null` when not a valid encoding. */
const decodeByteValue = (value: string, rule: ByteRule): Uint8Array | null => {
  switch (rule) {
    case 'bytes':
      return new TextEncoder().encode(value);
    case 'hex':
      return decodeHex(value);
    case 'base64':
      return decodeBase64(value);
  }
};

/**
 * Parse a disclosed string into a claim value under a rule.
 *
 * `null` means not certifiable: a numeric reading outside `[0, 2^64)`, or a
 * byte reading that is not a valid encoding or does not fit 32 bytes. For a
 * policy slot, use {@link parseSlotValue}, which also applies the slot's
 * `length` pin.
 */
export function parseDisclosedValue(value: string, rule: 'int' | 'float'): bigint | null;
export function parseDisclosedValue(value: string, rule: ByteRule): Uint8Array | null;
export function parseDisclosedValue(
  value: string,
  rule: ZkFetchParseRule,
): bigint | Uint8Array | null;
export function parseDisclosedValue(
  value: string,
  rule: ZkFetchParseRule,
): bigint | Uint8Array | null {
  switch (rule) {
    case 'int': {
      if (!/^\d+$/.test(value)) {
        return null;
      }
      const big = BigInt(value);
      return big < UINT64_MAX ? big : null;
    }
    case 'float':
      return parseDecimalUint64(value);
    case 'bytes':
    case 'hex':
    case 'base64': {
      const bytes = decodeByteValue(value, rule);
      return bytes === null ? null : padTo32(bytes);
    }
  }
}

/**
 * Parse a disclosed string for one policy slot: its rule and, for byte rules,
 * its exact `length` pin. `null` means not certifiable.
 */
export function parseSlotValue(
  slot: ZkFetchSlot & { parse: ByteRule },
  value: string,
): Uint8Array | null;
export function parseSlotValue(
  slot: ZkFetchSlot & { parse: 'int' | 'float' },
  value: string,
): bigint | null;
export function parseSlotValue(slot: ZkFetchSlot, value: string): bigint | Uint8Array | null;
export function parseSlotValue(slot: ZkFetchSlot, value: string): bigint | Uint8Array | null {
  if (!isByteRule(slot.parse)) {
    return parseDisclosedValue(value, slot.parse);
  }
  const bytes = decodeByteValue(value, slot.parse);
  if (bytes === null || (slot.length !== undefined && bytes.length !== slot.length)) {
    return null;
  }
  return padTo32(bytes);
}

/**
 * Build the parsed view of evidence without checking its signature.
 *
 * The attestor calls this after `verifyZkFetchProof`; the client calls it to
 * derive the claim it expects its attestors to sign.
 *
 * @throws if the claim context is not JSON.
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
 * Require every policy slot to fit the requested claim size and its rule's
 * region: numeric rules in `0..valueSlots-1`, byte rules after.
 *
 * @throws if a slot is out of range or in the wrong region for its rule.
 */
export function assertPolicySlotsInRange(
  policy: ZkFetchPolicy,
  valueSlots: number,
  byteSlots: number,
): void {
  const total = valueSlots + byteSlots;
  const outOfRange = policy.slots.find((slot) => slot.slot >= total);
  if (outOfRange !== undefined) {
    throw new Error(`policy slot ${outOfRange.slot} is out of the claim's ${total} value slots`);
  }
  const wrongRegion = policy.slots.find((slot) =>
    isByteRule(slot.parse) ? slot.slot < valueSlots : slot.slot >= valueSlots,
  );
  if (wrongRegion !== undefined) {
    throw new Error(
      isByteRule(wrongRegion.parse)
        ? `policy slot ${wrongRegion.slot} uses the '${wrongRegion.parse}' rule but targets a numeric slot`
        : `policy slot ${wrongRegion.slot} uses the '${wrongRegion.parse}' rule but targets a byte slot`,
    );
  }
}

/**
 * Derive the claim the attestor signs from parsed evidence.
 *
 * Values and `present` come from the disclosed values, `subjectHash` from the
 * signed request, `salt` from the claim context digest the witness signed
 * (ADR 0012), `policyHash` and `version` from the policy; `appId`, `holder`
 * and the window are the caller's (ADR 0004, ADR 0005). A slot whose
 * disclosure is absent or unparseable stays unpresent.
 *
 * @throws if a policy slot is out of range or in the wrong region, the policy
 *   fails {@link zkFetchPolicySchema}, the signed parameters carry no request
 *   (see {@link claimRequestOf}), or the signed context carries no claim
 *   context digest (see {@link signedClaimContextDigestOf}).
 */
export const deriveClaimFromEvidence = <V extends number, W extends number = 0>(options: {
  verified: VerifiedEvidence;
  policy: ZkFetchPolicy;
  /** 32 bytes. */
  appId: Uint8Array;
  /** Per-claim holder commitment, 32 bytes. */
  holder: Uint8Array;
  /** The contract's `#V`. */
  valueSlots: V;
  /** Half the contract's `#B`: each byte value takes two halves. Defaults to `0`. */
  byteSlots?: W;
  /** Unix seconds. */
  windowStart: bigint;
  /** Unix seconds. */
  windowEnd: bigint;
}): Claim<V, W> => {
  const { verified, policy, appId, holder, valueSlots, windowStart, windowEnd } = options;
  const byteSlots = options.byteSlots ?? 0;
  assertPolicySlotsInRange(policy, valueSlots, byteSlots);
  const present = Array.from({ length: valueSlots + byteSlots }, () => false);
  const values = Array.from({ length: valueSlots }, () => 0n);
  const byteValues: Uint8Array[] = Array.from(
    { length: byteSlots },
    () => new Uint8Array(BYTE_VALUE_BYTES),
  );
  for (const slot of policy.slots) {
    const raw = verified.disclosedValues[slot.name];
    if (raw === undefined) {
      continue;
    }
    const value = parseSlotValue(slot, raw);
    if (value === null) {
      continue;
    }
    present[slot.slot] = true;
    if (typeof value === 'bigint') {
      values[slot.slot] = value;
    } else {
      byteValues[slot.slot - valueSlots] = value;
    }
  }
  const { claimVersion } = normalizePolicy(policy);
  return {
    version: claimVersion,
    appId,
    holder,
    salt: hexToBytes(signedClaimContextDigestOf(verified.claim)),
    policyHash: zkFetchPolicyHashOf(policy),
    windowStart,
    windowEnd,
    subjectHash: zkFetchSubjectHashOf(claimRequestOf(verified.claim)),
    present,
    values,
    byteValues,
  } as Claim<V, W>;
};

/**
 * Check evidence against the policy: the signed request carries no
 * `{{param}}` template, the attested URL is HTTPS on an allowed host, the
 * signed request body carries no `*` and satisfies the policy's body mode,
 * the signed disclosure rules equal the policy's canonical form, and every
 * required slot is certifiable. `responseText` is not witness-signed and takes
 * no part.
 *
 * The policy is parsed with {@link zkFetchPolicySchema} first, so a missing
 * `bodyPolicy` or the empty body's pin fails here rather than later.
 *
 * @returns the lowercased attested host.
 * @throws on the first failed check.
 */
export const assertEvidenceMatchesPolicy = (
  verified: VerifiedEvidence,
  policy: ZkFetchPolicy,
): string => {
  const parsedPolicy = zkFetchPolicySchema.parse(policy);
  const parameters = claimParametersOf(verified.claim);
  // Any `{{` is refused, not only a fillable template: Reclaim matches the signed path and body
  // against the sent request with `{{…}…}` as a wildcard over redacted bytes. The url is normalised
  // the way WHATWG parses it (tab, LF and CR removed, path braces encoded) and the way Reclaim
  // decodes it back (`%7B`/`%7D` to braces) before the check.
  for (const field of ['url', 'body', 'geoLocation', 'proxySessionId'] as const) {
    const value = parameters[field];
    const text =
      field === 'url' && typeof value === 'string'
        ? value
            .replace(/[\t\n\r]/g, '')
            .replace(/%7B/gi, '{')
            .replace(/%7D/gi, '}')
        : value;
    if (typeof text === 'string' && text.includes('{{')) {
      throw new Error(`the signed ${field} cannot use {{param}} templates`);
    }
  }
  const url = new URL(parameters.url);
  if (url.protocol !== 'https:') {
    throw new Error(`attested url must be https, got ${url.protocol}//`);
  }
  const host = url.hostname.toLowerCase();
  if (!hostAllowed(host, parsedPolicy.allowedHosts)) {
    throw new Error(
      `attested host ${host} not in allowlist [${parsedPolicy.allowedHosts.join(', ')}]`,
    );
  }
  const request = claimRequestOf(verified.claim);
  const signedBody = request.body ?? '';
  // Reclaim's body comparison treats a signed `*` as equal to a `*` in the transcript, and the
  // caller chooses which request bytes it redacts to `*`, so each one leaves a sent byte unbound.
  if (signedBody.includes('*')) {
    throw new Error('the signed request body cannot contain *');
  }
  const bodyPolicy = parsedPolicy.bodyPolicy;
  if (bodyPolicy === 'ignored') {
    if (signedBody !== '') {
      throw new Error("the signed request body must be empty under bodyPolicy: 'ignored'");
    }
  } else if (bodyPolicy === 'non-empty') {
    if (signedBody === '') {
      throw new Error('the signed request body is empty but the policy requires a non-empty body');
    }
  } else if (bytesToHex(sha256(signedBody)) !== bytesToHex(bodyPolicy.sha256)) {
    throw new Error('the signed request body does not match the policy');
  }
  const signedRules = normalizedRulesOf({
    responseMatches: parameters.responseMatches,
    responseRedactions: parameters.responseRedactions,
  });
  const policyRules = normalizedRulesOf({
    responseMatches: parsedPolicy.responseMatches,
    responseRedactions: parsedPolicy.responseRedactions,
  });
  if (!isDeepStrictEqual(signedRules, policyRules)) {
    throw new Error('evidence disclosure rules do not match the policy');
  }
  for (const slot of parsedPolicy.slots) {
    if (slot.optional) {
      continue;
    }
    const raw = verified.disclosedValues[slot.name];
    if (raw === undefined || parseSlotValue(slot, raw) === null) {
      throw new Error(
        `policy requires a certifiable value for "${slot.name}" but the proof did not disclose a parseable value`,
      );
    }
  }
  return host;
};

/**
 * Require the witness's observation time to fall inside the proposed window,
 * bounds included (ADR 0005). The contract bounds the window's length and
 * checks it against block time.
 *
 * @throws if the witness observed outside the window.
 */
export const assertObservationInWindow = (options: {
  claim: Claim<number, number>;
  verified: VerifiedEvidence;
}): void => {
  const { claim, verified } = options;
  const observedAt = BigInt(verified.claim.timestampS);
  if (observedAt < claim.windowStart || observedAt > claim.windowEnd) {
    throw new Error(
      `witness observation ${observedAt} is outside the claim window [${claim.windowStart}, ${claim.windowEnd}]`,
    );
  }
};
