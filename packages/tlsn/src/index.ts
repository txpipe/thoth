// The tlsn@1 law: a TLSNotary notary attests one HTTPS session, the prover presents
// it, and the attestor reads the claim's values from the authenticated JSON response.

import { createHash } from 'node:crypto';
import type { AttestationInput } from '@txpipe/thoth-core';
import type { Claim, ClaimInput, FlatMessage } from '@txpipe/thoth-core/claim';
import { CLAIM_VERSION, claimSchema } from '@txpipe/thoth-core/claim';
import {
  type CanonicalValue,
  claimContextDigestOf,
  policyHashOf,
  subjectHashOf,
} from '@txpipe/thoth-core/claim-context';
import { z } from 'zod';
import { type RevealedRequest, type RevealedResponse, readRequest, readResponse } from './http.js';
import { type JsonPathSegment, lookupJsonPath, parseStrictJson } from './json.js';
import {
  BYTE_VALUE_BYTES,
  isByteRule,
  parseFieldValue,
  type TlsnByteRule,
  type TlsnParseRule,
} from './values.js';

export type { JsonPathSegment, RevealedRequest, RevealedResponse, TlsnByteRule, TlsnParseRule };
export { isByteRule, parseFieldValue };

/** The law's versioned tag, hashed into every policy hash. */
export const TLSN_LAW = 'tlsn@1';

/** The attestation extension id under which the notary signs the claim context digest. */
export const TLSN_CLAIM_CONTEXT_EXTENSION = 'thoth.claim-context';

/** Input caps an attestor applies before any costlier check. */
export const TLSN_LIMITS = Object.freeze({
  allowedHosts: 32,
  hostLength: 253,
  hiddenHeaders: 16,
  headerNameLength: 64,
  slots: 64,
  pathDepth: 16,
  pathSegmentLength: 256,
  valueSlots: 256,
  byteSlots: 64,
  /** Hex characters of one presentation. */
  presentationLength: 8 * 1024 * 1024,
});

const sha256 = (data: string | Uint8Array): Uint8Array =>
  new Uint8Array(createHash('sha256').update(data).digest());

const bytesToHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

/** One claim-slot binding: which JSON field feeds which slot, and how it is parsed. */
export interface TlsnSlot {
  /** Index into the claim's value slots: numeric `0..V-1`, byte `V..V+W-1`. */
  slot: number;
  /** Where the field sits in the JSON response body: object keys and array indices. */
  path: readonly JsonPathSegment[];
  parse: TlsnParseRule;
  /** Exact byte length, 1–32, byte rules only. */
  length?: number;
  /** When true, an absent or unparseable field is signed unpresent instead of rejected. */
  optional?: boolean;
}

/**
 * How the policy constrains the request body, which the presentation always
 * reveals: `empty`, `any`, or one exact body by SHA-256.
 */
export type TlsnBodyPolicy = 'empty' | 'any' | { readonly sha256: Uint8Array };

/** The policy a tlsn@1 attestor enforces. */
export interface TlsnPolicy {
  /** DNS names the server certificate may be for; exact match, case-insensitive. */
  allowedHosts: readonly string[];
  /**
   * Request header names whose values the prover may hide from the attestor,
   * such as `authorization`. Every other request byte is revealed.
   */
  hiddenHeaders?: readonly string[];
  /** The response status the attestor requires. Defaults to 200. */
  status?: number;
  slots: readonly TlsnSlot[];
  bodyPolicy: TlsnBodyPolicy;
  /** The claim version the attestor signs, 0–255. Defaults to 1. */
  claimVersion?: bigint;
}

/** What the client sends an attestor: one TLSNotary presentation, bincode-encoded, as hex. */
export interface TlsnEvidence {
  presentation: string;
}

/** A notary's public key, as `thoth-tlsn notary-key` prints it. */
export interface TlsnNotaryKey {
  /** The key algorithm, such as `k256`. */
  alg: string;
  /** The key, as lowercase hex. */
  key: string;
}

/** A DNS name in canonical form: lowercased, without a trailing dot. */
const canonicalHost = (host: string): string => host.toLowerCase().replace(/\.+$/, '');

const DNS_NAME =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

const slotSchema = z
  .object({
    slot: z.number().int().nonnegative(),
    path: z
      .array(
        z.union([z.string().max(TLSN_LIMITS.pathSegmentLength), z.number().int().nonnegative()]),
      )
      .min(1)
      .max(TLSN_LIMITS.pathDepth),
    parse: z.enum(['int', 'float', 'bytes', 'hex', 'base64']),
    length: z.number().int().min(1).max(BYTE_VALUE_BYTES).optional(),
    optional: z.boolean().optional(),
  })
  .refine((slot) => slot.length === undefined || isByteRule(slot.parse), {
    message: "'length' is only valid for byte rules",
    path: ['length'],
  });

/** Runtime validator for {@link TlsnPolicy}. */
export const tlsnPolicySchema = z.object({
  allowedHosts: z
    .array(
      z
        .string()
        .max(TLSN_LIMITS.hostLength)
        .refine((host) => DNS_NAME.test(canonicalHost(host)), {
          message: 'an allowedHosts entry must be a DNS name without a port',
        }),
    )
    .min(1)
    .max(TLSN_LIMITS.allowedHosts),
  hiddenHeaders: z
    .array(
      z
        .string()
        .max(TLSN_LIMITS.headerNameLength)
        .regex(/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/)
        .refine(
          (name) => !['host', 'content-length', 'transfer-encoding'].includes(name.toLowerCase()),
          {
            message: 'Host, Content-Length and Transfer-Encoding are always revealed',
          },
        ),
    )
    .max(TLSN_LIMITS.hiddenHeaders)
    .optional(),
  status: z.number().int().min(100).max(599).optional(),
  slots: z
    .array(slotSchema)
    .min(1)
    .max(TLSN_LIMITS.slots)
    .refine((slots) => new Set(slots.map(({ slot }) => slot)).size === slots.length, {
      message: 'a claim slot is declared more than once',
    }),
  bodyPolicy: z.union([
    z.literal('empty'),
    z.literal('any'),
    z.object({
      sha256: z
        .instanceof(Uint8Array)
        .refine((hash) => hash.length === 32, { message: 'expected 32 bytes' }),
    }),
  ]),
  claimVersion: z
    .bigint()
    .refine((version) => version >= 0n && version < 256n)
    .optional(),
});

/** Runtime validator for {@link TlsnEvidence}. */
export const tlsnEvidenceSchema = z.object({
  presentation: z
    .string()
    .max(TLSN_LIMITS.presentationLength)
    .regex(/^(?:[0-9a-f]{2})+$/, { message: 'the presentation must be lowercase hex' }),
});

/**
 * The tlsn@1 claim schema: `claimSchema()` with the slot counts taken from the
 * proposal and capped by {@link TLSN_LIMITS} before any element is parsed.
 */
export const tlsnClaimSchema = z.preprocess<
  unknown,
  ReturnType<typeof claimSchema<number, number>>,
  ClaimInput<number, number>
>((input: unknown, context) => {
  if (typeof input !== 'object' || input === null) return input;
  const bounded: Record<string, unknown> = { ...input };
  const caps = [
    ['values', TLSN_LIMITS.valueSlots],
    ['byteValues', TLSN_LIMITS.byteSlots],
    ['present', TLSN_LIMITS.valueSlots + TLSN_LIMITS.byteSlots],
  ] as const;
  for (const [key, max] of caps) {
    const entries = bounded[key];
    if (!Array.isArray(entries)) continue;
    // Copy before counting, so a getter cannot pass the cap with one array and parse another.
    const copy = entries.slice(0, max + 1);
    bounded[key] = copy;
    if (copy.length > max) {
      context.addIssue({
        code: 'too_big',
        origin: 'array',
        maximum: max,
        inclusive: true,
        input: copy,
        path: [key],
      });
    }
  }
  return bounded;
}, claimSchema<number, number>());

const hexBytes = z
  .string()
  .regex(/^(?:[0-9a-f]{2})*$/)
  .transform((hex) => new Uint8Array(Buffer.from(hex, 'hex')));

const directionSchema = z
  .object({
    length: z.number().int().nonnegative(),
    data: hexBytes,
    revealed: z.array(z.tuple([z.number().int().nonnegative(), z.number().int().nonnegative()])),
  })
  .superRefine((direction, context) => {
    if (direction.data.length !== direction.length) {
      context.addIssue({ code: 'custom', message: 'transcript data does not match its length' });
    }
    let previousEnd = 0;
    for (const [start, end] of direction.revealed) {
      if (start < previousEnd || end <= start || end > direction.length) {
        context.addIssue({
          code: 'custom',
          message: 'revealed ranges are not sorted and disjoint',
        });
        return;
      }
      previousEnd = end;
    }
  });

/** Validator for the JSON `thoth-tlsn verify` prints. */
export const verifiedPresentationSchema = z.object({
  notaryKey: z.object({ alg: z.string(), key: z.string() }),
  serverName: z.string(),
  time: z.number().int().nonnegative(),
  sent: directionSchema,
  received: directionSchema,
  extensions: z.array(z.object({ id: hexBytes, value: hexBytes })),
});

/** What a verified presentation authenticates: the notary's key, server, time and transcript. */
export type VerifiedPresentation = z.output<typeof verifiedPresentationSchema>;

/**
 * Verifies a presentation's cryptography: the notary's signature, the server's
 * certificate chain and the transcript proof. It does not decide whether to
 * trust the notary; the law compares the key with the pinned one.
 */
export interface TlsnPresentationVerifier {
  /**
   * Verify one presentation.
   *
   * @returns what it authenticates, in the shape {@link verifiedPresentationSchema} parses.
   * @throws if the presentation does not verify.
   */
  verify(presentation: string): Promise<unknown>;
}

/**
 * The tlsn@1 kind's definition, the value `createTlsnDefinition` returns.
 *
 * Declared here so the client can import the type without the attestor's
 * dependencies.
 */
export interface TlsnDefinition {
  /** The kind identifier, `tlsn@1`. */
  readonly kind: typeof TLSN_LAW;
  readonly policy: typeof tlsnPolicySchema;
  readonly evidence: typeof tlsnEvidenceSchema;
  readonly claim: typeof tlsnClaimSchema;
  /** The kind's check. Throws to reject. */
  verify(input: AttestationInput<TlsnPolicy, TlsnEvidence, Claim<number, number>>): Promise<void>;
  /** Encode the parsed claim into the flat signed message. */
  message(claim: Claim<number, number>): FlatMessage;
}

/**
 * Parse a policy into the form every hash and check reads: hosts canonical,
 * deduplicated and sorted; hidden headers lowercased, deduplicated and
 * sorted; defaults filled; slots sorted by index.
 *
 * @throws if the policy fails {@link tlsnPolicySchema}.
 */
export const normalizeTlsnPolicy = (policy: TlsnPolicy) => {
  const parsed = tlsnPolicySchema.parse(policy);
  return {
    allowedHosts: [...new Set(parsed.allowedHosts.map(canonicalHost))].sort(),
    hiddenHeaders: [
      ...new Set((parsed.hiddenHeaders ?? []).map((name) => name.toLowerCase())),
    ].sort(),
    status: parsed.status ?? 200,
    slots: parsed.slots
      .map((slot) => ({ ...slot, optional: slot.optional ?? false }))
      .sort((a, b) => a.slot - b.slot),
    bodyPolicy: parsed.bodyPolicy,
    claimVersion: parsed.claimVersion ?? CLAIM_VERSION,
  };
};

type NormalizedPolicy = ReturnType<typeof normalizeTlsnPolicy>;

const hashNormalized = (normalized: NormalizedPolicy): Uint8Array =>
  policyHashOf(TLSN_LAW, normalized as unknown as CanonicalValue, normalized.claimVersion);

/**
 * Hash a policy under the `tlsn@1` law. Policies that normalize the same hash
 * the same (see {@link normalizeTlsnPolicy}).
 *
 * @throws if the policy fails {@link tlsnPolicySchema}.
 */
export const tlsnPolicyHashOf = (policy: TlsnPolicy): Uint8Array =>
  hashNormalized(normalizeTlsnPolicy(policy));

/** The request a tlsn@1 claim is about. */
export interface TlsnSubjectRequest {
  method: string;
  /** The server's DNS name. */
  host: string;
  /** The origin-form target: path and query. */
  target: string;
  body: Uint8Array;
}

/**
 * The tlsn@1 subject: one SHA-256 per request part, mirroring a Compact
 * `struct { method, host, path, body: Bytes<32> }`. It is the zkFetch kind's
 * subject for the same request on port 443, so an app can bind the source the
 * same way under either kind.
 */
export interface TlsnSubject {
  method: Uint8Array;
  host: Uint8Array;
  path: Uint8Array;
  body: Uint8Array;
}

/** Build the subject of a request. */
export const tlsnSubjectOf = (request: TlsnSubjectRequest): TlsnSubject => ({
  method: sha256(request.method.toUpperCase()),
  host: sha256(canonicalHost(request.host)),
  path: sha256(request.target),
  body: sha256(request.body),
});

/** Hash the subject of a request. */
export const tlsnSubjectHashOf = (request: TlsnSubjectRequest): Uint8Array => {
  const { method, host, path, body } = tlsnSubjectOf(request);
  return subjectHashOf([method, host, path, body]);
};

/**
 * The subject request for a URL, as the prover will send it: the WHATWG path
 * and query as the target.
 *
 * @throws if the URL does not parse, is not HTTPS, or names a port other than 443.
 */
export const tlsnSubjectRequestOf = (request: {
  method?: string;
  url: string;
  body?: string;
}): TlsnSubjectRequest => {
  const url = new URL(request.url);
  if (url.protocol !== 'https:' || url.port !== '') {
    throw new Error('tlsn@1 requests are HTTPS on port 443');
  }
  return {
    method: (request.method ?? 'GET').toUpperCase(),
    host: url.hostname,
    target: `${url.pathname}${url.search}`,
    body: new TextEncoder().encode(request.body ?? ''),
  };
};

/**
 * The claim context digest the notary signs: `claimContextDigestOf` over the
 * policy hash, the request's subject hash, the holder and the window.
 *
 * @throws if the policy fails {@link tlsnPolicySchema}, the holder is not 32
 *   bytes, or a window bound is negative.
 */
export const tlsnClaimContextDigestOf = (options: {
  policy: TlsnPolicy;
  request: TlsnSubjectRequest;
  /** Per-claim holder commitment, 32 bytes. */
  holder: Uint8Array;
  /** Unix seconds. */
  windowStart: bigint;
  /** Unix seconds. */
  windowEnd: bigint;
}): Uint8Array =>
  claimContextDigestOf({
    policyHash: tlsnPolicyHashOf(options.policy),
    subjectHash: tlsnSubjectHashOf(options.request),
    holder: options.holder,
    windowStart: options.windowStart,
    windowEnd: options.windowEnd,
  });

/** What one verified presentation shows, read under a policy. */
export interface TlsnObservation {
  /** The server's DNS name, canonical. */
  readonly serverName: string;
  /** When the notary saw the server's hello, Unix seconds, by the notary's clock. */
  readonly time: bigint;
  readonly request: RevealedRequest;
  readonly response: RevealedResponse;
  /** The claim context digest the notary signed. */
  readonly claimContext: Uint8Array;
  /** Each policy slot's value, or `null` when absent or not certifiable. */
  readonly slotValues: ReadonlyMap<number, bigint | Uint8Array | null>;
}

/** The claim context extension id, as the bytes the attestation carries. */
const EXTENSION_ID = new TextEncoder().encode(TLSN_CLAIM_CONTEXT_EXTENSION);

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, index) => byte === b[index]);

/**
 * Read a verified presentation under a policy: the server is an allowed host,
 * the request is fully revealed except allowed hidden header values and its
 * `Host` is the server, the body satisfies the body policy, the whole response
 * is revealed with the required status, the notary signed exactly one claim
 * context digest, and every required slot is certifiable.
 *
 * It does not check the notary's key or the claim; the attestor does.
 *
 * @throws on the first failed check.
 */
export const observePresentation = (
  verified: VerifiedPresentation,
  policy: TlsnPolicy,
): TlsnObservation => {
  const normalized = normalizeTlsnPolicy(policy);
  const serverName = canonicalHost(verified.serverName);
  if (!normalized.allowedHosts.includes(serverName)) {
    throw new Error(`server ${serverName} is not in the allowlist`);
  }
  const request = readRequest(verified.sent, new Set(normalized.hiddenHeaders));
  // TLSNotary authenticates the server name, not the TCP port, so the request
  // must name the server without one.
  if (canonicalHost(request.host) !== serverName) {
    throw new Error(`the request Host ${request.host} is not the attested server ${serverName}`);
  }
  const { bodyPolicy } = normalized;
  if (bodyPolicy === 'empty' && request.body.length !== 0) {
    throw new Error("the request body must be empty under bodyPolicy: 'empty'");
  }
  if (typeof bodyPolicy === 'object' && !sameBytes(sha256(request.body), bodyPolicy.sha256)) {
    throw new Error('the request body does not match the policy');
  }
  const response = readResponse(verified.received);
  if (response.status !== normalized.status) {
    throw new Error(`the response status is ${response.status}, not ${normalized.status}`);
  }

  const contexts = verified.extensions.filter((extension) => sameBytes(extension.id, EXTENSION_ID));
  if (verified.extensions.length !== 1 || contexts.length !== 1) {
    throw new Error('the attestation must carry exactly one extension, the claim context digest');
  }
  const claimContext = (contexts[0] as { value: Uint8Array }).value;
  if (claimContext.length !== 32) {
    throw new Error('the claim context digest is not 32 bytes');
  }

  const json = parseStrictJson(new TextDecoder('utf-8', { fatal: true }).decode(response.body));
  const slotValues = new Map<number, bigint | Uint8Array | null>();
  for (const slot of normalized.slots) {
    const raw = lookupJsonPath(json, slot.path);
    const value = raw === undefined ? null : parseFieldValue(raw, slot.parse, slot.length);
    if (value === null && !slot.optional) {
      throw new Error(`the response has no certifiable value at ${JSON.stringify(slot.path)}`);
    }
    slotValues.set(slot.slot, value);
  }

  return {
    serverName,
    time: BigInt(verified.time),
    request,
    response,
    claimContext,
    slotValues,
  };
};

/**
 * Require every policy slot to fit the requested claim size and its rule's
 * region: numeric rules in `0..valueSlots-1`, byte rules after.
 *
 * @throws if a slot is out of range or in the wrong region for its rule.
 */
export const assertPolicySlotsInRange = (
  policy: TlsnPolicy,
  valueSlots: number,
  byteSlots: number,
): void => {
  for (const slot of policy.slots) {
    if (slot.slot >= valueSlots + byteSlots) {
      throw new Error(
        `policy slot ${slot.slot} is out of the claim's ${valueSlots + byteSlots} slots`,
      );
    }
    if (isByteRule(slot.parse) !== slot.slot >= valueSlots) {
      throw new Error(
        `policy slot ${slot.slot} targets the wrong region for its '${slot.parse}' rule`,
      );
    }
  }
};

/** The subject request of an observation, as the attestor saw it sent. */
export const subjectRequestOf = (observation: TlsnObservation): TlsnSubjectRequest => ({
  method: observation.request.method,
  host: observation.serverName,
  target: observation.request.target,
  body: observation.request.body,
});

/**
 * Derive the claim the attestor signs from an observation.
 *
 * Values and `present` come from the response, `subjectHash` from the
 * revealed request, `salt` from the claim context digest the notary signed,
 * `policyHash` and `version` from the policy; `appId`, `holder` and the window
 * are the caller's.
 *
 * @throws if a policy slot is out of range or in the wrong region.
 */
export const deriveTlsnClaim = (options: {
  observation: TlsnObservation;
  policy: TlsnPolicy;
  /** 32 bytes. */
  appId: Uint8Array;
  /** Per-claim holder commitment, 32 bytes. */
  holder: Uint8Array;
  /** The contract's `#V`. */
  valueSlots: number;
  /** Half the contract's `#B`: each byte value takes two halves. */
  byteSlots: number;
  /** Unix seconds. */
  windowStart: bigint;
  /** Unix seconds. */
  windowEnd: bigint;
}): Claim<number, number> => {
  const { observation, policy, appId, holder, valueSlots, byteSlots, windowStart, windowEnd } =
    options;
  assertPolicySlotsInRange(policy, valueSlots, byteSlots);
  const normalized = normalizeTlsnPolicy(policy);
  const present = Array.from({ length: valueSlots + byteSlots }, () => false);
  const values = Array.from({ length: valueSlots }, () => 0n);
  const byteValues = Array.from({ length: byteSlots }, () => new Uint8Array(BYTE_VALUE_BYTES));
  for (const [slot, value] of observation.slotValues) {
    if (value === null) continue;
    present[slot] = true;
    if (typeof value === 'bigint') {
      values[slot] = value;
    } else {
      byteValues[slot - valueSlots] = new Uint8Array(value);
    }
  }
  return {
    version: normalized.claimVersion,
    appId,
    holder,
    salt: observation.claimContext,
    policyHash: hashNormalized(normalized),
    windowStart,
    windowEnd,
    subjectHash: tlsnSubjectHashOf(subjectRequestOf(observation)),
    present,
    values,
    byteValues,
  };
};

/** The claim context digest as lowercase hex, for the prover's command line. */
export const claimContextHex = (digest: Uint8Array): string => bytesToHex(digest);
