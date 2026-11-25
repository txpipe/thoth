// The tlsn@1 law: the zkFetch policy and claim, with TLSNotary as the evidence. The notary
// attests one HTTPS session; the attestor plays the zkFetch witness's part on the redacted
// response the presentation reveals, and signs the claim it derives.

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
import { readRequest, redactedResponseText } from './http.js';
import { disclosedValuesOf, type TlsnResponseMatch } from './match.js';
import type { TlsnResponseRedaction } from './redact.js';
import { ruleCompileError, ruleGroupNames } from './regex.js';
import {
  BYTE_VALUE_BYTES,
  isByteRule,
  parseFieldValue,
  type TlsnByteRule,
  type TlsnParseRule,
} from './values.js';

export type { TlsnByteRule, TlsnParseRule, TlsnResponseMatch, TlsnResponseRedaction };
export { isByteRule, parseFieldValue };

/** The law's versioned tag, hashed into every policy hash. */
export const TLSN_LAW = 'tlsn@1';

/** The attestation extension id under which the notary signs the claim context digest. */
export const TLSN_CLAIM_CONTEXT_EXTENSION = 'thoth.claim-context';

/** Input caps an attestor applies before any costlier check. */
export const TLSN_LIMITS = Object.freeze({
  allowedHosts: 32,
  hostLength: 253,
  slots: 64,
  slotNameLength: 64,
  responseMatches: 32,
  responseRedactions: 32,
  ruleLength: 4096,
  valueSlots: 256,
  byteSlots: 64,
  /** Hex characters of one presentation. */
  presentationLength: 8 * 1024 * 1024,
});

const sha256 = (data: string | Uint8Array): Uint8Array =>
  new Uint8Array(createHash('sha256').update(data).digest());

const bytesToHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

const EMPTY_BODY_SHA256 = bytesToHex(sha256(''));

/** One claim-slot binding: which disclosed value feeds which slot, and how it is parsed. */
export interface TlsnSlot {
  /** Index into the claim's value slots: numeric `0..V-1`, byte `V..V+W-1`. */
  slot: number;
  /** The named regex group to read from the disclosed values. */
  name: string;
  parse: TlsnParseRule;
  /** Exact byte length, 1–32, byte rules only. */
  length?: number;
  /** When true, an absent or unparseable disclosure is signed unpresent instead of rejected. */
  optional?: boolean;
}

/**
 * How the policy constrains the request body, which the attestor reads from
 * the presentation: `ignored` requires an empty body, `non-empty` a non-empty
 * one, and `{ sha256 }` one exact non-empty body.
 */
export type TlsnBodyPolicy = 'ignored' | 'non-empty' | { readonly sha256: Uint8Array };

/**
 * The policy a tlsn@1 attestor enforces. It has the zkFetch policy's shape and
 * meaning, so one policy object serves either kind.
 */
export interface TlsnPolicy {
  /** Hosts the request may target: exact, or any subdomain of one. No ports. */
  allowedHosts: readonly string[];
  slots: readonly TlsnSlot[];
  /** The response patterns the attestor applies to the redacted response. */
  responseMatches: readonly TlsnResponseMatch[];
  /** The slices of the response the prover reveals. Everything else stays hidden. */
  responseRedactions: readonly TlsnResponseRedaction[];
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
  /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;

/** Whether a canonical host is an allowed entry or a subdomain of one. */
const hostAllowed = (host: string, allowedHosts: readonly string[]): boolean =>
  allowedHosts.some((entry) => {
    const allowed = canonicalHost(entry);
    return host === allowed || host.endsWith(`.${allowed}`);
  });

// A `{{name}}` template is filled from caller-chosen values in Reclaim, so it would let
// one policy run different rules; neither kind accepts one.
const noTemplate = (rule: string): boolean => !/\{\{[^{}]+\}\}/.test(rule);
const TEMPLATE_ERROR = 'disclosure rules cannot use {{param}} templates';

const ruleText = z.string().max(TLSN_LIMITS.ruleLength);

const refineRule = (source: string, context: z.RefinementCtx, path: string[]): void => {
  const reason = ruleCompileError(source);
  if (reason !== undefined) {
    context.addIssue({
      code: 'custom',
      message: `regex does not compile under RE2: ${reason}`,
      path,
    });
  }
};

/**
 * Runtime validator for {@link TlsnPolicy}.
 *
 * It accepts the zkFetch policies tlsn@1 can enforce: rule entries are strict
 * and template-free, every regex compiles under RE2, and every slot names a
 * group a regex match declares. It refuses `xPath` redactions and `host:port`
 * entries, which tlsn@1 cannot honour.
 */
export const tlsnPolicySchema = z
  .strictObject({
    allowedHosts: z
      .array(
        z
          .string()
          .max(TLSN_LIMITS.hostLength)
          .refine((host) => DNS_NAME.test(canonicalHost(host)), {
            message: 'an allowedHosts entry must be a host without a port',
          }),
      )
      .min(1)
      .max(TLSN_LIMITS.allowedHosts),
    slots: z
      .array(
        z
          .strictObject({
            slot: z.number().int().nonnegative(),
            name: z.string().min(1).max(TLSN_LIMITS.slotNameLength),
            parse: z.enum(['int', 'float', 'bytes', 'hex', 'base64']),
            length: z.number().int().min(1).max(BYTE_VALUE_BYTES).optional(),
            optional: z.boolean().optional(),
          })
          .refine((slot) => slot.length === undefined || isByteRule(slot.parse), {
            message: "'length' is only valid for byte rules",
            path: ['length'],
          }),
      )
      .min(1)
      .max(TLSN_LIMITS.slots)
      .refine((slots) => new Set(slots.map(({ slot }) => slot)).size === slots.length, {
        message: 'a claim slot is declared more than once',
      }),
    responseMatches: z
      .array(
        z
          .strictObject({
            type: z.enum(['regex', 'contains']),
            value: ruleText.min(1).refine(noTemplate, TEMPLATE_ERROR),
          })
          .superRefine((match, context) => {
            if (match.type === 'regex') refineRule(match.value, context, ['value']);
          }),
      )
      .min(1)
      .max(TLSN_LIMITS.responseMatches),
    responseRedactions: z
      .array(
        z
          .strictObject({
            regex: ruleText.refine(noTemplate, TEMPLATE_ERROR).optional(),
            jsonPath: ruleText.refine(noTemplate, TEMPLATE_ERROR).optional(),
            xPath: ruleText.optional(),
          })
          .superRefine((redaction, context) => {
            if (redaction.xPath !== undefined) {
              context.addIssue({
                code: 'custom',
                message: 'tlsn@1 does not support xPath redactions',
                path: ['xPath'],
              });
            }
            if (redaction.regex === undefined && redaction.jsonPath === undefined) {
              context.addIssue({
                code: 'custom',
                message: 'a redaction needs a jsonPath or a regex',
              });
            }
            if (redaction.regex !== undefined && redaction.regex !== '') {
              refineRule(redaction.regex, context, ['regex']);
            }
          }),
      )
      .max(TLSN_LIMITS.responseRedactions),
    bodyPolicy: z.union([
      z.literal('ignored'),
      z.literal('non-empty'),
      z
        .strictObject({
          sha256: z.instanceof(Uint8Array).refine((hash) => hash.length === 32, {
            message: 'expected 32 bytes',
          }),
        })
        .refine((pin) => bytesToHex(pin.sha256) !== EMPTY_BODY_SHA256, {
          message: "a body pin cannot be the empty body; use bodyPolicy: 'ignored'",
        }),
    ]),
    claimVersion: z.bigint().min(0n).max(255n).optional(),
  })
  .superRefine((policy, context) => {
    // A slot reads the disclosed value its name keys, so a slot no regex group names
    // is never certifiable.
    const groups = new Set<string>();
    for (const match of policy.responseMatches) {
      if (match.type !== 'regex') continue;
      const names = ruleGroupNames(match.value);
      if (names === undefined) return;
      for (const name of names) groups.add(name);
    }
    for (const [index, slot] of policy.slots.entries()) {
      if (!groups.has(slot.name)) {
        context.addIssue({
          code: 'custom',
          message: `slot '${slot.name}' is not a named group of any regex response match`,
          path: ['slots', index, 'name'],
        });
      }
    }
  });

/** Runtime validator for {@link TlsnEvidence}. */
export const tlsnEvidenceSchema = z.strictObject({
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

/** Deterministic JSON for sorting rule entries. */
const sortKey = (value: object): string =>
  JSON.stringify(value, Object.keys(value as Record<string, unknown>).sort());

/**
 * Parse a policy into the form every hash and check reads: hosts canonical,
 * deduplicated and sorted; slots sorted by index with `optional` filled; rule
 * entries sorted; the claim version filled.
 *
 * @throws if the policy fails {@link tlsnPolicySchema}.
 */
export const normalizeTlsnPolicy = (policy: TlsnPolicy) => {
  const parsed = tlsnPolicySchema.parse(policy);
  return {
    allowedHosts: [...new Set(parsed.allowedHosts.map(canonicalHost))].sort(),
    slots: parsed.slots
      .map((slot) => ({ ...slot, optional: slot.optional ?? false }))
      .sort((a, b) => a.slot - b.slot),
    responseMatches: [...parsed.responseMatches].sort((a, b) =>
      sortKey(a).localeCompare(sortKey(b)),
    ),
    responseRedactions: [...parsed.responseRedactions].sort((a, b) =>
      sortKey(a).localeCompare(sortKey(b)),
    ),
    bodyPolicy: parsed.bodyPolicy,
    claimVersion: parsed.claimVersion ?? CLAIM_VERSION,
  };
};

type NormalizedPolicy = ReturnType<typeof normalizeTlsnPolicy>;

const hashNormalized = (normalized: NormalizedPolicy): Uint8Array =>
  policyHashOf(TLSN_LAW, normalized as unknown as CanonicalValue, normalized.claimVersion);

/**
 * Hash a policy under the `tlsn@1` law. Policies that normalize the same hash
 * the same (see {@link normalizeTlsnPolicy}). The same policy hashes
 * differently under zkFetch, so a contract seals each kind it accepts.
 *
 * @throws if the policy fails {@link tlsnPolicySchema}.
 */
export const tlsnPolicyHashOf = (policy: TlsnPolicy): Uint8Array =>
  hashNormalized(normalizeTlsnPolicy(policy));

/** The request a tlsn@1 claim is about, in the zkFetch subject request's shape. */
export interface TlsnSubjectRequest {
  method: string;
  url: string;
  body?: string | Uint8Array;
}

/**
 * The tlsn@1 subject: one SHA-256 per request part, mirroring a Compact
 * `struct { method, host, path, body: Bytes<32> }`. It is the zkFetch kind's
 * subject for the same request, so an app binds the source the same way under
 * either kind.
 */
export interface TlsnSubject {
  method: Uint8Array;
  host: Uint8Array;
  path: Uint8Array;
  body: Uint8Array;
}

/**
 * Build the subject of a request.
 *
 * @throws if the URL does not parse.
 */
export const tlsnSubjectOf = (request: TlsnSubjectRequest): TlsnSubject => {
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
export const tlsnSubjectHashOf = (request: TlsnSubjectRequest): Uint8Array => {
  const { method, host, path, body } = tlsnSubjectOf(request);
  return subjectHashOf([method, host, path, body]);
};

/**
 * The claim context digest the notary signs: `claimContextDigestOf` over the
 * policy hash, the request's subject hash, the holder and the window.
 *
 * @throws if the policy fails {@link tlsnPolicySchema}, the URL does not parse,
 *   the holder is not 32 bytes, or a window bound is negative.
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
  /** The request the presentation reveals. */
  readonly request: TlsnSubjectRequest;
  /** The claim context digest the notary signed. */
  readonly claimContext: Uint8Array;
  /** The values the response matches disclosed, by group name. */
  readonly disclosedValues: Readonly<Record<string, string>>;
}

/** The claim context extension id, as the bytes the attestation carries. */
const EXTENSION_ID = new TextEncoder().encode(TLSN_CLAIM_CONTEXT_EXTENSION);

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, index) => byte === b[index]);

/** A slot's value from the disclosed values, or `null` when absent or not certifiable. */
const slotValueOf = (
  slot: TlsnSlot,
  disclosed: Readonly<Record<string, string>>,
): bigint | Uint8Array | null => {
  const raw = Object.hasOwn(disclosed, slot.name) ? disclosed[slot.name] : undefined;
  return typeof raw === 'string' ? parseFieldValue(raw, slot.parse, slot.length) : null;
};

/**
 * Read a verified presentation under a policy, as the zkFetch witness and
 * attestor together would.
 *
 * The server is an allowed host, or a subdomain of one. The request opens with
 * the fixed `Host` and `Connection: close` prefix, names the server without a
 * port, and has a body the body policy accepts. The response is a 2xx, and
 * the policy's response matches hold on its redacted text; their named groups
 * are the disclosed values, and every required slot's is certifiable. The
 * notary signed exactly one extension, a 32-byte claim context digest.
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
  if (!hostAllowed(serverName, normalized.allowedHosts)) {
    throw new Error(`server ${serverName} is not in the allowlist`);
  }
  const request = readRequest(verified.sent);
  // TLSNotary authenticates the server name, not the TCP port, so the request
  // must name the server without one.
  if (canonicalHost(request.host) !== serverName) {
    throw new Error(`the request Host ${request.host} is not the attested server ${serverName}`);
  }
  const { bodyPolicy } = normalized;
  if (bodyPolicy === 'ignored' && request.body.length !== 0) {
    throw new Error("the request body must be empty under bodyPolicy: 'ignored'");
  }
  if (bodyPolicy === 'non-empty' && request.body.length === 0) {
    throw new Error('the request body is empty but the policy requires a non-empty body');
  }
  if (typeof bodyPolicy === 'object' && !sameBytes(sha256(request.body), bodyPolicy.sha256)) {
    throw new Error('the request body does not match the policy');
  }

  const disclosedValues = disclosedValuesOf(
    redactedResponseText(verified.received),
    normalized.responseMatches,
  );
  for (const slot of normalized.slots) {
    if (!slot.optional && slotValueOf(slot, disclosedValues) === null) {
      throw new Error(`policy requires a certifiable value for "${slot.name}"`);
    }
  }

  const contexts = verified.extensions.filter((extension) => sameBytes(extension.id, EXTENSION_ID));
  if (verified.extensions.length !== 1 || contexts.length !== 1) {
    throw new Error('the attestation must carry exactly one extension, the claim context digest');
  }
  const claimContext = (contexts[0] as { value: Uint8Array }).value;
  if (claimContext.length !== 32) {
    throw new Error('the claim context digest is not 32 bytes');
  }

  return {
    serverName,
    time: BigInt(verified.time),
    request: {
      method: request.method,
      url: `https://${serverName}${request.target}`,
      body: request.body,
    },
    claimContext,
    disclosedValues,
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

/**
 * Derive the claim the attestor signs from an observation.
 *
 * Values and `present` come from the disclosed values, `subjectHash` from the
 * revealed request, `salt` from the claim context digest the notary signed,
 * `policyHash` and `version` from the policy; `appId`, `holder` and the window
 * are the caller's. A slot whose disclosure is absent or unparseable stays
 * unpresent.
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
  for (const slot of normalized.slots) {
    const value = slotValueOf(slot, observation.disclosedValues);
    if (value === null) continue;
    present[slot.slot] = true;
    if (typeof value === 'bigint') {
      values[slot.slot] = value;
    } else {
      byteValues[slot.slot - valueSlots] = new Uint8Array(value);
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
    subjectHash: tlsnSubjectHashOf(observation.request),
    present,
    values,
    byteValues,
  };
};
