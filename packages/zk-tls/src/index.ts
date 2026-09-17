import { createHash } from 'node:crypto';
import type { AttestationInput } from '@thoth/core';
import type { Claim, ClaimInput, FlatMessage } from '@thoth/core/claim';
import { CLAIM_VERSION } from '@thoth/core/claim';
import { z } from 'zod';

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
  readonly kind: 'zk-fetch@1';
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

/** A response redaction selection as declared in the claim's signed parameters. */
interface ResponseRedaction {
  /** Select a regex match from the response; named groups name the fields it hides. */
  regex?: string;
  /** Retrieve the item at a dot-notated JSON path; its leaf names the hidden field. */
  jsonPath?: string;
  /** Select an HTML node by xpath. */
  xPath?: string;
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
   * The extracted values the attestor can certify, keyed by named regex group;
   * already excludes redacted fields (which the proof's parameters mark as
   * hidden from the attestor).
   */
  disclosedValues: Readonly<Record<string, string>>;
  /** Claim identifier. */
  identifier: string;
  /** SHA-256 (hex) over the canonical serialization of the evidence; the claim's `evidenceHash`. */
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
 * allowlisted, whose signing Reclaim witness is pinned, and whose disclosures
 * cover every declared slot, within any size bound.
 */
export interface ZkFetchPolicy {
  /** Hosts the attested URL may target; exact or any subdomain suffix. */
  allowedHosts: readonly string[];
  /** The Reclaim attestor addresses this zkFetch attestor trusts. */
  attestorAddresses: readonly string[];
  /** Map extracted (disclosed) values onto claim slots. */
  slots: readonly ZkFetchSlot[];
  /** Upper bound on the captured response size in bytes. */
  maxResponseBytes?: number;
  /** Claim schema version the attestor signs; must match the contract's.
   * Defaults to 1. */
  claimVersion?: bigint;
  /** Contract-facing kind code the attestor signs (1 = zkFetch); must match the contract's. Defaults to 1. */
  claimKind?: bigint;
}

export const zkFetchPolicySchema = z.object({
  allowedHosts: z.array(z.string()).min(1),
  attestorAddresses: z.array(z.string()).min(1),
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
  maxResponseBytes: z.number().int().nonnegative().optional(),
  claimVersion: z.bigint().optional(),
  claimKind: z.bigint().optional(),
});

const hostAllowed = (host: string, allowedHosts: readonly string[]): boolean => {
  const lower = host.toLowerCase();
  return allowedHosts.some(
    (allowed) => lower === allowed.toLowerCase() || lower.endsWith(`.${allowed.toLowerCase()}`),
  );
};

const hexToBytes = (hex: string): Uint8Array =>
  new Uint8Array(Buffer.from(hex.replace(/^0x/, ''), 'hex'));

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

const NAMED_GROUP = /\(\?<([A-Za-z][A-Za-z0-9_]*)>/g;

/**
 * Extract the named-group names a regex pattern declares.
 *
 * Redaction and extraction patterns use `(?<name>…)` groups; the group names
 * are the field identifiers claim derivation keys on.
 *
 * @param pattern — the regex source.
 * @returns the named-group names, in order of appearance.
 */
const namedGroups = (pattern: string): string[] => {
  const names: string[] = [];
  for (const match of pattern.matchAll(NAMED_GROUP)) {
    const name = match[1];
    if (name !== undefined) {
      names.push(name);
    }
  }
  return names;
};

/**
 * The field names a redaction xPath hides.
 *
 * Mirrors the jsonPath leaf rule: an xPath names the node it selects, so the
 * hidden field is the selected node's local name — the last attribute/step
 * token of the expression (e.g. `/html/body/div[@id='x']/span` -> `span`,
 * `//price/@value` -> `value`). Returns an empty list when no name can be
 * derived; the caller then falls closed rather than certify a value the
 * witness may have hidden.
 *
 * @param expression — the redaction's xPath.
 * @returns the derived hidden field names, or `[]` when undecodable.
 */
const xPathFieldNames = (expression: string): string[] => {
  const last =
    expression
      .split('/')
      .filter((step) => step !== '' && step !== '.')
      .at(-1) ?? '';
  const attribute = last.startsWith('@') ? last.slice(1) : last;
  const name = attribute.replace(/\[.*$/, '').replace(/[^A-Za-z0-9_.-]/g, '');
  return name !== '' && name !== '*' ? [name] : [];
};

/**
 * Read the disclosed values the signed claim carries, dropping redacted fields.
 *
 * The signature already binds `claim.context`; this parser only interprets it.
 * Redaction is client-side in Reclaim — the attestor only ever sees selected
 * slices — so the *signed parameters* (`responseRedactions`) are the rule for
 * which extracted names are hidden and must never be certified. A redaction
 * names its fields through named regex groups, a JSON-path leaf, or an xPath
 * node name; a group-less regex names every disclosed value it matches; an
 * undecodable xPath falls closed (nothing is certified).
 *
 * @param claim — signed claim data whose context carries `extractedParameters`.
 * @returns the certifiable disclosed values; redacted names are dropped.
 */
const disclosedValuesOf = (claim: ProviderClaimData): Readonly<Record<string, string>> => {
  let parameters: Readonly<{ responseRedactions?: readonly ResponseRedaction[] }>;
  let context: Readonly<{ extractedParameters?: Readonly<Record<string, string>> }>;
  try {
    parameters = JSON.parse(claim.parameters) as Readonly<{
      responseRedactions?: readonly ResponseRedaction[];
    }>;
    context = JSON.parse(claim.context) as Readonly<{
      extractedParameters?: Readonly<Record<string, string>>;
    }>;
  } catch {
    throw new Error('claim parameters or context are not valid JSON');
  }
  const extracted = context.extractedParameters ?? {};
  const redacted = new Set<string>();
  const groupless: RegExp[] = [];
  for (const redaction of parameters.responseRedactions ?? []) {
    if (typeof redaction.regex === 'string' && redaction.regex !== '') {
      const groups = namedGroups(redaction.regex);
      if (groups.length === 0) {
        groupless.push(new RegExp(redaction.regex));
      } else {
        for (const name of groups) {
          redacted.add(name);
        }
      }
    }
    if (typeof redaction.jsonPath === 'string' && redaction.jsonPath !== '') {
      const leaf = redaction.jsonPath.split('.').at(-1);
      if (leaf !== undefined && leaf !== '') {
        redacted.add(leaf);
      }
    }
    if (typeof redaction.xPath === 'string' && redaction.xPath !== '') {
      const names = xPathFieldNames(redaction.xPath);
      if (names.length === 0) {
        // Undecodable selector: fall closed — none of the extracted values can
        // be certified, as any of them may be the one the witness hid.
        return {};
      }
      for (const name of names) {
        redacted.add(name);
      }
    }
  }
  const disclosed: Record<string, string> = {};
  for (const [name, value] of Object.entries(extracted)) {
    if (redacted.has(name)) {
      continue;
    }
    if (groupless.some((pattern) => pattern.test(value))) {
      continue;
    }
    disclosed[name] = value;
  }
  return disclosed;
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
 * The claim is a statement of what was observed, not what the client proposed:
 * `values`/`present` come straight from the policy-declared disclosures, the
 * timestamp is the fetch's (`evidence.timestampS`), and `evidenceHash` binds
 * the claim to the verified artifacts. `version`/`kind` come from the policy
 * (`claimVersion`/`claimKind`, defaulting to 1). The nonce is **deterministic**
 * in the evidence (SHA-256 over `identifier + canonicalHash`). A slot whose
 * disclosure is absent (or was redacted) stays unpresent — redacted fields are
 * never certified.
 *
 * @typeParam V — the claim's value-slot count.
 * @param options — the parsed evidence view, the policy, and the slot count.
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
}): Claim<V> => {
  const { verified, policy, valueSlots } = options;
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
    timestamp: BigInt(verified.claim.timestampS),
    nonce: hexToBytes(sha256Hex(`${verified.identifier}:${verified.canonicalHash}`)),
    evidenceHash: hexToBytes(verified.canonicalHash),
    present,
    values,
  } as Claim<V>;
};

/**
 * Check evidence against the policy.
 *
 * Fails fast so the attestor does not waste work: the attested URL must be
 * HTTPS against an allowlisted host, the proof must carry a signature from a
 * pinned Reclaim witness, every *required* policy slot's disclosure must be
 * certifiable (present and parseable — optional slots may be absent and are
 * signed unpresent), and the captured response must fit any size bound.
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
  const attestorAddress = verified.attestorAddress.toLowerCase();
  if (!policy.attestorAddresses.some((pinned) => pinned.toLowerCase() === attestorAddress)) {
    throw new Error(
      `attestor address ${verified.attestorAddress} not in pinned witnesses [${policy.attestorAddresses.join(
        ', ',
      )}]`,
    );
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
