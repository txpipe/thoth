// The claim context: the hashes that tie a claim to its policy, its subject,
// and the context every witness signs. Keyless and kind-agnostic; each kind
// supplies its own policy and subject structs.

import { createHash } from 'node:crypto';
import {
  CompactTypeBytes,
  CompactTypeVector,
  persistentHash,
} from '@midnight-ntwrk/compact-runtime';
import { CLAIM_VERSION } from './claim.js';

/**
 * A value with a canonical serialization: JSON data plus `bigint` and
 * `Uint8Array`. Object keys whose value is `undefined` are dropped.
 */
export type CanonicalValue =
  | string
  | number
  | boolean
  | null
  | bigint
  | Uint8Array
  | readonly CanonicalValue[]
  | { readonly [key: string]: CanonicalValue | undefined };

/**
 * The shared context of one attestation.
 *
 * Every witness signs {@link claimContextDigestOf} of this context, so every
 * attestor derives the same claim from it.
 */
export interface ClaimContext {
  /** The policy the attestors enforce (see {@link policyHashOf}). 32 bytes. */
  policyHash: Uint8Array;
  /** What the claim is about (see {@link subjectHashOf}). 32 bytes. */
  subjectHash: Uint8Array;
  /** The per-claim holder commitment. 32 bytes. */
  holder: Uint8Array;
  /** Random per-claim bytes. 32 bytes. */
  nonce: Uint8Array;
  /** Start of the observation window, Unix seconds. */
  windowStart: bigint;
  /** End of the observation window, Unix seconds. */
  windowEnd: bigint;
}

/** Domain tag that prefixes the canonical claim context. */
const CLAIM_CONTEXT_TAG = 'thoth:claim-context';

const HASH_BYTES = 32;

/**
 * Serialize a value canonically.
 *
 * JSON with object keys sorted by UTF-16 code unit and no whitespace. A
 * `bigint` becomes its decimal string, a `Uint8Array` its lowercase hex
 * string without a prefix. Numbers must be finite.
 *
 * @param value — the value to serialize.
 * @returns the canonical JSON text.
 * @throws if the value holds a non-finite number or anything that is not
 *   plain data.
 */
const canonicalJson = (value: CanonicalValue): string => {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(`cannot canonicalize ${value}: numbers must be finite`);
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'bigint') {
    return JSON.stringify(value.toString(10));
  }
  if (value instanceof Uint8Array) {
    return JSON.stringify(Buffer.from(value).toString('hex'));
  }
  if (Array.isArray(value)) {
    return `[${value.map((item: CanonicalValue) => canonicalJson(item)).join(',')}]`;
  }
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new Error('cannot canonicalize a value that is not plain data');
  }
  const record = value as { readonly [key: string]: CanonicalValue | undefined };
  const members = Object.keys(record)
    .sort()
    .flatMap((key) => {
      const member = record[key];
      return member === undefined ? [] : [`${JSON.stringify(key)}:${canonicalJson(member)}`];
    });
  return `{${members.join(',')}}`;
};

/**
 * SHA-256 of a value's canonical serialization.
 *
 * @param value — the value to hash.
 * @returns the 32-byte digest.
 */
const canonicalSha256 = (value: CanonicalValue): Uint8Array =>
  new Uint8Array(createHash('sha256').update(canonicalJson(value), 'utf-8').digest());

const assertHashBytes = (name: string, bytes: Uint8Array): void => {
  if (bytes.length !== HASH_BYTES) {
    throw new Error(`${name} must be ${HASH_BYTES} bytes, got ${bytes.length}`);
  }
};

/**
 * Hash a kind's policy.
 *
 * SHA-256 of the canonical serialization of `[law, version, policy]`, so the
 * same policy under another law or wire version hashes differently. The
 * contract only compares this hash, so it need not be a circuit hash.
 *
 * @param law — the kind's law tag, e.g. `zk-fetch@1`.
 * @param policy — the kind's policy, as plain data.
 * @param version — the claim wire version the policy signs under. Defaults to
 *   {@link CLAIM_VERSION}.
 * @returns the 32-byte policy hash.
 * @throws if the policy has no canonical serialization.
 */
export function policyHashOf(
  law: string,
  policy: CanonicalValue,
  version: bigint = CLAIM_VERSION,
): Uint8Array {
  return canonicalSha256([law, version, policy]);
}

/**
 * Hash what a claim is about.
 *
 * The kind's subject is a Compact struct whose fields are all `Bytes<32>`;
 * `fields` lists them in declaration order. The result equals the circuit's
 * `persistentHash<Subject>(subject)`, so an app can recompute it in-circuit
 * from private fields.
 *
 * @param fields — the subject struct's fields, 32 bytes each.
 * @returns the 32-byte subject hash.
 * @throws if there are no fields or a field is not 32 bytes.
 */
export function subjectHashOf(fields: readonly Uint8Array[]): Uint8Array {
  if (fields.length === 0) {
    throw new Error('a subject needs at least one field');
  }
  fields.forEach((field, index) => {
    assertHashBytes(`subject field ${index}`, field);
  });
  return persistentHash(new CompactTypeVector(fields.length, new CompactTypeBytes(HASH_BYTES)), [
    ...fields,
  ]);
}

/**
 * Digest a claim context for the witness context.
 *
 * SHA-256 of the canonical serialization of `['thoth:claim-context', context]`.
 *
 * @param context — the claim context.
 * @returns the 32-byte context digest.
 * @throws if a byte field is not 32 bytes or a window bound is negative.
 */
export function claimContextDigestOf(context: ClaimContext): Uint8Array {
  const { policyHash, subjectHash, holder, nonce, windowStart, windowEnd } = context;
  assertHashBytes('policyHash', policyHash);
  assertHashBytes('subjectHash', subjectHash);
  assertHashBytes('holder', holder);
  assertHashBytes('nonce', nonce);
  if (windowStart < 0n) {
    throw new Error(`windowStart must be non-negative, got ${windowStart}`);
  }
  if (windowEnd < 0n) {
    throw new Error(`windowEnd must be non-negative, got ${windowEnd}`);
  }
  return canonicalSha256([
    CLAIM_CONTEXT_TAG,
    { policyHash, subjectHash, holder, nonce, windowStart, windowEnd },
  ]);
}
