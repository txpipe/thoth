// The claim context hashes: policy, subject, holder and the claim context digest.
// Keyless and kind-agnostic; each kind supplies its own policy and subject structs.

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
 * The shared part of one attestation. Attestors given the same context and
 * the same observation derive the same claim. A kind binds it to its evidence
 * through {@link claimContextDigestOf} (ADR 0011).
 */
export interface ClaimContext {
  /** From {@link policyHashOf}. 32 bytes. */
  policyHash: Uint8Array;
  /** From {@link subjectHashOf}. 32 bytes. */
  subjectHash: Uint8Array;
  /** From {@link holderCommitmentOf}. 32 bytes. */
  holder: Uint8Array;
  /** Unix seconds. */
  windowStart: bigint;
  /** Unix seconds. */
  windowEnd: bigint;
}

const CLAIM_CONTEXT_TAG = 'thoth:claim-context';

const HASH_BYTES = 32;

// The circuit's 22-byte tag, unpadded. With the 32-byte secret the preimage is
// 54 bytes, one SHA-256 block in-circuit.
const HOLDER_COMMITMENT_TAG = new TextEncoder().encode('thoth:holder-commit:v1');

/**
 * Serialize a value canonically: JSON with object keys sorted by UTF-16 code
 * unit and no whitespace, a `bigint` as a quoted decimal string, a `Uint8Array`
 * as quoted lowercase hex without a prefix.
 *
 * @throws if the value holds a non-finite number, a sparse array, or anything
 *   that is not plain data.
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
    if (value.length !== Object.keys(value).length) {
      throw new Error('cannot canonicalize a sparse array');
    }
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

const canonicalSha256 = (value: CanonicalValue): Uint8Array =>
  new Uint8Array(createHash('sha256').update(canonicalJson(value), 'utf-8').digest());

const assertHashBytes = (name: string, bytes: Uint8Array): void => {
  if (bytes.length !== HASH_BYTES) {
    throw new Error(`${name} must be ${HASH_BYTES} bytes, got ${bytes.length}`);
  }
};

/**
 * Hash a kind's policy: SHA-256 of the canonical serialization of
 * `[law, version, policy]`, so the same policy under another law or wire
 * version hashes differently.
 *
 * @param law — the kind's law tag, such as `zk-fetch@1`.
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
 * `fields` are the kind's subject struct's `Bytes<32>` fields in declaration
 * order. The result equals the circuit's `persistentHash<Subject>(subject)`, so
 * an app can recompute it in-circuit from private fields (ADR 0001).
 *
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
 * Derive the per-claim holder commitment from a holder secret.
 *
 * Equals the circuit's `holderCommitment(secret)`: SHA-256 of the 22-byte tag
 * `thoth:holder-commit:v1`, then the secret. It is a different function from
 * the vault pseudonym the contract derives from the same secret, so the two
 * values are unrelated. Use a fresh secret per claim (ADR 0004).
 *
 * @param secret — 32 bytes.
 * @throws if the secret is not 32 bytes.
 */
export function holderCommitmentOf(secret: Uint8Array): Uint8Array {
  assertHashBytes('holder secret', secret);
  return new Uint8Array(createHash('sha256').update(HOLDER_COMMITMENT_TAG).update(secret).digest());
}

/**
 * Hash a claim context for a witness to sign: SHA-256 of the canonical
 * serialization of `['thoth:claim-context', context]`.
 *
 * @throws if a byte field is not 32 bytes or a window bound is negative.
 */
export function claimContextDigestOf(context: ClaimContext): Uint8Array {
  const { policyHash, subjectHash, holder, windowStart, windowEnd } = context;
  assertHashBytes('policyHash', policyHash);
  assertHashBytes('subjectHash', subjectHash);
  assertHashBytes('holder', holder);
  if (windowStart < 0n) {
    throw new Error(`windowStart must be non-negative, got ${windowStart}`);
  }
  if (windowEnd < 0n) {
    throw new Error(`windowEnd must be non-negative, got ${windowEnd}`);
  }
  return canonicalSha256([
    CLAIM_CONTEXT_TAG,
    { policyHash, subjectHash, holder, windowStart, windowEnd },
  ]);
}
