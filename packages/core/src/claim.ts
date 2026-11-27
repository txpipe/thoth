import { createHash } from 'node:crypto';
import { convertBytesToUint } from '@midnight-ntwrk/compact-runtime';
import { z } from 'zod';

/**
 * A signed message as Compact `Field`s. A standard kind's is the contract's
 * seven-field `Vector<7, Field>`, in the order of the wire layout in the
 * `attestation.compact` header, which a kind's `message()` reproduces.
 */
export type FlatMessage = readonly bigint[];

/**
 * The claim every standard kind attests: the header, one `present` flag per slot
 * (`V` numeric slots, then `W` byte slots), `V` numeric `values` and `W` 32-byte
 * `byteValues`.
 *
 * It carries no kind: the policy hash binds it (ADR 0002). The contract stores
 * byte values as 16-byte halves, so a dApp hands it {@link toContractClaim}'s
 * output, never this shape.
 */
// biome-ignore lint/correctness/noUnusedVariables: phantom type param — carries the claim's numeric value count `V`.
export interface Claim<V extends number, W extends number = 0> {
  /** Wire version, `1`. */
  version: bigint;
  /** 32 bytes. The module does not check it; an app that must compares it in its predicate. */
  appId: Uint8Array;
  /** From `policyHashOf`. 32 bytes. The contract accepts only hashes in its sealed set. */
  policyHash: Uint8Array;
  /** Unix seconds. When the attestor observed, not when the fact happened (ADR 0005). */
  windowStart: bigint;
  /** Unix seconds. */
  windowEnd: bigint;
  /** From `subjectHashOf`. 32 bytes. An app recomputes it in-circuit to bind the source. */
  subjectHash: Uint8Array;
  /** From `holderCommitmentOf`. 32 bytes. */
  holder: Uint8Array;
  /**
   * 32 secret bytes the nullifier hashes; the chain never sees them. The kind
   * fixes them from the evidence, so the client cannot change them without new
   * evidence (ADR 0012).
   */
  salt: Uint8Array;
  /**
   * Exactly `V + W` flags: `present[i]` true means `values[i]` was measured for
   * `i < V`, and `byteValues[i - V]` for `i >= V`. A measured value may be zero.
   */
  present: readonly boolean[];
  /** Exactly `V`. An absent slot carries zero. */
  values: readonly bigint[];
  /** Exactly `W`, 32 bytes each. An absent slot carries zero bytes. */
  byteValues: readonly Uint8Array[];
}

/**
 * The raw form of a {@link Claim}, the zod input of {@link claimSchema}: numeric
 * fields accept a safe-integer `number` or a `bigint`, and `version` and
 * `byteValues` may be omitted.
 */
// biome-ignore lint/correctness/noUnusedVariables: phantom type param — carries the claim's numeric value count `V`.
export interface ClaimInput<V extends number, W extends number = 0> {
  /** Defaults to {@link CLAIM_VERSION}. */
  version: number | bigint;
  /** 32 bytes. */
  appId: Uint8Array;
  /** 32 bytes. */
  policyHash: Uint8Array;
  /** Unix seconds. */
  windowStart: number | bigint;
  /** Unix seconds. */
  windowEnd: number | bigint;
  /** 32 bytes. */
  subjectHash: Uint8Array;
  /** 32 bytes. */
  holder: Uint8Array;
  /** 32 bytes. */
  salt: Uint8Array;
  present: readonly boolean[];
  values: readonly (number | bigint)[];
  /** 32 bytes each. Defaults to `[]`. */
  byteValues?: readonly Uint8Array[];
}

/** The claim wire version {@link claimSchema} applies when a raw input omits `version`. */
export const CLAIM_VERSION = 1n;

/**
 * Zod schema for the claim's 32-byte fields (`appId`, `policyHash`, `subjectHash`,
 * `holder`, `salt`). It returns a copy the caller cannot change, and checks the
 * copy, not the caller's object.
 */
export const bytes32Schema = z
  .instanceof(Uint8Array)
  // `new Uint8Array` copies even an array over shared memory, which
  // `structuredClone` would share. Checking the copy means a Proxy cannot
  // pass with one length and copy to another.
  .transform((bytes) => new Uint8Array(bytes))
  .refine((bytes) => bytes.length === 32, { message: 'expected 32 bytes' });

// A non-negative integer below 2^bits, as a safe-integer `number` or a `bigint`,
// coerced to `bigint`. The bound is the field's Compact type in
// `attestation.compact`, so a claim that parses never reaches a signer or the
// contract out of range.
function uintSchema(bits: number) {
  const bound = 1n << BigInt(bits);
  return z
    .union([z.int(), z.bigint()])
    .transform((value) => BigInt(value))
    .refine((value) => value >= 0n && value < bound, {
      message: `expected an integer in [0, 2^${bits})`,
    });
}

const versionSchema = uintSchema(8);
const windowSchema = uintSchema(32);
const valueSchema = uintSchema(64);

/**
 * Zod schema for a claim with `V` numeric and `W` byte slots: validates the
 * shape, checks each numeric field fits its contract type (`values` below 2^64,
 * `windowStart` and `windowEnd` below 2^32, `version` below 2^8), coerces the
 * numeric fields to `bigint`, and defaults an omitted
 * `byteValues` to `[]`. The parsed claim owns copies of every byte array, so
 * the caller cannot change it between an attestor's checks and its signature.
 *
 * Omit `v` for a size-agnostic schema: no exact-length check, but `present`
 * still needs one flag per value.
 *
 * @param w — defaults to `0`; read only when `v` is given.
 */
export function claimSchema<V extends number = number, W extends number = 0>(
  v?: V,
  w?: W,
): z.ZodType<Claim<V, W>, z.core.$ZodTypeInternals<Claim<V, W>, ClaimInput<V, W>>> {
  const byteCount = w ?? 0;
  const schema = z
    .object({
      version: versionSchema.default(CLAIM_VERSION),
      appId: bytes32Schema,
      policyHash: bytes32Schema,
      windowStart: windowSchema,
      windowEnd: windowSchema,
      subjectHash: bytes32Schema,
      holder: bytes32Schema,
      salt: bytes32Schema,
      present: v === undefined ? z.array(z.boolean()) : z.array(z.boolean()).length(v + byteCount),
      values: v === undefined ? z.array(valueSchema) : z.array(valueSchema).length(v),
      byteValues:
        v === undefined
          ? z.array(bytes32Schema).default([])
          : z.array(bytes32Schema).length(byteCount).prefault([]),
    })
    .refine((input) => input.present.length === input.values.length + input.byteValues.length, {
      message: 'present must have one flag per value: values.length + byteValues.length',
      path: ['present'],
    });
  return schema as unknown as z.ZodType<
    Claim<V, W>,
    z.core.$ZodTypeInternals<Claim<V, W>, ClaimInput<V, W>>
  >;
}

// The width in bytes of each integer the nullifier hashes, from its Compact
// type in `attestation.compact`: `Uint<32>` windows, `Uint<64>` values.
const WINDOW_BYTES = 4;
const VALUE_BYTES = 8;
// `version` is a `Uint<8>`.
const VERSION_BITS = 8;

function assertBytes32(name: string, bytes: Uint8Array): void {
  if (bytes.length !== 32) {
    throw new Error(`${name} must be 32 bytes, got ${bytes.length}`);
  }
}

// An out-of-range value throws: the contract's `Uint<bits>` cannot hold it, and
// wrapping it would give two claims one encoding.
function assertUint(name: string, value: bigint, bits: number): void {
  if (value < 0n || value >= 1n << BigInt(bits)) {
    throw new Error(`${name} must be in [0, 2^${bits}), got ${value}`);
  }
}

// `value` little-endian in `width` bytes, as `persistentHash` writes a
// `Uint<8 * width>`.
function uintBytes(name: string, value: bigint, width: number): Uint8Array {
  assertUint(name, value, 8 * width);
  const bytes = new Uint8Array(width);
  let rest = value;
  for (let i = 0; i < width; i++) {
    bytes[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return bytes;
}

/**
 * Hash a parsed {@link Claim}'s observation identity: the nullifier the
 * contract's `nullifierOf` computes over `toContractClaim(claim)`. The attestors
 * sign it through {@link claimToMessage}, and the contract rejects it a second
 * time as a replay. It is the SHA-256 of every claim field but `version` and
 * `holder`; the wire layout in the `attestation.compact` header and
 * `docs/DESIGN.md` gives the preimage.
 *
 * @throws if `appId`, `policyHash`, `subjectHash`, `salt` or a byte value is
 *   not 32 bytes, a window bound is not below 2^32, a value is not below 2^64,
 *   or `present` does not have one flag per value.
 */
export function nullifierOf<V extends number, W extends number = 0>(
  claim: Claim<V, W>,
): Uint8Array {
  const c = toContractClaim(claim);
  assertBytes32('appId', c.appId);
  assertBytes32('policyHash', c.policyHash);
  assertBytes32('subjectHash', c.subjectHash);
  assertBytes32('salt', c.salt);
  const hash = createHash('sha256');
  hash.update(c.appId);
  hash.update(c.policyHash);
  hash.update(c.subjectHash);
  hash.update(c.salt);
  hash.update(uintBytes('windowStart', c.windowStart, WINDOW_BYTES));
  hash.update(uintBytes('windowEnd', c.windowEnd, WINDOW_BYTES));
  c.values.forEach((value, i) => {
    hash.update(uintBytes(`values[${i}]`, value, VALUE_BYTES));
  });
  for (const half of c.byteHalves) {
    hash.update(half);
  }
  hash.update(Uint8Array.from([...c.present, ...c.bytePresent], (present) => (present ? 1 : 0)));
  return new Uint8Array(hash.digest());
}

const UINT248_MAX = (1n << 248n) - 1n;

// A 32-byte value as the two fields the circuit holds it as: byte 31, then
// bytes 0-30 little-endian. Must equal `limbs` in `attestation.compact`.
function limbs(name: string, bytes: Uint8Array): [bigint, bigint] {
  assertBytes32(name, bytes);
  return [
    BigInt(bytes[31] ?? 0),
    convertBytesToUint(UINT248_MAX, 31, bytes.slice(0, 31), 'Uint<248>', 'claimToMessage'),
  ];
}

/**
 * Encode a parsed {@link Claim} into the seven-field message the contract's
 * `buildMessage` rebuilds: the claim's version, its layout, its nullifier
 * ({@link nullifierOf}) and its holder. The wire layout is in the
 * `attestation.compact` header and the table in `docs/DESIGN.md`.
 *
 * A kind whose claim is exactly the standard shape implements `message()` with
 * this; a kind that extends the claim keeps its own encoder.
 *
 * @throws if `version` is not below 2^8, `appId`, `policyHash`, `subjectHash`,
 *   `holder`, `salt` or a byte value is not 32 bytes, a window bound is not
 *   below 2^32, a value is not below 2^64, or `present` does not have one flag
 *   per value.
 */
export function claimToMessage<V extends number, W extends number = 0>(
  claim: Claim<V, W>,
): FlatMessage {
  assertUint('version', claim.version, VERSION_BITS);
  const nullifier = nullifierOf(claim);
  return [
    claim.version,
    BigInt(claim.values.length),
    BigInt(2 * claim.byteValues.length),
    ...limbs('nullifier', nullifier),
    ...limbs('holder', claim.holder),
  ];
}

/**
 * The `Claim` struct of `attestation.compact`, field for field: the shape a
 * dApp's `getAttestationWitness` returns. Its byte fields are split as the wire
 * layout in the `attestation.compact` header shows (ADR 0009).
 */
export interface ContractClaim {
  version: bigint;
  /** 32 bytes. */
  appId: Uint8Array;
  /** 32 bytes. */
  policyHash: Uint8Array;
  /** Unix seconds. */
  windowStart: bigint;
  /** Unix seconds. */
  windowEnd: bigint;
  /** 32 bytes. */
  subjectHash: Uint8Array;
  /** 32 bytes. */
  holder: Uint8Array;
  /** 32 bytes. */
  salt: Uint8Array;
  /** Exactly `V`. */
  present: boolean[];
  /** Exactly `B`: each byte slot's flag twice. */
  bytePresent: boolean[];
  /** Exactly `V`. */
  values: bigint[];
  /** Exactly `B`: bytes 0–15, then bytes 16–31, per byte value. */
  byteHalves: Uint8Array[];
}

/**
 * Convert a parsed {@link Claim} into the contract's witness shape, so that
 * `buildMessage` over the result equals `claimToMessage(claim)`.
 *
 * @throws if `present` does not have one flag per value, or a byte value is not
 *   32 bytes.
 */
export function toContractClaim<V extends number, W extends number = 0>(
  claim: Claim<V, W>,
): ContractClaim {
  const numericCount = claim.values.length;
  if (claim.present.length !== numericCount + claim.byteValues.length) {
    throw new Error(
      `present must have length ${numericCount + claim.byteValues.length}, got ${claim.present.length}`,
    );
  }
  return {
    version: claim.version,
    appId: claim.appId,
    policyHash: claim.policyHash,
    windowStart: claim.windowStart,
    windowEnd: claim.windowEnd,
    subjectHash: claim.subjectHash,
    holder: claim.holder,
    salt: claim.salt,
    present: claim.present.slice(0, numericCount),
    bytePresent: claim.present.slice(numericCount).flatMap((present) => [present, present]),
    values: [...claim.values],
    byteHalves: claim.byteValues.flatMap((bytes) => {
      if (bytes.length !== 32) {
        throw new Error(`expected 32 bytes, got ${bytes.length}`);
      }
      return [bytes.slice(0, 16), bytes.slice(16, 32)];
    }),
  };
}
