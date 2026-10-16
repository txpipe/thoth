import { convertBytesToUint } from '@midnight-ntwrk/compact-runtime';
import { z } from 'zod';

/**
 * A Compact `Vector<K, Field>` signed message. Its field order is the wire
 * layout in the `attestation.compact` header, which a kind's `message()`
 * reproduces.
 */
export type FlatMessage = readonly bigint[];

/**
 * The claim every standard kind signs: the header, one `present` flag per slot
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
 * fields accept `number | bigint`, `version` and `byteValues` may be omitted.
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
  present: readonly boolean[];
  values: readonly (number | bigint)[];
  /** 32 bytes each. Defaults to `[]`. */
  byteValues?: readonly Uint8Array[];
}

/** The claim wire version {@link claimSchema} applies when a raw input omits `version`. */
export const CLAIM_VERSION = 1n;

/** Zod schema for the claim's 32-byte fields (`appId`, `policyHash`, `subjectHash`, `holder`). */
export const bytes32Schema = z
  .instanceof(Uint8Array)
  .refine((bytes) => bytes.length === 32, { message: 'expected 32 bytes' });

/**
 * Zod schema for a claim with `V` numeric and `W` byte slots: validates the
 * shape, coerces the numeric fields to `bigint`, and defaults an omitted
 * `byteValues` to `[]`.
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
      version: z.union([z.number(), z.bigint()]).default(CLAIM_VERSION),
      appId: bytes32Schema,
      policyHash: bytes32Schema,
      windowStart: z.union([z.number(), z.bigint()]),
      windowEnd: z.union([z.number(), z.bigint()]),
      subjectHash: bytes32Schema,
      holder: bytes32Schema,
      present: v === undefined ? z.array(z.boolean()) : z.array(z.boolean()).length(v + byteCount),
      values:
        v === undefined
          ? z.array(z.union([z.number(), z.bigint()]))
          : z.array(z.union([z.number(), z.bigint()])).length(v),
      byteValues:
        v === undefined
          ? z.array(bytes32Schema).default([])
          : z.array(bytes32Schema).length(byteCount).prefault([]),
    })
    .refine((input) => input.present.length === input.values.length + input.byteValues.length, {
      message: 'present must have one flag per value: values.length + byteValues.length',
      path: ['present'],
    })
    .transform((input) => ({
      version: BigInt(input.version),
      appId: input.appId,
      policyHash: input.policyHash,
      windowStart: BigInt(input.windowStart),
      windowEnd: BigInt(input.windowEnd),
      subjectHash: input.subjectHash,
      holder: input.holder,
      present: input.present,
      values: input.values.map((value) => BigInt(value)),
      byteValues: input.byteValues,
    }));
  return schema as unknown as z.ZodType<
    Claim<V, W>,
    z.core.$ZodTypeInternals<Claim<V, W>, ClaimInput<V, W>>
  >;
}

const UINT128_MAX = (1n << 128n) - 1n;

// Must equal the in-circuit cast in `attestation.compact`'s `splitBytes`; its
// header gives the byte order.
function splitBytes(bytes: Uint8Array): [bigint, bigint] {
  if (bytes.length !== 32) {
    throw new Error(`expected 32 bytes, got ${bytes.length}`);
  }
  return [
    convertBytesToUint(UINT128_MAX, 16, bytes.slice(0, 16), 'Uint<128>', 'claimToMessage'),
    convertBytesToUint(UINT128_MAX, 16, bytes.slice(16, 32), 'Uint<128>', 'claimToMessage'),
  ];
}

/**
 * Encode a parsed {@link Claim} into the flat message the contract's
 * `buildMessage` rebuilds. The wire layout is in the `attestation.compact`
 * header and the table in `docs/DESIGN.md`.
 *
 * A kind whose claim is exactly the standard shape implements `message()` with
 * this; a kind that extends the claim keeps its own encoder.
 *
 * @throws if `appId`, `policyHash`, `subjectHash`, `holder` or a byte value is
 *   not 32 bytes, or if `present` does not have one flag per value.
 */
export function claimToMessage<V extends number, W extends number = 0>(
  claim: Claim<V, W>,
): FlatMessage {
  const numericCount = claim.values.length;
  const byteCount = claim.byteValues.length;
  if (claim.present.length !== numericCount + byteCount) {
    throw new Error(
      `present must have length ${numericCount + byteCount}, got ${claim.present.length}`,
    );
  }
  const flags = claim.present.map((present) => (present ? 1n : 0n));
  const byteFlags = flags.slice(numericCount).flatMap((flag) => [flag, flag]);
  return [
    claim.version,
    ...splitBytes(claim.appId),
    ...splitBytes(claim.policyHash),
    claim.windowStart,
    claim.windowEnd,
    ...splitBytes(claim.subjectHash),
    ...splitBytes(claim.holder),
    BigInt(2 * byteCount),
    ...flags.slice(0, numericCount),
    ...byteFlags,
    ...claim.values,
    ...claim.byteValues.flatMap((bytes) => splitBytes(bytes)),
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
