import { convertBytesToUint } from '@midnight-ntwrk/compact-runtime';
import { z } from 'zod';

/**
 * A Compact `Vector<K, Field>` flat signed message.
 *
 * `K` and the field order are per-kind wire law: they are fixed by the target
 * contract's `buildMessage` and mirrored by `AttestorDefinition.message`.
 *
 * The `readonly` annotation is a type-level "do not mutate" promise.
 *
 * @see attestation.compact — `buildMessage` defines the wire layout a kind's
 *   `message()` must reproduce.
 */
export type FlatMessage = readonly bigint[];

/**
 * The fixed claim shape every kind is expected to sign.
 *
 * Mirror of `attestation.compact`'s `Claim` semantics: a header (version, appId,
 * policyHash, windowStart, windowEnd, subjectHash, holder), a per-position
 * `present` mask (`V` numeric slots followed by `W` byte slots), `V` numeric
 * `values`, and `W` 32-byte `byteValues`. The contract stores each byte value as
 * its two adjacent 16-byte halves and carries the byte slot's flag once per
 * half; `claimToMessage` performs that split, so this shape stays the
 * kind-facing one.
 *
 * There is no kind code: the policy hash is the on-chain binding, and the kind
 * stays an off-chain concept.
 *
 * This is the canonical shape kinds adopt unless they deviate.
 *
 * @typeParam V — the number of numeric value slots (`attestation<#K, #V, #B, #N, #M>`).
 * @typeParam W — the number of 32-byte byte value slots; `W = 0` is the canonical
 *   numeric-only shape and the default.
 * @see attestation.compact — the `Claim` struct this mirrors.
 */
// biome-ignore lint/correctness/noUnusedVariables: phantom type param — carries the claim's numeric value count `V`.
export interface Claim<V extends number, W extends number = 0> {
  /** Schema version of the claim format. Currently `1`. */
  version: bigint;
  /** The app the claim is for. 32 bytes. */
  appId: Uint8Array;
  /**
   * Hash of the policy the attestors enforced (see `@thoth/core/claim-context`'s
   * `policyHashOf`). The contract accepts it only if it is in its sealed set.
   * 32 bytes.
   */
  policyHash: Uint8Array;
  /**
   * Unix seconds at which the attestor's observation began. The window is when
   * the attestor observed, not when the underlying fact happened.
   */
  windowStart: bigint;
  /** Unix seconds at which the attestor's observation ended. */
  windowEnd: bigint;
  /**
   * Circuit hash of what the claim is about (see `@thoth/core/claim-context`'s
   * `subjectHashOf`); an app recomputes it in-circuit to bind the source.
   * 32 bytes.
   */
  subjectHash: Uint8Array;
  /** Per-claim commitment of the caller secret. 32 bytes, derived by holderCommitmentOf. */
  holder: Uint8Array;
  /**
   * Per-position present mask, exactly `V + W` flags: `present[i]` true means
   * `values[i]` was populated for `i < V`, and the byte value with index `i - V`
   * was populated for `i >= V`.
   */
  present: readonly boolean[];
  /** Positional numeric claim values, exactly `V` of them. */
  values: readonly bigint[];
  /** Positional byte claim values, exactly `W` of them, 32 bytes each. */
  byteValues: readonly Uint8Array[];
}

/**
 * The raw, unparsed form of a {@link Claim}: the zod `input` of
 * {@link claimSchema}.
 *
 * Uses `number | bigint` for the numeric fields so both JSON/wire payloads and
 * `bigint`-carrying objects validate; {@link claimSchema} coerces them to
 * `bigint` on parse. A raw payload may omit `byteValues` (defaults to `[]`).
 *
 * @typeParam V — the number of numeric value slots.
 * @typeParam W — the number of byte value slots.
 */
// biome-ignore lint/correctness/noUnusedVariables: phantom type param — carries the claim's numeric value count `V`.
export interface ClaimInput<V extends number, W extends number = 0> {
  /** Schema version; a raw payload may omit it (defaults to {@link CLAIM_VERSION}). */
  version: number | bigint;
  /** The app the claim is for. 32 bytes. */
  appId: Uint8Array;
  /** Hash of the policy the attestors enforced. 32 bytes. */
  policyHash: Uint8Array;
  /** Unix seconds at which the attestor's observation began. */
  windowStart: number | bigint;
  /** Unix seconds at which the attestor's observation ended. */
  windowEnd: number | bigint;
  /** Circuit hash of what the claim is about. 32 bytes. */
  subjectHash: Uint8Array;
  /** Per-claim commitment of the caller secret. 32 bytes, derived by holderCommitmentOf. */
  holder: Uint8Array;
  /** Per-position present mask; a schema built with `v` constrains it to `V + W`. */
  present: readonly boolean[];
  /** Positional numeric claim values; a schema built with `v` constrains it to `V`. */
  values: readonly (number | bigint)[];
  /** Positional byte claim values (32 bytes each); constrained to `W` when built with `v`, defaults to `[]`. */
  byteValues?: readonly Uint8Array[];
}

/**
 * The current claim schema version, applied by {@link claimSchema} when a raw
 * payload omits `version`.
 */
export const CLAIM_VERSION = 1n;

/**
 * Zod schema for a claim's 32-byte identity and hash fields
 * (`appId`, `policyHash`, `subjectHash`, `holder`).
 */
export const bytes32Schema = z
  .instanceof(Uint8Array)
  .refine((bytes) => bytes.length === 32, { message: 'expected 32 bytes' });

/**
 * Zod schema for a fixed `V`-numeric / `W`-byte claim.
 *
 * Runtime validator + type source: `z.output` is a {@link Claim}, `z.input` a
 * {@link ClaimInput}. Kinds use it as their `claim` schema (or an extended
 * schema) so client-proposed claims are validated against the canonical shape.
 *
 * @typeParam V — the number of numeric value slots; `number` when omitted.
 * @typeParam W — the number of byte value slots; defaults to `0`.
 * @param v — the number of numeric value slots, or omit when the count is
 *   unknown at parse time. Omitted, every exact-length constraint is skipped.
 * @param w — the number of 32-byte byte value slots; constrains `byteValues`
 *   and the mask's tail. Defaults to `0`; read only when `v` is given.
 * @returns a schema whose output is a {@link Claim}: validates the fixed shape,
 *   defaults an omitted `byteValues` to `[]`, and coerces the numeric fields to
 *   `bigint`.
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

// Split 32 bytes into two 16-byte halves cast to `Uint<128>`, exactly as
// `attestation.compact`'s `splitBytes` does, so every byte is signed. Each half
// is read little-endian (byte 0 least significant), the runtime's
// `convertBytesToUint` convention, matching the in-circuit cast.
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
 * Encode a parsed {@link Claim} into the flat signed-message field vector.
 *
 * The canonical default for kinds whose `message` is exactly the canonical
 * `Claim` shape: an 11-field header (version, then `appId` and `policyHash`
 * each split into two 16-byte halves, `windowStart`, `windowEnd`, then
 * `subjectHash`, and `holder` split the same way, exactly as `attestation.compact`'s
 * `buildMessage` does), followed by the `present` flags (`1`/`0`), each byte
 * slot's flag repeated for its two halves, the `values`, and each byte value's
 * two halves (`bytes 0–15`, then `bytes 16–31`, in value order).
 *
 * The result has length `2*V + 4*W + 11`, which is the signed-message length
 * `K` the target contract is specialized with (`K = 11 + 2V + 2B`, `B = 2W`).
 *
 * Kinds that extend the claim or use a different layout keep their own
 * `message()`; a kind whose `message` is exactly the canonical shape may
 * implement `message()` by delegating to this helper.
 *
 * @typeParam V — the number of numeric value slots.
 * @typeParam W — the number of byte value slots.
 * @param claim — a parsed {@link Claim}.
 * @returns the flat message the signer commits to and the contract verifies.
 * @throws if `claim.appId`, `claim.policyHash`, `claim.subjectHash`,
 *   `claim.holder`, or any `claim.byteValues[i]` is not exactly 32 bytes, or if
 *   `present` does not have length `V + W`.
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
    ...flags.slice(0, numericCount),
    ...byteFlags,
    ...claim.values,
    ...claim.byteValues.flatMap((bytes) => splitBytes(bytes)),
  ];
}
