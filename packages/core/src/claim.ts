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
 * Mirror of `attestation.compact`'s `Claim` struct: a header (version, appId,
 * policyHash, timestamp, nonce, subjectHash), a per-position `present` mask,
 * and `V` numeric `values`. There is no kind code: the policy hash is the
 * on-chain binding, and the kind stays an off-chain concept.
 *
 * This is the canonical shape kinds adopt unless they deviate.
 *
 * @typeParam V — the number of value slots (`attestation<#K, #V, #N, #M>`).
 * @see attestation.compact — the `Claim` struct this mirrors.
 */
// biome-ignore lint/correctness/noUnusedVariables: phantom type param — carries the claim's value count `V`.
export interface Claim<V extends number> {
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
  /** Unix seconds at which the attestation was produced. */
  timestamp: bigint;
  /** Per-claim randomness; prevents signature/claim replay on-chain. */
  nonce: Uint8Array;
  /**
   * Circuit hash of what the claim is about (see `@thoth/core/claim-context`'s
   * `subjectHashOf`); an app recomputes it in-circuit to bind the source.
   * 32 bytes.
   */
  subjectHash: Uint8Array;
  /** Per-position present mask; `present[i]` true means `values[i]` was populated. */
  present: readonly boolean[];
  /** Positional numeric claim values, exactly `V` of them. */
  values: readonly bigint[];
}

/**
 * The raw, unparsed form of a {@link Claim}: the zod `input` of
 * {@link claimSchema}.
 *
 * Uses `number | bigint` for the numeric fields so both JSON/wire payloads and
 * `bigint`-carrying objects validate; {@link claimSchema} coerces them to
 * `bigint` on parse.
 *
 * @typeParam V — the number of value slots.
 */
// biome-ignore lint/correctness/noUnusedVariables: phantom type param — carries the claim's value count `V`.
export interface ClaimInput<V extends number> {
  /** Schema version; a raw payload may omit it (defaults to {@link CLAIM_VERSION}). */
  version: number | bigint;
  /** The app the claim is for. 32 bytes. */
  appId: Uint8Array;
  /** Hash of the policy the attestors enforced. 32 bytes. */
  policyHash: Uint8Array;
  /** Unix seconds at which the attestation was produced. */
  timestamp: number | bigint;
  /** Per-claim randomness, replay protection. */
  nonce: Uint8Array;
  /** Circuit hash of what the claim is about. 32 bytes. */
  subjectHash: Uint8Array;
  /** Per-position present mask; length constrained to `V` by the schema. */
  present: readonly boolean[];
  /** Positional claim values; length constrained to `V` by the schema. */
  values: readonly (number | bigint)[];
}

/**
 * The current claim schema version, applied by {@link claimSchema} when a raw
 * payload omits `version`.
 */
export const CLAIM_VERSION = 1n;

/**
 * Zod schema for a claim's 32-byte identity and hash fields
 * (`appId`, `policyHash`, `subjectHash`).
 */
export const bytes32Schema = z
  .instanceof(Uint8Array)
  .refine((bytes) => bytes.length === 32, { message: 'expected 32 bytes' });

/**
 * Zod schema for a fixed `V` claim.
 *
 * Runtime validator + type source: `z.output` is a {@link Claim}, `z.input` a
 * {@link ClaimInput}. Kinds use it as their `claim` schema (or an extended
 * schema) so client-proposed claims are validated against the canonical shape.
 *
 * @param v — the number of value slots; constrains `present` and `values` to
 *   length `v`.
 * @returns a schema whose output is a {@link Claim}: validates the fixed shape
 *   and coerces the numeric fields to `bigint`.
 */
export function claimSchema<V extends number>(
  v: V,
): z.ZodType<Claim<V>, z.core.$ZodTypeInternals<Claim<V>, ClaimInput<V>>> {
  const schema = z
    .object({
      version: z.union([z.number(), z.bigint()]).default(CLAIM_VERSION),
      appId: bytes32Schema,
      policyHash: bytes32Schema,
      timestamp: z.union([z.number(), z.bigint()]),
      nonce: z.instanceof(Uint8Array),
      subjectHash: bytes32Schema,
      present: z.array(z.boolean()).length(v),
      values: z.array(z.union([z.number(), z.bigint()])).length(v),
    })
    .transform((input) => ({
      version: BigInt(input.version),
      appId: input.appId,
      policyHash: input.policyHash,
      timestamp: BigInt(input.timestamp),
      nonce: input.nonce,
      subjectHash: input.subjectHash,
      present: input.present,
      values: input.values.map((value) => BigInt(value)),
    }));
  return schema as unknown as z.ZodType<
    Claim<V>,
    z.core.$ZodTypeInternals<Claim<V>, ClaimInput<V>>
  >;
}

const UINT128_MAX = (1n << 128n) - 1n;

// Split 32 bytes into two 16-byte halves cast to `Uint<128>`, exactly as
// `attestation.compact`'s `splitBytes` does, so every byte is signed.
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
 * `Claim` shape: a 10-field header (version, then `appId` and `policyHash`
 * each split into two 16-byte halves, timestamp, then `nonce` and
 * `subjectHash` split the same way, exactly as `attestation.compact`'s
 * `buildMessage` does), followed by the `present` flags (`1`/`0`) and the
 * `values`. The result has length `2*V + 10`, which is
 * the signed-message length `K` the target contract is specialized with.
 *
 * Kinds that extend the claim or use a different layout keep their own
 * `message()`; a kind whose `message` is exactly the canonical shape may
 * implement `message()` by delegating to this helper.
 *
 * @param claim — a parsed {@link Claim}.
 * @returns the flat message the signer commits to and the contract verifies.
 * @throws if `claim.appId`, `claim.policyHash`, `claim.nonce` or
 *   `claim.subjectHash` is not exactly 32 bytes.
 */
export function claimToMessage<V extends number>(claim: Claim<V>): FlatMessage {
  return [
    claim.version,
    ...splitBytes(claim.appId),
    ...splitBytes(claim.policyHash),
    claim.timestamp,
    ...splitBytes(claim.nonce),
    ...splitBytes(claim.subjectHash),
    ...claim.present.map((p) => (p ? 1n : 0n)),
    ...claim.values,
  ];
}
