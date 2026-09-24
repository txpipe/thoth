import { degradeToTransient } from '@midnight-ntwrk/compact-runtime';
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
 * Mirror of `attestation.compact`'s `Claim` struct: an 8-field header
 * (version, kind, policyDigest, requestBinding, holder, nonce, windowStart,
 * windowEnd), a per-position `present` mask, and `V` numeric `values`.
 *
 * The claim is *common*: it carries only facts every attestor observing the
 * same intent shares, and nothing specific to one piece of evidence, so
 * independent observations of the same fact sign the same message.
 *
 * @typeParam V — the number of value slots (`attestation<#K, #V, #N, #M>`).
 * @see attestation.compact — the `Claim` struct this mirrors.
 */
// biome-ignore lint/correctness/noUnusedVariables: phantom type param — carries the claim's value count `V`.
export interface Claim<V extends number> {
  /** Schema version of the claim format. Currently `1`. */
  version: bigint;
  /** Attestor kind identifier (e.g. `1` for the reclaim/zkFetch kind). */
  kind: bigint;
  /** 32-byte digest of the policy the claim was attested under. */
  policyDigest: Uint8Array;
  /** 32-byte digest of the certified request identity. */
  requestBinding: Uint8Array;
  /** 32-byte holder commitment the claim is bound to. */
  holder: Uint8Array;
  /** 32-byte operation nonce; prevents replay on-chain. */
  nonce: Uint8Array;
  /** Start of the observation window, Unix seconds. */
  windowStart: bigint;
  /** End of the observation window, Unix seconds. */
  windowEnd: bigint;
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
  /** Attestor kind identifier. */
  kind: number | bigint;
  /** 32-byte policy digest. */
  policyDigest: Uint8Array;
  /** 32-byte request binding. */
  requestBinding: Uint8Array;
  /** 32-byte holder commitment. */
  holder: Uint8Array;
  /** 32-byte operation nonce. */
  nonce: Uint8Array;
  /** Start of the observation window, Unix seconds. */
  windowStart: number | bigint;
  /** End of the observation window, Unix seconds. */
  windowEnd: number | bigint;
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

const bytes32 = z.instanceof(Uint8Array).refine((b) => b.length === 32, 'must be 32 bytes');
const numeric = z.union([z.number(), z.bigint()]);

/**
 * Zod schema for a claim, optionally pinned to `V` value slots.
 *
 * Runtime validator + type source: `z.output` is a {@link Claim}, `z.input` a
 * {@link ClaimInput}. Kinds use it as their `claim` schema (or an extended
 * schema) so client-proposed claims are validated against the canonical shape.
 *
 * @param v — the number of value slots; constrains `present` and `values` to
 *   length `v`. Omit it to accept any (equal) length.
 * @returns a schema whose output is a {@link Claim}: validates the fixed shape
 *   and coerces the numeric fields to `bigint`.
 */
export function claimSchema<V extends number>(
  v?: V,
): z.ZodType<Claim<V>, z.core.$ZodTypeInternals<Claim<V>, ClaimInput<V>>> {
  const present = z.array(z.boolean());
  const values = z.array(numeric);
  const schema = z
    .object({
      version: numeric.default(CLAIM_VERSION),
      kind: numeric,
      policyDigest: bytes32,
      requestBinding: bytes32,
      holder: bytes32,
      nonce: bytes32,
      windowStart: numeric,
      windowEnd: numeric,
      present: v === undefined ? present : present.length(v),
      values: v === undefined ? values : values.length(v),
    })
    .refine((c) => c.present.length === c.values.length, 'present and values differ in length')
    .transform((input) => ({
      version: BigInt(input.version),
      kind: BigInt(input.kind),
      policyDigest: input.policyDigest,
      requestBinding: input.requestBinding,
      holder: input.holder,
      nonce: input.nonce,
      windowStart: BigInt(input.windowStart),
      windowEnd: BigInt(input.windowEnd),
      present: input.present,
      values: input.values.map((value) => BigInt(value)),
    }));
  return schema as unknown as z.ZodType<
    Claim<V>,
    z.core.$ZodTypeInternals<Claim<V>, ClaimInput<V>>
  >;
}

/**
 * Encode a parsed {@link Claim} into the flat signed-message field vector.
 *
 * The canonical default for kinds whose `message` is exactly the canonical
 * `Claim` shape: an 8-field header (version, kind, the four 32-byte fields
 * mapped via {@link !degradeToTransient} exactly as `attestation.compact`'s
 * `buildMessage` does, windowStart, windowEnd), followed by the `present`
 * flags (`1`/`0`) and the `values`. The result has length `2*V + 8`, which is
 * the signed-message length `K` the target contract is specialized with.
 *
 * Kinds that extend the claim or use a different layout keep their own
 * `message()`; a kind whose `message` is exactly the canonical shape may
 * implement `message()` by delegating to this helper.
 *
 * @param claim — a parsed {@link Claim}.
 * @returns the flat message the signer commits to and the contract verifies.
 * @throws if a 32-byte field is not exactly 32 bytes (the `degradeToTransient`
 *   precondition).
 */
export function claimToMessage<V extends number>(claim: Claim<V>): FlatMessage {
  return [
    claim.version,
    claim.kind,
    degradeToTransient(claim.policyDigest),
    degradeToTransient(claim.requestBinding),
    degradeToTransient(claim.holder),
    degradeToTransient(claim.nonce),
    claim.windowStart,
    claim.windowEnd,
    ...claim.present.map((p) => (p ? 1n : 0n)),
    ...claim.values,
  ];
}
