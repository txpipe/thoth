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
 * Mirror of `attestation.compact`'s `Claim` struct: a 5-field header (version,
 * kind, timestamp, nonce, evidenceHash), a per-position `present` mask, and `V`
 * numeric `values`.
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
  /** Attestor kind identifier (e.g. `1` for the reclaim/zkFetch kind). */
  kind: bigint;
  /** Unix seconds at which the attestation was produced. */
  timestamp: bigint;
  /** Per-claim randomness; prevents signature/claim replay on-chain. */
  nonce: Uint8Array;
  /** Hash of the evidence artifacts; binds the claim to its evidence. */
  evidenceHash: Uint8Array;
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
  /** Unix seconds at which the attestation was produced. */
  timestamp: number | bigint;
  /** Per-claim randomness, replay protection. */
  nonce: Uint8Array;
  /** Hash of the evidence artifacts. */
  evidenceHash: Uint8Array;
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
      kind: z.union([z.number(), z.bigint()]),
      timestamp: z.union([z.number(), z.bigint()]),
      nonce: z.instanceof(Uint8Array),
      evidenceHash: z.instanceof(Uint8Array),
      present: z.array(z.boolean()).length(v),
      values: z.array(z.union([z.number(), z.bigint()])).length(v),
    })
    .transform((input) => ({
      version: BigInt(input.version),
      kind: BigInt(input.kind),
      timestamp: BigInt(input.timestamp),
      nonce: input.nonce,
      evidenceHash: input.evidenceHash,
      present: input.present,
      values: input.values.map((value) => BigInt(value)),
    }));
  return schema as unknown as z.ZodType<
    Claim<V>,
    z.core.$ZodTypeInternals<Claim<V>, ClaimInput<V>>
  >;
}

/**
 * The input submitted to an attestor for evaluation.
 *
 * @typeParam P — the policy value (see {@link AttestorDefinition.policy}).
 * @typeParam E — the evidence value.
 * @typeParam C — the claim value.
 */
export interface AttestationInput<P, E, C> {
  /** The rules under which the attestation is produced. */
  policy: P;
  /**
   * The material the attestor uses to decide whether to attest (a zkFetch
   * proof, an observed on-chain event, a device quote, …).
   */
  evidence: E;
  /** The value or values the attestor certifies; application-specific and
   *  compatible with the Compact contracts. */
  claim: C;
}

/**
 * The shareable contract a kind of attestor implements.
 *
 * `P`, `E`, and `C` are zod schemas: they double as runtime validators and as
 * the type source for the parsed values (`z.output<P>` etc.).
 *
 * A definition owns both halves of the attestor's law: how to decide whether an
 * input may be attested (`verify`) and how to encode the certified claim into
 * the flat message (`message`).
 *
 * This type carries no signing key. Key-holding attestor instances live in
 * `@thoth/attestor`.
 *
 * @typeParam K — the stable, versioned kind identifier.
 * @typeParam P — policy schema.
 * @typeParam E — evidence schema.
 * @typeParam C — claim schema.
 * @see @thoth/attestor — where a definition is instantiated alongside its key.
 */
export interface AttestorDefinition<
  K extends string,
  P extends z.ZodType,
  E extends z.ZodType,
  C extends z.ZodType,
> {
  /** Stable, versioned identifier for this kind of attestation. */
  readonly kind: K;

  /** Runtime schema for the policy. */
  readonly policy: P;

  /** Runtime schema for the evidence. */
  readonly evidence: E;

  /** Runtime schema for the claim. */
  readonly claim: C;

  /**
   * Decides whether the input may be attested.
   *
   * Values are already parsed by their zod schemas. Resolve to authorize
   * signing; throw to reject the request.
   *
   * @param input — the parsed enforcement envelope.
   * @returns nothing on success; throws to reject.
   */
  verify(input: AttestationInput<z.output<P>, z.output<E>, z.output<C>>): void | Promise<void>;

  /**
   * The kind's wire law: encode the parsed claim into the exact flat field
   * vector the target contract's `buildMessage` verifies the signature over.
   *
   * @param claim — the parsed claim to encode.
   * @returns the flat message the signer commits to.
   */
  message(claim: z.output<C>): FlatMessage;
}

/**
 * The client-side face of an attestor instance: everything a client needs to
 * address the attestor and place its signatures, with none of the key-bearing
 * machinery of `@thoth/attestor`.
 *
 * `registryIndex` is load-bearing: `attestor_registry.compact` verifies
 * signatures *positionally* — `signature[i]` against `keys[i]` — so the
 * client must place each collected signature at the slot holding that
 * attestor's public key.
 *
 * @typeParam D — the attestor's definition type.
 * @typeParam PK — the attestor's public-key type (scheme-specific).
 */
export interface AttestorDescriptor<
  D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
> {
  /** Stable identifier for the attestor instance (non-cryptographic). */
  id: string;
  /** The kind's shareable law: schemas, `verify`, `message`. */
  definition: D;
  /** Public key this attestor attests under; maps to an on-chain registry slot. */
  publicKey: PK;
  /** Registry slot = position in the signatures vector; see type doc above. */
  registryIndex: number;
}

/**
 * The artifact an attestor produces and a client collects: it ties the signed
 * `message` and `signature` together with the `kind`, the certified `claim`,
 * and the `publicKey` that produced the signature — everything the client
 * later needs to submit the attestation to a contract.
 *
 * @typeParam K — the attestor kind.
 * @typeParam C — the certified claim (the client-proposed claim that
 *   survived `verify` and was signed).
 * @typeParam PK — the attesting public key.
 * @typeParam S — the signature scheme type.
 */
export interface Attestation<K, C, PK, S> {
  /** The attestor kind that produced this attestation. */
  kind: K;
  /** The parsed claim that was verified and is now certified. */
  claim: C;
  /** The flat message the signature commits to (`definition.message(claim)`). */
  message: FlatMessage;
  /** The public key whose signature is attached. */
  publicKey: PK;
  /** The signature over `message`, produced by the holder of `publicKey`. */
  signature: S;
}
