import type { z } from 'zod';
import type { FlatMessage } from './claim.js';

/**
 * The signed-message type of an attestor definition.
 *
 * Derived from the definition object's `message()` return type, so the whole
 * host stack (signer, key pair, attestation) picks up a custom message type
 * from the definition automatically — the definition is the single source of
 * truth. For standard kinds this is the default `FlatMessage`.
 *
 * @typeParam D — an {@link AttestorDefinition}.
 */
export type MessageOf<D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>> =
  ReturnType<D['message']>;

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
 * @typeParam Msg — the signed-message type; defaults to {@link FlatMessage}.
 * @see @thoth/attestor — where a definition is instantiated alongside its key.
 */
export interface AttestorDefinition<
  K extends string,
  P extends z.ZodType,
  E extends z.ZodType,
  C extends z.ZodType,
  Msg = FlatMessage,
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
   * The kind's wire law: encode the parsed claim into the exact message shape
   * the target contract's signature verifies over. Standard kinds produce a
   * flat field vector ({@link FlatMessage}); a kind may opt into another
   * message type via the definition's `Msg` parameter.
   *
   * @param claim — the parsed claim to encode.
   * @returns the message the signer commits to.
   */
  message(claim: z.output<C>): Msg;
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
 * `message` and `signature` together with the certified `claim` and the
 * `publicKey` that produced the signature. These are the values the client
 * later uses to submit the attestation to a contract.
 *
 * @typeParam C — the certified claim (the client-proposed claim that
 *   survived `verify` and was signed).
 * @typeParam PK — the attesting public key.
 * @typeParam S — the signature scheme type.
 * @typeParam Msg — the signed-message type; defaults to {@link FlatMessage}.
 */
export interface Attestation<C, PK, S, Msg = FlatMessage> {
  /** The parsed claim that was verified and is now certified. */
  claim: C;
  /** The message the signature commits to (`definition.message(claim)`). */
  message: Msg;
  /** The public key whose signature is attached. */
  publicKey: PK;
  /** The signature over `message`, produced by the holder of `publicKey`. */
  signature: S;
}
