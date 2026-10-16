import type { z } from 'zod';
import type { FlatMessage } from './claim.js';

/**
 * The signed-message type of an attestor definition, taken from its `message()`
 * return type so the signer, key pair and attestation agree with the definition.
 */
export type MessageOf<D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>> =
  ReturnType<D['message']>;

/** The input a dApp submits to an attestor. */
export interface AttestationInput<P, E, C> {
  /** The rules the attestor enforces for this input. */
  policy: P;
  /** What the attestor judges: a zkFetch proof, an observed event, a device quote, … */
  evidence: E;
  /** The claim proposal the attestor derives its signed claim from. */
  claim: C;
}

/**
 * The law a kind of attestor implements: zod schemas for the policy, evidence
 * and claim, plus `verify` and `message`.
 *
 * It carries no signing key; `@thoth/attestor` pairs it with one.
 */
export interface AttestorDefinition<
  K extends string,
  P extends z.ZodType,
  E extends z.ZodType,
  C extends z.ZodType,
  Msg = FlatMessage,
> {
  /** The kind's versioned law tag, such as `zk-fetch@1`. */
  readonly kind: K;

  readonly policy: P;

  readonly evidence: E;

  readonly claim: C;

  /**
   * Decides whether the parsed input may be attested: return to authorize
   * signing, throw to reject.
   *
   * @throws to reject the input.
   */
  verify(input: AttestationInput<z.output<P>, z.output<E>, z.output<C>>): void | Promise<void>;

  /**
   * Encodes the parsed claim into the message the attestor signs and the
   * contract verifies. Standard kinds delegate to `claimToMessage`.
   */
  message(claim: z.output<C>): Msg;
}

/**
 * The client-side view of an attestor: what a dApp needs to address it and
 * check its signatures, with no key material.
 *
 * It carries no registry slot: the signed message binds no registry, so one
 * attestor can serve many registries, and each app assigns the slot in its
 * trusted set (`@thoth/client`).
 */
export interface AttestorDescriptor<
  D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
> {
  /** Non-cryptographic identifier of the attestor instance. */
  id: string;
  definition: D;
  publicKey: PK;
}

/**
 * The signed artifact one attestor returns: the claim it derived, the message
 * it signed, and the public key and signature.
 */
export interface Attestation<C, PK, S, Msg = FlatMessage> {
  claim: C;
  /** `definition.message(claim)`, what `signature` commits to. */
  message: Msg;
  publicKey: PK;
  signature: S;
}
