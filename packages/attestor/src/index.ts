import type {
  Attestation,
  AttestationInput,
  AttestorDefinition,
  AttestorDescriptor,
  MessageOf,
} from '@thoth/core';
import type { FlatMessage } from '@thoth/core/claim';
import type { z } from 'zod';

/**
 * Type-checking identity for an attestor definition.
 *
 * Keeps `kind` and the schema types as the literals inferred from the object
 * literal, so the kind can be named by its exact type elsewhere.
 *
 * @example
 * ```ts
 * const law = defineAttestor({
 *   kind: 'my-kind@1',
 *   policy: myPolicySchema,
 *   evidence: myEvidenceSchema,
 *   claim: claimSchema<8>(8),
 *   verify: async (input) => {
 *     if (!accepts(input)) throw new Error('rejected');
 *   },
 *   message: (claim) => claimToMessage(claim),
 * });
 * ```
 */
export function defineAttestor<
  const D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
>(definition: D): D {
  return definition;
}

/**
 * The key boundary: whoever holds the private key implements `sign`.
 *
 * The key never crosses this interface; an implementation keeps it in a
 * closure or behind a hardware module.
 *
 * @typeParam Msg — the signed-message type; defaults to {@link FlatMessage}.
 */
export interface AttestorSigner<S, Msg = FlatMessage> {
  /** Sign a kind's `message(claim)` output with the held private key. */
  sign(message: Msg): S | Promise<S>;
}

/**
 * A public key paired with the signer that holds the matching private key.
 *
 * The kind's key package builds both from one private key. Binding them at
 * construction makes a signer with a mismatched public key impossible to
 * express, so no such mismatch reaches N-of-M verification.
 *
 * @typeParam Msg — the signed-message type; defaults to {@link FlatMessage}.
 */
export interface KeyPair<PK, S, Msg = FlatMessage> {
  readonly publicKey: PK;
  readonly signer: AttestorSigner<S, Msg>;
}

/**
 * A deployable attestor instance: the kind's shareable law, its key boundary,
 * and the public key it attests under.
 *
 * It carries no registry slot. The signed message binds none, so one instance
 * serves any number of registries; each app assigns the slot in its trusted
 * set (`@thoth/client`).
 */
export interface Attestor<
  D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
  S,
> {
  /** Stable, non-cryptographic identifier for client-side addressing. */
  id: string;
  definition: D;
  signer: AttestorSigner<S, MessageOf<D>>;
  /** The key the app maps to a registry slot. */
  publicKey: PK;

  /**
   * Run the attestation lifecycle: parse the raw input with the definition's
   * schemas, `verify`, then sign `message(claim)`.
   *
   * Each kind's package implements it and must call `verify` before signing.
   *
   * @param input — raw values, per the definition's `z.input` schemas.
   * @throws to reject the input.
   */
  attest(
    input: AttestationInput<z.input<D['policy']>, z.input<D['evidence']>, z.input<D['claim']>>,
  ): Promise<Attestation<z.output<D['claim']>, PK, S, MessageOf<D>>>;
}

/**
 * Project an {@link Attestor} to its client-facing {@link AttestorDescriptor}.
 *
 * Drops `signer` and `attest`, so the result is safe to share with clients.
 */
export function descriptorOf<
  D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
  S,
>(attestor: Attestor<D, PK, S>): AttestorDescriptor<D, PK> {
  return {
    id: attestor.id,
    definition: attestor.definition,
    publicKey: attestor.publicKey,
  };
}

/**
 * Build an {@link Attestor} from its parts.
 *
 * `publicKey` and `signer` come from one {@link KeyPair}; the kind supplies
 * `attest`, which the instance calls with its own definition and signer.
 *
 * @example
 * ```ts
 * const attestor = buildAttestor({
 *   id: 'my-kind-operator-1',
 *   definition: law,
 *   keyPair, // from the kind's key package
 *   attest: async (definition, signer, input) => {
 *     const parsed = {
 *       policy: definition.policy.parse(input.policy),
 *       evidence: definition.evidence.parse(input.evidence),
 *       claim: definition.claim.parse(input.claim),
 *     };
 *     await definition.verify(parsed);
 *     const message = definition.message(parsed.claim);
 *     const signature = await signer.sign(message);
 *     return { claim: parsed.claim, message, publicKey: keyPair.publicKey, signature };
 *   },
 * });
 * ```
 */
export function buildAttestor<
  const D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
  S,
>(parts: {
  id: string;
  definition: D;
  keyPair: KeyPair<PK, S, MessageOf<D>>;
  /** The kind's {@link Attestor.attest}, given the instance's definition and signer. */
  attest: (
    definition: D,
    signer: AttestorSigner<S, MessageOf<D>>,
    input: AttestationInput<z.input<D['policy']>, z.input<D['evidence']>, z.input<D['claim']>>,
  ) => Promise<Attestation<z.output<D['claim']>, PK, S, MessageOf<D>>>;
}): Attestor<D, PK, S> {
  const { id, definition, keyPair, attest } = parts;
  return {
    id,
    definition,
    signer: keyPair.signer,
    publicKey: keyPair.publicKey,
    attest: (input) => attest(definition, keyPair.signer, input),
  };
}
