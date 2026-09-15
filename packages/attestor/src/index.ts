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
 * Keeps `kind` and the exact schema types as literals inferred from the object
 * literal, so a kind can be referenced by its precise type elsewhere.
 *
 * @param definition — an object literal satisfying {@link AttestorDefinition}.
 * @returns the same object, unchanged (identity function).
 */
export function defineAttestor<
  const D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
>(definition: D): D {
  return definition;
}

/**
 * The key-boundary type: a minimal contract for whoever holds the signing key.
 *
 * Implementations never share the key itself — it stays behind this interface
 * (e.g. captured in a closure). The message shape is fixed per scheme (`Msg`);
 * only the signature type `S` is scheme-agnostic.
 *
 * @typeParam S — the signature scheme type produced by `sign`.
 * @typeParam Msg — the signed-message type; defaults to {@link FlatMessage}.
 */
export interface AttestorSigner<S, Msg = FlatMessage> {
  /**
   * Sign a message with the held private key.
   *
   * @param message — the message to commit to (a kind's `message(claim)` output).
   * @returns the signature, or a promise resolving to it.
   */
  sign(message: Msg): S | Promise<S>;
}

/**
 * The key-material contract: the public key and its signing boundary together.
 *
 * A concrete crypto/key package implements this per signature scheme, pairing
 * the exposed `publicKey` with the `signer` that holds the matching private
 * key. Binding the two at construction makes it impossible to pair a signer
 * with a *different* public key; the DESIGN decision only caught such
 * mismatches at N-of-M verification time.
 *
 * @typeParam PK — the public-key type (scheme-specific).
 * @typeParam S — the signature scheme type produced by `signer.sign`.
 * @typeParam Msg — the signed-message type; defaults to {@link FlatMessage}.
 */
export interface KeyPair<PK, S, Msg = FlatMessage> {
  /** The public key derived from the same private key the signer holds. */
  readonly publicKey: PK;
  /** The key boundary that signs with the matching private key. */
  readonly signer: AttestorSigner<S, Msg>;
}

/**
 * A deployable, identifiable attestor instance: the kind's law (shareable
 * `definition`), the key boundary (`signer`), and the single public key under
 * which it attests.
 *
 * The public key is the value the client maps to a slot in the on-chain
 * attestor registry. `attest` is the module-owned lifecycle hook.
 *
 * @typeParam D — the attestor's definition type.
 * @typeParam PK — the public-key type.
 * @typeParam S — the signature scheme type.
 */
export interface Attestor<
  D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
  S,
> {
  /** Stable identifier for this deployable instance (non-cryptographic). */
  id: string;
  /** The kind's shareable law: schemas, `verify`, `message`. */
  definition: D;
  /** The key boundary — holds the private key; never exposes it. */
  signer: AttestorSigner<S, MessageOf<D>>;
  /** The public key under which this instance attests. */
  publicKey: PK;
  /**
   * Slot index of this attestor's public key in the on-chain registry's key
   * vector, and therefore the position at which its signature must be
   * submitted in the N-of-M signatures vector: `attestor_registry.compact`
   * verifies `signatures[i]` against `keys[i]` positionally, never by key
   * matching.
   */
  registryIndex: number;

  /**
   * Run the attestation lifecycle for this instance: parse the raw input with
   * the definition's schemas, authorize via `verify`, then sign the kind's
   * `message(claim)`.
   *
   * Module-owned: each kind's package implements this. Implementations must
   * call `verify` before `sign` and throw to reject.
   *
   * @param input — raw (unparsed) policy/evidence/claim values, per the
   *   definition's `z.input` schemas.
   * @returns the signed {@link Attestation} artifact.
   */
  attest(
    input: AttestationInput<z.input<D['policy']>, z.input<D['evidence']>, z.input<D['claim']>>,
  ): Promise<Attestation<D['kind'], z.output<D['claim']>, PK, S, MessageOf<D>>>;
}

/**
 * Project an {@link Attestor} to its client-facing {@link AttestorDescriptor}.
 *
 * Drops the key-bearing machinery (`signer`, `attest`) so the descriptor is
 * safe to share with clients.
 *
 * @param attestor — the attestor instance to project.
 * @returns the client-addressable descriptor for the same instance.
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
    registryIndex: attestor.registryIndex,
  };
}

/**
 * Build an {@link Attestor} from its parts.
 *
 * A consistency-preserving constructor: `publicKey` and `signer` are taken
 * from a single {@link KeyPair}, so the instance cannot pair a signer with a
 * mismatched public key. The `attest` lifecycle stays module-owned — each
 * kind's package supplies its own implementation, and the returned instance
 * merely ties it to the instance fields.
 *
 * @param parts — the id, shareable definition, key pair, registry slot, and
 *   the kind's `attest` lifecycle implementation.
 * @returns an `Attestor` whose `attest` delegates to the supplied lifecycle.
 */
export function buildAttestor<
  const D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
  S,
>(parts: {
  /** Stable identifier for this deployable instance. */
  id: string;
  /** The kind's shareable law: schemas, `verify`, `message`. */
  definition: D;
  /** The key material: public key plus the matching signing boundary. */
  keyPair: KeyPair<PK, S, MessageOf<D>>;
  /** Slot index of this attestor's key in the on-chain registry. */
  registryIndex: number;
  /**
   * The kind's lifecycle: parse `input` with `definition`'s schemas,
   * authorize via `verify`, then sign `definition.message(claim)`.
   */
  attest: (
    definition: D,
    signer: AttestorSigner<S, MessageOf<D>>,
    input: AttestationInput<z.input<D['policy']>, z.input<D['evidence']>, z.input<D['claim']>>,
  ) => Promise<Attestation<D['kind'], z.output<D['claim']>, PK, S, MessageOf<D>>>;
}): Attestor<D, PK, S> {
  const { id, definition, keyPair, registryIndex, attest } = parts;
  return {
    id,
    definition,
    signer: keyPair.signer,
    publicKey: keyPair.publicKey,
    registryIndex,
    attest: (input) => attest(definition, keyPair.signer, input),
  };
}
