// The object a kind exports from its `./thoth` subpath, so tooling such as the
// `thoth` CLI can drive the kind without knowing it.
import type { JubjubPoint, JubjubSchnorrSignature } from '@midnight-ntwrk/compact-runtime';
import type { z } from 'zod';
import type { FlatMessage } from './claim.js';
import type { AttestorDefinition } from './index.js';

/** Which part of the claim a slot lands in: `values` or `byteValues`. */
export type SlotRegion = 'numeric' | 'bytes';

/** One slot of a kind's policy, as {@link denseLayout} reads it. */
export interface PolicySlot {
  /** The policy's slot index: numeric slots `0..V-1`, then byte slots `V..V+W-1`. */
  readonly slot: number;
  /** The slot's name. Generated code names its accessors after it. */
  readonly name: string;
  readonly region: SlotRegion;
  /** Whether the attestor may sign the slot unpresent. */
  readonly optional: boolean;
}

/** One named slot of a {@link KindLayout}. */
export interface LayoutSlot {
  /** An ASCII identifier: a letter or `_`, then letters, digits or `_`. */
  readonly name: string;
  readonly region: SlotRegion;
  /** The index within its region: `values[index]`, or byte value `index`. */
  readonly index: number;
  /** Whether the attestor may sign the slot unpresent. */
  readonly optional: boolean;
}

/** The claim layout a policy implies. */
export interface KindLayout {
  /** The contract's `#V`. */
  readonly valueSlots: number;
  /** Half the contract's `#B`: each byte value takes two halves. */
  readonly byteSlots: number;
  /** Every slot of the policy, numeric slots first, each region by index. */
  readonly names: readonly LayoutSlot[];
}

// Generated code names accessors `<name>Of` and `<name>Present`; with this ASCII
// subset both are valid in Compact and TypeScript. A bare name may be a keyword.
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

const describeSlot = (slot: PolicySlot): string => `${slot.slot} (${quote(slot.name)})`;

const quote = (name: string): string => `'${name}'`;

/**
 * Derive the claim layout from a policy's slots.
 *
 * The layout must be dense: numeric slots `0..V-1`, then byte slots from `V`.
 * A gap would be a slot every claim still pays for in its message, and a slot
 * map with one could fit more than one layout.
 *
 * A name must be an ASCII identifier, so generated accessor names built from it
 * are valid. It may still be a keyword such as `type`, so generated code uses
 * it only as the stem of an accessor name.
 *
 * @throws `Error` naming the slot, if a slot index is not a non-negative
 *   integer or is used twice, a name is not an ASCII identifier or is used
 *   twice, a byte slot comes before a numeric slot, or an index is unused. A
 *   region or gap error says how to renumber the slots.
 */
export function denseLayout(slots: readonly PolicySlot[]): KindLayout {
  const byIndex = new Map<number, PolicySlot>();
  const byName = new Map<string, PolicySlot>();
  for (const slot of slots) {
    if (!Number.isSafeInteger(slot.slot) || slot.slot < 0) {
      throw new Error(`slot ${describeSlot(slot)} is not a non-negative integer`);
    }
    const sameIndex = byIndex.get(slot.slot);
    if (sameIndex !== undefined) {
      throw new Error(
        `slot ${slot.slot} is used by both ${quote(sameIndex.name)} and ${quote(slot.name)}`,
      );
    }
    byIndex.set(slot.slot, slot);
    if (!IDENTIFIER.test(slot.name)) {
      throw new Error(
        `slot ${slot.slot}: name ${JSON.stringify(slot.name)} is not an ASCII identifier ` +
          '(a letter or _, then letters, digits or _); generated code names its accessors after it',
      );
    }
    const sameName = byName.get(slot.name);
    if (sameName !== undefined) {
      throw new Error(
        `slot ${slot.slot}: name ${quote(slot.name)} is also used by slot ${sameName.slot}`,
      );
    }
    byName.set(slot.name, slot);
  }

  const byPosition = (a: PolicySlot, b: PolicySlot): number => a.slot - b.slot;
  const numeric = slots.filter((slot) => slot.region === 'numeric').sort(byPosition);
  const bytes = slots.filter((slot) => slot.region === 'bytes').sort(byPosition);
  const dense = [...numeric, ...bytes];
  const renumbering = dense
    .flatMap((slot, index) =>
      slot.slot === index ? [] : [`${quote(slot.name)} from ${slot.slot} to ${index}`],
    )
    .join(', ');

  const lastNumeric = numeric.at(-1);
  const firstByte = bytes[0];
  if (lastNumeric !== undefined && firstByte !== undefined && firstByte.slot < lastNumeric.slot) {
    throw new Error(
      `byte slot ${describeSlot(firstByte)} comes before numeric slot ${describeSlot(lastNumeric)}; ` +
        `renumber ${renumbering}`,
    );
  }
  const unused = dense.findIndex((slot, index) => slot.slot !== index);
  if (unused !== -1) {
    throw new Error(`slot ${unused} is unused; renumber ${renumbering}`);
  }

  return {
    valueSlots: numeric.length,
    byteSlots: bytes.length,
    names: dense.map((slot) => ({
      name: slot.name,
      region: slot.region,
      index: slot.region === 'numeric' ? slot.slot : slot.slot - numeric.length,
      optional: slot.optional,
    })),
  };
}

/**
 * A Jubjub Schnorr public key and the signer that holds its private key: the
 * scheme the contract's registry verifies.
 */
export interface JubjubKeyPair {
  readonly publicKey: JubjubPoint;
  readonly signer: {
    sign(message: FlatMessage): JubjubSchnorrSignature | Promise<JubjubSchnorrSignature>;
  };
}

/** What tooling gives every attestor it builds through a {@link KindManifest}. */
export interface KindAttestorKey {
  /** The attestor's id, the one dApps pin in their trusted set. */
  readonly id: string;
  readonly keyPair: JubjubKeyPair;
}

/** The part of an attestor instance that tooling reads. */
export interface KindAttestor {
  readonly id: string;
  readonly publicKey: JubjubPoint;
}

/** One operator of a kind's offline evidence source. */
export interface DevOperator<Anchors, Prover> {
  /** The kind's trust anchors for an attestor that accepts this operator's evidence. */
  readonly attestorConfig: Anchors;
  /** The evidence source a client uses for this operator. */
  readonly prover: Prover;
}

/**
 * The client side of a kind: what a dApp needs to build its client and pin
 * its attestors, without the kind's attestor side. A kind exports one from its
 * client entry and names it in its manifest's `clientEntry`.
 *
 * @typeParam D - the definition a dApp pins in each attestor's descriptor.
 * @typeParam ClientConfig - what `client` takes.
 * @typeParam Client - what `client` returns.
 */
export interface KindClient<
  D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  ClientConfig,
  Client,
> {
  /** The kind's versioned law tag, such as `zk-fetch@1`. */
  readonly law: string;
  /**
   * The definition a dApp pins in each attestor's descriptor. It comes from a
   * client-safe entry, so a dApp never loads the kind's attestor side.
   */
  definition(): D;
  /** @throws if the kind's client refuses `config`. */
  client(config: ClientConfig): Client;
}

/**
 * Where code generated for a dApp imports a kind's {@link KindClient} from.
 * The module loads only the kind's client side, so a browser bundle stays free
 * of attestor and offline evidence code.
 */
export interface KindClientEntry {
  /** A module specifier, such as `@thoth/zk-tls/client`. */
  readonly module: string;
  /** The name the module exports its {@link KindClient} under. */
  readonly export: string;
}

/** A command a kind adds to tooling, such as a `try` that runs a policy against its source. */
export interface KindCommand {
  /** One line for the command's help. */
  readonly describe: string;
  /** @throws to fail the command. */
  run(args: readonly string[]): Promise<void>;
}

/**
 * Describes a kind to tooling: its law, its policy, the claim layout a policy
 * implies, and how to build its client and its attestors. A kind exports one
 * from its `./thoth` subpath, built with {@link defineKind}, and exports its
 * client side alone from the module `clientEntry` names.
 *
 * Keys and signatures are Jubjub Schnorr, the scheme the contract's registry
 * verifies. It holds no key: tooling passes one to `attestor`.
 *
 * @typeParam P - the parsed policy.
 * @typeParam D - the definition a dApp pins in each attestor's descriptor.
 * @typeParam ClientConfig - what `client` takes.
 * @typeParam Client - what `client` returns.
 * @typeParam Anchors - the kind's per-operator trust anchors, such as a witness address.
 * @typeParam Attestor - what `attestor` returns.
 * @typeParam DevInput - what every offline operator observes.
 * @typeParam Prover - the evidence source a client uses for one operator.
 */
export interface KindManifest<
  P,
  D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  ClientConfig,
  Client,
  Anchors,
  Attestor extends KindAttestor,
  DevInput = never,
  Prover = never,
> extends KindClient<D, ClientConfig, Client> {
  /** Where generated client code imports this kind's {@link KindClient} from. */
  readonly clientEntry: KindClientEntry;
  readonly policySchema: z.ZodType<P>;
  /**
   * The hash the contract seals for `policy`: the claim's `policyHash`.
   *
   * @throws if `policy` fails `policySchema`.
   */
  policyHashOf(policy: P): Uint8Array;
  /**
   * The claim layout `policy` implies. Build it with {@link denseLayout}.
   *
   * @throws if `policy` fails `policySchema`, or its slots fail {@link denseLayout}.
   */
  layoutOf(policy: P): KindLayout;
  /** @throws if the kind's attestor refuses `config`. */
  attestor(config: KindAttestorKey & Anchors): Attestor;
  /**
   * An offline evidence source: `operators` operators that all observe
   * `input`, each with the trust anchors of an attestor that accepts its
   * evidence. Only for local development and tests.
   *
   * @throws if `policy` fails `policySchema`.
   */
  devEvidence?(
    policy: P,
    operators: number,
    input: DevInput,
  ): readonly DevOperator<Anchors, Prover>[];
  /** Commands the kind adds to tooling, by name. */
  readonly commands?: Readonly<Record<string, KindCommand>>;
}

/**
 * Declare the object a kind exports from its `./thoth` subpath. It returns
 * `manifest` unchanged and infers its types.
 *
 * @example
 * ```ts
 * import { defineKind, denseLayout, type KindAttestorKey } from '@thoth/core/kind';
 * import { myKindClient } from '../client/index.js'; // a KindClient
 *
 * export const myKind = defineKind({
 *   ...myKindClient, // law, definition and client
 *   clientEntry: { module: 'my-kind/client', export: 'myKindClient' },
 *   policySchema: myPolicySchema,
 *   policyHashOf: (policy: MyPolicy) => myPolicyHashOf(policy),
 *   layoutOf: (policy: MyPolicy) =>
 *     denseLayout(policy.slots.map((slot) => ({ ...slot, region: 'numeric', optional: false }))),
 *   attestor: (config: KindAttestorKey & { sourceKey: string }) => myAttestor(config),
 * });
 * ```
 */
export function defineKind<
  P,
  D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  ClientConfig,
  Client,
  Anchors,
  Attestor extends KindAttestor,
  DevInput = never,
  Prover = never,
>(
  manifest: KindManifest<P, D, ClientConfig, Client, Anchors, Attestor, DevInput, Prover>,
): KindManifest<P, D, ClientConfig, Client, Anchors, Attestor, DevInput, Prover> {
  return manifest;
}
