// The names the generated Compact file declares, and the checks that keep them
// apart from each other and from the app contract that includes the file.
import type { KindLayout, LayoutSlot } from '@thoth/core/kind';

/** The import prefix of the attestation module in the generated file. */
export const ATTESTATION_PREFIX = 'Thoth_';
/** The import prefix of the attestor registry module in the generated file. */
export const REGISTRY_PREFIX = 'ThothRegistry_';

const PREFIXES = [ATTESTATION_PREFIX, REGISTRY_PREFIX] as const;

/**
 * The unprefixed names the generated file declares besides the accessors:
 * its own circuits and witness, and the modules' witnesses, which Compact
 * does not prefix.
 */
export const FIXED_NAMES = [
  'thothInit',
  'verifyAttestation',
  'message',
  'claimId',
  'seedPolicies',
  'getAttestationWitness',
  'getHolderSecret',
  'seedKeys',
] as const;

/** The two circuits the generated file declares for one slot. */
export interface SlotAccessors {
  readonly slot: LayoutSlot;
  /** Returns the slot's value and asserts it was measured. */
  readonly value: string;
  /** Returns whether the slot was measured. */
  readonly present: string;
}

/**
 * Name each slot's accessors. A slot name may be a Compact or TypeScript
 * keyword such as `type`, so it is used only as the stem of a name.
 */
export function accessorsOf(layout: KindLayout): SlotAccessors[] {
  return layout.names.map((slot) => ({
    slot,
    value: `${slot.name}Of`,
    present: `${slot.name}Present`,
  }));
}

/** A name a Compact source declares, or an import prefix it introduces. */
export interface CompactDeclaration {
  readonly kind: 'circuit' | 'witness' | 'ledger' | 'struct' | 'enum' | 'module' | 'prefix';
  readonly name: string;
}

// Comments and string literals, blanked out so a keyword inside them is not
// read as a declaration.
const COMMENT_OR_STRING = /\/\/[^\n]*|\/\*[\s\S]*?\*\/|"(?:[^"\\\n]|\\.)*"/g;
const DECLARATION =
  /\b(circuit|witness|ledger|struct|enum|module|prefix)\s+([A-Za-z_][A-Za-z0-9_]*)/g;

/**
 * List the names a Compact source declares and the import prefixes it uses,
 * in source order. It scans tokens rather than parsing, which is enough to
 * find a clash with the generated names.
 */
export function compactDeclarations(source: string): CompactDeclaration[] {
  const code = source.replace(COMMENT_OR_STRING, ' ');
  return [...code.matchAll(DECLARATION)].map((match) => ({
    kind: match[1] as CompactDeclaration['kind'],
    name: match[2] as string,
  }));
}

const prefixOf = (name: string): string | undefined =>
  PREFIXES.find((prefix) => name.startsWith(prefix));

/**
 * Check that the generated names are distinct, that no accessor lands inside
 * a generated module prefix, and that the app contract declares none of them.
 *
 * @param appSource - the app's own Compact source, without the generated file.
 * @throws `Error` naming the first clash.
 */
export function checkNames(layout: KindLayout, appSource: string): void {
  const generated = new Set<string>(FIXED_NAMES);
  for (const { slot, value, present } of accessorsOf(layout)) {
    for (const name of [value, present]) {
      const prefix = prefixOf(name);
      if (prefix !== undefined) {
        throw new Error(
          `slot '${slot.name}': accessor '${name}' is inside the generated module prefix ` +
            `'${prefix}'; rename the slot`,
        );
      }
      if (generated.has(name)) {
        throw new Error(
          `slot '${slot.name}': accessor '${name}' is declared twice; rename the slot`,
        );
      }
      generated.add(name);
    }
  }
  for (const { name } of compactDeclarations(appSource)) {
    const prefix = prefixOf(name);
    if (prefix !== undefined) {
      throw new Error(
        `the app contract declares '${name}', inside the generated module prefix '${prefix}'; ` +
          'rename it',
      );
    }
    if (generated.has(name)) {
      throw new Error(
        `the app contract declares '${name}', which thoth generate also declares; rename it`,
      );
    }
  }
}
