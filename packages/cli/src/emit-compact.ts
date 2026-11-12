// The generated Compact file the app's contract `include`s: the module imports,
// `thothInit`, the exported entry points and the named slot accessors.
import { ATTESTATION_PREFIX, REGISTRY_PREFIX, type SlotAccessors } from './names.js';
import type { ModuleParameters } from './parameters.js';

/** What the Compact file is built from. */
export interface CompactInput {
  readonly law: string;
  readonly parameters: ModuleParameters;
  /** 32 bytes. */
  readonly appId: Uint8Array;
  readonly freshnessWindow: number;
  readonly maxWindow: number;
  readonly accessors: readonly SlotAccessors[];
}

const A = ATTESTATION_PREFIX;
const R = REGISTRY_PREFIX;

const numericAccessors = ({ slot, value, present }: SlotAccessors): string => {
  const i = slot.index;
  return `// Slot '${slot.name}': numeric value ${i}${slot.optional ? ', optional' : ''}.
pure circuit ${present}(c: ${A}Claim): Boolean {
  return c.present[${i}];
}

pure circuit ${value}(c: ${A}Claim): Uint<64> {
  assert(c.present[${i}], "${slot.name} not measured");
  return c.values[${i}];
}`;
};

// A byte value is two adjacent 16-byte halves; an honest claim flags both.
const byteAccessors = ({ slot, value, present }: SlotAccessors): string => {
  const low = 2 * slot.index;
  const high = low + 1;
  return `// Slot '${slot.name}': byte value ${slot.index}, halves ${low} and ${high}${slot.optional ? ', optional' : ''}.
pure circuit ${present}(c: ${A}Claim): Boolean {
  return c.bytePresent[${low}] && c.bytePresent[${high}];
}

pure circuit ${value}(c: ${A}Claim): Bytes<32> {
  assert(${present}(c), "${slot.name} not measured");
  return Bytes[...c.byteHalves[${low}], ...c.byteHalves[${high}]];
}`;
};

/** The body of `thoth.compact`, without the generated-file header. */
export function emitCompact(input: CompactInput): string {
  const { V, W, B, K, N, M } = input.parameters;
  const accessors = input.accessors.map((accessor) =>
    accessor.slot.region === 'numeric' ? numericAccessors(accessor) : byteAccessors(accessor),
  );
  return `// Kind ${input.law}: V=${V}, W=${W}, B=${B}, K=${K}, ${N}-of-${M}.
// Include it at the top of your contract and call thothInit() from your constructor.
pragma language_version >= 0.22;

import CompactStandardLibrary;

// Bare module names: imports in an included file resolve from the including
// file's directory, so \`thoth compile\` finds the modules through COMPACT_PATH.
//       K=${K} msg fields  V=${V} values  B=${B} byte halves  N=${N} threshold  M=${M} signatures
import "attestation"<${K}, ${V}, ${B}, ${N}, ${M}> prefix ${A};

import "attestor_registry"<${M}, ${K}> prefix ${R};

export { ${A}Claim, ${A}ClaimEntry };

export { ${A}appId, ${A}freshnessWindow, ${A}maxWindow, ${A}policyHashes, ${A}claimsVault, ${A}nullifiers };

// The accepted policy hashes. A witness, not a literal, so the accepted set
// can change without changing this file's shape.
witness seedPolicies(): Vector<1, Bytes<32>>;

// Seals the app id, the windows, the policy hash and the registry keys. Call it
// once, from your constructor: Compact allows a constructor only at the top level.
circuit thothInit(): [] {
  ${A}appId = disclose(Bytes[${[...input.appId].join(', ')}]);
  ${A}freshnessWindow = disclose(${input.freshnessWindow});
  ${A}maxWindow = disclose(${input.maxWindow});
  for (const h of seedPolicies()) {
    ${A}policyHashes.insert(disclose(h));
  }
  ${R}initRegistry();
}

// Verify an attested claim and store it in the claims vault.
export circuit verifyAttestation(): [] {
  ${A}verifyAttestation();
}

// The signed message, so off-chain code can reproduce it.
export pure circuit message(c: ${A}Claim): Vector<${K}, Field> {
  return ${A}buildMessage(c);
}

// The vault id \`verifyAttestation\` stores a claim under; pass it to ${A}openClaim.
export pure circuit claimId(c: ${A}Claim, rand: Bytes<32>): Bytes<32> {
  return ${A}computeId(c, rand);
}

// Named slot accessors. \`<name>Of\` asserts the slot was measured; check an
// optional slot's \`<name>Present\` flag first.
${accessors.join('\n\n')}
`;
}
