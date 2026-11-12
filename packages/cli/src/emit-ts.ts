// The generated TypeScript: `thoth.ts`, the client-only entry a dApp bundles,
// and `thoth.check.ts`, which refuses a config that changed since `generate`.
import type { KindClientEntry, KindLayout } from '@thoth/core/kind';
import type { ConfigAttestor } from './config.js';
import type { ModuleParameters } from './parameters.js';

/** What `thoth.ts` is built from. */
export interface ClientInput {
  readonly law: string;
  readonly clientEntry: KindClientEntry;
  readonly parameters: ModuleParameters;
  readonly layout: KindLayout;
  /** The parsed policy; it survives a JSON round trip. */
  readonly policy: unknown;
  /** 32 bytes. */
  readonly policyHash: Uint8Array;
  /** 32 bytes. */
  readonly appId: Uint8Array;
  readonly attestors: readonly ConfigAttestor[];
}

const bytes = (value: Uint8Array): string => `new Uint8Array([${[...value].join(', ')}])`;

/** The body of `thoth.ts`, without the generated-file header. */
export function emitClient(input: ClientInput): string {
  const { V, W, B, K, N, M } = input.parameters;
  const slots = input.layout.names
    .map(
      (slot) =>
        `  ${slot.name}: { region: '${slot.region}', index: ${slot.index}, optional: ${slot.optional} },`,
    )
    .join('\n');
  const attestors = input.attestors
    .map(
      ({ id, publicKey }, slot) =>
        `  { id: ${JSON.stringify(id)}, publicKey: { x: ${publicKey.x}n, y: ${publicKey.y}n } }, // registry slot ${slot}`,
    )
    .join('\n');
  return `// The client-only entry for the ${input.law} embedding: the client, the trusted set
// and the Compact witness functions. It loads no attestor or offline evidence code.
import type { JubjubPoint, JubjubSchnorrSignature } from '@midnight-ntwrk/compact-runtime';
import { buildTrustedSet, type CollectedAttestation } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';
import { type Claim, type ContractClaim, toContractClaim } from '@thoth/core/claim';
import { ${input.clientEntry.export} as kind } from ${JSON.stringify(input.clientEntry.module)};

type KindClientConfig = Parameters<typeof kind.client>[0];

/** What \`createClient\` takes: the kind's client config without the fields generated here. */
export type ClientParts = Omit<
  KindClientConfig,
  'trusted' | 'verifier' | 'policy' | 'appId' | 'valueSlots' | 'byteSlots'
>;

/** The contract's module parameters. */
export const LAYOUT = {
  /** \`#V\`. */
  valueSlots: ${V},
  /** Byte values; \`#B\` is twice this. */
  byteSlots: ${W},
  /** \`#B\`. */
  byteHalves: ${B},
  /** \`#K\`. */
  messageFields: ${K},
  /** \`#N\`. */
  threshold: ${N},
  /** \`#M\`. */
  registrySize: ${M},
} as const;

/** Each policy slot's region and index in the claim, by name. */
export const SLOTS = {
${slots}
} as const;

/** The policy every attestor enforces. */
export const POLICY: KindClientConfig['policy'] = ${JSON.stringify(input.policy, null, 2)};

/** The policy's hash, the one the contract seals. */
export const POLICY_HASH: Uint8Array = ${bytes(input.policyHash)};

/** The app id the contract seals. */
export const APP_ID: Uint8Array = ${bytes(input.appId)};

/** The pinned attestors, in registry slot order. */
export const ATTESTORS: readonly { readonly id: string; readonly publicKey: JubjubPoint }[] = [
${attestors}
];

/** The trusted set: each attestor at its registry slot. */
export const trustedSet = buildTrustedSet({
  registrySize: LAYOUT.registrySize,
  attestors: ATTESTORS.map(({ id, publicKey }, registryIndex) => ({
    attestor: { id, definition: kind.definition(), publicKey },
    registryIndex,
  })),
});

/**
 * The kind's client, set up with this contract's policy, app id, slot counts
 * and trusted set.
 *
 * @throws whatever the kind's client throws for \`parts\`.
 */
export const createClient = (parts: ClientParts) =>
  kind.client({
    ...parts,
    trusted: trustedSet,
    verifier: jubjubVerifier,
    policy: POLICY,
    appId: APP_ID,
    valueSlots: LAYOUT.valueSlots,
    byteSlots: LAYOUT.byteSlots,
  });

/** The private state the generated witnesses read. */
export interface ThothPrivateState {
  readonly claim: ContractClaim | null;
  /** One per registry slot: \`signatures[i]\` is checked against registry key \`i\`. */
  readonly signatures: JubjubSchnorrSignature[];
  /** The randomness the claim's vault id commits with. */
  readonly commitRand: Uint8Array;
  /** The secret behind the claim's holder commitment. */
  readonly holderSecret: Uint8Array;
}

/** The collected signatures for one claim, as a kind's client returns them. */
export interface CollectedAttestment {
  readonly claim: Claim<number, number>;
  readonly collected: readonly CollectedAttestation<unknown, JubjubPoint, JubjubSchnorrSignature>[];
}

/** Fills a registry slot no attestor answered for. It never verifies. */
export const EMPTY_SIGNATURE: JubjubSchnorrSignature = {
  announcement: { x: 0n, y: 1n },
  response: 0n,
};

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, i) => byte === b[i]);

/**
 * The private state that submits \`attestment\`: its claim in the contract's
 * shape and each signature at its attestor's registry slot.
 *
 * @param holderSecret - the secret behind the claim's holder commitment.
 * @param commitRand - 32 random bytes the claim's vault id commits with.
 * @throws \`Error\` if the claim is for another app, policy or layout, a registry
 *   slot is out of range or answered twice, or fewer than \`LAYOUT.threshold\`
 *   attestors signed.
 */
export function privateStateOf(
  attestment: CollectedAttestment,
  holderSecret: Uint8Array,
  commitRand: Uint8Array,
): ThothPrivateState {
  const { claim, collected } = attestment;
  if (!sameBytes(claim.appId, APP_ID)) {
    throw new Error('the claim is for another app id');
  }
  if (!sameBytes(claim.policyHash, POLICY_HASH)) {
    throw new Error('the claim is for another policy');
  }
  if (claim.values.length !== LAYOUT.valueSlots || claim.byteValues.length !== LAYOUT.byteSlots) {
    throw new Error(
      \`the claim has \${claim.values.length} numeric and \${claim.byteValues.length} byte values; \` +
        \`the contract takes \${LAYOUT.valueSlots} and \${LAYOUT.byteSlots}\`,
    );
  }
  if (collected.length < LAYOUT.threshold) {
    throw new Error(\`\${collected.length} attestors signed; the contract needs \${LAYOUT.threshold}\`);
  }
  const signatures = Array.from({ length: LAYOUT.registrySize }, () => EMPTY_SIGNATURE);
  const filled = new Set<number>();
  for (const { registryIndex, attestation } of collected) {
    if (!Number.isSafeInteger(registryIndex) || registryIndex < 0 || registryIndex >= LAYOUT.registrySize) {
      throw new Error(\`registry slot \${registryIndex} is outside 0..\${LAYOUT.registrySize - 1}\`);
    }
    if (filled.has(registryIndex)) {
      throw new Error(\`registry slot \${registryIndex} is answered twice\`);
    }
    filled.add(registryIndex);
    signatures[registryIndex] = attestation.signature;
  }
  return { claim: toContractClaim(claim), signatures, commitRand, holderSecret };
}

type WitnessContext<PS> = { readonly privateState: PS };

/** The Compact witness functions the generated contract declares. */
export const witnesses = {
  /** @throws \`Error\` if the private state holds no claim. */
  getAttestationWitness<PS extends ThothPrivateState>({
    privateState,
  }: WitnessContext<PS>): [PS, [ContractClaim, JubjubSchnorrSignature[], Uint8Array]] {
    if (privateState.claim === null) {
      throw new Error('getAttestationWitness: the private state holds no claim');
    }
    return [privateState, [privateState.claim, privateState.signatures, privateState.commitRand]];
  },
  getHolderSecret<PS extends ThothPrivateState>({
    privateState,
  }: WitnessContext<PS>): [PS, Uint8Array] {
    return [privateState, privateState.holderSecret];
  },
  /** The attestor keys, in registry slot order. */
  seedKeys<PS>({ privateState }: WitnessContext<PS>): [PS, JubjubPoint[]] {
    return [privateState, ATTESTORS.map(({ publicKey }) => publicKey)];
  },
  /** The accepted policy hashes. */
  seedPolicies<PS>({ privateState }: WitnessContext<PS>): [PS, Uint8Array[]] {
    return [privateState, [POLICY_HASH]];
  },
};
`;
}

/** What `thoth.check.ts` is built from. */
export interface CheckInput {
  /** The config's import specifier, relative to the generated file. */
  readonly configImport: string;
  /** `configFingerprint` of the config the files were generated from. */
  readonly fingerprint: string;
}

/** The body of `thoth.check.ts`, without the generated-file header. */
export function emitCheck(input: CheckInput): string {
  return `// Refuses a thoth.config.ts that changed since the last \`thoth generate\`. Import
// \`config\` from here in tooling and tests; a dApp's client imports ./thoth.js.
import { createHash } from 'node:crypto';
import loaded from ${JSON.stringify(input.configImport)};

const GENERATED_FROM = '${input.fingerprint}';

type Config = typeof loaded;

// Mirrors configFingerprint in @thoth/cli.
const fingerprintOf = (config: Config): string => {
  const policy = config.kind.policySchema.parse(config.policy);
  const layout = config.kind.layoutOf(policy);
  const json = JSON.stringify([
    config.kind.law,
    [config.kind.clientEntry.module, config.kind.clientEntry.export],
    Buffer.from(config.kind.policyHashOf(policy)).toString('hex'),
    [
      layout.valueSlots,
      layout.byteSlots,
      layout.names.map((slot) => [slot.name, slot.region, slot.index, slot.optional]),
    ],
    config.appId.toLowerCase().replace(/^0x/, ''),
    config.threshold,
    config.attestors.map(({ id, publicKey }) => [id, \`\${publicKey.x}\`, \`\${publicKey.y}\`]),
    [config.contract.freshnessWindow, config.contract.maxWindow],
  ]);
  return createHash('sha256').update(json).digest('hex');
};

/**
 * Check that \`candidate\` is the config the generated files came from.
 *
 * @throws \`Error\` if it changed since the last \`thoth generate\`.
 */
export function assertConfigCurrent(candidate: Config = loaded): void {
  if (fingerprintOf(candidate) !== GENERATED_FROM) {
    throw new Error(
      'thoth.config.ts changed since the last \`thoth generate\`; run it again before using the generated files',
    );
  }
}

assertConfigCurrent();

/** The config the generated files came from, checked when this module loads. */
export const config: Config = loaded;
`;
}
