// The `thoth.config.ts` shape: one kind, one policy, the attestors and the
// contract settings `thoth generate` derives everything else from.
import type { JubjubPoint } from '@midnight-ntwrk/compact-runtime';
import type { AttestorDefinition } from '@thoth/core';
import type { KindAttestor, KindManifest } from '@thoth/core/kind';
import { z } from 'zod';

/** A kind manifest of any kind: the CLI drives every kind through this shape. */
export type AnyKindManifest = KindManifest<
  unknown,
  AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  unknown,
  unknown,
  unknown,
  KindAttestor,
  unknown,
  unknown
>;

/** One pinned attestor. Its position in `attestors` is its registry slot. */
export interface ConfigAttestor {
  /** The id the attestor serves under, as in its descriptor. */
  readonly id: string;
  readonly publicKey: JubjubPoint;
}

/** The app contract's settings. */
export interface ContractConfig {
  /**
   * The app's top-level Compact file, relative to the config. It includes the
   * generated file; `thoth generate` checks its names against the generated
   * ones, and `thoth compile` compiles it.
   */
  readonly source: string;
  /**
   * The directory that holds `attestation.compact` and
   * `attestor_registry.compact`, relative to the config. `thoth compile` sets
   * `COMPACT_PATH` to it.
   */
  readonly modules: string;
  /** Seconds after a claim's `windowEnd` that it stays submittable. */
  readonly freshnessWindow: number;
  /** The longest observation window the contract accepts, in seconds. */
  readonly maxWindow: number;
}

/** Where `thoth generate` and `thoth compile` write, each relative to the config. */
export interface OutConfig {
  /** The directory for the generated Compact file, `thoth.compact`. */
  readonly compact: string;
  /** The directory for the generated TypeScript, `thoth.ts` and `thoth.check.ts`. */
  readonly ts: string;
  /** The directory `thoth compile` writes the compiled contract to. */
  readonly artifacts: string;
}

/** A `thoth.config.ts`, typed by its kind manifest. */
export interface ThothConfig<M extends AnyKindManifest = AnyKindManifest> {
  /** The kind manifest, from the kind's `./thoth` entry. */
  readonly kind: M;
  /** The one policy the contract accepts, in the kind's policy format. */
  readonly policy: z.input<M['policySchema']>;
  /** The app id the contract seals: 32 bytes as 64 hex digits, with or without `0x`. */
  readonly appId: string;
  /** How many attestors must sign a claim: the module's `#N`. */
  readonly threshold: number;
  /** The pinned attestors in registry slot order: the module's `#M` is their count. */
  readonly attestors: readonly ConfigAttestor[];
  readonly contract: ContractConfig;
  readonly out: OutConfig;
}

/**
 * Declare a `thoth.config.ts`. It returns `config` unchanged and types the
 * policy by the kind.
 *
 * @example
 * ```ts
 * import { defineConfig } from '@thoth/cli';
 * import { zkTls } from '@thoth/zk-tls/thoth';
 *
 * export default defineConfig({
 *   kind: zkTls,
 *   policy: { allowedHosts: ['www.strava.com'], slots: [...], ... },
 *   appId: 'a1'.repeat(32),
 *   threshold: 2,
 *   attestors: [
 *     { id: 'attestor-a', publicKey: { x: 0x12n, y: 0x34n } }, // registry slot 0
 *     ...
 *   ],
 *   contract: {
 *     source: 'contract/app.compact',
 *     modules: '../thoth/packages/contracts',
 *     freshnessWindow: 86400,
 *     maxWindow: 300,
 *   },
 *   out: { compact: 'contract/generated', ts: 'src/generated', artifacts: 'artifacts/app' },
 * });
 * ```
 */
export function defineConfig<M extends AnyKindManifest>(config: ThothConfig<M>): ThothConfig<M> {
  return config;
}

const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const path = z.string().min(1);
const seconds = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const fn = z.custom<(...args: never[]) => unknown>((value) => typeof value === 'function');

const configSchema = z.object({
  kind: z.looseObject({
    law: z.string().min(1),
    clientEntry: z.object({
      module: z.string().min(1),
      export: z.string().regex(IDENTIFIER, 'must be a JavaScript identifier'),
    }),
    // Duck-typed: the kind may bring its own copy of zod.
    policySchema: z.custom<z.ZodType>(
      (value) => typeof (value as { parse?: unknown } | null)?.parse === 'function',
      'must be a zod schema',
    ),
    policyHashOf: fn,
    layoutOf: fn,
    definition: fn,
    client: fn,
  }),
  policy: z.unknown(),
  appId: z.string().regex(/^(0x)?[0-9a-fA-F]{64}$/, 'must be 32 bytes as 64 hex digits'),
  threshold: z.number(),
  attestors: z.array(
    z.object({
      id: z.string().min(1),
      publicKey: z.object({ x: z.bigint(), y: z.bigint() }),
    }),
  ),
  contract: z.object({ source: path, modules: path, freshnessWindow: seconds, maxWindow: seconds }),
  out: z.object({ compact: path, ts: path, artifacts: path }),
});

/**
 * Check a loaded config's shape, and that its attestors have distinct ids and
 * keys.
 *
 * @throws `Error` listing every field that fails, or naming the repeated
 *   attestor.
 */
export function checkConfig(value: unknown): ThothConfig {
  const parsed = configSchema.safeParse(value);
  if (!parsed.success) {
    throw new Error(`thoth.config.ts is invalid:\n${z.prettifyError(parsed.error)}`);
  }
  const config = value as ThothConfig;
  const ids = new Set<string>();
  const keys = new Set<string>();
  for (const [slot, { id, publicKey }] of config.attestors.entries()) {
    if (ids.has(id)) {
      throw new Error(`attestor ${slot}: id '${id}' is used twice`);
    }
    const key = `${publicKey.x}:${publicKey.y}`;
    if (keys.has(key)) {
      throw new Error(`attestor ${slot} ('${id}'): its public key is pinned twice`);
    }
    ids.add(id);
    keys.add(key);
  }
  return config;
}
