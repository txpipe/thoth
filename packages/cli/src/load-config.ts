// Loads a `thoth.config.ts` and checks its shape before any command uses it.
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { z } from 'zod';
import type { ThothConfig } from './config.js';

const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const path = z.string().min(1);
const seconds = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const aFunction = z.custom<(...args: never[]) => unknown>((value) => typeof value === 'function');

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
    policyHashOf: aFunction,
    layoutOf: aFunction,
    definition: aFunction,
    client: aFunction,
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

/** A checked config and the absolute path it was loaded from. */
export interface LoadedConfig {
  readonly config: ThothConfig;
  readonly path: string;
}

/**
 * Import a `thoth.config.ts` and check it with {@link checkConfig}.
 *
 * @throws `Error` if the file is missing, has no default export, or fails
 *   {@link checkConfig}; whatever importing the file throws.
 */
export async function loadConfig(path: string): Promise<LoadedConfig> {
  const absolute = resolve(path);
  if (!existsSync(absolute)) {
    throw new Error(`no config at ${absolute}`);
  }
  const module = (await import(pathToFileURL(absolute).href)) as { default?: unknown };
  if (module.default === undefined) {
    throw new Error(`${absolute} has no default export; export defineConfig({ ... })`);
  }
  return { config: checkConfig(module.default), path: absolute };
}
