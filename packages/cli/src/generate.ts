// `thoth generate`: derives the module parameters and the slot accessors from
// the config and its kind manifest, then writes the Compact and TypeScript files.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import type { KindClient } from '@thoth/core/kind';
import { checkConfig, type ThothConfig } from './config.js';
import { emitCompact } from './emit-compact.js';
import { emitCheck, emitClient } from './emit-ts.js';
import { configFingerprint } from './fingerprint.js';
import { writeGenerated } from './generated-file.js';
import { accessorsOf, checkNames } from './names.js';
import { moduleParameters } from './parameters.js';

/** A config, checked, and the path it was loaded from. */
export interface LoadedConfig {
  readonly config: ThothConfig;
  /** Absolute. */
  readonly path: string;
}

/**
 * Import a `thoth.config.ts` and check its shape.
 *
 * @throws `Error` if the file is missing, fails to load, has no default
 *   export, or fails {@link checkConfig}.
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

const hexBytes = (hex: string): Uint8Array =>
  Uint8Array.from(Buffer.from(hex.replace(/^0x/, ''), 'hex'));

// A relative ES module specifier: forward slashes, a leading ./, and .js for .ts.
const importSpecifier = (from: string, to: string): string => {
  const path = relative(from, to).split(sep).join('/').replace(/\.ts$/, '.js');
  return path.startsWith('.') ? path : `./${path}`;
};

// Generated client code imports the kind from its client entry, so check now
// that the entry loads and is the same kind.
const checkClientEntry = async (config: ThothConfig): Promise<void> => {
  const { module, export: name } = config.kind.clientEntry;
  let loaded: Record<string, unknown>;
  try {
    loaded = (await import(module)) as Record<string, unknown>;
  } catch (error) {
    throw new Error(`the kind's client entry ${module} does not load`, { cause: error });
  }
  const client = loaded[name] as Partial<KindClient<never, never, never>> | undefined;
  if (client?.law !== config.kind.law || typeof client.client !== 'function') {
    throw new Error(`${module} does not export the ${config.kind.law} client as ${name}`);
  }
};

/**
 * Write the generated files for the config at `configPath`, after checking
 * the config, the names and the files already there.
 *
 * @returns the absolute paths written.
 * @throws `Error` if the config is invalid, the policy fails the kind's schema
 *   or layout or does not survive a JSON round trip, the kind's client entry
 *   does not load, a generated name clashes, or a file to overwrite was edited
 *   or not generated.
 */
export async function generate(configPath: string): Promise<string[]> {
  const { config, path } = await loadConfig(configPath);
  const root = dirname(path);
  const { kind } = config;
  const policy = kind.policySchema.parse(config.policy);
  if (!isDeepStrictEqual(JSON.parse(JSON.stringify(policy)), policy)) {
    throw new Error('the policy does not survive a JSON round trip, so it cannot be generated');
  }
  const layout = kind.layoutOf(policy);
  const parameters = moduleParameters(layout, config.attestors.length, config.threshold);
  await checkClientEntry(config);

  const source = resolve(root, config.contract.source);
  checkNames(layout, existsSync(source) ? readFileSync(source, 'utf8') : '');

  const appId = hexBytes(config.appId);
  const policyHash = kind.policyHashOf(policy);
  const tsDir = resolve(root, config.out.ts);
  const files = [
    {
      path: resolve(root, config.out.compact, 'thoth.compact'),
      body: emitCompact({
        law: kind.law,
        parameters,
        appId,
        freshnessWindow: config.contract.freshnessWindow,
        maxWindow: config.contract.maxWindow,
        accessors: accessorsOf(layout),
      }),
    },
    {
      path: join(tsDir, 'thoth.ts'),
      body: emitClient({
        law: kind.law,
        clientEntry: kind.clientEntry,
        parameters,
        layout,
        policy,
        policyHash,
        appId,
        attestors: config.attestors,
      }),
    },
    {
      path: join(tsDir, 'thoth.check.ts'),
      body: emitCheck({
        configImport: importSpecifier(tsDir, path),
        fingerprint: configFingerprint(config),
      }),
    },
  ];
  writeGenerated(files);
  return files.map((file) => file.path);
}
