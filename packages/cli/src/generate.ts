// `thoth generate`: derives the module parameters and the slot accessors from
// the config and its kind manifest, then writes the Compact and TypeScript files.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { emitCompact } from './emit-compact.js';
import { emitCheck, emitClient } from './emit-ts.js';
import { configFingerprint } from './fingerprint.js';
import { writeGenerated } from './generated-file.js';
import { loadConfig } from './load-config.js';
import { accessorsOf, checkNames } from './names.js';
import { moduleParameters } from './parameters.js';

const hexBytes = (hex: string): Uint8Array =>
  Uint8Array.from(Buffer.from(hex.replace(/^0x/, ''), 'hex'));

// A relative module specifier: forward slashes and a leading ./. It keeps the
// .ts extension, which Node 24 loads and TypeScript's rewriteRelativeImportExtensions maps.
const importSpecifier = (from: string, to: string): string => {
  const path = relative(from, to).split(sep).join('/');
  return path.startsWith('.') ? path : `./${path}`;
};

/**
 * Write the generated files for the config at `configPath`, after checking
 * the config, the names and the files already there.
 *
 * @returns the absolute paths written.
 * @throws `Error` if the config is invalid, the policy fails the kind's schema
 *   or layout or does not survive a JSON round trip, a generated name clashes,
 *   or a file to overwrite was edited or not generated.
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

  const source = resolve(root, config.contract.source);
  checkNames(layout, existsSync(source) ? readFileSync(source, 'utf8') : '');

  const appId = hexBytes(config.appId);
  const policyHash = kind.policyHashOf(policy);
  const tsDir = resolve(root, config.out.ts);
  const fingerprint = configFingerprint(config);
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
        fingerprint,
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
        fingerprint,
      }),
    },
  ];
  writeGenerated(files);
  return files.map((file) => file.path);
}
