// `thoth compile`: the pinned Compact compiler on the app contract, with
// COMPACT_PATH set so the generated file's bare module imports resolve.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { delimiter, dirname, resolve } from 'node:path';
import { FINGERPRINT_LINE } from './emit-compact.js';
import { configFingerprint } from './fingerprint.js';
import { checkGenerated } from './generated-file.js';
import { loadConfig } from './load-config.js';

// The compiler Thoth's modules are checked against. Bump it with the other pins
// AGENTS.md lists.
const COMPACT_VERSION = '0.36.1';

/**
 * Compile the config's `contract.source` into `out.artifacts`, after checking
 * that the generated Compact file is unedited and matches the config.
 *
 * @param flags - passed to `compact compile` as they are, such as `--skip-zk`.
 * @returns the compiler's exit status.
 * @throws `Error` if the config does not load, the generated Compact file is
 *   missing, edited, or from a config that changed since, or the `compact` CLI
 *   cannot be started.
 */
export async function compile(configPath: string, flags: readonly string[]): Promise<number> {
  const { config, path } = await loadConfig(configPath);
  const root = dirname(path);
  const generated = resolve(root, config.out.compact, 'thoth.compact');
  if (!checkGenerated(generated)) {
    throw new Error(`${generated} does not exist; run thoth generate first`);
  }
  const recorded = FINGERPRINT_LINE.exec(readFileSync(generated, 'utf8'))?.[1];
  if (recorded !== configFingerprint(config)) {
    throw new Error(
      'thoth.config.ts changed since the last `thoth generate`; run it again before compiling',
    );
  }
  // The modules come first; a COMPACT_PATH you set still resolves your own imports.
  const compactPath = [resolve(root, config.contract.modules), process.env.COMPACT_PATH]
    .filter((entry) => entry !== undefined && entry !== '')
    .join(delimiter);
  const run = spawnSync(
    'compact',
    [
      'compile',
      `+${COMPACT_VERSION}`,
      ...flags,
      resolve(root, config.contract.source),
      resolve(root, config.out.artifacts),
    ],
    { stdio: 'inherit', env: { ...process.env, COMPACT_PATH: compactPath } },
  );
  if (run.error !== undefined) {
    throw new Error(`could not run the compact CLI; install it with compiler ${COMPACT_VERSION}`, {
      cause: run.error,
    });
  }
  return run.status ?? 1;
}
