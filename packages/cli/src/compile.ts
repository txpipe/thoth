// `thoth compile`: the pinned Compact compiler on the app contract, with
// COMPACT_PATH set so the generated file's bare module imports resolve.
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { loadConfig } from './generate.js';

/** The Compact compiler version Thoth's modules are checked against. */
export const COMPACT_VERSION = '0.36.1';

/**
 * Compile the config's `contract.source` into `out.artifacts`.
 *
 * @param flags - passed to `compact compile` as they are, such as `--skip-zk`.
 * @returns the compiler's exit status.
 * @throws `Error` if the config does not load, or the `compact` CLI cannot be
 *   started.
 */
export async function compile(configPath: string, flags: readonly string[]): Promise<number> {
  const { config, path } = await loadConfig(configPath);
  const root = dirname(path);
  const run = spawnSync(
    'compact',
    [
      'compile',
      `+${COMPACT_VERSION}`,
      ...flags,
      resolve(root, config.contract.source),
      resolve(root, config.out.artifacts),
    ],
    {
      stdio: 'inherit',
      env: { ...process.env, COMPACT_PATH: resolve(root, config.contract.modules) },
    },
  );
  if (run.error !== undefined) {
    throw new Error(`could not run the compact CLI; install it with compiler ${COMPACT_VERSION}`, {
      cause: run.error,
    });
  }
  return run.status ?? 1;
}
