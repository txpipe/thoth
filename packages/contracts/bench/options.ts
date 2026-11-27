// The proving benchmark's options, read and checked once from the environment, before it
// starts any proof server.
import { existsSync, readdirSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import type { DockerOptions } from './proof-server.js';

/** The variable through which the vitest process tells the worker which run it is. */
export const RUN_ENV = 'THOTH_BENCH_RUN';

// The compiler the keys come from; its `zkir-v3` reports each circuit's k and rows.
export const COMPILER_VERSION = '0.36.1';

/** How one benchmark run proves and where it writes its report. */
export type BenchOptions = {
  /** A running server to prove on, or `null` to start one per circuit in Docker. */
  externalUrl: string | null;
  docker: DockerOptions;
  /** Warm proofs per circuit, after the first. */
  warmRuns: number;
  /** The absolute path of the JSON report. */
  out: string;
  /** The `zkir-v3` binary that reports k and rows. */
  zkir: string;
};

/**
 * The `zkir-v3` of the pinned compiler. The Compact CLI installs each compiler under a directory
 * named for the host platform, so look for the one entry that has the binary.
 *
 * @throws {Error} when no entry under the compiler's directory holds a `zkir-v3`.
 */
const findZkir = (home: string): string => {
  const versions = join(home, '.compact', 'versions', COMPILER_VERSION);
  const found = (existsSync(versions) ? readdirSync(versions) : [])
    .map((entry) => join(versions, entry, 'zkir-v3'))
    .find((path) => existsSync(path));
  if (!found) {
    throw new Error(`no zkir-v3 for compiler ${COMPILER_VERSION} under ${versions}; set ZKIR_BIN`);
  }
  return found;
};

/** How the benchmark runs Docker, from `BENCH_DOCKER`, `BENCH_PARAMS` and `THOTH_BENCH_RUN`. */
export const dockerOptions = (
  env: Readonly<Record<string, string | undefined>>,
): DockerOptions => ({
  docker: (env.BENCH_DOCKER ?? 'docker').split(/\s+/).filter(Boolean),
  // A named volume by default, so the server downloads its public parameters once.
  params: env.BENCH_PARAMS ?? 'thoth-bench-zk-params',
  run: env[RUN_ENV] ?? null,
});

const warmRuns = (value: string | undefined): number => {
  const runs = value === undefined ? 3 : Number(value);
  if (value?.trim() === '' || !Number.isInteger(runs) || runs < 1) {
    throw new Error(`BENCH_RUNS must be an integer of at least 1, got ${JSON.stringify(value)}`);
  }
  return runs;
};

/**
 * Read the benchmark's options from `env`.
 *
 * @param context.cwd — the process's directory; npm runs a workspace script from the workspace,
 *   so a relative `BENCH_OUT` resolves against `INIT_CWD`, where you ran npm, when it is set.
 * @throws {Error} when `BENCH_RUNS` is not an integer of at least 1, or no `zkir-v3` is found.
 */
export const benchOptions = (
  env: Readonly<Record<string, string | undefined>>,
  context: { cwd: string; home: string; defaultOut: string },
): BenchOptions => {
  const out = env.BENCH_OUT;
  return {
    externalUrl: env.PROOF_SERVER_URL ? env.PROOF_SERVER_URL.replace(/\/+$/, '') : null,
    docker: dockerOptions(env),
    warmRuns: warmRuns(env.BENCH_RUNS),
    out:
      out === undefined
        ? context.defaultOut
        : isAbsolute(out)
          ? out
          : resolve(env.INIT_CWD ?? context.cwd, out),
    zkir: env.ZKIR_BIN ?? findZkir(context.home),
  };
};
