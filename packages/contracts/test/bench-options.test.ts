// The proving benchmark's options: how it reads its environment before it starts a proof server.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { benchOptions } from '../bench/options.js';

let home: string;

// A Compact install with compiler 0.36.1 for one platform, plus a stray file beside it.
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'thoth-bench-options-'));
  const versions = join(home, '.compact', 'versions', '0.36.1');
  mkdirSync(join(versions, 'x86_64-unknown-linux-musl'), { recursive: true });
  writeFileSync(join(versions, '.DS_Store'), '');
  writeFileSync(join(versions, 'x86_64-unknown-linux-musl', 'zkir-v3'), '');
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

const read = (env: Record<string, string | undefined>) =>
  benchOptions(env, { cwd: '/repo/packages/contracts', home, defaultOut: '/default/latest.json' });

describe('benchOptions', () => {
  it('starts its own Docker server with three warm proofs by default', () => {
    expect(read({})).toEqual({
      externalUrl: null,
      docker: { docker: ['docker'], params: 'thoth-bench-zk-params', run: null },
      warmRuns: 3,
      out: '/default/latest.json',
      zkir: join(home, '.compact', 'versions', '0.36.1', 'x86_64-unknown-linux-musl', 'zkir-v3'),
    });
  });

  it('splits the Docker command into words', () => {
    expect(read({ BENCH_DOCKER: 'sudo -n docker' }).docker.docker).toEqual([
      'sudo',
      '-n',
      'docker',
    ]);
  });

  it('drops a trailing slash from the proof server URL', () => {
    expect(read({ PROOF_SERVER_URL: 'http://127.0.0.1:6301/' }).externalUrl).toBe(
      'http://127.0.0.1:6301',
    );
  });

  it.each(['0', '', 'abc', '-1', '1.5'])('refuses BENCH_RUNS=%j', (runs) => {
    expect(() => read({ BENCH_RUNS: runs })).toThrow('BENCH_RUNS must be an integer of at least 1');
  });

  it('resolves a relative BENCH_OUT against the directory npm was run from', () => {
    expect(read({ BENCH_OUT: 'out/bench.json', INIT_CWD: '/repo' }).out).toBe(
      '/repo/out/bench.json',
    );
    expect(read({ BENCH_OUT: 'bench.json' }).out).toBe('/repo/packages/contracts/bench.json');
  });

  it('takes ZKIR_BIN as given', () => {
    expect(read({ ZKIR_BIN: '/opt/zkir-v3' }).zkir).toBe('/opt/zkir-v3');
  });

  it('refuses a Compact install without zkir-v3', () => {
    rmSync(join(home, '.compact', 'versions', '0.36.1', 'x86_64-unknown-linux-musl', 'zkir-v3'));
    expect(() => read({})).toThrow('no zkir-v3 for compiler 0.36.1');
  });
});
