// The proof server the benchmark proves on: one it starts in Docker, whose CPU time and memory it
// reads from the container's cgroup, or one already running at a URL, which it cannot measure.
import { execFile, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { promisify } from 'node:util';

const run = promisify(execFile);

/** The pinned proof server; the compiler `0.36.1` keys prove only on a `9.0.x` server. */
export const PROOF_SERVER_IMAGE = 'midnightntwrk/proof-server:9.0.0';

/** The server's resource use since it started, read from its container's cgroup. */
export type ServerUsage = { cpuSeconds: number; peakMemoryBytes: number };

/** A proof server the benchmark sends requests to. */
export type ProofServer = {
  url: string;
  /** True when the benchmark started this server, so it had parsed no proving key before. */
  started: boolean;
  /**
   * The server's CPU time and peak memory since it started, or `null` when the benchmark cannot
   * read them: it did not start the server, or the host does not expose the container's cgroup.
   *
   * @throws {Error} when the container's cgroup files disappear, as they do once it stops.
   */
  usage(): ServerUsage | null;
  stop(): Promise<void>;
};

/** How the benchmark runs Docker and where the proof server keeps its public parameters. */
export type DockerOptions = {
  /** The Docker command, split into words, such as `['docker']` or `['sudo', '-n', 'docker']`. */
  docker: readonly string[];
  /** A host directory or a named volume, mounted as the server's parameter cache. */
  params: string;
  /** The value of the `thoth-bench-run` label on this run's containers, if any. */
  run: string | null;
};

const RUN_LABEL = 'thoth-bench-run';

/**
 * Remove every container labelled with this run, synchronously, so it can run in an `exit`
 * handler. Errors are ignored: this is cleanup on the way out.
 */
export const removeRunContainers = ({ docker, run }: DockerOptions): void => {
  const [command, ...prefix] = docker;
  if (!command || run === null) {
    return;
  }
  const { stdout } = spawnSync(
    command,
    [...prefix, 'ps', '-aq', '--filter', `label=${RUN_LABEL}=${run}`],
    { encoding: 'utf8' },
  );
  const ids = (stdout ?? '').split('\n').filter(Boolean);
  if (ids.length > 0) {
    spawnSync(command, [...prefix, 'rm', '-f', ...ids], { stdio: 'ignore' });
  }
};

/** A server the benchmark did not start: it proves there, but cannot measure the server. */
export const externalProofServer = (url: string): ProofServer => ({
  url,
  started: false,
  usage: () => null,
  stop: async () => {},
});

const SIGNALS = ['SIGINT', 'SIGTERM'] as const;

/**
 * Remove the container if the run is interrupted. The container is detached, so a Ctrl-C would
 * otherwise leave a proof server running, holding up to a few gigabytes. On a signal the handler
 * removes it and raises the signal again, so the process ends as it would have. On `exit` it
 * removes it too: vitest's worker exits without a signal when the vitest process above it is
 * stopped. Removal is synchronous because neither path gets a chance to await.
 *
 * @returns a function that detaches the handlers.
 */
const removeOnInterrupt = (remove: () => void): (() => void) => {
  const onExit = () => {
    detach();
    remove();
  };
  const onSignal = (signal: NodeJS.Signals) => {
    onExit();
    process.kill(process.pid, signal);
  };
  const detach = () => {
    process.off('exit', onExit);
    for (const signal of SIGNALS) {
      process.off(signal, onSignal);
    }
  };
  process.on('exit', onExit);
  for (const signal of SIGNALS) {
    process.on(signal, onSignal);
  }
  return detach;
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const waitForHealth = async (url: string, timeoutMs: number): Promise<void> => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if ((await fetch(`${url}/health`)).ok) {
        return;
      }
    } catch {
      // Not listening yet.
    }
    await sleep(200);
  }
  throw new Error(`the proof server at ${url} did not become healthy in ${timeoutMs} ms`);
};

/**
 * The container's cgroup v2 directory on the host, or `null` when it is not readable here (cgroup
 * v1, or Docker running in a VM, as Docker Desktop does).
 */
const cgroupOf = (pid: number): string | null => {
  try {
    const line = readFileSync(`/proc/${pid}/cgroup`, 'utf8')
      .split('\n')
      .find((entry) => entry.startsWith('0::'));
    if (!line) {
      return null;
    }
    const dir = `/sys/fs/cgroup${line.slice(3)}`;
    readUsage(dir);
    return dir;
  } catch {
    return null;
  }
};

/**
 * @throws {Error} when the cgroup's `cpu.stat` or `memory.peak` cannot be read.
 */
const readUsage = (cgroup: string): ServerUsage => {
  const cpu = /^usage_usec (\d+)$/m.exec(readFileSync(`${cgroup}/cpu.stat`, 'utf8'));
  if (!cpu) {
    throw new Error(`${cgroup}/cpu.stat has no usage_usec`);
  }
  return {
    cpuSeconds: Number(cpu[1]) / 1e6,
    // `memory.peak` is the cgroup's high-water mark, so no proof's peak falls between samples.
    peakMemoryBytes: Number(readFileSync(`${cgroup}/memory.peak`, 'utf8').trim()),
  };
};

/**
 * Start a fresh proof server in Docker on a free local port, and wait until it answers.
 *
 * @param name — the container name; a container left over under it is replaced.
 * @throws {Error} when Docker fails or the server does not become healthy.
 */
export const startProofServer = async (
  name: string,
  { docker, params, run: runId }: DockerOptions,
): Promise<ProofServer> => {
  const [command, ...prefix] = docker;
  if (!command) {
    throw new Error('the Docker command is empty');
  }
  const dockerRun = (args: string[]) => run(command, [...prefix, ...args], { encoding: 'utf8' });
  await dockerRun(['rm', '-f', name]).catch(() => {});
  // Attached before `docker run`, so an interrupt while the container starts removes it too.
  const detach = removeOnInterrupt(() => {
    spawnSync(command, [...prefix, 'rm', '-f', name], { stdio: 'ignore' });
  });
  const stop = async () => {
    detach();
    await dockerRun(['rm', '-f', name]).catch(() => {});
  };
  try {
    await dockerRun([
      'run',
      '-d',
      '--rm',
      '--name',
      name,
      '-p',
      '127.0.0.1::6300',
      '-e',
      'MIDNIGHT_PP=/params',
      '-v',
      `${params}:/params`,
      ...(runId === null ? [] : ['--label', `${RUN_LABEL}=${runId}`]),
      PROOF_SERVER_IMAGE,
    ]);
    const { stdout: port } = await dockerRun(['port', name, '6300/tcp']);
    const address = port.split('\n').find((entry) => entry.startsWith('127.0.0.1:'));
    if (!address) {
      throw new Error(`docker port gave no local address for ${name}: ${port}`);
    }
    const url = `http://${address.trim()}`;
    await waitForHealth(url, 60_000);
    const { stdout: pid } = await dockerRun(['inspect', '-f', '{{.State.Pid}}', name]);
    const cgroup = cgroupOf(Number(pid.trim()));
    return {
      url,
      started: true,
      usage: () => (cgroup === null ? null : readUsage(cgroup)),
      stop,
    };
  } catch (error) {
    await stop();
    throw error;
  }
};
