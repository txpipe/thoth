// Runs scripts/start-witnesses.sh offline against a fake attestor-core clone whose
// re2 and witness server the test controls, to check the script's startup gates.
import { type ChildProcess, execFileSync, spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const script = fileURLToPath(new URL('../scripts/start-witnesses.sh', import.meta.url));

const FAKE_RE2 = `if (process.env.FAKE_RE2 === 'broken') throw new Error('fake re2 binding missing');
module.exports = RegExp;
`;

const FAKE_SERVER = `import { createServer } from 'node:http';
const mode = process.env.FAKE_WITNESS;
if (mode === 'crash') process.exit(1);
if (mode === 'regexp') console.log('{"msg":"Failed to load RE2; falling back to native RegExp"}');
const port = Number(process.env.PORT);
let answered = 0;
createServer((_, response) => {
  response.end(JSON.stringify({ address: '0xfake' + port }));
  // The script asks twice: once to see the witness is up, once for its address.
  if (mode === 'exit-later' && ++answered === 2) setTimeout(() => process.exit(1), 100);
}).listen(port);
`;

// A git hook, such as the pre-push test run, exports GIT_DIR and friends. They
// would point these git calls, and the script's, at this repository instead.
// The caller's global git config and npm cache stay out too.
const baseEnv: Record<string, string | undefined> = {
  ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('GIT_'))),
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
};

let root: string;
let cloneDir: string;
let ref: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'thoth-start-witnesses-'));
  baseEnv.npm_config_cache = join(root, 'npm-cache');
  cloneDir = join(root, 'attestor-core');
  mkdirSync(join(cloneDir, 'node_modules/re2'), { recursive: true });
  mkdirSync(join(cloneDir, 'src/scripts'), { recursive: true });
  writeFileSync(join(cloneDir, 'package.json'), '{ "type": "module" }\n');
  writeFileSync(join(cloneDir, 'node_modules/re2/package.json'), '{ "name": "re2" }\n');
  writeFileSync(join(cloneDir, 'node_modules/re2/index.js'), FAKE_RE2);
  writeFileSync(join(cloneDir, 'src/scripts/start-server.ts'), FAKE_SERVER);
  const git = (...args: string[]) =>
    execFileSync('git', ['-C', cloneDir, ...args], { encoding: 'utf8', env: baseEnv }).trim();
  git('init', '--quiet');
  git(
    ...['-c', 'user.name=test', '-c', 'user.email=test@example.com', '-c', 'commit.gpgsign=false'],
    ...['commit', '--allow-empty', '--no-verify', '--quiet', '-m', 'fake'],
  );
  ref = git('rev-parse', 'HEAD');
});

// A test that times out leaves its script running; stop it before the
// directory its witnesses run from is removed.
const running = new Set<ChildProcess>();

afterAll(() => {
  for (const child of running) child.kill('SIGTERM');
  rmSync(root, { recursive: true, force: true });
});

function listen(port = 0): Promise<Server> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(port, () => resolve(server));
  });
}

async function freePorts(): Promise<[number, number]> {
  const servers = [await listen(), await listen()];
  const ports = servers.map((server) => {
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('no port');
    return address.port;
  });
  await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
  return [ports[0] as number, ports[1] as number];
}

interface Run {
  code: number | null;
  output: string;
}

/** Runs the script; `stopOn` sends SIGTERM once the output contains it. */
function run(env: Record<string, string>, stopOn?: string): Promise<Run> {
  const logDir = mkdtempSync(join(root, 'run-'));
  return new Promise((resolve, reject) => {
    const child = spawn('bash', [script], {
      env: {
        ...baseEnv,
        WITNESS_CLONE_DIR: cloneDir,
        WITNESS_REF: ref,
        TMPDIR: logDir,
        ...env,
      },
    });
    let output = '';
    const onData = (chunk: Buffer) => {
      output += chunk.toString();
      if (stopOn !== undefined && output.includes(stopOn)) child.kill('SIGTERM');
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.once('error', reject);
    child.once('close', (code) => resolve({ code, output }));
    running.add(child);
    child.once('close', () => running.delete(child));
  });
}

describe.concurrent('start-witnesses.sh', { timeout: 30_000 }, () => {
  it('starts both witnesses and stops them on SIGTERM', async () => {
    const [a, b] = await freePorts();
    const ports = { WITNESS_PORT_A: String(a), WITNESS_PORT_B: String(b) };
    const { code, output } = await run({ ...ports, FAKE_WITNESS: 'serve' }, 'Ctrl-C stops');
    expect(output).toContain(`witness A public address: 0xfake${a}`);
    expect(output).toContain(`witness B public address: 0xfake${b}`);
    expect(code).toBe(143);
    const [serverA, serverB] = [await listen(a), await listen(b)];
    serverA.close();
    serverB.close();
  });

  it('refuses a port another process listens on', async () => {
    const [a, b] = await freePorts();
    const busy = await listen(a);
    try {
      const { code, output } = await run({ WITNESS_PORT_A: String(a), WITNESS_PORT_B: String(b) });
      expect(code).toBe(1);
      expect(output).toContain(`port ${a} is already in use`);
      expect(output).not.toContain('public address');
    } finally {
      busy.close();
    }
  });

  it('stops before starting the witnesses when re2 does not load', async () => {
    const [a, b] = await freePorts();
    const env = { WITNESS_PORT_A: String(a), WITNESS_PORT_B: String(b), FAKE_RE2: 'broken' };
    const { code, output } = await run(env);
    expect(code).toBe(1);
    expect(output).toContain('building re2');
    expect(output).toContain('re2 does not load');
    expect(output).toContain('fake re2 binding missing');
    expect(output).not.toContain('public address');
  });

  it('fails when a witness logs the RegExp fallback', async () => {
    const [a, b] = await freePorts();
    const env = { WITNESS_PORT_A: String(a), WITNESS_PORT_B: String(b), FAKE_WITNESS: 'regexp' };
    const { code, output } = await run(env);
    expect(code).toBe(1);
    expect(output).toContain('fell back to RegExp');
    expect(output).not.toContain('public address');
  });

  it('fails when a witness exits before it answers', async () => {
    const [a, b] = await freePorts();
    const env = { WITNESS_PORT_A: String(a), WITNESS_PORT_B: String(b), FAKE_WITNESS: 'crash' };
    const { code, output } = await run(env);
    expect(code).toBe(1);
    expect(output).toContain('witness A failed to start');
  });

  it('fails when a witness exits after startup', async () => {
    const [a, b] = await freePorts();
    const env = {
      WITNESS_PORT_A: String(a),
      WITNESS_PORT_B: String(b),
      FAKE_WITNESS: 'exit-later',
    };
    const { code, output } = await run(env);
    expect(output).toContain('Ctrl-C stops');
    expect(output).toContain('a witness exited');
    expect(code).toBe(1);
  });
});
