// Plants a fake City API token where check.ts searches and checks that it fails, never
// shows the token and writes no fixture. It runs a copy of src/ under .state/test with a
// fake HOME, so the real token is never read; the evidence is the recorded fixture.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import {
  appendFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { after, beforeEach, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const SPIKE = fileURLToPath(new URL('..', import.meta.url));
const ROOT = join(SPIKE, '.state', 'test');
const COPY = join(ROOT, 'spike-ownership');
const HOME = join(ROOT, 'home');
const HERMES_DIR = join(HOME, '.hermes', 'skills', 'midnight-city-direct-control');
const STATE = join(COPY, '.state');
const FIXTURE = join(ROOT, 'fixtures', 'control-claimable.json');
const WITNESS_LOGS = [join(ROOT, 'witness-1.log'), join(ROOT, 'witness-2.log')] as const;
const RECORDED = readFileSync(
  new URL('../../fixtures/control-claimable.json', import.meta.url),
  'utf8',
);

const token = `mcity_${randomBytes(24).toString('base64url')}`;
const hex = Buffer.from(token).toString('hex');

beforeEach(() => {
  rmSync(ROOT, { recursive: true, force: true });
  cpSync(join(SPIKE, 'src'), join(COPY, 'src'), { recursive: true });
  mkdirSync(HERMES_DIR, { recursive: true });
  writeFileSync(join(HERMES_DIR, '.env'), `MCITY_API_TOKEN=${token}\n`);
  mkdirSync(STATE);
  writeFileSync(join(STATE, 'evidence.json'), RECORDED);
  writeFileSync(join(STATE, 'run.log'), '{"level":30,"msg":"wrote request to server"}\n');
  for (const log of WITNESS_LOGS) {
    writeFileSync(log, '{"level":30,"msg":"WS server listening"}\n');
  }
});
after(() => rmSync(ROOT, { recursive: true, force: true }));

/** Run the copied check.ts; fails the test if its output carries the token. */
const check = (): { status: number | null; output: string } => {
  const run = spawnSync(process.execPath, [join(COPY, 'src', 'check.ts')], {
    env: { ...process.env, HOME, WITNESS_LOGS: WITNESS_LOGS.join(',') },
    encoding: 'utf8',
  });
  const output = run.stdout + run.stderr;
  assert.ok(!output.includes(token), 'check printed the token');
  assert.ok(!output.toLowerCase().includes(hex), 'check printed the token as hex');
  return { status: run.status, output };
};

/** Run check.ts and expect it to report `failure` and write no fixture. */
const assertCaught = (failure: string): string => {
  const { status, output } = check();
  assert.equal(status, 1, output);
  assert.ok(output.includes(failure), output);
  assert.ok(!existsSync(FIXTURE), 'fixture written despite the leak');
  return output;
};

test('a clean run writes the fixture', () => {
  const { status, output } = check();
  assert.equal(status, 0, output);
  assert.equal(readFileSync(FIXTURE, 'utf8'), RECORDED);
});

test('the token in the run log is caught and the log withheld', () => {
  appendFileSync(join(STATE, 'run.log'), `{"headers":{"authorization":"Bearer ${token}"}}\n`);
  const output = assertCaught('run log contains the token');
  assert.ok(output.includes('run log withheld'), output);
});

test('the token in the evidence is caught', () => {
  const pair = JSON.parse(RECORDED) as { evidences: { responseText?: string }[] };
  const [first] = pair.evidences;
  assert.ok(first !== undefined);
  // responseText isn't witness-signed, so the pair still verifies: only the search catches it.
  first.responseText = `GET /observer/api/local-control/claimable HTTP/1.1\r\nAuthorization: Bearer ${token}\r\n`;
  writeFileSync(join(STATE, 'evidence.json'), JSON.stringify(pair));
  assertCaught('evidence pair contains the token');
});

test('the token as upper-case hex in a witness log is caught', () => {
  appendFileSync(WITNESS_LOGS[0], `transcript ${hex.toUpperCase()}\n`);
  assertCaught('witness 1 log contains the token');
});

for (const pad of [0, 1, 2]) {
  test(`the token as base64 in a witness log is caught (shifted by ${pad})`, () => {
    const request = `${'x'.repeat(pad)}Authorization: Bearer ${token}\r\n`;
    appendFileSync(WITNESS_LOGS[1], `transcript ${Buffer.from(request).toString('base64')}\n`);
    assertCaught('witness 2 log contains the token');
  });
}

test('a missing witness log fails the check', () => {
  rmSync(WITNESS_LOGS[1]);
  assertCaught('witness 2 log not found');
});
