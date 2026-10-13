// Spike for #129, second half: search prove.ts's evidence pair, its run log and both
// witnesses' logs for the City API token, then verify the pair. Only a clean, verified
// pair becomes the fixture. The token itself is never printed.
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { claimUrl, type ZkFetchEvidence } from '@thoth/zk-tls';
import { verifyZkFetchProof } from '@thoth/zk-tls/attestor';
import { CLAIMABLE_URL, EVIDENCE_PATH, loadToken, RUN_LOG_PATH } from './common.ts';

/** Where `npm run witnesses --workspace=packages/zk-tls` logs, unless overridden. */
const WITNESS_LOGS = (
  process.env.WITNESS_LOGS ??
  ['8001', '8002'].map((port) => join(tmpdir(), `thoth-witness-${port}.log`)).join(',')
).split(',');

const FIXTURE_PATH = new URL('../../fixtures/control-claimable.json', import.meta.url);

const token = Buffer.from(loadToken());
const hex = token.toString('hex');
// A log can carry the token as text, hex, or base64 at any of three byte alignments.
// Each base64 needle drops the edge characters that mix in neighbouring bytes.
const needles = [
  token.toString(),
  ...[0, 1, 2].map((pad) =>
    Buffer.concat([Buffer.alloc(pad), token])
      .toString('base64')
      .replace(/=+$/, '')
      .slice([0, 2, 3][pad], -2),
  ),
];
const leaks = (text: string): boolean =>
  needles.some((needle) => text.includes(needle)) || text.toLowerCase().includes(hex);

for (const pad of [0, 1, 2]) {
  const embedded = Buffer.concat([Buffer.alloc(pad, 0x41), token, Buffer.from('}"')]);
  assert(leaks(`log:${embedded.toString('base64')}`), `base64 needle misses alignment ${pad}`);
}

const failures: string[] = [];
const searched = (label: string, path: string | URL): string => {
  if (!existsSync(path)) {
    failures.push(`${label} not found at ${path}`);
    return '';
  }
  const text = readFileSync(path, 'utf8');
  if (leaks(text)) {
    failures.push(`${label} contains the token`);
  }
  console.log(`searched ${label} (${Buffer.byteLength(text)} bytes)`);
  return text;
};

const runLog = searched('run log', RUN_LOG_PATH);
const evidenceText = searched('evidence pair', EVIDENCE_PATH);
WITNESS_LOGS.forEach((path, i) => {
  searched(`witness ${i + 1} log`, path);
});

// prove.ts's output goes to the terminal only once it's known to be clean.
console.log(
  failures.some((failure) => failure.startsWith('run log'))
    ? '--- run log withheld: it contains the token ---'
    : `--- run log ---\n${runLog.trimEnd()}\n---`,
);

if (evidenceText !== '') {
  const { evidences } = JSON.parse(evidenceText) as { evidences: ZkFetchEvidence[] };
  const verified = await Promise.all(evidences.map((evidence) => verifyZkFetchProof(evidence)));
  for (const view of verified) {
    console.log(
      `witness ${view.attestorAddress}: ${claimUrl(view.claim)} at ${view.claim.timestampS}, agent ${view.disclosedValues.agent}`,
    );
  }
  const checks: [boolean, string][] = [
    [verified.length === 2, 'two evidences'],
    [verified.every((view) => claimUrl(view.claim) === CLAIMABLE_URL), 'both fetched claimable'],
    [new Set(verified.map((view) => view.attestorAddress)).size === 2, 'two distinct witnesses'],
    [new Set(verified.map((view) => view.identifier)).size === 1, 'witnesses sign one claim'],
    [
      verified.every((view) => /^user-agent-[0-9a-z]+$/.test(view.disclosedValues.agent ?? '')),
      'both disclose an agent ID',
    ],
  ];
  for (const [ok, check] of checks) {
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${check}`);
    if (!ok) {
      failures.push(check);
    }
  }
}

if (failures.length > 0) {
  console.log(`\nFAILED:\n- ${failures.join('\n- ')}`);
  process.exit(1);
}
mkdirSync(new URL('.', FIXTURE_PATH), { recursive: true });
writeFileSync(FIXTURE_PATH, evidenceText);
console.log(`\nno token anywhere; fixture written to ${FIXTURE_PATH.pathname}`);
