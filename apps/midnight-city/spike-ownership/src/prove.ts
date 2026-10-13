// Spike for #129, first half: prove "this City API token controls agent A" through two
// zkFetch witnesses, with the token as a secret header. Run it through `npm start`, which
// sends this output to .state/run.log so check.ts can search it for the token before
// anyone sees it: the Reclaim client logs at `info` with PII redaction off, straight to fd 1.
import { mkdirSync, writeFileSync } from 'node:fs';
import type { ZkFetchEvidence } from '@thoth/zk-tls';
import type { ZkFetchRequest } from '@thoth/zk-tls/client';
import { zkFetchProver } from '@thoth/zk-tls/prover';
import { CLAIMABLE_URL, EVIDENCE_PATH, loadToken } from './common.ts';

const WITNESS_URLS = (process.env.WITNESS_URLS ?? 'ws://localhost:8001/ws,ws://localhost:8002/ws')
  .split(',')
  .map((url) => url.trim());

// The first listed agent only (#121). A `[^\]]*` before the group would capture the last one.
// IDs come as base 36, as hex, or as a UUID with hyphens.
const FIRST_AGENT = '"agentIds":\\["(?<agent>user-agent-[0-9a-z-]+)"';

const token = loadToken();
const authorization = `Bearer ${token}`;

// A plain read first: the response size #129 asks for, and the regex checked before proving.
const plainStart = performance.now();
const response = await fetch(CLAIMABLE_URL, { headers: { authorization } });
const body = await response.text();
console.log(
  `plain read: HTTP ${response.status}, ${Buffer.byteLength(body)} body bytes, ${Math.round(performance.now() - plainStart)} ms`,
);
if (!response.ok) {
  throw new Error(`claimable returned HTTP ${response.status}`);
}
const plainAgent = new RegExp(FIRST_AGENT).exec(body)?.groups?.agent;
if (plainAgent === undefined) {
  throw new Error('the first-agent regex does not match the claimable response');
}
console.log(`agents listed: ${(JSON.parse(body) as { agentIds: string[] }).agentIds.length}`);
console.log(`first agent: ${plainAgent}`);

// Everything here is signed into the evidence; the secret header is added only to `request`.
const publicRequest = {
  url: CLAIMABLE_URL,
  method: 'GET',
  responseMatches: [{ type: 'regex', value: FIRST_AGENT }],
  // The witness sees only this slice: no other agent IDs and no response headers.
  responseRedactions: [{ regex: '"agentIds":\\["user-agent-[0-9a-z-]+"' }],
} satisfies ZkFetchRequest;
const request: ZkFetchRequest = { ...publicRequest, secretHeaders: { authorization } };

// One witness at a time, so each latency is the proof's own.
const evidences: ZkFetchEvidence[] = [];
for (const witnessUrl of WITNESS_URLS) {
  const proofStart = performance.now();
  evidences.push(await zkFetchProver({ witnessUrl }).prove(request));
  console.log(`proof via ${witnessUrl}: ${Math.round(performance.now() - proofStart)} ms`);
}

mkdirSync(new URL('.', EVIDENCE_PATH), { recursive: true });
writeFileSync(
  EVIDENCE_PATH,
  `${JSON.stringify({ generatedAt: new Date().toISOString(), request: publicRequest, evidences }, null, 2)}\n`,
);
console.log(`evidence pair written to ${EVIDENCE_PATH.pathname}`);
// The Reclaim client pools its witness websockets and never closes them.
process.exit(0);
