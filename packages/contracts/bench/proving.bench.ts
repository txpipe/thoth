// Proving benchmark: proves and verifies every circuit of both mocks on a real proof server and
// reports k, rows, key and proof size, time, CPU time and peak memory. Run `npm run bench`.

import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { cpus, homedir, totalmem } from 'node:os';
import { dirname, join } from 'node:path';
import { type ProofData, proofDataIntoSerializedPreimage } from '@midnight-ntwrk/compact-runtime';
import { createCheckPayload, createProvingPayload } from '@midnight-ntwrk/ledger-v9';
import { expect, it } from 'vitest';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import { pureCircuits as bytesPureCircuits } from '../artifacts/mock_attestation_bytes/contract/index.js';
import {
  bytesIdOf,
  DEFAULT_BYTE_VALUE,
  DEFAULT_HOLDER_SECRET,
  DUMMY_SIGNATURE,
  idOf,
  makeByteClaim,
  makeClaim,
  makeNotaryKey,
  signClaim,
} from '../test/helpers/fixtures.js';
import { createPrivateState } from '../test/helpers/private-state.js';
import { signMessage } from '../test/helpers/sign.js';
import { MockAttestationBytesSim, MockAttestationSim } from '../test/helpers/sim.js';
import { benchOptions } from './options.js';
import {
  externalProofServer,
  PROOF_SERVER_IMAGE,
  type ProofServer,
  startProofServer,
} from './proof-server.js';
import { type CircuitMeasurement, type CircuitRow, formatTable, summarize } from './report.js';

const ARTIFACTS = join(import.meta.dirname, '..', 'artifacts');
const MOCKS = ['mock_attestation', 'mock_attestation_bytes'] as const;
type Mock = (typeof MOCKS)[number];

// Read once, before any circuit runs or any server starts, so a bad option fails at once.
// With PROOF_SERVER_URL set, the benchmark proves on that server and cannot read its CPU time
// or memory, so it reports both as not measured.
const OPTIONS = benchOptions(process.env, {
  cwd: process.cwd(),
  home: homedir(),
  defaultOut: join(import.meta.dirname, 'results', 'latest.json'),
});

type Captured = { mock: Mock; circuit: string; proofData: ProofData };

/** Run every circuit of both mocks once on the simulator and keep each call's proof inputs. */
const capture = async (): Promise<Captured[]> => {
  const keys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;
  const registryKeys = keys.map((key) => key.pk);
  const holderSecret = DEFAULT_HOLDER_SECRET;
  const captured: Captured[] = [];

  // Two of three attestors sign, as a client sends a threshold of signatures.
  const signers = [keys[0], null, keys[2]];
  const numeric = await MockAttestationSim.create(createPrivateState(holderSecret), registryKeys);
  const filled = (byte: number) => new Uint8Array(32).fill(byte);
  const subject = { method: filled(1), host: filled(2), path: filled(3), body: filled(4) };
  const claim = makeClaim({
    values: [100n, 200n, 0n],
    present: [true, true, false],
    subjectHash: pureCircuits.subjectHash(subject),
  });
  const signed = { ...signClaim(claim, signers, randomBytes(32)), holderSecret };
  const id = idOf(claim, signed.commitRand);
  const onNumeric = async (circuit: string, ...args: unknown[]) => {
    const proofData = await numeric.callForProof(circuit, signed, ...args);
    captured.push({ mock: 'mock_attestation', circuit, proofData });
  };
  await onNumeric('verifyAttestation');
  await onNumeric('openAndRead', id, 100n, 200n);
  await onNumeric('openAndReadPresence', id, true, true);
  await onNumeric('openAndRequireMetric0', id, 100n);
  await onNumeric('openAndBindHost', id, subject, subject.host);

  const bytes = await MockAttestationBytesSim.create(
    createPrivateState(holderSecret),
    registryKeys,
  );
  const byteClaim = makeByteClaim();
  const message = bytesPureCircuits.message(byteClaim);
  const byteSigned = {
    ...createPrivateState(holderSecret),
    claim: byteClaim,
    signatures: signers.map((key) =>
      key === null ? DUMMY_SIGNATURE : signMessage(key.sk, message).signature,
    ),
    commitRand: randomBytes(32),
  };
  const onBytes = async (circuit: string, ...args: unknown[]) => {
    const proofData = await bytes.callForProof(circuit, byteSigned, ...args);
    captured.push({ mock: 'mock_attestation_bytes', circuit, proofData });
  };
  await onBytes('verifyAttestation');
  await onBytes(
    'openAndReadBytes',
    bytesIdOf(byteClaim, byteSigned.commitRand),
    DEFAULT_BYTE_VALUE,
  );
  return captured;
};

/** The circuits a mock was compiled with, from the proving keys the compiler wrote. */
const compiledCircuits = (mock: Mock): string[] => {
  const dir = join(ARTIFACTS, mock, 'keys');
  if (!existsSync(dir)) {
    throw new Error(`${dir} is missing: compile the mocks with keys (npm run compact)`);
  }
  return readdirSync(dir)
    .filter((file) => file.endsWith('.prover'))
    .map((file) => file.slice(0, -'.prover'.length))
    .sort();
};

const paths = ({ mock, circuit }: Pick<Captured, 'mock' | 'circuit'>) => ({
  prover: join(ARTIFACTS, mock, 'keys', `${circuit}.prover`),
  verifier: join(ARTIFACTS, mock, 'keys', `${circuit}.verifier`),
  bzkir: join(ARTIFACTS, mock, 'zkir', `${circuit}.bzkir`),
  zkir: join(ARTIFACTS, mock, 'zkir', `${circuit}.zkir`),
});

const keyMaterial = (item: Captured) => {
  const files = paths(item);
  return {
    proverKey: readFileSync(files.prover),
    verifierKey: readFileSync(files.verifier),
    ir: readFileSync(files.bzkir),
  };
};

const preimageOf = ({ circuit, proofData }: Captured): Uint8Array =>
  proofDataIntoSerializedPreimage(
    proofData.input,
    proofData.output,
    proofData.publicTranscript,
    proofData.privateTranscriptOutputs,
    circuit,
  );

/**
 * k and rows as `zkir-v3 mock-compile` reports them, without a proof server.
 *
 * @throws {Error} when `zkir-v3` fails or prints no k and rows.
 */
const circuitSize = (zkir: string): { k: number; rows: number } => {
  // zkir-v3 prints its report on stderr.
  const { stdout, stderr, error, status } = spawnSync(OPTIONS.zkir, ['mock-compile', zkir], {
    encoding: 'utf8',
  });
  if (error) {
    throw error;
  }
  const output = `${stdout}${stderr}`;
  if (status !== 0) {
    throw new Error(`zkir-v3 mock-compile exited with ${status} for ${zkir}: ${output}`);
  }
  const match = /k=(\d+), rows=(\d+)/.exec(output);
  if (!match) {
    throw new Error(`zkir-v3 mock-compile gave no k and rows for ${zkir}: ${output}`);
  }
  return { k: Number(match[1]), rows: Number(match[2]) };
};

const send = (server: ProofServer, path: string, body?: Uint8Array): Promise<Response> =>
  fetch(`${server.url}${path}`, body ? { method: 'POST', body } : {});

const request = async (server: ProofServer, path: string, body?: Uint8Array) => {
  const response = await send(server, path, body);
  if (!response.ok) {
    throw new Error(`${path}: ${response.status} ${(await response.text()).slice(0, 300)}`);
  }
  return new Uint8Array(await response.arrayBuffer());
};

const PROOF_TAG = new TextEncoder().encode('midnight:proof-versioned:');

/**
 * Prove one circuit once, then `warmRuns` more times with the same key.
 *
 * The server verifies each proof against the verifier key in the request before it answers, and
 * answers `Invalid proof` when it does not verify, so each proof that comes back is verified.
 * The wrong-key control checks that the server does refuse.
 *
 * @throws {Error} when the server refuses the preimage or a proof request.
 */
const measure = async (server: ProofServer, item: Captured): Promise<CircuitMeasurement> => {
  const files = paths(item);
  const { k, rows } = circuitSize(files.zkir);
  const material = keyMaterial(item);
  const preimage = preimageOf(item);
  // Download the public parameters for k now, so no timed proof waits for them.
  await request(server, `/fetch-params/${k}`);
  // /check runs the circuit on the preimage: a wrong witness fails here, before any proving.
  await request(server, '/check', createCheckPayload(preimage, material.ir));
  const payload = createProvingPayload(preimage, undefined, material);
  const proofs = [];
  let proofBytes = 0;
  for (let i = 0; i <= OPTIONS.warmRuns; i++) {
    const before = server.usage();
    const start = performance.now();
    const proof = await request(server, '/prove', payload);
    const ms = performance.now() - start;
    const after = server.usage();
    if (!PROOF_TAG.every((byte, j) => proof[j] === byte)) {
      throw new Error('/prove answered 200 without a proof');
    }
    proofBytes = proof.length;
    proofs.push({
      ms,
      cpuSeconds: before && after ? after.cpuSeconds - before.cpuSeconds : null,
    });
  }
  const [first, ...warm] = proofs;
  if (!first) {
    throw new Error('no proof was made');
  }
  return {
    mock: item.mock,
    circuit: item.circuit,
    k,
    rows,
    proverKeyBytes: statSync(files.prover).size,
    verifierKeyBytes: statSync(files.verifier).size,
    proofBytes,
    first,
    warm,
    peakMemoryBytes: server.usage()?.peakMemoryBytes ?? null,
    freshServer: server.started,
  };
};

/**
 * Prove the circuit with the smallest proving key under another circuit's verifier key and
 * require the server to refuse it. Without this, a server that stopped verifying would make
 * every "verified" above meaningless. `ledger-v9`'s `wellFormed` is no substitute: it accepts a
 * tampered proof and a wrong verifier key.
 *
 * @throws {Error} when the server does not answer `Invalid proof`.
 */
const requireWrongKeyRefused = async (server: ProofServer, items: Captured[]): Promise<void> => {
  const [target, other] = [...items].sort(
    (a, b) => statSync(paths(a).prover).size - statSync(paths(b).prover).size,
  );
  if (!target || !other) {
    throw new Error('the wrong-key control needs two circuits');
  }
  const wrongKey = readFileSync(paths(other).verifier);
  if (Buffer.compare(wrongKey, readFileSync(paths(target).verifier)) === 0) {
    throw new Error(`${target.circuit} and ${other.circuit} have the same verifier key`);
  }
  const { k } = circuitSize(paths(target).zkir);
  await request(server, `/fetch-params/${k}`);
  const payload = createProvingPayload(preimageOf(target), undefined, {
    ...keyMaterial(target),
    verifierKey: wrongKey,
  });
  const response = await send(server, '/prove', payload);
  const body = await response.text();
  if (response.ok || !body.includes('Invalid proof')) {
    throw new Error(
      `the proof server did not refuse ${target.mock}.${target.circuit} under ${other.circuit}'s verifier key: ${response.status} ${body.slice(0, 200)}`,
    );
  }
};

/** A fresh server per use when the benchmark runs its own, so each circuit is measured alone. */
const openServer = (): Promise<ProofServer> =>
  OPTIONS.externalUrl
    ? Promise.resolve(externalProofServer(OPTIONS.externalUrl))
    : startProofServer(`thoth-bench-${process.pid}`, OPTIONS.docker);

const withServer = async <T>(use: (server: ProofServer) => Promise<T>): Promise<T> => {
  const server = await openServer();
  try {
    return await use(server);
  } finally {
    await server.stop();
  }
};

const messageOf = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

it('proves and verifies every mock circuit', { timeout: 3_600_000 }, async () => {
  const captured = await capture();
  for (const mock of MOCKS) {
    const benchmarked = captured.filter((item) => item.mock === mock).map((item) => item.circuit);
    // A circuit added to a mock must be added here too, or it would go unproved.
    expect(benchmarked.sort(), `${mock} circuits the benchmark proves`).toEqual(
      compiledCircuits(mock),
    );
  }

  const rows: CircuitRow[] = [];
  const failures: string[] = [];
  let proofServer = '';
  for (const item of captured) {
    try {
      rows.push(
        await withServer(async (server) => {
          proofServer = new TextDecoder().decode(await request(server, '/version'));
          return summarize(await measure(server, item));
        }),
      );
    } catch (error) {
      failures.push(`${item.mock}.${item.circuit} did not prove: ${messageOf(error)}`);
    }
  }
  let controlRefused = false;
  try {
    await withServer((server) => requireWrongKeyRefused(server, captured));
    controlRefused = true;
  } catch (error) {
    failures.push(`wrong-key control: ${messageOf(error)}`);
  }

  const cpu = cpus();
  const machine = `${cpu[0]?.model.trim() ?? 'unknown CPU'}, ${cpu.length} threads, ${Math.round(totalmem() / 2 ** 30)} GiB`;
  const server = OPTIONS.externalUrl
    ? `proof server ${proofServer} at ${OPTIONS.externalUrl}, not started by the benchmark, so CPU time and peak memory are not measured`
    : `proof server ${proofServer} (${PROOF_SERVER_IMAGE}), a fresh container per circuit`;
  const { warmRuns, out } = OPTIONS;
  const report = { machine, server, warmRuns, controlRefused, rows, failures };
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
  console.log(
    [
      '',
      `${machine}; ${server}; ${warmRuns} warm proof${warmRuns === 1 ? '' : 's'} per circuit.`,
      controlRefused
        ? 'The proof server verified every proof against its verifier key, and refused a proof under the wrong verifier key.'
        : 'The proof server did not refuse a proof under the wrong verifier key, so no proof here counts as verified.',
      '',
      formatTable(rows),
      ...failures.map((failure) => `\nFAILED: ${failure}`),
      '',
    ].join('\n'),
  );
  expect(failures).toEqual([]);
});
