// Proving benchmark: k, rows, key sizes, proof size and proving time for every circuit of the
// two mocks, timed on a local proof server that verifies each proof, after the server checks the
// signature circuits on random claims. Run `npm run bench`.
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { cpus, homedir, totalmem } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  type CircuitContext,
  createCircuitContext,
  dummyContractAddress,
  type ProofData,
  proofDataIntoSerializedPreimage,
} from '@midnight-ntwrk/compact-runtime';
import { createCheckPayload, createProvingPayload } from '@midnight-ntwrk/ledger-v9';
import { expect, it } from 'vitest';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import {
  bySlot,
  bytesIdOf,
  DEFAULT_BYTE_VALUE,
  DEFAULT_HOLDER_SECRET,
  idOf,
  makeByteClaim,
  makeClaim,
  makeNotaryKey,
  type NotaryKey,
  randomByteClaim,
  randomClaim,
  signClaim,
} from '../test/helpers/fixtures.js';
import { createPrivateState } from '../test/helpers/private-state.js';
import { signClaim as signOne } from '../test/helpers/sign.js';
import { MockAttestationBytesSim, MockAttestationSim } from '../test/helpers/sim.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ARTIFACTS = join(HERE, '..', 'artifacts');
const PROOF_SERVER = process.env.PROOF_SERVER_URL ?? 'http://127.0.0.1:6300';
const ZKIR_BIN =
  process.env.ZKIR_BIN ??
  join(homedir(), '.compact/versions/0.36.1/x86_64-unknown-linux-musl/zkir-v3');
const WARM_RUNS = Number(process.env.BENCH_RUNS ?? 3);
const OUT = process.env.BENCH_OUT ?? join(HERE, 'results', 'latest.json');
// BENCH_PROVE=0 reports the static numbers only (no proof server needed).
const PROVE = process.env.BENCH_PROVE !== '0';
// Random claims per mock whose `verifyAttestation` preimage the server checks against the zkir.
const ZKIR_CHECKS = Number(process.env.BENCH_ZKIR_CHECKS ?? 16);

type Row = {
  artifact: string;
  circuit: string;
  k: number;
  rows: number;
  proverKeyBytes: number;
  verifierKeyBytes: number;
  zkirBytes: number;
  proofBytes: number | null;
  /**
   * The first proof with this prover key. The server parses an uploaded prover key once and
   * keeps the last five it parsed, keyed by their hash, so this includes the parse; it is
   * the cost of a circuit's first proof after the server starts.
   */
  coldMs: number | null;
  /** Later proofs with the same key, which the server finds already parsed. */
  warmMs: number[];
  warmMedianMs: number | null;
  /**
   * True when the cold proof was not clearly slower than the warm ones: the server already had
   * this key parsed (it proved the same key recently), so `coldMs` is not a cold measurement.
   */
  coldWasCached: boolean | null;
};

type Captured = { artifact: string; circuit: string; proofData: ProofData };

type Sim = {
  contract: { circuits: Record<string, unknown> };
  state: unknown;
  now: number | null;
};

/** Run one circuit on the simulator, advance its state, and keep its proof inputs. */
const run = async <PS>(
  artifact: string,
  sim: Sim,
  circuit: string,
  privateState: PS,
  ...args: unknown[]
): Promise<Captured> => {
  const context = createCircuitContext({
    circuitId: circuit,
    contractAddress: dummyContractAddress(),
    coinPublicKeyOrZswapState: '0'.repeat(64),
    contractState: sim.state as never,
    privateState,
    time: sim.now ?? undefined,
  });
  const call = sim.contract.circuits[circuit] as (
    context: CircuitContext<PS>,
    ...args: unknown[]
  ) => Promise<{ context: CircuitContext<PS> }>;
  const result = await call(context, ...args);
  sim.state = result.context.callContext.currentQueryContext.state;
  const proofData = result.context.callProofDataTrace[0];
  if (!proofData) {
    throw new Error(`${circuit}: the simulator recorded no proof data`);
  }
  return { artifact, circuit, proofData };
};

const send = (path: string, body: Uint8Array): Promise<Response> =>
  fetch(`${PROOF_SERVER}${path}`, { method: 'POST', body });

const post = async (path: string, body: Uint8Array): Promise<Uint8Array> => {
  const response = await send(path, body);
  if (!response.ok) {
    throw new Error(`${path}: ${response.status} ${await response.text()}`);
  }
  return new Uint8Array(await response.arrayBuffer());
};

const PROOF_TAG = new TextEncoder().encode('midnight:proof-versioned:');

const keyPaths = (artifact: string, circuit: string) => {
  const dir = join(ARTIFACTS, artifact);
  return {
    prover: join(dir, 'keys', `${circuit}.prover`),
    verifier: join(dir, 'keys', `${circuit}.verifier`),
    ir: join(dir, 'zkir', `${circuit}.bzkir`),
  };
};

const keyMaterial = (artifact: string, circuit: string) => {
  const paths = keyPaths(artifact, circuit);
  return {
    proverKey: readFileSync(paths.prover),
    verifierKey: readFileSync(paths.verifier),
    ir: readFileSync(paths.ir),
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

/** k and rows as `zkir-v3 mock-compile` reports them. */
const circuitSize = (zkirPath: string): { k: number; rows: number } => {
  const { stdout, stderr } = spawnSync(ZKIR_BIN, ['mock-compile', zkirPath], { encoding: 'utf8' });
  const output = `${stdout}${stderr}`;
  const match = /k=(\d+), rows=(\d+)/.exec(output);
  if (!match) {
    throw new Error(`mock-compile gave no k/rows for ${zkirPath}: ${output}`);
  }
  return { k: Number(match[1]), rows: Number(match[2]) };
};

const median = (values: number[]): number => {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  const upper = sorted[middle] ?? 0;
  return sorted.length % 2 === 1 ? upper : ((sorted[middle - 1] ?? upper) + upper) / 2;
};

const measure = async (item: Captured): Promise<Row> => {
  const { artifact, circuit } = item;
  const paths = keyPaths(artifact, circuit);
  const row: Row = {
    artifact,
    circuit,
    ...circuitSize(join(ARTIFACTS, artifact, 'zkir', `${circuit}.zkir`)),
    proverKeyBytes: statSync(paths.prover).size,
    verifierKeyBytes: statSync(paths.verifier).size,
    zkirBytes: statSync(paths.ir).size,
    proofBytes: null,
    coldMs: null,
    warmMs: [],
    warmMedianMs: null,
    coldWasCached: null,
  };
  if (!PROVE) {
    return row;
  }
  const preimage = preimageOf(item);
  const material = keyMaterial(artifact, circuit);
  // /check runs the circuit on the preimage: a wrong witness fails here, before
  // any proving time is spent.
  await post('/check', createCheckPayload(preimage, material.ir));
  const payload = createProvingPayload(preimage, undefined, material);
  for (let i = 0; i <= WARM_RUNS; i++) {
    const start = performance.now();
    const proof = await post('/prove', payload);
    const elapsed = performance.now() - start;
    if (!PROOF_TAG.every((byte, j) => proof[j] === byte)) {
      throw new Error(`${artifact}.${circuit}: /prove answered 200 without a proof`);
    }
    row.proofBytes = proof.length;
    if (i === 0) {
      row.coldMs = elapsed;
    } else {
      row.warmMs.push(elapsed);
    }
  }
  if (row.warmMs.length > 0 && row.coldMs !== null) {
    row.warmMedianMs = median(row.warmMs);
    // Parsing the prover key adds about a third to a proof at every k measured (14, 15 and 17),
    // so a cold proof within 10% of the warm median means the server had the key parsed already.
    row.coldWasCached = row.coldMs < row.warmMedianMs * 1.1;
  }
  return row;
};

/**
 * Checks that the proof server verifies what it proves. The server checks each proof against
 * the verifier key in the payload before it answers and refuses with `Invalid proof` when the
 * proof does not verify; the bench sends each circuit's own verifier key, so every proof it
 * accepted was verified against that key. This proves one circuit under another circuit's
 * verifier key and requires the refusal. It runs after the timings because it makes the
 * server parse a prover key. (The npm ledger-v9 build leaves out the ledger's proof
 * verification: its `Transaction.wellFormed` accepts any proof, so it cannot do this check.)
 */
const requireVerifyingServer = async (items: Captured[]): Promise<void> => {
  const [target, other] = [...items].sort(
    (a, b) =>
      statSync(keyPaths(a.artifact, a.circuit).prover).size -
      statSync(keyPaths(b.artifact, b.circuit).prover).size,
  );
  if (!target || !other) {
    throw new Error('the verification check needs two circuits');
  }
  const payload = createProvingPayload(preimageOf(target), undefined, {
    ...keyMaterial(target.artifact, target.circuit),
    verifierKey: readFileSync(keyPaths(other.artifact, other.circuit).verifier),
  });
  const response = await send('/prove', payload);
  const body = await response.text();
  if (response.ok || !body.includes('Invalid proof')) {
    throw new Error(
      `the proof server does not refuse a proof under the wrong verifier key: ${response.status} ${body.slice(0, 200)}`,
    );
  }
};

const checkPreimage = (item: Captured): Promise<Response> =>
  send(
    '/check',
    createCheckPayload(preimageOf(item), readFileSync(keyPaths(item.artifact, item.circuit).ir)),
  );

/**
 * Checks the zkir of each mock's `verifyAttestation` on random claims, each signed over
 * `claimToMessage` with the runtime's `jubjubSchnorrSign`, as an attestor signs. The simulator
 * runs the compiled JavaScript, not the circuit the prover runs; `/check` runs that circuit on
 * the simulator's preimage, so it fails if the zkir's Schnorr challenge or nullifier differs
 * from the runtime's. A control first requires `/check` to refuse a failing assertion: an
 * `openAndRead` preimage whose expected value is off by one.
 *
 * @returns how many claims the server checked.
 */
const requireZkirParity = async (
  captured: Captured[],
  keys: readonly NotaryKey[],
  holderSecret: Uint8Array,
): Promise<number> => {
  const opened = captured.find((item) => item.circuit === 'openAndRead');
  if (!opened) {
    throw new Error('the zkir control needs the openAndRead preimage');
  }
  const [id, expected, ...rest] = opened.proofData.input.value;
  const wrong: Captured = {
    ...opened,
    proofData: {
      ...opened.proofData,
      input: {
        ...opened.proofData.input,
        value: [id, Uint8Array.of((expected?.[0] ?? 0) + 1), ...rest],
      },
    },
  } as Captured;
  const control = await checkPreimage(wrong);
  const refusal = await control.text();
  if (control.ok || !refusal.includes('assertion')) {
    throw new Error(
      `the proof server /check does not refuse a failing assertion: ${control.status} ${refusal.slice(0, 200)}`,
    );
  }
  const registryKeys = keys.map((key) => key.pk);
  const signers = [keys[0] ?? null, null, keys[2] ?? null];
  const numeric = await MockAttestationSim.create(createPrivateState(holderSecret), registryKeys);
  const bytes = await MockAttestationBytesSim.create(
    createPrivateState(holderSecret),
    registryKeys,
  );
  let checked = 0;
  for (let i = 0; i < ZKIR_CHECKS; i++) {
    const a = randomClaim();
    const b = randomByteClaim();
    const items = [
      await run('mock_attestation', numeric, 'verifyAttestation', {
        ...signClaim(a.claim, signers),
        holderSecret: a.secret,
      }),
      await run('mock_attestation_bytes', bytes, 'verifyAttestation', {
        claim: b.claim,
        signatures: bySlot(signers.map((key) => key && signOne(key.sk, b.claim).signature)),
        holderSecret: b.secret,
      }),
    ];
    for (const item of items) {
      const response = await checkPreimage(item);
      if (!response.ok) {
        throw new Error(
          `${item.artifact}: /check refused a random claim: ${await response.text()}`,
        );
      }
      checked++;
    }
  }
  return checked;
};

const keys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;

const capture = async (): Promise<Captured[]> => {
  const registryKeys = keys.map((key) => key.pk);
  const holderSecret = DEFAULT_HOLDER_SECRET;
  const captured: Captured[] = [];

  const numeric = 'mock_attestation';
  const sim = await MockAttestationSim.create(createPrivateState(holderSecret), registryKeys);
  const filled = (byte: number) => new Uint8Array(32).fill(byte);
  const subject = { method: filled(1), host: filled(2), path: filled(3), body: filled(4) };
  const claim = makeClaim({
    values: [100n, 200n, 0n],
    present: [true, true, false],
    subjectHash: pureCircuits.subjectHash(subject),
  });
  const signed = { ...signClaim(claim, keys), holderSecret };
  const id = idOf(claim);
  captured.push(
    await run(numeric, sim, 'verifyAttestation', signed),
    await run(numeric, sim, 'openAndRead', signed, id, 100n, 200n),
    await run(numeric, sim, 'openAndReadPresence', signed, id, true, true),
    await run(numeric, sim, 'openAndRequireMetric0', signed, id, 100n),
    await run(numeric, sim, 'openAndBindHost', signed, id, subject, subject.host),
  );

  const bytes = 'mock_attestation_bytes';
  const bytesSim = await MockAttestationBytesSim.create(
    createPrivateState(holderSecret),
    registryKeys,
  );
  const byteClaim = makeByteClaim();
  const signatures = bySlot(keys.map((key) => signOne(key.sk, byteClaim).signature));
  const byteSigned = { claim: byteClaim, signatures, holderSecret };
  captured.push(
    await run(bytes, bytesSim, 'verifyAttestation', byteSigned),
    await run(
      bytes,
      bytesSim,
      'openAndReadBytes',
      byteSigned,
      bytesIdOf(byteClaim),
      DEFAULT_BYTE_VALUE,
    ),
  );
  return captured;
};

const seconds = (ms: number | null): string => (ms === null ? '-' : (ms / 1000).toFixed(2));
const megabytes = (bytes: number): string => (bytes / 1e6).toFixed(1);

it('measures every mock circuit', { timeout: 3_600_000 }, async () => {
  const captured = await capture();
  const zkirChecks = PROVE ? await requireZkirParity(captured, keys, DEFAULT_HOLDER_SECRET) : 0;
  const rows: Row[] = [];
  for (const item of captured) {
    rows.push(await measure(item));
  }
  if (PROVE) {
    await requireVerifyingServer(captured);
  }
  const report = {
    proofServer: PROVE ? await (await fetch(`${PROOF_SERVER}/version`)).text() : null,
    machine: `${cpus().length}x ${cpus()[0]?.model ?? 'cpu'}, ${Math.round(totalmem() / 2 ** 30)} GiB`,
    warmRuns: WARM_RUNS,
    proofsVerified: PROVE,
    zkirChecks,
    rows,
  };
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, `${JSON.stringify(report, null, 2)}\n`);

  const table = [
    '| Artifact | Circuit | k | Rows | Proving key (MB) | Proof (B) | Cold (s) | Warm median (s) |',
    '|---|---|---|---|---|---|---|---|',
    ...rows.map(
      (r) =>
        `| ${r.artifact} | ${r.circuit} | ${r.k} | ${r.rows} | ${megabytes(r.proverKeyBytes)} | ${r.proofBytes ?? '-'} | ${seconds(r.coldMs)}${r.coldWasCached ? ' (key was cached)' : ''} | ${seconds(r.warmMedianMs)} |`,
    ),
  ].join('\n');
  const verified = PROVE
    ? `, every proof verified against its verifier key, ${zkirChecks} random claims checked against the zkir`
    : '';
  console.log(
    `\n${report.machine}, proof server ${report.proofServer ?? 'not used'}${verified}\n${table}\n`,
  );
  expect(rows.length).toBeGreaterThan(0);
});
