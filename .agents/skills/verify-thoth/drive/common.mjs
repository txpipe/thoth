// Shared setup for the verify-thoth drives: what a dApp and its attestor operators hold
// (the recorded zkFetch evidence, the policy it satisfies, Jubjub keys, the app id and a
// holder secret), built only from the packages' public entry points.
import { readFileSync } from 'node:fs';
import {
  CompactTypeField,
  CompactTypeVector,
  jubjubSchnorrSign,
  jubjubSchnorrVerifyingKey,
  sampleJubjubSchnorrSk,
} from '@midnight-ntwrk/compact-runtime';
import { descriptorOf } from '@thoth/attestor';
import { buildTrustedSet } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';
import { holderCommitmentOf } from '@thoth/core/claim-context';
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';
import { zkFetchClient } from '@thoth/zk-tls/client';

/** A genuine Reclaim-witnessed HTTPS fetch, recorded once; verifies offline. */
export const evidence = JSON.parse(
  readFileSync(
    new URL(
      '../../../../examples/demo-attestation/fixtures/fixture-github-attestor-core-x-0m.json',
      import.meta.url,
    ),
    'utf-8',
  ),
);

/** When the recorded witness observed, Unix seconds. */
export const OBSERVED_AT = BigInt(evidence.claim.timestampS);

/** The request the recorded witness fetched. */
export const request = { url: evidence.request.url, method: 'GET' };

/** The fixture discloses the whole response as `data`, which no numeric rule parses. */
export const policy = {
  allowedHosts: ['api.github.com'],
  slots: [{ slot: 0, name: 'data', parse: 'float', optional: true }],
};

export const APP_ID = new Uint8Array(32).fill(0xa1);
export const HOLDER_SECRET = new Uint8Array(32).fill(0xc1);
export const HOLDER = holderCommitmentOf(HOLDER_SECRET);

/** The example app's `#V`, `#M` and `#N`: three value slots, three registry slots, 2-of-3. */
export const VALUE_SLOTS = 3;
export const REGISTRY_SIZE = 3;

/** What fills a registry slot no attestor answered for: it never verifies. */
export const DUMMY_SIGNATURE = { announcement: { x: 0n, y: 1n }, response: 0n };

/** A Jubjub key pair whose signer signs the flat message, as an attestor operator holds. */
export const jubjubKeyPair = () => {
  const sk = sampleJubjubSchnorrSk();
  return {
    publicKey: jubjubSchnorrVerifyingKey(sk),
    signer: {
      sign: (message) =>
        jubjubSchnorrSign(
          new CompactTypeVector(message.length, CompactTypeField),
          [...message],
          sk,
        ),
    },
  };
};

/** One zkFetch attestor instance trusting `witnessAddress` (default: the recorded witness). */
export const attestorNamed = (id, witnessAddress = evidence.attestorAddress) =>
  zkFetchAttestor({ id, keyPair: jubjubKeyPair(), witnessAddress });

/**
 * The dApp side: two operators the app pinned at registry slots 0 and 2 (slot 1 holds a
 * third operator it does not query), each proving through a prover that replays the
 * recorded evidence, reached through an in-process transport.
 *
 * @param tamper — rewrites one attestor's reply on the way back, as a broken transport would.
 */
export const dapp = ({ tamper = (_id, reply) => reply } = {}) => {
  const operators = [
    { attestor: attestorNamed('operator-a'), registryIndex: 0 },
    { attestor: attestorNamed('operator-b'), registryIndex: 2 },
  ];
  const unqueried = jubjubKeyPair().publicKey;
  const registryKeys = [
    operators[0].attestor.publicKey,
    unqueried,
    operators[1].attestor.publicKey,
  ];
  const byId = new Map(operators.map(({ attestor }) => [attestor.id, attestor]));
  const client = zkFetchClient.init({
    trusted: buildTrustedSet({
      registrySize: REGISTRY_SIZE,
      attestors: operators.map(({ attestor, registryIndex }) => ({
        attestor: descriptorOf(attestor),
        registryIndex,
      })),
    }),
    verifier: jubjubVerifier,
    transport: {
      request: async (descriptor, input) =>
        tamper(descriptor.id, await byId.get(descriptor.id).attest(input)),
    },
    policy,
    appId: APP_ID,
    valueSlots: VALUE_SLOTS,
    provers: Object.fromEntries(
      operators.map(({ attestor }) => [attestor.id, { prove: async () => evidence }]),
    ),
  });
  return { client, operators, registryKeys };
};

/** The collection options a dApp fixes: holder, a minute-long window over the observation. */
export const collectOptions = (overrides = {}) => ({
  holder: HOLDER,
  windowStart: OBSERVED_AT,
  windowEnd: OBSERVED_AT + 60n,
  expiresAt: Date.now() + 60_000,
  threshold: 2,
  attestorTimeoutMs: 5_000,
  ...overrides,
});

/** Lay collected signatures out at their registry slots, the dummy in every other slot. */
export const signaturesBySlot = (collected) =>
  Array.from(
    { length: REGISTRY_SIZE },
    (_, slot) =>
      collected.find((entry) => entry.registryIndex === slot)?.attestation.signature ??
      DUMMY_SIGNATURE,
  );

const hex = (bytes) => `0x${Buffer.from(bytes).toString('hex')}`;

/** Print a result as JSON: bigints as decimal strings, bytes as 0x-hex. */
export const show = (value) =>
  console.log(
    JSON.stringify(
      value,
      (_key, v) => {
        if (typeof v === 'bigint') {
          return v.toString();
        }
        if (v instanceof Uint8Array) {
          return hex(v);
        }
        return v;
      },
      2,
    ),
  );

/**
 * Run the step named on the command line. Exit 0 when the library accepted, 1 with
 * `{ refused }` when it threw, 2 for an unknown step.
 *
 * @param steps — step name to an async function returning what to print.
 */
export const main = async (steps) => {
  const name = process.argv[2];
  const step = steps[name];
  if (!step) {
    console.log(`usage: node ${process.argv[1]} <${Object.keys(steps).join('|')}>`);
    process.exitCode = 2;
    return;
  }
  try {
    show(await step());
  } catch (error) {
    show({
      refused: {
        error: error?.constructor?.name,
        message: error?.message,
        ...(error?.reason === undefined ? {} : { reason: error.reason }),
        ...(error?.failures === undefined ? {} : { failures: error.failures }),
        ...(error?.code === undefined ? {} : { code: error.code }),
      },
    });
    process.exitCode = 1;
  }
};

/** The example app the run compiled from `packages/contracts/examples/example_app.compact`. */
export const exampleApp = async () => {
  const runDir = process.env.VERIFY_THOTH_RUN_DIR;
  if (!runDir) {
    throw new Error('VERIFY_THOTH_RUN_DIR is unset: run drives through `control-thoth run`');
  }
  return import(`${runDir}/example_app/contract/index.js`);
};
