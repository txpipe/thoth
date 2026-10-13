// Drive: an app's contract embedding the Compact modules — the example app the run
// compiled from `packages/contracts/examples/example_app.compact` — deployed on the
// Compact runtime's simulator, taking an attestment the dApp collected.
import { randomBytes } from 'node:crypto';
import {
  createCircuitContext,
  createConstructorContext,
  dummyContractAddress,
} from '@midnight-ntwrk/compact-runtime';
import { zkFetchPolicyHashOf } from '@thoth/zk-tls';
import {
  collectOptions,
  DUMMY_SIGNATURE,
  dapp,
  exampleApp,
  HOLDER_SECRET,
  main,
  OBSERVED_AT,
  policy,
  request,
  signaturesBySlot,
} from './common.mjs';

const COIN_PK = '0'.repeat(64);

/** What the app's witnesses hand the circuits: the submission and the caller's secret. */
const privateState = (submission = null, holderSecret = HOLDER_SECRET) => ({
  submission,
  holderSecret,
});

/** Deploy the example app, sealing `keys` and `policies`, and return a caller for it. */
const deploy = async (keys, policies = [zkFetchPolicyHashOf(policy)]) => {
  const { Contract, ledger } = await exampleApp();
  const contract = new Contract({
    getAttestationWitness: ({ privateState: ps }) => {
      const { claim, signatures, commitRand } = ps.submission;
      return [ps, [claim, signatures, commitRand]];
    },
    getHolderSecret: ({ privateState: ps }) => [ps, ps.holderSecret],
    seedKeys: ({ privateState: ps }) => [ps, keys],
    seedPolicies: ({ privateState: ps }) => [ps, policies],
  });
  const deployed = await contract.initialState(createConstructorContext(privateState(), COIN_PK));
  let state = deployed.currentContractState.data;
  return {
    /** Call `verifyAttestation` at block time `now` (Unix seconds). */
    submit: async (ps, now) => {
      const ctx = createCircuitContext(
        'verifyAttestation',
        dummyContractAddress(),
        COIN_PK,
        state,
        ps,
        undefined,
        undefined,
        undefined,
        Number(now),
      );
      const result = await contract.circuits.verifyAttestation(ctx);
      state = result.context.callContext.currentQueryContext.state;
    },
    view: () => {
      const l = ledger(state);
      return {
        freshnessWindow: l.A_freshnessWindow,
        maxWindow: l.A_maxWindow,
        policyHashes: [...l.A_policyHashes],
        nullifiers: l.A_nullifiers.size(),
        claimsVault: [...l.A_claimsVault].map(([id, entry]) => ({ id, ...entry })),
      };
    },
  };
};

/** Collect an attestment as the dApp does and shape it as the contract's witness reads it. */
const collected = async (options = {}) => {
  const { client, registryKeys } = dapp();
  const { claim, collected } = await client.collect(request, collectOptions(options));
  const submission = {
    claim: { ...claim, present: [...claim.present], values: [...claim.values] },
    signatures: signaturesBySlot(collected),
    commitRand: randomBytes(32),
  };
  return { registryKeys, submission };
};

/** Deploy, submit once at `now` (default: the window's end), and show the ledger. */
const submitOnce = async ({ change = (s) => s, policies, holderSecret, now, options } = {}) => {
  const { registryKeys, submission } = await collected(options);
  const app = await deploy(registryKeys, policies);
  const sent = change(submission);
  await app.submit(privateState(sent, holderSecret), now ?? sent.claim.windowEnd);
  return app.view();
};

await main({
  deploy: async () => {
    const { registryKeys } = await collected();
    return (await deploy(registryKeys)).view();
  },
  accept: async () => submitOnce(),
  replay: async () => {
    const { registryKeys, submission } = await collected();
    const app = await deploy(registryKeys);
    await app.submit(privateState(submission), submission.claim.windowEnd);
    // The same observation again, under fresh vault randomness.
    await app.submit(
      privateState({ ...submission, commitRand: randomBytes(32) }),
      submission.claim.windowEnd,
    );
    return app.view();
  },
  'one-signature': async () =>
    submitOnce({
      change: (s) => ({ ...s, signatures: [s.signatures[0], DUMMY_SIGNATURE, DUMMY_SIGNATURE] }),
    }),
  'swapped-slots': async () =>
    submitOnce({
      change: (s) => ({ ...s, signatures: [s.signatures[2], s.signatures[1], s.signatures[0]] }),
    }),
  'unaccepted-policy': async () => submitOnce({ policies: [new Uint8Array(32).fill(0xbf)] }),
  'holder-mismatch': async () => submitOnce({ holderSecret: new Uint8Array(32).fill(0xc2) }),
  // The attestors sign any window holding their observation; the app bounds its length.
  'window-too-long': async () => submitOnce({ options: { windowEnd: OBSERVED_AT + 301n } }),
  'too-old': async () => {
    const { registryKeys, submission } = await collected();
    const app = await deploy(registryKeys);
    // The example seals freshnessWindow = 3600: the window's end plus an hour is too late.
    await app.submit(privateState(submission), submission.claim.windowEnd + 3600n);
    return app.view();
  },
  'in-the-future': async () => {
    const { registryKeys, submission } = await collected();
    const app = await deploy(registryKeys);
    await app.submit(privateState(submission), submission.claim.windowStart - 1n);
    return app.view();
  },
});
