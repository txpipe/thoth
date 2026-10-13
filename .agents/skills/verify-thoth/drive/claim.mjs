// Drive: the canonical claim a kind signs and an app submits, its flat wire message, and
// the claim-context hashes, through `@thoth/core/claim` and `@thoth/core/claim-context`,
// held against the message circuit of the example app the run compiled.
import { claimSchema, claimToMessage } from '@thoth/core/claim';
import {
  claimContextDigestOf,
  holderCommitmentOf,
  policyHashOf,
  subjectHashOf,
} from '@thoth/core/claim-context';
import { exampleApp, HOLDER, HOLDER_SECRET, main, OBSERVED_AT } from './common.mjs';

// Distinct bytes, so a field whose two 16-byte halves were swapped would show.
const counting = (from) => Uint8Array.from({ length: 32 }, (_, i) => from + i);

/** A raw claim as a kind or client hands it over: plain numbers, slot 1 a measured zero. */
const raw = {
  appId: counting(0x00),
  policyHash: counting(0x20),
  windowStart: Number(OBSERVED_AT),
  windowEnd: Number(OBSERVED_AT) + 60,
  subjectHash: counting(0x40),
  holder: HOLDER,
  present: [true, true, false],
  values: [42, 0, 0],
};

const claim = () => claimSchema(3).parse(raw);

await main({
  parse: async () => claim(),
  'short-app-id': async () => claimSchema(3).parse({ ...raw, appId: new Uint8Array(31) }),
  'absent-nonzero': async () => {
    // The schema does not judge presence; the contract does (`Absent slot has nonzero value`).
    const parsed = claimSchema(3).parse({
      ...raw,
      present: [true, false, false],
      values: [42, 7, 0],
    });
    return { parsed: true, present: parsed.present, values: parsed.values };
  },
  message: async () => {
    const message = claimToMessage(claim());
    return { length: message.length, message };
  },
  parity: async () => {
    const { pureCircuits } = await exampleApp();
    const offChain = claimToMessage(claim());
    const inCircuit = pureCircuits.message(claim());
    const differing = offChain.flatMap((field, i) => (field === inCircuit[i] ? [] : [i]));
    return { offChainLength: offChain.length, inCircuitLength: inCircuit.length, differing };
  },
  hashes: async () => ({
    policyHash: policyHashOf('verify-kind@1', { allowedHosts: ['example.com'] }),
    subjectHash: subjectHashOf([counting(0x00), counting(0x20)]),
    holder: holderCommitmentOf(HOLDER_SECRET),
    claimContextDigest: claimContextDigestOf({
      policyHash: counting(0x20),
      subjectHash: counting(0x40),
      holder: HOLDER,
      windowStart: OBSERVED_AT,
      windowEnd: OBSERVED_AT + 60n,
    }),
  }),
});
