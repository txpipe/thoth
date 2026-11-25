// Cross-seam acceptance for the tlsn@1 prototype: two attestors, each pinning its own
// notary, read a redacted response and sign with real Jubjub keys, the client collects
// the threshold set, and the unchanged contract simulator accepts it. The policy is one
// object that zkFetch accepts too, and the contract seals both kinds' hashes of it: the
// dApp's choice of kind is a choice of evidence, not of contract. Every signed binding
// is then mutated under the same signatures. The presentations' cryptography is
// stubbed; `packages/tlsn/test/live.test.ts` runs it for real.
import { randomBytes } from 'node:crypto';
import { descriptorOf } from '@txpipe/thoth-attestor';
import { buildTrustedSet } from '@txpipe/thoth-client';
import { jubjubVerifier } from '@txpipe/thoth-client/jubjub';
import type { Claim } from '@txpipe/thoth-core/claim';
import { toContractClaim } from '@txpipe/thoth-core/claim';
import {
  TLSN_CLAIM_CONTEXT_EXTENSION,
  type TlsnPolicy,
  type TlsnPresentationVerifier,
  tlsnPolicyHashOf,
  tlsnPolicySchema,
  tlsnSubjectHashOf,
} from '@txpipe/thoth-tlsn';
import { tlsnAttestor } from '@txpipe/thoth-tlsn/attestor';
import { TLSN_CLAIM_CONTEXT_KEY, tlsnClient } from '@txpipe/thoth-tlsn/client';
import { requestReveals, responseReveals } from '@txpipe/thoth-tlsn/disclosure';
import type { TlsnProver } from '@txpipe/thoth-tlsn/prover';
import {
  type ZkFetchPolicy,
  zkFetchPolicyHashOf,
  zkFetchPolicySchema,
  zkFetchSubjectHashOf,
} from '@txpipe/thoth-zk-tls';
import { beforeAll, describe, expect, it } from 'vitest';
import { type B_Claim, pureCircuits } from '../artifacts/mock_attestation_bytes/contract/index.js';
import { jubjubKeyPair, type Submission, submit } from './helpers/acceptance.js';
import {
  APP_ID,
  bytesIdOf,
  DUMMY_SIGNATURE,
  flip,
  makeNotaryKey,
  splitHalves,
} from './helpers/fixtures.js';
import { createPrivateState } from './helpers/private-state.js';
import { MockAttestationBytesSim } from './helpers/sim.js';

const HOST = 'api.example.com';
const URL_ = `https://${HOST}/repos/x`;
const BODY = '{"stars":1234,"forks":56,"owner":{"login":"octocat","email":"private@example.com"}}';
const TIME = 1_700_000_000;

// Two numeric facts and one byte fact, sized for the V=3, B=2, K=24 mock. Typed as both
// kinds' policy: the same object is valid for zkFetch and for tlsn@1.
const policy: TlsnPolicy & ZkFetchPolicy = {
  allowedHosts: ['example.com'],
  slots: [
    { slot: 0, name: 'stars', parse: 'int' },
    { slot: 1, name: 'forks', parse: 'int' },
    { slot: 3, name: 'login', parse: 'bytes' },
  ],
  responseMatches: [
    { type: 'regex', value: '"stars":(?<stars>\\d+)' },
    { type: 'regex', value: '"forks":(?<forks>\\d+)' },
    { type: 'regex', value: '"login":"(?<login>[^"]+)"' },
  ],
  responseRedactions: [
    { jsonPath: '$.stars' },
    { jsonPath: '$.forks' },
    { jsonPath: '$.owner.login' },
  ],
  bodyPolicy: 'ignored',
};

const notaryKeys = [0, 1].map((index) => ({ alg: 'k256', key: `0${2 + index}${'ab'.repeat(32)}` }));

/**
 * A stub of `thoth-tlsn`: a "presentation" is the verifier's JSON output itself, for
 * one notary over one HTTPS exchange, revealed by the real prover-side redaction.
 */
const stubProver = (notary: number): TlsnProver => ({
  prove: async (request) => {
    const sent = `GET /repos/x HTTP/1.1\r\nHost: ${HOST}\r\nConnection: close\r\n\r\n`;
    const received = `HTTP/1.1 200 OK\r\nContent-Length: ${BODY.length}\r\n\r\n${BODY}`;
    const view = (text: string, revealed: readonly (readonly [number, number])[]) => {
      const data = Buffer.from(text);
      const shown = Buffer.alloc(data.length);
      for (const [start, end] of revealed) data.copy(shown, start, start, end);
      return { length: data.length, data: shown.toString('hex'), revealed };
    };
    expect(request.url).toBe(URL_);
    const claimContext = request.context?.[TLSN_CLAIM_CONTEXT_KEY] as string;
    const verified = {
      notaryKey: notaryKeys[notary],
      serverName: HOST,
      time: TIME,
      sent: view(sent, requestReveals(Buffer.from(sent), new Set())),
      received: view(
        received,
        responseReveals(Buffer.from(received), request.responseRedactions ?? []),
      ),
      extensions: [
        { id: Buffer.from(TLSN_CLAIM_CONTEXT_EXTENSION).toString('hex'), value: claimContext },
      ],
    };
    return { presentation: Buffer.from(JSON.stringify(verified)).toString('hex') };
  },
});

const stubVerifier: TlsnPresentationVerifier = {
  verify: async (presentation) => JSON.parse(Buffer.from(presentation, 'hex').toString('utf-8')),
};

// Each operator pins its own notary.
const attestors = [0, 1].map((index) =>
  tlsnAttestor({
    id: `tlsn-attestor-${index}`,
    keyPair: jubjubKeyPair(),
    notaryKey: notaryKeys[index] as { alg: string; key: string },
    verifier: stubVerifier,
  }),
);
// Registry slot 2 is pinned to an operator the app does not query.
const registryKeys = [...attestors.map((attestor) => attestor.publicKey), makeNotaryKey().pk];

const holderSecret = randomBytes(32);
const window = { windowStart: BigInt(TIME - 30), windowEnd: BigInt(TIME + 30) };

/** The claim the honest threshold set signed. */
let honestClaim: Claim<number, number>;

const collectSubmission = async (secret = holderSecret): Promise<Submission> => {
  const client = tlsnClient.init({
    trusted: buildTrustedSet({
      registrySize: registryKeys.length,
      attestors: attestors.map((attestor, registryIndex) => ({
        attestor: descriptorOf(attestor),
        registryIndex,
      })),
    }),
    verifier: jubjubVerifier,
    transport: {
      request: (descriptor, input) => {
        const attestor = attestors.find((candidate) => candidate.id === descriptor.id);
        if (!attestor) {
          throw new Error(`transport: unknown attestor ${descriptor.id}`);
        }
        return attestor.attest(input);
      },
    },
    presentationVerifier: stubVerifier,
    policy,
    appId: APP_ID,
    valueSlots: 3,
    byteSlots: 1,
    provers: { 'tlsn-attestor-0': stubProver(0), 'tlsn-attestor-1': stubProver(1) },
  });
  const { claim, collected } = await client.collect(
    { url: URL_ },
    {
      holder: pureCircuits.holderCommitment(secret),
      ...window,
      threshold: 2,
      expiresAt: Date.now() + 60_000,
      attestorTimeoutMs: 30_000,
    },
  );
  honestClaim = claim;
  const signatures = registryKeys.map(
    (_, slot) =>
      collected.find((entry) => entry.registryIndex === slot)?.attestation.signature ??
      DUMMY_SIGNATURE,
  );
  return { claim: toContractClaim(claim), signatures, commitRand: randomBytes(32) };
};

// A fresh ledger that seals the app id and the policy under both kinds, so the dApp
// accepts a claim from either, with its block time in the window.
const freshLedger = async (appId = APP_ID): Promise<MockAttestationBytesSim> => {
  const sim = await MockAttestationBytesSim.create(
    createPrivateState<B_Claim>(holderSecret),
    registryKeys,
    { appId, policyHashes: [tlsnPolicyHashOf(policy), zkFetchPolicyHashOf(policy)] },
  );
  sim.now = Number(honestClaim.windowStart);
  return sim;
};

describe('tlsn@1 cross-seam acceptance', () => {
  let honest: Submission;

  beforeAll(async () => {
    honest = await collectSubmission();
  });

  it('takes one policy object that both kinds accept, with the same subject', () => {
    expect(() => tlsnPolicySchema.parse(policy)).not.toThrow();
    expect(() => zkFetchPolicySchema.parse(policy)).not.toThrow();
    expect(tlsnSubjectHashOf({ method: 'GET', url: URL_ })).toEqual(
      zkFetchSubjectHashOf({ method: 'GET', url: URL_ }),
    );
    // The law tag differs, so each kind's signatures commit to its own policy hash.
    expect(tlsnPolicyHashOf(policy)).not.toEqual(zkFetchPolicyHashOf(policy));
  });

  it('collects a claim carrying every binding the contract checks', () => {
    expect(honest.claim).toMatchObject({
      appId: APP_ID,
      policyHash: tlsnPolicyHashOf(policy),
      subjectHash: tlsnSubjectHashOf({ method: 'GET', url: URL_ }),
      holder: pureCircuits.holderCommitment(holderSecret),
      ...window,
      present: [true, true, false],
      bytePresent: [true, true],
      values: [1234n, 56n, 0n],
      byteHalves: splitHalves(
        (() => {
          const login = new Uint8Array(32);
          login.set(Buffer.from('octocat'));
          return login;
        })(),
      ),
    });
    expect(honest.signatures[2]).toBe(DUMMY_SIGNATURE);
  });

  it('accepts the honest claim end to end', async () => {
    const sim = await freshLedger();
    await submit(sim, honest, holderSecret);
    expect(sim.ledgerView().B_claimsVault.member(bytesIdOf(honest.claim, honest.commitRand))).toBe(
      true,
    );
  });

  it('refuses a resubmission of the accepted claim under fresh vault randomness', async () => {
    const sim = await freshLedger();
    await submit(sim, honest, holderSecret);
    await expect(
      submit(sim, { ...honest, commitRand: randomBytes(32) }, holderSecret),
    ).rejects.toThrow('Observation replay');
  });

  const otherSecret = randomBytes(32);

  it.each([
    { name: 'a value', mutate: (c: B_Claim) => ({ ...c, values: [1235n, 56n, 0n] }) },
    {
      name: 'the presence mask',
      mutate: (c: B_Claim) => ({ ...c, present: [true, false, false] }),
    },
    {
      name: 'the byte value',
      mutate: (c: B_Claim) => ({
        ...c,
        byteHalves: [
          flip(c.byteHalves[0] ?? new Uint8Array(16), 0),
          c.byteHalves[1] ?? new Uint8Array(16),
        ],
      }),
    },
    {
      // Sealed too, so only the signatures refuse it: tlsn@1 attestors never signed it.
      name: 'the policy, swapped for the zkFetch hash of the same policy',
      mutate: (c: B_Claim) => ({ ...c, policyHash: zkFetchPolicyHashOf(policy) }),
    },
    {
      name: 'the app id',
      mutate: (c: B_Claim) => ({ ...c, appId: flip(c.appId, 0) }),
      sealedAppId: flip(APP_ID, 0),
    },
    {
      name: 'the subject',
      mutate: (c: B_Claim) => ({ ...c, subjectHash: flip(c.subjectHash, 0) }),
    },
    { name: 'the window end', mutate: (c: B_Claim) => ({ ...c, windowEnd: c.windowEnd + 1n }) },
    { name: 'the salt', mutate: (c: B_Claim) => ({ ...c, salt: flip(c.salt, 0) }) },
    {
      name: 'the holder',
      mutate: (c: B_Claim) => ({ ...c, holder: pureCircuits.holderCommitment(otherSecret) }),
      secret: otherSecret,
    },
  ])(
    'rejects the signatures over a claim with $name mutated',
    async ({ mutate, secret, sealedAppId }) => {
      const sim = await freshLedger(sealedAppId);
      await expect(
        submit(sim, { ...honest, claim: mutate(honest.claim) }, secret ?? holderSecret),
      ).rejects.toThrow('Insufficient valid signatures');
    },
  );
});
