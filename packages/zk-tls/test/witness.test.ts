// Test-key witnesses: local secp256k1 keys stand in for Reclaim witnesses and
// sign provider claim data. Drives the zkFetch attestor offline and
// deterministically: intent binding, request binding, observation window,
// witness pinning, and the common claim two witnesses agree on.
import type { Claim, FlatMessage } from '@thoth/core/claim';
import { claimToMessage } from '@thoth/core/claim';
import {
  deriveClaimFromEvidence,
  INTENT_CONTEXT_KEY,
  intentDigestOf,
  parsedEvidenceView,
  policyDigestOf,
  requestBindingOf,
  type ZkFetchEvidence,
  type ZkFetchIntent,
  type ZkFetchPolicy,
} from '@thoth/zk-tls';
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';
import { describe, expect, it } from 'vitest';
import { type Observation, type TestWitness, testWitness } from './helpers/witness.js';

const alice = testWitness(`0x${'11'.repeat(32)}`);
const bob = testWitness(`0x${'22'.repeat(32)}`);

const REQUEST = { url: 'https://api.example.com/v1/account', method: 'GET', body: '' };
const OBSERVED_AT = 1_786_000_000;

const policy = (...pinned: string[]): ZkFetchPolicy => ({
  allowedHosts: ['api.example.com'],
  maxWindowSeconds: 120,
  attestorAddresses: pinned.length > 0 ? pinned : [alice.address, bob.address],
  slots: [
    { slot: 0, name: 'balance', parse: 'int' },
    { slot: 1, name: 'score', parse: 'float', optional: true },
  ],
});

const intentFor = (p: ZkFetchPolicy, overrides: Partial<ZkFetchIntent> = {}): ZkFetchIntent => ({
  policyDigest: policyDigestOf(p),
  requestBinding: requestBindingOf(REQUEST),
  holder: new Uint8Array(32).fill(0xaa),
  nonce: new Uint8Array(32).fill(0x5e),
  windowStart: BigInt(OBSERVED_AT - 60),
  windowEnd: BigInt(OBSERVED_AT + 60),
  ...overrides,
});

/** A witnessed session bound to `intent`, unless overridden. */
const observe = (
  witness: TestWitness,
  intent: ZkFetchIntent,
  overrides: Partial<Observation> = {},
): Promise<ZkFetchEvidence> =>
  witness.sign({
    values: { balance: '0', score: '7.6' },
    timestampS: OBSERVED_AT,
    parameters: REQUEST,
    context: { [INTENT_CONTEXT_KEY]: intentDigestOf(intent) },
    ...overrides,
  });

const attestor = zkFetchAttestor({
  id: 'attestor-0',
  keyPair: {
    publicKey: 'pk-0',
    signer: { sign: (message: FlatMessage): string => `sig:${message.join(',')}` },
  },
  registryIndex: 0,
});

const derive = (evidence: ZkFetchEvidence, p: ZkFetchPolicy, intent: ZkFetchIntent): Claim<3> =>
  deriveClaimFromEvidence({
    verified: parsedEvidenceView(evidence),
    policy: p,
    intent,
    valueSlots: 3,
  });

const attest = (
  evidence: ZkFetchEvidence,
  p: ZkFetchPolicy,
  intent: ZkFetchIntent,
  claim: Claim<3> = derive(evidence, p, intent),
) =>
  attestor.attest({ policy: p, evidence, claim } as unknown as Parameters<
    typeof attestor.attest
  >[0]);

describe('test-key witness', () => {
  it('derives the Ethereum address of its key', () => {
    // The well-known address of secp256k1 key 0x11…11.
    expect(alice.address).toBe('0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a');
    expect(bob.address).not.toBe(alice.address);
  });

  it('produces evidence carrying the chosen values, timestamp, parameters and context', async () => {
    const evidence = await observe(alice, intentFor(policy()), { timestampS: 1_786_000_123 });
    expect(evidence.attestorAddress).toBe(alice.address);
    expect(evidence.claim.timestampS).toBe(1_786_000_123);
    expect(JSON.parse(evidence.claim.parameters)).toMatchObject(REQUEST);
    const context = JSON.parse(evidence.claim.context);
    expect(context[INTENT_CONTEXT_KEY]).toBe(intentDigestOf(intentFor(policy())));
    expect(context.extractedParameters).toEqual({ balance: '0', score: '7.6' });
  });

  it('is deterministic across runs', async () => {
    // RFC 6979 signing: the same observation always yields this signature.
    const evidence = await alice.sign({
      values: { balance: '0', score: '7.6' },
      timestampS: OBSERVED_AT,
      parameters: REQUEST,
      context: { intent: 'ab'.repeat(32) },
    });
    expect(evidence.signatureHex).toBe(
      '0xc8f99f97782ae3983f0236964238b2dc2f84944f9da2d4fc20e25ead54cd188652fe9ef0d2201e4c73c90e64e72e5f4c1737978c59b95e46c7a5f0fec7385e3a1b',
    );
  });
});

describe('zkFetch attestor', () => {
  it('signs the common claim for evidence bound to the intent', async () => {
    const p = policy();
    const intent = intentFor(p);
    const attestation = await attest(await observe(alice, intent), p, intent);
    expect(attestation.claim).toMatchObject({
      version: 1n,
      kind: 1n,
      policyDigest: intent.policyDigest,
      requestBinding: intent.requestBinding,
      holder: intent.holder,
      nonce: intent.nonce,
      windowStart: intent.windowStart,
      windowEnd: intent.windowEnd,
    });
    // A present zero stays present.
    expect(attestation.claim.present).toEqual([true, true, false]);
    expect(attestation.claim.values).toEqual([0n, 8n, 0n]);
    expect(attestation.message).toHaveLength(14);
    expect(attestation.signature).toMatch(/^sig:/);
  });

  it('derives byte-identical claims from two witnesses observing the same intent', async () => {
    const p = policy();
    const intent = intentFor(p);
    const fromAlice = await attest(await observe(alice, intent), p, intent);
    const fromBob = await attest(
      await observe(bob, intent, { timestampS: OBSERVED_AT + 30 }),
      p,
      intent,
    );
    expect(fromBob.message).toEqual(fromAlice.message);
  });

  it('derives a different message when any claim input changes', async () => {
    const p = policy();
    const intent = intentFor(p);
    const base = claimToMessage(derive(await observe(alice, intent), p, intent));
    const other = policy(alice.address);
    const variants = [
      derive(await observe(alice, intent, { values: { balance: '1', score: '7.6' } }), p, intent),
      derive(await observe(alice, intent, { values: { balance: '0' } }), p, intent),
      derive(await observe(alice, intent), other, {
        ...intent,
        policyDigest: policyDigestOf(other),
      }),
      derive(await observe(alice, intent), p, { ...intent, holder: new Uint8Array(32).fill(1) }),
      derive(await observe(alice, intent), p, { ...intent, requestBinding: new Uint8Array(32) }),
      derive(await observe(alice, intent), p, { ...intent, windowEnd: intent.windowEnd + 1n }),
    ];
    for (const variant of variants) {
      expect(claimToMessage(variant)).not.toEqual(base);
    }
  });

  it('rejects a witness the policy does not pin', async () => {
    const p = policy(alice.address);
    const intent = intentFor(p);
    await expect(attest(await observe(bob, intent), p, intent)).rejects.toThrow(
      /not in pinned witnesses/,
    );
  });

  it('rejects evidence claiming another witness address', async () => {
    const p = policy();
    const intent = intentFor(p);
    const forged = { ...(await observe(bob, intent)), attestorAddress: alice.address };
    await expect(attest(forged, p, intent)).rejects.toThrow(/Invalid claim signature/);
  });

  it('rejects evidence whose signed context lacks the intent digest', async () => {
    const p = policy();
    const intent = intentFor(p);
    const unbound = await observe(alice, intent, { context: {} });
    await expect(attest(unbound, p, intent)).rejects.toThrow(/intent digest/);
  });

  it('rejects evidence bound to a different intent', async () => {
    const p = policy();
    const intent = intentFor(p);
    const other = await observe(alice, { ...intent, nonce: new Uint8Array(32).fill(1) });
    await expect(attest(other, p, intent)).rejects.toThrow(/intent digest/);
  });

  it('rejects evidence whose signed request does not match the request binding', async () => {
    const p = policy();
    const intent = intentFor(p);
    const posted = await observe(alice, intent, { parameters: { ...REQUEST, body: '{"a":1}' } });
    await expect(attest(posted, p, intent)).rejects.toThrow(/request binding/);
  });

  it('rejects an observation outside the window', async () => {
    const p = policy();
    const intent = intentFor(p);
    for (const timestampS of [OBSERVED_AT - 61, OBSERVED_AT + 61]) {
      const stale = await observe(alice, intent, { timestampS });
      await expect(attest(stale, p, intent)).rejects.toThrow(/outside the intent window/);
    }
  });

  it('rejects an inverted window', async () => {
    const p = policy();
    const intent = intentFor(p, {
      windowStart: BigInt(OBSERVED_AT),
      windowEnd: BigInt(OBSERVED_AT - 1),
    });
    await expect(attest(await observe(alice, intent), p, intent)).rejects.toThrow(/inverted/);
  });

  it('rejects a window longer than the policy permits', async () => {
    const p = { ...policy(), maxWindowSeconds: 119 };
    const intent = intentFor(p);
    await expect(attest(await observe(alice, intent), p, intent)).rejects.toThrow(
      /policy maximum of 119 seconds/,
    );
  });

  it('rejects a missing required disclosure', async () => {
    const p = policy();
    const intent = intentFor(p);
    const missing = await observe(alice, intent, { values: { score: '7.6' } });
    await expect(attest(missing, p, intent)).rejects.toThrow(/not disclose a parseable value/);
  });

  it('rejects a proposed claim under a different policy digest', async () => {
    const p = policy();
    // The session is bound to an intent naming another policy; the attestor
    // signs only the digest of the policy it received.
    const intent = intentFor(p, { policyDigest: new Uint8Array(32).fill(7) });
    const evidence = await observe(alice, intent);
    const proposed = { ...derive(evidence, p, intent), policyDigest: intent.policyDigest };
    await expect(attest(evidence, p, intent, proposed)).rejects.toThrow(
      /does not match the claim derived/,
    );
  });
});
