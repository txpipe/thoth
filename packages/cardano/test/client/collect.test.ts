// Unit tests for the cardano@1 client (`@txpipe/thoth-cardano/client`): one read, one
// derived proposal, a threshold of vetted attestations, and the failure paths.

import { CARDANO_LIMITS, type CardanoDefinition, type CardanoPolicy } from '@txpipe/thoth-cardano';
import { cardanoAttestor } from '@txpipe/thoth-cardano/attestor';
import {
  type CardanoCollectOptions,
  CardanoThresholdError,
  cardanoClient,
} from '@txpipe/thoth-cardano/client';
import type { AttestationVerifier, AttestorTransport } from '@txpipe/thoth-client';
import { buildTrustedSet } from '@txpipe/thoth-client';
import type { Attestation } from '@txpipe/thoth-core';
import {
  collectedSlots,
  type FakePublicKey,
  type FakeSignature,
  fakeKeyPair,
  fakeVerifier,
  inMemoryTransport,
  trustedSetOf,
} from '@txpipe/thoth-test-utils/harness';
import { describe, expect, it } from 'vitest';
import { APP_ID, claimFor, HOLDER, LOCATOR, OBSERVATION, POLICY } from '../output/fixtures.js';

type FakeAttestor = ReturnType<typeof makeAttestor>;

const makeAttestor = (id: string, observation: typeof OBSERVATION = OBSERVATION) =>
  cardanoAttestor({ id, keyPair: fakeKeyPair(id), read: () => observation });

const trustedOf = (attestors: FakeAttestor[]) =>
  trustedSetOf(buildTrustedSet, attestors, { registrySize: 3 });

const expectedClaim = claimFor();

const options = (overrides: Partial<CardanoCollectOptions> = {}) => ({
  holder: HOLDER,
  expiresAt: Date.now() + 60_000,
  threshold: 2,
  attestorTimeoutMs: 5_000,
  ...overrides,
});

const clientFor = (
  attestors: FakeAttestor[],
  parts: {
    transport?: AttestorTransport<CardanoDefinition, FakePublicKey, FakeSignature>;
    verifier?: AttestationVerifier<FakePublicKey, FakeSignature>;
    read?: () => typeof OBSERVATION | Promise<typeof OBSERVATION>;
  } = {},
) =>
  cardanoClient.init({
    trusted: trustedOf(attestors),
    transport: parts.transport ?? inMemoryTransport(attestors),
    verifier: parts.verifier ?? fakeVerifier(),
    policy: POLICY,
    appId: APP_ID,
    valueSlots: 5,
    byteSlots: 1,
    read: parts.read ?? (() => OBSERVATION),
  });

describe('cardanoClient', () => {
  it('collects a threshold of attestations over the derived claim', async () => {
    const attestors = [makeAttestor('attestor-0'), makeAttestor('attestor-1')];
    const attestment = await clientFor(attestors).collect(LOCATOR, options());

    expect(attestment.claim).toEqual(expectedClaim);
    expect(attestment.claim.appId).toEqual(APP_ID);
    expect(attestment.claim.holder).toEqual(HOLDER);
    expect(collectedSlots(attestment)).toEqual([0, 1]);
    expect(attestment.failures).toEqual([]);
  });

  it('rejects the whole collection when the threshold is not met', async () => {
    const attestors = [makeAttestor('attestor-0'), makeAttestor('attestor-1')];
    const transport = inMemoryTransport(attestors);
    const oneDown: AttestorTransport<CardanoDefinition, FakePublicKey, FakeSignature> = {
      request: (descriptor, input) => {
        if (descriptor.id === 'attestor-1') {
          throw new Error('attestor down');
        }
        return transport.request(descriptor, input);
      },
    };

    const error = await clientFor(attestors, { transport: oneDown })
      .collect(LOCATOR, options())
      .catch((failure: unknown) => failure);

    expect(error).toBeInstanceOf(CardanoThresholdError);
    expect(error).toMatchObject({
      reason: 'threshold',
      failures: [{ registryIndex: 1, reason: 'attestation' }],
    });
  });

  it('recovers from a timed-out attestor to meet the threshold', async () => {
    const attestors = [makeAttestor('attestor-0'), makeAttestor('attestor-1')];
    const transport = inMemoryTransport(attestors);
    const slow: AttestorTransport<CardanoDefinition, FakePublicKey, FakeSignature> = {
      request: (descriptor, input) =>
        descriptor.id === 'attestor-0'
          ? new Promise<Attestation<typeof expectedClaim, FakePublicKey, FakeSignature>>(() => {})
          : transport.request(descriptor, input),
    };

    const attestment = await clientFor(attestors, { transport: slow }).collect(
      LOCATOR,
      options({ threshold: 1, attestorTimeoutMs: 10, attestorIds: ['attestor-0', 'attestor-1'] }),
    );

    expect(collectedSlots(attestment)).toEqual([1]);
    expect(attestment.failures).toEqual([{ registryIndex: 0, reason: 'timeout' }]);
  });

  it('returns at the threshold without waiting for the remaining candidates', async () => {
    const attestors = [
      makeAttestor('attestor-0'),
      makeAttestor('attestor-1'),
      makeAttestor('attestor-2'),
    ];
    const transport = inMemoryTransport(attestors);
    const slow: AttestorTransport<CardanoDefinition, FakePublicKey, FakeSignature> = {
      request: (descriptor, input) =>
        descriptor.id === 'attestor-2'
          ? new Promise<Attestation<typeof expectedClaim, FakePublicKey, FakeSignature>>(() => {})
          : transport.request(descriptor, input),
    };

    const attestment = await clientFor(attestors, { transport: slow }).collect(
      LOCATOR,
      options({ threshold: 1, attestorTimeoutMs: 5_000 }),
    );

    expect(collectedSlots(attestment)).toEqual([0]);
    expect(attestment.failures).toEqual([]);
  });

  it('drops an attestor that signs another claim', async () => {
    const attestors = [makeAttestor('attestor-0'), makeAttestor('attestor-1')];
    const transport = inMemoryTransport(attestors);
    const tampered: AttestorTransport<CardanoDefinition, FakePublicKey, FakeSignature> = {
      request: async (descriptor, input) => {
        const attestation = await transport.request(descriptor, input);
        if (descriptor.id !== 'attestor-1') {
          return attestation;
        }
        return {
          ...attestation,
          claim: {
            ...attestation.claim,
            values: attestation.claim.values.map((value, index) =>
              index === 0 ? value + 1n : value,
            ),
          },
        };
      },
    };

    const attestment = await clientFor(attestors, { transport: tampered }).collect(
      LOCATOR,
      options({ threshold: 1, attestorIds: ['attestor-1', 'attestor-0'] }),
    );

    expect(collectedSlots(attestment)).toEqual([0]);
    expect(attestment.failures).toEqual([{ registryIndex: 1, reason: 'attestation' }]);
  });

  it('drops an attestor whose read derives another claim', async () => {
    // A fork: attestor 1 saw the event in another block, so its subject differs.
    const forked = {
      ...OBSERVATION,
      block: { ...OBSERVATION.block, hash: 'ef'.repeat(32) },
    };
    const attestors = [makeAttestor('attestor-0'), makeAttestor('attestor-1', forked)];

    const error = await clientFor(attestors)
      .collect(LOCATOR, options())
      .catch((failure: unknown) => failure);

    expect(error).toBeInstanceOf(CardanoThresholdError);
    expect(error).toMatchObject({
      reason: 'threshold',
      failures: [{ registryIndex: 1, reason: 'attestation' }],
    });
  });

  it('drops an attestor whose signature does not verify', async () => {
    const attestors = [makeAttestor('attestor-0'), makeAttestor('attestor-1')];
    const attestment = await clientFor(attestors, {
      verifier: fakeVerifier(['attestor-1']),
    }).collect(LOCATOR, options({ threshold: 1, attestorIds: ['attestor-1', 'attestor-0'] }));

    expect(collectedSlots(attestment)).toEqual([0]);
    expect(attestment.failures).toEqual([{ registryIndex: 1, reason: 'attestation' }]);
  });

  it('rejects invalid options with a safe reason', async () => {
    const attestors = [makeAttestor('attestor-0'), makeAttestor('attestor-1')];
    const client = clientFor(attestors);

    for (const invalid of [
      options({ threshold: 3 }),
      options({ attestorTimeoutMs: 0 }),
      options({ attestorIds: ['missing'] }),
    ]) {
      const error = await client.collect(LOCATOR, invalid).catch((failure: unknown) => failure);
      expect(error).toBeInstanceOf(CardanoThresholdError);
      expect(error).toMatchObject({ reason: 'invalid-options' });
    }
  });

  it('rejects an expired collection', async () => {
    const attestors = [makeAttestor('attestor-0'), makeAttestor('attestor-1')];
    const error = await clientFor(attestors)
      .collect(LOCATOR, options({ expiresAt: Date.now() - 1 }))
      .catch((failure: unknown) => failure);

    expect(error).toBeInstanceOf(CardanoThresholdError);
    expect(error).toMatchObject({ reason: 'expired' });
  });

  it('rejects as expired when its own read outlives the deadline', async () => {
    const attestors = [makeAttestor('attestor-0'), makeAttestor('attestor-1')];
    const client = clientFor(attestors, { read: () => new Promise(() => {}) });

    const error = await client
      .collect(LOCATOR, options({ expiresAt: Date.now() + 50 }))
      .catch((failure: unknown) => failure);

    expect(error).toBeInstanceOf(CardanoThresholdError);
    expect(error).toMatchObject({ reason: 'expired' });
  });

  it('does not hide a failed read behind a threshold error', async () => {
    const attestors = [makeAttestor('attestor-0'), makeAttestor('attestor-1')];
    const client = clientFor(attestors, {
      read: () => {
        throw new Error('read failed');
      },
    });

    await expect(client.collect(LOCATOR, options())).rejects.toThrow('read failed');
  });

  it('rejects its own read that is not at the policy address', async () => {
    const attestors = [makeAttestor('attestor-0')];
    const client = clientFor(attestors, {
      read: () => ({
        ...OBSERVATION,
        output: { ...OBSERVATION.output, address: `addr_test1${'p'.repeat(53)}` },
      }),
    });

    await expect(client.collect(LOCATOR, options({ threshold: 1 }))).rejects.toThrow(
      'is not the policy address',
    );
  });

  it('rejects at init a policy whose slots do not fit the claim size', () => {
    const single = [makeAttestor('attestor-0')];
    expect(() =>
      cardanoClient.init({
        trusted: trustedOf(single),
        transport: inMemoryTransport(single),
        verifier: fakeVerifier(),
        policy: POLICY,
        appId: APP_ID,
        valueSlots: 2,
        byteSlots: 0,
        read: () => OBSERVATION,
      }),
    ).toThrow("outside the claim's 2 slots");
  });

  it('rejects a byte slot count above the limit at init', () => {
    const single = [makeAttestor('attestor-0')];
    expect(() =>
      cardanoClient.init({
        trusted: trustedOf(single),
        transport: inMemoryTransport(single),
        verifier: fakeVerifier(),
        policy: POLICY,
        appId: APP_ID,
        valueSlots: 5,
        byteSlots: CARDANO_LIMITS.byteSlots + 1,
        read: () => OBSERVATION,
      }),
    ).toThrow();
  });

  it('rejects a value slot count above the limit at init', () => {
    const numericOnly: CardanoPolicy = { ...POLICY, slots: [{ slot: 0, name: 'lovelace' }] };
    const single = [makeAttestor('attestor-0')];
    expect(() =>
      cardanoClient.init({
        trusted: trustedOf(single),
        transport: inMemoryTransport(single),
        verifier: fakeVerifier(),
        policy: numericOnly,
        appId: APP_ID,
        valueSlots: CARDANO_LIMITS.valueSlots + 1,
        byteSlots: 0,
        read: () => OBSERVATION,
      }),
    ).toThrow();
  });

  it('validates the locator before reading', async () => {
    let reads = 0;
    const client = clientFor([makeAttestor('attestor-0')], {
      read: () => {
        reads += 1;
        return OBSERVATION;
      },
    });

    await expect(
      client.collect(
        { ...LOCATOR, txHash: LOCATOR.txHash.toUpperCase() },
        options({ threshold: 1 }),
      ),
    ).rejects.toThrow('64 lowercase hex');
    expect(reads).toBe(0);
  });
});
