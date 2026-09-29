// Parity between the off-chain holder commitment
// (`@thoth/core/claim-context`'s `holderCommitmentOf`) and the compiled
// `holderCommitment` pure circuit.
//
// ADR 0004 binds each claim to a per-claim holder commitment. The client
// derives it off-chain for the claim context and the contract re-derives it
// in-circuit from the caller's secret, so the two must agree byte for byte.
// The compiled pure circuit is the oracle.
import { randomBytes } from 'node:crypto';
import {
  CompactTypeBytes,
  CompactTypeVector,
  persistentHash,
} from '@midnight-ntwrk/compact-runtime';
import { holderCommitmentOf } from '@thoth/core/claim-context';
import { describe, expect, it } from 'vitest';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';

const filled = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);

describe('holderCommitmentOf circuit parity', () => {
  it('matches the holderCommitment circuit for fixed and random secrets', () => {
    for (const secret of [filled(0x00), filled(0xff), filled(0x42), randomBytes(32)]) {
      expect(holderCommitmentOf(secret)).toEqual(pureCircuits.holderCommitment(secret));
    }
  });

  it('gives distinct secrets distinct commitments', () => {
    expect(pureCircuits.holderCommitment(filled(1))).not.toEqual(
      pureCircuits.holderCommitment(filled(2)),
    );
  });

  it('is domain-separated from the vault pseudonym tag', () => {
    // The same hash under deriveHolder's `thoth:holder:v1` tag must not
    // collide with the commitment, so one secret yields unrelated values.
    const secret = filled(7);
    const vaultTag = new Uint8Array(32);
    vaultTag.set(new TextEncoder().encode('thoth:holder:v1'));
    const underVaultTag = persistentHash(new CompactTypeVector(2, new CompactTypeBytes(32)), [
      vaultTag,
      secret,
    ]);

    expect(pureCircuits.holderCommitment(secret)).not.toEqual(underVaultTag);
  });
});
