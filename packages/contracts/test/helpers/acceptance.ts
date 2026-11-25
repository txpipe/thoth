// Shared helpers for cross-seam acceptance suites: signature-slot packing and
// fresh bytes-mock ledgers.
import type { JubjubPoint, JubjubSchnorrSignature } from '@midnight-ntwrk/compact-runtime';
import type { B_Claim } from '../../artifacts/mock_attestation_bytes/contract/index.js';
import { APP_ID, DUMMY_SIGNATURE } from './fixtures.js';
import { createPrivateState } from './private-state.js';
import { MockAttestationBytesSim } from './sim.js';

/** Lay collected signatures out at their registry slots, filling absent slots with a dummy. */
export const packSignatures = (
  registrySize: number,
  collected: readonly {
    readonly registryIndex: number;
    readonly attestation: { readonly signature: JubjubSchnorrSignature };
  }[],
): JubjubSchnorrSignature[] =>
  Array.from(
    { length: registrySize },
    (_, slot) =>
      collected.find((entry) => entry.registryIndex === slot)?.attestation.signature ??
      DUMMY_SIGNATURE,
  );

/** Deploy a fresh bytes-mock ledger sealing `appId` and `policyHashes` at block time `now`. */
export const freshBytesLedger = async (options: {
  readonly holderSecret: Uint8Array;
  readonly registryKeys: JubjubPoint[];
  readonly appId?: Uint8Array;
  readonly policyHashes: readonly Uint8Array[];
  readonly now: bigint | number;
}): Promise<MockAttestationBytesSim> => {
  const sim = await MockAttestationBytesSim.create(
    createPrivateState<B_Claim>(options.holderSecret),
    options.registryKeys,
    { appId: options.appId ?? APP_ID, policyHashes: options.policyHashes },
  );
  sim.now = Number(options.now);
  return sim;
};
