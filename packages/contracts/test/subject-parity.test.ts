// Parity between the off-chain claim-context subject hash
// (`@thoth/core/claim-context`'s `subjectHashOf`) and the compiled circuit's
// `persistentHash<Subject>` over a struct of four `Bytes<32>` fields.
//
// ADR 0001 binds a claim to its source with an in-circuit hash, so an app
// recomputes the subject hash in-circuit from private fields. That binding is
// only sound if the off-chain helper and the circuit agree, and a pinned
// literal alone cannot fail if the compiler's struct layout changes. Here the
// compiled pure circuit is the oracle.
import { subjectHashOf } from '@thoth/core/claim-context';
import { describe, expect, it } from 'vitest';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';

const filled = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);

describe('subjectHashOf circuit parity', () => {
  it('matches persistentHash<Subject> for the struct the pinned vector came from', () => {
    const method = filled(1);
    const host = filled(2);
    const path = filled(3);
    const body = filled(4);

    expect(subjectHashOf([method, host, path, body])).toEqual(
      pureCircuits.subjectHash({ method, host, path, body }),
    );
  });

  it('matches for arbitrary field values', () => {
    const method = filled(0x9a);
    const host = filled(0x00);
    const path = filled(0xff);
    const body = filled(0x42);

    expect(subjectHashOf([method, host, path, body])).toEqual(
      pureCircuits.subjectHash({ method, host, path, body }),
    );
  });
});
