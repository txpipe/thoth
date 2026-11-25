// Parity between the off-chain claim-context subject hash
// (`@txpipe/thoth-core/claim-context`'s `subjectHashOf`) and the compiled circuit's
// `persistentHash<Subject>` over a struct of four `Bytes<32>` fields.
//
// ADR 0001 binds a claim to its source with an in-circuit hash, so an app
// recomputes the subject hash in-circuit from private fields. That binding is
// only sound if the off-chain helper and the circuit agree, and a pinned
// literal alone cannot fail if the compiler's struct layout changes. Here the
// compiled pure circuit is the oracle.
import { subjectHashOf } from '@txpipe/thoth-core/claim-context';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { anyBytes32 } from '../../core/test/arbitraries.js';
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

  it('matches for every four-field subject', () => {
    fc.assert(
      fc.property(
        fc.record({
          method: anyBytes32(),
          host: anyBytes32(),
          path: anyBytes32(),
          body: anyBytes32(),
        }),
        (subject) => {
          const { method, host, path, body } = subject;
          expect(subjectHashOf([method, host, path, body])).toEqual(
            pureCircuits.subjectHash(subject),
          );
        },
      ),
    );
  });
});
