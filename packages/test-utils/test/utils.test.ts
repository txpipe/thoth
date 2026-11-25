// Unit tests for the shared private test utilities (`@txpipe/thoth-test-utils`).
import {
  CompactTypeField,
  CompactTypeVector,
  jubjubSchnorrVerify,
} from '@midnight-ntwrk/compact-runtime';
import { describe, expect, it } from 'vitest';
import { filled, fullSpan, hex, le, padded32, sha256 } from '../src/bytes.js';
import { parseEnvList, parseEnvUrl } from '../src/env.js';
import { collectedSlots, fakeKeyPair, fakeVerifier, inMemoryTransport } from '../src/harness.js';
import { jubjubKeyPair, signJubjubMessage } from '../src/jubjub.js';

describe('bytes', () => {
  it('fills 32 bytes by default and encodes lowercase hex', () => {
    expect(filled(0xab)).toEqual(new Uint8Array(32).fill(0xab));
    expect(hex(filled(0xab, 2))).toBe('abab');
  });

  it('computes SHA-256 of UTF-8 text', () => {
    expect(sha256('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('builds a 32-byte full span and decodes little-endian integers', () => {
    const span = fullSpan();
    expect(span).toHaveLength(32);
    expect(span[0]).toBe(0);
    expect(span[31]).toBe(31);
    expect(le(Uint8Array.from([1, 2]))).toBe(1n + 2n * 256n);
  });

  it('zero-pads strings and byte arrays to 32 bytes and rejects longer inputs', () => {
    const fromStr = padded32('ab');
    expect(fromStr.slice(0, 2)).toEqual(Uint8Array.from([0x61, 0x62]));
    expect(fromStr.slice(2)).toEqual(new Uint8Array(30));
    expect(padded32(Uint8Array.from([0x61, 0x62]))).toEqual(fromStr);
    expect(() => padded32('a'.repeat(33))).toThrow(/32-byte limit/);
    expect(() => padded32(new Uint8Array(33))).toThrow(/32-byte limit/);
  });
});

describe('env', () => {
  it('returns empty results for unset, blank, or comma-only values', () => {
    for (const raw of [undefined, '', '   ', ',', ' , , ']) {
      expect(parseEnvList('WITNESS_URLS', { WITNESS_URLS: raw })).toEqual([]);
      expect(parseEnvUrl('DOLOS_URL', { DOLOS_URL: raw })).toBe('');
    }
  });

  it('trims populated list and URL entries', () => {
    expect(parseEnvList('WITNESS_URLS', { WITNESS_URLS: ' ws://a , , ws://b ' })).toEqual([
      'ws://a',
      'ws://b',
    ]);
    expect(parseEnvUrl('DOLOS_URL', { DOLOS_URL: ' https://example.com ' })).toBe(
      'https://example.com',
    );
  });
});

describe('harness', () => {
  it('signs and verifies fake signatures and honors rejected ids', () => {
    const kp = fakeKeyPair('a');
    const sig = kp.signer.sign([1n, 2n]);
    expect(fakeVerifier().verify(kp.publicKey, [1n, 2n], sig)).toBe(true);
    expect(fakeVerifier(['a']).verify(kp.publicKey, [1n, 2n], sig)).toBe(false);
  });

  it('dispatches in-memory transport requests by attestor id', async () => {
    const transport = inMemoryTransport([{ id: 'a', attest: async (n: number) => n + 1 }]);
    await expect(transport.request({ id: 'a' }, 41)).resolves.toBe(42);
    expect(() => transport.request({ id: 'missing' }, 1)).toThrow(/unknown attestor missing/);
  });

  it('extracts collected registry slots', () => {
    expect(collectedSlots({ collected: [{ registryIndex: 2 }, { registryIndex: 0 }] })).toEqual([
      2, 0,
    ]);
  });
});

describe('jubjub', () => {
  it('builds a key pair whose signatures verify against its public key', () => {
    const kp = jubjubKeyPair(17n);
    const message = [1n, 2n];
    const type = new CompactTypeVector(message.length, CompactTypeField);
    expect(jubjubSchnorrVerify(type, message, kp.publicKey, kp.signer.sign(message))).toBe(true);
    expect(jubjubSchnorrVerify(type, message, kp.publicKey, signJubjubMessage(17n, message))).toBe(
      true,
    );
  });
});
