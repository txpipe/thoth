// Shared 32-byte field encoders for cardano@1 subjects and salts, plus the
// address hash an app pins in-circuit.

import { createHash } from 'node:crypto';

const FIELD_BYTES = 32;

/** The lowercase hex pattern every 32-byte hash uses. */
export const HEX_64 = /^[0-9a-f]{64}$/;

/**
 * Encode text as a 32-byte field: UTF-8, left-aligned and zero-padded, the
 * same direction as the circuit's `pad(32, …)`.
 *
 * @throws if the UTF-8 encoding is longer than 32 bytes.
 */
export const bytes32OfText = (text: string): Uint8Array => {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length > FIELD_BYTES) {
    throw new Error(`text is ${bytes.length} bytes, expected at most ${FIELD_BYTES}`);
  }
  const field = new Uint8Array(FIELD_BYTES);
  field.set(bytes);
  return field;
};

/**
 * Encode a uint32 as a 32-byte field: big-endian, right-aligned and
 * zero-padded.
 *
 * @throws if the value is not an integer from 0 to 2^32-1.
 */
export const bytes32OfUint32 = (value: number): Uint8Array => {
  if (!Number.isInteger(value) || value < 0 || value > 2 ** 32 - 1) {
    throw new Error(`expected a uint32, got ${value}`);
  }
  const field = new Uint8Array(FIELD_BYTES);
  field[28] = (value >>> 24) & 0xff;
  field[29] = (value >>> 16) & 0xff;
  field[30] = (value >>> 8) & 0xff;
  field[31] = value & 0xff;
  return field;
};

/**
 * Decode a 64-character lowercase hex hash into its 32 bytes.
 *
 * @throws if the input is not 64 lowercase hex characters.
 */
export const bytes32OfHex = (hex: string): Uint8Array => {
  if (!HEX_64.test(hex)) {
    throw new Error(`expected 64 lowercase hex characters, got ${hex}`);
  }
  return new Uint8Array(Buffer.from(hex, 'hex'));
};

/**
 * Hash a Cardano address to its subject field: SHA-256 of the lowercase
 * bech32 string. An app pins this value to check an observation's address.
 */
export const cardanoAddressHashOf = (address: string): Uint8Array =>
  new Uint8Array(createHash('sha256').update(address.toLowerCase(), 'utf-8').digest());
