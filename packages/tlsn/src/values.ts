// Parse rules: how a string from the response becomes a claim value. They follow the
// zkFetch kind's rules exactly, so the same field yields the same value under both kinds.

/** How a slot turns the response field's text into a claim value. */
export type TlsnParseRule = 'int' | 'float' | 'bytes' | 'hex' | 'base64';

/** The parse rules that fill a 32-byte claim slot. */
export type TlsnByteRule = 'bytes' | 'hex' | 'base64';

/** Whether a parse rule targets a byte slot rather than a numeric one. */
export const isByteRule = (rule: TlsnParseRule): rule is TlsnByteRule =>
  rule === 'bytes' || rule === 'hex' || rule === 'base64';

/** The contract's `Uint<64>` holds only values below this exclusive bound. */
const UINT64_LIMIT = 1n << 64n;

/** The fixed width of a claim byte value. */
export const BYTE_VALUE_BYTES = 32;

/** Parse an unsigned decimal, round halves up, and require a Uint<64> result. */
const parseDecimalUint64 = (value: string): bigint | null => {
  const match = /^([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/.exec(value);
  if (match?.[1] === undefined || match[0] !== value) {
    return null;
  }
  const whole = match[1];
  const fraction = match[2] ?? '';
  const exponent = BigInt(match[3] ?? '0');
  const digits = (whole + fraction).replace(/^0+/, '');
  if (digits.length === 0) {
    return 0n;
  }
  const integerDigitCount = BigInt(digits.length) - BigInt(fraction.length) + exponent;
  if (integerDigitCount < 0n) {
    return 0n;
  }
  // Uint<64> has at most 20 digits; reject before padding enormous exponents.
  if (integerDigitCount > 20n) {
    return null;
  }
  const position = Number(integerDigitCount);
  const integerDigits = digits.slice(0, position).padEnd(position, '0') || '0';
  const roundUp = (digits[position] ?? '0') >= '5';
  const rounded = BigInt(integerDigits) + (roundUp ? 1n : 0n);
  return rounded < UINT64_LIMIT ? rounded : null;
};

/** Decode hex with an optional `0x` prefix; separators and whitespace make it invalid. */
const decodeHex = (value: string): Uint8Array | null => {
  const digits = value.replace(/^0[xX]/, '');
  if (digits.length === 0 || digits.length % 2 !== 0 || digits.length > 2 * BYTE_VALUE_BYTES) {
    return null;
  }
  if (!/^[0-9a-fA-F]+$/.test(digits)) {
    return null;
  }
  return new Uint8Array(Buffer.from(digits, 'hex'));
};

/** Decode standard or URL-safe base64; partial padding and non-canonical trailing bits are invalid. */
const decodeBase64 = (value: string): Uint8Array | null => {
  const match = /^([A-Za-z0-9+/_-]+)(=*)$/.exec(value);
  const body = match?.[1];
  const padding = match?.[2] ?? '';
  if (body === undefined || padding.length > 2) {
    return null;
  }
  if (padding.length > 0 && (body.length + padding.length) % 4 !== 0) {
    return null;
  }
  const canonical = body.replace(/-/g, '+').replace(/_/g, '/');
  if (canonical.length > 43) {
    return null;
  }
  const bytes = Buffer.from(canonical, 'base64');
  if (bytes.toString('base64').replace(/=+$/, '') !== canonical) {
    return null;
  }
  return new Uint8Array(bytes);
};

/** Decode a string under a byte rule, unpadded; `null` when not a valid encoding. */
const decodeByteValue = (value: string, rule: TlsnByteRule): Uint8Array | null => {
  switch (rule) {
    case 'bytes':
      return new TextEncoder().encode(value);
    case 'hex':
      return decodeHex(value);
    case 'base64':
      return decodeBase64(value);
  }
};

/**
 * Parse a response field's text into a claim value under a rule and, for byte
 * rules, an exact `length` pin.
 *
 * `null` means not certifiable: a numeric reading outside `[0, 2^64)` or
 * outside the rule's grammar, or a byte reading that is not a valid encoding,
 * misses its `length`, or does not fit 32 bytes.
 */
export const parseFieldValue = (
  value: string,
  rule: TlsnParseRule,
  length?: number,
): bigint | Uint8Array | null => {
  switch (rule) {
    case 'int': {
      if (!/^(?:[0-9]+|0[xX][0-9a-fA-F]+)$/.test(value)) {
        return null;
      }
      const big = BigInt(value);
      return big < UINT64_LIMIT ? big : null;
    }
    case 'float':
      return parseDecimalUint64(value);
    case 'bytes':
    case 'hex':
    case 'base64': {
      const bytes = decodeByteValue(value, rule);
      if (bytes === null || bytes.length > BYTE_VALUE_BYTES) {
        return null;
      }
      if (length !== undefined && bytes.length !== length) {
        return null;
      }
      const padded = new Uint8Array(BYTE_VALUE_BYTES);
      padded.set(bytes);
      return padded;
    }
  }
};
