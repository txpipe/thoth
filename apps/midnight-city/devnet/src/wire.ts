// JSON for Thoth values over HTTP: bigints and byte arrays survive the round trip.

/**
 * Encode a value as JSON, tagging bigints and byte arrays.
 *
 * @param value - the value.
 * @returns its JSON text.
 */
export const encode = (value: unknown): string =>
  // `this[key]` is the raw value: JSON.stringify has already applied a Buffer's toJSON to `v`.
  JSON.stringify(value, function (this: Record<string, unknown>, key: string, v: unknown) {
    const raw = this[key];
    if (typeof raw === 'bigint') {
      return { $bigint: raw.toString() };
    }
    if (raw instanceof Uint8Array) {
      return { $bytes: Buffer.from(raw).toString('hex') };
    }
    return v;
  });

/**
 * Decode JSON written by {@link encode}.
 *
 * @param text - the JSON text.
 * @returns the value, with bigints and byte arrays restored.
 */
export const decode = (text: string): unknown =>
  JSON.parse(text, (_, v: unknown) => {
    if (v !== null && typeof v === 'object') {
      if ('$bigint' in v && typeof v.$bigint === 'string') {
        return BigInt(v.$bigint);
      }
      if ('$bytes' in v && typeof v.$bytes === 'string') {
        return new Uint8Array(Buffer.from(v.$bytes, 'hex'));
      }
    }
    return v;
  });
