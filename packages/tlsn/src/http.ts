// HTTP over a TLSNotary transcript. The attestor reads the request and a redacted view
// of the response; the prover parses the full response to choose what to reveal. Both
// follow the zkFetch witness, so one policy reads the same bytes under either kind.

/** One direction of a verified transcript: every byte, and which ranges are revealed. */
export interface RevealedBytes {
  /** Every byte; a byte outside `revealed` carries no data. */
  readonly data: Uint8Array;
  /** Revealed byte ranges, `[start, end)`, sorted and disjoint. */
  readonly revealed: readonly (readonly [number, number])[];
}

/** A byte range, `[start, end)`. */
export type ByteRange = readonly [number, number];

/** The request the presentation authenticates. */
export interface RevealedRequest {
  /** The method, uppercase. */
  readonly method: 'GET' | 'POST' | 'PUT' | 'PATCH';
  /** The origin-form target: path and query. */
  readonly target: string;
  /** The `Host` header's value. */
  readonly host: string;
  readonly body: Uint8Array;
}

/** How Reclaim marks a hidden byte in the text its witness matches on. */
export const REDACTION_CHAR = '*';

const CR = 0x0d;
const LF = 0x0a;
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
/** The headers whose values a request may never hide: they frame the request or name its server. */
const ALWAYS_REVEALED = new Set(['host', 'connection', 'content-length', 'transfer-encoding']);

/** A per-byte revealed flag. */
export const maskOf = (bytes: RevealedBytes): Uint8Array => {
  const mask = new Uint8Array(bytes.data.length);
  for (const [start, end] of bytes.revealed) {
    mask.fill(1, start, end);
  }
  return mask;
};

const latin1 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('latin1');

/** Trim HTTP optional whitespace (space and tab). */
const trimOws = (value: string): string => value.replace(/^[ \t]+|[ \t]+$/g, '');

/**
 * Read the request from the sent transcript.
 *
 * The request opens as the zkFetch witness requires: `METHOD target HTTP/1.1`,
 * then `Host`, then `Connection: close`, all revealed. Any later header's value
 * may stay hidden, except `Content-Length` and `Transfer-Encoding`; header
 * names, line endings and the body are always revealed.
 *
 * @throws if a hidden byte sits anywhere else, the request does not open with
 *   that prefix, uses `Transfer-Encoding`, or its `Content-Length` disagrees
 *   with the body.
 */
export const readRequest = (sent: RevealedBytes): RevealedRequest => {
  const { data } = sent;
  const mask = maskOf(sent);
  const revealedSpan = (start: number, end: number): boolean => {
    for (let index = start; index < end; index += 1) {
      if (mask[index] !== 1) return false;
    }
    return true;
  };

  // Each line runs to the first revealed CRLF. Hidden bytes are allowed only in a
  // header value; they could themselves hold a CRLF the attestor cannot see, the
  // same exposure a zkFetch secret header has.
  const lines: { name?: string; value?: string; text?: string }[] = [];
  let position = 0;
  let bodyStart = -1;
  while (bodyStart < 0) {
    if (position + 1 >= data.length) {
      throw new Error('the request headers do not end');
    }
    if (lines.length > 0 && data[position] === CR && data[position + 1] === LF) {
      if (!revealedSpan(position, position + 2)) {
        throw new Error('the request header terminator is hidden');
      }
      bodyStart = position + 2;
      break;
    }
    let end = position;
    let hidden = false;
    let colon = -1;
    for (;;) {
      if (end + 1 >= data.length) {
        throw new Error('a request line has no ending');
      }
      if (mask[end] !== 1) {
        if (lines.length === 0 || colon < 0) {
          throw new Error('the request line or a header name is hidden');
        }
        hidden = true;
        end += 1;
        continue;
      }
      if (data[end] === 0x3a && colon < 0) colon = end;
      if (data[end] === CR || data[end] === LF) {
        if (data[end] === CR && data[end + 1] === LF && mask[end + 1] === 1) break;
        throw new Error('a request line has a bare line break');
      }
      end += 1;
    }
    if (lines.length === 0) {
      lines.push({ text: latin1(data.subarray(position, end)) });
    } else {
      const name = latin1(data.subarray(position, colon));
      if (!TOKEN.test(name)) {
        throw new Error(`a request header name is not a token: ${JSON.stringify(name)}`);
      }
      const lowered = name.toLowerCase();
      if (hidden && ALWAYS_REVEALED.has(lowered)) {
        throw new Error(`the request hides its ${lowered} header`);
      }
      lines.push(
        hidden
          ? { name: lowered }
          : { name: lowered, value: trimOws(latin1(data.subarray(colon + 1, end))) },
      );
    }
    position = end + 2;
  }

  const [requestLine, hostLine, connectionLine, ...rest] = lines;
  const parts = /^(GET|POST|PUT|PATCH) (\/[\x21-\x7e]*) HTTP\/1\.1$/.exec(requestLine?.text ?? '');
  if (parts === null) {
    throw new Error('the request line is not GET, POST, PUT or PATCH /target HTTP/1.1');
  }
  if (hostLine?.name !== 'host' || hostLine.value === undefined || hostLine.value === '') {
    throw new Error('the first request header is not a revealed Host');
  }
  if (connectionLine?.name !== 'connection' || connectionLine.value?.toLowerCase() !== 'close') {
    throw new Error('the second request header is not Connection: close');
  }
  if (rest.some(({ name }) => name === 'host' || name === 'connection')) {
    throw new Error('the request repeats its Host or Connection header');
  }
  if (rest.some(({ name }) => name === 'transfer-encoding')) {
    throw new Error('the request cannot use Transfer-Encoding');
  }
  if (!revealedSpan(bodyStart, data.length)) {
    throw new Error('the request body has hidden bytes');
  }
  const body = data.slice(bodyStart);
  const lengths = rest.filter(({ name }) => name === 'content-length');
  if (lengths.length > 1) {
    throw new Error('the request repeats Content-Length');
  }
  const contentLength = lengths[0]?.value;
  if (contentLength === undefined ? body.length !== 0 : contentLength !== String(body.length)) {
    throw new Error('the request Content-Length does not match its body');
  }
  return {
    method: parts[1] as RevealedRequest['method'],
    target: parts[2] as string,
    host: hostLine.value,
    body,
  };
};

/** A response the prover holds in full, parsed the way Reclaim's prover parses it. */
export interface ParsedResponse {
  readonly status: number;
  /** Where the status line's CRLF starts. */
  readonly statusLineEnd: number;
  /** Where the blank line that ends the headers starts: `\r\n\r\n`. */
  readonly headerEnd: number;
  /** Each header's line, without its CRLF, by lowercase name; a repeated name keeps the last. */
  readonly headerLines: ReadonlyMap<string, ByteRange>;
  /** Chunk data ranges in the transcript, when the body is chunked. */
  readonly chunks?: readonly ByteRange[];
  /** The body, de-chunked. */
  readonly body: Uint8Array;
}

/**
 * Parse a complete response.
 *
 * @throws if the response has no status line, its headers never end, or its
 *   chunked framing is malformed.
 */
export const parseResponse = (data: Uint8Array): ParsedResponse => {
  const text = latin1(data);
  const statusLineEnd = text.indexOf('\r\n');
  const status = /^HTTP\/\d\.\d (\d{3})/.exec(text.slice(0, Math.max(statusLineEnd, 0)));
  if (statusLineEnd < 0 || status === null) {
    throw new Error('the response has no status line');
  }
  const headerEnd = text.indexOf('\r\n\r\n', statusLineEnd);
  if (headerEnd < 0) {
    throw new Error('the response headers do not end');
  }
  const headerLines = new Map<string, ByteRange>();
  let lineStart = statusLineEnd + 2;
  while (lineStart < headerEnd + 2) {
    const lineEnd = text.indexOf('\r\n', lineStart);
    const name = text.slice(lineStart, lineEnd).split(': ')[0]?.toLowerCase() ?? '';
    headerLines.set(name, [lineStart, lineEnd]);
    lineStart = lineEnd + 2;
  }
  const bodyStart = headerEnd + 4;
  const transferEncoding = headerLines.get('transfer-encoding');
  const chunked =
    transferEncoding !== undefined &&
    text.slice(transferEncoding[0], transferEncoding[1]).toLowerCase().includes('chunked');
  if (!chunked) {
    return {
      status: Number(status[1]),
      statusLineEnd,
      headerEnd,
      headerLines,
      body: data.slice(bodyStart),
    };
  }
  const chunks: ByteRange[] = [];
  let position = bodyStart;
  for (;;) {
    const lineEnd = text.indexOf('\r\n', position);
    if (lineEnd < 0) {
      throw new Error('a response chunk size has no line ending');
    }
    const size = Number.parseInt(text.slice(position, lineEnd), 16);
    if (Number.isNaN(size) || position + 2 > data.length) {
      throw new Error('a response chunk size is malformed');
    }
    if (size === 0) break;
    const from = lineEnd + 2;
    if (from + size + 2 > data.length) {
      throw new Error('a response chunk is truncated');
    }
    chunks.push([from, from + size]);
    position = from + size + 2;
  }
  const body = new Uint8Array(Buffer.concat(chunks.map(([from, to]) => data.subarray(from, to))));
  return { status: Number(status[1]), statusLineEnd, headerEnd, headerLines, chunks, body };
};

/** Decode a chunked body whose data may hold redaction markers; the framing must be readable. */
const dechunkRedacted = (body: Uint8Array): Uint8Array => {
  const text = latin1(body);
  const parts: Uint8Array[] = [];
  let position = 0;
  for (;;) {
    const lineEnd = text.indexOf('\r\n', position);
    if (lineEnd < 0) break;
    const sizeText = text.slice(position, lineEnd);
    if (sizeText === '') {
      position = lineEnd + 2;
      continue;
    }
    const size = Number.parseInt(sizeText, 16);
    if (Number.isNaN(size)) {
      throw new Error('a response chunk size is hidden or malformed');
    }
    if (size === 0) break;
    parts.push(body.subarray(lineEnd + 2, lineEnd + 2 + size));
    position = lineEnd + 2 + size;
  }
  return new Uint8Array(Buffer.concat(parts));
};

/** The charset a revealed `Content-Type` names, read the way Reclaim's witness reads it. */
const charsetOf = (headers: string): string | undefined => {
  const contentType = /(?:^|[\r\n*])content-type\s*:\s*([^*\r\n]*)/i.exec(headers)?.[1];
  if (contentType === undefined) return undefined;
  const match = /(?:^|;)\s*charset\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;\s]*))/i.exec(contentType);
  const charset = match?.[1]?.replace(/\\(.)/g, '$1') ?? match?.[2];
  return charset?.trim() || undefined;
};

/** The shortest status line, which the witness skips before it looks for the blank line. */
const STATUS_PREFIX_LENGTH = 'HTTP/1.1 200'.length;

/**
 * The response as the zkFetch witness matches on it: every hidden byte as `*`,
 * the headers as text, then the body de-chunked and decoded by its charset.
 *
 * @throws if the status line is not a revealed `HTTP/1.1 2xx`, the headers
 *   never end, or the body's charset is unsupported.
 */
export const redactedResponseText = (received: RevealedBytes): string => {
  const mask = maskOf(received);
  const bytes = new Uint8Array(received.data);
  for (let index = 0; index < bytes.length; index += 1) {
    if (mask[index] !== 1) bytes[index] = REDACTION_CHAR.charCodeAt(0);
  }
  const separator = Buffer.from(bytes.subarray(STATUS_PREFIX_LENGTH)).indexOf('\r\n\r\n');
  if (separator < 0) {
    throw new Error('the response headers do not end');
  }
  const bodyStart = STATUS_PREFIX_LENGTH + separator + 4;
  const headersText = new TextDecoder().decode(bytes.subarray(0, bodyStart));
  const status = /^HTTP\/1\.1 (\d{3})/.exec(headersText);
  if (status === null || !status[1]?.startsWith('2')) {
    throw new Error(
      status === null
        ? 'the response status line is hidden or not HTTP/1.1'
        : `the response status is ${status[1]}, not 2xx`,
    );
  }
  let body: Uint8Array = bytes.subarray(bodyStart);
  if (/transfer-encoding:\s*chunked/i.test(headersText)) {
    body = dechunkRedacted(body);
  }
  const charset = charsetOf(headersText);
  let bodyText: string;
  try {
    bodyText = new TextDecoder(charset ?? 'utf-8').decode(body);
  } catch (error) {
    throw new Error(`unsupported response charset ${JSON.stringify(charset)}`, { cause: error });
  }
  return headersText + bodyText;
};
