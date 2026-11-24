// Read the HTTP request and response out of a verified TLSNotary transcript. Only
// revealed bytes are data; a hidden byte is allowed only where the policy lets the
// request hide a header value, and nowhere in the response.

/** One direction of a verified transcript: every byte, and which ranges are revealed. */
export interface RevealedBytes {
  /** Every byte; a byte outside `revealed` is zero and carries no data. */
  readonly data: Uint8Array;
  /** Revealed byte ranges, `[start, end)`, sorted and disjoint. */
  readonly revealed: readonly (readonly [number, number])[];
}

/** The request the presentation authenticates. */
export interface RevealedRequest {
  /** The method, as sent. */
  readonly method: string;
  /** The origin-form target: path and query. */
  readonly target: string;
  /** The `Host` header's value. */
  readonly host: string;
  /** Header names in order, lowercased, with their value, or `undefined` when it is hidden. */
  readonly headers: readonly (readonly [string, string | undefined])[];
  readonly body: Uint8Array;
}

/** The response the presentation authenticates. */
export interface RevealedResponse {
  readonly status: number;
  /** Header names in order, lowercased, with their value. */
  readonly headers: readonly (readonly [string, string])[];
  /** The body, de-chunked. */
  readonly body: Uint8Array;
}

const CR = 0x0d;
const LF = 0x0a;
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/** A per-byte revealed flag. */
const maskOf = (bytes: RevealedBytes): Uint8Array => {
  const mask = new Uint8Array(bytes.data.length);
  for (const [start, end] of bytes.revealed) {
    mask.fill(1, start, end);
  }
  return mask;
};

const latin1 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('latin1');

/** Trim HTTP optional whitespace (space and tab). */
const trimOws = (value: string): string => value.replace(/^[ \t]+|[ \t]+$/g, '');

/** The single value of a header that may appear at most once, or `undefined`. */
const singleHeader = <V>(
  headers: readonly (readonly [string, V])[],
  name: string,
  what: string,
): V | undefined => {
  const matches = headers.filter(([headerName]) => headerName === name);
  if (matches.length > 1) {
    throw new Error(`the ${what} carries more than one ${name} header`);
  }
  return matches[0]?.[1];
};

/**
 * Read the request from the sent transcript.
 *
 * Every byte must be revealed except inside the value of a header named in
 * `hiddenHeaders`. The request line, every header name, every line ending,
 * the `Host` header and the body are always revealed.
 *
 * @param hiddenHeaders — lowercase header names whose values may stay hidden.
 * @throws if a hidden byte sits anywhere else, the request is not one HTTP/1.1
 *   request in origin form, its `Host` is missing or repeated, it uses
 *   `Transfer-Encoding`, or `Content-Length` disagrees with the body.
 */
export const readRequest = (
  sent: RevealedBytes,
  hiddenHeaders: ReadonlySet<string>,
): RevealedRequest => {
  const { data } = sent;
  const mask = maskOf(sent);
  const revealedSpan = (start: number, end: number): boolean => {
    for (let index = start; index < end; index += 1) {
      if (mask[index] !== 1) return false;
    }
    return true;
  };
  // The first revealed CRLF at or after `from`; every byte before it must be revealed.
  const revealedLine = (from: number, what: string): [string, number] => {
    for (let index = from; index + 1 < data.length; index += 1) {
      if (mask[index] !== 1) {
        throw new Error(`the ${what} has hidden bytes`);
      }
      if (data[index] === CR && data[index + 1] === LF && mask[index + 1] === 1) {
        return [latin1(data.subarray(from, index)), index + 2];
      }
    }
    throw new Error(`the ${what} has no line ending`);
  };

  const [requestLine, afterRequestLine] = revealedLine(0, 'request line');
  const parts = /^([A-Z]+) (\/[\x21-\x7e]*) HTTP\/1\.1$/.exec(requestLine);
  if (parts === null) {
    throw new Error('the request line is not METHOD /target HTTP/1.1');
  }
  const [, method, target] = parts as unknown as [string, string, string];

  const headers: [string, string | undefined][] = [];
  let position = afterRequestLine;
  for (;;) {
    if (position + 1 >= data.length) {
      throw new Error('the request headers do not end');
    }
    if (
      data[position] === CR &&
      data[position + 1] === LF &&
      revealedSpan(position, position + 2)
    ) {
      position += 2;
      break;
    }
    const colon = data.indexOf(0x3a, position);
    if (colon < 0 || !revealedSpan(position, colon + 1)) {
      throw new Error('a request header name is hidden or malformed');
    }
    const name = latin1(data.subarray(position, colon));
    if (!TOKEN.test(name)) {
      throw new Error(`a request header name is not a token: ${JSON.stringify(name)}`);
    }
    const lowered = name.toLowerCase();
    // The value runs to the first revealed CRLF. Hidden bytes are allowed only in a
    // hidden header's value; they could themselves hold a CRLF the attestor cannot see,
    // which is why a policy names the few headers that may hide.
    let end = colon + 1;
    let hidden = false;
    for (;;) {
      if (end + 1 >= data.length) {
        throw new Error(`the ${lowered} header has no line ending`);
      }
      if (mask[end] !== 1) {
        if (!hiddenHeaders.has(lowered)) {
          throw new Error(
            `the ${lowered} header value is hidden, but the policy does not allow it`,
          );
        }
        hidden = true;
        end += 1;
        continue;
      }
      if (data[end] === CR || data[end] === LF) {
        if (data[end] === CR && data[end + 1] === LF && mask[end + 1] === 1) {
          break;
        }
        throw new Error(`the ${lowered} header has a bare line break`);
      }
      end += 1;
    }
    headers.push([lowered, hidden ? undefined : trimOws(latin1(data.subarray(colon + 1, end)))]);
    position = end + 2;
  }

  if (!revealedSpan(position, data.length)) {
    throw new Error('the request body has hidden bytes');
  }
  const body = data.slice(position);

  const host = singleHeader(headers, 'host', 'request');
  if (host === undefined) {
    throw new Error('the request has no revealed Host header');
  }
  if (headers.some(([name]) => name === 'transfer-encoding')) {
    throw new Error('the request cannot use Transfer-Encoding');
  }
  if (
    headers.some(
      ([name, value]) => (name === 'host' || name === 'content-length') && value === undefined,
    )
  ) {
    throw new Error('the request hides its Host or Content-Length value');
  }
  const contentLength = singleHeader(headers, 'content-length', 'request');
  if (contentLength === undefined ? body.length !== 0 : contentLength !== String(body.length)) {
    throw new Error('the request Content-Length does not match its body');
  }
  return { method, target, host, headers, body };
};

/** Decode a chunked body that must end exactly at the end of `data`. */
const dechunk = (data: Uint8Array, from: number): Uint8Array => {
  const chunks: Uint8Array[] = [];
  let position = from;
  const line = (): string => {
    const end = data.indexOf(LF, position);
    if (end < 1 || data[end - 1] !== CR) {
      throw new Error('a response chunk line has no CRLF');
    }
    const text = latin1(data.subarray(position, end - 1));
    position = end + 1;
    return text;
  };
  for (;;) {
    const sizeText = line().split(';')[0] ?? '';
    if (!/^[0-9a-fA-F]{1,8}$/.test(sizeText)) {
      throw new Error('a response chunk size is malformed');
    }
    const size = Number.parseInt(sizeText, 16);
    if (size === 0) {
      // Trailers end at an empty line.
      while (line() !== '') {
        // Trailer fields carry no body data.
      }
      break;
    }
    if (position + size + 2 > data.length || data[position + size] !== CR) {
      throw new Error('a response chunk is truncated');
    }
    chunks.push(data.subarray(position, position + size));
    position += size;
    if (line() !== '') {
      throw new Error('a response chunk does not end with CRLF');
    }
  }
  if (position !== data.length) {
    throw new Error('the transcript continues after the response');
  }
  return new Uint8Array(Buffer.concat(chunks));
};

/**
 * Read the one response from the received transcript.
 *
 * Every received byte must be revealed: with hidden bytes, the attestor could
 * not tell which part of the response a revealed field belongs to.
 *
 * @throws if any byte is hidden, the transcript is not exactly one HTTP/1.1
 *   response, or the body is compressed.
 */
export const readResponse = (received: RevealedBytes): RevealedResponse => {
  const { data } = received;
  const mask = maskOf(received);
  if (mask.some((flag) => flag !== 1)) {
    throw new Error('the response has hidden bytes; tlsn@1 requires the whole response');
  }
  const headerEnd = Buffer.from(data).indexOf('\r\n\r\n');
  if (headerEnd < 0) {
    throw new Error('the response headers do not end');
  }
  const [statusLine = '', ...headerLines] = latin1(data.subarray(0, headerEnd)).split('\r\n');
  const status = /^HTTP\/1\.1 ([0-9]{3})(?: .*)?$/.exec(statusLine);
  if (status === null) {
    throw new Error('the status line is not HTTP/1.1 NNN');
  }
  const headers = headerLines.map((line): [string, string] => {
    const colon = line.indexOf(':');
    const name = line.slice(0, colon);
    if (colon < 1 || !TOKEN.test(name) || /[\r\n]/.test(line)) {
      throw new Error('a response header is malformed');
    }
    return [name.toLowerCase(), trimOws(line.slice(colon + 1))];
  });
  const encoding = singleHeader(headers, 'content-encoding', 'response');
  if (encoding !== undefined && encoding.toLowerCase() !== 'identity') {
    throw new Error(`the response body is encoded (${encoding})`);
  }
  const bodyStart = headerEnd + 4;
  const transferEncoding = singleHeader(headers, 'transfer-encoding', 'response');
  const contentLength = singleHeader(headers, 'content-length', 'response');
  let body: Uint8Array;
  if (transferEncoding !== undefined) {
    if (transferEncoding.toLowerCase() !== 'chunked' || contentLength !== undefined) {
      throw new Error('the response framing is not plain chunked');
    }
    body = dechunk(data, bodyStart);
  } else if (contentLength !== undefined) {
    if (!/^[0-9]{1,10}$/.test(contentLength)) {
      throw new Error('the response Content-Length is malformed');
    }
    const length = Number(contentLength);
    if (bodyStart + length !== data.length) {
      throw new Error('the response Content-Length does not match the transcript');
    }
    body = data.slice(bodyStart);
  } else {
    // Without framing headers the body runs to the end of the connection.
    body = data.slice(bodyStart);
  }
  return { status: Number(status[1]), headers, body };
};
