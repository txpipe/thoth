// What the prover reveals, chosen the way Reclaim's prover chooses it: the response's
// status line, framing, a few headers and each redaction's slice; the request without
// its secret header values. Everything else stays hidden from the attestor.

import { JSONPath } from 'jsonpath-plus';
import { type ByteRange, type ParsedResponse, parseResponse } from './http.js';
import { parseRangedJson, spanAtPointer } from './json.js';
import { compileRule } from './regex.js';

/** One slice of the response to reveal; everything not selected stays hidden. */
export interface TlsnResponseRedaction {
  regex?: string;
  jsonPath?: string;
  /** Refused by tlsn@1, which does not parse HTML. */
  xPath?: string;
}

/** The response does not satisfy a redaction rule, or is not a 2xx. Carries no response text. */
export class RedactionError extends Error {
  /** Build the error from a message that names no response bytes. */
  constructor(message: string) {
    super(message);
    this.name = 'RedactionError';
  }
}

const latin1 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('latin1');

/** Sort and merge ranges, dropping empty ones. */
export const mergeRanges = (ranges: readonly ByteRange[]): ByteRange[] => {
  const sorted = ranges.filter(([start, end]) => end > start).sort((a, b) => a[0] - b[0]);
  const merged: [number, number][] = [];
  for (const [start, end] of sorted) {
    const last = merged.at(-1);
    if (last !== undefined && start <= last[1]) {
      last[1] = Math.max(last[1], end);
    } else {
      merged.push([start, end]);
    }
  }
  return merged;
};

/**
 * What the prover reveals of its request: every byte except the values of the
 * named secret headers.
 *
 * @param secretNames — lowercase header names.
 * @throws if a secret header is one the request must always reveal.
 */
export const requestReveals = (sent: Uint8Array, secretNames: ReadonlySet<string>): ByteRange[] => {
  for (const name of ['host', 'connection', 'content-length', 'transfer-encoding']) {
    if (secretNames.has(name)) {
      throw new Error(`the ${name} header cannot be secret`);
    }
  }
  const text = latin1(sent);
  const headerEnd = text.indexOf('\r\n\r\n');
  if (headerEnd < 0) {
    throw new Error('the request headers do not end');
  }
  const hidden: ByteRange[] = [];
  let lineStart = text.indexOf('\r\n') + 2;
  while (lineStart < headerEnd + 2) {
    const lineEnd = text.indexOf('\r\n', lineStart);
    const line = text.slice(lineStart, lineEnd);
    const colon = line.indexOf(':');
    if (colon > 0 && secretNames.has(line.slice(0, colon).toLowerCase())) {
      // Keep the name and the space after the colon, as a zkFetch secret header does.
      const valueStart = lineStart + colon + 1 + (line[colon + 1] === ' ' ? 1 : 0);
      hidden.push([valueStart, lineEnd]);
    }
    lineStart = lineEnd + 2;
  }
  const reveals: ByteRange[] = [];
  let cursor = 0;
  for (const [start, end] of mergeRanges(hidden)) {
    reveals.push([cursor, start]);
    cursor = end;
  }
  reveals.push([cursor, sent.length]);
  return mergeRanges(reveals);
};

/** Map an offset in the de-chunked body to the transcript; `end` maps a range's end. */
const toTranscript = (response: ParsedResponse, offset: number, end: boolean): number => {
  const bodyStart = response.headerEnd + 4;
  if (response.chunks === undefined) {
    return bodyStart + offset;
  }
  let consumed = 0;
  for (const [from, to] of response.chunks) {
    const size = to - from;
    if (offset < consumed + size || (end && offset === consumed + size)) {
      return from + (offset - consumed);
    }
    consumed += size;
  }
  return response.chunks.at(-1)?.[1] ?? bodyStart;
};

/** The body slices one redaction selects, as `[start, end)` in the de-chunked body. */
const selectedSlices = (body: string, redaction: TlsnResponseRedaction): ByteRange[] => {
  if (redaction.xPath !== undefined) {
    throw new RedactionError('xPath redactions are not supported by tlsn@1');
  }
  const regexSlice = (start: number, element: string): ByteRange => {
    const regex = compileRule(redaction.regex as string);
    const match = regex.exec(element);
    if (!match?.[0]) {
      throw new RedactionError(`redaction regex ${JSON.stringify(redaction.regex)} does not match`);
    }
    return [start + match.index, start + match.index + match[0].length];
  };
  if (redaction.jsonPath !== undefined) {
    let pointers: unknown;
    let tree: ReturnType<typeof parseRangedJson>;
    try {
      tree = parseRangedJson(body);
      pointers = JSONPath({
        path: redaction.jsonPath,
        json: JSON.parse(body) as object,
        wrap: false,
        resultType: 'pointer',
        eval: 'safe',
      });
    } catch {
      throw new RedactionError('the response body is not JSON a jsonPath can select from');
    }
    if (pointers === undefined || pointers === null) {
      throw new RedactionError(`jsonPath ${JSON.stringify(redaction.jsonPath)} selects nothing`);
    }
    const slices: ByteRange[] = [];
    for (const pointer of Array.isArray(pointers) ? pointers : [pointers]) {
      const span = typeof pointer === 'string' ? spanAtPointer(tree, pointer) : undefined;
      if (span === undefined) continue;
      slices.push(
        redaction.regex
          ? regexSlice(span.start, body.slice(span.start, span.end))
          : [span.start, span.end],
      );
    }
    if (slices.length === 0) {
      throw new RedactionError(`jsonPath ${JSON.stringify(redaction.jsonPath)} selects nothing`);
    }
    return slices;
  }
  if (redaction.regex) {
    return [regexSlice(0, body)];
  }
  throw new RedactionError('a redaction needs a jsonPath or a regex');
};

/**
 * What the prover reveals of its response, as Reclaim's prover chooses it.
 *
 * With no redactions, the whole response. Otherwise the status line, the blank
 * line ending the headers, the `Date`, `Content-Type` and `Transfer-Encoding`
 * header lines, the chunk framing, and each redaction's slices. A `jsonPath`
 * reveals the selected property's key and value, or the selected element.
 *
 * @throws {@link RedactionError} if the response is not a 2xx or a redaction
 *   selects nothing.
 * @throws if the response does not parse.
 */
export const responseReveals = (
  received: Uint8Array,
  redactions: readonly TlsnResponseRedaction[],
): ByteRange[] => {
  const response = parseResponse(received);
  if (Math.floor(response.status / 100) !== 2) {
    throw new RedactionError(`the response status is ${response.status}, not 2xx`);
  }
  if (redactions.length === 0) {
    return [[0, received.length]];
  }
  const reveals: ByteRange[] = [
    [0, response.statusLineEnd],
    [response.headerEnd, response.headerEnd + 4],
  ];
  for (const name of ['date', 'content-type', 'transfer-encoding']) {
    const line = response.headerLines.get(name);
    if (line !== undefined) reveals.push(line);
  }
  if (response.chunks !== undefined) {
    let previous = response.headerEnd + 4;
    for (const [from, to] of response.chunks) {
      reveals.push([previous, from]);
      previous = to;
    }
    reveals.push([previous, received.length]);
  }
  const body = latin1(response.body);
  for (const redaction of redactions) {
    for (const [start, end] of selectedSlices(body, redaction)) {
      reveals.push([toTranscript(response, start, false), toTranscript(response, end, true)]);
    }
  }
  return mergeRanges(reveals);
};
