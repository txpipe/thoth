// A strict JSON reader that records where each value sits in the text, so a jsonPath
// redaction reveals exactly the bytes of the property or element it selects. It
// refuses duplicate keys, which parsers resolve differently and would let the reveal
// and the selection disagree.

/** Where a value sits: `[start, end)` in the text, and for a property, where its key starts. */
export interface JsonSpan {
  readonly start: number;
  readonly end: number;
}

/** A parsed JSON value with its span; members and items keep their own. */
export type RangedJson =
  | {
      readonly type: 'object';
      readonly span: JsonSpan;
      /** Each property's value, and the span from its key's opening quote to its value's end. */
      readonly members: ReadonlyMap<string, { value: RangedJson; property: JsonSpan }>;
    }
  | { readonly type: 'array'; readonly span: JsonSpan; readonly items: readonly RangedJson[] }
  | { readonly type: 'scalar'; readonly span: JsonSpan };

/** The deepest nesting the reader accepts, so a hostile body cannot exhaust the stack. */
export const MAX_JSON_DEPTH = 64;

const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

/**
 * Parse JSON text strictly (RFC 8259), recording every value's span. No
 * duplicate keys; nesting at most {@link MAX_JSON_DEPTH}. Leading and trailing
 * whitespace is allowed.
 *
 * @throws `SyntaxError` if the text is not valid JSON, has a duplicate key, or
 *   nests too deeply.
 */
export const parseRangedJson = (text: string): RangedJson => {
  let position = 0;

  const fail = (message: string): never => {
    throw new SyntaxError(`invalid JSON at ${position}: ${message}`);
  };
  const skipWhitespace = () => {
    while (position < text.length && ' \t\n\r'.includes(text[position] as string)) {
      position += 1;
    }
  };
  const expect = (literal: string) => {
    if (!text.startsWith(literal, position)) {
      fail(`expected ${JSON.stringify(literal)}`);
    }
    position += literal.length;
  };

  const readString = (): string => {
    const start = position;
    expect('"');
    while (position < text.length) {
      const char = text[position] as string;
      if (char === '"') {
        position += 1;
        // The span is valid JSON string syntax, so JSON.parse decodes its escapes.
        return JSON.parse(text.slice(start, position)) as string;
      }
      if (char === '\\') {
        const next = text[position + 1];
        if (next === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(position + 2, position + 6))) {
            fail('bad unicode escape');
          }
          position += 6;
        } else if (next !== undefined && '"\\/bfnrt'.includes(next)) {
          position += 2;
        } else {
          fail('bad escape');
        }
        continue;
      }
      if (char.charCodeAt(0) < 0x20) {
        fail('control character in string');
      }
      position += 1;
    }
    return fail('unterminated string');
  };

  const readValue = (depth: number): RangedJson => {
    if (depth > MAX_JSON_DEPTH) {
      fail('nested too deeply');
    }
    skipWhitespace();
    const start = position;
    const char = text[position];
    if (char === '{') {
      position += 1;
      const members = new Map<string, { value: RangedJson; property: JsonSpan }>();
      skipWhitespace();
      if (text[position] !== '}') {
        for (;;) {
          skipWhitespace();
          const keyStart = position;
          const key = readString();
          if (members.has(key)) {
            fail(`duplicate key ${JSON.stringify(key)}`);
          }
          skipWhitespace();
          expect(':');
          const value = readValue(depth + 1);
          members.set(key, { value, property: { start: keyStart, end: value.span.end } });
          skipWhitespace();
          if (text[position] === ',') {
            position += 1;
            continue;
          }
          break;
        }
      }
      expect('}');
      return { type: 'object', span: { start, end: position }, members };
    }
    if (char === '[') {
      position += 1;
      const items: RangedJson[] = [];
      skipWhitespace();
      if (text[position] !== ']') {
        for (;;) {
          items.push(readValue(depth + 1));
          skipWhitespace();
          if (text[position] === ',') {
            position += 1;
            continue;
          }
          break;
        }
      }
      expect(']');
      return { type: 'array', span: { start, end: position }, items };
    }
    if (char === '"') {
      readString();
    } else if (text.startsWith('true', position)) {
      position += 4;
    } else if (text.startsWith('false', position)) {
      position += 5;
    } else if (text.startsWith('null', position)) {
      position += 4;
    } else {
      NUMBER.lastIndex = position;
      const number = NUMBER.exec(text);
      if (number === null) {
        return fail('unexpected token');
      }
      position += number[0].length;
    }
    return { type: 'scalar', span: { start, end: position } };
  };

  const root = readValue(0);
  skipWhitespace();
  if (position !== text.length) {
    fail('trailing data');
  }
  return root;
};

/**
 * The span a JSON pointer selects, as Reclaim reveals it: a property's key and
 * value, an array element, or the whole document for the empty pointer.
 * `undefined` when the pointer selects nothing.
 */
export const spanAtPointer = (root: RangedJson, pointer: string): JsonSpan | undefined => {
  if (pointer === '') {
    return root.span;
  }
  if (!pointer.startsWith('/')) {
    return undefined;
  }
  const tokens = pointer
    .slice(1)
    .split('/')
    .map((token) => token.replace(/~1/g, '/').replace(/~0/g, '~'));
  let node: RangedJson = root;
  let span: JsonSpan = root.span;
  for (const token of tokens) {
    if (node.type === 'object') {
      const member = node.members.get(token);
      if (member === undefined) return undefined;
      node = member.value;
      span = member.property;
    } else if (node.type === 'array') {
      if (!/^(?:0|[1-9][0-9]*)$/.test(token)) return undefined;
      const item = node.items[Number(token)];
      if (item === undefined) return undefined;
      node = item;
      span = item.span;
    } else {
      return undefined;
    }
  }
  return span;
};
