// A strict JSON reader for response bodies. It keeps each number's source text, so a
// large integer reaches its parse rule exactly, and refuses duplicate keys, which
// parsers resolve differently and would let two attestors read two values.

/** A parsed JSON value; numbers keep their source text. */
export type JsonNode =
  | { readonly type: 'object'; readonly members: ReadonlyMap<string, JsonNode> }
  | { readonly type: 'array'; readonly items: readonly JsonNode[] }
  | { readonly type: 'string'; readonly value: string }
  | { readonly type: 'number'; readonly raw: string }
  | { readonly type: 'boolean'; readonly value: boolean }
  | { readonly type: 'null' };

/** The deepest nesting the reader accepts, so a hostile body cannot exhaust the stack. */
export const MAX_JSON_DEPTH = 64;

const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

/**
 * Parse JSON text strictly (RFC 8259): no duplicate keys, nesting at most
 * {@link MAX_JSON_DEPTH}.
 *
 * @throws `SyntaxError` if the text is not valid JSON, has a duplicate key, or
 *   nests too deeply.
 */
export const parseStrictJson = (text: string): JsonNode => {
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

  const readValue = (depth: number): JsonNode => {
    if (depth > MAX_JSON_DEPTH) {
      fail('nested too deeply');
    }
    skipWhitespace();
    const char = text[position];
    if (char === '{') {
      position += 1;
      const members = new Map<string, JsonNode>();
      skipWhitespace();
      if (text[position] === '}') {
        position += 1;
        return { type: 'object', members };
      }
      for (;;) {
        skipWhitespace();
        const key = readString();
        if (members.has(key)) {
          fail(`duplicate key ${JSON.stringify(key)}`);
        }
        skipWhitespace();
        expect(':');
        members.set(key, readValue(depth + 1));
        skipWhitespace();
        if (text[position] === ',') {
          position += 1;
          continue;
        }
        expect('}');
        return { type: 'object', members };
      }
    }
    if (char === '[') {
      position += 1;
      const items: JsonNode[] = [];
      skipWhitespace();
      if (text[position] === ']') {
        position += 1;
        return { type: 'array', items };
      }
      for (;;) {
        items.push(readValue(depth + 1));
        skipWhitespace();
        if (text[position] === ',') {
          position += 1;
          continue;
        }
        expect(']');
        return { type: 'array', items };
      }
    }
    if (char === '"') {
      return { type: 'string', value: readString() };
    }
    if (text.startsWith('true', position)) {
      position += 4;
      return { type: 'boolean', value: true };
    }
    if (text.startsWith('false', position)) {
      position += 5;
      return { type: 'boolean', value: false };
    }
    if (text.startsWith('null', position)) {
      position += 4;
      return { type: 'null' };
    }
    NUMBER.lastIndex = position;
    const number = NUMBER.exec(text);
    if (number === null) {
      return fail('unexpected token');
    }
    position += number[0].length;
    return { type: 'number', raw: number[0] };
  };

  const root = readValue(0);
  skipWhitespace();
  if (position !== text.length) {
    fail('trailing data');
  }
  return root;
};

/** One step into a JSON value: an object key, or an array index. */
export type JsonPathSegment = string | number;

/**
 * The text of the string or number at `path`, or `undefined` when the path
 * does not exist or ends at an object, array, boolean or null. A number's text
 * is its source text, so `1e3` stays `1e3`.
 */
export const lookupJsonPath = (
  root: JsonNode,
  path: readonly JsonPathSegment[],
): string | undefined => {
  let node: JsonNode | undefined = root;
  for (const segment of path) {
    if (node === undefined) {
      return undefined;
    }
    if (typeof segment === 'number') {
      node = node.type === 'array' ? node.items[segment] : undefined;
    } else {
      node = node.type === 'object' ? node.members.get(segment) : undefined;
    }
  }
  if (node?.type === 'string') {
    return node.value;
  }
  if (node?.type === 'number') {
    return node.raw;
  }
  return undefined;
};
