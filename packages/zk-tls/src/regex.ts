// The regex subset a zkFetch policy may use: syntax that RE2 and RegExp, under the flags
// Reclaim compiles with, both accept and read the same way. The dApp guide lists it.

/** Thrown when a regex uses syntax outside the regex subset. */
export class RegexSubsetError extends Error {
  /** The refused construct, as the message names it. */
  readonly construct: string;
  /** Where the construct starts in the regex source, in UTF-16 code units. */
  readonly index: number;

  constructor(construct: string, index: number) {
    super(`regex uses ${construct} at index ${index}, which the regex subset does not allow`);
    this.name = 'RegexSubsetError';
    this.construct = construct;
    this.index = index;
  }
}

/** What {@link scanRegexSubset} read from a regex in the subset. */
export interface RegexSubsetScan {
  /** The named groups, in source order. */
  readonly groupNames: readonly string[];
}

// RE2 refuses a compiled program over its memory budget, and nested counted repeats whose
// counts multiply past 1000; RegExp has neither limit. The worst atom in the subset, a negated
// class of alternating ASCII characters, still compiles at 6000 copies.
const MAX_SIZE = 1000;

/** Characters that need a backslash to be literal, outside a class. */
const SYNTAX_CHARACTERS = '^$\\.*+?()[]{}|/';

const CONTROL_ESCAPES: Readonly<Record<string, number>> = {
  t: 0x09,
  n: 0x0a,
  v: 0x0b,
  f: 0x0c,
  r: 0x0d,
};

const CLASS_ESCAPES = 'dDwWsS';

/** What the parser knows about a parsed piece of the pattern. */
interface Shape {
  /** Whether it can match the empty string. */
  readonly nullable: boolean;
  /** Whether it holds a capture group. */
  readonly captures: boolean;
  /** How many atoms it holds once every counted repeat is written out. */
  readonly size: number;
}

/** One class member: a single character, or a set such as `\d` that cannot bound a range. */
type ClassMember = { readonly code: number } | { readonly set: true };

const isAsciiDigit = (char: string | undefined): boolean =>
  char !== undefined && char >= '0' && char <= '9';

const isHexDigit = (char: string | undefined): boolean =>
  char !== undefined && /^[0-9A-Fa-f]$/.test(char);

const codePointLabel = (code: number): string =>
  `U+${code.toString(16).toUpperCase().padStart(4, '0')}`;

class Scanner {
  private position = 0;
  private readonly groupNames: string[] = [];
  private readonly source: string;

  constructor(source: string) {
    this.source = source;
  }

  scan(): RegexSubsetScan {
    this.disjunction();
    if (this.position < this.source.length) {
      // disjunction() stops only at the end or at a `)` no group opened.
      this.fail('an unmatched )', this.position);
    }
    return { groupNames: [...this.groupNames] };
  }

  private fail(construct: string, index: number): never {
    throw new RegexSubsetError(construct, index);
  }

  private peek(offset = 0): string | undefined {
    return this.source[this.position + offset];
  }

  private disjunction(): Shape {
    let shape = this.alternative();
    while (this.peek() === '|') {
      this.position += 1;
      const next = this.alternative();
      shape = {
        nullable: shape.nullable || next.nullable,
        captures: shape.captures || next.captures,
        size: this.sized(shape.size + next.size, 0),
      };
    }
    return shape;
  }

  private alternative(): Shape {
    let nullable = true;
    let captures = false;
    let size = 0;
    while (this.peek() !== undefined && this.peek() !== '|' && this.peek() !== ')') {
      const start = this.position;
      const term = this.term();
      nullable &&= term.nullable;
      captures ||= term.captures;
      size = this.sized(size + term.size, start);
    }
    return { nullable, captures, size };
  }

  private term(): Shape {
    const start = this.position;
    const atom = this.atom();
    const quantifierStart = this.position;
    const counts = this.quantifier();
    if (counts === undefined) {
      return atom;
    }
    // RegExp resets a group's captures on every iteration and refuses an empty one; RE2
    // keeps the last captures and takes the empty one. Both change what a match returns.
    if (atom.captures) {
      this.fail('a quantifier on a capture group', quantifierStart);
    }
    if (atom.nullable) {
      this.fail('a quantifier on something that can match the empty string', quantifierStart);
    }
    // Counted the way RE2 counts nested repeats: the maximum, else the minimum, and 0 as 1.
    const factor = counts.counted ? (counts.max ?? counts.min) : 1;
    const size = this.sized(atom.size * Math.max(factor, 1), start);
    return { nullable: counts.min === 0, captures: false, size };
  }

  /** Refuse a pattern whose written-out size passes {@link MAX_SIZE}. */
  private sized(size: number, index: number): number {
    if (size > MAX_SIZE) {
      this.fail(`more than ${MAX_SIZE} atoms once counted repeats are written out`, index);
    }
    return size;
  }

  /** Parse a quantifier if one follows; `max` is undefined when unbounded. */
  private quantifier(): { min: number; max: number | undefined; counted: boolean } | undefined {
    const start = this.position;
    let counts: { min: number; max: number | undefined; counted: boolean };
    switch (this.peek()) {
      case '*':
        counts = { min: 0, max: undefined, counted: false };
        this.position += 1;
        break;
      case '+':
        counts = { min: 1, max: undefined, counted: false };
        this.position += 1;
        break;
      case '?':
        counts = { min: 0, max: 1, counted: false };
        this.position += 1;
        break;
      case '{':
        counts = this.countedQuantifier();
        break;
      default:
        return undefined;
    }
    if (this.peek() === '?') {
      this.position += 1;
    }
    const next = this.peek();
    if (next === '*' || next === '+' || next === '?' || next === '{') {
      this.fail('a quantifier on a quantifier', start);
    }
    return counts;
  }

  private countedQuantifier(): { min: number; max: number | undefined; counted: boolean } {
    const start = this.position;
    const match = /^\{(\d+)(,(\d*))?\}/.exec(this.source.slice(start));
    if (match === null) {
      this.fail('an unescaped {', start);
    }
    this.position += match[0].length;
    const min = Number(match[1]);
    const max = match[2] === undefined ? min : match[3] === '' ? undefined : Number(match[3]);
    if (max !== undefined && max < min) {
      this.fail('a repeat range whose maximum is below its minimum', start);
    }
    return { min, max, counted: true };
  }

  private atom(): Shape {
    const start = this.position;
    const char = this.peek();
    const single: Shape = { nullable: false, captures: false, size: 1 };
    switch (char) {
      case '^':
      case '$':
        this.position += 1;
        return { nullable: true, captures: false, size: 1 };
      case '.':
        this.position += 1;
        return single;
      case '(':
        return this.group();
      case '[':
        this.characterClass();
        return single;
      case '\\':
        return this.escape();
      case '*':
      case '+':
      case '?':
        return this.fail('a quantifier with nothing to repeat', start);
      case '{':
      case '}':
      case ']':
        return this.fail(`an unescaped ${char}`, start);
      default:
        this.literal();
        return single;
    }
  }

  /** Consume one literal character, refusing anything but printable ASCII. */
  private literal(): number {
    const start = this.position;
    const code = this.source.codePointAt(start) ?? 0;
    if (code > 0x7e) {
      this.fail(`the non-ASCII character ${codePointLabel(code)}`, start);
    }
    if (code < 0x20 || code === 0x7f) {
      this.fail(`the control character ${codePointLabel(code)}; escape it`, start);
    }
    this.position += 1;
    return code;
  }

  private group(): Shape {
    const start = this.position;
    this.position += 1;
    let captures = true;
    if (this.peek() === '?') {
      const kind = this.peek(1);
      const after = this.peek(2);
      if (kind === ':') {
        captures = false;
        this.position += 2;
      } else if (kind === '<' && after !== '=' && after !== '!') {
        this.position += 2;
        this.groupName(start);
      } else if (kind === '=') {
        this.fail('lookahead (?=', start);
      } else if (kind === '!') {
        this.fail('negative lookahead (?!', start);
      } else if (kind === '<') {
        this.fail(after === '=' ? 'lookbehind (?<=' : 'negative lookbehind (?<!', start);
      } else if (kind === 'P') {
        this.fail('a (?P group', start);
      } else {
        this.fail('inline flags or an unknown group (?', start);
      }
    }
    const body = this.disjunction();
    if (this.peek() !== ')') {
      this.fail('an unclosed (', start);
    }
    this.position += 1;
    return { nullable: body.nullable, captures: captures || body.captures, size: body.size };
  }

  private groupName(groupStart: number): void {
    const match = /^([A-Za-z_][A-Za-z0-9_]*)>/.exec(this.source.slice(this.position));
    if (match === null) {
      this.fail('a group name that is not an ASCII identifier', groupStart);
    }
    const name = match[1] as string;
    if (this.groupNames.includes(name)) {
      this.fail(`the duplicate group name ${name}`, groupStart);
    }
    this.groupNames.push(name);
    this.position += match[0].length;
  }

  private escape(): Shape {
    const char = this.peek(1);
    if (char === 'b' || char === 'B') {
      this.position += 2;
      return { nullable: true, captures: false, size: 1 };
    }
    this.escapedCharacter(false);
    return { nullable: false, captures: false, size: 1 };
  }

  /**
   * Consume an escape that stands for one character or a class such as `\d`. `inClass` adds
   * `\-` and refuses `\b`, which a class reads as a backspace in RegExp and refuses in RE2.
   */
  private escapedCharacter(inClass: boolean): ClassMember {
    const start = this.position;
    const char = this.peek(1);
    if (char === undefined) {
      this.fail('a trailing \\', start);
    }
    this.position += 2;
    if (CLASS_ESCAPES.includes(char)) {
      return { set: true };
    }
    const control = CONTROL_ESCAPES[char];
    if (control !== undefined) {
      return { code: control };
    }
    if (SYNTAX_CHARACTERS.includes(char) || (inClass && char === '-')) {
      return { code: char.charCodeAt(0) };
    }
    if (char === 'x') {
      const digits = this.source.slice(this.position, this.position + 2);
      if (!isHexDigit(digits[0]) || !isHexDigit(digits[1])) {
        this.fail('an incomplete \\x escape', start);
      }
      const code = Number.parseInt(digits, 16);
      if (code > 0x7f) {
        this.fail('a \\x escape above \\x7F', start);
      }
      this.position += 2;
      return { code };
    }
    if (isAsciiDigit(char)) {
      this.fail(char === '0' ? 'the escape \\0' : `the backreference \\${char}`, start);
    }
    if (char === 'k') {
      this.fail('the named backreference \\k', start);
    }
    if (char === 'p' || char === 'P') {
      this.fail(`the Unicode property escape \\${char}`, start);
    }
    const code = this.source.codePointAt(start + 1) ?? 0;
    if (code > 0x7e || code < 0x20) {
      this.fail(`the escape of ${codePointLabel(code)}`, start);
    }
    return this.fail(`the escape \\${char}`, start);
  }

  private characterClass(): void {
    const start = this.position;
    this.position += 1;
    if (this.peek() === '^') {
      this.position += 1;
    }
    if (this.peek() === ']') {
      this.fail('an empty class', start);
    }
    let first = true;
    while (this.peek() !== ']') {
      if (this.peek() === undefined) {
        this.fail('an unclosed [', start);
      }
      const memberStart = this.position;
      const low = this.classMember(first);
      first = false;
      if (this.peek() !== '-' || this.peek(1) === ']' || this.peek(1) === undefined) {
        continue;
      }
      if (!('code' in low)) {
        this.fail('a class escape as a range bound', memberStart);
      }
      this.position += 1;
      const highStart = this.position;
      if (this.peek() === '-') {
        this.fail('an unescaped - as a range bound', highStart);
      }
      const high = this.classMember(false);
      if (!('code' in high)) {
        this.fail('a class escape as a range bound', highStart);
      }
      if (high.code < low.code) {
        this.fail('a range whose bounds are out of order', memberStart);
      }
    }
    this.position += 1;
  }

  private classMember(first: boolean): ClassMember {
    const start = this.position;
    const char = this.peek();
    if (char === '\\') {
      if (this.peek(1) === 'b' || this.peek(1) === 'B') {
        this.fail(`\\${this.peek(1)} in a class`, start);
      }
      return this.escapedCharacter(true);
    }
    if (char === '[') {
      this.fail('an unescaped [ in a class', start);
    }
    if (char === '-' && !first && this.peek(1) !== ']') {
      this.fail('an unescaped - that is not first, last or a range', start);
    }
    return { code: this.literal() };
  }
}

/**
 * Check a regex against the regex subset and read its named groups.
 *
 * The subset is an allowlist: printable ASCII literals, `.`, `^`, `$`, `\b`, `\B`, the class
 * escapes `\d \D \w \W \s \S`, the escapes `\t \n \r \f \v`, `\x00`–`\x7F`, a backslash before
 * a syntax character, classes of those with ranges, `(…)`, `(?:…)`, `(?<name>…)`, and the
 * quantifiers `* + ? {n} {n,} {n,m}` with an optional lazy `?`. A quantifier cannot apply to a
 * capture group or to something that can match the empty string.
 *
 * @throws {RegexSubsetError} if the regex uses anything else, naming the first such construct.
 */
export const scanRegexSubset = (source: string): RegexSubsetScan => new Scanner(source).scan();
