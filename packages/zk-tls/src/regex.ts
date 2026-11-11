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

// The attestor parses a caller-supplied policy before any proof check, so the scan is bounded
// in time and stack before it reads anything.
const MAX_LENGTH = 4096;
const MAX_DEPTH = 100;

// RE2's own limits, which RegExp does not have: a counted repeat above 1000, and nested counted
// repeats whose counts multiply past 1000, fail to compile.
const MAX_REPEAT = 1000;

// RE2 also refuses a compiled program over its memory budget. Weights bound each atom's
// measured share of it from above: RE2 fails near 125,000 for the costliest atoms (a negated
// class of 47 alternating characters, `\W`), so the cap keeps a margin of three.
const MAX_PROGRAM = 40_000;
const CHARACTER_WEIGHT = 1;
const WIDE_WEIGHT = 8;

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

// Sticky, so a match reads at `lastIndex` without copying the rest of the source. A count has
// no leading zero: RE2 reads `{02}` as literal text.
const COUNTED_QUANTIFIER = /\{(0|[1-9]\d*)(,(0|[1-9]\d*)?)?\}/y;
const ANY_COUNTED_QUANTIFIER = /\{\d+(,\d*)?\}/y;
const GROUP_NAME = /([A-Za-z_][A-Za-z0-9_]*)>/y;
const HEX_PAIR = /[0-9A-Fa-f]{2}/y;

/** What the parser knows about a parsed piece of the pattern. */
interface Shape {
  /** Whether it can match the empty string. */
  readonly nullable: boolean;
  /** Whether it holds a capture group. */
  readonly captures: boolean;
  /** The largest product of counted repeats along any nesting path inside it, as RE2 counts. */
  readonly repeat: number;
  /** Its weighted size once every counted repeat is written out; see {@link MAX_PROGRAM}. */
  readonly weight: number;
}

/** A quantifier's bounds; `max` is undefined when unbounded. */
interface Counts {
  readonly min: number;
  readonly max: number | undefined;
  readonly counted: boolean;
}

/** One class member: a single character, or a set such as `\d` that cannot bound a range. */
type ClassMember = { readonly code: number } | { readonly set: true };

const atomShape = (nullable: boolean, weight: number): Shape => ({
  nullable,
  captures: false,
  repeat: 1,
  weight,
});

const isAsciiDigit = (char: string | undefined): boolean =>
  char !== undefined && char >= '0' && char <= '9';

const codePointLabel = (code: number): string =>
  `U+${code.toString(16).toUpperCase().padStart(4, '0')}`;

class Scanner {
  private position = 0;
  private depth = 0;
  private readonly groupNames = new Set<string>();
  private readonly source: string;

  constructor(source: string) {
    this.source = source;
  }

  scan(): RegexSubsetScan {
    if (this.source.length > MAX_LENGTH) {
      this.fail(`more than ${MAX_LENGTH} characters`, MAX_LENGTH);
    }
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

  /** Run a sticky pattern at the current position. */
  private read(pattern: RegExp): RegExpExecArray | null {
    pattern.lastIndex = this.position;
    return pattern.exec(this.source);
  }

  /** Refuse a weight past {@link MAX_PROGRAM}, naming the construct that starts at `index`. */
  private weighed(weight: number, index: number): number {
    if (weight > MAX_PROGRAM) {
      this.fail('a pattern too large for RE2 once counted repeats are written out', index);
    }
    return weight;
  }

  private disjunction(): Shape {
    let shape = this.alternative();
    while (this.peek() === '|') {
      this.position += 1;
      const start = this.position;
      const next = this.alternative();
      shape = {
        nullable: shape.nullable || next.nullable,
        captures: shape.captures || next.captures,
        repeat: Math.max(shape.repeat, next.repeat),
        weight: this.weighed(shape.weight + next.weight, start),
      };
    }
    return shape;
  }

  private alternative(): Shape {
    let nullable = true;
    let captures = false;
    let repeat = 1;
    let weight = 0;
    while (this.peek() !== undefined && this.peek() !== '|' && this.peek() !== ')') {
      const start = this.position;
      const term = this.term();
      nullable &&= term.nullable;
      captures ||= term.captures;
      repeat = Math.max(repeat, term.repeat);
      weight = this.weighed(weight + term.weight, start);
    }
    return { nullable, captures, repeat, weight };
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
    if (!counts.counted) {
      return { ...atom, nullable: counts.min === 0 };
    }
    if (counts.min > MAX_REPEAT || (counts.max ?? 0) > MAX_REPEAT) {
      this.fail(`a repeat count above ${MAX_REPEAT}`, quantifierStart);
    }
    // RE2 counts the maximum, else the minimum, and skips a zero.
    const factor = Math.max(counts.max ?? counts.min, 1);
    const repeat = atom.repeat * factor;
    if (repeat > MAX_REPEAT) {
      this.fail(`nested repeat counts multiplying past ${MAX_REPEAT}`, start);
    }
    return {
      nullable: counts.min === 0,
      captures: false,
      repeat,
      weight: this.weighed(atom.weight * factor, start),
    };
  }

  /** Parse a quantifier if one follows. */
  private quantifier(): Counts | undefined {
    const start = this.position;
    let counts: Counts;
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

  private countedQuantifier(): Counts {
    const start = this.position;
    const match = this.read(COUNTED_QUANTIFIER);
    if (match === null) {
      this.fail(
        this.read(ANY_COUNTED_QUANTIFIER) === null
          ? 'an unescaped {'
          : 'a repeat count with a leading zero',
        start,
      );
    }
    this.position += match[0].length;
    const min = Number(match[1]);
    const max =
      match[2] === undefined ? min : match[3] === undefined ? undefined : Number(match[3]);
    if (max !== undefined && max < min) {
      this.fail('a repeat range whose maximum is below its minimum', start);
    }
    return { min, max, counted: true };
  }

  private atom(): Shape {
    const start = this.position;
    const char = this.peek();
    switch (char) {
      case '^':
      case '$':
        this.position += 1;
        return atomShape(true, CHARACTER_WEIGHT);
      case '.':
        this.position += 1;
        return atomShape(false, WIDE_WEIGHT);
      case '(':
        return this.group();
      case '[':
        return atomShape(false, this.characterClass());
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
        return atomShape(false, CHARACTER_WEIGHT);
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
    if (this.depth >= MAX_DEPTH) {
      this.fail(`groups nested more than ${MAX_DEPTH} deep`, start);
    }
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
    this.depth += 1;
    const body = this.disjunction();
    this.depth -= 1;
    if (this.peek() !== ')') {
      this.fail('an unclosed (', start);
    }
    this.position += 1;
    return { ...body, captures: captures || body.captures };
  }

  private groupName(groupStart: number): void {
    const match = this.read(GROUP_NAME);
    if (match === null) {
      this.fail('a group name that is not an ASCII identifier', groupStart);
    }
    const name = match[1] as string;
    if (this.groupNames.has(name)) {
      this.fail(`the duplicate group name ${name}`, groupStart);
    }
    this.groupNames.add(name);
    this.position += match[0].length;
  }

  private escape(): Shape {
    const char = this.peek(1);
    if (char === 'b' || char === 'B') {
      this.position += 2;
      return atomShape(true, CHARACTER_WEIGHT);
    }
    const member = this.escapedCharacter(false);
    return atomShape(false, 'set' in member ? WIDE_WEIGHT : CHARACTER_WEIGHT);
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
      const digits = this.read(HEX_PAIR);
      if (digits === null) {
        this.fail('an incomplete \\x escape', start);
      }
      const code = Number.parseInt(digits[0], 16);
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

  /** Consume a bracket class and return its weight: a wide atom plus one per member. */
  private characterClass(): number {
    const start = this.position;
    this.position += 1;
    if (this.peek() === '^') {
      this.position += 1;
    }
    if (this.peek() === ']') {
      // RE2 reads a leading `]` as a member, RegExp as the end of an empty class.
      this.fail('a ] first in a class; escape it as \\]', this.position);
    }
    let members = 0;
    while (this.peek() !== ']') {
      if (this.peek() === undefined) {
        this.fail('an unclosed [', start);
      }
      members += 1;
      const memberStart = this.position;
      const low = this.classMember(members === 1);
      if (this.peek() !== '-' || this.peek(1) === ']' || this.peek(1) === undefined) {
        continue;
      }
      if (!('code' in low)) {
        this.fail('a class escape as a range bound', memberStart);
      }
      this.position += 1;
      const highStart = this.position;
      // A bare `-` may end a range: `[!--]` is `!` to `-` in every engine.
      const high = this.peek() === '-' ? this.literalDash() : this.classMember(false);
      if (!('code' in high)) {
        this.fail('a class escape as a range bound', highStart);
      }
      if (high.code < low.code) {
        this.fail('a range whose bounds are out of order', memberStart);
      }
    }
    this.position += 1;
    return WIDE_WEIGHT + members;
  }

  private literalDash(): ClassMember {
    this.position += 1;
    return { code: 0x2d };
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
      this.fail('an unescaped - that is not first, last or a range bound', start);
    }
    return { code: this.literal() };
  }
}

/**
 * Check a regex against the regex subset and read its named groups. The subset is listed in the
 * dApp guide's "Regex subset" section, under "Building the policy".
 *
 * @throws {RegexSubsetError} if the regex is outside the subset, naming the first construct
 *   outside it.
 */
export const scanRegexSubset = (source: string): RegexSubsetScan => new Scanner(source).scan();
