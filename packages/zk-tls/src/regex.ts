// The regex subset a zkFetch policy may use: syntax that RE2 and RegExp, under the flags
// Reclaim compiles with, both accept and read the same way. The dApp guide lists it.

import { type AST, RegExpParser, RegExpSyntaxError } from '@eslint-community/regexpp';

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
// in time and stack before it reads anything. The parser recurses once per group and overflows
// the stack near a few thousand, and every group opens with `(`, so counting `(` bounds it.
const MAX_LENGTH = 4096;
const MAX_PARENTHESES = 100;

// RE2 writes out every counted repeat and refuses a program over its memory budget; RegExp has
// no such limit. Holding counted repeats to single atoms whose counts sum to at most 1000 keeps
// the costliest regex in the subset near a sixth of that budget.
const MAX_REPEAT_TOTAL = 1000;

// Strict `u` mode is the strictest of the three dialects: it already refuses a lone `{`, `}`
// or `]`, identity escapes such as `\A`, `(?P<`, a class escape as a range bound and an
// out-of-order range. ES2018 adds named groups but predates inline modifiers and duplicate
// group names, so the parser refuses those too.
const parser = new RegExpParser({ ecmaVersion: 2018, strict: true });

/** The escapes a Character may be written as; everything else is refused by its raw text. */
const CHARACTER_ESCAPE = /^\\(?:[tnvfr^$\\.*+?()[\]{}|/]|x[0-7][0-9A-Fa-f])$/;

/** What the walk knows about a node. */
interface Shape {
  /** Whether it can match the empty string. */
  readonly nullable: boolean;
  /** Whether it holds a capture group. */
  readonly captures: boolean;
}

const ATOM: Shape = { nullable: false, captures: false };
const ASSERTION: Shape = { nullable: true, captures: false };

const codePointLabel = (code: number): string =>
  `U+${code.toString(16).toUpperCase().padStart(4, '0')}`;

const fail = (construct: string, index: number): never => {
  throw new RegexSubsetError(construct, index);
};

/** Allow a printable ASCII character or one of the escapes all three dialects read alike. */
const checkCharacter = (node: AST.Character, inClass: boolean): void => {
  const code = node.raw.codePointAt(0) ?? 0;
  if (code !== 0x5c) {
    if (code > 0x7e) fail(`the non-ASCII character ${codePointLabel(code)}`, node.start);
    if (code < 0x20 || code === 0x7f) {
      fail(`the control character ${codePointLabel(code)}; escape it`, node.start);
    }
    return;
  }
  if (CHARACTER_ESCAPE.test(node.raw) || (inClass && node.raw === '\\-')) {
    return;
  }
  fail(`the escape ${node.raw}`, node.start);
};

class Walk {
  readonly groupNames: string[] = [];
  private repeatTotal = 0;

  disjunction(alternatives: readonly AST.Alternative[]): Shape {
    const shapes = alternatives.map((alternative) => this.alternative(alternative));
    return {
      nullable: shapes.some((shape) => shape.nullable),
      captures: shapes.some((shape) => shape.captures),
    };
  }

  private alternative(node: AST.Alternative): Shape {
    const shapes = node.elements.map((element) => this.element(element));
    return {
      nullable: shapes.every((shape) => shape.nullable),
      captures: shapes.some((shape) => shape.captures),
    };
  }

  private element(node: AST.Element): Shape {
    switch (node.type) {
      case 'Quantifier':
        return this.quantifier(node);
      case 'Assertion':
        if (node.kind === 'lookahead' || node.kind === 'lookbehind') {
          return fail(`${node.negate ? 'negative ' : ''}${node.kind}`, node.start);
        }
        return ASSERTION;
      case 'Backreference':
        return fail(`the backreference ${node.raw}`, node.start);
      case 'Character':
        checkCharacter(node, false);
        return ATOM;
      case 'CharacterSet':
        if (node.kind === 'property') {
          return fail(`the Unicode property escape ${node.raw.slice(0, 2)}`, node.start);
        }
        return ATOM;
      case 'CharacterClass':
        this.characterClass(node);
        return ATOM;
      case 'Group':
      case 'CapturingGroup':
        return this.group(node);
      default:
        return fail(`the construct ${node.raw}`, node.start);
    }
  }

  private group(node: AST.Group | AST.CapturingGroup): Shape {
    if (node.type === 'CapturingGroup' && node.name !== null) {
      this.groupNames.push(node.name);
    }
    const body = this.disjunction(node.alternatives);
    return { ...body, captures: node.type === 'CapturingGroup' || body.captures };
  }

  private quantifier(node: AST.Quantifier): Shape {
    const atom = this.element(node.element);
    const quantifierStart = node.element.end;
    // RegExp resets a group's captures on every iteration and refuses an empty one; RE2
    // keeps the last captures and takes the empty one. Both change what a match returns.
    if (atom.captures) {
      fail('a quantifier on a capture group', quantifierStart);
    }
    if (atom.nullable) {
      fail('a quantifier on something that can match the empty string', quantifierStart);
    }
    const text = node.raw.slice(node.element.end - node.start);
    if (text.startsWith('{')) {
      this.countedRepeat(node, text, quantifierStart);
    }
    return { ...atom, nullable: node.min === 0 };
  }

  private countedRepeat(node: AST.Quantifier, text: string, start: number): void {
    if (node.element.type === 'Group' || node.element.type === 'CapturingGroup') {
      fail('a counted repeat on a group', start);
    }
    // RE2 reads `{02}` as literal text; RegExp reads it as a count.
    if (/[{,]0\d/.test(text)) {
      fail('a repeat count with a leading zero', start);
    }
    // RE2 writes the maximum out, else the minimum.
    this.repeatTotal += Number.isFinite(node.max) ? node.max : node.min;
    if (this.repeatTotal > MAX_REPEAT_TOTAL) {
      fail(`repeat counts adding up past ${MAX_REPEAT_TOTAL}`, start);
    }
  }

  private characterClass(node: AST.CharacterClass): void {
    // RE2 reads `[]a]` as a class holding `]` and `a`; RegExp reads `[]` as matching nothing.
    if (node.elements.length === 0) {
      fail('an empty class', node.start);
    }
    node.elements.forEach((element, position) => {
      switch (element.type) {
        case 'Character':
          checkCharacter(element, true);
          // RE2 refuses `[a-c-e]`; RegExp reads the middle `-` as a literal.
          if (element.raw === '-' && position > 0 && position < node.elements.length - 1) {
            fail('an unescaped - that is not first, last or a range bound', element.start);
          }
          return;
        case 'CharacterClassRange':
          checkCharacter(element.min, true);
          checkCharacter(element.max, true);
          return;
        case 'CharacterSet':
          if (element.kind === 'property') {
            fail(`the Unicode property escape ${element.raw.slice(0, 2)}`, element.start);
          }
          return;
        default:
          fail(`the class member ${element.raw}`, element.start);
      }
    });
  }
}

const parse = (source: string): AST.Pattern => {
  try {
    return parser.parsePattern(source, 0, source.length, { unicode: true });
  } catch (error) {
    if (error instanceof RegExpSyntaxError) {
      // The parser's message repeats the whole pattern; keep only its reason.
      const reason = error.message.replace(/^Invalid regular expression: \/.*\/u?: /s, '');
      return fail(`invalid syntax (${reason})`, error.index);
    }
    throw error;
  }
};

/**
 * Check a regex against the regex subset and read its named groups. The subset is listed in the
 * dApp guide's "Regex subset" section, under "Building the policy".
 *
 * @throws {RegexSubsetError} if the regex is outside the subset, naming the first construct
 *   outside it.
 */
export const scanRegexSubset = (source: string): RegexSubsetScan => {
  if (source.length > MAX_LENGTH) {
    fail(`more than ${MAX_LENGTH} characters`, MAX_LENGTH);
  }
  let parentheses = 0;
  for (let index = source.indexOf('('); index !== -1; index = source.indexOf('(', index + 1)) {
    parentheses += 1;
    if (parentheses > MAX_PARENTHESES) {
      fail(`more than ${MAX_PARENTHESES} ( characters`, index);
    }
  }
  const walk = new Walk();
  walk.disjunction(parse(source).alternatives);
  return { groupNames: walk.groupNames };
};
