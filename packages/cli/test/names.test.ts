// Accessor naming and the name-collision checks `thoth generate` runs before it
// writes anything.
import type { KindLayout } from '@thoth/core/kind';
import { describe, expect, it } from 'vitest';
import { accessorsOf, checkNames, compactDeclarations } from '../src/names.js';

const layout: KindLayout = {
  valueSlots: 2,
  byteSlots: 1,
  names: [
    { name: 'distance', region: 'numeric', index: 0, optional: false },
    { name: 'movingTime', region: 'numeric', index: 1, optional: true },
    { name: 'type', region: 'bytes', index: 0, optional: false },
  ],
};

describe('accessorsOf', () => {
  it('names a value accessor and a presence flag per slot, using the slot name only as a stem', () => {
    expect(accessorsOf(layout)).toEqual([
      { slot: layout.names[0], value: 'distanceOf', present: 'distancePresent' },
      { slot: layout.names[1], value: 'movingTimeOf', present: 'movingTimePresent' },
      { slot: layout.names[2], value: 'typeOf', present: 'typePresent' },
    ]);
  });
});

describe('compactDeclarations', () => {
  it('lists declared names and import prefixes, skipping comments and strings', () => {
    const source = `
      include "generated/thoth";
      import "token"<3> prefix Tok_;
      // circuit commented(): [] {}
      /* witness blockComment(): Field; */
      export sealed ledger owner: Bytes<32>;
      export ledger rewarded: Counter;
      struct Reward { amount: Uint<64>; }
      enum Tier { gold, silver }
      witness secretKey(): Bytes<32>;
      export pure circuit score(x: Uint<64>): Uint<64> { return x; }
      export circuit claim(): [] { assert(true, "circuit inString(): []"); }
    `;
    expect(compactDeclarations(source)).toEqual([
      { kind: 'prefix', name: 'Tok_' },
      { kind: 'ledger', name: 'owner' },
      { kind: 'ledger', name: 'rewarded' },
      { kind: 'struct', name: 'Reward' },
      { kind: 'enum', name: 'Tier' },
      { kind: 'witness', name: 'secretKey' },
      { kind: 'circuit', name: 'score' },
      { kind: 'circuit', name: 'claim' },
    ]);
  });
});

describe('checkNames', () => {
  it('accepts an app whose names stay clear of the generated ones', () => {
    expect(() => checkNames(layout, 'export circuit claimReward(): [] {}')).not.toThrow();
  });

  it.each([
    ['an accessor', 'circuit distanceOf(x: Field): Field { return x; }', 'distanceOf'],
    ['a presence flag', 'export ledger typePresent: Boolean;', 'typePresent'],
    ['the init circuit', 'circuit thothInit(): [] {}', 'thothInit'],
    ['the policy witness', 'witness seedPolicies(): Vector<1, Bytes<32>>;', 'seedPolicies'],
    ['a module witness', 'witness getHolderSecret(): Bytes<32>;', 'getHolderSecret'],
    [
      'an exported circuit',
      'export pure circuit message(x: Field): Field { return x; }',
      'message',
    ],
  ])('refuses an app declaration that reuses %s', (_, source, name) => {
    expect(() => checkNames(layout, source)).toThrow(
      `the app contract declares '${name}', which thoth generate also declares`,
    );
  });

  it.each([
    ['a declaration', 'circuit Thoth_helper(): [] {}', "'Thoth_helper'"],
    ['an import prefix', 'import "other" prefix ThothRegistry_;', "'ThothRegistry_'"],
  ])('refuses %s inside a generated module prefix', (_, source, name) => {
    expect(() => checkNames(layout, source)).toThrow(
      `the app contract declares ${name}, inside the generated module prefix`,
    );
  });

  it('refuses a slot whose accessors land inside a generated module prefix', () => {
    const prefixed: KindLayout = {
      valueSlots: 1,
      byteSlots: 0,
      names: [{ name: 'Thoth_holder', region: 'numeric', index: 0, optional: false }],
    };
    expect(() => checkNames(prefixed, '')).toThrow(
      "slot 'Thoth_holder': accessor 'Thoth_holderOf' is inside the generated module prefix 'Thoth_'",
    );
  });
});
