// Unit tests for `denseLayout` (`@thoth/core/kind`): the claim layout a kind's
// policy slots imply, and the slot maps it refuses.
import { denseLayout, type PolicySlot } from '@thoth/core/kind';
import { describe, expect, it } from 'vitest';

const numeric = (slot: number, name: string, optional = false): PolicySlot => ({
  slot,
  name,
  region: 'numeric',
  optional,
});
const bytes = (slot: number, name: string, optional = false): PolicySlot => ({
  slot,
  name,
  region: 'bytes',
  optional,
});

describe('denseLayout', () => {
  it('counts numeric slots from 0 and byte slots right after them', () => {
    const layout = denseLayout([
      bytes(2, 'owner'),
      numeric(1, 'forks', true),
      numeric(0, 'stars'),
      bytes(3, 'repo', true),
    ]);
    expect(layout).toEqual({
      valueSlots: 2,
      byteSlots: 2,
      names: [
        { name: 'stars', region: 'numeric', index: 0, optional: false },
        { name: 'forks', region: 'numeric', index: 1, optional: true },
        { name: 'owner', region: 'bytes', index: 0, optional: false },
        { name: 'repo', region: 'bytes', index: 1, optional: true },
      ],
    });
  });

  it('lays out a numeric-only or a bytes-only policy', () => {
    expect(denseLayout([numeric(0, 'stars')])).toMatchObject({ valueSlots: 1, byteSlots: 0 });
    expect(denseLayout([bytes(0, 'owner')])).toMatchObject({
      valueSlots: 0,
      byteSlots: 1,
      names: [{ name: 'owner', region: 'bytes', index: 0, optional: false }],
    });
  });

  it('refuses a gap, naming the unused slot and how to renumber', () => {
    expect(() =>
      denseLayout([numeric(0, 'stars'), numeric(1, 'forks'), bytes(3, 'owner')]),
    ).toThrow("slot 2 is unused; renumber 'owner' from 3 to 2");
    expect(() => denseLayout([numeric(1, 'stars')])).toThrow(
      "slot 0 is unused; renumber 'stars' from 1 to 0",
    );
  });

  it('refuses a byte slot before a numeric slot, saying how to renumber', () => {
    expect(() => denseLayout([bytes(0, 'owner'), numeric(1, 'stars')])).toThrow(
      "byte slot 0 ('owner') comes before numeric slot 1 ('stars'); " +
        "renumber 'stars' from 1 to 0, 'owner' from 0 to 1",
    );
  });

  it('refuses a slot index used twice', () => {
    expect(() => denseLayout([numeric(0, 'stars'), numeric(0, 'forks')])).toThrow(
      "slot 0 is used by both 'stars' and 'forks'",
    );
  });

  it('refuses a slot index that is not a non-negative integer', () => {
    expect(() => denseLayout([numeric(-1, 'stars')])).toThrow(
      "slot -1 ('stars') is not a non-negative integer",
    );
    expect(() => denseLayout([numeric(0.5, 'stars')])).toThrow(
      "slot 0.5 ('stars') is not a non-negative integer",
    );
  });

  it.each(['a$b', '$x', 'café', '1st', 'a-b', ''])(
    'refuses %j, which is not an ASCII identifier, naming its slot',
    (name) => {
      expect(() => denseLayout([numeric(0, 'stars'), numeric(1, name)])).toThrow(
        `slot 1: name ${JSON.stringify(name)} is not an ASCII identifier`,
      );
    },
  );

  it.each(['_x', 'stars2', 'Owner_ID'])('accepts the identifier %j', (name) => {
    expect(denseLayout([numeric(0, name)]).names[0]?.name).toBe(name);
  });

  it('refuses a name used by two slots', () => {
    expect(() => denseLayout([numeric(0, 'stars'), bytes(1, 'stars')])).toThrow(
      "slot 1: name 'stars' is also used by slot 0",
    );
  });
});
