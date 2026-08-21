import { describe, expect, it } from 'vitest';

import { thoth } from './index.js';

describe('thoth', () => {
  it('exports the placeholder namespace', () => {
    expect(thoth).toEqual({});
  });
});
