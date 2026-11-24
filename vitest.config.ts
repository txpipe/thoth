import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    // One glob for every package: CI runs vitest from the root, so a package left off a
    // hand-kept list would have its tests skipped without any error.
    include: ['packages/*/test/**/*.test.ts'],
    exclude: [...configDefaults.exclude],
    reporters: 'verbose',
  },
});
