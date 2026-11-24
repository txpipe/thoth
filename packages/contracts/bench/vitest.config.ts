import { defineConfig } from 'vitest/config';

// Separate from the test config so `npm test` and CI never run the benchmark.
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    root: import.meta.dirname,
    include: ['**/*.bench.ts'],
    reporters: 'default',
    fileParallelism: false,
  },
});
