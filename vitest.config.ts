import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: [
      'packages/contracts/**/*.test.ts',
      'packages/cardano/**/*.test.ts',
      'packages/core/**/*.test.ts',
      'packages/client/**/*.test.ts',
      'packages/zk-tls/**/*.test.ts',
    ],
    exclude: [...configDefaults.exclude],
    reporters: 'verbose',
  },
});
