import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.test.ts', 'contracts/**/*.test.ts'],
    exclude: [...configDefaults.exclude],
    reporters: 'verbose',
  },
});
