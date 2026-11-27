import { defineConfig } from 'vitest/config';

// Separate from the test config so `npm test` and CI never run the benchmark.
export default defineConfig({
  test: {
    environment: 'node',
    root: import.meta.dirname,
    include: ['**/*.bench.ts'],
    fileParallelism: false,
    globalSetup: ['global-setup.ts'],
    // A child process, not a worker thread: only a process receives the SIGINT or SIGTERM on
    // which the benchmark removes its proof server container.
    pool: 'forks',
    // The report is the benchmark's output, so keep it even when the run passes; vitest's
    // agent reporter would hide a passing test's console output.
    reporters: ['default'],
  },
});
