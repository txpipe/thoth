// The proving benchmark's report: how it summarizes one circuit's proofs and what it prints.
// The benchmark itself needs a proof server, so it runs only through `npm run bench`.
import { describe, expect, it } from 'vitest';
import { type CircuitMeasurement, formatTable, summarize } from '../bench/report.js';

const measured = (overrides: Partial<CircuitMeasurement> = {}): CircuitMeasurement => ({
  mock: 'mock_attestation',
  circuit: 'openAndRead',
  k: 14,
  rows: 8610,
  proverKeyBytes: 24_600_000,
  verifierKeyBytes: 2_000,
  proofBytes: 5_772,
  first: { ms: 1_600, cpuSeconds: 12 },
  warm: [
    { ms: 1_300, cpuSeconds: 10.8 },
    { ms: 1_200, cpuSeconds: 10.2 },
    { ms: 1_250, cpuSeconds: 10.6 },
  ],
  peakMemoryBytes: 380_000_000,
  ...overrides,
});

describe('summarize', () => {
  it('reports the warm median time and the median CPU time per warm proof', () => {
    const row = summarize(measured());
    expect(row.warmMedianMs).toBe(1_250);
    expect(row.warmCpuSeconds).toBe(10.6);
    expect(row.firstMs).toBe(1_600);
  });

  // Parsing a proving key adds about a third to a proof, so a first proof as fast as the warm
  // ones ran on a server that had already parsed the key.
  it('flags a first proof that was not slower than the warm ones as cached', () => {
    expect(summarize(measured()).firstWasCached).toBe(false);
    expect(summarize(measured({ first: { ms: 1_300, cpuSeconds: 10.9 } })).firstWasCached).toBe(
      true,
    );
  });
});

describe('formatTable', () => {
  it('prints one line per circuit with its sizes, times, CPU time and peak memory', () => {
    const [, , line] = formatTable([summarize(measured())]).split('\n');
    expect(line).toBe(
      '| mock_attestation | openAndRead | 14 | 8,610 | 24.6 | 5,772 | 1.60 | 1.25 | 10.6 | 380 |',
    );
  });

  it('prints CPU time and peak memory as not measured on a server the benchmark did not start', () => {
    const unmeasured = measured({
      first: { ms: 1_600, cpuSeconds: null },
      warm: [{ ms: 1_250, cpuSeconds: null }],
      peakMemoryBytes: null,
    });
    const [, , line] = formatTable([summarize(unmeasured)]).split('\n');
    expect(line).toBe(
      '| mock_attestation | openAndRead | 14 | 8,610 | 24.6 | 5,772 | 1.60 | 1.25 | not measured | not measured |',
    );
  });

  it('marks a first proof whose key the server had already parsed', () => {
    const cached = measured({ first: { ms: 1_250, cpuSeconds: 10.6 } });
    const [, , line] = formatTable([summarize(cached)]).split('\n');
    expect(line).toContain('| 1.25 (key was cached) |');
  });
});
