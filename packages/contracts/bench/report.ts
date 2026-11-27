// The proving benchmark's report: one row per circuit from its measured proofs, and the table
// the benchmark prints.

/** One `/prove` request: its wall time, and the server's CPU time when the benchmark can read it. */
export type ProofRun = { ms: number; cpuSeconds: number | null };

/** What the benchmark measured for one circuit. */
export type CircuitMeasurement = {
  mock: string;
  circuit: string;
  k: number;
  rows: number;
  proverKeyBytes: number;
  verifierKeyBytes: number;
  proofBytes: number;
  /** The first proof with this circuit's proving key, which includes parsing the key. */
  first: ProofRun;
  /** Later proofs with the same key, which the server finds already parsed. */
  warm: ProofRun[];
  /** The server's peak memory while it proved this circuit, or `null` when not measured. */
  peakMemoryBytes: number | null;
};

/** One circuit's line of the report. */
export type CircuitRow = Omit<CircuitMeasurement, 'first' | 'warm'> & {
  firstMs: number;
  warmMs: number[];
  warmMedianMs: number;
  /**
   * True when the first proof was not clearly slower than the warm ones: the server had parsed
   * this key already, so `firstMs` is not the cost of a circuit's first proof.
   */
  firstWasCached: boolean;
  /** Median server CPU time of a warm proof, or `null` when not measured. */
  warmCpuSeconds: number | null;
};

// A first proof within this factor of the warm median found its key already parsed.
const CACHED_MARGIN = 1.1;

const median = (values: readonly number[]): number => {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  const upper = sorted[middle] ?? Number.NaN;
  return sorted.length % 2 === 1 ? upper : ((sorted[middle - 1] ?? upper) + upper) / 2;
};

/**
 * Summarize one circuit's proofs into its report row.
 *
 * @throws {Error} when there is no warm proof to take a median of.
 */
export const summarize = ({ first, warm, ...sizes }: CircuitMeasurement): CircuitRow => {
  if (warm.length === 0) {
    throw new Error(`${sizes.mock}.${sizes.circuit}: no warm proof to summarize`);
  }
  const cpu = warm.map((run) => run.cpuSeconds);
  const warmMedianMs = median(warm.map((run) => run.ms));
  return {
    ...sizes,
    firstMs: first.ms,
    warmMs: warm.map((run) => run.ms),
    warmMedianMs,
    // Parsing a proving key adds about a third to a proof at every k measured (14, 15 and 17).
    firstWasCached: first.ms < warmMedianMs * CACHED_MARGIN,
    warmCpuSeconds: cpu.every((s) => s !== null) ? median(cpu) : null,
  };
};

const NOT_MEASURED = 'not measured';
const count = (n: number): string => n.toLocaleString('en-US');
const seconds = (ms: number): string => (ms / 1000).toFixed(2);
const megabytes = (bytes: number): string => (bytes / 1e6).toFixed(1);

/** Render the report rows as a Markdown table, the form the contracts README carries. */
export const formatTable = (rows: readonly CircuitRow[]): string =>
  [
    '| Mock | Circuit | k | Rows | Proving key (MB) | Proof (B) | First proof (s) | Warm proof (s) | CPU per warm proof (s) | Peak memory (MB) |',
    '|---|---|---|---|---|---|---|---|---|---|',
    ...rows
      .map((r) =>
        [
          r.mock,
          r.circuit,
          r.k,
          count(r.rows),
          megabytes(r.proverKeyBytes),
          count(r.proofBytes),
          `${seconds(r.firstMs)}${r.firstWasCached ? ' (key was cached)' : ''}`,
          seconds(r.warmMedianMs),
          r.warmCpuSeconds === null ? NOT_MEASURED : r.warmCpuSeconds.toFixed(1),
          r.peakMemoryBytes === null ? NOT_MEASURED : Math.round(r.peakMemoryBytes / 1e6),
        ].join(' | '),
      )
      .map((line) => `| ${line} |`),
  ].join('\n');
