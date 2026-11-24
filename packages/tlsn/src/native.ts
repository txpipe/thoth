// Run the thoth-tlsn binary: one subprocess per call, JSON on stdout.

import { spawn } from 'node:child_process';

/** The most output a thoth-tlsn call may print, so a runaway process cannot exhaust memory. */
const MAX_OUTPUT_BYTES = 32 * 1024 * 1024;

/** A thoth-tlsn call failed. `stderr` is the tool's own diagnostics, kept local. */
export class TlsnNativeError extends Error {
  /** The tool's diagnostics. Never forward it to a remote caller. */
  readonly stderr: string;

  /** Build the error from the subcommand and what the tool printed. */
  constructor(command: string, stderr: string, options?: ErrorOptions) {
    super(`thoth-tlsn ${command} failed`, options);
    this.name = 'TlsnNativeError';
    this.stderr = stderr;
  }
}

/**
 * Run `binary args…` with `stdin`, and parse its stdout as JSON.
 *
 * @throws {@link TlsnNativeError} if the process cannot start, exits non-zero,
 *   times out, prints too much, or prints something that is not JSON.
 */
export const runNative = (options: {
  binary: string;
  args: readonly string[];
  stdin?: string;
  timeoutMs: number;
}): Promise<unknown> =>
  new Promise((resolve, reject) => {
    const command = options.args[0] ?? '';
    const child = spawn(options.binary, options.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: options.timeoutMs,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let size = 0;
    child.stdout.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_OUTPUT_BYTES) {
        child.kill();
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      if (stderr.reduce((total, part) => total + part.length, 0) < 64 * 1024) stderr.push(chunk);
    });
    child.on('error', (error) => {
      reject(new TlsnNativeError(command, '', { cause: error }));
    });
    child.on('close', (code) => {
      const diagnostics = Buffer.concat(stderr).toString('utf-8');
      if (code !== 0 || size > MAX_OUTPUT_BYTES) {
        reject(new TlsnNativeError(command, diagnostics));
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(stdout).toString('utf-8')));
      } catch (error) {
        reject(new TlsnNativeError(command, diagnostics, { cause: error }));
      }
    });
    child.stdin.on('error', () => {
      // A process that exits before reading stdin is reported by `close`.
    });
    child.stdin.end(options.stdin ?? '');
  });
