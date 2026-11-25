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

/** A running thoth-tlsn process that exchanges one JSON object per line. */
export interface NativeSession {
  /** Write one JSON line to the process. */
  send(message: unknown): void;
  /**
   * The next JSON line the process prints.
   *
   * @throws {@link TlsnNativeError} if the process exits first or prints something that is not JSON.
   */
  next(): Promise<unknown>;
  /**
   * Close stdin and wait for a clean exit.
   *
   * @throws {@link TlsnNativeError} if the process exits non-zero or times out.
   */
  finish(): Promise<void>;
  /** Stop the process without waiting. */
  kill(): void;
}

/** Start `binary args…` for a line-by-line JSON exchange. */
export const startNativeSession = (options: {
  binary: string;
  args: readonly string[];
  timeoutMs: number;
}): NativeSession => {
  const command = options.args[0] ?? '';
  const child = spawn(options.binary, options.args, {
    stdio: ['pipe', 'pipe', 'pipe'],
    timeout: options.timeoutMs,
  });
  const stderr: Buffer[] = [];
  let stderrSize = 0;
  child.stderr.on('data', (chunk: Buffer) => {
    if (stderrSize < 64 * 1024) {
      stderr.push(chunk);
      stderrSize += chunk.length;
    }
  });
  const diagnostics = () => Buffer.concat(stderr).toString('utf-8');

  const lines: string[] = [];
  const waiters: { resolve: (line: string) => void; reject: (error: Error) => void }[] = [];
  let buffered = '';
  let closed: Error | undefined;
  child.stdout.setEncoding('utf-8');
  child.stdout.on('data', (chunk: string) => {
    buffered += chunk;
    if (buffered.length > MAX_OUTPUT_BYTES) {
      child.kill();
      return;
    }
    for (let newline = buffered.indexOf('\n'); newline >= 0; newline = buffered.indexOf('\n')) {
      const line = buffered.slice(0, newline);
      buffered = buffered.slice(newline + 1);
      const waiter = waiters.shift();
      if (waiter === undefined) lines.push(line);
      else waiter.resolve(line);
    }
  });
  const exited = new Promise<number | null>((resolve) => {
    child.on('close', (code) => {
      closed = new TlsnNativeError(command, diagnostics());
      for (const waiter of waiters.splice(0)) waiter.reject(closed);
      resolve(code);
    });
  });
  child.on('error', (error) => {
    closed = new TlsnNativeError(command, '', { cause: error });
  });
  child.stdin.on('error', () => {
    // A process that exits before reading stdin is reported by `close`.
  });

  return {
    send: (message) => {
      child.stdin.write(`${JSON.stringify(message)}\n`);
    },
    next: async () => {
      const line =
        lines.shift() ??
        (closed !== undefined
          ? Promise.reject(closed)
          : new Promise<string>((resolve, reject) => waiters.push({ resolve, reject })));
      const text = await line;
      try {
        return JSON.parse(text);
      } catch (error) {
        throw new TlsnNativeError(command, diagnostics(), { cause: error });
      }
    },
    finish: async () => {
      child.stdin.end();
      const code = await exited;
      if (code !== 0) {
        throw new TlsnNativeError(command, diagnostics());
      }
    },
    kill: () => {
      child.kill();
    },
  };
};
