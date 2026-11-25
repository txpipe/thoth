// Minimal type declaration for the `ws` devDependency used by `fake-witness.ts`.
declare module 'ws' {
  import type { EventEmitter } from 'node:events';
  import type { IncomingMessage } from 'node:http';
  import type { AddressInfo } from 'node:net';

  export interface WebSocket extends EventEmitter {
    send(data: Uint8Array | string): void;
    terminate(): void;
    on(event: 'message', listener: (data: Buffer) => void): this;
    on(event: 'close', listener: () => void): this;
    on(event: string, listener: (...args: unknown[]) => void): this;
  }

  export class WebSocketServer extends EventEmitter {
    readonly clients: Set<WebSocket>;
    constructor(options: { port?: number; host?: string });
    address(): AddressInfo | string | null;
    close(callback?: (err?: Error) => void): void;
    on(event: 'connection', listener: (ws: WebSocket, request: IncomingMessage) => void): this;
    on(event: string, listener: (...args: unknown[]) => void): this;
  }
}
