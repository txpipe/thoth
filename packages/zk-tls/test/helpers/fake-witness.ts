// An offline stand-in for a Reclaim witness and the source it fetches from, so
// tests drive attestor-core's real client: its TLS handshake, request and receipt checks.
import { once } from 'node:events';
import { type AddressInfo, connect, type Socket } from 'node:net';
import { createServer as createTlsServer } from 'node:tls';
import { AttestorError, proto } from '@reclaimprotocol/attestor-core';
import { WebSocketServer } from 'ws';

/** A self-signed P-256 certificate for `localhost`, valid until 2126. */
const SOURCE_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOyT9i6KeFiSEVuR5
MQVpDaLOdocYr51JiuPMSnpcpH2hRANCAAQrGb2XjftvGWMtC+IH3ZmTJCFR8N4y
q7ljEKUwHD3V+U6DjVpoDosgaH6qY8Cjk2ytfRJeYiWhY/ApmK4oSJSW
-----END PRIVATE KEY-----`;
const SOURCE_CERT = `-----BEGIN CERTIFICATE-----
MIIBljCCATugAwIBAgIUE/tpNx1CUwpmRY/w8zzs5c53fC0wCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTExMTE5MTIyMVoYDzIxMjYxMDE4
MTkxMjIxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQrGb2XjftvGWMtC+IH3ZmTJCFR8N4yq7ljEKUwHD3V+U6DjVpoDosg
aH6qY8Cjk2ytfRJeYiWhY/ApmK4oSJSWo2kwZzAdBgNVHQ4EFgQUaDzmiXNiwoXw
YzbzC9MEW0Hb1McwHwYDVR0jBBgwFoAUaDzmiXNiwoXwYzbzC9MEW0Hb1McwDwYD
VR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwID
SQAwRgIhAOBbraXSaaNpavD65BrD5LkkOiqNU4HsnOOe//r9QcEIAiEA56brk/8x
O4kBtC4j7DxpyzhD7y47YQaC0/YNcS8qp6Q=
-----END CERTIFICATE-----`;

/** A running test server. */
export interface TestServer {
  /** The TCP port it listens on. */
  readonly port: number;
  close(): Promise<void>;
}

/** A running fake witness. */
export interface FakeWitness extends TestServer {
  /** The WebSocket URL a prover connects to. */
  readonly url: string;
}

/**
 * An HTTPS source on `localhost` that answers every request with `body`. Its
 * certificate is self-signed, so a client must skip certificate verification.
 */
export const startSource = async (body: string): Promise<TestServer> => {
  const server = createTlsServer({ key: SOURCE_KEY, cert: SOURCE_CERT }, (socket) => {
    let received = '';
    socket.on('data', (chunk: Buffer) => {
      received += chunk.toString('latin1');
      if (received.includes('\r\n\r\n')) {
        socket.end(
          `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
        );
      }
    });
    socket.on('error', () => undefined);
  });
  server.listen(0);
  await once(server, 'listening');
  return {
    port: (server.address() as AddressInfo).port,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
};

type RpcMessage = proto.RPCMessage;

/**
 * A witness that answers `init`, opens real TCP tunnels and relays their bytes,
 * like attestor-core's server. A tunnel that cannot connect is answered the way
 * the server's RPC handler answers any thrown error: `AttestorError.fromError`.
 * It never signs a claim.
 */
export const startFakeWitness = async (): Promise<FakeWitness> => {
  const server = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  await once(server, 'listening');
  server.on('connection', (ws, upgrade) => {
    const tunnels = new Map<number, Socket>();
    const send = (...messages: Partial<RpcMessage>[]) => {
      const packed = proto.RPCMessages.create({
        messages: messages.map((message) => proto.RPCMessage.create(message)),
      });
      ws.send(proto.RPCMessages.encode(packed).finish());
    };
    const handle = (message: RpcMessage) => {
      if (message.initRequest) {
        send({
          id: message.id,
          initResponse: { toprfPublicKey: new Uint8Array(), attestorAddress: '' },
        });
      } else if (message.createTunnelRequest) {
        const { id: tunnelId, host, port } = message.createTunnelRequest;
        const socket = connect({ host, port });
        tunnels.set(tunnelId, socket);
        let connected = false;
        socket.once('connect', () => {
          connected = true;
          send({ id: message.id, createTunnelResponse: {} });
        });
        socket.once('error', (error) => {
          if (!connected) {
            send({ id: message.id, requestError: AttestorError.fromError(error).toProto() });
          }
        });
        socket.on('data', (data: Buffer) => send({ tunnelMessage: { tunnelId, message: data } }));
        socket.on('close', () => send({ tunnelDisconnectEvent: { tunnelId, error: undefined } }));
      } else if (message.tunnelMessage) {
        tunnels.get(message.tunnelMessage.tunnelId)?.write(message.tunnelMessage.message);
      } else if (message.disconnectTunnelRequest) {
        tunnels.get(message.disconnectTunnelRequest.id)?.end();
        send({ id: message.id, disconnectTunnelResponse: {} });
      }
    };
    const receive = (bytes: Uint8Array) => {
      for (const message of proto.RPCMessages.decode(bytes).messages) {
        handle(message);
      }
    };
    // The client sends its first messages in the connection URL.
    const initial = new URL(upgrade.url ?? '', 'ws://witness').searchParams.get('messages');
    if (initial !== null) {
      receive(Buffer.from(initial, 'base64'));
    }
    ws.on('message', (data: Buffer) => receive(new Uint8Array(data)));
    ws.on('close', () => {
      for (const socket of tunnels.values()) {
        socket.destroy();
      }
    });
  });
  const { port } = server.address() as AddressInfo;
  return {
    port,
    url: `ws://127.0.0.1:${port}/ws`,
    close: async () => {
      for (const client of server.clients) {
        client.terminate();
      }
      await new Promise((resolve) => server.close(() => resolve(undefined)));
    },
  };
};
