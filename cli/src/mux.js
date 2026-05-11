import * as net from 'node:net';
import * as dgram from 'node:dgram';
import { EventEmitter } from 'node:events';

/**
 * Bridges local TCP/UDP ports to QUIC streams/datagrams over the WebTransport tunnel.
 *
 * TCP: each local connection → one bidirectional WebTransport stream.
 * UDP: each local datagram → one WebTransport datagram (length-prefixed frame).
 */
export class Multiplexer extends EventEmitter {
  #dialer;
  #servers = [];

  constructor(dialer) {
    super();
    this.#dialer = dialer;
  }

  /** Bridge a local TCP port: each accepted connection → a new QUIC stream. */
  async bindTcp(localPort) {
    const server = net.createServer(async (socket) => {
      let stream;
      try {
        stream = await this.#dialer.openStream();
      } catch (e) {
        socket.destroy(e);
        return;
      }

      // local → relay
      socket.on('data', (chunk) => stream.write(chunk));
      // relay → local
      stream.on('data', (chunk) => { if (!socket.destroyed) socket.write(chunk); });

      stream.on('end', () => socket.end());
      socket.once('close', () => stream.close().catch(() => {}));
      socket.once('error', () => socket.destroy());
    });

    await new Promise((resolve, reject) => {
      server.listen(localPort, '127.0.0.1', resolve);
      server.once('error', reject);
    });

    this.#servers.push(server);
    this.emit('bound', { protocol: 'tcp', port: localPort });
    return server;
  }

  /** Bridge a local UDP port: each datagram → a WebTransport datagram. */
  async bindUdp(localPort) {
    const socket = dgram.createSocket('udp4');
    const sessions = new Map(); // "ip:port" → last seen rinfo

    socket.on('message', async (msg, rinfo) => {
      const key = `${rinfo.address}:${rinfo.port}`;
      sessions.set(key, rinfo);

      // 2-byte length prefix + payload
      const frame = Buffer.alloc(2 + msg.length);
      frame.writeUInt16BE(msg.length, 0);
      msg.copy(frame, 2);
      await this.#dialer.sendDatagram(frame).catch(() => {});
    });

    // Pump incoming relay datagrams back to local clients
    if (this.#dialer.datagramReader) {
      (async () => {
        const reader = this.#dialer.datagramReader.getReader();
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          const data = Buffer.from(value);
          const len = data.readUInt16BE(0);
          const payload = data.subarray(2, 2 + len);
          // Broadcast to all active sessions (UDP is connectionless)
          for (const rinfo of sessions.values()) {
            socket.send(payload, rinfo.port, rinfo.address);
          }
        }
      })().catch(() => {});
    }

    await new Promise((resolve, reject) => {
      socket.bind(localPort, '127.0.0.1', resolve);
      socket.once('error', reject);
    });

    this.#servers.push(socket);
    this.emit('bound', { protocol: 'udp', port: localPort });
    return socket;
  }

  closeAll() {
    for (const srv of this.#servers) {
      try { srv.close(); } catch { /* already closed */ }
    }
    this.#servers = [];
  }
}
