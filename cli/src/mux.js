import * as net from 'node:net';
import * as dgram from 'node:dgram';
import { EventEmitter } from 'node:events';

const UDP_QUEUE_MAX = 256; // max queued datagrams while disconnected

/**
 * Bridges local TCP/UDP ports to QUIC streams/datagrams over the WebTransport tunnel.
 *
 * Resilience behaviour:
 *   - On dialer 'reconnecting': TCP sockets are paused (no new openStream calls);
 *     UDP datagrams are queued up to UDP_QUEUE_MAX.
 *   - On dialer 'reconnected': TCP sockets are resumed; queued UDP datagrams are
 *     flushed over the new session.
 */
export class Multiplexer extends EventEmitter {
  #dialer;
  #servers = [];
  #tcpSockets = new Set();   // all live TCP sockets, for pause/resume
  #udpQueue = [];            // buffered UDP frames while disconnected

  constructor(dialer) {
    super();
    this.#dialer = dialer;

    dialer.on('reconnecting', () => {
      for (const sock of this.#tcpSockets) {
        if (!sock.destroyed) sock.pause();
      }
    });

    dialer.on('reconnected', () => {
      // Flush queued UDP datagrams over the new session.
      const queued = this.#udpQueue.splice(0);
      for (const frame of queued) {
        this.#dialer.sendDatagram(frame).catch(() => {});
      }
      // Resume paused TCP sockets — new openStream() calls will succeed.
      for (const sock of this.#tcpSockets) {
        if (!sock.destroyed) sock.resume();
      }
    });
  }

  /** Bridge a local TCP port: each accepted connection → a new QUIC stream. */
  async bindTcp(localPort) {
    const server = net.createServer(async (socket) => {
      this.#tcpSockets.add(socket);
      socket.once('close', () => this.#tcpSockets.delete(socket));

      // If we're mid-reconnect, pause immediately until the dialer comes back.
      if (!this.#dialer.connected) socket.pause();

      let stream;
      try {
        stream = await this.#dialer.openStream();
      } catch (e) {
        socket.destroy(e);
        return;
      }

      socket.on('data', (chunk) => stream.write(chunk));
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
    const sessions = new Map();

    socket.on('message', async (msg, rinfo) => {
      const key = `${rinfo.address}:${rinfo.port}`;
      sessions.set(key, rinfo);

      const frame = Buffer.alloc(2 + msg.length);
      frame.writeUInt16BE(msg.length, 0);
      msg.copy(frame, 2);

      if (!this.#dialer.connected) {
        // Buffer while disconnected; drop oldest if queue is full.
        if (this.#udpQueue.length >= UDP_QUEUE_MAX) this.#udpQueue.shift();
        this.#udpQueue.push(frame);
        return;
      }

      await this.#dialer.sendDatagram(frame).catch(() => {});
    });

    if (this.#dialer.datagramReader) {
      (async () => {
        const reader = this.#dialer.datagramReader.getReader();
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          const data = Buffer.from(value);
          const len = data.readUInt16BE(0);
          const payload = data.subarray(2, 2 + len);
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

  /** Test helper — enqueue a raw UDP frame as if received while disconnected. */
  _testEnqueueUdp(frame) {
    if (this.#udpQueue.length >= UDP_QUEUE_MAX) this.#udpQueue.shift();
    this.#udpQueue.push(frame);
  }

  closeAll() {
    for (const srv of this.#servers) {
      try { srv.close(); } catch { /* already closed */ }
    }
    this.#servers = [];
    this.#tcpSockets.clear();
    this.#udpQueue.length = 0;
  }
}
