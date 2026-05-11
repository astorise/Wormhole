import * as net from 'node:net';
import * as dgram from 'node:dgram';
import { EventEmitter } from 'node:events';

/**
 * Bridges local TCP/UDP ports to QUIC streams opened over the tunnel.
 * Each local connection/datagram gets its own QUIC stream (bidirectional for TCP,
 * unidirectional datagram encapsulation for UDP).
 */
export class Multiplexer extends EventEmitter {
  #dialer;
  #servers = [];

  constructor(dialer) {
    super();
    this.#dialer = dialer;
  }

  /** Start bridging a local TCP port over the QUIC tunnel. */
  async bindTcp(localPort) {
    const server = net.createServer((socket) => {
      const stream = this.#dialer.openStream();

      socket.on('data', (chunk) => stream.write(chunk));
      stream.on('data', (chunk) => socket.write(chunk));

      socket.once('end', () => stream.emit('end'));
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

  /** Start bridging a local UDP port over the QUIC tunnel. */
  async bindUdp(localPort) {
    const socket = dgram.createSocket('udp4');

    socket.on('message', (msg, rinfo) => {
      const stream = this.#dialer.openStream();
      // Encapsulate UDP datagram: 2-byte length prefix + payload
      const frame = Buffer.alloc(2 + msg.length);
      frame.writeUInt16BE(msg.length, 0);
      msg.copy(frame, 2);
      stream.write(frame);

      // Return path: relay sends framed response back
      stream.on('data', (data) => {
        const len = data.readUInt16BE(0);
        const payload = data.subarray(2, 2 + len);
        socket.send(payload, rinfo.port, rinfo.address);
      });
    });

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
