import * as net from 'node:net';
import * as dgram from 'node:dgram';
import { EventEmitter } from 'node:events';

const UDP_QUEUE_MAX = 256;
const LOOPBACK = '127.0.0.1';

/**
 * Demultiplexes framed relay traffic to local TCP/UDP ports.
 *
 * Protocol v2 frames inbound relay traffic with a 2-byte big-endian public
 * port header. The multiplexer strips that header, resolves the local target,
 * and forwards only the original payload to the local application.
 */
export class Multiplexer extends EventEmitter {
  #dialer;
  #tcpRoutes = new Map();
  #udpRoutes = new Map();
  #udpSockets = new Set();
  #tcpSockets = new Set();
  #udpQueue = [];
  #datagramReader = null;
  #unsubscribeIncomingStreams = null;

  constructor(dialer) {
    super();
    this.#dialer = dialer;

    this.#unsubscribeIncomingStreams = dialer.onIncomingStream?.((stream) => {
      this.#handleIncomingStream(stream);
    }) ?? null;

    dialer.on('reconnecting', () => {
      for (const sock of this.#tcpSockets) {
        if (!sock.destroyed) sock.pause();
      }
    });

    dialer.on('connected', () => this.#startDatagramReader());
    dialer.on('reconnected', () => {
      this.#startDatagramReader();

      const queued = this.#udpQueue.splice(0);
      for (const frame of queued) {
        this.#dialer.sendDatagram(frame).catch(() => {});
      }

      for (const sock of this.#tcpSockets) {
        if (!sock.destroyed) sock.resume();
      }
    });

    this.#startDatagramReader();
  }

  bindTcp(publicPort, localPort = publicPort) {
    this.#tcpRoutes.set(publicPort, localPort);
    this.emit('bound', { protocol: 'tcp', publicPort, localPort });
    return Promise.resolve();
  }

  async bindUdp(publicPort, localPort = publicPort) {
    const socket = dgram.createSocket('udp4');
    this.#udpRoutes.set(publicPort, { localPort, socket });
    this.#udpSockets.add(socket);

    socket.on('message', async (msg) => {
      if (!this.#dialer.connected) {
        if (this.#udpQueue.length >= UDP_QUEUE_MAX) this.#udpQueue.shift();
        this.#udpQueue.push(msg);
        return;
      }

      await this.#dialer.sendDatagram(msg).catch(() => {});
    });

    await new Promise((resolve, reject) => {
      socket.bind(0, LOOPBACK, resolve);
      socket.once('error', reject);
    });

    this.emit('bound', { protocol: 'udp', publicPort, localPort });
    return socket;
  }

  #handleIncomingStream(stream) {
    let header = Buffer.alloc(0);
    let localSocket = null;
    let closed = false;

    const closeBoth = () => {
      if (closed) return;
      closed = true;
      localSocket?.destroy();
      stream.close().catch(() => {});
    };

    stream.on('data', (chunk) => {
      if (closed) return;

      if (!localSocket) {
        header = Buffer.concat([header, chunk]);
        if (header.length < 2) return;

        const publicPort = header.readUInt16BE(0);
        const localPort = this.#tcpRoutes.get(publicPort);
        if (!localPort) {
          closeBoth();
          return;
        }

        localSocket = net.createConnection({ host: LOOPBACK, port: localPort });
        this.#tcpSockets.add(localSocket);
        localSocket.once('close', () => {
          this.#tcpSockets.delete(localSocket);
          stream.close().catch(() => {});
        });
        localSocket.once('error', closeBoth);
        localSocket.on('data', (data) => {
          stream.write(data).catch(closeBoth);
        });

        const initialPayload = header.subarray(2);
        if (initialPayload.length > 0) localSocket.write(initialPayload);
        header = null;
        return;
      }

      localSocket.write(chunk);
    });

    stream.once('end', () => localSocket?.end());
    stream.once('error', closeBoth);
  }

  #startDatagramReader() {
    if (this.#datagramReader || !this.#dialer.datagramReader) return;

    const readable = this.#dialer.datagramReader;
    let pump;
    pump = (async () => {
      const reader = readable.getReader();
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          this.#handleIncomingDatagram(Buffer.from(value));
        }
      } finally {
        reader.releaseLock?.();
        if (this.#datagramReader === pump) this.#datagramReader = null;
      }
    })();

    this.#datagramReader = pump;
    this.#datagramReader.catch(() => {});
  }

  #handleIncomingDatagram(data) {
    if (data.length < 2) return;

    const publicPort = data.readUInt16BE(0);
    const route = this.#udpRoutes.get(publicPort);
    if (!route) return;

    const payload = data.subarray(2);
    route.socket.send(payload, route.localPort, LOOPBACK);
  }

  /** Test helper: enqueue a raw UDP payload as if received while disconnected. */
  _testEnqueueUdp(frame) {
    if (this.#udpQueue.length >= UDP_QUEUE_MAX) this.#udpQueue.shift();
    this.#udpQueue.push(frame);
  }

  drain() {
    this.#udpQueue.length = 0;

    if (this.#tcpSockets.size === 0) return Promise.resolve();

    return new Promise((resolve) => {
      let remaining = this.#tcpSockets.size;
      const onClose = () => {
        remaining--;
        if (remaining === 0) resolve();
      };
      for (const sock of this.#tcpSockets) {
        if (sock.destroyed) {
          onClose();
        } else {
          sock.once('close', onClose);
          sock.end();
        }
      }
    });
  }

  closeAll() {
    this.#unsubscribeIncomingStreams?.();
    this.#unsubscribeIncomingStreams = null;

    for (const sock of this.#tcpSockets) {
      try { sock.destroy(); } catch {}
    }
    for (const socket of this.#udpSockets) {
      try { socket.close(); } catch {}
    }

    this.#tcpRoutes.clear();
    this.#udpRoutes.clear();
    this.#udpSockets.clear();
    this.#tcpSockets.clear();
    this.#udpQueue.length = 0;
  }
}
