import { createSocket } from 'node:dgram';
import { readFileSync } from 'node:fs';
import { EventEmitter } from 'node:events';

/**
 * Minimal QUIC dialer built on Node.js native dgram.
 * In production this would delegate to a native QUIC library (e.g. node-quic,
 * @fails-components/webtransport, or the upcoming net.createQUICSocket API).
 * This implementation provides the structural contract used by Wormhole.
 */
export class QuicDialer extends EventEmitter {
  #socket;
  #relayHost;
  #relayPort;
  #connected = false;
  #streams = new Map();
  #nextStreamId = 1;

  constructor({ relayHost, relayPort, tlsConfig }) {
    super();
    this.#relayHost = relayHost;
    this.#relayPort = relayPort;
    this._tlsConfig = tlsConfig;
  }

  /** Establish the persistent outbound QUIC connection to the relay. */
  async connect() {
    this.#socket = createSocket('udp4');

    await new Promise((resolve, reject) => {
      this.#socket.bind(0, () => resolve());
      this.#socket.once('error', reject);
    });

    this.#socket.on('message', (msg) => this._onMessage(msg));

    // Send QUIC Initial packet (placeholder — real impl uses QUIC crypto)
    const initPacket = this._buildInitPacket();
    await this._send(initPacket);

    this.#connected = true;
    this.emit('connected');
  }

  /** Open a bidirectional stream over the QUIC connection. */
  openStream() {
    if (!this.#connected) throw new Error('not connected');
    const id = this.#nextStreamId++;
    const stream = new QuicStream(id, (data) => this._sendStream(id, data));
    this.#streams.set(id, stream);
    return stream;
  }

  close() {
    this.#connected = false;
    this.#socket?.close();
    this.emit('closed');
  }

  get connected() { return this.#connected; }

  _onMessage(msg) {
    const streamId = msg.readUInt32BE(0);
    const payload = msg.subarray(4);
    this.#streams.get(streamId)?.push(payload);
  }

  _buildInitPacket() {
    const buf = Buffer.alloc(4);
    buf.write('INIT');
    return buf;
  }

  async _send(data) {
    return new Promise((resolve, reject) => {
      this.#socket.send(data, this.#relayPort, this.#relayHost, (err) => {
        if (err) reject(err); else resolve();
      });
    });
  }

  async _sendStream(streamId, data) {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(streamId, 0);
    await this._send(Buffer.concat([header, data]));
  }
}

export class QuicStream extends EventEmitter {
  #id;
  #send;

  constructor(id, send) {
    super();
    this.#id = id;
    this.#send = send;
  }

  push(data) { this.emit('data', data); }

  write(data) { return this.#send(Buffer.from(data)); }

  get id() { return this.#id; }
}

/** Load mTLS config from cert/key PEM files. */
export function loadTlsConfig(auth) {
  if (!auth) return { rejectUnauthorized: false };
  return {
    cert: readFileSync(auth.cert),
    key: readFileSync(auth.key),
    rejectUnauthorized: true,
  };
}
