import { readFileSync } from 'node:fs';
import { EventEmitter } from 'node:events';
import { Http3WebTransport } from '@fails-components/webtransport';

/**
 * QUIC dialer built on the WebTransport API (@fails-components/webtransport).
 * Each call to openStream() opens a bidirectional WebTransport stream, which
 * maps to a QUIC bidirectional stream on the underlying connection.
 */
export class QuicDialer extends EventEmitter {
  #transport = null;
  #relayUrl;
  #tlsConfig;

  constructor({ relayHost, relayPort, tlsConfig }) {
    super();
    this.#relayUrl = `https://${relayHost}:${relayPort}/wormhole`;
    this.#tlsConfig = tlsConfig;
  }

  get connected() {
    return this.#transport !== null;
  }

  /** Establish the persistent outbound QUIC/WebTransport session. */
  async connect() {
    const opts = {
      serverCertificateHashes: this.#tlsConfig.serverCertHashes ?? [],
    };

    if (this.#tlsConfig.cert && this.#tlsConfig.key) {
      // mTLS: pass client cert/key when the relay requires client auth.
      opts.clientCertificate = {
        certificate: this.#tlsConfig.cert,
        privateKey: this.#tlsConfig.key,
      };
    }

    this.#transport = new Http3WebTransport(this.#relayUrl, opts);
    await this.#transport.ready;
    this.emit('connected');
  }

  /** Open a bidirectional QUIC stream over the active session. */
  async openStream() {
    if (!this.#transport) throw new Error('not connected');
    const { readable, writable } = await this.#transport.createBidirectionalStream();
    return new QuicStream(readable, writable);
  }

  /** Send a datagram (UDP encapsulation). */
  async sendDatagram(data) {
    if (!this.#transport) throw new Error('not connected');
    await this.#transport.datagrams.writable.getWriter().write(data);
  }

  /** Subscribe to incoming datagrams from the relay. */
  get datagramReader() {
    return this.#transport?.datagrams.readable;
  }

  close() {
    this.#transport?.close();
    this.#transport = null;
    this.emit('closed');
  }
}

export class QuicStream extends EventEmitter {
  #readable;
  #writable;
  #writer;

  constructor(readable, writable) {
    super();
    this.#readable = readable;
    this.#writable = writable;
    this.#writer = writable.getWriter();
    this._pump();
  }

  async _pump() {
    const reader = this.#readable.getReader();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) { this.emit('end'); break; }
        this.emit('data', Buffer.from(value));
      }
    } catch (e) {
      this.emit('error', e);
    }
  }

  write(data) { return this.#writer.write(data instanceof Buffer ? data : Buffer.from(data)); }

  async close() { await this.#writer.close(); }
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
