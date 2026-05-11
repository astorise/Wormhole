import { readFileSync } from 'node:fs';
import { EventEmitter } from 'node:events';

/**
 * QUIC dialer backed by @fails-components/webtransport (libquiche).
 * The package is loaded lazily inside connect() so the module can be imported
 * in tests without triggering the native addon load.
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
    // Dynamic import avoids loading the native addon at module parse time.
    const { Http3WebTransport } = await import('@fails-components/webtransport');

    const opts = {
      serverCertificateHashes: this.#tlsConfig.serverCertHashes ?? [],
    };

    if (this.#tlsConfig.cert && this.#tlsConfig.key) {
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

  /** Send a UDP-encapsulated datagram to the relay. */
  async sendDatagram(data) {
    if (!this.#transport) throw new Error('not connected');
    const writer = this.#transport.datagrams.writable.getWriter();
    await writer.write(data);
    writer.releaseLock();
  }

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
  #writer;

  constructor(readable, writable) {
    super();
    this.#writer = writable.getWriter();
    this._pump(readable);
  }

  async _pump(readable) {
    const reader = readable.getReader();
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

  write(data) {
    return this.#writer.write(data instanceof Buffer ? data : Buffer.from(data));
  }

  async close() {
    await this.#writer.close();
  }
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
