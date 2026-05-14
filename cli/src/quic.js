import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';

const BACKOFF_BASE_MS = 500;
const BACKOFF_MAX_MS = 30_000;
const CERT_PEM_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;
const KEY_PEM_PATTERN = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----/;

/**
 * QUIC dialer backed by @fails-components/webtransport (libquiche).
 * Supports exponential-backoff auto-reconnect.
 *
 * Events:
 *   connected     — session established (initial or after reconnect)
 *   reconnecting  — attempting to reconnect after a drop (detail: { attempt, delayMs })
 *   reconnected   — session re-established after a drop
 *   closed        — permanently closed (close() was called)
 */
export class QuicDialer extends EventEmitter {
  #transport = null;
  #relayUrl;
  #tlsConfig;
  #stopped = false;
  #incomingStreamHandlers = new Set();
  #incomingStreamPump = null;

  constructor({ relayHost, relayPort, tlsConfig }) {
    super();
    this.#relayUrl = `https://${relayHost}:${relayPort}/wormhole`;
    this.#tlsConfig = tlsConfig;
  }

  get connected() {
    return this.#transport !== null;
  }

  /** One-shot connect (no retry). Used internally and for unit tests. */
  async connect() {
    const { Http3WebTransport } = await import('@fails-components/webtransport');

    const opts = {
      rejectUnauthorized: this.#tlsConfig.rejectUnauthorized,
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
    this.#startIncomingStreamPump();
    this.emit('connected');
  }

  /**
   * Connect with exponential backoff.  Keeps retrying until the session is
   * established or close() is called.  After the first successful connection,
   * monitors the session and retries on unexpected drops.
   */
  async connectWithRetry() {
    await this.#tryConnect(false);

    // Monitor for unexpected disconnects and auto-reconnect.
    this.#watchForDrops();
  }

  async #tryConnect(isReconnect) {
    let attempt = 0;
    while (!this.#stopped) {
      try {
        await this.connect();
        if (isReconnect) this.emit('reconnected');
        return;
      } catch {
        if (this.#stopped) return;
        attempt++;
        const delayMs = Math.min(BACKOFF_BASE_MS * 2 ** (attempt - 1), BACKOFF_MAX_MS);
        this.emit('reconnecting', { attempt, delayMs });
        await this.#sleep(delayMs);
      }
    }
  }

  #watchForDrops() {
    const checkLoop = async () => {
      const transport = this.#transport;
      if (!transport) return;

      let closeReason = null;
      try {
        closeReason = await transport.closed;
      } catch (err) {
        closeReason = err;
      }

      if (this.#stopped) return;
      this.#transport = null;
      this.#incomingStreamPump = null;

      // If the relay sent a graceful GoAway (reason "node_shutting_down"),
      // do not attempt to reconnect — emit 'server_closed' so the caller
      // can tear down cleanly.
      const reason = closeReason?.reason ?? closeReason?.message ?? '';
      if (typeof reason === 'string' && reason.includes('node_shutting_down')) {
        this.#stopped = true;
        this.emit('server_closed', { reason });
        return;
      }

      await this.#tryConnect(true);
      this.#watchForDrops();
    };
    checkLoop().catch(() => {});
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

  onIncomingStream(handler) {
    this.#incomingStreamHandlers.add(handler);
    this.#startIncomingStreamPump();
    return () => this.#incomingStreamHandlers.delete(handler);
  }

  #startIncomingStreamPump() {
    if (this.#incomingStreamPump || !this.#transport?.incomingBidirectionalStreams) return;

    const transport = this.#transport;
    this.#incomingStreamPump = (async () => {
      const reader = transport.incomingBidirectionalStreams.getReader();
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          const stream = new QuicStream(value.readable, value.writable);
          for (const handler of this.#incomingStreamHandlers) {
            handler(stream);
          }
        }
      } finally {
        reader.releaseLock?.();
        if (this.#transport === transport) this.#incomingStreamPump = null;
      }
    })();

    this.#incomingStreamPump.catch(() => {});
  }

  close() {
    this.#stopped = true;
    this.#transport?.close();
    this.#transport = null;
    this.#incomingStreamPump = null;
    this.emit('closed');
  }

  #sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
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

/**
 * Build the TLS configuration object for the QUIC dialer.
 *
 * @param {{ cert: string, key: string } | undefined} auth - Client cert/key paths for mTLS.
 * @param {string | undefined} caPath - Path to the relay's CA certificate chain (.pem).
 *   When provided, its SHA-256 fingerprint is added to `serverCertificateHashes`
 *   so the WebTransport client pins that trust anchor and rejects any relay cert
 *   not signed by it (prevents MITM).
 * @param {{ unsecure?: boolean }} [options] - Explicitly disable strict relay verification.
 */
export function loadTlsConfig(auth, caPath, options = {}) {
  const config = { rejectUnauthorized: options.unsecure !== true };

  if (auth) {
    // auth.raw === true when the cert/key are PEM strings (auto-generated or
    // discovered from ~/.ssh/). Otherwise they are file paths to read.
    config.cert = readPemInput(
      auth.cert,
      auth.raw,
      CERT_PEM_PATTERN,
      'Invalid certificate provided. Must be a valid PEM file path or string.',
    );
    config.key = readPemInput(
      auth.key,
      auth.raw,
      KEY_PEM_PATTERN,
      'Invalid private key provided. Must be a valid PEM file path or string.',
    );
  }

  if (caPath) {
    config.serverCertHashes = parsePemCertificatesToDer(readFileSync(caPath)).map((caDer) => ({
      algorithm: 'sha-256',
      value: createHash('sha-256').update(caDer).digest(),
    }));
  }

  return config;
}

/**
 * Strip PEM armour and return the raw DER bytes for every certificate block.
 * @param {Buffer} pem
 * @returns {Buffer[]}
 */
function parsePemCertificatesToDer(pem) {
  const text = pem.toString('ascii');
  const certs = [];
  const pattern = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;

  for (const match of text.matchAll(pattern)) {
    const b64 = match[1].replace(/\s+/g, '');
    if (b64.length > 0) certs.push(Buffer.from(b64, 'base64'));
  }

  if (certs.length === 0) {
    throw new Error('Invalid CA certificate provided. Must be a valid PEM file path.');
  }

  return certs;
}

function readPemInput(value, raw, pattern, message) {
  let pem;
  try {
    pem = raw ? Buffer.from(value) : readFileSync(value);
  } catch {
    throw new Error(message);
  }

  if (!pattern.test(pem.toString('ascii'))) {
    throw new Error(message);
  }

  return pem;
}
