import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';

const BACKOFF_BASE_MS = 500;
const BACKOFF_MAX_MS = 30_000;
const KEEPALIVE_INTERVAL_MS = 15_000;
const PING = Buffer.from([0x01]); // 1-byte keep-alive payload

/**
 * QUIC dialer backed by @fails-components/webtransport (libquiche).
 * Supports exponential-backoff auto-reconnect and a periodic keep-alive ping.
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
  #keepAliveTimer = null;

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
    this.#startKeepalive();
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
      this.#stopKeepalive();
      this.#transport = null;

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

  /** Send a periodic 1-byte ping to keep NAT and gateway affinity alive. */
  #startKeepalive() {
    this.#stopKeepalive();
    this.#keepAliveTimer = setInterval(async () => {
      if (!this.#transport) return;
      try { await this.sendDatagram(PING); } catch { /* ignore; drop handled by watchForDrops */ }
    }, KEEPALIVE_INTERVAL_MS);
    this.#keepAliveTimer.unref?.(); // don't prevent process exit
  }

  #stopKeepalive() {
    if (this.#keepAliveTimer) {
      clearInterval(this.#keepAliveTimer);
      this.#keepAliveTimer = null;
    }
  }

  close() {
    this.#stopped = true;
    this.#stopKeepalive();
    this.#transport?.close();
    this.#transport = null;
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
 * @param {string | undefined} caPath - Path to the relay's CA certificate (.pem).
 *   When provided, its SHA-256 fingerprint is added to `serverCertificateHashes`
 *   so the WebTransport client pins that trust anchor and rejects any relay cert
 *   not signed by it (prevents MITM).
 */
export function loadTlsConfig(auth, caPath) {
  const config = { rejectUnauthorized: !!auth };

  if (auth) {
    // auth.raw === true when the cert/key are PEM strings (auto-generated or
    // discovered from ~/.ssh/). Otherwise they are file paths to read.
    config.cert = auth.raw ? Buffer.from(auth.cert) : readFileSync(auth.cert);
    config.key = auth.raw ? Buffer.from(auth.key) : readFileSync(auth.key);
  }

  if (caPath) {
    const caDer = parsePemToDer(readFileSync(caPath));
    const hash = createHash('sha-256').update(caDer).digest();
    config.serverCertHashes = [{ algorithm: 'sha-256', value: hash }];
  }

  return config;
}

/**
 * Strip PEM armour and return the raw DER bytes of the first certificate.
 * @param {Buffer} pem
 * @returns {Buffer}
 */
function parsePemToDer(pem) {
  const b64 = pem
    .toString('ascii')
    .split('\n')
    .filter((l) => !l.startsWith('-----'))
    .join('');
  return Buffer.from(b64, 'base64');
}
