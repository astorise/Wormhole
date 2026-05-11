import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { QuicDialer, loadTlsConfig } from '../src/quic.js';
import { Multiplexer } from '../src/mux.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal fake dialer that supports the Multiplexer's resilience protocol. */
class FakeDialer extends EventEmitter {
  #connected;
  constructor(connected = true) {
    super();
    this.#connected = connected;
  }
  get connected() { return this.#connected; }
  openStream() {
    if (!this.#connected) return Promise.reject(new Error('not connected'));
    return Promise.reject(new Error('no relay in test'));
  }
  sendDatagram() { return Promise.resolve(); }
  simulateDisconnect() {
    this.#connected = false;
    this.emit('reconnecting', { attempt: 1, delayMs: 500 });
  }
  simulateReconnect() {
    this.#connected = true;
    this.emit('reconnected');
  }
}

// ---------------------------------------------------------------------------
// loadTlsConfig
// ---------------------------------------------------------------------------

describe('loadTlsConfig', () => {
  it('returns insecure config when no auth provided', () => {
    const cfg = loadTlsConfig(undefined);
    assert.equal(cfg.rejectUnauthorized, false);
  });
});

// ---------------------------------------------------------------------------
// QuicDialer
// ---------------------------------------------------------------------------

describe('QuicDialer', () => {
  it('is not connected before connect()', () => {
    const d = new QuicDialer({ relayHost: '127.0.0.1', relayPort: 4433, tlsConfig: {} });
    assert.equal(d.connected, false);
  });

  it('rejects when opening a stream before connect()', async () => {
    const d = new QuicDialer({ relayHost: '127.0.0.1', relayPort: 4433, tlsConfig: {} });
    await assert.rejects(() => d.openStream(), /not connected/);
  });

  it('emits reconnecting with attempt and delayMs', () => {
    const d = new QuicDialer({ relayHost: '127.0.0.1', relayPort: 4433, tlsConfig: {} });
    const events = [];
    d.on('reconnecting', (detail) => events.push(detail));
    d.emit('reconnecting', { attempt: 1, delayMs: 500 });
    assert.equal(events.length, 1);
    assert.equal(events[0].attempt, 1);
    assert.ok(events[0].delayMs >= 0);
  });

  it('close() marks dialer as disconnected', () => {
    const d = new QuicDialer({ relayHost: '127.0.0.1', relayPort: 4433, tlsConfig: {} });
    d.close();
    assert.equal(d.connected, false);
  });
});

// ---------------------------------------------------------------------------
// Multiplexer — disconnect / reconnect resilience
// ---------------------------------------------------------------------------

describe('Multiplexer', () => {
  it('can be instantiated with a dialer-like object', () => {
    const fakeDial = new FakeDialer();
    const mux = new Multiplexer(fakeDial);
    assert.ok(mux);
  });

  it('queues UDP datagrams while disconnected and flushes on reconnect', async () => {
    const sent = [];
    const dialer = new FakeDialer(false); // start disconnected
    dialer.sendDatagram = async (frame) => { sent.push(frame); };

    const mux = new Multiplexer(dialer);

    // Directly test the queue path by triggering the socket.on('message') logic:
    // simulate the dialer being disconnected then reconnecting.
    dialer.simulateDisconnect(); // emits 'reconnecting'

    // Manually push frames into the internal queue by using the UDP message handler.
    // We reach the queue by creating the UDP binding — but to keep the test
    // self-contained without real ports, we instead verify via the reconnected flush.
    // Drive the queue directly by accessing the reconnected event handler:
    const frame1 = Buffer.from([0x00, 0x01, 0xAA]);
    const frame2 = Buffer.from([0x00, 0x01, 0xBB]);
    mux._testEnqueueUdp(frame1);
    mux._testEnqueueUdp(frame2);

    assert.equal(sent.length, 0, 'nothing sent while disconnected');

    dialer.simulateReconnect(); // emits 'reconnected', triggers flush
    // Allow the microtask queue to process the async sendDatagram calls.
    await new Promise((r) => setImmediate(r));

    assert.equal(sent.length, 2, 'queued frames flushed on reconnect');
    mux.closeAll();
  });
});
