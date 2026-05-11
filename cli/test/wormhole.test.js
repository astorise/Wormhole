import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { QuicDialer, loadTlsConfig } from '../src/quic.js';
import { Multiplexer } from '../src/mux.js';

describe('loadTlsConfig', () => {
  it('returns insecure config when no auth provided', () => {
    const cfg = loadTlsConfig(undefined);
    assert.equal(cfg.rejectUnauthorized, false);
  });
});

describe('QuicDialer', () => {
  it('is not connected before connect()', () => {
    const d = new QuicDialer({ relayHost: '127.0.0.1', relayPort: 4433, tlsConfig: {} });
    assert.equal(d.connected, false);
  });

  it('rejects when opening a stream before connect()', async () => {
    const d = new QuicDialer({ relayHost: '127.0.0.1', relayPort: 4433, tlsConfig: {} });
    await assert.rejects(() => d.openStream(), /not connected/);
  });
});

describe('Multiplexer', () => {
  it('can be instantiated with a dialer-like object', () => {
    const fakeDial = { openStream: () => {} };
    const mux = new Multiplexer(fakeDial);
    assert.ok(mux);
  });
});
