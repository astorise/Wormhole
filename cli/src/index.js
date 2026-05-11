import { QuicDialer, loadTlsConfig } from './quic.js';
import { Multiplexer } from './mux.js';

/**
 * @typedef {Object} TunnelTarget
 * @property {'tcp'|'udp'} protocol
 * @property {number} port  Local port to expose
 */

/**
 * @typedef {Object} WormholeOptions
 * @property {string} relay            Relay address, e.g. "relay.tachyon.io:4433"
 * @property {TunnelTarget[]} targets  Ports to expose
 * @property {string} [sni]            SNI hostname (defaults to relay host)
 * @property {{ cert: string, key: string }} [auth]  mTLS cert/key paths
 */

export class Wormhole {
  #dialer;
  #mux;
  #endpoint;

  constructor(dialer, mux, endpoint) {
    this.#dialer = dialer;
    this.#mux = mux;
    this.#endpoint = endpoint;
  }

  /** Public endpoint advertised by the relay for this tunnel. */
  get endpoint() { return this.#endpoint; }

  /** Gracefully shut down the tunnel and release all local bindings. */
  close() {
    this.#mux.closeAll();
    this.#dialer.close();
  }

  /**
   * Create and open a Wormhole tunnel.
   * @param {WormholeOptions} opts
   * @returns {Promise<Wormhole>}
   */
  static async create(opts) {
    const { relay, targets = [], sni, auth, ca } = opts;

    const [relayHost, relayPortStr] = relay.split(':');
    const relayPort = parseInt(relayPortStr ?? '4433', 10);

    const tlsConfig = loadTlsConfig(auth, ca);
    const dialer = new QuicDialer({ relayHost, relayPort, tlsConfig });

    await dialer.connect();

    const mux = new Multiplexer(dialer);

    // When the relay sends a graceful GoAway, drain active connections then exit.
    dialer.on('server_closed', async ({ reason }) => {
      console.error(`[wormhole] relay closed: ${reason} — draining connections`);
      await mux.drain();
      dialer.close();
    });

    for (const target of targets) {
      if (target.protocol === 'tcp') {
        await mux.bindTcp(target.port);
      } else if (target.protocol === 'udp') {
        await mux.bindUdp(target.port);
      }
    }

    const effectiveSni = sni ?? relayHost;
    const endpoint = `wormhole://${effectiveSni}`;

    return new Wormhole(dialer, mux, endpoint);
  }
}
