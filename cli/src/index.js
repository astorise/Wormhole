import { QuicDialer, loadTlsConfig } from './quic.js';
import { Multiplexer } from './mux.js';
import { discoverCerts, generateEphemeralCert } from './certs.js';

/**
 * @typedef {Object} TunnelTarget
 * @property {'tcp'|'udp'} protocol
 * @property {number} port  Local port to expose
 */

/**
 * @typedef {Object} WormholeOptions
 * @property {string} relay              Relay address, e.g. "relay.tachyon.io:4433"
 * @property {TunnelTarget[]} targets    Ports to expose
 * @property {string} [sni]             SNI hostname (defaults to relay host)
 * @property {{ cert: string, key: string }} [auth]  mTLS cert/key file paths
 * @property {string} [ca]              Path to relay CA certificate (.pem)
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

  get endpoint() { return this.#endpoint; }

  close() {
    this.#mux.closeAll();
    this.#dialer.close();
  }

  /**
   * Create and open a Wormhole tunnel.
   *
   * When no explicit `auth` is provided, credentials are resolved in order:
   *   1. `~/.ssh/<relayHost>.pem` / `.key`
   *   2. Auto-generated ephemeral self-signed cert (dev mode)
   *
   * @param {WormholeOptions} opts
   * @returns {Promise<Wormhole>}
   */
  static async create(opts) {
    const { relay, targets = [], sni, auth: explicitAuth, ca } = opts;

    const [relayHost, relayPortStr] = relay.split(':');
    const relayPort = parseInt(relayPortStr ?? '4433', 10);
    const effectiveSni = sni ?? relayHost;

    // ── Credential resolution ──────────────────────────────────────────────
    let auth = explicitAuth;
    if (!auth) {
      const discovered = discoverCerts(relayHost);
      if (discovered) {
        auth = discovered;
        console.log(`[Auth] Using certificate from ~/.ssh/${relayHost}.pem`);
      } else {
        auth = await generateEphemeralCert(effectiveSni);
        console.log(`[Auth] Auto-generated ephemeral certificate for ${effectiveSni}`);
      }
    }

    const tlsConfig = loadTlsConfig(auth, ca);
    const dialer = new QuicDialer({ relayHost, relayPort, tlsConfig });

    await dialer.connect();

    const mux = new Multiplexer(dialer);

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

    const endpoint = `wormhole://${effectiveSni}`;
    return new Wormhole(dialer, mux, endpoint);
  }
}
