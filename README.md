# Wormhole

Wormhole is a QUIC-based L4 tunnel for exposing local TCP and UDP services through an edge relay. The relay owns the public ingress port. The CLI keeps an outbound mTLS tunnel open and routes relay-pushed traffic to local loopback services.

## Protocol Model

- The relay listens on public TCP and UDP ports.
- The CLI connects outbound to the relay over QUIC using the `wormhole/3` ALPN.
- TCP ingress is pushed from relay to CLI as a bidirectional QUIC stream with a 2-byte public-port header.
- UDP ingress is pushed as QUIC datagrams with a 4-byte header: public port plus relay session id.
- UDP replies from the local service reuse the same 4-byte header so the relay can return packets to the exact remote caller.
- In production, relay tunnel identity comes from the verified client certificate SAN.

## Usage

Expose local TCP port `8443` on public port `443`, and local UDP port `4433` on public port `443`:

```bash
npx @tachyon-mesh/wormhole --relay relay.tachyon.io:4433 --tcp 443:8443 --udp 443:4433 --ca relay-ca.pem --cert client.pem --key client.key
```

For local development only, the relay can run without mTLS:

```bash
WORMHOLE_DEV=1 wormhole-relay
npx @tachyon-mesh/wormhole --relay 127.0.0.1:4433 --tcp 8443 --udp 4433 --unsecure
```

A single port value maps public and local ports to the same number. For example, `--tcp 8080` is equivalent to `--tcp 8080:8080`.

## Library

```javascript
import { Wormhole } from '@tachyon-mesh/wormhole';

const tunnel = await Wormhole.create({
  relay: 'relay.tachyon.io:4433',
  targets: [
    { protocol: 'tcp', publicPort: 443, localPort: 8443 },
    { protocol: 'udp', publicPort: 443, localPort: 4433 },
  ],
  ca: './relay-ca.pem',
  auth: { cert: './client.pem', key: './client.key' },
});

console.log(`Wormhole open: ${tunnel.endpoint}`);
```

## Repository

- `cli`: Node.js CLI and library that maintains the outbound QUIC tunnel and demultiplexes relay-pushed traffic.
- `faas`: Rust relay for Tachyon edge workers.
- `manifest`: protocol and deployment metadata.
- `openspec`: change proposals, tasks, and archived implementation records.

## Relay Configuration

- `WORMHOLE_CA_CERT`: path to the CA certificate used to verify client mTLS certificates.
- `WORMHOLE_DEV=1`: local development mode without client authentication.
- `WORMHOLE_RELAY_CERT_DIR`: directory for persisted relay development certificate and key. Defaults to `/tmp`.

## Development

```bash
cd faas && cargo test
cd ../cli && npm test
```
