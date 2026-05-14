# Design: Symmetric Routing & Hardening

## 1. V3 Symmetric UDP Framing
Every datagram exchanged between the FaaS Relay and the CLI must start with a 4-byte header:
- `Bytes 0-1`: `public_port` (u16 Big-Endian).
- `Bytes 2-3`: `session_id` (u16 Big-Endian).

**Relay Egress & Ingress:**
- `router.rs`: `udp_callers` becomes `DashMap<(String, u16, u16), SocketAddr>` mapping `(tunnel_key, public_port, session_id) -> caller_addr`.
- When the Relay receives a public UDP packet, it generates a `session_id` (or hashes the caller's 5-tuple), stores the `caller_addr`, prepends the 4-byte header, and sends it to the CLI.
- When the Relay receives a datagram from the CLI, it parses the 4-byte header, looks up the `caller_addr`, and strips the header before sending it to the public internet.

**CLI Multiplexer (`mux.js`):**
- Maintains a `Map<number, dgram.Socket>` mapping `session_id -> local ephemeral socket`.
- When receiving a framed datagram from the relay, if the `session_id` is unknown, bind a new ephemeral UDP socket to talk to the local application.
- When the local ephemeral socket receives a reply from the local app, the CLI prepends the 4-byte header (using the known `publicPort` and `session_id`) and pushes it into the tunnel.

## 2. QUIC Initial SNI Peeking (N1)
In `faas/src/ingress_udp.rs`:
- If a packet is a QUIC Long Header (Initial), the relay must use a lightweight initial decrypter (e.g., utilizing `rustls` or a dedicated QUIC tool) to unseal the payload using the standard QUIC v1 initial salt.
- It parses the TLS ClientHello to extract the SNI.
- It maps `DCID -> SNI` in a dedicated `DashMap<String, String>` inside the `Router`, bridging the gap between the public DCID and the client's registered tunnel key.

## 3. mTLS and Boot Hardening (N3, N7)
- `faas/src/router.rs`: In `register()`, unconditionally check `if self.table.contains_key(&key) { return Err(...) }` to prevent SAN hijacking.
- `faas/src/main.rs`: Refactor the config loading block to use `bail!` for missing certs instead of `panic!`.