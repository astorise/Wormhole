# Design: Release Prep & Hygiene

## 1. Relay Certificate Persistence (N4)
In `faas/src/tls.rs` & `faas/src/main.rs`:
- Read `WORMHOLE_RELAY_CERT_DIR` (defaults to `/tmp` in dev, but can be set to `/var/lib/wormhole` in prod).
- Ensure the directory exists.
- Save `wormhole-relay-cert.der` and `wormhole-relay-key.der` with strict `0600` permissions.
- If the files exist and are valid, load them instead of generating new ones, ensuring the CA pinning survives Tachyon worker restarts.

## 2. CLI Hardening (N12, N18)
In `cli/src/quic.js`:
- Remove the `Buffer.from(auth.cert)` fallback. If `auth.cert` is provided but isn't a valid file path or valid PEM string, throw a clear error: `Invalid certificate provided. Must be a valid PEM file path or string.`
In `cli/src/mux.js`:
- Add a `udpDropped` counter. When the UDP queue is full (`UDP_QUEUE_MAX`), increment the counter and emit a `warn` event or log it.

## 3. Repo Hygiene & Docs (N5, N16, N19)
- Create `LICENSE` (MIT).
- Create `SECURITY.md` detailing the mTLS architecture and how to report vulnerabilities.
- Update `README.md` to reflect V3: "The Relay exposes the public port. The CLI connects via mTLS and routes traffic down to your local loopback services."

## 4. E2E Tests (N10)
Create `faas/tests/integration_test.rs`:
- Spawn `Relay::bind("127.0.0.1:0")`.
- Use a dummy QUIC client to connect, simulating the V3 `wormhole/3` ALPN and proving that the relay accepts the connection and registers the SNI.