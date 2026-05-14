# Design: Audit Remediation

## 1. Routing & State Management (FaaS)
- **O(N) Fix & Traffic Leak:** In `faas/src/router.rs`, remove the `.or_else(|| self.table.iter().next())` fallback in `route_udp_ingress`. If a DCID doesn't match, drop the packet. To map QUIC `stable_id` to the `sni_key` without O(N) iteration, introduce `inverse_table: DashMap<String, String>` (mapping `stable_id` to `sni`).
- **SNI Hijacking Fix:** In `register()`, if running in unsecure/dev mode, check if `self.table.contains_key(sni)`. If it does, reject the new connection to prevent hijacking.

## 2. Security Defaults (FaaS & CLI)
- **FaaS Boot:** In `faas/src/main.rs`, check for `WORMHOLE_CA_CERT` or `WORMHOLE_DEV=1`. Panic if neither is present.
- **Relay Cert Persistence:** In `faas/src/tls.rs`, if generating a self-signed cert for the relay, cache it to `/tmp/wormhole_relay.pem` (or similar) so reboots don't break CA pinning immediately during dev.
- **CLI Pinning:** In `cli/src/quic.js`, `loadTlsConfig` must default to `rejectUnauthorized: true`. Add an `--unsecure` flag to `cli.js` to override this. Ensure `parsePemToDer` loops through all PEM blocks if a bundle is provided.

## 3. Resilience & Parsing (Correctness)
- **Auto-Reconnect:** In `cli/src/index.js`, replace `dialer.connect()` with `await dialer.connectWithRetry()`.
- **Keep-Alive:** Remove the `sendDatagram(PING)` logic from `cli/src/quic.js`.
- **Fragmented SNI:** In `faas/src/ingress.rs`, replace the single `read()` with a `read_buf` inside a loop (with a strict timeout of 5 seconds via `tokio::time::timeout`) until `tls_parser::parse_tls_plaintext` returns a complete ClientHello or fails.