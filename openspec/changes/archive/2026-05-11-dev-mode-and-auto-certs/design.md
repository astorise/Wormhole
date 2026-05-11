# Design: Auto-Certs & Unsecure Mode

## 1. CLI Smart Discovery & Generation
In `cli/src/quic.js` and `cli/src/cli.js`:
- **Discovery:** Use `os.homedir()` to resolve `~/.ssh/`. If `auth` options are missing, attempt to read `~/.ssh/${relayHost}.pem` and `.key`.
- **Generation:** If files are missing, use a lightweight library (like `node-forge`) to generate a 2048-bit RSA keypair and a self-signed X.509 certificate. The `subjectAltName` must be set to the requested SNI.
- Pass these generated PEM strings directly into the `Http3WebTransport` client configuration.

## 2. Relay Unsecure Mode (Rust)
In `faas/src/tls.rs` and `faas/src/relay.rs`:
- Add a configuration boolean `allow_insecure`.
- If `allow_insecure` is true:
  - Configure `rustls` with `with_no_client_auth()` or a custom dummy verifier.
  - In `relay.rs`, when resolving the `tunnel_key`, if `peer_identity()` fails or yields no verified SAN, fallback to the SNI extracted from `conn.handshake_data()`.
- If `allow_insecure` is false (default), maintain the strict `WebPkiClientVerifier` logic implemented in the previous change.

## 3. Warning Telemetry
When the FaaS operates in unsecure mode, it must emit a prominent `tracing::warn!` on startup indicating that the relay is operating as an open proxy and is vulnerable to SNI spoofing.