# Tasks: Zero-Trust Security Implementation

## Phase 1: Rust Strict mTLS
- [x] 1. Add `x509-parser` to `faas/Cargo.toml` for lightweight certificate inspection.
- [x] 2. Update `faas/src/tls.rs` to accept an optional CA certificate. If provided, configure `rustls` to require client authentication using `WebPkiClientVerifier`.
- [x] 3. Update `faas/src/relay.rs` to extract the `peer_identity` from the established `quinn::Connection`. Parse the certificate to extract the SAN (Subject Alternative Name).
- [x] 4. In `relay.rs`, use the extracted SAN as the absolute `tunnel_key` for `router.register()`, preventing SNI spoofing. Drop connections that lack a valid client certificate.

## Phase 2: CLI CA Validation
- [x] 5. Update `cli/src/cli.js` to accept a `--ca <path>` argument.
- [x] 6. Update `cli/src/quic.js` to read the CA file and use its fingerprint in the `serverCertificateHashes` option of `Http3WebTransport` (or use Node.js `tls` context if supported by the webtransport library) to prevent MITM attacks.

## Phase 3: Testing & Integration
- [x] 7. Update `faas/src/main.rs` to read the path to `ca.pem` from an environment variable (e.g., `WORMHOLE_CA_CERT`).
- [x] 8. Ensure local tests in `faas/src/relay.rs` mock a valid client certificate or bypass authentication strictly for the test environment.