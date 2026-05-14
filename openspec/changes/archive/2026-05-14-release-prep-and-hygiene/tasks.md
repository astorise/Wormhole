# Tasks: Release Prep Implementation

## Phase 1: Repository Hygiene & Docs
- [x] 1. Create `LICENSE` file with the MIT License text.
- [x] 2. Create `SECURITY.md` outlining the threat model and reporting instructions.
- [x] 3. Rewrite `README.md` to accurately describe V3 bidirectional routing semantics, replacing outdated V1 examples.
- [x] 4. Bump version to `0.3.0` in `cli/package.json` and `faas/Cargo.toml`.

## Phase 2: Relay Certificate Persistence
- [x] 5. Update `faas/src/main.rs` and `faas/src/tls.rs` to accept and use `WORMHOLE_RELAY_CERT_DIR`.
- [x] 6. Implement logic to load existing DER keys from the directory, falling back to generation only if they are missing. Ensure `0600` permissions.

## Phase 3: CLI Hardening
- [x] 7. Update `cli/src/quic.js` `loadTlsConfig` to throw an explicit error on invalid PEM inputs instead of silently falling back to a raw Buffer.
- [x] 8. Update `cli/src/mux.js` to increment a `udpDropped` counter when the queue overflows, and log a warning.

## Phase 4: E2E Integration Testing
- [x] 9. Create `faas/tests/integration_test.rs`.
- [x] 10. Write a test that initializes the Relay on a random port, creates a local `quinn` client, dials the Relay, and asserts that the connection is successfully established and registered.
