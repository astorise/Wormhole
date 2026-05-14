# Tasks: Audit Remediation Implementation

## Phase 1: Security Hardening & Defaults
- [x] 1. Update `faas/src/main.rs`: Enforce `WORMHOLE_CA_CERT` or `WORMHOLE_DEV=1` environment variables. Panic with a clear message if both are missing.
- [x] 2. Update `faas/src/tls.rs`: Persist the auto-generated relay certificate to a local file (`/tmp/wormhole-relay-cert.der`) to survive restarts, or load it if it already exists.
- [x] 3. Update `cli/src/quic.js`: Modify `loadTlsConfig` to enforce `rejectUnauthorized: true` by default. Implement logic to extract multiple certificates if the provided CA is a chain.
- [x] 4. Update `cli/src/cli.js`: Add an `--unsecure` flag and pass it down to disable strict CA checking only when explicitly requested.

## Phase 2: Routing Correctness (FaaS)
- [x] 5. Update `faas/src/router.rs`: Add an `inverse_table: DashMap<String, String>` mapping connection `stable_id` to the tunnel `key`.
- [x] 6. Update `faas/src/router.rs` (`route_udp_ingress`): Remove the `or_else` fallback. Drop the datagram if the DCID is not in the routing tables.
- [x] 7. Update `faas/src/router.rs` (`register`): Reject incoming connections (or return an error) if the SNI is already registered and the relay is in `unsecure` mode.
- [x] 8. Update `faas/src/ingress.rs`: Wrap the TCP stream read in a loop with a 5-second `tokio::time::timeout` to handle fragmented TLS ClientHello packets properly.

## Phase 3: Client Resilience
- [x] 9. Update `cli/src/index.js`: Change the initialization to use `await dialer.connectWithRetry()` instead of the one-shot `connect()`.
- [x] 10. Update `cli/src/quic.js`: Delete the `0x01` application-level ping datagram logic, relying instead on the underlying QUIC transport's keep-alive.
