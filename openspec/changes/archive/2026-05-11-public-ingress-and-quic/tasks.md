# Tasks: Public Ingress and QUIC Implementation

## Phase 1: Tachyon Manifest Integration
- [x] 1. Update `manifest/config.yaml` to add `execution_mode: worker` and configure Gateway Steering (L4 affinity based on SNI/Connection ID).

## Phase 2: Rust Ingress & SNI Parsing (FaaS)
- [x] 2. Add `tls-parser` to `faas/Cargo.toml`.
- [x] 3. Create `faas/src/ingress.rs` with a TCP listener for public incoming connections.
- [x] 4. Implement `peek_sni` logic in `ingress.rs` to parse the TLS ClientHello without consuming the stream.
- [x] 5. Refactor `faas/src/relay.rs` to abstract standard UDP sockets and prepare for Tachyon's Virtual Socket Layer injection.
- [x] 6. Update `faas/src/main.rs` to spawn both the Ingress listener and the QUIC control plane.

## Phase 3: Node.js Real Transport (CLI)
- [x] 7. Add a WebTransport/QUIC package to `cli/package.json` (e.g., `@fails-components/webtransport` or a native QUIC wrapper).
- [x] 8. Rewrite `cli/src/quic.js` to replace the `dgram` mock with the actual WebTransport API.
- [x] 9. Update the multiplexer logic in `cli/src/mux.js` to correctly interface with real WebTransport streams/datagrams.

## Phase 4: Bridging
- [x] 10. Update `faas/src/router.rs` to handle the modified incoming stream (bridging the buffered ClientHello + the rest of the TCP stream into the QUIC stream).