# Tasks: Protocol V2 Implementation

## Phase 1: OpenSpec & CLI Arguments
- [x] 1. Update `manifest/config.yaml` to change the ALPN from `wormhole/1` to `wormhole/2`.
- [x] 2. Update `cli/src/cli.js` to support and parse the new `--tcp <public>:<local>` and `--udp <public>:<local>` argument formats.

## Phase 2: FaaS Framing (Rust)
- [x] 3. Update `faas/src/main.rs` and `ingress.rs` / `ingress_udp.rs` to pass the bound public port number into the router functions.
- [x] 4. Modify `faas/src/router.rs` (`route_ingress`): Prepend the `ingress_port` as a 2-byte Big-Endian `u16` to the QUIC stream before writing the TLS ClientHello bytes.
- [x] 5. Modify `faas/src/router.rs` (`route_udp_ingress`): Allocate a new buffer, write the `ingress_port` (`u16`), append the raw datagram, and send it to the client.

## Phase 3: CLI Demultiplexing (Node.js)
- [x] 6. Refactor `cli/src/mux.js` to act as a true demultiplexer. Instead of `bindTcp` creating a single stream mapping, it should maintain a registry of `{ publicPort -> localPort }`.
- [x] 7. Update `cli/src/quic.js` (or `mux.js`) to expose an event listener for incoming streams initiated by the FaaS (since TCP ingress now flows *Server -> Client* instead of *Client -> Server* as it was implicitly modeled before).
- [x] 8. Implement a reader in the CLI that awaits the 2-byte header, resolves the local port, establishes a connection to the local app (e.g., `net.createConnection(localPort)`), and pipes the remaining data.
