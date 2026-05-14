# Tasks: Symmetric Routing Fixes

## Phase 1: V3 Framing & CLI State (N2, N6)
- [x] 1. Update `manifest/config.yaml` to change ALPN to `wormhole/3` and bump version to `0.3.0`.
- [x] 2. Update `cli/src/mux.js`: Refactor `bindUdp` to handle the new 4-byte header (`publicPort` + `sessionId`). Maintain a `Map` of session IDs to ephemeral `dgram.Socket`s.
- [x] 3. Update `cli/src/mux.js`: Ensure outgoing UDP responses to the relay are prepended with the 4-byte header representing the originating session.

## Phase 2: Relay Framing & SNI Extraction (N1)
- [x] 4. Add a lightweight QUIC Initial decryption routine to `faas/src/ingress_udp.rs` to extract the SNI from the embedded TLS ClientHello.
- [x] 5. Update `faas/src/router.rs`: Add a `dcid_to_sni: DashMap<String, String>` to store the mapped identities.
- [x] 6. Update `faas/src/router.rs` (`route_udp_ingress`): Use `dcid_to_sni` to find the correct `tunnel_key`. Prepend the 4-byte header before forwarding to the client.
- [x] 7. Update `faas/src/relay.rs` (`egress_loop`): Parse the 4-byte header from the client, lookup the remote caller's `SocketAddr` using `(tunnel_key, public_port, session_id)`, and forward the stripped payload.

## Phase 3: Security & Boot Hardening (N3, N7)
- [x] 8. Update `faas/src/router.rs` (`register`): Return an error if the SNI is already registered (no silent overwrites).
- [x] 9. Update `faas/src/main.rs`: Replace `panic!` with `anyhow::bail!` for missing `WORMHOLE_CA_CERT` / `WORMHOLE_DEV`.

## Phase 4: Documentation (N5)
- [x] 10. Update `README.md` to accurately describe the traffic flow: the relay exposes the public port and pushes traffic down to the CLI, which routes to a local service.
