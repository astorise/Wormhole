# Tasks: v0.3.1 Protocol Correctness

## Phase 1: Documentation & Config (R7)
- [x] 1. Update `manifest/config.yaml` description: Remove the claim "without decrypting the payload". Clarify that "Initial packets are peeked for SNI routing, while application payloads remain E2E encrypted."
- [x] 2. Bump package versions in `cli/package.json` and `faas/Cargo.toml` to `0.3.1`.

## Phase 2: QUIC Parser & Tests (R5, R6)
- [x] 3. Update `faas/src/ingress_udp.rs`: Implement a simple QUIC VarInt decoder to read the `Offset` field of the `CRYPTO` frame.
- [x] 4. Update `faas/src/ingress_udp.rs`: Add validation logic to handle cases where the `Offset` is greater than 0.
- [x] 5. Add unit tests in `faas/src/ingress_udp.rs` using hardcoded hex arrays of QUIC packets to verify `peek_quic_initial_sni` functionality.

## Phase 3: Routing Stability (R4)
- [x] 6. Update `faas/src/router.rs` (`route_udp_ingress`): If the DCID is not found in the `dcid_to_sni` map (e.g., due to rotation in a Short Header), attempt to look up the client's `SocketAddr` in the `udp_callers` map values to find the established `tunnel_key`.
