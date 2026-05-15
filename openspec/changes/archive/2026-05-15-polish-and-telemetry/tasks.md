# Tasks: Polish and Telemetry Implementation

## Phase 1: Logic & Telemetry (R-new4, R-new9, R-new12)
- [x] 1. Update `faas/src/router.rs`: Add `total_session_id_exhausted` atomic counter and increment it when the session allocator fails.
- [x] 2. Update `faas/src/router.rs` (`route_udp_ingress`): Add explicit `tracing` logs distinguishing between DCID routing and Fallback routing.
- [x] 3. Update `faas/src/router.rs` (`tunnel_key_for_caller`): Make conflict resolution deterministic by returning the tunnel with the most recent `last_seen` timestamp if an IP is shared.

## Phase 2: Testing & Edge Cases (R-new7, R-new10, R-new11)
- [x] 4. Update `faas/src/ingress_udp.rs`: Add tests for 0-byte and 20-byte DCIDs, and a 1200-byte padded Initial packet.
- [x] 5. Update `faas/src/ingress_udp.rs`: Add explicit comments documenting the 8-byte Short Header assumption.

## Phase 3: Benchmarking (R-new6)
- [x] 6. Add `criterion` to `faas/Cargo.toml` under `[dev-dependencies]`.
- [x] 7. Create `faas/benches/router_bench.rs` simulating 10,000 concurrent UDP callers and benchmark the `route_udp_ingress` function.

## Phase 4: CI & Release (R-new13)
- [x] 8. Update `.github/workflows/ci-faas.yml`: Replace `actions-rust-lang/audit@v1` with the official `rustsec/audit-check@v2.0.0`.
- [x] 9. Bump version to `0.3.3` in `Cargo.toml`, `package.json`, and release metadata.
