# Tasks: v0.3.2 Scale and Security Implementation

## Phase 1: O(1) Routing & State (R-new1)
- [x] 1. Update `faas/src/router.rs` to add `caller_to_tunnel` and `caller_to_session` DashMaps.
- [x] 2. Refactor `route_udp_ingress` to use the O(1) `caller_to_tunnel` lookup instead of `.iter().find_map()`.
- [x] 3. Refactor `udp_session_id` allocation to use the O(1) `caller_to_session` lookup.

## Phase 2: Anti-Spoofing & Timestamps (R-new3)
- [x] 4. Modify all UDP routing maps in `faas/src/router.rs` to store `std::time::Instant` alongside their values.
- [x] 5. Implement the 5-second anti-spoofing time window check in `route_udp_ingress` when falling back to the `caller_addr`. Update the `Instant` upon a successful DCID match.

## Phase 3: Garbage Collection & Allocation (R-new2)
- [x] 6. Implement `pub fn gc_udp_sessions(&self, max_idle: Duration)` in `faas/src/router.rs` to sweep and retain only active sessions.
- [x] 7. Update `faas/src/relay.rs` (`run`) to spawn a detached Tokio task that calls `router.gc_udp_sessions(10_mins)` every 60 seconds.
- [x] 8. Refactor the `udp_session_id` allocator to be scoped per-tunnel (e.g., storing the atomic counter inside a wrapper struct stored in `self.table`) rather than globally.

## Phase 4: Hygiene & Docs (R-new5, R-new8)
- [x] 9. Update `SECURITY.md` to add a contact email for vulnerability reporting.
- [x] 10. Update `manifest/config.yaml` to document the WASM target limitations.
- [x] 11. Bump the version to `0.3.2` across `Cargo.toml` and `package.json`.
