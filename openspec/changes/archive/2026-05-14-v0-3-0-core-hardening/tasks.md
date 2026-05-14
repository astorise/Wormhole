# Tasks: Core Hardening Implementation

## Phase 1: Routing & State (R2, R8, R9)
- [x] 1. Update `faas/src/relay.rs` to pass an `is_mtls` boolean flag to `router.register()`, indicating whether the connection was authenticated via a client cert.
- [x] 2. Update `faas/src/router.rs` `register()`: Implement the "Kick Previous" logic for `is_mtls = true` and "Reject Duplicate" for `is_mtls = false`.
- [x] 3. Update `faas/src/router.rs` `unregister()`: Ensure all `udp_callers` associated with the dying `tunnel_key` are actively removed.
- [x] 4. Update `cli/src/mux.js`: Implement a TTL garbage collector for `#udpSessions` that closes and deletes ephemeral `dgram` sockets after 5 minutes of inactivity.

## Phase 2: UDP Session Allocator (R3)
- [x] 5. Update `faas/src/ingress_udp.rs` (or `router.rs`): Replace the `DefaultHasher` session ID generation with a sequential `AtomicU16` counter, ensuring no cross-tenant collisions.

## Phase 3: CI Hardening (Q4, Q6)
- [x] 6. Update `.github/workflows/ci-faas.yml`: Modify the cache key to use `Cargo.lock` instead of `Cargo.toml`.
- [x] 7. Update `.github/workflows/ci-faas.yml`: Remove `continue-on-error: true` from the WASM build step.

## Phase 4: Validation
- [x] 8. Write a test in `faas/src/router.rs` validating that mTLS takeover succeeds and terminates the old connection, while insecure duplicates are rejected.
