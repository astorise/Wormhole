# Design: Core Hardening

## 1. Smart Session Takeover (R2)
In `faas/src/router.rs`:
- Modify `register(conn, key, is_mtls)`.
- If the key exists:
  - If `is_mtls == true`, this is a cryptographically verified reconnect. Retrieve the old `Connection`, call `.close(0, "takeover")` on it, and overwrite the `DashMap` entry with the new connection.
  - If `is_mtls == false`, return an error to prevent SNI spoofing.

## 2. Collision-Free UDP Allocator (R3)
In `faas/src/ingress_udp.rs`:
- Remove `DefaultHasher`.
- Introduce a global or per-tunnel `AtomicU16` for session IDs.
- On a new caller, use `counter.fetch_add(1, Ordering::Relaxed)`. Verify the ID isn't currently active in `udp_callers`; if it is, increment again.

## 3. Memory Leak Prevention (R8, R9)
In `cli/src/mux.js`:
- For each ephemeral UDP socket, maintain a `lastActivity` timestamp.
- Create a `setInterval` garbage collector (e.g., every 60s) that destroys UDP sockets with no activity for > 5 minutes and deletes them from `#udpSessions`.
In `faas/src/router.rs`:
- During `unregister(key)` (when a tunnel dies), explicitly iterate through `udp_callers` and `remove_if` the entry belongs to the dying `tunnel_key`.

## 4. CI Tweaks (Q4, Q6)
In `.github/workflows/ci-faas.yml`:
- Change `hashFiles('faas/Cargo.toml')` to `hashFiles('faas/Cargo.lock')`.
- Remove `continue-on-error: true` from the `wasm32-wasi` build step to enforce compilation correctness.