# Design: Scale & Security Fixes

## 1. O(1) UDP Routing (R-new1)
In `faas/src/router.rs`:
- Add `caller_to_tunnel: DashMap<SocketAddr, (String, std::time::Instant)>`.
- Add `caller_to_session: DashMap<(String, SocketAddr), u16>`.
- Update `route_udp_ingress` to use `caller_to_tunnel.get(&caller_addr)` instead of iterating over `udp_callers`.
- Update `udp_session_id` to use `caller_to_session` for O(1) lookups.

## 2. Server-Side TTL & GC (R-new2)
In `faas/src/router.rs` and `faas/src/relay.rs`:
- Update `udp_callers` to store the last activity timestamp: `DashMap<(String, u16, u16), (SocketAddr, std::time::Instant)>`.
- Update the activity `Instant` every time a packet is routed (ingress or egress).
- Spawn a `tokio::spawn` background task in `Relay::run` that loops every 60 seconds (`tokio::time::sleep`). It will call a new `router.gc_udp_sessions()` method that uses `retain` on the three UDP DashMaps to remove entries older than 10 minutes.
- Move the `AtomicU16` session ID counter from a global static into the `Connection` metadata or a per-tunnel struct to avoid global exhaustion.

## 3. UDP Spoofing Mitigation (R-new3)
In `faas/src/router.rs`:
- When `route_udp_ingress` falls back to `caller_to_tunnel`, it retrieves the `(tunnel_key, last_seen_instant)`.
- **Security Check:** `if last_seen_instant.elapsed() > Duration::from_secs(5) { return drop }`.
- This ensures an attacker has at most a 5-second window to spoof a packet after a legitimate client sends a valid QUIC Initial/Handshake packet.

## 4. Repo Hygiene (R-new5, R-new8)
- Update `manifest/config.yaml` to add comments stating `target: wasm32-wasip1` is currently a placeholder for future Tachyon host bindings.
- Update `SECURITY.md` to include an explicit security contact email.