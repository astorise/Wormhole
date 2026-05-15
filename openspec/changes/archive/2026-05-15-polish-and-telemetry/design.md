# Design: Polish & Telemetry

## 1. Deterministic Caller Fallback (R-new4)
In `faas/src/router.rs`:
- Update `caller_to_tunnel` to handle multiple tunnels per IP (or update the logic to resolve conflicts).
- When a `caller_addr` maps to multiple tunnels, pick the one with the most recent `last_seen` timestamp. This reliably maps returning traffic to the active flow.

## 2. Telemetry and Logging (R-new9, R-new12)
In `faas/src/router.rs` and `faas/src/ingress_udp.rs`:
- Add `total_session_id_exhausted: AtomicUsize` to the `Router` metrics.
- Increment it if `udp_session_id` exhausts the `u16::MAX` search loop and returns `None`.
- In `route_udp_ingress`, emit `tracing::debug!("routing via DCID match")` or `tracing::info!("routing via caller_addr fallback")` to make production observability actionable.

## 3. QUIC Edge Case Tests (R-new7, R-new10, R-new11)
In `faas/src/ingress_udp.rs`:
- Add `test_peek_quic_dcid_0_bytes()` and `test_peek_quic_dcid_20_bytes()`.
- Add `test_peek_quic_initial_with_1200_byte_padding()` padding the mock packet to exactly 1200 bytes (RFC 9000 compliant).
- Add a code comment documenting the 8-byte Short Header constraint as a known limitation compensated by Tachyon Gateway L4 stickiness.

## 4. Performance Benchmark (R-new6)
Add `faas/benches/router_bench.rs` using the `criterion` crate:
- Setup a `Router` populated with 10,000 mock `udp_callers`.
- Benchmark `route_udp_ingress` (which internally calls `tunnel_key_for_caller`) to ensure it executes in sub-microsecond O(1) time.