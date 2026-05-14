# Design: QUIC Parsing Hardening

## 1. Crypto Frame Offset Parsing (R6)
In `faas/src/ingress_udp.rs`:
- The QUIC `CRYPTO` frame format is: `Type (i), Offset (i), Length (i), Crypto Data`.
- The current implementation assumes `Offset == 0`. We must parse the `Offset` using a QUIC VarInt decoder. If `Offset > 0`, it means the ClientHello is fragmented. While full reassembly is out of scope, the parser must cleanly return `None` (or buffer) instead of parsing garbage data.

## 2. DCID Rotation & Flow Tracking (R4)
In `faas/src/router.rs`:
- A QUIC client might change its DCID (e.g., from `DCID_A` to `DCID_B`).
- When we successfully peek the SNI from the Initial packet using `DCID_A`, we store the caller's `SocketAddr`.
- For subsequent Short Header packets, if the new `DCID_B` is unknown, fallback to checking if the caller's `SocketAddr` is already an established flow in `udp_callers`. If it is, route to the associated `tunnel_key`.

## 3. Unit Tests (R5)
In `faas/src/ingress_udp.rs` (or a dedicated `tests` module):
- Add a test `test_peek_quic_initial_sni_valid()`. Provide a static byte array representing a valid QUIC Initial packet (captured via Wireshark) and assert that the correct SNI is extracted.
- Add a test `test_peek_quic_initial_sni_fragmented()` to ensure the offset parser rejects or handles fragmented frames correctly without panicking.