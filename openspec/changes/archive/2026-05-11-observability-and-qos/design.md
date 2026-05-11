# Design: QoS & Telemetry

## 1. Quality of Service (QoS) Tuning
In `faas/src/relay.rs`:
- Update `quinn::TransportConfig` to strictly define:
  - `max_concurrent_bidi_streams` (e.g., 100 per tunnel).
  - `max_concurrent_uni_streams` (e.g., 0, since we only use bidi and datagrams).
  - Stream flow control windows (e.g., `stream_receive_window`).

## 2. Telemetry (Metrics)
In `faas/src/router.rs`:
- Add `std::sync::atomic::AtomicUsize` counters for:
  - `total_ingress_bytes`
  - `total_egress_bytes`
  - `active_tunnels`
- Periodically log these metrics at the `INFO` level using `tracing`, or emit them upon connection closure. Tachyon's log aggregator will index these fields.

## 3. Graceful Shutdown
In `faas/src/main.rs`:
- Use `tokio::signal::ctrl_c()` (or an appropriate WASI yield mechanism) to wait for a shutdown signal.
- Upon receiving the signal, call `endpoint.close(0, b"node_shutting_down")` on the `quinn::Endpoint`.
In `cli/src/index.js` & `mux.js`:
- Listen for the `closed` event with the graceful shutdown reason.
- Stop accepting new TCP connections immediately, flush existing queues, and exit cleanly.