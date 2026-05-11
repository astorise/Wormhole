# Tasks: Observability and QoS Implementation

## Phase 1: FaaS QoS Limits
- [x] 1. Update `faas/src/relay.rs` to configure strict limits on `quinn::TransportConfig` (max concurrent streams, receive windows).
- [x] 2. Update `faas/src/ingress.rs` and `faas/src/ingress_udp.rs` to handle stream/socket backpressure and drop packets gracefully if the client tunnel is saturated.

## Phase 2: Telemetry and Counters
- [x] 3. Add `AtomicUsize` fields to the `Router` struct in `faas/src/router.rs`.
- [x] 4. Increment byte counters during the `tokio::io::copy` phase in `route_ingress` and inside the datagram egress/ingress loops.
- [x] 5. Emit structured `tracing::info!` logs containing these metrics when a tunnel is unregistered.

## Phase 3: Graceful Shutdown
- [x] 6. Update `faas/src/main.rs` to use `tokio::select!` with a signal listener (`ctrl_c()`) to trigger a graceful shutdown of the QUIC endpoint.
- [x] 7. Update `cli/src/quic.js` to catch server-initiated closure frames.
- [x] 8. Update `cli/src/mux.js` to expose a `drain()` method that stops the local servers but finishes serving active connections before terminating the Node.js process.