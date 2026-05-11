# Design: Tunnel Resilience

## 1. FaaS Memory Management (Rust)
In `faas/src/router.rs`:
- Add an `unregister(&self, key: &str)` method.
In `faas/src/relay.rs`:
- When spawning the task to handle an incoming client connection, `quinn::Connection` provides a `.closed()` future. 
- The relay will await `conn.closed()` concurrently with its stream processing. Once resolved, it triggers `router.remove(sni)`, ensuring the `DashMap` is strictly bound to the actual lifecycle of the QUIC tunnel.

## 2. Client Reconnection Engine (Node.js)
In `cli/src/quic.js`:
- Wrap the `Http3WebTransport` instantiation in a retry loop.
- Use exponential backoff: `delay = min(base_delay * 2^attempt, max_delay)`.
- Expose `pause` and `resume` events to the `Multiplexer`.

In `cli/src/mux.js`:
- Decouple the local servers (TCP/UDP) from a single dialer instance.
- When the dialer emits `disconnected`, the multiplexer should queue incoming local data (up to a memory limit) instead of destroying the local sockets.
- When the dialer emits `connected` again, flush the queued buffers over new WebTransport streams.

## 3. Keep-Alive Strategy
- Configure `quinn` ServerConfig with a reasonable `max_idle_timeout` (e.g., 30 seconds).
- The Node.js client will send a 1-byte "Ping" WebTransport datagram every 15 seconds if no other data is flowing, keeping the Tachyon Gateway L4 affinity session alive.