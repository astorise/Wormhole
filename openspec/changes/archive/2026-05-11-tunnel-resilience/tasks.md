# Tasks: Tunnel Resilience Implementation

## Phase 1: FaaS State Cleanup
- [x] 1. Update `faas/src/router.rs` to add `unregister(&self, key: &str)` to remove dead entries from the `DashMap`.
- [x] 2. Update `faas/src/relay.rs` to monitor `conn.closed()` for each client. When the connection drops, call `unregister()` to free memory.
- [x] 3. Update the `quinn` ServerConfig in `faas/src/relay.rs` to enforce a `max_idle_timeout` of 30 seconds.

## Phase 2: Node.js Auto-Reconnect
- [x] 4. Refactor `cli/src/quic.js` to implement an exponential backoff loop inside a new `connectWithRetry` method.
- [x] 5. Add event emitters for `reconnecting` and `reconnected` in `QuicDialer`.
- [x] 6. Implement a Keep-Alive mechanism in `QuicDialer` that sends an empty datagram (or 1-byte ping) every 15 seconds.

## Phase 3: Multiplexer Buffer & Swap
- [x] 7. Update `cli/src/mux.js` to listen for dialer state changes. If disconnected, pause reading from local TCP sockets and queue incoming UDP datagrams.
- [x] 8. Once reconnected, transparently open new `QuicStream`s for active local TCP connections and flush any queued data.
- [x] 9. Write a test in `cli/test/wormhole.test.js` simulating a dialer disconnect/reconnect cycle to verify the multiplexer recovers without crashing.