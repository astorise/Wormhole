# Tasks: Tachyon Networking Implementation

## Phase 1: Fix UDP Egress NAT Issue
- [x] 1. Modify `faas/src/relay.rs`: update the `egress_loop` signature to accept an `Arc<UdpSocket>` representing the public ingress socket.
- [x] 2. Remove the ephemeral `UdpSocket::bind("0.0.0.0:0")` from `egress_loop` and replace it with the shared public socket for `send_to()`.
- [x] 3. Update `faas/src/main.rs` to pass the `udp_ingress.socket()` into the `relay.run()` context so it can be shared with the egress tasks.

## Phase 2: Tachyon Virtual Socket Layer
- [x] 4. Create `faas/src/tachyon_net.rs` to abstract network bindings.
- [x] 5. Implement `tachyon_net::bind_tcp` and `tachyon_net::bind_udp`. 
- [x] 6. Use conditional compilation (`#[cfg(not(target_os = "wasi"))]`) to return standard `tokio::net` sockets for local testing.
- [x] 7. For `#[cfg(target_os = "wasi")]`, implement the logic to retrieve the `TachyonSocket` (e.g., using `std::os::wasi::io::FromRawFd` to convert pre-opened file descriptors passed by the Tachyon Gateway into Tokio sockets).
- [x] 8. Update `faas/src/ingress.rs`, `faas/src/ingress_udp.rs`, and `faas/src/relay.rs` to use `tachyon_net` for socket initialization.