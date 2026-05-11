# Tasks: UDP Ingress Implementation

## Phase 1: Rust UDP Ingress Component
- [x] 1. Create `faas/src/ingress_udp.rs` and set up a `tokio::net::UdpSocket` listening on the target port.
- [x] 2. Implement a `peek_quic_dcid(&[u8]) -> Option<String>` function to extract the unencrypted QUIC Destination Connection ID from Short and Long headers.
- [x] 3. Expose the UDP Ingress execution loop and spawn it in `faas/src/main.rs` alongside the TCP ingress and QUIC control plane.

## Phase 2: Routing and Return Paths
- [x] 4. Update `faas/src/router.rs` to add a new `DashMap` (or update the existing one) to map `Tunnel Key -> SocketAddr` representing the remote caller's UDP return path.
- [x] 5. Add a `route_udp_ingress` method to `router.rs` that accepts a raw datagram, finds the associated client tunnel, updates the return path, and forwards the datagram via `conn.send_datagram()`.

## Phase 3: FaaS UDP Egress
- [x] 6. Update `faas/src/relay.rs` (in the client connection handler loop) to actively listen for incoming datagrams from the client tunnel using `conn.read_datagram()`.
- [x] 7. When a datagram is received from the client tunnel, look up the remote caller's `SocketAddr` and send the datagram out through a shared reference to the public `UdpSocket`.

## Phase 4: Integration
- [x] 8. Write a unit test in `ingress_udp.rs` to verify that `peek_quic_dcid` correctly extracts the connection ID from a simulated raw QUIC packet header.