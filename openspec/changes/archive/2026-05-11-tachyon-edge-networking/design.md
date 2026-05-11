# Design: Edge Networking & Sockets

## 1. Correcting UDP Egress (NAT Traversal)
The `Relay` struct and its `run` method will be updated.
- Currently, `Relay` only holds `Endpoint` and `Router`.
- We will inject an `Option<Arc<UdpSocket>>` (the public ingress socket) into the `Relay` or directly into the `egress_loop`.
- When `egress_loop` receives a datagram from the client tunnel, it uses `public_socket.send_to(...)` instead of binding a new ephemeral socket.

## 2. Tachyon Networking Bindings (WASI)
Since WASI networking is still evolving, Tachyon-Mesh uses a Virtual Socket Layer.
- We will define a `tachyon_net.rs` module.
- We will use `#[cfg(target_os = "wasi")]` to conditionally compile the Tachyon-specific socket retrieval logic.
- Instead of `TcpListener::bind("0.0.0.0:443")`, the code will call a function that requests the pre-bound socket file descriptor from the Tachyon Host via standard WASI preopens or custom WIT imports.
- For local testing (Node/Linux), it will fallback to standard `tokio::net`.