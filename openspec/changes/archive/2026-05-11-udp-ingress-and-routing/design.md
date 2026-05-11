# Design: UDP Ingress Routing

## 1. UDP Data Plane (`ingress_udp.rs`)
The FaaS will spawn an additional `tokio::net::UdpSocket` binding to the same port as the TCP listener (e.g., `0.0.0.0:443`).
- **Ingress Flow:** When a datagram arrives from a Remote Caller, the relay will peek into the first few bytes. Using `quinn_proto` (or manual byte matching), it extracts the QUIC DCID.
- **Routing:** The relay queries the `Router` using the extracted DCID. 
- **Forwarding:** It encapsulates the raw datagram into a WebTransport datagram and sends it through the client's tunnel.

## 2. Managing the UDP Return Path
Because UDP is connectionless, when the local Node.js client sends a reply datagram up the tunnel, the FaaS needs to know where to send it on the public internet.
- The `Router` will maintain an ephemeral mapping (`DashMap<String, SocketAddr>`) tracking the `Client Tunnel ID -> Last seen LLM Public IP:Port`.
- **Egress Flow:** When the FaaS receives a datagram from the client's tunnel, it looks up this mapped `SocketAddr` and sends the packet out via the public `UdpSocket`.

## 3. Tachyon Compatibility
Tachyon's L4 Gateway Steering already guarantees that all UDP packets with the same QUIC Connection ID will hit the exact same FaaS worker. The worker only needs to maintain the return path in memory.