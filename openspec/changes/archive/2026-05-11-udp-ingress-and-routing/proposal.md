# Proposal: UDP Ingress and QUIC Datagram Routing

## Problem
Currently, the Wormhole FaaS relay only binds a public `TcpListener`. While this successfully routes standard HTTPS/TCP traffic using SNI pass-through, it entirely drops incoming UDP traffic. Consequently, remote callers (e.g., LLMs) cannot leverage modern HTTP/3 (QUIC) over the tunnel. Since QUIC payloads are encrypted, we cannot use SNI peeking for UDP datagrams.

## Proposed Solution
Implement a UDP Ingress plane on the FaaS relay capable of routing raw UDP datagrams (primarily HTTP/3 traffic) bidirectionally.

1. **UDP Ingress Listener:** Bind a public `UdpSocket` alongside the TCP listener.
2. **QUIC Header Peeking (DCID):** For incoming UDP packets, parse the unencrypted QUIC header to extract the Destination Connection ID (DCID).
3. **Stateful Return Path:** Use the DCID as the fallback routing key in the `DashMap` (already defined in our config). Forward the datagram to the correct local client tunnel via WebTransport datagrams, while temporarily storing the remote caller's public `SocketAddr` to route the client's replies back to the caller.

## Non-Goals
- Re-assembling UDP fragments on the relay (the relay operates strictly as a stateless datagram proxy).
- Implementing STUN/TURN traversal logic inside the relay.