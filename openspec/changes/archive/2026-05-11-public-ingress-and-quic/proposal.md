# Proposal: Public Ingress, Real QUIC, and Tachyon Native Integration

## Problem
The initial `core-architecture` relied on mocked transport layers (plain UDP instead of QUIC) and lacked public-facing ingress. Furthermore, to run effectively on the Tachyon-Mesh, the FaaS relay cannot operate in a standard ephemeral request/response mode, and standard WASI lacks transparent UDP socket support for QUIC.

## Proposed Solution
Replace mocks with production transport layers and deeply integrate with Tachyon-Mesh's advanced runtime features:

1. **Tachyon Worker Mode:** Configure the relay to run as a long-lived process (`execution_mode: worker`) allowing `tokio` to maintain active QUIC connections and memory-pinned state (`DashMap`).
2. **Virtual Socket Integration:** Adapt the FaaS relay to use Tachyon's Virtual Socket Layer (via WIT bindings) for UDP/QUIC, rather than relying on standard OS sockets.
3. **Gateway Steering Affinity:** Configure the manifest to instruct the Tachyon Gateway to use L4 stickiness (SNI/QUIC Connection ID) to ensure packets are routed to the correct worker instance holding the RAM state.
4. **Real QUIC Client:** Integrate WebTransport/QUIC into the Node.js CLI.
5. **SNI Pass-Through:** Implement a lightweight TLS ClientHello parser in Rust for pure L4 routing without terminating mTLS.

## Non-Goals
- Full HTTP/3 implementation on the relay.
- Implementing custom STUN/TURN (we rely entirely on Tachyon's gateway and our outbound QUIC tunnel).