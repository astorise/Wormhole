# Proposal: Core Wormhole Architecture

## Problem
Remote AI models, edge workers, and distributed nodes (within the Tachyon-Mesh ecosystem) need secure, bi-directional access to local development environments (e.g., VS Code workspaces) hidden behind NATs and firewalls. Traditional solutions require complex router configurations, port forwarding, or heavy VPN installations. Furthermore, existing tunneling solutions often terminate TLS at the relay, compromising data privacy, or suffer from "TCP Meltdown" when tunneling modern protocols like HTTP/3.

## Proposed Solution
Build **Wormhole**, a universal, high-performance Layer 4 transport tunnel. 
Wormhole establishes a persistent outbound QUIC connection from the local machine (the client) to a public relay. This conduit securely transports both TCP and UDP traffic through NATs using end-to-end mTLS encryption.

### Key Capabilities
- **QUIC-Powered Transport**: Utilizes QUIC to avoid TCP over TCP meltdown and enables true multiplexing for L4 traffic.
- **Protocol Agnostic (L4)**: Capable of tunneling WebDAV, SSH, HTTP/1.1, and HTTP/3 without application-level parsing.
- **End-to-End mTLS**: Security is terminated exclusively at the local client and the remote caller. The relay acts purely as a blind proxy.
- **Asymmetric Stack**: A pure JavaScript client (Node.js/CLI) for zero-friction local installation, paired with a high-performance Rust/Wasm relay.

## Non-Goals
- Layer 7 processing (e.g., HTTP header manipulation, URL rewriting).
- Layer 3 routing (IP-level VPN configurations like TUN/TAP interfaces).