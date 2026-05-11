# Design: Core Wormhole Architecture

## System Architecture

Wormhole operates on a tripartite model:
1. **The Remote Caller** (e.g., LLM Agent, external service)
2. **The FaaS Relay** (Public edge node)
3. **The Local Client** (CLI/Node.js on the developer's machine)

### Data Flow
1. **Registration**: The Local Client initiates an outbound QUIC connection to the FaaS Relay, authenticating via mTLS.
2. **Listening**: The Relay registers the active tunnel and listens for incoming connections on public ports.
3. **Bridging**: When the Remote Caller connects to the Relay, the Relay encapsulates the incoming TCP streams or UDP datagrams into the existing QUIC tunnel without decrypting the payload (TLS Pass-through).
4. **Resolution**: The Local Client receives the encapsulated data, unpacks it, and bridges it to the designated local service (e.g., localhost:8443).

## Technical Stack

### 1. Local Client (`/cli`)
- **Runtime**: Node.js
- **Network**: Native QUIC implementation (or lightweight lib like `@fails-components/webtransport` / native `dgram` wrapped) to establish the tunnel. Native `net` and `dgram` modules to bridge local TCP/UDP ports.
- **Interface**: Executable via `npx` with CLI arguments for target mapping (`--tcp 8443 --udp 4433`).

### 2. Edge Relay (`/faas`)
- **Language**: Rust compiled to `wasm32-wasi` for execution on Tachyon-Mesh nodes.
- **Network**: `quinn` (or similar asynchronous QUIC implementation compatible with Wasm) to handle massive concurrency and SNI-based routing.
- **State**: Stateless routing table mapping SNIs/Connection IDs to active QUIC outbound sockets.

### 3. OpenSpec Manifest (`/manifest`)
- YAML-based OpenSpec definitions detailing the `MultiProtocolTransport` capabilities, ALPN configurations, and routing strategies for Tachyon integration.