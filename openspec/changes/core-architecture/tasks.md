# Tasks: Core Architecture Implementation

## Phase 1: Foundation
- [x] 1. Scaffold project directory structure (`/cli`, `/faas`, `/manifest`).
- [x] 2. Define the initial `wormhole-core` OpenSpec manifest in `/manifest/config.yaml`.
- [x] 3. Setup GitHub Actions CI/CD workflows for Rust->Wasm compilation, JS bundling, Rust tests (`cargo test`), and Node.js tests (`npm test`).

## Phase 2: The Rust FaaS Relay
- [x] 4. Initialize Rust project (`cargo init`) with Wasm target configuration.
- [x] 5. Implement the QUIC listener using `quinn` to accept incoming outbound tunnels from clients.
- [x] 6. Implement the stateless SNI/Connection ID router (TLS Pass-through) to map public incoming requests to the correct QUIC stream.

## Phase 3: The JS Local Client
- [x] 7. Initialize Node.js project (`npm init`) and configure CLI argument parsing.
- [x] 8. Implement the QUIC dialer to establish the persistent outbound tunnel to the FaaS Relay.
- [x] 9. Implement the mTLS handshake configuration (loading cert/key pairs).
- [x] 10. Implement the TCP/UDP multiplexing logic to bridge QUIC streams/datagrams to local `localhost` ports.
- [x] 11. Add a unified programmatic API `Wormhole.create()` to allow usage as a standard NPM dependency.