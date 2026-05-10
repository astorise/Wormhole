# 🕳️ Wormhole

**Wormhole** is a universal, high-performance transport-layer tunnel designed to bypass NATs and firewalls. By utilizing **QUIC** as its underlying transport, it creates a secure bi-directional conduit for both **TCP** and **UDP** traffic with minimal overhead and end-to-end mTLS encryption.

Part of the **Tachyon-Mesh** ecosystem, Wormhole provides the "secure pipe" necessary to expose local development environments, HTTP/3 services, or any custom network stack to remote clients (LLMs, edge workers, or Pulsar nodes).

## ✨ Key Features

- **L4 Agnostic**: Transparently tunnels TCP (SSH, HTTP/1.1, WebDAV) and UDP (HTTP/3, QUIC, DNS).
- **QUIC Powered**: Leverage multiplexing and 0-RTT handshakes to eliminate "TCP Meltdown" and reduce latency.
- **Pure JS Client**: A lightweight CLI and library for Node.js, perfect for VS Code extensions and automation.
- **Rust/Wasm Relay**: High-throughput edge routing using Tachyon FaaS components.
- **True E2E mTLS**: Security is terminated at the local client. The relay acts as a stateless bit-shifter, ensuring total privacy.

## 🏗️ Project Structure

- **/cli**: The Node.js client. Initiates the outbound QUIC tunnel and bridges local ports.
- **/faas**: Rust-based logic for Tachyon-Mesh nodes, handling SNI-based routing for incoming flows.
- **/manifest**: OpenSpec definitions and protocol orchestration metadata.

## 🚀 Usage

### Standalone CLI
Expose a local WebDAV server (TCP) and a dev HTTP/3 service (UDP):

```bash
npx @tachyon-mesh/wormhole --relay https://relay.tachyon.io --tcp 8443 --udp 4433
```

### As a Dependency
Integrate secure tunneling directly into your Node.js application:

```javascript
import { Wormhole } from '@tachyon-mesh/wormhole';

const tunnel = await Wormhole.create({
    relay: 'relay.tachyon.io',
    targets: [
        { protocol: 'tcp', port: 8443 },
        { protocol: 'udp', port: 4433 }
    ],
    auth: { cert: './client.crt', key: './client.key' }
});

console.log(`Wormhole open: ${tunnel.endpoint}`);
```

## 🛠️ Build & CI
The project uses GitHub Actions for:
- **Wasm Compilation**: Optimizing Rust FaaS for Tachyon edge nodes.
- **Zero-Dependency Bundle**: Minifying the CLI for instant execution.

---
*Forging the backbone of the decentralized mesh.*