# Design: Ingress, Transport & Tachyon Integration

## 1. Tachyon-Mesh Native Runtime
Based on the Tachyon architecture guidelines:
- **Manifest:** The `manifest/config.yaml` will be updated to include `execution_mode: worker` and affinity routing rules for the `system-faas-gateway`.
- **Sockets:** We will abstract the `quinn` UDP socket binding to accept a stream/socket provided by Tachyon's Virtual Socket Layer (accelerator-host.wit).

## 2. FaaS Public Listeners & SNI Routing
The Relay will manage two independent network components concurrently:
- **Control Plane (QUIC):** Accepts outbound tunnels from local clients using the Tachyon Virtual Socket.
- **Data Plane (Ingress):** A TCP Listener for incoming remote caller traffic.
  - When a Remote Caller connects, the relay reads the first chunk (TLS ClientHello).
  - A lightweight parser (`tls-parser` crate) extracts the SNI.
  - The relay queries the `DashMap` (which remains stable thanks to Tachyon's Gateway Steering) for the corresponding client tunnel.
  - The relay encapsulates the TCP bytes into a new QUIC stream on that tunnel.

## 3. Node.js Real Transport
The CLI will drop the `node:dgram` mock and implement a real WebTransport/QUIC session.
- Bidirectional streams map to local TCP ports.
- Datagrams map to local UDP ports.