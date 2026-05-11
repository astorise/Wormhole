# Proposal: Tunnel Resilience and State Cleanup

## Problem
With the `public-ingress-and-quic` update, the core transport works securely. However, distributed edge networks (like Tachyon-Mesh) are dynamic; nodes may restart, and client networks may drop. Currently, the Node.js client terminates its process if the WebTransport session fails, lacking any auto-reconnect logic. On the FaaS side, disconnected client tunnels are never removed from the in-memory `DashMap`, creating a memory leak that will eventually crash the long-lived worker.

## Proposed Solution
Implement connection lifecycle management and automatic error recovery:

1. **Auto-Reconnect Engine (Client):** Add an exponential backoff reconnection loop to the Node.js client. When the tunnel drops, local TCP/UDP listeners should remain active, buffering incoming local traffic until the tunnel is re-established.
2. **State Cleanup (Relay):** The Rust relay must detect when a QUIC connection is closed (or timed out) and actively remove the corresponding SNI entry from the `DashMap` routing table.
3. **Keep-Alive:** Ensure WebTransport datagram keep-alives are active to prevent intermediate NATs and the Tachyon Gateway from silently dropping idle L4 connections.

## Non-Goals
- Implementing persistent connection state synchronization across multiple FaaS nodes (we rely entirely on the client's reconnect logic to establish state on a newly assigned FaaS node).