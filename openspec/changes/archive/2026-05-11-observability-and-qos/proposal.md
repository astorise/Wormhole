# Proposal: Observability, QoS, and Graceful Shutdown

## Problem
With transport and security fully implemented, Wormhole is cryptographically secure but vulnerable to resource exhaustion. The FaaS relay allows unbounded concurrent streams and unlimited datagram ingress, which could crash the Tachyon-Mesh edge node under heavy LLM load. Furthermore, the system lacks structured metrics for the Tachyon control plane to monitor health, and shutting down the relay abruptly severs connections without allowing clients to gracefully reconnect.

## Proposed Solution
Introduce Quality of Service (QoS) limits, emit structured metrics, and implement graceful termination.

1. **Resource Limits (QoS):** Configure strict limits in `quinn` for maximum concurrent bidirectional streams and datagram buffer sizes to prevent Out-Of-Memory (OOM) scenarios.
2. **Telemetry & Metrics:** Add lightweight atomic counters in the FaaS router to track active tunnels, bytes transferred, and rejected connections. Expose these metrics via tracing spans compatible with Tachyon-Mesh's logging infrastructure.
3. **Graceful Shutdown:** Intercept termination signals (SIGINT/SIGTERM or WASI equivalents) in both the FaaS relay and the Node.js client to send proper QUIC `GoAway` frames, allowing local multiplexers to cleanly flush data before exiting.

## Non-Goals
- Implementing a full Prometheus scraping endpoint (we rely on standard `tracing` events which Tachyon-Mesh aggregates).
- Persistent rate-limiting across distributed nodes (QoS is strictly local to the worker instance).