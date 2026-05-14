# Proposal: Protocol V2 Multi-Port Multiplexing

## Problem
The current Wormhole architecture lacks a framing mechanism to identify the intended target port of an incoming QUIC stream or datagram. If a client exposes multiple local ports (e.g., `--tcp 8080 --tcp 3000`), the CLI receives inbound WebTransport streams but cannot distinguish which local application the traffic is intended for. This limits the tunnel to effectively serving only a single port per protocol.

## Proposed Solution
Upgrade the ALPN to `wormhole/2` and introduce a minimal, zero-overhead framing header for all inbound traffic. 

1. **Port Mapping Syntax:** Update the CLI to accept mapped ports (e.g., `--tcp 443:8443`), similar to Docker, distinguishing between the public ingress port on the relay and the local destination port.
2. **Stream Framing (TCP):** The FaaS relay will prepend a 2-byte header (representing the public ingress port as a `u16`) to every new QUIC stream before piping the raw TCP payload.
3. **Datagram Framing (UDP):** Similarly, prepend the 2-byte port header to UDP datagrams.
4. **Multiplexer Routing:** The Node.js client will intercept the first 2 bytes of any new stream or datagram, look up the corresponding local port, and dynamically route the rest of the payload.

## Non-Goals
- Modifying the underlying data payloads or HTTP headers. The framing is stripped out by the client before hitting the local application.