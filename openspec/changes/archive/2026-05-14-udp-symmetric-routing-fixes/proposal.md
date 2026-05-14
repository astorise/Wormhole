# Proposal: Symmetric UDP Routing and Correctness Fixes

## Problem
The recent V2 protocol implementation introduced severe regressions and architectural flaws, specifically concerning UDP routing and multi-tenant security:
1. **Broken UDP Ingress (N1):** The relay currently drops all incoming public UDP datagrams because it attempts to look up the tunnel using the remote caller's QUIC DCID instead of the registered SNI.
2. **Asymmetric UDP Framing & State Loss (N2, N6):** The Node.js client strips the ingress port header but does not prepend it (nor any session identifier) when sending replies back to the relay. This causes the relay to blindly overwrite return paths, breaking UDP for multiple concurrent callers.
3. **mTLS Race Condition (N3):** The relay silently overwrites existing tunnels if a second client connects with the same SAN, allowing accidental or malicious session hijacking.

## Proposed Solution
Upgrade the ALPN to `wormhole/3` and implement Symmetric UDP Routing alongside strict state management:
1. **Symmetric V3 Framing:** Introduce a 4-byte header for UDP (`u16` public port + `u16` session ID). Both the FaaS relay and the CLI will read and write this header to perfectly map responses back to the exact remote caller.
2. **QUIC Initial SNI Peeking:** The relay will decrypt the payload of incoming QUIC Initial packets (using the standard, public QUIC initial salt) to extract the TLS ClientHello SNI. This establishes a reliable `DCID -> SNI` mapping for datagram routing without relying on fallbacks.
3. **Strict Security & Boot:** Enforce `reject_duplicate_sni` unconditionally. Replace brittle boot panics with graceful `anyhow::bail!`.
4. **Documentation Sync:** Update the `README.md` to accurately reflect the relay-to-client traffic flow (reversing the outdated "CLI exposes local port" narrative).

## Non-Goals
- Full implementation of QUIC Short Header state tracking (N9); we will rely on the Tachyon Gateway's L4 stickiness to maintain UDP flows to the correct worker once the Initial packet establishes the `DCID -> SNI` link.