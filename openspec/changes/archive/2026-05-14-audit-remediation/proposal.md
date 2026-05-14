# Proposal: Security and Correctness Remediation

## Problem
A comprehensive expert audit of the Wormhole project identified several critical security vulnerabilities and serious correctness bugs preventing a production-ready v1.0.0 release. Key issues include a UDP routing fallback that leaks traffic in multi-tenant environments (C1), an insecure CLI fallback when certs are missing (C2), SNI hijacking in dev mode (C5), dead code preventing auto-reconnection (S2), and O(N) routing performance degradation under load (S5).

## Proposed Solution
Execute a targeted remediation sweep across the Rust FaaS relay and the Node.js CLI:
1. **Strict Security Posture:** The Relay will refuse to start without explicit mTLS configurations (`WORMHOLE_CA_CERT`) or an explicit `WORMHOLE_DEV=1` flag. The CLI will maintain `rejectUnauthorized: true` unless explicitly overridden via an `--unsecure` flag.
2. **Routing Integrity:** Remove the UDP fallback logic to prevent traffic leaks. Implement an inverse index in the Router (`stable_id -> sni_key`) to eliminate the O(N) iteration bug. Prevent SNI hijacking in dev mode by rejecting duplicate SNI registrations.
3. **Transport Correctness:** Activate the dormant `connectWithRetry` logic in the CLI. Remove the hacky `0x01` app-level datagram ping in favor of native QUIC keep-alives. Update the TLS ClientHello parser (`peek_sni`) to handle fragmented records properly via a buffered read loop.

## Non-Goals
- Adding complex multi-port framing (S4) in this specific change, as it requires a protocol version bump. We will focus first on ensuring the single-port baseline is bulletproof.
- Fixing all CI/CD pipeline issues (S6, S7); these will be handled in a separate DevOps chore change.