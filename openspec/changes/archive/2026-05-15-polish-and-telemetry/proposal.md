# Proposal: Protocol Edge Cases, Telemetry, and Benchmarking (v0.3.3)

## Why
The Round 5 audit identified several non-blocking but important polish items (R-new4, R-new6, R-new7, R-new9-R-new13) remaining in the codebase:
1. **Routing Non-Determinism (R-new4):** If an IP address (caller) is shared across multiple tunnels (e.g., behind a NAT), the fallback routing resolves non-deterministically.
2. **Missing Telemetry (R-new9, R-new12):** There is no visibility when the relay falls back to IP-based routing instead of DCID, nor when the UDP session ID allocator is exhausted.
3. **QUIC Test Coverage (R-new7, R-new10, R-new11):** The QUIC parser tests do not cover RFC 9000 edge cases, such as 1200-byte padding or extreme DCID lengths (0 and 20 bytes).
4. **No Load Testing (R-new6):** The theoretical O(1) routing performance improvements have no benchmark to prove they scale to 10,000+ callers.

## What Changes
Execute a final polish and telemetry sweep to close all Round 5 audit items:
1. **Deterministic Fallback:** Update the inverse index to track the `last_seen` timestamp per caller-tunnel pair, ensuring the most recently active tunnel wins in a conflict.
2. **Telemetry & Logs:** Add explicit `tracing::info!` logs distinguishing "DCID match" vs "Fallback match". Add an `AtomicUsize` counter for `total_session_id_exhausted`.
3. **Robust Tests:** Expand the `peek_quic_initial_sni` test suite with 0-byte, 20-byte, and 1200-byte padded payloads. Document the 8-byte Short Header assumption.
4. **Benchmarks:** Add a minimal `cargo bench` (using `criterion`) or a load-test simulation script verifying routing throughput.
5. **CI Tweak:** Switch to `rustsec/audit-check@v2.0.0` so the FaaS subdirectory can be scanned with the action's `working-directory` input.

## Capabilities
- Runtime UDP routing observability.
- Deterministic UDP fallback routing.
- QUIC parser edge-case coverage.
- Router scalability benchmark coverage.

## Impact
- Touches the Rust relay router, UDP ingress parser tests, FaaS CI, release metadata, and CLI version reporting.
- Adds Criterion as a Rust dev-dependency and introduces a native benchmark target.
