# Proposal: Release Prep, E2E Testing, and Repo Hygiene

## Problem
While the core routing and security mechanics are now robust, the project lacks the final polish required for a public `v0.3.0` release. Remaining issues from the V2 audit include:
- **Ephemeral Certs (N4):** Relay auto-generated certs are stored in `/tmp/`, which gets wiped on container restarts, breaking CA pinning.
- **Outdated Docs (N5):** The README still describes V1 semantics (CLI exposing a port) rather than V3 semantics (Relay exposing the port, CLI routing to a local service).
- **Fragile Fallbacks (N12):** The CLI PEM parser falls back to raw buffers unpredictably if parsing fails.
- **Missing Tests & Metrics (N10, N18):** No End-to-End (E2E) integration tests exist, and UDP datagram drops on the CLI are silent.
- **Missing OSS Hygiene (N19):** No `LICENSE` or `SECURITY.md`.

## Proposed Solution
Perform a final cleanup and hardening sweep:
1. **Configurable Persistence:** Introduce `WORMHOLE_RELAY_CERT_DIR` to allow persisting auto-generated relay certificates across container restarts safely.
2. **Strict Validation & Metrics:** Fail hard on invalid PEM certs in the CLI. Add backpressure tracking (`#udpDropped`) to the CLI multiplexer.
3. **Documentation & Hygiene:** Rewrite the README to match the V3 protocol architecture. Bump versions to `0.3.0`. Add MIT `LICENSE` and `SECURITY.md`.
4. **E2E Integration Tests:** Add a basic Rust integration test that spins up the Relay and verifies a mocked TCP/UDP handshake flow.

## Non-Goals
- Complex CI/CD overhauls (e.g., adding Biome/ESLint or `cargo-deny`); we will handle those in standard repository maintenance outside of the core architecture specs.