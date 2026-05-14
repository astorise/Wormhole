## Why

Round 4 audit findings exposed release-blocking correctness and security issues around duplicate tunnel registration, UDP session collisions, stale UDP state, and CI enforcement.

## What Changes

- Allow verified mTLS reconnects to take over an existing tunnel key while continuing to reject duplicate unauthenticated tunnel keys.
- Remove hash-derived UDP session IDs in favor of sequential allocation with active-session collision checks.
- Clean up UDP return paths on tunnel unregister and garbage-collect idle CLI UDP sockets.
- Harden FaaS CI by keying Cargo cache on `Cargo.lock` and requiring the WASM build to pass.
- Add regression coverage for mTLS takeover and insecure duplicate rejection.

## Capabilities

### New Capabilities

- None. This change hardens existing tunnel routing and CI behavior.

### Modified Capabilities

- None. No main OpenSpec capability documents are maintained in this repository.

## Impact

- Affects FaaS relay/router UDP routing behavior, CLI UDP session lifecycle, Rust CI workflow behavior, and native/WASM build configuration.
