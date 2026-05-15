## Why

Round 5 audit findings showed that UDP routing still had O(N) fallback paths, unbounded caller state, an overly long spoofing window, and unclear WASM target expectations.

## What Changes

- Add O(1) UDP inverse indexes for caller-to-tunnel and caller-to-session lookup.
- Timestamp UDP routing state and reject caller-address fallback outside a 5-second authenticated DCID window.
- Add server-side UDP session garbage collection and run it periodically from the relay.
- Scope UDP session ID counters per tunnel instead of globally.
- Document WASM target limitations, add an explicit security contact, and bump package versions to `0.3.2`.

## Capabilities

### New Capabilities

- None. This change hardens the existing multi-protocol tunnel implementation.

### Modified Capabilities

- None. No main OpenSpec capability documents are maintained in this repository.

## Impact

- Affects FaaS UDP routing state, relay background maintenance, package versions/lockfiles, manifest metadata, and security reporting documentation.
