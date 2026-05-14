## Why

The QUIC Initial packet parser needed stronger correctness guarantees for CRYPTO frame offsets, DCID rotation, and documentation accuracy before shipping the `0.3.1` patch.

## What Changes

- Bump CLI, FaaS, and manifest versions to `0.3.1`.
- Clarify that Initial packets are peeked for SNI routing while application payloads remain end-to-end encrypted.
- Parse QUIC CRYPTO frame offsets via VarInt and reject non-zero offsets instead of parsing fragmented data incorrectly.
- Add tests covering QUIC VarInts, CRYPTO frame parsing, valid Initial SNI peeking, and fragmented Initial rejection.
- Route UDP packets with unknown rotated DCIDs by falling back to established caller `SocketAddr` state.

## Capabilities

### New Capabilities

- None. This is a protocol correctness and release patch over existing routing behavior.

### Modified Capabilities

- None. No main OpenSpec capability documents are maintained in this repository.

## Impact

- Affects `manifest/config.yaml`, package versions/lockfiles, QUIC Initial parsing, UDP routing fallback, and FaaS parser/router tests.
