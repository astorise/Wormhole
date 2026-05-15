# Design: Release v1.0.0

## 1. Version Upgrades
- `faas/Cargo.toml`: Update `version` to `1.0.0`.
- `cli/package.json`: Update `version` to `1.0.0`.
- `manifest/config.yaml`: Update `version` to `1.0.0`.

## 2. Changelog Structure
Create a `CHANGELOG.md` at the root of the repository following the "Keep a Changelog" format.
- Add a `[1.0.0]` section.
- Summarize the key features:
  - Universal L4 QUIC tunnel (TCP & UDP).
  - V3 Symmetric UDP Framing for multi-tenant support.
  - Zero-Trust mTLS identity-based routing.
  - O(1) high-performance relay routing.
  - Auto-reconnect and graceful fallback for dev modes.