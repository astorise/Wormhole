# Proposal: v1.0.0 Stable Release

## Why
The Wormhole relay and CLI have reached production maturity following rigorous architecture and security audits. The network protocol (V3), the mTLS Zero-Trust security model, and the O(1) routing performance are fully stabilized. However, the project version is still at `0.3.3`, which implies a pre-release or unstable API, and the repository lacks a formal `CHANGELOG.md` documenting its journey to stability.

## What Changes
Promote Wormhole to its first major stable release (`v1.0.0`).
1. **Version Bump:** Update all package configurations (`Cargo.toml`, `package.json`, and `manifest/config.yaml`) to `1.0.0`.
2. **Changelog Creation:** Introduce a `CHANGELOG.md` file summarizing the major milestones (Core transport, mTLS, V3 Framing, Scale/O(1) routing) that justify the 1.0.0 designation.
3. **API Freeze:** Formally declare the CLI flags and the ALPN `wormhole/3` protocol as stable.

## Capabilities
- Stable release metadata for the Rust relay, Node CLI, and deployment manifest.
- Root changelog documenting the v1.0.0 feature and security baseline.
- Stable public CLI and protocol version reporting.

## Impact
- Touches release metadata, CLI version reporting, lockfiles, and documentation only.
- Does not change runtime behavior or protocol logic.

## Non-Goals
- Adding any new features or changing business logic. This is strictly a release management and documentation change.
