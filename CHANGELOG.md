# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic Versioning.

## [1.0.0] - 2026-05-15

### Added

- Stable universal L4 transport tunnel over QUIC for TCP and UDP services.
- `wormhole/3` ALPN protocol with V3 symmetric UDP framing for public-port and relay-session routing.
- End-to-end mTLS tunnel identity and certificate SAN based relay routing for production deployments.
- Node.js CLI and library entrypoint for opening QUIC tunnels, mapping TCP/UDP ports, and reconnecting after transport interruptions.
- Rust relay runtime for Tachyon edge workers, including SNI/DCID routing, UDP return-path tracking, and structured telemetry.
- O(1) relay routing indexes and a Criterion benchmark covering 10,000 concurrent UDP callers.
- Tachyon manifest metadata for the relay, CLI, protocol capabilities, and wasm32-wasip1 placeholder target.

### Security

- Relay certificate verification is strict by default in the CLI.
- `--unsecure` is limited to explicit local development usage.
- mTLS takeover replaces an existing tunnel only for authenticated clients.
- Dependency audit workflows cover both Rust and Node.js packages.

### Stable

- CLI flags for relay address, TCP/UDP port mappings, client cert/key, relay CA pinning, development mode, and SNI selection.
- Public package name `@tachyon-mesh/wormhole`.
- Relay ALPN `wormhole/3`.
