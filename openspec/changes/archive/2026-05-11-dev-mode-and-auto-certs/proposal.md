# Proposal: Dev Mode and Auto-Generated Certificates

## Problem
The strict mTLS enforcement introduced in `zero-trust-security` creates significant friction for onboarding and local development. Specifically, for integrations like the VS Code extension, requiring end-users to manually provision and link PKI certificates severely hurts adoption. The CLI currently fails if no valid certificate is provided.

## Proposed Solution
Introduce a seamless "Dev Mode" that automatically handles cryptographic identities when strict security is not required.

1. **Smart Credential Discovery (CLI):** The Node.js client will automatically look for `relay-domain.pem` and `relay-domain.key` in the user's `~/.ssh/` directory as a fallback if no explicit paths are provided.
2. **Ephemeral Certificate Generation (CLI):** If no certificates are found in `~/.ssh/`, the CLI will automatically generate an in-memory, self-signed X.509 certificate with the SAN matching the requested SNI.
3. **Unsecure Mode (FaaS):** Introduce an opt-in `--unsecure` flag (or `WORMHOLE_UNSECURE=true` env var) on the FaaS relay. When active, the relay bypasses the Root CA verification, accepts self-signed client certificates, and falls back to using the unverified `HandshakeData::server_name` as the routing key.

## Non-Goals
- Persisting auto-generated certificates to the user's disk (they remain ephemeral in memory to avoid clutter).
- Removing the strict mTLS logic. Strict mode remains the default behavior unless explicitly overridden.