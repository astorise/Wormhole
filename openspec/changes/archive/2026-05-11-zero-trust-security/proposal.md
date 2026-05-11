# Proposal: Zero-Trust Security & mTLS Enforcement

## Problem
Currently, the Wormhole FaaS relay accepts QUIC control-plane connections from any client without authentication (`with_no_client_auth`). Furthermore, the relay blindly trusts the SNI requested by the client during the QUIC handshake. This creates an open relay vulnerability and allows malicious clients to spoof SNIs, hijacking traffic intended for legitimate developers. 

## Proposed Solution
Enforce strict mutual TLS (mTLS) on the QUIC Control Plane, anchoring the routing logic to cryptographic identities rather than self-reported strings.

1. **Strict Client Authentication (Relay):** Configure `rustls` on the FaaS to require and verify client certificates against a trusted Root CA.
2. **Cryptographic SNI Binding:** Instead of relying on the client's requested SNI, the Relay will extract the Subject Alternative Name (SAN) or Common Name (CN) directly from the verified client certificate. This value will strictly dictate which ingress SNI the client is allowed to receive traffic for.
3. **Verified CA Dialing (Client):** Update the Node.js CLI to verify the relay's certificate against a provided CA, preventing Man-in-the-Middle (MITM) attacks on the outbound tunnel.

## Non-Goals
- Implementing a full PKI (Public Key Infrastructure) certificate generation service. We assume the Tachyon ecosystem or the user provides valid `ca.pem`, `cert.pem`, and `key.pem` files.