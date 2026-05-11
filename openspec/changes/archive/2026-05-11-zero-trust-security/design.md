# Design: mTLS Enforcement

## 1. Relay TLS Configuration (Rust)
In `faas/src/tls.rs`:
- Remove `.with_no_client_auth()`.
- Load a Root CA certificate (`ca.pem`).
- Use `rustls::server::WebPkiClientVerifier::builder(root_cert_store).build()` to enforce client authentication.

## 2. Identity-Based Routing (`relay.rs`)
When a client connects to the `quinn::Endpoint`:
- Retrieve the verified certificate chain via `conn.peer_identity()`.
- Parse the end-entity X.509 certificate (using a lightweight crate like `x509-parser`).
- Extract the Subject Alternative Name (DNS Name).
- **Security Rule:** This extracted SAN becomes the unforgeable `tunnel_key`. If the certificate does not contain a valid SAN, the connection is instantly rejected. The self-reported `hd.server_name` is ignored.

## 3. Node.js Client Strict Verification
In `cli/src/quic.js`:
- Add a `--ca <path>` parameter to the CLI.
- Compute the SHA-256 hash of the CA certificate DER and pass it as `serverCertificateHashes` to `Http3WebTransport`. This pins the relay's trust anchor, preventing MITM even for self-signed relay certificates.