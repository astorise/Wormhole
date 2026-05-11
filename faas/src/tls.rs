use anyhow::{Context, Result};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::ServerConfig;
use std::sync::Arc;

pub fn self_signed_cert() -> Result<(
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["wormhole-relay".to_string()])
            .context("failed to generate self-signed cert")?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("invalid private key: {e}"))?;

    Ok((cert_der, key_der))
}

/// Build a rustls `ServerConfig`.
///
/// When `ca_cert` is `Some`, mutual TLS is enforced: the relay requires and
/// verifies the client certificate against the provided CA.
/// When `None`, client authentication is skipped (useful for local dev/tests).
pub fn server_config(
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    ca_cert: Option<rustls::pki_types::CertificateDer<'static>>,
) -> Result<ServerConfig> {
    let builder = if let Some(ca) = ca_cert {
        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store
            .add(ca)
            .context("failed to add CA cert to root store")?;

        let client_verifier =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(root_cert_store))
                .build()
                .context("failed to build mTLS client verifier")?;

        ServerConfig::builder().with_client_cert_verifier(client_verifier)
    } else {
        ServerConfig::builder().with_no_client_auth()
    };

    let mut config = builder
        .with_single_cert(vec![cert], key)
        .context("TLS server cert error")?;

    config.alpn_protocols = vec![b"wormhole/1".to_vec(), b"h3".to_vec()];
    Ok(config)
}
