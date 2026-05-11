use anyhow::{Context, Result};
use rustls::ServerConfig;
use rcgen::{CertifiedKey, generate_simple_self_signed};

pub fn self_signed_cert() -> Result<(rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>)> {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["wormhole-relay".to_string()])
            .context("failed to generate self-signed cert")?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
        .context("invalid private key")?;

    Ok((cert_der, key_der))
}

pub fn server_config(
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("TLS config error")?;

    config.alpn_protocols = vec![b"wormhole/1".to_vec(), b"h3".to_vec()];
    Ok(config)
}
