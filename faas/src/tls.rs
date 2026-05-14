use anyhow::{Context, Result};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::ServerConfig;
use std::fs;
use std::path::Path;
use std::sync::Arc;

const RELAY_CERT_PATH: &str = "/tmp/wormhole-relay-cert.der";
const RELAY_KEY_PATH: &str = "/tmp/wormhole-relay-key.der";

pub fn self_signed_cert() -> Result<(
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    if let Some(cert) = load_persisted_self_signed_cert()? {
        return Ok(cert);
    }

    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["wormhole-relay".to_string()])
            .context("failed to generate self-signed cert")?;

    let cert_bytes = cert.der().to_vec();
    let key_bytes = key_pair.serialize_der();
    persist_self_signed_cert(&cert_bytes, &key_bytes)?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert_bytes);
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_bytes)
        .map_err(|e| anyhow::anyhow!("invalid private key: {e}"))?;

    Ok((cert_der, key_der))
}

fn load_persisted_self_signed_cert() -> Result<
    Option<(
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )>,
> {
    let cert_path = Path::new(RELAY_CERT_PATH);
    let key_path = Path::new(RELAY_KEY_PATH);

    if !cert_path.exists() || !key_path.exists() {
        return Ok(None);
    }

    let cert_bytes = fs::read(cert_path)
        .with_context(|| format!("failed to read relay cert from {RELAY_CERT_PATH}"))?;
    let key_bytes = fs::read(key_path)
        .with_context(|| format!("failed to read relay key from {RELAY_KEY_PATH}"))?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert_bytes);
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_bytes)
        .map_err(|e| anyhow::anyhow!("invalid persisted relay private key: {e}"))?;

    Ok(Some((cert_der, key_der)))
}

fn persist_self_signed_cert(cert_der: &[u8], key_der: &[u8]) -> Result<()> {
    if let Some(parent) = Path::new(RELAY_CERT_PATH).parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create relay cert directory {parent:?}"))?;
    }
    if let Some(parent) = Path::new(RELAY_KEY_PATH).parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create relay key directory {parent:?}"))?;
    }

    fs::write(RELAY_CERT_PATH, cert_der)
        .with_context(|| format!("failed to persist relay cert to {RELAY_CERT_PATH}"))?;
    fs::write(RELAY_KEY_PATH, key_der)
        .with_context(|| format!("failed to persist relay key to {RELAY_KEY_PATH}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(RELAY_KEY_PATH, fs::Permissions::from_mode(0o600)).with_context(
            || format!("failed to restrict relay key permissions at {RELAY_KEY_PATH}"),
        )?;
    }

    Ok(())
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

    config.alpn_protocols = vec![b"wormhole/2".to_vec(), b"h3".to_vec()];
    Ok(config)
}
