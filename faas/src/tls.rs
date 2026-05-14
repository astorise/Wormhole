use anyhow::{Context, Result};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::ServerConfig;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const DEFAULT_RELAY_CERT_DIR: &str = "/tmp";
const RELAY_CERT_FILE: &str = "wormhole-relay-cert.der";
const RELAY_KEY_FILE: &str = "wormhole-relay-key.der";

pub fn relay_cert_dir() -> PathBuf {
    env::var_os("WORMHOLE_RELAY_CERT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_RELAY_CERT_DIR))
}

pub fn self_signed_cert() -> Result<(
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let cert_dir = relay_cert_dir();
    if let Some(cert) = load_persisted_self_signed_cert(&cert_dir)? {
        return Ok(cert);
    }

    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["wormhole-relay".to_string()])
            .context("failed to generate self-signed cert")?;

    let cert_bytes = cert.der().to_vec();
    let key_bytes = key_pair.serialize_der();
    persist_self_signed_cert(&cert_dir, &cert_bytes, &key_bytes)?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert_bytes);
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_bytes)
        .map_err(|e| anyhow::anyhow!("invalid private key: {e}"))?;

    Ok((cert_der, key_der))
}

fn load_persisted_self_signed_cert(
    cert_dir: &Path,
) -> Result<
    Option<(
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )>,
> {
    let cert_path = cert_dir.join(RELAY_CERT_FILE);
    let key_path = cert_dir.join(RELAY_KEY_FILE);

    if !cert_path.exists() || !key_path.exists() {
        return Ok(None);
    }

    let cert_bytes = fs::read(&cert_path)
        .with_context(|| format!("failed to read relay cert from {}", cert_path.display()))?;
    let key_bytes = fs::read(&key_path)
        .with_context(|| format!("failed to read relay key from {}", key_path.display()))?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert_bytes);
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_bytes)
        .map_err(|e| anyhow::anyhow!("invalid persisted relay private key: {e}"))?;

    Ok(Some((cert_der, key_der)))
}

fn persist_self_signed_cert(cert_dir: &Path, cert_der: &[u8], key_der: &[u8]) -> Result<()> {
    fs::create_dir_all(cert_dir).with_context(|| {
        format!(
            "failed to create relay cert directory {}",
            cert_dir.display()
        )
    })?;

    let cert_path = cert_dir.join(RELAY_CERT_FILE);
    let key_path = cert_dir.join(RELAY_KEY_FILE);

    fs::write(&cert_path, cert_der)
        .with_context(|| format!("failed to persist relay cert to {}", cert_path.display()))?;
    fs::write(&key_path, key_der)
        .with_context(|| format!("failed to persist relay key to {}", key_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o600)).with_context(|| {
            format!(
                "failed to restrict relay cert permissions at {}",
                cert_path.display()
            )
        })?;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).with_context(|| {
            format!(
                "failed to restrict relay key permissions at {}",
                key_path.display()
            )
        })?;
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

    config.alpn_protocols = vec![b"wormhole/3".to_vec(), b"h3".to_vec()];
    Ok(config)
}
