use anyhow::{Context, Result};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use wormhole_relay::{ingress::Ingress, ingress_udp::UdpIngress, relay::Relay};

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install ring crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Optional: enforce mTLS on the QUIC control plane.
    // Set WORMHOLE_CA_CERT to a PEM file path to require client certificates
    // signed by that CA; leave unset for unauthenticated (dev/test) mode.
    let relay = match std::env::var("WORMHOLE_CA_CERT").ok() {
        Some(path) => {
            let pem = std::fs::read(&path)
                .with_context(|| format!("failed to read CA cert from {path}"))?;
            let ca_cert = load_ca_cert_from_pem(&pem)?;
            Relay::bind_with_mtls("0.0.0.0:4433", ca_cert).await?
        }
        None => Relay::bind("0.0.0.0:4433").await?,
    };

    let router = relay.router();

    let tcp_ingress = Ingress::new("0.0.0.0:443", Arc::clone(&router)).await?;
    let udp_ingress = UdpIngress::bind("0.0.0.0:443", Arc::clone(&router)).await?;
    let public_socket = udp_ingress.socket();

    tokio::select! {
        res = relay.run(public_socket)  => res?,
        res = tcp_ingress.run()         => res?,
        res = udp_ingress.run()         => res?,
    }

    Ok(())
}

fn load_ca_cert_from_pem(pem: &[u8]) -> Result<rustls::pki_types::CertificateDer<'static>> {
    let mut cursor = std::io::Cursor::new(pem);
    let certs = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse CA PEM")?;
    certs
        .into_iter()
        .next()
        .context("CA PEM contained no certificates")
}
