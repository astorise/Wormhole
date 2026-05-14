#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(not(target_arch = "wasm32"))]
use anyhow::{Context, Result};
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use tracing::info;
#[cfg(not(target_arch = "wasm32"))]
use tracing_subscriber::EnvFilter;

#[cfg(not(target_arch = "wasm32"))]
use wormhole_relay::{ingress::Ingress, ingress_udp::UdpIngress, relay::Relay};

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install ring crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let relay_cert_dir = wormhole_relay::tls::relay_cert_dir();
    info!(path = %relay_cert_dir.display(), "relay certificate persistence directory");

    // Priority: mTLS > explicit local development mode.
    let relay = if let Ok(path) = std::env::var("WORMHOLE_CA_CERT") {
        let pem =
            std::fs::read(&path).with_context(|| format!("failed to read CA cert from {path}"))?;
        let ca_cert = load_ca_cert_from_pem(&pem)?;
        Relay::bind_with_mtls("0.0.0.0:4433", ca_cert).await?
    } else if env_flag("WORMHOLE_DEV") {
        Relay::bind_unsecure("0.0.0.0:4433").await?
    } else {
        anyhow::bail!(
            "WORMHOLE_CA_CERT is required for mTLS; set WORMHOLE_DEV=1 only for local unsecure development"
        );
    };

    // Grab a cloned endpoint handle *before* consuming `relay` in `run()`.
    // This lets the shutdown branch close the endpoint gracefully.
    let ep = relay.endpoint_handle();
    let router = relay.router();

    let tcp_ingress = Ingress::new("0.0.0.0:443", Arc::clone(&router)).await?;
    let udp_ingress = UdpIngress::bind("0.0.0.0:443", Arc::clone(&router)).await?;
    let public_socket = udp_ingress.socket();

    tokio::select! {
        // Graceful shutdown on SIGINT (Ctrl-C) or SIGTERM.
        _ = shutdown_signal() => {
            info!("shutdown signal received — sending QUIC GoAway");
            ep.close(quinn::VarInt::from_u32(0), b"node_shutting_down");
            // Allow 3 s for in-flight connections to drain.
            tokio::time::sleep(Duration::from_secs(3)).await;
            info!("graceful shutdown complete");
        }
        res = relay.run(public_socket)  => res?,
        res = tcp_ingress.run()         => res?,
        res = udp_ingress.run()         => res?,
    }

    Ok(())
}

/// Resolves on SIGINT (Ctrl-C) on all platforms; also listens for SIGTERM
/// on Unix so process managers (systemd, Docker) can trigger clean shutdown.
#[cfg(not(target_arch = "wasm32"))]
async fn shutdown_signal() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.unwrap_or(()) };

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).unwrap_or_else(|e| {
            tracing::warn!(err = %e, "failed to install SIGTERM handler");
            // Return a stream that never fires by blocking forever.
            // This is intentional — we only warn, ctrl_c still works.
            signal(SignalKind::hangup()).expect("SIGHUP fallback")
        });
        tokio::select! {
            _ = ctrl_c       => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    ctrl_c.await;
}

#[cfg(not(target_arch = "wasm32"))]
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

#[cfg(not(target_arch = "wasm32"))]
fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}
