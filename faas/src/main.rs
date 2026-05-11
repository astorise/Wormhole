use anyhow::Result;
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

    let relay = Relay::bind("0.0.0.0:4433").await?;
    let router = relay.router();

    // TCP ingress: SNI pass-through for HTTPS/TLS traffic.
    let tcp_ingress = Ingress::new("0.0.0.0:443", Arc::clone(&router)).await?;

    // UDP ingress: QUIC DCID-based routing for HTTP/3 traffic.
    let udp_ingress = UdpIngress::bind("0.0.0.0:443", Arc::clone(&router)).await?;

    tokio::select! {
        res = relay.run()       => res?,
        res = tcp_ingress.run() => res?,
        res = udp_ingress.run() => res?,
    }

    Ok(())
}
