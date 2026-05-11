use anyhow::Result;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use wormhole_relay::{ingress::Ingress, relay::Relay};

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
    let ingress = Ingress::new("0.0.0.0:443", Arc::clone(&router)).await?;

    // Run both planes concurrently; stop the process if either one exits.
    tokio::select! {
        res = relay.run()   => res?,
        res = ingress.run() => res?,
    }

    Ok(())
}
