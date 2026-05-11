use anyhow::Result;
use tracing_subscriber::EnvFilter;
use wormhole_relay::relay::Relay;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let relay = Relay::new("0.0.0.0:4433").await?;
    relay.run().await
}
