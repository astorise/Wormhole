use anyhow::{Context, Result};
use quinn::{Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

use crate::router::Router;
use crate::tls;

pub struct Relay {
    endpoint: Endpoint,
    router: Arc<Router>,
}

impl Relay {
    pub async fn new(bind_addr: &str) -> Result<Self> {
        let addr: SocketAddr = bind_addr.parse().context("invalid bind address")?;
        let (cert, key) = tls::self_signed_cert()?;

        let tls_config = tls::server_config(cert, key)?;
        let server_config = ServerConfig::with_crypto(Arc::new(tls_config));

        let endpoint = Endpoint::server(server_config, addr)
            .context("failed to bind QUIC endpoint")?;

        info!(addr = %addr, "QUIC relay listening");

        Ok(Self {
            endpoint,
            router: Arc::new(Router::new()),
        })
    }

    pub async fn run(self) -> Result<()> {
        while let Some(incoming) = self.endpoint.accept().await {
            let router = Arc::clone(&self.router);
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        let sni = conn
                            .handshake_data()
                            .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                            .and_then(|hd| hd.server_name.clone());

                        info!(sni = ?sni, remote = %conn.remote_address(), "client connected");
                        router.register(conn, sni).await;
                    }
                    Err(e) => warn!(err = %e, "connection failed"),
                }
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn relay_binds_to_address() {
        let relay = Relay::new("127.0.0.1:0").await;
        assert!(relay.is_ok(), "relay should bind successfully");
    }
}
