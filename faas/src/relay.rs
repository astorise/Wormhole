use anyhow::{Context, Result};
use quinn::{crypto::rustls::QuicServerConfig, Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

use crate::router::Router;
use crate::tls;

pub enum SocketSource {
    Bind(SocketAddr),
    Tachyon(TachyonSocket),
}

pub struct TachyonSocket;

pub struct Relay {
    endpoint: Endpoint,
    router: Arc<Router>,
}

impl Relay {
    pub async fn new(source: SocketSource) -> Result<Self> {
        let (cert, key) = tls::self_signed_cert()?;
        let tls_config = tls::server_config(cert, key)?;
        let quic_config =
            QuicServerConfig::try_from(tls_config).context("invalid QUIC TLS config")?;

        let mut transport = quinn::TransportConfig::default();
        // Close idle connections after 30 s; keeps DashMap bounded.
        transport.max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .expect("valid idle timeout"),
        ));
        transport.keep_alive_interval(Some(Duration::from_secs(15)));

        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_config));
        server_config.transport_config(Arc::new(transport));

        let endpoint = match source {
            SocketSource::Bind(addr) => {
                let ep = Endpoint::server(server_config, addr)
                    .context("failed to bind QUIC endpoint")?;
                info!(addr = %addr, "QUIC relay listening (native socket)");
                ep
            }
            SocketSource::Tachyon(_sock) => {
                unimplemented!("Tachyon Virtual Socket Layer not yet wired")
            }
        };

        Ok(Self {
            endpoint,
            router: Arc::new(Router::new()),
        })
    }

    pub async fn bind(addr: &str) -> Result<Self> {
        let addr: SocketAddr = addr.parse().context("invalid bind address")?;
        Self::new(SocketSource::Bind(addr)).await
    }

    pub fn router(&self) -> Arc<Router> {
        Arc::clone(&self.router)
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

                        let key = sni.clone().unwrap_or_else(|| conn.stable_id().to_string());

                        info!(key = %key, remote = %conn.remote_address(), "client tunnel connected");
                        router.register(conn.clone(), sni).await;

                        // Await the connection closing, then clean up routing state.
                        let reason = conn.closed().await;
                        info!(key = %key, reason = ?reason, "client tunnel closed");
                        router.unregister(&key);
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
    async fn relay_binds_to_loopback() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let relay = Relay::bind("127.0.0.1:0").await;
        assert!(relay.is_ok(), "relay should bind to a random port");
    }
}
