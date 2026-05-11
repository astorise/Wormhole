use anyhow::{Context, Result};
use quinn::{crypto::rustls::QuicServerConfig, Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

use crate::router::Router;
use crate::tls;

/// Abstraction over the UDP socket that backs the QUIC endpoint.
/// In production on Tachyon-Mesh the socket is injected by the Virtual Socket
/// Layer (accelerator-host.wit). In tests/native we bind a standard OS socket.
pub enum SocketSource {
    /// Bind a new OS UDP socket at the given address.
    Bind(SocketAddr),
    /// Use a socket already provided by the Tachyon runtime.
    /// The inner value is an opaque handle; the real type would be the WIT
    /// binding generated from accelerator-host.wit.
    Tachyon(TachyonSocket),
}

/// Placeholder for the Tachyon Virtual Socket Layer binding.
/// Replaced by the generated WIT type once the runtime crate is available.
pub struct TachyonSocket;

pub struct Relay {
    endpoint: Endpoint,
    router: Arc<Router>,
}

impl Relay {
    /// Create a relay using the given socket source.
    pub async fn new(source: SocketSource) -> Result<Self> {
        let (cert, key) = tls::self_signed_cert()?;
        let tls_config = tls::server_config(cert, key)?;
        let quic_config =
            QuicServerConfig::try_from(tls_config).context("invalid QUIC TLS config")?;
        let server_config = ServerConfig::with_crypto(Arc::new(quic_config));

        let endpoint = match source {
            SocketSource::Bind(addr) => {
                let ep = Endpoint::server(server_config, addr)
                    .context("failed to bind QUIC endpoint")?;
                info!(addr = %addr, "QUIC relay listening (native socket)");
                ep
            }
            SocketSource::Tachyon(_sock) => {
                // TODO: construct Endpoint from Tachyon virtual UDP socket once
                // the WIT bindings are generated.
                // let ep = Endpoint::new_with_abstract_socket(...);
                unimplemented!("Tachyon Virtual Socket Layer not yet wired")
            }
        };

        Ok(Self {
            endpoint,
            router: Arc::new(Router::new()),
        })
    }

    /// Convenience constructor for native/test use.
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

                        info!(sni = ?sni, remote = %conn.remote_address(), "client tunnel connected");
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
    async fn relay_binds_to_loopback() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok(); // ok() because another test in the same process may have already installed it
        let relay = Relay::bind("127.0.0.1:0").await;
        assert!(relay.is_ok(), "relay should bind to a random port");
    }
}
