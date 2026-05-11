use anyhow::{Context, Result};
use quinn::{crypto::rustls::QuicServerConfig, Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

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
                unimplemented!("Tachyon Virtual Socket Layer not yet wired for QUIC endpoint")
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

    /// Run the QUIC control-plane.
    ///
    /// `public_socket` is the **shared** UDP socket already bound by `UdpIngress`
    /// (e.g. on port 443).  All datagram egress replies use this socket so they
    /// originate from the same public port that callers sent to, keeping NAT
    /// mappings alive.
    pub async fn run(self, public_socket: Arc<UdpSocket>) -> Result<()> {
        while let Some(incoming) = self.endpoint.accept().await {
            let router = Arc::clone(&self.router);
            let socket = Arc::clone(&public_socket);
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

                        tokio::join!(
                            Self::watch_closed(conn.clone(), key.clone(), Arc::clone(&router)),
                            Self::egress_loop(conn, key, router, socket),
                        );
                    }
                    Err(e) => warn!(err = %e, "connection failed"),
                }
            });
        }
        Ok(())
    }

    async fn watch_closed(conn: quinn::Connection, key: String, router: Arc<Router>) {
        let reason = conn.closed().await;
        info!(key = %key, reason = ?reason, "client tunnel closed");
        router.unregister(&key);
    }

    /// Read datagrams from the client tunnel and forward them to the remote caller
    /// using the shared public UDP socket (same port as ingress — NAT-safe).
    async fn egress_loop(
        conn: quinn::Connection,
        key: String,
        router: Arc<Router>,
        public_socket: Arc<UdpSocket>,
    ) {
        while let Ok(data) = conn.read_datagram().await {
            if let Some(caller_addr) = router.udp_return_addr(&key) {
                if let Err(e) = public_socket.send_to(&data, caller_addr).await {
                    warn!(key = %key, err = %e, "failed to send egress UDP datagram");
                } else {
                    debug!(
                        key = %key,
                        caller = %caller_addr,
                        bytes = data.len(),
                        "UDP egress datagram sent"
                    );
                }
            }
        }
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
