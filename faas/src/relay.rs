use anyhow::{Context, Result};
use quinn::{crypto::rustls::QuicServerConfig, Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

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
    /// mTLS enforced: client certs required, SAN used as tunnel key.
    mtls: bool,
    /// Explicit unsecure opt-in: no client auth, SNI used as key, warning emitted.
    allow_insecure: bool,
}

impl Relay {
    pub async fn new(
        source: SocketSource,
        ca_cert: Option<rustls::pki_types::CertificateDer<'static>>,
        allow_insecure: bool,
    ) -> Result<Self> {
        let mtls = ca_cert.is_some();

        let (cert, key) = tls::self_signed_cert()?;
        let tls_config = tls::server_config(cert, key, ca_cert)?;
        let quic_config =
            QuicServerConfig::try_from(tls_config).context("invalid QUIC TLS config")?;

        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .expect("valid idle timeout"),
        ));
        transport.keep_alive_interval(Some(Duration::from_secs(15)));

        // QoS: prevent resource exhaustion under heavy LLM load.
        transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(100));
        transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
        // 1 MB per-stream receive window; 8 MB connection-level receive window.
        transport.stream_receive_window(quinn::VarInt::from_u64(1 << 20).expect("valid window"));
        transport.receive_window(quinn::VarInt::from_u64(1 << 23).expect("valid window"));
        // 64 KB datagram buffer (ingress); 128 KB datagram send buffer.
        transport.datagram_receive_buffer_size(Some(1 << 16));
        transport.datagram_send_buffer_size(1 << 17);

        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_config));
        server_config.transport_config(Arc::new(transport));

        let endpoint = match source {
            SocketSource::Bind(addr) => {
                let ep = Endpoint::server(server_config, addr)
                    .context("failed to bind QUIC endpoint")?;
                if allow_insecure {
                    error!(
                        addr = %addr,
                        "⚠ RELAY RUNNING IN UNSECURE MODE — no client authentication, \
                         SNI spoofing possible. Set WORMHOLE_CA_CERT to enable mTLS."
                    );
                } else {
                    info!(addr = %addr, mtls, "QUIC relay listening");
                }
                ep
            }
            SocketSource::Tachyon(_sock) => {
                unimplemented!("Tachyon Virtual Socket Layer not yet wired for QUIC endpoint")
            }
        };

        Ok(Self {
            endpoint,
            router: Arc::new(Router::new()),
            mtls,
            allow_insecure,
        })
    }

    /// Convenience constructor — no mTLS (tests / local dev, no warning).
    pub async fn bind(addr: &str) -> Result<Self> {
        let addr: SocketAddr = addr.parse().context("invalid bind address")?;
        Self::new(SocketSource::Bind(addr), None, false).await
    }

    /// Unsecure mode: no client auth, but emits a prominent warning on startup.
    pub async fn bind_unsecure(addr: &str) -> Result<Self> {
        let addr: SocketAddr = addr.parse().context("invalid bind address")?;
        Self::new(SocketSource::Bind(addr), None, true).await
    }

    /// mTLS enforced: client certs must chain to the provided CA.
    pub async fn bind_with_mtls(
        addr: &str,
        ca_cert: rustls::pki_types::CertificateDer<'static>,
    ) -> Result<Self> {
        let addr: SocketAddr = addr.parse().context("invalid bind address")?;
        Self::new(SocketSource::Bind(addr), Some(ca_cert), false).await
    }

    pub fn router(&self) -> Arc<Router> {
        Arc::clone(&self.router)
    }

    /// Return a cloned handle to the underlying QUIC endpoint so callers can
    /// trigger a graceful shutdown (`endpoint.close(...)`) without consuming `self`.
    pub fn endpoint_handle(&self) -> quinn::Endpoint {
        self.endpoint.clone()
    }

    pub async fn run(self, public_socket: Arc<UdpSocket>) -> Result<()> {
        let mtls = self.mtls;
        let allow_insecure = self.allow_insecure;
        while let Some(incoming) = self.endpoint.accept().await {
            let router = Arc::clone(&self.router);
            let socket = Arc::clone(&public_socket);
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        let key = if mtls {
                            match extract_client_san(&conn) {
                                Some(san) => san,
                                None => {
                                    warn!(
                                        remote = %conn.remote_address(),
                                        "mTLS: no valid SAN in client cert — rejecting"
                                    );
                                    conn.close(
                                        quinn::VarInt::from_u32(1),
                                        b"missing client certificate SAN",
                                    );
                                    return;
                                }
                            }
                        } else {
                            // Unsecure / dev mode: trust the unverified SNI.
                            // In allow_insecure mode this is explicitly acknowledged.
                            let key = conn
                                .handshake_data()
                                .and_then(|d| {
                                    d.downcast::<quinn::crypto::rustls::HandshakeData>().ok()
                                })
                                .and_then(|hd| hd.server_name.clone())
                                .unwrap_or_else(|| conn.stable_id().to_string());
                            if allow_insecure {
                                warn!(
                                    key = %key,
                                    remote = %conn.remote_address(),
                                    "accepting unauthenticated tunnel (unsecure mode)"
                                );
                            }
                            key
                        };

                        info!(key = %key, remote = %conn.remote_address(), "client tunnel connected");
                        if let Err(e) =
                            router.register(conn.clone(), Some(key.clone()), allow_insecure)
                        {
                            warn!(
                                key = %key,
                                remote = %conn.remote_address(),
                                err = %e,
                                "rejecting duplicate unauthenticated tunnel"
                            );
                            conn.close(
                                quinn::VarInt::from_u32(1),
                                b"duplicate tunnel key in unsecure mode",
                            );
                            return;
                        }

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

    async fn egress_loop(
        conn: quinn::Connection,
        key: String,
        router: Arc<Router>,
        public_socket: Arc<UdpSocket>,
    ) {
        while let Ok(data) = conn.read_datagram().await {
            if let Some(caller_addr) = router.udp_return_addr(&key) {
                match public_socket.send_to(&data, caller_addr).await {
                    Ok(n) => {
                        router.record_egress_bytes(n as u64);
                        debug!(
                            key = %key,
                            caller = %caller_addr,
                            bytes = n,
                            "UDP egress datagram sent"
                        );
                    }
                    Err(e) => warn!(key = %key, err = %e, "failed to send egress UDP datagram"),
                }
            }
        }
    }
}

/// Extract the first DNS Subject Alternative Name from the verified peer
/// certificate chain.  Falls back to the Common Name if no SAN is present.
/// Returns `None` when no certificate was presented (mTLS not enforced on the
/// peer, or peer_identity() downcast failed).
fn extract_client_san(conn: &quinn::Connection) -> Option<String> {
    let certs = conn
        .peer_identity()
        .and_then(|id| {
            id.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .map(|v| *v)?;

    let end_entity = certs.first()?;
    extract_san_from_der(end_entity.as_ref())
}

fn extract_san_from_der(cert_der: &[u8]) -> Option<String> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;

    // Prefer the first DNS SAN.
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::DNSName(dns) = name {
                    return Some(dns.to_string());
                }
            }
        }
    }

    // Fallback: Common Name — collect to owned before `cert` is dropped.
    let mut cn = None;
    for attr in cert.subject().iter_common_name() {
        if let Ok(s) = attr.as_str() {
            cn = Some(s.to_owned());
            break;
        }
    }
    cn
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without a CA cert, mTLS is disabled.  The relay binds and accepts
    /// connections without requiring client certificates.
    #[tokio::test]
    async fn relay_binds_without_mtls() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let relay = Relay::bind("127.0.0.1:0").await;
        assert!(relay.is_ok(), "relay should bind without mTLS");
        assert!(!relay.unwrap().mtls, "mtls flag must be false");
    }

    #[test]
    fn extract_san_returns_none_for_garbage() {
        assert!(extract_san_from_der(b"not a cert").is_none());
    }

    #[test]
    fn extract_san_returns_none_for_empty() {
        assert!(extract_san_from_der(b"").is_none());
    }
}
