use anyhow::{bail, Result};
use bytes::Bytes;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use quinn::Connection;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info, warn};

/// Maps SNI / DCID / stable-ID → active client QUIC tunnel.
pub struct Router {
    table: DashMap<String, Connection>,
    inverse_table: DashMap<String, String>,
    dcid_to_sni: DashMap<String, String>,
    /// UDP return-path: tunnel key → last seen remote-caller SocketAddr.
    udp_callers: DashMap<(String, u16, u16), SocketAddr>,
    next_udp_session_id: AtomicU16,

    // ── Telemetry counters (updated atomically, logged on tunnel close) ──────
    pub total_ingress_bytes: AtomicU64,
    pub total_egress_bytes: AtomicU64,
    pub total_rejected_datagrams: AtomicU64,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
            inverse_table: DashMap::new(),
            dcid_to_sni: DashMap::new(),
            udp_callers: DashMap::new(),
            next_udp_session_id: AtomicU16::new(0),
            total_ingress_bytes: AtomicU64::new(0),
            total_egress_bytes: AtomicU64::new(0),
            total_rejected_datagrams: AtomicU64::new(0),
        }
    }

    /// Register a new client tunnel keyed by SNI or stable connection ID.
    pub fn register(&self, conn: Connection, sni: Option<String>, is_mtls: bool) -> Result<String> {
        let key = sni.unwrap_or_else(|| conn.stable_id().to_string());
        if let Some(previous) = self.table.get(&key) {
            if !is_mtls {
                bail!("tunnel key is already registered");
            }

            let previous = previous.clone();
            self.inverse_table.remove(&previous.stable_id().to_string());
            previous.close(quinn::VarInt::from_u32(0), b"takeover");
        }

        self.table.insert(key.clone(), conn.clone());
        self.inverse_table
            .insert(conn.stable_id().to_string(), key.clone());
        info!(key = %key, "tunnel registered");
        Ok(key)
    }

    /// Remove a dead tunnel and emit structured metrics for the Tachyon log aggregator.
    pub fn unregister(&self, key: &str) {
        self.unregister_inner(key, None);
    }

    /// Remove a dead tunnel only if the closing connection is still active.
    pub fn unregister_connection(&self, key: &str, stable_id: &str) {
        self.unregister_inner(key, Some(stable_id));
    }

    fn unregister_inner(&self, key: &str, expected_stable_id: Option<&str>) {
        let should_remove = self.table.get(key).is_some_and(|conn| {
            expected_stable_id.is_none_or(|stable_id| conn.stable_id().to_string() == stable_id)
        });
        if !should_remove {
            return;
        }

        if let Some((_key, conn)) = self.table.remove(key) {
            self.inverse_table.remove(&conn.stable_id().to_string());
            self.dcid_to_sni.retain(|_, sni| sni != key);
            self.udp_callers
                .retain(|(tunnel_key, _, _), _| tunnel_key != key);
            let ingress = self.total_ingress_bytes.load(Ordering::Relaxed);
            let egress = self.total_egress_bytes.load(Ordering::Relaxed);
            let rejected = self.total_rejected_datagrams.load(Ordering::Relaxed);
            let active = self.table.len();
            info!(
                key = %key,
                total_ingress_bytes = ingress,
                total_egress_bytes = egress,
                total_rejected_datagrams = rejected,
                remaining_active_tunnels = active,
                "tunnel unregistered"
            );
        }
    }

    pub fn map_dcid_to_sni(&self, dcid: &str, sni: String) {
        self.dcid_to_sni.insert(dcid.to_string(), sni);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // TCP ingress
    // ──────────────────────────────────────────────────────────────────────────

    /// Route an ingress TCP stream into the matching client QUIC tunnel.
    /// Bytes transferred are counted in both directions for telemetry.
    pub async fn route_ingress(
        &self,
        sni: &str,
        ingress_port: u16,
        initial: &[u8],
        stream: TcpStream,
    ) {
        let Some(client_conn) = self.table.get(sni).map(|e| e.clone()) else {
            warn!(sni = %sni, "no tunnel registered for SNI — dropping connection");
            self.total_rejected_datagrams
                .fetch_add(1, Ordering::Relaxed);
            return;
        };

        let (mut quic_send, mut quic_recv) = match client_conn.open_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(sni = %sni, err = %e, "failed to open stream on client tunnel");
                return;
            }
        };

        let port_header = ingress_port.to_be_bytes();
        if let Err(e) = quic_send.write_all(&port_header).await {
            warn!(sni = %sni, err = %e, "failed to write ingress port header to QUIC stream");
            return;
        }

        if let Err(e) = quic_send.write_all(initial).await {
            warn!(sni = %sni, err = %e, "failed to write initial bytes to QUIC stream");
            return;
        }
        self.total_ingress_bytes.fetch_add(
            (port_header.len() + initial.len()) as u64,
            Ordering::Relaxed,
        );

        debug!(sni = %sni, "bridging ingress TCP stream to client tunnel");

        let (mut tcp_read, mut tcp_write) = stream.into_split();
        let (ingress, egress) = tokio::join!(
            tokio::io::copy(&mut tcp_read, &mut quic_send),
            tokio::io::copy(&mut quic_recv, &mut tcp_write),
        );
        self.total_ingress_bytes
            .fetch_add(ingress.unwrap_or(0), Ordering::Relaxed);
        self.total_egress_bytes
            .fetch_add(egress.unwrap_or(0), Ordering::Relaxed);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // UDP ingress
    // ──────────────────────────────────────────────────────────────────────────

    /// Route a raw UDP datagram from a remote caller into the client QUIC tunnel.
    ///
    /// Returns `false` when the tunnel's datagram buffer is saturated (backpressure).
    /// The caller should drop the datagram and increment its own reject counter.
    pub async fn route_udp_ingress(
        &self,
        dcid: &str,
        ingress_port: u16,
        datagram: &[u8],
        caller_addr: SocketAddr,
        _public_socket: Arc<UdpSocket>,
    ) -> bool {
        let tunnel_key = if let Some(tunnel_key) = self.dcid_to_sni.get(dcid) {
            tunnel_key.value().clone()
        } else if let Some(tunnel_key) = self.tunnel_key_for_caller(caller_addr) {
            tunnel_key
        } else {
            warn!(dcid = %dcid, "no tunnel for DCID — dropping UDP datagram");
            self.total_rejected_datagrams
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };

        let Some(client_conn) = self.table.get(&tunnel_key).map(|e| e.clone()) else {
            warn!(dcid = %dcid, tunnel_key = %tunnel_key, "mapped UDP tunnel is not registered");
            self.total_rejected_datagrams
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };

        let Some(session_id) = self.udp_session_id(&tunnel_key, ingress_port, caller_addr) else {
            warn!(
                dcid = %dcid,
                tunnel_key = %tunnel_key,
                "no UDP session ids available for tunnel"
            );
            self.total_rejected_datagrams
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };

        let mut framed = Vec::with_capacity(4 + datagram.len());
        framed.extend_from_slice(&ingress_port.to_be_bytes());
        framed.extend_from_slice(&session_id.to_be_bytes());
        framed.extend_from_slice(datagram);

        match client_conn.send_datagram(Bytes::from(framed)) {
            Ok(()) => {
                self.total_ingress_bytes
                    .fetch_add((4 + datagram.len()) as u64, Ordering::Relaxed);
                debug!(
                    dcid = %dcid,
                    ingress_port,
                    session_id,
                    caller = %caller_addr,
                    bytes = datagram.len(),
                    "UDP datagram forwarded to client"
                );
                true
            }
            Err(e) => {
                // SendDatagramError::Blocked → tunnel send buffer saturated.
                // SendDatagramError::UnsupportedByPeer / TooLarge → protocol issue.
                warn!(dcid = %dcid, err = %e, "datagram send failed (backpressure or error)");
                self.total_rejected_datagrams
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Track bytes sent from client tunnel back to remote caller (egress).
    pub fn record_egress_bytes(&self, n: u64) {
        self.total_egress_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// Look up the UDP return address for a given tunnel key.
    pub fn udp_return_addr(
        &self,
        tunnel_key: &str,
        public_port: u16,
        session_id: u16,
    ) -> Option<SocketAddr> {
        self.udp_callers
            .get(&(tunnel_key.to_string(), public_port, session_id))
            .map(|e| *e)
    }

    pub fn active_tunnels(&self) -> usize {
        self.table.len()
    }

    fn tunnel_key_for_caller(&self, caller_addr: SocketAddr) -> Option<String> {
        self.udp_callers
            .iter()
            .find_map(|entry| (*entry.value() == caller_addr).then(|| entry.key().0.clone()))
    }

    fn udp_session_id(
        &self,
        tunnel_key: &str,
        public_port: u16,
        caller_addr: SocketAddr,
    ) -> Option<u16> {
        if let Some(existing) = self.udp_callers.iter().find_map(|entry| {
            let (entry_tunnel, entry_port, session_id) = entry.key();
            (entry_tunnel == tunnel_key
                && *entry_port == public_port
                && *entry.value() == caller_addr)
                .then_some(*session_id)
        }) {
            return Some(existing);
        }

        for _ in 0..u16::MAX {
            let session_id = self
                .next_udp_session_id
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            if session_id == 0 {
                continue;
            }

            let key = (tunnel_key.to_string(), public_port, session_id);
            match self.udp_callers.entry(key) {
                Entry::Vacant(entry) => {
                    entry.insert(caller_addr);
                    return Some(session_id);
                }
                Entry::Occupied(_) => {}
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};
    use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Endpoint, ServerConfig};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn new_router_is_empty() {
        let router = Router::new();
        assert_eq!(router.active_tunnels(), 0);
        assert_eq!(router.total_ingress_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(router.total_egress_bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn byte_counters_are_independent() {
        let router = Router::new();
        router
            .total_ingress_bytes
            .fetch_add(1024, Ordering::Relaxed);
        router.total_egress_bytes.fetch_add(512, Ordering::Relaxed);
        assert_eq!(router.total_ingress_bytes.load(Ordering::Relaxed), 1024);
        assert_eq!(router.total_egress_bytes.load(Ordering::Relaxed), 512);
    }

    #[tokio::test]
    async fn mtls_takeover_replaces_existing_and_insecure_duplicate_is_rejected() -> Result<()> {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let server = test_server_endpoint()?;
        let router = Router::new();
        let key = "test.local".to_string();

        let (_client_endpoint_1, client_conn_1, server_conn_1) =
            connect_pair(&server, &key).await?;
        router.register(server_conn_1.clone(), Some(key.clone()), true)?;
        assert_eq!(router.active_tunnels(), 1);

        let (_client_endpoint_2, client_conn_2, server_conn_2) =
            connect_pair(&server, &key).await?;
        router.register(server_conn_2.clone(), Some(key.clone()), true)?;

        assert_eq!(router.active_tunnels(), 1);
        assert_eq!(
            router.table.get(&key).expect("active tunnel").stable_id(),
            server_conn_2.stable_id()
        );

        let old_closed = tokio::time::timeout(Duration::from_secs(1), server_conn_1.closed()).await;
        assert!(
            old_closed.is_ok(),
            "takeover should close the old connection"
        );

        router.unregister_connection(&key, &server_conn_1.stable_id().to_string());
        assert_eq!(
            router.active_tunnels(),
            1,
            "stale close must not remove takeover"
        );

        let err = router
            .register(server_conn_2.clone(), Some(key.clone()), false)
            .expect_err("insecure duplicate should be rejected");
        assert!(err.to_string().contains("already registered"));
        assert_eq!(
            router.table.get(&key).expect("active tunnel").stable_id(),
            server_conn_2.stable_id()
        );

        client_conn_1.close(quinn::VarInt::from_u32(0), b"test done");
        client_conn_2.close(quinn::VarInt::from_u32(0), b"test done");
        server.close(quinn::VarInt::from_u32(0), b"test done");
        Ok(())
    }

    fn test_server_endpoint() -> Result<Endpoint> {
        let (cert, key) = crate::tls::self_signed_cert()?;
        let tls_config = crate::tls::server_config(cert, key, None)?;
        let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?;
        Endpoint::server(
            ServerConfig::with_crypto(Arc::new(quic_config)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .context("server endpoint")
    }

    async fn connect_pair(
        server: &Endpoint,
        server_name: &str,
    ) -> Result<(Endpoint, Connection, Connection)> {
        let mut client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        client.set_default_client_config(insecure_client_config()?);

        let connecting = client.connect(server.local_addr()?, server_name)?;
        let incoming = server.accept().await.context("server accept")?;
        let (client_conn, server_conn) = tokio::try_join!(connecting, incoming)?;
        Ok((client, client_conn, server_conn))
    }

    fn insecure_client_config() -> Result<ClientConfig> {
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"wormhole/3".to_vec(), b"h3".to_vec()];

        Ok(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
            crypto,
        )?)))
    }

    #[derive(Debug)]
    struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

    impl SkipServerVerification {
        fn new() -> Arc<Self> {
            Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
        }
    }

    impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}
