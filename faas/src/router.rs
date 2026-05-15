use anyhow::{bail, Result};
use bytes::Bytes;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use quinn::Connection;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info, warn};

const UDP_FALLBACK_WINDOW: Duration = Duration::from_secs(5);

struct Tunnel {
    conn: Connection,
    next_udp_session_id: AtomicU16,
}

#[derive(Clone)]
struct CallerTunnel {
    tunnel_key: String,
    caller_addr: SocketAddr,
    last_seen: Instant,
}

/// Maps SNI / DCID / stable-ID → active client QUIC tunnel.
pub struct Router {
    table: DashMap<String, Arc<Tunnel>>,
    inverse_table: DashMap<String, String>,
    dcid_to_sni: DashMap<String, (String, Instant)>,
    /// UDP return-path: tunnel key → last seen remote-caller SocketAddr.
    udp_callers: DashMap<(String, u16, u16), (SocketAddr, Instant)>,
    caller_to_tunnel: DashMap<IpAddr, Vec<CallerTunnel>>,
    caller_to_session: DashMap<(String, SocketAddr), (u16, Instant)>,

    // ── Telemetry counters (updated atomically, logged on tunnel close) ──────
    pub total_ingress_bytes: AtomicU64,
    pub total_egress_bytes: AtomicU64,
    pub total_rejected_datagrams: AtomicU64,
    pub total_session_id_exhausted: AtomicUsize,
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
            caller_to_tunnel: DashMap::new(),
            caller_to_session: DashMap::new(),
            total_ingress_bytes: AtomicU64::new(0),
            total_egress_bytes: AtomicU64::new(0),
            total_rejected_datagrams: AtomicU64::new(0),
            total_session_id_exhausted: AtomicUsize::new(0),
        }
    }

    /// Register a new client tunnel keyed by SNI or stable connection ID.
    pub fn register(&self, conn: Connection, sni: Option<String>, is_mtls: bool) -> Result<String> {
        let key = sni.unwrap_or_else(|| conn.stable_id().to_string());
        if let Some(previous) = self.table.get(&key) {
            if !is_mtls {
                bail!("tunnel key is already registered");
            }

            let previous = Arc::clone(previous.value());
            self.inverse_table
                .remove(&previous.conn.stable_id().to_string());
            self.remove_udp_state_for_tunnel(&key);
            previous.conn.close(quinn::VarInt::from_u32(0), b"takeover");
        }

        let tunnel = Arc::new(Tunnel {
            conn: conn.clone(),
            next_udp_session_id: AtomicU16::new(0),
        });
        self.table.insert(key.clone(), tunnel);
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
            expected_stable_id
                .is_none_or(|stable_id| conn.conn.stable_id().to_string() == stable_id)
        });
        if !should_remove {
            return;
        }

        if let Some((_key, tunnel)) = self.table.remove(key) {
            self.inverse_table
                .remove(&tunnel.conn.stable_id().to_string());
            self.remove_udp_state_for_tunnel(key);
            let ingress = self.total_ingress_bytes.load(Ordering::Relaxed);
            let egress = self.total_egress_bytes.load(Ordering::Relaxed);
            let rejected = self.total_rejected_datagrams.load(Ordering::Relaxed);
            let session_id_exhausted = self.total_session_id_exhausted.load(Ordering::Relaxed);
            let active = self.table.len();
            info!(
                key = %key,
                total_ingress_bytes = ingress,
                total_egress_bytes = egress,
                total_rejected_datagrams = rejected,
                total_session_id_exhausted = session_id_exhausted,
                remaining_active_tunnels = active,
                "tunnel unregistered"
            );
        }
    }

    pub fn map_dcid_to_sni(&self, dcid: &str, sni: String) {
        self.dcid_to_sni
            .insert(dcid.to_string(), (sni, Instant::now()));
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
        let Some(client_conn) = self.table.get(sni).map(|e| e.conn.clone()) else {
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
        let now = Instant::now();
        let tunnel_key = if let Some(mut entry) = self.dcid_to_sni.get_mut(dcid) {
            let tunnel_key = entry.value().0.clone();
            entry.value_mut().1 = now;
            self.record_caller_tunnel(caller_addr, &tunnel_key, now);
            debug!(
                dcid = %dcid,
                tunnel_key = %tunnel_key,
                caller = %caller_addr,
                "routing UDP via DCID match"
            );
            tunnel_key
        } else if let Some(tunnel_key) = self.tunnel_key_for_caller(caller_addr, now) {
            info!(
                dcid = %dcid,
                tunnel_key = %tunnel_key,
                caller = %caller_addr,
                "routing UDP via caller_addr fallback"
            );
            tunnel_key
        } else {
            warn!(dcid = %dcid, "no tunnel for DCID — dropping UDP datagram");
            self.total_rejected_datagrams
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };

        let Some(tunnel) = self.table.get(&tunnel_key).map(|e| Arc::clone(e.value())) else {
            warn!(dcid = %dcid, tunnel_key = %tunnel_key, "mapped UDP tunnel is not registered");
            self.total_rejected_datagrams
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };

        let Some(session_id) =
            self.udp_session_id(&tunnel_key, ingress_port, caller_addr, &tunnel, now)
        else {
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

        match tunnel.conn.send_datagram(Bytes::from(framed)) {
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
        let now = Instant::now();
        let mut caller = None;
        if let Some(mut entry) =
            self.udp_callers
                .get_mut(&(tunnel_key.to_string(), public_port, session_id))
        {
            entry.value_mut().1 = now;
            caller = Some(entry.value().0);
        }

        let caller = caller?;
        if let Some(mut entry) = self
            .caller_to_session
            .get_mut(&(tunnel_key.to_string(), caller))
        {
            entry.value_mut().1 = now;
        }
        Some(caller)
    }

    pub fn active_tunnels(&self) -> usize {
        self.table.len()
    }

    pub fn gc_udp_sessions(&self, max_idle: Duration) {
        let now = Instant::now();
        self.dcid_to_sni
            .retain(|_, (_, last_seen)| now.duration_since(*last_seen) <= max_idle);
        self.udp_callers
            .retain(|_, (_, last_seen)| now.duration_since(*last_seen) <= max_idle);
        self.caller_to_tunnel.retain(|_, mappings| {
            mappings.retain(|mapping| now.duration_since(mapping.last_seen) <= max_idle);
            !mappings.is_empty()
        });
        self.caller_to_session
            .retain(|_, (_, last_seen)| now.duration_since(*last_seen) <= max_idle);
    }

    fn tunnel_key_for_caller(&self, caller_addr: SocketAddr, now: Instant) -> Option<String> {
        let ip = caller_addr.ip();
        let mut entry = self.caller_to_tunnel.get_mut(&ip)?;
        let (tunnel_key, should_remove) = {
            let mappings = entry.value_mut();
            mappings.retain(|mapping| {
                now.saturating_duration_since(mapping.last_seen) <= UDP_FALLBACK_WINDOW
            });
            let tunnel_key = mappings
                .iter()
                .max_by(|a, b| {
                    a.last_seen
                        .cmp(&b.last_seen)
                        .then_with(|| a.tunnel_key.cmp(&b.tunnel_key))
                        .then_with(|| a.caller_addr.cmp(&b.caller_addr))
                })
                .map(|mapping| mapping.tunnel_key.clone());
            (tunnel_key, mappings.is_empty())
        };
        drop(entry);

        if should_remove {
            self.caller_to_tunnel.remove(&ip);
        }

        tunnel_key
    }

    fn udp_session_id(
        &self,
        tunnel_key: &str,
        public_port: u16,
        caller_addr: SocketAddr,
        tunnel: &Tunnel,
        now: Instant,
    ) -> Option<u16> {
        let session_key = (tunnel_key.to_string(), caller_addr);
        if let Some(mut existing) = self.caller_to_session.get_mut(&session_key) {
            let session_id = existing.value().0;
            existing.value_mut().1 = now;
            self.udp_callers.insert(
                (tunnel_key.to_string(), public_port, session_id),
                (caller_addr, now),
            );
            return Some(session_id);
        }

        for _ in 0..u16::MAX {
            let session_id = tunnel
                .next_udp_session_id
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            if session_id == 0 {
                continue;
            }

            let key = (tunnel_key.to_string(), public_port, session_id);
            match self.udp_callers.entry(key) {
                Entry::Vacant(entry) => {
                    entry.insert((caller_addr, now));
                    self.caller_to_session
                        .insert(session_key, (session_id, now));
                    return Some(session_id);
                }
                Entry::Occupied(_) => {}
            }
        }

        self.total_session_id_exhausted
            .fetch_add(1, Ordering::Relaxed);
        None
    }

    fn record_caller_tunnel(&self, caller_addr: SocketAddr, tunnel_key: &str, now: Instant) {
        let ip = caller_addr.ip();
        let mapping = CallerTunnel {
            tunnel_key: tunnel_key.to_string(),
            caller_addr,
            last_seen: now,
        };

        match self.caller_to_tunnel.entry(ip) {
            Entry::Vacant(entry) => {
                entry.insert(vec![mapping]);
            }
            Entry::Occupied(mut entry) => {
                let mappings = entry.get_mut();
                if let Some(existing) = mappings
                    .iter_mut()
                    .find(|candidate| candidate.tunnel_key == tunnel_key)
                {
                    existing.caller_addr = caller_addr;
                    existing.last_seen = now;
                } else {
                    mappings.push(mapping);
                }
            }
        }
    }

    fn remove_udp_state_for_tunnel(&self, key: &str) {
        self.dcid_to_sni
            .retain(|_, (tunnel_key, _)| tunnel_key != key);
        self.udp_callers
            .retain(|(tunnel_key, _, _), _| tunnel_key != key);
        self.caller_to_tunnel.retain(|_, mappings| {
            mappings.retain(|mapping| mapping.tunnel_key != key);
            !mappings.is_empty()
        });
        self.caller_to_session
            .retain(|(tunnel_key, _), _| tunnel_key != key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};
    use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Endpoint, ServerConfig};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    #[test]
    fn new_router_is_empty() {
        let router = Router::new();
        assert_eq!(router.active_tunnels(), 0);
        assert_eq!(router.total_ingress_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(router.total_egress_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(router.total_rejected_datagrams.load(Ordering::Relaxed), 0);
        assert_eq!(router.total_session_id_exhausted.load(Ordering::Relaxed), 0);
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

    #[test]
    fn caller_fallback_is_time_windowed() {
        let router = Router::new();
        let caller: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let now = Instant::now();

        router.record_caller_tunnel(caller, "test.local", now - Duration::from_secs(6));
        assert_eq!(router.tunnel_key_for_caller(caller, now), None);

        router.record_caller_tunnel(caller, "test.local", now);
        assert_eq!(
            router.tunnel_key_for_caller(caller, now),
            Some("test.local".to_string())
        );
    }

    #[test]
    fn caller_fallback_chooses_most_recent_tunnel_for_shared_ip() {
        let router = Router::new();
        let now = Instant::now();
        let older_caller: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let newer_caller: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        let fallback_caller: SocketAddr = "127.0.0.1:60000".parse().unwrap();

        router.record_caller_tunnel(older_caller, "older.local", now - Duration::from_secs(1));
        router.record_caller_tunnel(newer_caller, "newer.local", now);

        assert_eq!(
            router.tunnel_key_for_caller(fallback_caller, now),
            Some("newer.local".to_string())
        );
    }

    #[test]
    fn gc_udp_sessions_sweeps_idle_indexes() {
        let router = Router::new();
        let now = Instant::now();
        let old = now - Duration::from_secs(601);
        let fresh = now - Duration::from_secs(60);
        let old_caller: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let fresh_caller: SocketAddr = "127.0.0.2:50001".parse().unwrap();

        router
            .dcid_to_sni
            .insert("old-dcid".to_string(), ("old.local".to_string(), old));
        router
            .dcid_to_sni
            .insert("fresh-dcid".to_string(), ("fresh.local".to_string(), fresh));
        router
            .udp_callers
            .insert(("old.local".to_string(), 443, 1), (old_caller, old));
        router
            .udp_callers
            .insert(("fresh.local".to_string(), 443, 1), (fresh_caller, fresh));
        router.record_caller_tunnel(old_caller, "old.local", old);
        router.record_caller_tunnel(fresh_caller, "fresh.local", fresh);
        router
            .caller_to_session
            .insert(("old.local".to_string(), old_caller), (1, old));
        router
            .caller_to_session
            .insert(("fresh.local".to_string(), fresh_caller), (1, fresh));

        router.gc_udp_sessions(Duration::from_secs(600));

        assert!(!router.dcid_to_sni.contains_key("old-dcid"));
        assert!(router.dcid_to_sni.contains_key("fresh-dcid"));
        assert!(!router
            .udp_callers
            .contains_key(&("old.local".to_string(), 443, 1)));
        assert!(router
            .udp_callers
            .contains_key(&("fresh.local".to_string(), 443, 1)));
        assert!(!router.caller_to_tunnel.contains_key(&old_caller.ip()));
        assert!(router.caller_to_tunnel.contains_key(&fresh_caller.ip()));
        assert!(!router
            .caller_to_session
            .contains_key(&("old.local".to_string(), old_caller)));
        assert!(router
            .caller_to_session
            .contains_key(&("fresh.local".to_string(), fresh_caller)));
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
            router
                .table
                .get(&key)
                .expect("active tunnel")
                .conn
                .stable_id(),
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
            router
                .table
                .get(&key)
                .expect("active tunnel")
                .conn
                .stable_id(),
            server_conn_2.stable_id()
        );

        client_conn_1.close(quinn::VarInt::from_u32(0), b"test done");
        client_conn_2.close(quinn::VarInt::from_u32(0), b"test done");
        server.close(quinn::VarInt::from_u32(0), b"test done");
        Ok(())
    }

    #[tokio::test]
    async fn udp_session_ids_are_per_tunnel_and_indexed_by_caller() -> Result<()> {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let server = test_server_endpoint()?;
        let router = Router::new();
        let key = "test.local".to_string();
        let (_client_endpoint, client_conn, server_conn) = connect_pair(&server, &key).await?;
        router.register(server_conn, Some(key.clone()), true)?;

        let tunnel = Arc::clone(router.table.get(&key).expect("registered tunnel").value());
        let now = Instant::now();
        let caller_a: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let caller_b: SocketAddr = "127.0.0.1:50001".parse().unwrap();

        let first = router
            .udp_session_id(&key, 443, caller_a, &tunnel, now)
            .expect("first session");
        let reused = router
            .udp_session_id(&key, 443, caller_a, &tunnel, now)
            .expect("reused session");
        let second = router
            .udp_session_id(&key, 443, caller_b, &tunnel, now)
            .expect("second session");

        assert_eq!(first, reused);
        assert_ne!(first, second);
        assert_eq!(
            router
                .caller_to_session
                .get(&(key.clone(), caller_a))
                .expect("caller index")
                .value()
                .0,
            first
        );
        assert_eq!(
            router
                .udp_callers
                .get(&(key.clone(), 443, first))
                .expect("return path")
                .value()
                .0,
            caller_a
        );

        client_conn.close(quinn::VarInt::from_u32(0), b"test done");
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
