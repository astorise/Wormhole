use anyhow::{bail, Result};
use bytes::Bytes;
use dashmap::DashMap;
use quinn::Connection;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info, warn};

/// Maps SNI / DCID / stable-ID → active client QUIC tunnel.
pub struct Router {
    table: DashMap<String, Connection>,
    inverse_table: DashMap<String, String>,
    /// UDP return-path: tunnel key → last seen remote-caller SocketAddr.
    udp_callers: DashMap<String, SocketAddr>,

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
            udp_callers: DashMap::new(),
            total_ingress_bytes: AtomicU64::new(0),
            total_egress_bytes: AtomicU64::new(0),
            total_rejected_datagrams: AtomicU64::new(0),
        }
    }

    /// Register a new client tunnel keyed by SNI or stable connection ID.
    pub fn register(
        &self,
        conn: Connection,
        sni: Option<String>,
        reject_duplicate_sni: bool,
    ) -> Result<String> {
        let key = sni.unwrap_or_else(|| conn.stable_id().to_string());
        if reject_duplicate_sni && self.table.contains_key(&key) {
            bail!("tunnel key is already registered");
        }

        if let Some(old_conn) = self.table.insert(key.clone(), conn.clone()) {
            self.inverse_table.remove(&old_conn.stable_id().to_string());
        }
        self.inverse_table
            .insert(conn.stable_id().to_string(), key.clone());
        info!(key = %key, "tunnel registered");
        Ok(key)
    }

    /// Remove a dead tunnel and emit structured metrics for the Tachyon log aggregator.
    pub fn unregister(&self, key: &str) {
        if let Some((_key, conn)) = self.table.remove(key) {
            self.inverse_table.remove(&conn.stable_id().to_string());
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
        self.udp_callers.remove(key);
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
        let Some(client_conn) = self.table.get(dcid).map(|e| e.clone()) else {
            warn!(dcid = %dcid, "no tunnel for DCID — dropping UDP datagram");
            self.total_rejected_datagrams
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };

        let stable_id = client_conn.stable_id().to_string();
        let tunnel_key = self
            .inverse_table
            .get(&stable_id)
            .map(|e| e.value().clone())
            .unwrap_or_else(|| dcid.to_string());

        self.udp_callers.insert(tunnel_key.clone(), caller_addr);

        let mut framed = Vec::with_capacity(2 + datagram.len());
        framed.extend_from_slice(&ingress_port.to_be_bytes());
        framed.extend_from_slice(datagram);

        match client_conn.send_datagram(Bytes::from(framed)) {
            Ok(()) => {
                self.total_ingress_bytes
                    .fetch_add((2 + datagram.len()) as u64, Ordering::Relaxed);
                debug!(
                    dcid = %dcid,
                    ingress_port,
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
    pub fn udp_return_addr(&self, tunnel_key: &str) -> Option<SocketAddr> {
        self.udp_callers.get(tunnel_key).map(|e| *e)
    }

    pub fn active_tunnels(&self) -> usize {
        self.table.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
