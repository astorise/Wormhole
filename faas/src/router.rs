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
            udp_callers: DashMap::new(),
            total_ingress_bytes: AtomicU64::new(0),
            total_egress_bytes: AtomicU64::new(0),
            total_rejected_datagrams: AtomicU64::new(0),
        }
    }

    /// Register a new client tunnel keyed by SNI or stable connection ID.
    pub async fn register(&self, conn: Connection, sni: Option<String>) {
        let key = sni.unwrap_or_else(|| conn.stable_id().to_string());
        info!(key = %key, "tunnel registered");
        self.table.insert(key, conn);
    }

    /// Remove a dead tunnel and emit structured metrics for the Tachyon log aggregator.
    pub fn unregister(&self, key: &str) {
        if self.table.remove(key).is_some() {
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
    pub async fn route_ingress(&self, sni: &str, initial: &[u8], stream: TcpStream) {
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

        if let Err(e) = quic_send.write_all(initial).await {
            warn!(sni = %sni, err = %e, "failed to write initial bytes to QUIC stream");
            return;
        }
        self.total_ingress_bytes
            .fetch_add(initial.len() as u64, Ordering::Relaxed);

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
        datagram: &[u8],
        caller_addr: SocketAddr,
        _public_socket: Arc<UdpSocket>,
    ) -> bool {
        let client_conn = self
            .table
            .get(dcid)
            .map(|e| e.clone())
            .or_else(|| self.table.iter().next().map(|e| e.clone()));

        let Some(client_conn) = client_conn else {
            warn!(dcid = %dcid, "no tunnel for DCID — dropping UDP datagram");
            self.total_rejected_datagrams
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };

        let tunnel_key = self
            .table
            .iter()
            .find(|e| e.value().stable_id() == client_conn.stable_id())
            .map(|e| e.key().clone())
            .unwrap_or_else(|| dcid.to_string());

        self.udp_callers.insert(tunnel_key.clone(), caller_addr);

        match client_conn.send_datagram(Bytes::copy_from_slice(datagram)) {
            Ok(()) => {
                self.total_ingress_bytes
                    .fetch_add(datagram.len() as u64, Ordering::Relaxed);
                debug!(
                    dcid = %dcid,
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
