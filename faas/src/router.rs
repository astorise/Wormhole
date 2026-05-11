use bytes::Bytes;
use dashmap::DashMap;
use quinn::Connection;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info, warn};

/// Maps SNI / DCID / stable-ID → active client QUIC tunnel.
pub struct Router {
    table: DashMap<String, Connection>,
    /// UDP return-path: tunnel key → last seen remote-caller SocketAddr.
    udp_callers: DashMap<String, SocketAddr>,
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
        }
    }

    /// Register a new client tunnel keyed by SNI or stable connection ID.
    pub async fn register(&self, conn: Connection, sni: Option<String>) {
        let key = sni.unwrap_or_else(|| conn.stable_id().to_string());
        info!(key = %key, "tunnel registered");
        self.table.insert(key, conn);
    }

    /// Remove a dead tunnel from the routing table to free memory.
    pub fn unregister(&self, key: &str) {
        if self.table.remove(key).is_some() {
            info!(key = %key, "tunnel unregistered");
        }
        self.udp_callers.remove(key);
    }

    // -------------------------------------------------------------------------
    // TCP ingress
    // -------------------------------------------------------------------------

    /// Route an ingress TCP stream (TLS ClientHello already buffered) into the
    /// matching client QUIC tunnel via bidirectional stream bridging.
    pub async fn route_ingress(&self, sni: &str, initial: &[u8], stream: TcpStream) {
        let Some(client_conn) = self.table.get(sni).map(|e| e.clone()) else {
            warn!(sni = %sni, "no tunnel registered for SNI — dropping connection");
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

        debug!(sni = %sni, "bridging ingress TCP stream to client tunnel");

        let (mut tcp_read, mut tcp_write) = stream.into_split();
        let _ = tokio::join!(
            tokio::io::copy(&mut tcp_read, &mut quic_send),
            tokio::io::copy(&mut quic_recv, &mut tcp_write),
        );
    }

    // -------------------------------------------------------------------------
    // UDP ingress
    // -------------------------------------------------------------------------

    /// Route a raw UDP datagram (carrying QUIC/HTTP-3 payload) from a remote
    /// caller into the client tunnel identified by `dcid`.
    ///
    /// The caller's `SocketAddr` is stored in `udp_callers` keyed by the tunnel
    /// key so that egress datagrams from the client can be returned to the right
    /// endpoint.
    pub async fn route_udp_ingress(
        &self,
        dcid: &str,
        datagram: &[u8],
        caller_addr: SocketAddr,
        _public_socket: Arc<UdpSocket>,
    ) {
        // Look up by DCID first; fall back to any available tunnel for
        // single-tenant deployments where the DCID may not be a registered key.
        let client_conn = self
            .table
            .get(dcid)
            .map(|e| e.clone())
            .or_else(|| self.table.iter().next().map(|e| e.clone()));

        let Some(client_conn) = client_conn else {
            warn!(dcid = %dcid, "no tunnel for DCID — dropping UDP datagram");
            return;
        };

        let tunnel_key = self
            .table
            .iter()
            .find(|e| e.value().stable_id() == client_conn.stable_id())
            .map(|e| e.key().clone())
            .unwrap_or_else(|| dcid.to_string());

        // Record the return path for egress.
        self.udp_callers.insert(tunnel_key.clone(), caller_addr);

        if let Err(e) = client_conn.send_datagram(Bytes::copy_from_slice(datagram)) {
            warn!(dcid = %dcid, err = %e, "failed to send datagram to client tunnel");
        } else {
            debug!(dcid = %dcid, caller = %caller_addr, bytes = datagram.len(), "UDP datagram forwarded to client");
        }
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
    }
}
