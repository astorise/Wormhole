use dashmap::DashMap;
use quinn::Connection;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

/// Maps SNI hostname → active client QUIC connection (the outbound tunnel).
pub struct Router {
    table: DashMap<String, Connection>,
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
        }
    }

    /// Register a new client tunnel keyed by SNI or stable connection ID.
    pub async fn register(&self, conn: Connection, sni: Option<String>) {
        let key = sni.unwrap_or_else(|| conn.stable_id().to_string());
        info!(key = %key, "tunnel registered");
        self.table.insert(key, conn);
    }

    /// Route an ingress TCP stream into the matching client QUIC tunnel.
    ///
    /// `initial` contains the bytes already read (the TLS ClientHello fragment).
    /// They are forwarded to the QUIC send stream first so the client sees the
    /// full, unmodified byte sequence. The rest is then bridged bidirectionally:
    ///   TCP read  → QUIC SendStream
    ///   QUIC RecvStream → TCP write
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

        // Write the already-read ClientHello bytes before bridging.
        if let Err(e) = quic_send.write_all(initial).await {
            warn!(sni = %sni, err = %e, "failed to write initial bytes to QUIC stream");
            return;
        }

        debug!(sni = %sni, "bridging ingress stream to client tunnel");

        // Split TcpStream so we can drive two independent copy directions.
        let (mut tcp_read, mut tcp_write) = stream.into_split();

        // TCP→QUIC and QUIC→TCP run concurrently; stop when either direction ends.
        let _ = tokio::join!(
            tokio::io::copy(&mut tcp_read, &mut quic_send),
            tokio::io::copy(&mut quic_recv, &mut tcp_write),
        );
    }

    /// Remove a dead tunnel from the routing table to free memory.
    pub fn unregister(&self, key: &str) {
        if self.table.remove(key).is_some() {
            info!(key = %key, "tunnel unregistered");
        }
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
