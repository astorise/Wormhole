use dashmap::DashMap;
use quinn::Connection;
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tracing::{debug, info, warn};

/// Maps SNI hostname → active client QUIC connection (the outbound tunnel).
pub struct Router {
    table: DashMap<String, Connection>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
        }
    }

    /// Register a new client tunnel. If the client presented an SNI, index by it;
    /// otherwise use the stable connection ID as a fallback key.
    pub async fn register(&self, conn: Connection, sni: Option<String>) {
        let key = sni.unwrap_or_else(|| conn.stable_id().to_string());
        info!(key = %key, "tunnel registered");
        self.table.insert(key, conn);
    }

    /// Route an incoming remote caller's bi-directional stream to the correct
    /// client tunnel identified by `sni`. Streams are bridged without touching
    /// the encrypted payload — pure pass-through at L4.
    pub async fn route(
        self: &Arc<Self>,
        sni: &str,
        mut incoming: (impl tokio::io::AsyncRead + Unpin, impl tokio::io::AsyncWrite + Unpin),
    ) {
        let Some(client_conn) = self.table.get(sni).map(|e| e.clone()) else {
            warn!(sni = %sni, "no tunnel registered for SNI");
            return;
        };

        match client_conn.open_bi().await {
            Ok((mut send, mut recv)) => {
                debug!(sni = %sni, "bridging stream");
                let _ = copy_bidirectional(&mut incoming.0, &mut send).await;
                drop(recv);
            }
            Err(e) => warn!(sni = %sni, err = %e, "failed to open stream to client"),
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
