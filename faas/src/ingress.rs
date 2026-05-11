use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::router::Router;
use crate::tachyon_net;

const PEEK_BUF: usize = 1024;

pub struct Ingress {
    listener: TcpListener,
    router: Arc<Router>,
}

impl Ingress {
    pub async fn new(bind_addr: &str, router: Arc<Router>) -> Result<Self> {
        let addr: SocketAddr = bind_addr.parse().context("invalid ingress bind address")?;
        let listener = tachyon_net::bind_tcp(addr)
            .await
            .context("failed to bind TCP ingress")?;
        info!(addr = %addr, "TCP ingress listening");
        Ok(Self { listener, router })
    }

    pub async fn run(self) -> Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let router = Arc::clone(&self.router);
            tokio::spawn(async move {
                if let Err(e) = handle(stream, peer, router).await {
                    warn!(peer = %peer, err = %e, "ingress error");
                }
            });
        }
    }
}

async fn handle(mut stream: TcpStream, peer: SocketAddr, router: Arc<Router>) -> Result<()> {
    let mut buf = vec![0u8; PEEK_BUF];
    let n = stream
        .read(&mut buf)
        .await
        .context("failed to read ClientHello")?;
    buf.truncate(n);

    let sni = peek_sni(&buf).unwrap_or_else(|| {
        warn!(peer = %peer, "could not parse SNI from ClientHello");
        peer.ip().to_string()
    });

    info!(peer = %peer, sni = %sni, "routing ingress connection");
    router.route_ingress(&sni, &buf, stream).await;
    Ok(())
}

pub fn peek_sni(buf: &[u8]) -> Option<String> {
    use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake};

    let (_, tls) = parse_tls_plaintext(buf).ok()?;
    let msg = tls.msg.into_iter().next()?;

    let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(hello)) = msg else {
        return None;
    };

    let extensions = hello.ext?;
    tls_parser::parse_tls_extensions(extensions)
        .ok()?
        .1
        .into_iter()
        .find_map(|ext| {
            if let tls_parser::TlsExtension::SNI(list) = ext {
                list.first()
                    .map(|(_, name)| String::from_utf8_lossy(name).into_owned())
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_sni_returns_none_for_garbage() {
        assert!(peek_sni(b"not a tls packet").is_none());
    }

    #[test]
    fn peek_sni_returns_none_for_empty() {
        assert!(peek_sni(b"").is_none());
    }
}
