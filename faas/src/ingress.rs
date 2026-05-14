use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{info, warn};

use crate::router::Router;
use crate::tachyon_net;

const PEEK_BUF: usize = 1024;
const MAX_CLIENT_HELLO: usize = 16 * 1024;
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Ingress {
    listener: TcpListener,
    router: Arc<Router>,
    ingress_port: u16,
}

impl Ingress {
    pub async fn new(bind_addr: &str, router: Arc<Router>) -> Result<Self> {
        let addr: SocketAddr = bind_addr.parse().context("invalid ingress bind address")?;
        let listener = tachyon_net::bind_tcp(addr)
            .await
            .context("failed to bind TCP ingress")?;
        let ingress_port = listener
            .local_addr()
            .context("failed to read TCP ingress local address")?
            .port();
        info!(addr = %addr, "TCP ingress listening");
        Ok(Self {
            listener,
            router,
            ingress_port,
        })
    }

    pub async fn run(self) -> Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let router = Arc::clone(&self.router);
            let ingress_port = self.ingress_port;
            tokio::spawn(async move {
                if let Err(e) = handle(stream, peer, router, ingress_port).await {
                    warn!(peer = %peer, err = %e, "ingress error");
                }
            });
        }
    }
}

async fn handle(
    mut stream: TcpStream,
    peer: SocketAddr,
    router: Arc<Router>,
    ingress_port: u16,
) -> Result<()> {
    let buf = read_client_hello_prefix(&mut stream)
        .await
        .context("failed to read ClientHello")?;

    let sni = peek_sni(&buf).unwrap_or_else(|| {
        warn!(peer = %peer, "could not parse SNI from ClientHello");
        peer.ip().to_string()
    });

    info!(peer = %peer, sni = %sni, "routing ingress connection");
    router.route_ingress(&sni, ingress_port, &buf, stream).await;
    Ok(())
}

async fn read_client_hello_prefix(stream: &mut TcpStream) -> Result<Vec<u8>> {
    timeout(CLIENT_HELLO_TIMEOUT, async {
        let mut buf = Vec::with_capacity(PEEK_BUF);
        let mut chunk = [0u8; PEEK_BUF];

        loop {
            let n = stream
                .read(&mut chunk)
                .await
                .context("failed to read ClientHello bytes")?;
            if n == 0 {
                break;
            }

            buf.extend_from_slice(&chunk[..n]);
            if !client_hello_needs_more(&buf) {
                break;
            }

            if buf.len() >= MAX_CLIENT_HELLO {
                anyhow::bail!("ClientHello exceeded {MAX_CLIENT_HELLO} bytes");
            }
        }

        Ok(buf)
    })
    .await
    .context("timed out reading fragmented ClientHello")?
}

fn client_hello_needs_more(buf: &[u8]) -> bool {
    matches!(
        tls_parser::parse_tls_plaintext(buf),
        Err(tls_parser::nom::Err::Incomplete(_))
    )
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
