use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info};

use crate::router::Router;
use crate::tachyon_net;

const MAX_DATAGRAM: usize = 1500;

pub struct UdpIngress {
    socket: Arc<UdpSocket>,
    router: Arc<Router>,
    ingress_port: u16,
}

impl UdpIngress {
    /// Bind a UDP socket via `tachyon_net` (OS socket on native, pre-opened FD
    /// on `wasm32-wasi`) and return the ingress handler.
    pub async fn bind(bind_addr: &str, router: Arc<Router>) -> Result<Self> {
        let addr: SocketAddr = bind_addr.parse().context("invalid UDP ingress address")?;
        let socket = tachyon_net::bind_udp(addr)
            .await
            .context("failed to bind UDP ingress socket")?;
        let ingress_port = socket
            .local_addr()
            .context("failed to read UDP ingress local address")?
            .port();
        info!(addr = %addr, "UDP ingress listening");
        Ok(Self {
            socket: Arc::new(socket),
            router,
            ingress_port,
        })
    }

    /// Expose the underlying socket so `relay.run()` can reuse it for egress.
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    pub async fn run(self) -> Result<()> {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let (n, caller_addr) = self
                .socket
                .recv_from(&mut buf)
                .await
                .context("UDP recv_from failed")?;

            let datagram = &buf[..n];

            let dcid = match peek_quic_dcid(datagram) {
                Some(id) => id,
                None => {
                    debug!(caller = %caller_addr, "could not extract DCID — dropping datagram");
                    continue;
                }
            };

            debug!(caller = %caller_addr, dcid = %dcid, bytes = n, "UDP datagram received");

            let forwarded = self
                .router
                .route_udp_ingress(
                    &dcid,
                    self.ingress_port,
                    datagram,
                    caller_addr,
                    Arc::clone(&self.socket),
                )
                .await;
            if !forwarded {
                debug!(dcid = %dcid, "UDP datagram dropped (backpressure)");
            }
        }
    }
}

/// Extract the QUIC Destination Connection ID from the first bytes of a raw
/// UDP datagram containing a QUIC packet.
///
/// QUIC Long Header: byte 0 high-bit set; DCID length at byte 5; DCID at 6..
/// QUIC Short Header: byte 0 high-bit clear; 8-byte DCID assumed at bytes 1..9.
pub fn peek_quic_dcid(buf: &[u8]) -> Option<String> {
    if buf.is_empty() {
        return None;
    }

    let long_header = (buf[0] & 0x80) != 0;

    if long_header {
        if buf.len() < 7 {
            return None;
        }
        let dcid_len = buf[5] as usize;
        if dcid_len == 0 || buf.len() < 6 + dcid_len {
            return None;
        }
        Some(hex(&buf[6..6 + dcid_len]))
    } else {
        if buf.len() < 9 {
            return None;
        }
        Some(hex(&buf[1..9]))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long_header_packet(dcid: &[u8]) -> Vec<u8> {
        let mut p = vec![0xC0u8];
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        p.push(dcid.len() as u8);
        p.extend_from_slice(dcid);
        p.extend_from_slice(&[0x00, 0xAA, 0xBB]);
        p
    }

    fn short_header_packet(dcid: &[u8; 8]) -> Vec<u8> {
        let mut p = vec![0x40u8];
        p.extend_from_slice(dcid);
        p.extend_from_slice(&[0xDE, 0xAD]);
        p
    }

    #[test]
    fn extracts_dcid_from_long_header() {
        let dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let pkt = long_header_packet(&dcid);
        assert_eq!(peek_quic_dcid(&pkt), Some("0102030405060708".to_string()));
    }

    #[test]
    fn extracts_dcid_from_short_header() {
        let dcid = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        let pkt = short_header_packet(&dcid);
        assert_eq!(peek_quic_dcid(&pkt), Some("aabbccddeeff1122".to_string()));
    }

    #[test]
    fn returns_none_for_empty_packet() {
        assert_eq!(peek_quic_dcid(&[]), None);
    }

    #[test]
    fn returns_none_for_short_packet() {
        assert_eq!(peek_quic_dcid(&[0x40, 0x01]), None);
    }

    #[test]
    fn returns_none_for_zero_dcid_length_in_long_header() {
        let pkt = vec![0xC0, 0, 0, 0, 1, 0, 0xAA];
        assert_eq!(peek_quic_dcid(&pkt), None);
    }
}
