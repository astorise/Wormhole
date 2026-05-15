use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit};
use aes::Aes128;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Nonce};
use anyhow::{Context, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info};

use crate::router::Router;
use crate::tachyon_net;

const MAX_DATAGRAM: usize = 1500;
const QUIC_V1: u32 = 0x0000_0001;
const QUIC_V1_INITIAL_SALT: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

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

            if let Some(sni) = peek_quic_initial_sni(datagram) {
                self.router.map_dcid_to_sni(&dcid, sni);
            }

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

pub fn peek_quic_initial_sni(buf: &[u8]) -> Option<String> {
    let parts = parse_initial_parts(buf)?;
    let secrets = initial_secrets(&parts.dcid)?;
    let mut packet = buf[..parts.packet_end].to_vec();

    let sample_offset = parts.pn_offset.checked_add(4)?;
    let sample = packet.get(sample_offset..sample_offset + 16)?;
    let mask = aes_mask(&secrets.hp, sample)?;

    packet[0] ^= mask[0] & 0x0f;
    let pn_len = ((packet[0] & 0x03) + 1) as usize;
    if parts.length < pn_len || parts.pn_offset + pn_len > parts.packet_end {
        return None;
    }
    for i in 0..pn_len {
        packet[parts.pn_offset + i] ^= mask[i + 1];
    }

    let packet_number = packet[parts.pn_offset..parts.pn_offset + pn_len]
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    let header_len = parts.pn_offset + pn_len;
    let payload_end = parts.pn_offset + parts.length;
    let aad = packet[..header_len].to_vec();
    let mut payload = packet[header_len..payload_end].to_vec();

    let nonce = initial_nonce(&secrets.iv, packet_number);
    let cipher = Aes128Gcm::new_from_slice(&secrets.key).ok()?;
    cipher
        .decrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut payload)
        .ok()?;

    let crypto = first_crypto_frame(&payload)?;
    sni_from_tls_handshake(&crypto)
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
        // QUIC short headers do not encode the DCID length. Wormhole assumes
        // an 8-byte DCID here and relies on Tachyon Gateway L4 stickiness to
        // keep short-header traffic pinned to the worker that saw the Initial.
        if buf.len() < 9 {
            return None;
        }
        Some(hex(&buf[1..9]))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct InitialParts {
    dcid: Vec<u8>,
    pn_offset: usize,
    length: usize,
    packet_end: usize,
}

struct InitialSecrets {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn parse_initial_parts(buf: &[u8]) -> Option<InitialParts> {
    if buf.len() < 7 || (buf[0] & 0x80) == 0 {
        return None;
    }

    let version = u32::from_be_bytes(buf.get(1..5)?.try_into().ok()?);
    if version != QUIC_V1 || ((buf[0] & 0x30) >> 4) != 0 {
        return None;
    }

    let mut offset = 5;
    let dcid_len = *buf.get(offset)? as usize;
    offset += 1;
    let dcid = buf.get(offset..offset + dcid_len)?.to_vec();
    offset += dcid_len;

    let scid_len = *buf.get(offset)? as usize;
    offset += 1 + scid_len;

    let (token_len, token_len_bytes) = read_varint(buf.get(offset..)?)?;
    offset += token_len_bytes + token_len as usize;

    let (length, length_len_bytes) = read_varint(buf.get(offset..)?)?;
    offset += length_len_bytes;

    let length = usize::try_from(length).ok()?;
    let packet_end = offset.checked_add(length)?;
    if packet_end > buf.len() {
        return None;
    }

    Some(InitialParts {
        dcid,
        pn_offset: offset,
        length,
        packet_end,
    })
}

fn initial_secrets(dcid: &[u8]) -> Option<InitialSecrets> {
    let initial = Hkdf::<Sha256>::new(Some(QUIC_V1_INITIAL_SALT), dcid);
    let mut client_secret = [0u8; 32];
    hkdf_expand_label(&initial, b"client in", &mut client_secret)?;

    let client = Hkdf::<Sha256>::from_prk(&client_secret).ok()?;
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    hkdf_expand_label(&client, b"quic key", &mut key)?;
    hkdf_expand_label(&client, b"quic iv", &mut iv)?;
    hkdf_expand_label(&client, b"quic hp", &mut hp)?;

    Some(InitialSecrets { key, iv, hp })
}

fn hkdf_expand_label(hkdf: &Hkdf<Sha256>, label: &[u8], out: &mut [u8]) -> Option<()> {
    let full_label_len = 6usize.checked_add(label.len())?;
    let out_len = u16::try_from(out.len()).ok()?;
    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1);
    info.extend_from_slice(&out_len.to_be_bytes());
    info.push(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    hkdf.expand(&info, out).ok()
}

fn aes_mask(key: &[u8; 16], sample: &[u8]) -> Option<[u8; 16]> {
    let cipher = Aes128::new_from_slice(key).ok()?;
    let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(sample);
    cipher.encrypt_block(&mut block);
    let mut mask = [0u8; 16];
    mask.copy_from_slice(&block);
    Some(mask)
}

fn initial_nonce(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let pn = packet_number.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn[i];
    }
    nonce
}

fn first_crypto_frame(mut payload: &[u8]) -> Option<Vec<u8>> {
    while !payload.is_empty() {
        let (frame_type, consumed) = read_varint(payload)?;
        payload = &payload[consumed..];

        match frame_type {
            0x00 | 0x01 => {}
            0x02 | 0x03 => {
                payload = skip_ack_frame(payload)?;
            }
            0x06 => {
                let (offset, consumed) = read_varint(payload)?;
                if offset > 0 {
                    return None;
                }
                payload = &payload[consumed..];
                let (len, consumed) = read_varint(payload)?;
                payload = &payload[consumed..];
                let len = usize::try_from(len).ok()?;
                return Some(payload.get(..len)?.to_vec());
            }
            _ => return None,
        }
    }

    None
}

fn skip_ack_frame(mut payload: &[u8]) -> Option<&[u8]> {
    for _ in 0..3 {
        let (_, consumed) = read_varint(payload)?;
        payload = &payload[consumed..];
    }
    let (range_count, consumed) = read_varint(payload)?;
    payload = &payload[consumed..];
    for _ in 0..range_count {
        let (_, consumed) = read_varint(payload)?;
        payload = &payload[consumed..];
        let (_, consumed) = read_varint(payload)?;
        payload = &payload[consumed..];
    }
    Some(payload)
}

fn sni_from_tls_handshake(data: &[u8]) -> Option<String> {
    if data.len() < 4 || data[0] != 0x01 {
        return None;
    }

    let len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | data[3] as usize;
    let body = data.get(4..4 + len)?;
    let (_, hello) = tls_parser::parse_tls_handshake_client_hello(body).ok()?;
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

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(..len)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
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

    fn encode_varint(value: u64) -> Vec<u8> {
        if value < 64 {
            vec![value as u8]
        } else if value < 16_384 {
            ((value as u16) | 0x4000).to_be_bytes().to_vec()
        } else if value < 1_073_741_824 {
            ((value as u32) | 0x8000_0000).to_be_bytes().to_vec()
        } else {
            (value | 0xC000_0000_0000_0000).to_be_bytes().to_vec()
        }
    }

    fn client_hello_with_sni(name: &str) -> Vec<u8> {
        let name = name.as_bytes();
        let extension_len = 2 + 1 + 2 + name.len();
        let extension_block_len = 4 + extension_len;
        let body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extension_block_len;

        let mut hello = Vec::with_capacity(4 + body_len);
        hello.push(0x01);
        hello.extend_from_slice(&[
            ((body_len >> 16) & 0xff) as u8,
            ((body_len >> 8) & 0xff) as u8,
            (body_len & 0xff) as u8,
        ]);
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0x11; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        hello.extend_from_slice(&[0x01, 0x00]);
        hello.extend_from_slice(&(extension_block_len as u16).to_be_bytes());
        hello.extend_from_slice(&[0x00, 0x00]);
        hello.extend_from_slice(&(extension_len as u16).to_be_bytes());
        hello.extend_from_slice(&((extension_len - 2) as u16).to_be_bytes());
        hello.push(0);
        hello.extend_from_slice(&(name.len() as u16).to_be_bytes());
        hello.extend_from_slice(name);
        hello
    }

    fn crypto_frame(offset: u64, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x06];
        frame.extend_from_slice(&encode_varint(offset));
        frame.extend_from_slice(&encode_varint(data.len() as u64));
        frame.extend_from_slice(data);
        frame
    }

    fn protected_initial_packet(crypto_offset: u64, server_name: &str) -> Vec<u8> {
        protected_initial_packet_with_target_len(crypto_offset, server_name, None)
    }

    fn protected_initial_packet_with_target_len(
        crypto_offset: u64,
        server_name: &str,
        target_len: Option<usize>,
    ) -> Vec<u8> {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let crypto = crypto_frame(crypto_offset, &client_hello_with_sni(server_name));
        let secrets = initial_secrets(&dcid).expect("initial secrets");
        let packet_number = 1u64;
        let pn_len = 4usize;
        let mut padding_len = 0usize;

        let (header, pn_offset, payload_len) = loop {
            let payload_len = crypto.len() + padding_len;
            let length = pn_len + payload_len + 16;

            let mut header = vec![0xC0 | ((pn_len - 1) as u8)];
            header.extend_from_slice(&QUIC_V1.to_be_bytes());
            header.push(dcid.len() as u8);
            header.extend_from_slice(&dcid);
            header.push(0);
            header.extend_from_slice(&encode_varint(0));
            header.extend_from_slice(&encode_varint(length as u64));
            let pn_offset = header.len();
            header.extend_from_slice(&(packet_number as u32).to_be_bytes());

            let packet_len = header.len() + payload_len + 16;
            match target_len {
                Some(target) if packet_len < target => {
                    padding_len += target - packet_len;
                }
                Some(target) if packet_len > target => {
                    panic!("target packet length {target} is too small for Initial packet");
                }
                _ => break (header, pn_offset, payload_len),
            }
        };

        let nonce = initial_nonce(&secrets.iv, packet_number);
        let cipher = Aes128Gcm::new_from_slice(&secrets.key).expect("initial cipher");
        let mut payload = crypto;
        payload.resize(payload_len, 0x00);
        cipher
            .encrypt_in_place(Nonce::from_slice(&nonce), &header, &mut payload)
            .expect("encrypt initial payload");

        let mut packet = header;
        packet.extend_from_slice(&payload);

        let sample = packet
            .get(pn_offset + 4..pn_offset + 20)
            .expect("header protection sample");
        let mask = aes_mask(&secrets.hp, sample).expect("header protection mask");
        packet[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[i + 1];
        }

        packet
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

    #[test]
    fn extracts_dcid_from_20_byte_long_header() {
        let dcid = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        ];
        let pkt = long_header_packet(&dcid);

        assert_eq!(
            peek_quic_dcid(&pkt),
            Some("000102030405060708090a0b0c0d0e0f10111213".to_string())
        );
    }

    #[test]
    fn reads_quic_varints() {
        assert_eq!(read_varint(&[0x25]), Some((37, 1)));
        assert_eq!(read_varint(&[0x40, 0x25]), Some((37, 2)));
        assert_eq!(read_varint(&[0x80, 0x00, 0x00, 0x25]), Some((37, 4)));
        assert_eq!(
            read_varint(&[0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25]),
            Some((37, 8))
        );
    }

    #[test]
    fn extracts_first_crypto_frame_at_zero_offset() {
        let hello = client_hello_with_sni("example.com");
        assert_eq!(first_crypto_frame(&crypto_frame(0, &hello)), Some(hello));
    }

    #[test]
    fn rejects_fragmented_crypto_frame_offset() {
        let hello = client_hello_with_sni("example.com");
        assert_eq!(first_crypto_frame(&crypto_frame(1, &hello)), None);
    }

    #[test]
    fn peeks_sni_from_valid_initial_packet() {
        let packet = protected_initial_packet(0, "example.com");
        assert_eq!(
            peek_quic_initial_sni(&packet),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn peeks_sni_from_1200_byte_padded_initial_packet() {
        let packet = protected_initial_packet_with_target_len(0, "example.com", Some(1200));

        assert_eq!(packet.len(), 1200);
        assert_eq!(
            peek_quic_initial_sni(&packet),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn rejects_fragmented_initial_packet() {
        let packet = protected_initial_packet(1, "example.com");
        assert_eq!(peek_quic_initial_sni(&packet), None);
    }
}
