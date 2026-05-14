use anyhow::Result;
use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Endpoint};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use wormhole_relay::relay::Relay;

#[tokio::test]
async fn relay_accepts_quic_client_and_registers_tunnel() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let relay = Relay::bind("127.0.0.1:0").await?;
    let relay_addr = relay.endpoint_handle().local_addr()?;
    let relay_endpoint = relay.endpoint_handle();
    let router = relay.router();
    let public_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);

    let relay_task = tokio::spawn(async move { relay.run(public_socket).await });

    let mut client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    client.set_default_client_config(insecure_client_config()?);

    let conn = client.connect(relay_addr, "test.local")?.await?;

    for _ in 0..20 {
        if router.active_tunnels() == 1 {
            conn.close(quinn::VarInt::from_u32(0), b"test done");
            relay_endpoint.close(quinn::VarInt::from_u32(0), b"test done");
            relay_task.abort();
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    relay_endpoint.close(quinn::VarInt::from_u32(0), b"test timeout");
    relay_task.abort();
    anyhow::bail!("relay did not register client tunnel");
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
