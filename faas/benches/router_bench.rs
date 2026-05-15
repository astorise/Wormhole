use anyhow::{Context, Result};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Connection, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use wormhole_relay::router::Router;

const CALLER_COUNT: usize = 10_000;
const INGRESS_PORT: u16 = 443;

struct BenchState {
    runtime: Runtime,
    router: Arc<Router>,
    socket: Arc<UdpSocket>,
    callers: Vec<SocketAddr>,
    payload: Vec<u8>,
    _server: Endpoint,
    _client: Endpoint,
    _client_conn: Connection,
}

fn bench_route_udp_ingress(c: &mut Criterion) {
    let state = BenchState::new().expect("benchmark state");
    let router = Arc::clone(&state.router);
    let socket = Arc::clone(&state.socket);
    let callers = state.callers.clone();
    let payload = state.payload.clone();
    let mut next_caller = 0usize;

    c.bench_function("route_udp_ingress_10000_callers_fallback", |b| {
        b.to_async(&state.runtime).iter(|| {
            let router = Arc::clone(&router);
            let socket = Arc::clone(&socket);
            let caller = callers[next_caller % callers.len()];
            let payload = payload.clone();
            next_caller = next_caller.wrapping_add(1);

            async move {
                let forwarded = router
                    .route_udp_ingress(
                        black_box("unknown-dcid"),
                        INGRESS_PORT,
                        black_box(payload.as_slice()),
                        black_box(caller),
                        socket,
                    )
                    .await;
                black_box(forwarded);
            }
        });
    });
}

impl BenchState {
    fn new() -> Result<Self> {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let runtime = Runtime::new().context("tokio runtime")?;
        let (router, socket, callers, server, client, client_conn) =
            runtime.block_on(setup_router())?;

        Ok(Self {
            runtime,
            router,
            socket,
            callers,
            payload: vec![0x42; 64],
            _server: server,
            _client: client,
            _client_conn: client_conn,
        })
    }
}

async fn setup_router() -> Result<(
    Arc<Router>,
    Arc<UdpSocket>,
    Vec<SocketAddr>,
    Endpoint,
    Endpoint,
    Connection,
)> {
    let server = test_server_endpoint()?;
    let (client, client_conn, server_conn) = connect_pair(&server, "bench.local").await?;

    let drain_conn = client_conn.clone();
    tokio::spawn(async move { while drain_conn.read_datagram().await.is_ok() {} });

    let router = Arc::new(Router::new());
    let tunnel_key = router.register(server_conn, Some("bench.local".to_string()), true)?;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let mut callers = Vec::with_capacity(CALLER_COUNT);

    for i in 0..CALLER_COUNT {
        let caller = caller_addr(i);
        let dcid = format!("bench-dcid-{i}");
        router.map_dcid_to_sni(&dcid, tunnel_key.clone());
        let _ = router
            .route_udp_ingress(&dcid, INGRESS_PORT, b"prime", caller, Arc::clone(&socket))
            .await;
        callers.push(caller);
    }

    Ok((router, socket, callers, server, client, client_conn))
}

fn caller_addr(i: usize) -> SocketAddr {
    let third = ((i / 256) & 0xff) as u8;
    let fourth = (i & 0xff) as u8;
    let port = 1024 + (i % 60_000) as u16;
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, third, fourth)), port)
}

fn test_server_endpoint() -> Result<Endpoint> {
    let (cert, key) = wormhole_relay::tls::self_signed_cert()?;
    let tls_config = wormhole_relay::tls::server_config(cert, key, None)?;
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?;
    Endpoint::server(
        ServerConfig::with_crypto(Arc::new(quic_config)),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .context("server endpoint")
}

async fn connect_pair(
    server: &Endpoint,
    server_name: &str,
) -> Result<(Endpoint, Connection, Connection)> {
    let mut client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    client.set_default_client_config(insecure_client_config()?);

    let connecting = client.connect(server.local_addr()?, server_name)?;
    let incoming = server.accept().await.context("server accept")?;
    let (client_conn, server_conn) = tokio::try_join!(connecting, incoming)?;
    Ok((client, client_conn, server_conn))
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

criterion_group!(benches, bench_route_udp_ingress);
criterion_main!(benches);
