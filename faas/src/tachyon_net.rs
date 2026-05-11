//! Conditional socket abstraction for Tachyon-Mesh deployment.
//!
//! On native targets (Linux/macOS/Windows) the functions delegate to standard
//! `tokio::net` socket binding, identical to calling the types directly.
//!
//! On `wasm32-wasi` the Tachyon Gateway pre-opens sockets and passes them to
//! the worker via WASI file-descriptor inheritance (analogous to `stdin`/`stdout`
//! but for network sockets).  The fd numbers are read from environment variables
//! `TACHYON_TCP_FD` and `TACHYON_UDP_FD`, defaulting to 3 and 4 respectively.

use anyhow::{Context, Result};
use std::net::SocketAddr;

// ─────────────────────────────────────────────────────────────────────────────
// Native (non-WASI) implementation
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(not(target_os = "wasi"))]
pub async fn bind_tcp(addr: SocketAddr) -> Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind TCP socket on {addr}"))
}

#[cfg(not(target_os = "wasi"))]
pub async fn bind_udp(addr: SocketAddr) -> Result<tokio::net::UdpSocket> {
    tokio::net::UdpSocket::bind(addr)
        .await
        .with_context(|| format!("failed to bind UDP socket on {addr}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// WASI implementation — Tachyon pre-opened file descriptors
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "wasi")]
pub async fn bind_tcp(_addr: SocketAddr) -> Result<tokio::net::TcpListener> {
    use std::os::fd::{FromRawFd, RawFd};

    let fd: RawFd = std::env::var("TACHYON_TCP_FD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);

    // SAFETY: the Tachyon host guarantees fd `TACHYON_TCP_FD` is a valid,
    // already-bound, non-blocking TCP listening socket.
    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    std_listener
        .set_nonblocking(true)
        .context("set_nonblocking on Tachyon TCP fd")?;
    tokio::net::TcpListener::from_std(std_listener).context("TcpListener::from_std (Tachyon fd)")
}

#[cfg(target_os = "wasi")]
pub async fn bind_udp(_addr: SocketAddr) -> Result<tokio::net::UdpSocket> {
    use std::os::fd::{FromRawFd, RawFd};

    let fd: RawFd = std::env::var("TACHYON_UDP_FD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);

    // SAFETY: the Tachyon host guarantees fd `TACHYON_UDP_FD` is a valid,
    // already-bound, non-blocking UDP socket.
    let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    std_socket
        .set_nonblocking(true)
        .context("set_nonblocking on Tachyon UDP fd")?;
    tokio::net::UdpSocket::from_std(std_socket).context("UdpSocket::from_std (Tachyon fd)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_tcp_loopback() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = bind_tcp(addr).await;
        assert!(listener.is_ok(), "should bind TCP on loopback");
    }

    #[tokio::test]
    async fn bind_udp_loopback() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = bind_udp(addr).await;
        assert!(socket.is_ok(), "should bind UDP on loopback");
    }
}
