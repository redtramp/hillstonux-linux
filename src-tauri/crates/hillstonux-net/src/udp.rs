//! UDP socket wrapper for the ESP data channel.
//!
//! Thin newtype around `tokio::net::UdpSocket` that re-exports the most-used
//! methods. The daemon's data-plane tasks (`tun → encrypt → sendto`,
//! `recvfrom → decrypt → tun`) hold one of these each.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Cheap-to-clone UDP socket wrapper. Wraps `UdpSocket` in `Arc` so both the
/// outbound and inbound data-plane tasks can share the same socket.
#[derive(Debug, Clone)]
pub struct EspSocket(Arc<UdpSocket>);

impl EspSocket {
    /// Bind to the wildcard address with an OS-chosen local port.
    ///
    /// The socket must *not* be bound to the loopback address: a socket
    /// bound to 127.0.0.1 cannot send to a non-loopback peer — the kernel
    /// rejects it with EINVAL ("Invalid argument"). The ESP transport talks
    /// to the VPN server's public address, so the socket has to be reachable
    /// from any local address. The source address of each outgoing packet is
    /// then selected by the routing table, which routes the server through
    /// the pre-tunnel gateway (see `route::RouteManager`).
    pub async fn bind_any() -> std::io::Result<Self> {
        let s = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(Self(Arc::new(s)))
    }

    /// Bind to a specific local address (for tests / pinned ports).
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let s = UdpSocket::bind(addr).await?;
        Ok(Self(Arc::new(s)))
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.local_addr()
    }

    pub async fn send_to(&self, pkt: &[u8], server: SocketAddr) -> std::io::Result<()> {
        self.0.send_to(pkt, server).await?;
        Ok(())
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }
}
