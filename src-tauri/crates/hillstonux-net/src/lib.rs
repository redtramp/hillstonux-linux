//! Hillstonux system-integration layer.
//!
//! Wraps the kernel interfaces the daemon needs:
//! - TUN device creation + async read/write of IP packets
//! - UDP socket for the ESP data channel
//! - Routing-table manipulation via `ip` (iproute2)
//! - DNS configuration via `resolvectl` / `nmcli`

pub mod dns;
pub mod route;
pub mod tun;
pub mod udp;

pub use dns::{DnsManager, DnsSnapshot};
pub use route::{RouteManager, RouteSnapshot};
pub use tun::TunDevice;
pub use udp::EspSocket;

pub fn hello_world() -> &'static str {
    "hello"
}
