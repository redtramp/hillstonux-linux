//! TUN device wrapper.
//!
//! Wraps the Linux TUN device from the `tun` crate (synchronous std::io::Read/
//! Write) behind a small interface. Callers in the daemon's async context
//! should use [`tokio::task::spawn_blocking`] to invoke read/write so the
//! reactor isn't blocked while the kernel copies packets.
//!
//! API choices:
//! - `TunDevice` is the owning handle; on drop the underlying fd is closed.
//! - `recv` / `send` are blocking std-style. The device is left in blocking
//!   mode by default — the daemon uses `spawn_blocking` to read/write.
//! - `name()` returns the interface name (e.g. "hillstonux0").
//! - `as_raw_fd()` exposes the fd for tests that need to set non-blocking
//!   mode or poll directly.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};

pub struct TunDevice {
    inner: tun::Device,
    name: String,
}

impl TunDevice {
    /// Create a new TUN device with the given name.
    ///
    /// Requires `CAP_NET_ADMIN` (or root). The device is created but NOT brought
    /// up or assigned an address — the caller must run `ip link set <name> up`
    /// and `ip addr add ... dev <name>` after creation.
    pub fn create(name: &str) -> std::io::Result<Self> {
        let mut config = tun::Configuration::default();
        config.tun_name(name); // default layer is L3 (TUN)
        let device = tun::create(&config).map_err(std::io::Error::other)?;
        Ok(Self {
            inner: device,
            name: name.to_string(),
        })
    }

    /// Construct a `TunDevice` from an already-open TUN file descriptor.
    ///
    /// Used by the daemon when the TUN device was created by the privileged
    /// helper (hillstonux-privhelper) and the fd was passed back over a Unix
    /// socket via SCM_RIGHTS. The device is owned by this struct and the fd is
    /// closed on drop (the helper's copy was already dropped after sending).
    pub fn from_fd(fd: RawFd, name: String) -> std::io::Result<Self> {
        let mut config = tun::Configuration::default();
        config.raw_fd(fd);
        let device = tun::Device::new(&config)?;
        Ok(Self {
            inner: device,
            name,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }

    /// Block until a packet is read from the TUN device. Returns 0 on EOF.
    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.recv(buf)
    }

    /// Block until the packet is written to the TUN device.
    pub fn send(&self, pkt: &[u8]) -> std::io::Result<usize> {
        self.inner.send(pkt)
    }
}

impl Read for TunDevice {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for TunDevice {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
