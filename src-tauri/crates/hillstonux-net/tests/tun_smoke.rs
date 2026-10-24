//! TUN device smoke tests. Marked `#[ignore]` because they require root
//! and a `/dev/net/tun` device. Run with `sudo cargo test -- --ignored`.

use hillstonux_net::TunDevice;
use std::process::Command;

#[test]
#[ignore = "requires CAP_NET_ADMIN and /dev/net/tun"]
fn create_tun_device() {
    let dev = TunDevice::create("hillstonux-test").expect("create tun");
    assert_eq!(dev.name(), "hillstonux-test");

    // Verify it shows up in `ip link`.
    let output = Command::new("ip")
        .args(["link", "show", "hillstonux-test"])
        .output()
        .expect("ip link");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("hillstonux-test"),
        "tun device not visible in ip link"
    );

    // Clean up.
    let _ = Command::new("ip")
        .args(["link", "del", "hillstonux-test"])
        .output();
}
