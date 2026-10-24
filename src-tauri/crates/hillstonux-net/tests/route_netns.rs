//! Integration test for the routing-table setup.
//!
//! The test re-executes itself inside a private user + network namespace
//! (`unshare -rn`) so it can manipulate a real routing table without
//! touching the host's configuration. Unprivileged user namespaces make
//! this possible without root.

use std::net::Ipv4Addr;
use std::process::Command;

use hillstonux_core::client::{NetworkConfig, Route};
use hillstonux_net::route::RouteManager;

const CHILD_ENV: &str = "HILLSTONUX_ROUTE_NETNS_CHILD";
const TEST_NAME: &str = "vpn_routes_are_applied_and_restored";
const TEST_NAME_SPLIT: &str = "vpn_split_routes_keep_default_route";

fn ip(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().expect("run ip");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[tokio::test]
async fn vpn_routes_are_applied_and_restored() {
    if std::env::var(CHILD_ENV).is_ok() {
        run_in_namespace().await;
        return;
    }

    // User namespaces are not available everywhere (some hardened kernels and
    // containers disable them). Probe first: if the namespace cannot be
    // created the test has nothing to run against.
    match Command::new("unshare").args(["-rn", "true"]).status() {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("skipping: unprivileged user namespaces are unavailable here");
            return;
        }
    }

    let exe = std::env::current_exe().expect("current_exe");
    let status = Command::new("unshare")
        .args([
            "-rn",
            exe.to_str().expect("test binary path"),
            "--exact",
            TEST_NAME,
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .status()
        .expect("spawn unshare");
    assert!(status.success(), "netns child failed: {status}");
}

/// Runs inside the namespace: a fake uplink plus the real `RouteManager`.
async fn run_in_namespace() {
    // A stand-in uplink: address, default route via a gateway.
    ip(&["link", "add", "wlan0", "type", "dummy"]);
    ip(&["addr", "add", "172.16.248.56/22", "dev", "wlan0"]);
    ip(&["link", "set", "wlan0", "up"]);
    ip(&[
        "route",
        "add",
        "default",
        "via",
        "172.16.248.1",
        "dev",
        "wlan0",
        "metric",
        "600",
    ]);
    // A stand-in for the TUN device the daemon would have created.
    ip(&["link", "add", "hillstonux0", "type", "dummy"]);

    let server = Ipv4Addr::new(112, 30, 185, 147);
    let cfg = NetworkConfig {
        client_ip: Ipv4Addr::new(10, 250, 253, 194),
        netmask: 22,
        gateway: Ipv4Addr::new(10, 250, 252, 1),
        dns: vec![],
        server_udp_port: 0,
        routes: vec![],
    };

    let mut mgr = RouteManager::snapshot("hillstonux0", server)
        .await
        .expect("snapshot");
    mgr.apply_vpn_routes(&cfg, true)
        .await
        .expect("apply routes");

    // The VPN server must bypass the tunnel, otherwise the ESP transport
    // would be swallowed by the tunnel's own default route.
    let server_route = ip(&["route", "get", &server.to_string()]);
    assert!(
        server_route.contains("via 172.16.248.1"),
        "server does not bypass the tunnel: {server_route}"
    );
    assert!(
        server_route.contains("dev wlan0"),
        "server does not bypass the tunnel: {server_route}"
    );

    // Everything else goes through the tunnel.
    let default_route = ip(&["route", "get", "8.8.8.8"]);
    assert!(
        default_route.contains("via 10.250.252.1"),
        "default route is not tunnelled: {default_route}"
    );
    assert!(
        default_route.contains("dev hillstonux0"),
        "default route is not tunnelled: {default_route}"
    );

    // The VPN network is routed by its *network* address; the host address
    // would be rejected as an invalid prefix.
    let table = ip(&["route", "show"]);
    assert!(
        table.contains("10.250.252.0/22"),
        "vpn network route missing: {table}"
    );

    // The tunnel interface carries the negotiated address.
    let addr = ip(&["addr", "show", "dev", "hillstonux0"]);
    assert!(
        addr.contains("10.250.253.194/22"),
        "tun address missing: {addr}"
    );

    // Restoring brings the pre-VPN table back, byte-for-byte.
    mgr.restore().await.expect("restore");
    let restored = ip(&["route", "show"]);
    assert!(
        restored.contains("default via 172.16.248.1 dev wlan0 metric 600"),
        "original default route not restored: {restored}"
    );
    assert!(
        !restored.contains("10.250."),
        "vpn routes left behind after restore: {restored}"
    );
    assert!(
        !restored.contains("112.30.185.147"),
        "server bypass left behind after restore: {restored}"
    );
}

#[tokio::test]
async fn vpn_split_routes_keep_default_route() {
    if std::env::var(CHILD_ENV).is_ok() {
        run_split_in_namespace().await;
        return;
    }

    match Command::new("unshare").args(["-rn", "true"]).status() {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("skipping: unprivileged user namespaces are unavailable here");
            return;
        }
    }

    let exe = std::env::current_exe().expect("current_exe");
    let status = Command::new("unshare")
        .args([
            "-rn",
            exe.to_str().expect("test binary path"),
            "--exact",
            TEST_NAME_SPLIT,
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .status()
        .expect("spawn unshare");
    assert!(status.success(), "netns child failed: {status}");
}

/// Split-tunnel inside the namespace: advertised subnets go via the tunnel,
/// the default route stays on the uplink, restore is clean.
async fn run_split_in_namespace() {
    ip(&["link", "add", "wlan0", "type", "dummy"]);
    ip(&["addr", "add", "172.16.248.56/22", "dev", "wlan0"]);
    ip(&["link", "set", "wlan0", "up"]);
    ip(&[
        "route",
        "add",
        "default",
        "via",
        "172.16.248.1",
        "dev",
        "wlan0",
        "metric",
        "600",
    ]);
    ip(&["link", "add", "hillstonux0", "type", "dummy"]);

    let server = Ipv4Addr::new(112, 30, 185, 147);
    let cfg = NetworkConfig {
        client_ip: Ipv4Addr::new(10, 250, 253, 194),
        netmask: 22,
        gateway: Ipv4Addr::new(10, 250, 252, 1),
        dns: vec![],
        server_udp_port: 0,
        routes: vec![
            // An internal network the server wants us to reach via the
            // tunnel (deliberately includes the VPN network itself to prove
            // duplicate tracking does not break restore).
            Route {
                dest: Ipv4Addr::new(10, 1, 0, 0),
                prefix: 16,
            },
            Route {
                dest: Ipv4Addr::new(10, 250, 252, 0),
                prefix: 22,
            },
        ],
    };

    let mut mgr = RouteManager::snapshot("hillstonux0", server)
        .await
        .expect("snapshot");
    mgr.apply_vpn_routes(&cfg, false)
        .await
        .expect("apply split routes");

    // The VPN server still bypasses the tunnel.
    let server_route = ip(&["route", "get", &server.to_string()]);
    assert!(
        server_route.contains("via 172.16.248.1") && server_route.contains("dev wlan0"),
        "server does not bypass the tunnel: {server_route}"
    );

    // Advertised subnet is tunneled.
    let internal = ip(&["route", "get", "10.1.111.154"]);
    assert!(
        internal.contains("via 10.250.252.1") && internal.contains("dev hillstonux0"),
        "advertised subnet is not tunneled: {internal}"
    );

    // Non-advertised destinations keep the uplink default route.
    let external = ip(&["route", "get", "8.8.8.8"]);
    assert!(
        external.contains("via 172.16.248.1") && external.contains("dev wlan0"),
        "default route was hijacked in split mode: {external}"
    );

    // Restoring brings the pre-VPN table back with no leftovers.
    mgr.restore().await.expect("restore");
    let restored = ip(&["route", "show"]);
    assert!(
        restored.contains("default via 172.16.248.1 dev wlan0 metric 600"),
        "original default route not restored: {restored}"
    );
    assert!(
        !restored.contains("10.250."),
        "vpn routes left behind after restore: {restored}"
    );
    assert!(
        !restored.contains("10.1."),
        "advertised subnet route left behind after restore: {restored}"
    );
    assert!(
        !restored.contains("112.30.185.147"),
        "server bypass left behind after restore: {restored}"
    );
}
