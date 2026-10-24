//! End-to-end test of the privileged helper.
//!
//! The helper is the process that actually creates the TUN device and
//! changes the routing table. This test drives it exactly the way the
//! daemon does — same wire format, same SCM_RIGHTS fd passing — but starts
//! it directly instead of through pkexec, so no polkit prompt is involved.
//! What is under test is the protocol and the privileged operations, not
//! the authorization UI.
//!
//! The whole test runs inside an unprivileged user + network namespace
//! (`unshare -rn`), where the process has CAP_NET_ADMIN over a *private*
//! network namespace. The host's routing table is never touched.

use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hillstonux_daemon::privops::protocol::{
    read_frame_sync, recv_fd, write_frame_sync, HelperRequest, HelperResponse,
};
use hillstonux_net::TunDevice;

const CHILD_ENV: &str = "HILLSTONUX_PRIVHELPER_NETNS_CHILD";
const TEST_NAME: &str = "helper_creates_tun_and_applies_routes";

const SERVER: Ipv4Addr = Ipv4Addr::new(112, 30, 185, 147);
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 250, 253, 194);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 250, 252, 1);
const NETMASK: u8 = 22;
const TUN: &str = "hillstonux0";

fn ip(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().expect("run ip");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn helper_creates_tun_and_applies_routes() {
    if std::env::var(CHILD_ENV).is_ok() {
        run_in_namespace();
        return;
    }

    // User namespaces are not available everywhere (hardened kernels and
    // containers disable them). Probe first: without one the test has
    // nothing to run against.
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

/// Runs inside the namespace: a fake uplink plus the real privileged helper.
fn run_in_namespace() {
    // A stand-in uplink: address + default route via a gateway.
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

    let dir = tempfile::tempdir().expect("tempdir");
    let sock_path = dir.path().join("priv.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind helper socket");

    // The helper connects to us, so it has to be started before we accept.
    let mut helper: Child = Command::new(env!("CARGO_BIN_EXE_hillstonux-daemon"))
        .arg("--privhelper")
        .arg(&sock_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn privhelper");

    let mut stream = accept_with_timeout(&listener);

    // --- TunCreate: the helper creates the device and hands the fd back ---
    send(
        &mut stream,
        HelperRequest::TunCreate {
            name: TUN.to_string(),
        },
    );
    let resp = recv(&mut stream);
    match resp {
        HelperResponse::Ok { name } => {
            assert_eq!(
                name.as_deref(),
                Some(TUN),
                "helper reported a different device"
            );
        }
        HelperResponse::Err { message } => panic!("TunCreate failed: {message}"),
    }

    // The fd arrives as an SCM_RIGHTS message right after the response frame.
    let fd = recv_fd(stream.as_raw_fd()).expect("receive tun fd");
    let tun = TunDevice::from_fd(fd, TUN.to_string()).expect("adopt tun fd");
    assert_eq!(tun.name(), TUN);
    let link = ip(&["-o", "link", "show", TUN]);
    assert!(
        link.contains(TUN),
        "tun device not visible after the fd handover: {link}"
    );

    // --- RoutesApply: the real RouteManager, against a real routing table ---
    send(
        &mut stream,
        HelperRequest::RoutesApply {
            client_ip: CLIENT_IP,
            netmask: NETMASK,
            gateway: GATEWAY,
            server_host: SERVER,
            tun_name: TUN.to_string(),
            routes: vec![],
            full_tunnel: true,
        },
    );
    match recv(&mut stream) {
        HelperResponse::Ok { .. } => {}
        HelperResponse::Err { message } => panic!("RoutesApply failed: {message}"),
    }

    // The VPN server must bypass the tunnel, otherwise the ESP transport
    // would be swallowed by the tunnel's own default route.
    let server_route = ip(&["route", "get", &SERVER.to_string()]);
    assert!(
        server_route.contains("via 172.16.248.1") && server_route.contains("dev wlan0"),
        "server does not bypass the tunnel: {server_route}"
    );

    // Everything else goes through the tunnel.
    let default_route = ip(&["route", "get", "8.8.8.8"]);
    assert!(
        default_route.contains("via 10.250.252.1") && default_route.contains("dev hillstonux0"),
        "default route is not tunnelled: {default_route}"
    );

    let table = ip(&["route", "show"]);
    assert!(
        table.contains("10.250.252.0/22"),
        "vpn network route missing: {table}"
    );
    let addr = ip(&["addr", "show", "dev", TUN]);
    assert!(
        addr.contains("10.250.253.194/22"),
        "tun address missing: {addr}"
    );

    // --- RoutesRestore: the pre-VPN table comes back ---
    send(&mut stream, HelperRequest::RoutesRestore);
    match recv(&mut stream) {
        HelperResponse::Ok { .. } => {}
        HelperResponse::Err { message } => panic!("RoutesRestore failed: {message}"),
    }
    let restored = ip(&["route", "show"]);
    assert!(
        restored.contains("default via 172.16.248.1 dev wlan0 metric 600"),
        "original default route not restored: {restored}"
    );
    assert!(
        !restored.contains("10.250.") && !restored.contains("112.30.185.147"),
        "vpn routes left behind after restore: {restored}"
    );

    // --- TunDestroy: the device is gone ---
    send(
        &mut stream,
        HelperRequest::TunDestroy {
            name: TUN.to_string(),
        },
    );
    match recv(&mut stream) {
        HelperResponse::Ok { .. } => {}
        HelperResponse::Err { message } => panic!("TunDestroy failed: {message}"),
    }
    let link = ip(&["-o", "link", "show", TUN]);
    assert!(
        !link.contains(TUN),
        "tun device still present after TunDestroy: {link}"
    );

    let _ = helper.kill();
    let _ = helper.wait();
}

/// Accept the helper's connection, but do not wait forever: a helper that
/// fails to start must fail the test instead of hanging it.
fn accept_with_timeout(listener: &UnixListener) -> UnixStream {
    listener
        .set_nonblocking(true)
        .expect("non-blocking listener");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).expect("blocking stream");
                return stream;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    panic!("privhelper did not connect to the control socket");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("accept: {e}"),
        }
    }
}

fn send(stream: &mut UnixStream, req: HelperRequest) {
    write_frame_sync(stream, &req).expect("write request");
}

fn recv(stream: &mut UnixStream) -> HelperResponse {
    read_frame_sync(stream).expect("read response")
}
