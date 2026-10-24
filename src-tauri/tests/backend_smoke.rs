//! End-to-end smoke test of the GUI <-> daemon connection plumbing.
//!
//! Verifies two things:
//!   1. The login config is read from the file selected by
//!      `HILLSTONUX_CONFIG` (including the `user` / `pass` shorthand aliases).
//!   2. Clicking connect reaches the daemon and the daemon progress events are
//!      delivered back to the client (the exact path that makes the GUI status
//!      react instead of sitting idle).
//!
//! The test creates its own config pointing at a closed local port, so it
//! never depends on (or mutates) the developer's real login file.

use hillstonux_daemon::ipc::{IpcResponse, VpnEvent};
use hillstonux_gui_lib::config;
use hillstonux_gui_lib::ipc_client::{IpcClient, IpcRequestParams};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::sync::mpsc;

/// Walk up from the test binary to locate a sibling file by name.
fn find_upward(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    for anc in exe.ancestors() {
        let cand = anc.join(name);
        if cand.exists() {
            return cand;
        }
    }
    panic!("could not find {name} near {exe:?}");
}

#[tokio::test]
#[allow(clippy::zombie_processes)]
async fn smoke_backend_connection() {
    // --- (1) config is read from the selected config file ----------------
    let cfg_path = std::env::temp_dir().join(format!(
        "hillstonux-smoke-config-{}.json",
        std::process::id()
    ));
    std::fs::write(
        &cfg_path,
        r#"{
            "server": "127.0.0.1",
            "port": 1,
            "user": "smoke-user",
            "pass": "smoke-password"
        }"#,
    )
    .expect("write smoke config");
    std::env::set_var("HILLSTONUX_CONFIG", &cfg_path);
    let cfg = config::load().expect("load config.json");
    assert_eq!(cfg.server, "127.0.0.1");
    assert_eq!(cfg.port, 1);
    assert_eq!(cfg.username, "smoke-user", "username read via user alias");
    assert_eq!(
        cfg.password, "smoke-password",
        "password read via pass alias"
    );
    println!(
        "config ok: server={} port={} user={}",
        cfg.server, cfg.port, cfg.username
    );

    // --- (2) spawn the daemon and talk to it over the socket -----------
    let socket = std::env::temp_dir().join(format!("hillstonux-smoke-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);

    let daemon = find_upward("hillstonux-daemon");
    let mut child = Command::new(&daemon)
        .env("HILLSTONUX_SOCKET", &socket)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn hillstonux-daemon");

    // Wait for the socket to appear (daemon is up).
    let start = std::time::Instant::now();
    while !socket.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "daemon socket never appeared"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let (evt_tx, mut evt_rx) = mpsc::unbounded_channel::<VpnEvent>();
    // IpcClient connects lazily and launches the daemon itself if needed.
    let client = IpcClient::new(socket.clone(), evt_tx);

    // Ping exercises the request/response half of the protocol.
    let resp = client
        .request(IpcRequestParams::Ping)
        .await
        .expect("ping request");
    assert!(
        matches!(resp, IpcResponse::Ok { .. }),
        "ping should return Ok"
    );

    // Connect to the configured server. Whether it ultimately succeeds or
    // fails, the daemon must push StateChanged events back to us. That is
    // what makes the GUI react.
    client
        .request(IpcRequestParams::Connect {
            server: &cfg.server,
            port: cfg.port,
            user: &cfg.username,
            password: &cfg.password,
            password_ref: "",
            full_tunnel: false,
        })
        .await
        .expect("connect request dispatched");

    // Wait (bounded) for the first StateChanged event.
    let mut got_state = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(3), evt_rx.recv()).await {
            Ok(Some(VpnEvent::StateChanged { state })) => {
                println!("event: {state:?}");
                got_state = true;
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    assert!(
        got_state,
        "expected at least one StateChanged event from the backend"
    );

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(&cfg_path);
}
