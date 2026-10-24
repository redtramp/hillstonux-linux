//! Controller smoke tests: state transitions without real network I/O.

use hillstonux_daemon::controller::{Controller, Settings};
use hillstonux_daemon::ipc::{VpnEvent, VpnStateDto};
use std::time::Duration;
use tokio::sync::broadcast;

#[tokio::test]
async fn controller_starts_in_idle_state() {
    let (tx, _rx) = broadcast::channel::<VpnEvent>(1024);
    let controller = Controller::new(Settings::default(), tx.clone());
    let state = controller.state().await;
    assert!(matches!(state.phase, VpnStateDto::Idle));

    // No events should have been emitted yet.
    let mut rx = tx.subscribe();
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn disconnect_when_idle_is_noop() {
    let (tx, _rx) = broadcast::channel::<VpnEvent>(1024);
    let controller = Controller::new(Settings::default(), tx.clone());
    // Should succeed even when nothing is connected.
    controller
        .disconnect()
        .await
        .expect("disconnect on idle is OK");
}

#[tokio::test]
async fn connect_without_network_fails_and_emits_error() {
    let (tx, _rx) = broadcast::channel::<VpnEvent>(1024);
    let controller = Controller::new(Settings::default(), tx.clone());
    // Subscribe before connecting so we capture the failure events.
    let mut rx = tx.subscribe();
    // 192.0.2.1 is in TEST-NET-1, never routable; connect should fail quickly.
    let result = controller
        .connect(hillstonux_daemon::ipc::ConnectParams {
            server: "192.0.2.1".into(),
            port: 4433,
            user: "u".into(),
            password: String::new(),
            password_ref: "p".into(),
            full_tunnel: false,
        })
        .await;
    assert!(result.is_err());

    // We expect at least one StateChanged(Error) event to have been emitted.
    let mut saw_error = false;
    while let Ok(timeout_res) = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
        match timeout_res {
            Ok(VpnEvent::StateChanged {
                state: VpnStateDto::Error { .. },
            }) => {
                saw_error = true;
                break;
            }
            Ok(_) => continue,
            Err(_) => break, // sender dropped / channel closed
        }
    }
    assert!(
        saw_error,
        "expected an Error state event after failed connect"
    );
}
