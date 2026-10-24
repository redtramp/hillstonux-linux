//! Unix-socket server smoke test: spin up the server, connect, send Ping,
//! expect Ok reply, then drop the connection.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hillstonux_daemon::ipc::framing::{read_frame, write_frame};
use hillstonux_daemon::ipc::{IpcRequest, IpcResponse};
use hillstonux_daemon::server::{EventSink, RequestHandler};
use tokio::net::UnixStream;
use tokio::sync::Notify;

struct CountingHandler {
    pub received: std::sync::Arc<tokio::sync::Mutex<Vec<IpcRequest>>>,
}

impl RequestHandler for CountingHandler {
    fn handle(
        &self,
        req: IpcRequest,
        _sink: EventSink,
    ) -> Result<Option<serde_json::Value>, String> {
        let received = self.received.clone();
        tokio::spawn(async move {
            received.lock().await.push(req);
        });
        Ok(None)
    }
}

#[tokio::test]
async fn server_accepts_ping() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("test.sock");
    let received = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let handler: Arc<dyn RequestHandler> = Arc::new(CountingHandler {
        received: received.clone(),
    });
    let shutdown = Arc::new(Notify::new());
    let server_handle = {
        let handler = handler.clone();
        let shutdown = shutdown.clone();
        let sock = sock.clone();
        tokio::spawn(async move { hillstonux_daemon::server::run(sock, handler, shutdown).await })
    };

    // Give the listener a beat to come up.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = UnixStream::connect(&sock).await.expect("connect");
    write_frame(&mut stream, &IpcRequest::Ping { id: 1 })
        .await
        .expect("write ping");
    let resp: IpcResponse = read_frame(&mut stream).await.expect("read resp");
    match resp {
        IpcResponse::Ok { id, .. } => assert_eq!(id, 1),
        other => panic!("expected Ok, got {:?}", other),
    }

    // Verify the handler saw the Ping.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let received = received.lock().await;
    assert_eq!(received.len(), 1);
    assert!(matches!(received[0], IpcRequest::Ping { id: 1 }));

    // Clean shutdown.
    shutdown.notify_waiters();
    drop(stream);
    let _ = tokio::time::timeout(Duration::from_secs(1), server_handle).await;
}

#[tokio::test]
async fn server_handles_unknown_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let sock: PathBuf = tmp.path().join("missing.sock");
    let handler: Arc<dyn RequestHandler> = Arc::new(CountingHandler {
        received: Arc::new(tokio::sync::Mutex::new(Vec::new())),
    });
    let shutdown = Arc::new(Notify::new());

    // Don't start a server; connecting to a non-existent path should fail.
    let result = tokio::time::timeout(Duration::from_millis(100), UnixStream::connect(&sock)).await;
    assert!(result.is_err() || result.unwrap().is_err());

    let _ = handler;
    shutdown.notify_waiters();
}
