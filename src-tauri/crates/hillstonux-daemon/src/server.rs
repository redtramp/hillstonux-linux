//! Unix-socket server: length-prefix framed JSON request/response.
//!
//! One task per connection. The handler is provided as a closure so the
//! caller (typically `main`) can plug in any state machine — production
//! passes `Controller`, tests pass a mock.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::BufStream;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

use crate::ipc::framing::{read_frame, write_frame};
use crate::ipc::{IpcRequest, IpcResponse};

pub trait RequestHandler: Send + Sync + 'static {
    /// Handle one request. Returns:
    /// - `Ok(Some(value))` for synchronous requests (e.g. `State`) whose
    ///   reply should carry data back to the client. The framework writes
    ///   `Ok { id, data: Some(value) }`.
    /// - `Ok(None)` for fire-and-forget requests (e.g. `Connect`,
    ///   `Disconnect`) that produce their effects asynchronously via the
    ///   event sink. The framework writes `Ok { id, data: None }`.
    /// - `Err(message)` for synchronous errors. The framework writes
    ///   `Err { id, code: 1, message }`.
    fn handle(&self, req: IpcRequest, tx: EventSink) -> Result<Option<serde_json::Value>, String>;
}

pub type EventSink = Arc<dyn Fn(crate::ipc::VpnEvent) + Send + Sync>;

/// Run the unix-socket server until the listener errors or `shutdown` fires.
pub async fn run(
    socket_path: PathBuf,
    handler: Arc<dyn RequestHandler>,
    shutdown: Arc<Notify>,
) -> std::io::Result<()> {
    // Best-effort remove any stale socket file.
    let _ = std::fs::remove_file(&socket_path);

    // Ensure the parent directory exists (e.g. $XDG_RUNTIME_DIR/hillstonux).
    // Without this, bind() fails when the daemon is launched standalone
    // rather than via a systemd unit that provisions RuntimeDirectory.
    if let Some(parent) = socket_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    let listener = UnixListener::bind(&socket_path)?;
    restrict_socket_perms(&socket_path)?;
    tracing::info!(?socket_path, "daemon listening");

    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                tracing::info!("shutdown signal received");
                break;
            }
            accepted = listener.accept() => {
                let (stream, _addr) = accepted?;
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, handler).await {
                        tracing::warn!(?e, "connection error");
                    }
                });
            }
        }
    }

    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

async fn handle_connection(
    stream: UnixStream,
    handler: Arc<dyn RequestHandler>,
) -> std::io::Result<()> {
    let stream = BufStream::new(stream);
    // Split into independent read/write halves so the connection loop can keep
    // reading requests while the handler's event sink pushes frames on the
    // write half concurrently.
    let (mut read_half, write_half) = tokio::io::split(stream);
    let write_arc = Arc::new(tokio::sync::Mutex::new(write_half));

    // Sink that serializes a VpnEvent into an IpcResponse::Event frame and
    // writes it to the shared write half. The handler may call this from tasks
    // spawned to forward the controller's event broadcast onto this connection.
    let sink: EventSink = {
        let write_arc = write_arc.clone();
        Arc::new(move |evt: crate::ipc::VpnEvent| {
            let write_arc = write_arc.clone();
            tokio::spawn(async move {
                let mut guard = write_arc.lock().await;
                let resp = IpcResponse::Event(evt);
                if let Err(e) = write_frame(&mut *guard, &resp).await {
                    tracing::debug!(?e, "failed to push event");
                }
            });
        })
    };

    loop {
        let req: IpcRequest = match read_frame(&mut read_half).await {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };

        let id = req_id(&req);
        let req_kind = req_kind_name(&req);

        // Dispatch synchronously to keep request-response ordering simple.
        // The handler spawns its own async work and uses `sink` (shared write
        // half) to push intermediate events back on the same connection.
        let result = handler.handle(req, sink.clone());
        let resp = match result {
            Ok(Some(data)) => IpcResponse::Ok {
                id,
                data: Some(data),
            },
            Ok(None) => IpcResponse::Ok { id, data: None },
            Err(message) => IpcResponse::Err {
                id,
                code: 1,
                message,
            },
        };
        {
            let mut guard = write_arc.lock().await;
            write_frame(&mut *guard, &resp).await?;
        }
        tracing::trace!(id, kind = req_kind, "responded");
    }
}

fn req_id(req: &IpcRequest) -> u64 {
    match req {
        IpcRequest::Connect { id, .. }
        | IpcRequest::Disconnect { id }
        | IpcRequest::State { id }
        | IpcRequest::Ping { id } => *id,
    }
}

fn req_kind_name(req: &IpcRequest) -> &'static str {
    match req {
        IpcRequest::Connect { .. } => "connect",
        IpcRequest::Disconnect { .. } => "disconnect",
        IpcRequest::State { .. } => "state",
        IpcRequest::Ping { .. } => "ping",
    }
}

/// Lock down socket permissions to 0600 so only the owning UID can connect.
/// Falls back to a warning on filesystems where chmod is unsupported (e.g.
/// some tmpfs / 9p mounts) — the caller is expected to set umask before
/// invocation as a defense-in-depth.
fn restrict_socket_perms(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
}
