//! TCP-style unix-socket client to the daemon. Used by the GUI's Tauri
//! commands to send IpcRequests and to stream VpnEvents back to the frontend
//! via app.emit.
//!
//! The client keeps a single unix-socket connection. A background reader task
//! demultiplexes the frames the daemon writes on that one connection:
//!   - IpcResponse::Event frames are forwarded to the Tauri event bus
//!     (re-emitted as vpn-event), and
//!   - IpcResponse::Ok / Err frames are routed to the pending request that
//!     is waiting for that id (via a oneshot).
//!
//! This is required because the daemon pushes both the request response AND
//! the (many) progress events on the SAME connection. Splitting the socket
//! into a write half (used by request()) and a read half (owned by the
//! reader) lets writes and reads proceed concurrently without corruption.
//!
//! The client is lazily connected and self-starting: IpcClient::new only
//! records the socket path and the event sender. The first time a connection
//! is needed, ensure_connected tries to reach the daemon and, if the socket is
//! missing, best-effort launches the daemon itself.

use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use hillstonux_daemon::ipc::framing::{read_frame, write_frame};
use hillstonux_daemon::ipc::{IpcRequest, IpcResponse, VpnEvent};
use thiserror::Error;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot, Mutex};

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("daemon not running at {0}")]
    NotRunning(PathBuf),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("connection closed")]
    Closed,
}

/// A handle to a (possibly not-yet-open) daemon connection. Cloning shares
/// the underlying connection; closing the last clone terminates the stream.
#[derive(Clone)]
pub struct IpcClient {
    inner: Arc<Mutex<IpcInner>>,
}

struct IpcInner {
    socket: PathBuf,
    next_id: u64,
    /// Set once we have attempted to launch the daemon, so we don't spawn it
    /// repeatedly on every reconnect attempt.
    start_attempted: bool,
    connected: bool,
    /// Serializes writes to the socket. The read half is owned by the reader
    /// task, so writers never touch it.
    write: Option<Arc<Mutex<WriteHalf<UnixStream>>>>,
    /// Pending request waiters, keyed by request id.
    pending: HashMap<u64, oneshot::Sender<IpcResponse>>,
    /// Where to forward Event frames (the Tauri event bus).
    event_tx: mpsc::UnboundedSender<VpnEvent>,
}

impl IpcClient {
    /// Create a handle bound to socket_path. The connection (and, if needed,
    /// the daemon itself) is opened lazily; event_tx receives every VpnEvent
    /// the daemon pushes so the GUI can update its UI.
    pub fn new(socket_path: PathBuf, event_tx: mpsc::UnboundedSender<VpnEvent>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(IpcInner {
                socket: socket_path,
                next_id: 1,
                start_attempted: false,
                connected: false,
                write: None,
                pending: HashMap::new(),
                event_tx,
            })),
        }
    }

    /// Ensure a live connection, (re)connecting and launching the daemon if
    /// necessary. Retries for a bounded time so a freshly-spawned daemon has
    /// a chance to create its socket before we give up.
    async fn ensure_connected(&self) -> Result<(), IpcError> {
        // Fast path: already connected.
        {
            let g = self.inner.lock().await;
            if g.connected && g.write.is_some() {
                return Ok(());
            }
        }

        let socket = self.inner.lock().await.socket.clone();
        // 若已有守护进程在监听、但其磁盘二进制已过期（重编译/删除后残留的旧
        // 进程，再经 pkexec 自拉起必然失败），先停掉它，让下面的拉起流程启动
        // 新构建，而不是继续和旧进程通信。健康的同版本实例不受影响。
        if socket.exists() {
            let candidate = daemon_binary_path();
            let sock = socket.clone();
            let stopped = tokio::task::spawn_blocking(move || {
                hillstonux_daemon::instance::replace_stale_daemon(&sock, Path::new(&candidate))
            })
            .await
            .unwrap_or(false);
            if stopped {
                // 刚停掉了旧实例：允许（重新）拉起守护进程。
                let mut g = self.inner.lock().await;
                g.start_attempted = false;
            }
        }
        for _ in 0..8 {
            match tokio::time::timeout(Duration::from_millis(1500), UnixStream::connect(&socket))
                .await
            {
                Ok(Ok(stream)) => {
                    let (read_half, write_half) = tokio::io::split(stream);
                    let mut g = self.inner.lock().await;
                    g.write = Some(Arc::new(Mutex::new(write_half)));
                    g.connected = true;
                    // Spawn the demultiplexing reader for this connection.
                    let reader_inner = self.inner.clone();
                    tokio::spawn(reader_loop(read_half, reader_inner));
                    return Ok(());
                }
                // Daemon not reachable yet: try to bring it up (once), then
                // wait briefly before retrying the connect.
                _ => {
                    let should_start = {
                        let mut g = self.inner.lock().await;
                        if !g.start_attempted {
                            g.start_attempted = true;
                            true
                        } else {
                            false
                        }
                    };
                    if should_start {
                        start_daemon(&socket);
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
        Err(IpcError::NotRunning(socket))
    }

    /// Send a request, await the matching reply. Concurrent calls are safe:
    /// each gets a unique id and its own oneshot waiter; the reader routes the
    /// response back by id.
    pub async fn request(&self, params: IpcRequestParams<'_>) -> Result<IpcResponse, IpcError> {
        self.ensure_connected().await?;

        let id = {
            let mut g = self.inner.lock().await;
            let id = g.next_id;
            g.next_id += 1;
            id
        };

        let req: IpcRequest = match params {
            IpcRequestParams::Connect {
                server,
                port,
                user,
                password,
                password_ref,
                full_tunnel,
            } => IpcRequest::Connect {
                id,
                params: hillstonux_daemon::ipc::ConnectParams {
                    server: server.into(),
                    port,
                    user: user.into(),
                    password: password.into(),
                    password_ref: password_ref.into(),
                    full_tunnel,
                },
            },
            IpcRequestParams::Disconnect => IpcRequest::Disconnect { id },
            IpcRequestParams::State => IpcRequest::State { id },
            IpcRequestParams::Ping => IpcRequest::Ping { id },
        };

        let (tx, rx) = oneshot::channel::<IpcResponse>();
        {
            let mut g = self.inner.lock().await;
            g.pending.insert(id, tx);
        }

        // Write the request. We clone the Arc<Mutex> out (independent of the
        // inner lock) so the reader is free to deliver responses concurrently
        // while we await the write.
        {
            let w = {
                let g = self.inner.lock().await;
                g.write.clone().ok_or(IpcError::Closed)?
            };
            let mut wh = w.lock().await;
            write_frame(&mut *wh, &req).await?;
        }

        match rx.await {
            Ok(resp) => Ok(resp),
            Err(_) => Err(IpcError::Closed),
        }
    }

    /// Close the underlying connection. After this, future request calls
    /// reconnect (and re-launch the daemon if needed) lazily.
    pub async fn close(&self) {
        let mut g = self.inner.lock().await;
        g.connected = false;
        g.write = None;
        // Dropping the waiters makes any in-flight request fail with Closed.
        g.pending.clear();
    }
}

/// Build parameters for an outgoing request.
pub enum IpcRequestParams<'a> {
    Connect {
        server: &'a str,
        port: u16,
        user: &'a str,
        password: &'a str,
        password_ref: &'a str,
        full_tunnel: bool,
    },
    Disconnect,
    State,
    Ping,
}

/// Background reader: owns the socket's read half and demultiplexes every
/// frame the daemon writes. Event frames go to the Tauri event bus; Ok/Err
/// frames are routed to the pending request waiting for that id.
async fn reader_loop(mut read_half: ReadHalf<UnixStream>, inner: Arc<Mutex<IpcInner>>) {
    loop {
        let resp: IpcResponse = match read_frame(&mut read_half).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[reader] read error: {e}");
                break;
            }
        };
        let mut g = inner.lock().await;
        match resp {
            IpcResponse::Event(evt) => {
                let _ = g.event_tx.send(evt);
            }
            IpcResponse::Ok { id, .. } | IpcResponse::Err { id, .. } => {
                if let Some(waiter) = g.pending.remove(&id) {
                    let _ = waiter.send(resp);
                }
            }
        }
    }
    // Connection lost: reset so future requests reconnect, and fail any
    // pending waiters.
    let mut g = inner.lock().await;
    g.connected = false;
    g.write = None;
    g.pending.clear();
}

/// Best-effort launch of the daemon so the GUI can connect immediately.
/// Prefers the user systemd unit (clean lifecycle plus auto-restart); falls
/// back to spawning the daemon binary directly — located via the sibling of
/// the GUI executable (dev / installed layout), then PATH, then the packaged
/// /usr/bin path. The spawned process is detached via process_group(0) so it
/// keeps running independently of the GUI's lifetime.
fn start_daemon(socket: &Path) {
    // 1. systemd user unit (idempotent if already running).
    if Command::new("systemctl")
        .args(["--user", "start", "hillstonux-daemon.service"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return;
    }

    // 2. Spawn the binary directly. The socket's parent dir is created by the
    //    daemon on bind, so we only need to find and run the executable.
    let bin = daemon_binary_path();
    tracing::info!(?bin, ?socket, "starting daemon directly");
    let _ = Command::new(&bin)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn();
}

/// Resolve the daemon executable path. Defaults to the daemon shipped in the
/// same directory as the running GUI (covers both dev builds and the installed
/// layout where both binaries sit together), then PATH, then the packaged
/// /usr/bin fallback.
fn daemon_binary_path() -> String {
    // 1. Same directory as the running GUI — preferred, since it matches the
    //    exact version of the GUI that is running.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("hillstonux-daemon");
            if sibling.exists() {
                return sibling.to_string_lossy().into_owned();
            }
        }
    }
    // 2. PATH (in case the daemon is installed elsewhere on PATH).
    if let Ok(out) = Command::new("sh")
        .args(["-c", "command -v hillstonux-daemon"])
        .output()
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return s;
            }
        }
    }
    // 3. Packaged fallback.
    "/usr/bin/hillstonux-daemon".to_string()
}
