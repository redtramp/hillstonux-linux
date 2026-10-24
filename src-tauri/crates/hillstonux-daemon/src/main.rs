//! Hillstonux daemon entry point.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{broadcast, Notify};
use tracing_subscriber::EnvFilter;

mod controller;
mod data_plane;
mod ipc;
mod privhelper;
mod privops;
mod server;
// instance 与 GUI 共享（见 lib 导出），bin 直接复用 lib 版本，避免重复编译。
use hillstonux_daemon::instance;
use hillstonux_net::RouteManager;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 特权辅助进程模式：由 pkexec 以 root 重新执行自身（--privhelper <sock>），
    // 在整个 VPN 会话期间为守护进程执行需要 root 的操作（创建 TUN、改路由 / DNS）。
    if let Some(idx) = std::env::args().position(|a| a == "--privhelper") {
        let sock = std::env::args()
            .nth(idx + 1)
            .ok_or_else(|| anyhow::anyhow!("missing --privhelper socket path"))?;
        init_logging();
        return privhelper::run(&sock).await;
    }

    init_logging();

    let socket_path: PathBuf = std::env::var_os("HILLSTONUX_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(default_socket_path);

    // 检测到上一次异常退出遗留的 DNS 状态文件则提前告警。实际恢复由辅助
    // 进程在下次连接前完成（需要 root）。
    if socket_path
        .parent()
        .map(|d| d.join("dns-state.json"))
        .is_some_and(|p| p.exists())
    {
        tracing::warn!(
            "detected dns-state.json left over from a previous abnormal exit: \
             system DNS may still be in VPN state; it will be restored before the next connect"
        );
    }

    let shutdown = Arc::new(Notify::new());
    install_signal_handlers(shutdown.clone())?;

    // DP5: instance takeover — 若同一 socket 上仍有旧实例在运行（例如重编译后
    // 残留的旧二进制进程），先停掉它，再由本进程绑定 socket，避免新旧两代
    // 守护进程并存。只接管服务于本 socket 的实例；其他 socket（如 /tmp 测试
    // socket）上的同名实例不受影响。阻塞等待放在 blocking 线程池。
    let socket_for_takeover = socket_path.clone();
    let replaced = tokio::task::spawn_blocking(move || {
        instance::take_over_previous_instances(&socket_for_takeover)
    })
    .await
    .unwrap_or_default();
    for pid in replaced {
        tracing::info!(?pid, "stopped previous daemon instance");
    }

    // DP4: residue recovery — clean up any leftover tun devices/routes from a
    // previous crash before starting the server. Best-effort: ignore failures
    // (no leftover state is also a valid outcome). The snapshot doubles as a
    // probe that `ip` is usable; on failure there is nothing to recover from
    // anyway, so warn and continue instead of panicking at startup.
    let tun_name = controller::Settings::default().tun_name;
    match hillstonux_net::RouteManager::snapshot(&tun_name, std::net::Ipv4Addr::new(0, 0, 0, 0))
        .await
    {
        Ok(_mgr) => {
            let _ = RouteManager::detect_residue_and_recover().await;
        }
        Err(e) => {
            tracing::warn!(?e, "route snapshot failed; skipping residue recovery")
        }
    }

    // Build a Controller and wire it into the IPC server. The controller
    // owns the connection state machine.
    let (event_tx, _event_rx) = broadcast::channel::<ipc::VpnEvent>(1024);
    // Log events for now; the GUI client receives them over the socket.
    let mut log_rx = event_tx.subscribe();
    tokio::spawn(async move {
        while let Ok(evt) = log_rx.recv().await {
            tracing::debug!(?evt, "vpn event");
        }
    });
    let controller = controller::Controller::new(controller::Settings::default(), event_tx.clone());
    let handler: Arc<dyn server::RequestHandler> =
        Arc::new(IpcBridge::new(controller.clone(), event_tx.clone()));
    // 记录 PID 到 socket 同目录的 pidfile，供 GUI 识别本实例（并在二进制过期
    // 时替换它）。尽力而为：失败不影响守护进程启动。
    let socket_for_pidfile = socket_path.clone();
    let _ = instance::write_pidfile(&socket_for_pidfile);
    server::run(socket_path, handler, shutdown).await?;
    // 优雅退出：若仍有活动会话，先完整拆除（数据面 → DNS → 路由 → TUN），
    // 保证"程序退出后网络正常恢复"。SIGKILL / 崩溃等无法走到这里的路径，
    // 由 DNS 状态文件的孤儿恢复（下次连接前）兜底。
    match tokio::time::timeout(std::time::Duration::from_secs(10), controller.disconnect()).await {
        Ok(Ok(())) => tracing::info!("active session torn down (or none) on exit"),
        Ok(Err(e)) => tracing::warn!(?e, "teardown on exit failed"),
        Err(_) => {
            tracing::warn!(
                "teardown on exit timed out; orphan DNS will be restored before the next connect"
            )
        }
    }
    instance::remove_pidfile(&socket_for_pidfile);
    Ok(())
}

/// 日志初始化：stderr 与持久化文件双写（`$XDG_STATE_HOME/hillstonux/daemon.log`）。
/// GUI 直接拉起的守护进程 stdout/stderr 指向 /dev/null，只有文件日志保证
/// 崩溃 / 异常退出之后仍可取证。
fn init_logging() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let registry = tracing_subscriber::registry().with(filter);
    let stderr_layer = tracing_subscriber::fmt::layer();

    let state_home = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let log_dir = state_home.join("hillstonux");

    match std::fs::create_dir_all(&log_dir) {
        Ok(()) => {
            let appender = tracing_appender::rolling::never(&log_dir, "daemon.log");
            let (nb, guard) = tracing_appender::non_blocking(appender);
            // guard 必须活到进程结束，否则后台 flush 线程退出后日志丢失。
            std::mem::forget(guard);
            registry
                .with(stderr_layer)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(nb),
                )
                .init();
        }
        Err(e) => {
            // 文件日志不可用不阻止启动：退回纯 stderr。
            eprintln!(
                "warning: cannot create log dir {}: {e}; file logging disabled",
                log_dir.display()
            );
            registry.with(stderr_layer).init();
        }
    }
}

fn default_socket_path() -> PathBuf {
    // $XDG_RUNTIME_DIR is per-user; falls back to /tmp for headless systems
    // without it (CI, etc.).
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir)
            .join("hillstonux")
            .join("hillstonux.sock");
    }
    PathBuf::from("/tmp/hillstonux.sock")
}

fn install_signal_handlers(shutdown: Arc<Notify>) -> anyhow::Result<()> {
    use futures_util::StreamExt;
    use signal_hook::consts::{SIGINT, SIGTERM};
    use signal_hook_tokio::Signals;

    let mut signals = Signals::new([SIGTERM, SIGINT])?;
    tokio::spawn(async move {
        if let Some(sig) = signals.next().await {
            tracing::info!(?sig, "received signal, shutting down");
            shutdown.notify_waiters();
        }
    });
    Ok(())
}

/// Bridge from `IpcRequest` to `Controller` methods. Lives here (rather than
/// in `controller.rs`) because it depends on the IPC types.
struct IpcBridge {
    controller: controller::Controller,
    events: tokio::sync::broadcast::Sender<ipc::VpnEvent>,
}

impl IpcBridge {
    fn new(
        controller: controller::Controller,
        events: tokio::sync::broadcast::Sender<ipc::VpnEvent>,
    ) -> Self {
        Self { controller, events }
    }
}

impl server::RequestHandler for IpcBridge {
    fn handle(
        &self,
        req: ipc::IpcRequest,
        sink: server::EventSink,
    ) -> Result<Option<serde_json::Value>, String> {
        let controller = self.controller.clone();
        match req {
            ipc::IpcRequest::Connect { params, .. } => {
                // Forward the controller's events to this connection's sink so
                // the GUI receives progress (connecting -> connected, stats...).
                let mut evt_rx = self.events.subscribe();
                let evt_sink = sink.clone();
                tokio::spawn(async move {
                    while let Ok(evt) = evt_rx.recv().await {
                        evt_sink(evt);
                    }
                });
                let controller = self.controller.clone();
                let sink = sink.clone();
                tokio::spawn(async move {
                    // connect_with_retry honors Settings::auto_reconnect +
                    // max_reconnect_attempts internally. The client sees
                    // events pushed via the sink for progress.
                    if let Err(e) = controller.connect_with_retry(params).await {
                        tracing::warn!(?e, "ipc connect (with retry) failed");
                        sink(crate::ipc::VpnEvent::LogLine {
                            level: ipc::LogLevel::Error,
                            msg: format!("connect failed: {e}"),
                        });
                    }
                });
                Ok(None)
            }
            ipc::IpcRequest::Disconnect { .. } => {
                let mut evt_rx = self.events.subscribe();
                let evt_sink = sink.clone();
                tokio::spawn(async move {
                    while let Ok(evt) = evt_rx.recv().await {
                        evt_sink(evt);
                    }
                });
                let controller = self.controller.clone();
                tokio::spawn(async move {
                    if let Err(e) = controller.disconnect().await {
                        tracing::warn!(?e, "ipc disconnect failed");
                    }
                });
                Ok(None)
            }
            ipc::IpcRequest::State { .. } => {
                // Synchronous query — read the current state and return it
                // as JSON so the GUI can render correctly on startup.
                let snapshot = controller
                    .try_state()
                    .ok_or_else(|| "state lock contended; retry".to_string())?;
                let value = serde_json::to_value(snapshot.phase)
                    .map_err(|e| format!("state serialization: {e}"))?;
                Ok(Some(value))
            }
            ipc::IpcRequest::Ping { .. } => Ok(None),
        }
    }
}
