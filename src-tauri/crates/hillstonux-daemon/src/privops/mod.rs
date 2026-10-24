//! Privilege separation for system-level VPN operations.
//!
//! 守护进程通常以普通用户身份运行。需要 root 的操作（创建 TUN、改路由 / DNS）
//! 通过以下两种方式之一完成：
//! - 守护进程本身就是 root 时，直接执行（DirectOps）；
//! - 否则，通过 pkexec 拉起短生命周期的特权辅助进程（HelperClient），
//!   这会触发一次 polkit 认证弹窗（用户在首次连接时输入密码）。辅助进程通过
//!   SCM_RIGHTS 把 TUN fd 回传给守护进程。

pub mod protocol;

use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use hillstonux_core::client::NetworkConfig;
use hillstonux_net::{DnsManager, RouteManager, TunDevice};
use tokio::net::{UnixListener, UnixStream};

use self::protocol::{recv_fd, HelperRequest, HelperResponse};

/// 特权操作抽象层可能产生的错误。
#[derive(Debug, thiserror::Error)]
pub enum PrivError {
    #[error("io error: {0}")]
    Io(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    /// 用户未完成 polkit 认证（拒绝或等待超时）。
    #[error("{0}")]
    AuthCancelled(String),
    /// 辅助进程报告操作失败。
    #[error("privileged helper failed: {0}")]
    HelperFailed(String),
}

/// 系统级 VPN 操作的特权抽象。实现可以是直接执行（root），也可以是调用
/// 经 pkexec 拉起的辅助进程。
#[async_trait]
pub trait PrivilegedOps: Send + Sync {
    /// 创建 TUN 设备，返回由调用方拥有的句柄。
    async fn tun_create(&mut self, name: &str) -> Result<TunDevice, PrivError>;
    /// 拆除 TUN 设备（尽力而为）。
    async fn tun_destroy(&mut self, name: &str) -> Result<(), PrivError>;
    /// 快照主路由表并下发 VPN 路由。`full_tunnel` 控制路由策略：
    /// true = 全隧道（接管默认路由）；false = 分流（只路由服务端
    /// SET_ROUTE 下发的子网，外网保持直连）。
    async fn routes_apply(
        &mut self,
        cfg: &NetworkConfig,
        server_host: Ipv4Addr,
        tun_name: &str,
        full_tunnel: bool,
    ) -> Result<(), PrivError>;
    /// 恢复路由表到连接前状态。
    async fn routes_restore(&mut self) -> Result<(), PrivError>;
    /// 探测 DNS 后端并应用给定的服务器。
    async fn dns_apply(&mut self, dns: &[Ipv4Addr]) -> Result<(), PrivError>;
    /// 恢复 DNS 到连接前状态。
    async fn dns_restore(&mut self) -> Result<(), PrivError>;
}

/// DirectOps 场景下存放 DNS 状态文件的目录（与控制 socket 同目录）。
fn dns_state_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(|d| PathBuf::from(d).join("hillstonux"))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// 直接执行特权操作。用于守护进程本身已是 root 的场景（例如以 root 运行的
/// systemd 服务，或测试环境）。
pub struct DirectOps {
    route_mgr: Option<RouteManager>,
    dns_mgr: Option<DnsManager>,
}

impl DirectOps {
    pub fn new() -> Self {
        Self {
            route_mgr: None,
            dns_mgr: None,
        }
    }
}

impl Default for DirectOps {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PrivilegedOps for DirectOps {
    async fn tun_create(&mut self, name: &str) -> Result<TunDevice, PrivError> {
        TunDevice::create(name).map_err(|e| PrivError::Io(e.to_string()))
    }

    async fn tun_destroy(&mut self, name: &str) -> Result<(), PrivError> {
        // 尽力而为：删除网络接口。TUN 本身是非持久化的，关闭 fd 也会消失，
        // 但显式删除能在设备残留时保持干净。
        let _ = Command::new("ip")
            .args(["link", "del", "dev", name])
            .status();
        Ok(())
    }

    async fn routes_apply(
        &mut self,
        cfg: &NetworkConfig,
        server_host: Ipv4Addr,
        tun_name: &str,
        full_tunnel: bool,
    ) -> Result<(), PrivError> {
        let mut mgr = RouteManager::snapshot(tun_name, server_host)
            .await
            .map_err(|e| PrivError::Io(e.to_string()))?;
        mgr.apply_vpn_routes(cfg, full_tunnel)
            .await
            .map_err(|e| PrivError::Io(e.to_string()))?;
        self.route_mgr = Some(mgr);
        Ok(())
    }

    async fn routes_restore(&mut self) -> Result<(), PrivError> {
        if let Some(mut mgr) = self.route_mgr.take() {
            let _ = mgr.restore().await;
        }
        Ok(())
    }

    async fn dns_apply(&mut self, dns: &[Ipv4Addr]) -> Result<(), PrivError> {
        // DirectOps 场景（守护进程自身为 root）：状态文件与控制 socket 同目录。
        let mut mgr =
            DnsManager::with_paths("/etc/resolv.conf", dns_state_dir().join("dns-state.json"));
        mgr.restore_orphaned().await;
        mgr.apply(dns)
            .await
            .map_err(|e| PrivError::Io(e.to_string()))?;
        self.dns_mgr = Some(mgr);
        Ok(())
    }

    async fn dns_restore(&mut self) -> Result<(), PrivError> {
        if let Some(mut mgr) = self.dns_mgr.take() {
            let _ = mgr.restore().await;
        }
        Ok(())
    }
}

/// 通过 pkexec 拉起的特权辅助进程执行操作。守护进程（普通用户）持有到辅助
/// 进程的私有控制套接字；辅助进程存活于整个 VPN 会话期间，断开时随连接关闭
/// 而退出。
pub struct HelperClient {
    stream: UnixStream,
    child: tokio::process::Child,
}

/// 区分同一进程内多次拉起的辅助进程，避免它们共用一个控制套接字路径。
static HELPER_SEQ: AtomicU64 = AtomicU64::new(0);

/// 等待 polkit 认证的最长时间。KDE 的认证代理本身会等 5 分钟，守护进程不应
/// 比它更早放弃——用户可能需要切回桌面才能看到弹窗。
const AUTH_TIMEOUT: Duration = Duration::from_secs(300);

impl HelperClient {
    /// 通过 pkexec 拉起辅助进程并建立私有控制通道。阻塞到辅助进程连上来
    /// 为止；若用户取消认证弹窗，则不会连上来，最终超时并返回 AuthCancelled。
    pub async fn spawn() -> Result<Self, PrivError> {
        Self::spawn_with_program("pkexec").await
    }

    /// Testable core: `program` is `pkexec` in production and a stub in tests.
    async fn spawn_with_program(program: &str) -> Result<Self, PrivError> {
        let dir = runtime_socket_dir();
        let _ = std::fs::create_dir_all(&dir);
        // The socket name has to be unique per spawn, not just per process:
        // two helpers alive at the same time (a reconnect while the old one is
        // still shutting down) would otherwise fight over the same path and
        // the second bind would fail with EADDRINUSE.
        let seq = HELPER_SEQ.fetch_add(1, Ordering::Relaxed);
        let sock_path = dir.join(format!(
            "hillstonux-priv-{}-{}.sock",
            std::process::id(),
            seq
        ));
        let _ = std::fs::remove_file(&sock_path);

        let listener = UnixListener::bind(&sock_path)
            .map_err(|e| PrivError::Io(format!("bind privhelper socket: {e}")))?;
        // 仅用户本人（及 root）可连接。
        let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600));

        let exe = resolve_helper_exe()?;
        // pkexec has no `--keep-environment` option (only `--keep-cwd`). The
        // helper does not need the caller's environment: it receives the
        // socket path as an argument and runs system tools from pkexec's safe
        // PATH. Passing an unknown option made pkexec exit 127 immediately,
        // leaving the daemon waiting for a helper that could never connect.
        let mut child = tokio::process::Command::new(program)
            .arg(&exe)
            .arg("--privhelper")
            .arg(&sock_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| PrivError::Io(format!("failed to launch pkexec: {e}")))?;

        // 等待辅助进程连上来；同时监控 pkexec 退出。否则 pkexec 因参数错误/
        // 没有认证代理/用户取消而立即退出时，要等满超时才报错，还会留下
        // zombie 子进程。
        let deadline = tokio::time::Instant::now() + AUTH_TIMEOUT;
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|e| PrivError::Io(format!("wait pkexec: {e}")))?
            {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    use tokio::io::AsyncReadExt;
                    let _ = pipe.read_to_string(&mut stderr).await;
                }
                let _ = std::fs::remove_file(&sock_path);
                let detail = stderr.trim();
                // pkexec exit codes: 126 = the authentication dialog was
                // dismissed, 127 = "authorization refused" *or* a usage
                // error (an unknown option also exits 127). The stderr text
                // tells the two apart: only a refusal is a decision by the
                // user, and only that one must not be retried.
                let refused = detail.to_lowercase().contains("not authorized");
                if status.code() == Some(126) || refused {
                    return Err(PrivError::AuthCancelled(
                        "授权被拒绝：已取消 polkit 认证".into(),
                    ));
                }
                let msg = if detail.is_empty() {
                    format!("pkexec exited ({status})")
                } else {
                    format!("pkexec exited ({status}): {detail}")
                };
                return Err(PrivError::HelperFailed(msg));
            }

            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                let _ = std::fs::remove_file(&sock_path);
                let _ = child.start_kill();
                return Err(PrivError::AuthCancelled(format!(
                    "等待授权超时：请在弹出的对话框中输入密码（{} 分钟内有效）",
                    AUTH_TIMEOUT.as_secs() / 60
                )));
            }

            match tokio::time::timeout(Duration::from_millis(200).min(remaining), listener.accept())
                .await
            {
                Ok(Ok((stream, _))) => {
                    let _ = std::fs::remove_file(&sock_path);
                    return Ok(HelperClient { stream, child });
                }
                Ok(Err(e)) => {
                    let _ = std::fs::remove_file(&sock_path);
                    let _ = child.start_kill();
                    return Err(PrivError::Io(format!("accept privhelper: {e}")));
                }
                Err(_) => continue,
            }
        }
    }

    async fn request(&mut self, req: HelperRequest) -> Result<HelperResponse, PrivError> {
        crate::ipc::framing::write_frame(&mut self.stream, &req)
            .await
            .map_err(|e| PrivError::Protocol(format!("write_frame: {e}")))?;
        crate::ipc::framing::read_frame(&mut self.stream)
            .await
            .map_err(|e| PrivError::Protocol(format!("read_frame: {e}")))
    }
}

impl Drop for HelperClient {
    fn drop(&mut self) {
        // 守护进程放弃会话时，确保辅助进程（及其持有的路由 / DNS 状态）退出。
        // 残留的路由 / DNS 由下次启动的 residue recovery 清理。kill_on_drop
        // 会让 tokio 异步回收该子进程，避免在 Drop 里阻塞等待。
        let _ = self.child.start_kill();
    }
}

#[async_trait]
impl PrivilegedOps for HelperClient {
    async fn tun_create(&mut self, name: &str) -> Result<TunDevice, PrivError> {
        let resp = self
            .request(HelperRequest::TunCreate {
                name: name.to_string(),
            })
            .await?;
        match resp {
            HelperResponse::Ok { .. } => {
                let fd = recv_fd(self.stream.as_raw_fd())
                    .map_err(|e| PrivError::Io(format!("recv_fd: {e}")))?;
                TunDevice::from_fd(fd, name.to_string())
                    .map_err(|e| PrivError::Io(format!("from_fd: {e}")))
            }
            HelperResponse::Err { message } => Err(PrivError::HelperFailed(message)),
        }
    }

    async fn tun_destroy(&mut self, name: &str) -> Result<(), PrivError> {
        match self
            .request(HelperRequest::TunDestroy {
                name: name.to_string(),
            })
            .await?
        {
            HelperResponse::Ok { .. } => Ok(()),
            HelperResponse::Err { message } => Err(PrivError::HelperFailed(message)),
        }
    }

    async fn routes_apply(
        &mut self,
        cfg: &NetworkConfig,
        server_host: Ipv4Addr,
        tun_name: &str,
        full_tunnel: bool,
    ) -> Result<(), PrivError> {
        match self
            .request(HelperRequest::RoutesApply {
                client_ip: cfg.client_ip,
                netmask: cfg.netmask,
                gateway: cfg.gateway,
                server_host,
                tun_name: tun_name.to_string(),
                routes: cfg.routes.clone(),
                full_tunnel,
            })
            .await?
        {
            HelperResponse::Ok { .. } => Ok(()),
            HelperResponse::Err { message } => Err(PrivError::HelperFailed(message)),
        }
    }

    async fn routes_restore(&mut self) -> Result<(), PrivError> {
        match self.request(HelperRequest::RoutesRestore).await? {
            HelperResponse::Ok { .. } => Ok(()),
            HelperResponse::Err { message } => Err(PrivError::HelperFailed(message)),
        }
    }

    async fn dns_apply(&mut self, dns: &[Ipv4Addr]) -> Result<(), PrivError> {
        match self
            .request(HelperRequest::DnsApply { dns: dns.to_vec() })
            .await?
        {
            HelperResponse::Ok { .. } => Ok(()),
            HelperResponse::Err { message } => Err(PrivError::HelperFailed(message)),
        }
    }

    async fn dns_restore(&mut self) -> Result<(), PrivError> {
        match self.request(HelperRequest::DnsRestore).await? {
            HelperResponse::Ok { .. } => Ok(()),
            HelperResponse::Err { message } => Err(PrivError::HelperFailed(message)),
        }
    }
}

fn runtime_socket_dir() -> PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let mut p = base;
    p.push("hillstonux");
    p
}

/// 本守护进程的二进制名。当 `current_exe()` 不再指向磁盘上真实存在的文件时，
/// 用它重新定位可执行文件（见 [`resolve_helper_exe`]）。
const BIN_NAME: &str = "hillstonux-daemon";

/// 解析要交给 pkexec 的本守护进程可执行文件路径。
///
/// Linux 上 `std::env::current_exe()` 读取 `/proc/self/exe`。若本进程仍在运行、
/// 但其二进制文件已被替换或删除（例如开发期 `cargo build` 重新链接），内核会在
/// 路径末尾追加字面量 ` (deleted)`——这不再是有效路径，直接交给 pkexec 会以
/// 退出码 127 / "No such file or directory" 失败。
///
/// 因此优先使用 `current_exe()`（文件仍存在于磁盘时）；否则去掉 ` (deleted)`
/// 后缀再检查（覆盖原地重编译的情形，此时二进制通常已被重建在原位置）；仍不
/// 存在则依次回退到 PATH 与打包安装的 `/usr/bin` 位置（与 GUI 定位守护进程的
/// 顺序一致）。全部落空时返回明确错误，而不是让 pkexec 抛出难以理解的 127。
fn resolve_helper_exe() -> Result<PathBuf, PrivError> {
    let current =
        std::env::current_exe().map_err(|e| PrivError::Io(format!("current_exe: {e}")))?;
    if current.is_file() {
        return Ok(current);
    }

    // 磁盘上的文件已被 unlink，`current_exe()` 返回的路径带 " (deleted)" 后缀。
    // 重新检查去掉后缀后的干净路径：原地重编译（cargo build）很可能已在原位置
    // 重建了二进制。
    if let Some(stripped) = strip_deleted_suffix(&current) {
        if stripped.is_file() {
            return Ok(stripped);
        }
    }

    // 回退：先查 PATH，再查打包安装位置（与 GUI 侧 daemon_binary_path 的顺序一致）。
    // pkexec 要求绝对路径，跳过空条目与相对条目。
    let mut candidates = Vec::new();
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            if !dir.is_empty() && Path::new(dir).is_absolute() {
                candidates.push(Path::new(dir).join(BIN_NAME));
            }
        }
    }
    candidates.push(Path::new("/usr/bin").join(BIN_NAME));

    for cand in candidates {
        if cand.is_file() {
            return Ok(cand);
        }
    }

    Err(PrivError::Io(format!(
        "无法在磁盘上定位 {BIN_NAME} 可执行文件：当前运行中的可执行文件 \
         ({current}) 已被替换或删除。请重新构建并重启守护进程，或重新安装包。",
        current = current.display()
    )))
}

/// 若 `path` 的文件名带有内核为已删除可执行文件追加的 ` (deleted)` 后缀，
/// 返回去掉该后缀后的路径；否则返回 `None`。
fn strip_deleted_suffix(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    let clean = name.strip_suffix(" (deleted)")?;
    let mut p = path.to_path_buf();
    p.pop();
    p.push(clean);
    Some(p)
}

/// 选择特权策略。已是 root 时直接操作；否则通过 pkexec 拉起辅助进程。
pub async fn ensure_privileged_ops() -> Result<Box<dyn PrivilegedOps>, PrivError> {
    // SAFETY: geteuid 始终安全。
    if unsafe { libc::geteuid() } == 0 {
        Ok(Box::new(DirectOps::new()))
    } else {
        let client = HelperClient::spawn().await?;
        Ok(Box::new(client))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    /// A privilege helper that exits immediately must be reported promptly,
    /// not after the accept timeout. This is the regression that made
    /// the GUI sit on `exchange_key` when pkexec rejected an unknown option.
    #[tokio::test]
    async fn fast_helper_failure_is_reported_promptly() {
        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("stub-privilege-wrapper");
        std::fs::write(&stub, "#!/bin/sh\necho 'Unknown option' >&2\nexit 127\n").unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();

        let start = Instant::now();
        let err = match HelperClient::spawn_with_program(stub.to_str().unwrap()).await {
            Ok(_) => panic!("stub helper must fail"),
            Err(err) => err,
        };
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "failure took {:?}, expected a prompt error",
            start.elapsed()
        );
        let msg = err.to_string();
        assert!(msg.contains("Unknown option"), "unexpected error: {msg}");
    }

    /// A refused authorization has to be reported as such: it must not be
    /// retried, because every retry raises another polkit prompt for
    /// something the user just declined.
    #[tokio::test]
    async fn refused_authorization_is_reported_as_auth_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("stub-refuse-authorization");
        std::fs::write(
            &stub,
            "#!/bin/sh\necho 'Error executing command as another user: Not authorized' >&2\nexit 127\n",
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();

        let err = match HelperClient::spawn_with_program(stub.to_str().unwrap()).await {
            Ok(_) => panic!("stub helper must fail"),
            Err(err) => err,
        };
        assert!(
            matches!(err, PrivError::AuthCancelled(_)),
            "expected AuthCancelled, got {err:?}"
        );
    }
}
