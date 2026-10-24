//! DNS 管理 —— 非侵入式（直写 `/etc/resolv.conf`）。
//!
//! 对齐 Python 参考实现（hilldust/platform_linux.py）：备份原文件、写入
//! VPN DNS、断开时从备份恢复。不触碰 NetworkManager / systemd-resolved：
//! - 不会对正在运行的物理网卡产生副作用（旧实现的 `nmcli dev reapply` 会
//!   重置网卡配置，触发 firewalld 重新评估接口区域）；
//! - 不会永久污染 NM 连接 profile（旧实现的 `nmcli con mod` 会把 VPN DNS
//!   写进 profile，断开甚至重启后仍残留）；
//! - 重启后系统自愈：profile 未被修改，NM/resolved 会自行重写干净的
//!   resolv.conf。
//!
//! 若 `/etc/resolv.conf` 是符号链接（systemd-resolved 的 stub），先移除
//! 链接再写入常规文件；恢复时移除文件并重建原链接。
//!
//! 异常退出保障：写入 VPN DNS 时把备份持久化到状态文件
//! （`<控制socket目录>/dns-state.json`）。守护进程崩溃或被 SIGKILL（内存
//! 快照丢失）后，下次连接前调用 [`DnsManager::restore_orphaned`] 从该文件
//! 恢复，保证"程序退出后网络能正常恢复"。

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("dns state file: {0}")]
    State(String),
}

/// 连接前的 DNS 状态备份（唯一持久快照）。
#[derive(Debug, Clone, PartialEq)]
pub enum DnsSnapshot {
    /// 常规文件：保存原始字节内容。
    File { content: Vec<u8> },
    /// 符号链接：保存链接目标（目标文件由系统管理，我们从不改动它）。
    Symlink { target: PathBuf },
    /// 原本不存在（罕见）。
    Missing,
}

impl DnsSnapshot {
    /// 序列化为状态文件内容（自包含的三行文本格式，不引入 JSON 依赖）。
    pub fn to_bytes(&self) -> Result<Vec<u8>, DnsError> {
        let mut out = String::from("1\n");
        match self {
            DnsSnapshot::File { content } => {
                out.push_str("file\n");
                out.push_str(&hex_encode(content));
                out.push('\n');
            }
            DnsSnapshot::Symlink { target } => {
                out.push_str(&format!("symlink:{}\n", target.display()));
            }
            DnsSnapshot::Missing => out.push_str("missing\n"),
        }
        Ok(out.into_bytes())
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, DnsError> {
        let text =
            std::str::from_utf8(raw).map_err(|e| DnsError::State(format!("not utf8: {e}")))?;
        let mut lines = text.lines();
        let version = lines
            .next()
            .ok_or_else(|| DnsError::State("empty state".to_string()))?;
        if version != "1" {
            return Err(DnsError::State(format!("unsupported version: {version}")));
        }
        let kind = lines
            .next()
            .ok_or_else(|| DnsError::State("missing kind line".to_string()))?;
        if kind == "file" {
            let hex = lines
                .next()
                .ok_or_else(|| DnsError::State("missing content line".to_string()))?;
            let content = hex_decode(hex.trim())
                .ok_or_else(|| DnsError::State("bad hex content".to_string()))?;
            Ok(DnsSnapshot::File { content })
        } else if let Some(target) = kind.strip_prefix("symlink:") {
            Ok(DnsSnapshot::Symlink {
                target: PathBuf::from(target),
            })
        } else if kind == "missing" {
            Ok(DnsSnapshot::Missing)
        } else {
            Err(DnsError::State(format!("unrecognized kind: {kind}")))
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

pub struct DnsManager {
    resolv_path: PathBuf,
    state_path: PathBuf,
    snapshot: Option<DnsSnapshot>,
}

impl DnsManager {
    /// 生产入口（privhelper 侧）：`/etc/resolv.conf` + 状态文件位于控制
    /// socket 同目录（即 `$XDG_RUNTIME_DIR/hillstonux/`）。辅助进程以 root
    /// 运行且不继承守护进程的环境变量，故状态文件路径从 socket 路径推导。
    pub fn for_helper_socket_dir(socket_dir: impl Into<PathBuf>) -> Self {
        Self::with_paths(
            PathBuf::from("/etc/resolv.conf"),
            socket_dir.into().join("dns-state.json"),
        )
    }

    /// 测试/自定义入口：独立指定 resolv 文件与状态文件路径。
    pub fn with_paths(resolv_path: impl Into<PathBuf>, state_path: impl Into<PathBuf>) -> Self {
        Self {
            resolv_path: resolv_path.into(),
            state_path: state_path.into(),
            snapshot: None,
        }
    }

    /// 若存在上一次异常退出遗留的 DNS 状态文件，先恢复到连接前状态
    /// （尽力而为：失败仅记日志），使本次连接的快照取自干净状态。
    pub async fn restore_orphaned(&self) {
        match self.try_restore_orphaned().await {
            Ok(Some(_snap)) => {
                tracing::info!("restored DNS state left over from a previous abnormal exit");
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    ?e,
                    "failed to restore DNS state left over from a previous abnormal exit (continuing with current state)"
                );
            }
        }
    }

    async fn try_restore_orphaned(&self) -> Result<Option<DnsSnapshot>, DnsError> {
        let raw = match tokio::fs::read(&self.state_path).await {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let snap = DnsSnapshot::from_bytes(&raw)?;
        self.write_snapshot(&snap).await?;
        tokio::fs::remove_file(&self.state_path).await?;
        Ok(Some(snap))
    }

    /// 读取当前状态作为备份（幂等：首次备份为准）。
    pub async fn snapshot(&mut self) -> Result<(), DnsError> {
        if self.snapshot.is_some() {
            return Ok(());
        }
        let meta = match tokio::fs::symlink_metadata(&self.resolv_path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.snapshot = Some(DnsSnapshot::Missing);
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        let snap = if meta.file_type().is_symlink() {
            let target = tokio::fs::read_link(&self.resolv_path).await?;
            DnsSnapshot::Symlink { target }
        } else {
            let content = tokio::fs::read(&self.resolv_path).await?;
            DnsSnapshot::File { content }
        };
        self.snapshot = Some(snap);
        Ok(())
    }

    /// 写入 VPN DNS（对齐 Python 参考：每个地址一行 `nameserver <ip>`）。
    ///
    /// 原子替换：先写同目录临时文件再 rename，避免写一半留下残缺的
    /// resolv.conf。状态文件持久化为尽力而为：即使失败，内存快照仍可
    /// 支撑本次会话的 restore。
    pub async fn apply(&mut self, dns: &[Ipv4Addr]) -> Result<(), DnsError> {
        if self.snapshot.is_none() {
            self.snapshot().await?;
        }
        let mut buf = String::new();
        for d in dns {
            buf.push_str(&format!("nameserver {d}\n"));
        }
        // 符号链接先移除再写常规文件 —— 否则 fs::write 会跟随链接，覆盖
        // 系统管理的文件（例如 resolved 的 stub 文件）。
        if matches!(&self.snapshot, Some(DnsSnapshot::Symlink { .. })) {
            tokio::fs::remove_file(&self.resolv_path).await?;
        }
        write_file_atomic(&self.resolv_path, buf.as_bytes()).await?;
        // 持久化状态文件（孤儿恢复用）。root 以 0644 写出，守护进程
        // （普通用户）也能读取以提前告警。
        if let Some(snap) = &self.snapshot {
            match snap.to_bytes() {
                Ok(raw) => {
                    if let Err(e) = tokio::fs::write(&self.state_path, &raw).await {
                        tracing::warn!(
                            ?e,
                            "failed to write dns state file (abnormal-exit fallback unavailable)"
                        );
                    }
                }
                Err(e) => tracing::warn!(?e, "failed to serialize dns state file"),
            }
        }
        tracing::info!(dns = ?dns, path = ?self.resolv_path, "wrote VPN DNS");
        Ok(())
    }

    /// 恢复到连接前状态并清理状态文件。
    pub async fn restore(&mut self) -> Result<(), DnsError> {
        if let Some(snap) = self.snapshot.take() {
            self.write_snapshot(&snap).await?;
        }
        // 无论是否持有内存快照都清理状态文件（DirectOps 等场景下状态文件
        // 可能由更早的写入遗留）。
        match tokio::fs::remove_file(&self.state_path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        tracing::info!(path = ?self.resolv_path, "restored DNS");
        Ok(())
    }

    async fn write_snapshot(&self, snap: &DnsSnapshot) -> Result<(), DnsError> {
        match snap {
            DnsSnapshot::File { content } => {
                write_file_atomic(&self.resolv_path, content).await?;
            }
            DnsSnapshot::Symlink { target } => {
                // 先移除我们写入的常规文件（或残留链接），再重建原链接。
                remove_if_exists(&self.resolv_path).await?;
                std::os::unix::fs::symlink(target, &self.resolv_path)?;
            }
            DnsSnapshot::Missing => {
                remove_if_exists(&self.resolv_path).await?;
            }
        }
        Ok(())
    }
}

/// 同目录临时文件 + rename 的原子写入。
async fn write_file_atomic(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let name = path.file_name().map_or("resolv.conf".to_string(), |f| {
        f.to_string_lossy().into_owned()
    });
    let tmp = path.with_file_name(format!(".hillstonux-{name}.tmp"));
    tokio::fs::write(&tmp, content).await?;
    if let Err(e) = tokio::fs::rename(&tmp, path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e);
    }
    Ok(())
}

async fn remove_if_exists(path: &Path) -> std::io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_mgr(t: &tempfile::TempDir) -> DnsManager {
        DnsManager::with_paths(
            t.path().join("resolv.conf"),
            t.path().join("dns-state.json"),
        )
    }

    #[tokio::test]
    async fn file_apply_and_restore_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let resolv = dir.path().join("resolv.conf");
        tokio::fs::write(&resolv, b"# original\nnameserver 8.8.8.8\n")
            .await
            .unwrap();

        let mut m = tmp_mgr(&dir);
        m.apply(&[
            Ipv4Addr::new(10, 1, 252, 10),
            Ipv4Addr::new(114, 114, 114, 114),
        ])
        .await
        .unwrap();
        let applied = tokio::fs::read_to_string(&resolv).await.unwrap();
        assert_eq!(
            applied,
            "nameserver 10.1.252.10\nnameserver 114.114.114.114\n"
        );
        // 状态文件应存在（孤儿恢复用）
        assert!(dir.path().join("dns-state.json").exists());

        m.restore().await.unwrap();
        let restored = tokio::fs::read_to_string(&resolv).await.unwrap();
        assert_eq!(restored, "# original\nnameserver 8.8.8.8\n");
        // 状态文件被清理
        assert!(!dir.path().join("dns-state.json").exists());
    }

    #[tokio::test]
    async fn orphan_restore_recovers_after_crash() {
        // 模拟：apply 后进程崩溃（未 restore）→ 下次连接前经状态文件恢复。
        let dir = tempfile::tempdir().unwrap();
        let resolv = dir.path().join("resolv.conf");
        tokio::fs::write(&resolv, b"nameserver 8.8.8.8\n")
            .await
            .unwrap();

        {
            let mut m = tmp_mgr(&dir);
            m.apply(&[Ipv4Addr::new(10, 1, 252, 10)]).await.unwrap();
            // drop 而未 restore = 进程崩溃
        }
        assert_eq!(
            tokio::fs::read_to_string(&resolv).await.unwrap(),
            "nameserver 10.1.252.10\n"
        );

        // 下次连接前的预检恢复原状态
        let m2 = tmp_mgr(&dir);
        m2.restore_orphaned().await;
        assert_eq!(
            tokio::fs::read_to_string(&resolv).await.unwrap(),
            "nameserver 8.8.8.8\n"
        );

        // 随后正常 apply / restore
        let mut m2 = m2;
        m2.apply(&[Ipv4Addr::new(10, 1, 252, 10)]).await.unwrap();
        m2.restore().await.unwrap();
        assert_eq!(
            tokio::fs::read_to_string(&resolv).await.unwrap(),
            "nameserver 8.8.8.8\n"
        );
        assert!(!dir.path().join("dns-state.json").exists());
    }

    #[tokio::test]
    async fn symlink_apply_replaces_and_restores_link() {
        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("stub-resolv.conf");
        let resolv = dir.path().join("resolv.conf");
        tokio::fs::write(&stub, b"stub content - must stay untouched\n")
            .await
            .unwrap();
        std::os::unix::fs::symlink(&stub, &resolv).unwrap();

        let mut m = tmp_mgr(&dir);
        m.apply(&[Ipv4Addr::new(10, 1, 252, 10)]).await.unwrap();
        // 写入后应为常规文件
        let meta = std::fs::symlink_metadata(&resolv).unwrap();
        assert!(!meta.file_type().is_symlink());
        // 链接目标文件未被改动
        assert_eq!(
            std::fs::read_to_string(&stub).unwrap(),
            "stub content - must stay untouched\n"
        );

        m.restore().await.unwrap();
        let meta = std::fs::symlink_metadata(&resolv).unwrap();
        assert!(meta.file_type().is_symlink());
        assert_eq!(std::fs::read_link(&resolv).unwrap(), stub);
    }

    #[tokio::test]
    async fn missing_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = tmp_mgr(&dir);
        m.apply(&[Ipv4Addr::new(10, 1, 252, 10)]).await.unwrap();
        m.restore().await.unwrap();
        assert!(!dir.path().join("resolv.conf").exists());
        assert!(!dir.path().join("dns-state.json").exists());
    }

    #[test]
    fn snapshot_bytes_roundtrip() {
        for snap in [
            DnsSnapshot::File {
                content: b"abc\n\x00\xff".to_vec(),
            },
            DnsSnapshot::Symlink {
                target: PathBuf::from("/run/systemd/resolve/stub-resolv.conf"),
            },
            DnsSnapshot::Missing,
        ] {
            let raw = snap.to_bytes().unwrap();
            assert_eq!(DnsSnapshot::from_bytes(&raw).unwrap(), snap);
        }
        assert!(DnsSnapshot::from_bytes(b"garbage").is_err());
        assert!(DnsSnapshot::from_bytes(b"2\nfile\n").is_err());
        assert!(DnsSnapshot::from_bytes(b"").is_err());
    }
}
