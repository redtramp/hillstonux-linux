//! Daemon instance management: pidfile, stale-instance detection and
//! replacement.
//!
//! 守护进程是每用户单实例。本模块有两个入口：
//! - 守护进程启动时（[`take_over_previous_instances`]）：若同用户下仍有旧实例
//!   在运行（例如 `cargo build` 重编译后残留的旧二进制进程），先停掉它，再由
//!   新进程绑定 socket，避免新旧两代守护进程并存；
//! - GUI 连接前（[`replace_stale_daemon`]）：若 socket 后面站着一个"过期"守护
//!   进程（其磁盘二进制已被替换/删除，再经 pkexec 自拉起必然失败），停掉它，让
//!   GUI 走"拉起新构建"路径。健康的同版本守护进程绝不会被误杀——VPN 会话必须
//!   能跨 GUI 重启存活。

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// 磁盘上守护进程二进制的名字。
pub const DAEMON_BIN_NAME: &str = "hillstonux-daemon";

/// 内核对已删除可执行文件追加到 /proc/<pid>/exe 路径末尾的字面量后缀。
const DELETED_SUFFIX: &str = " (deleted)";

/// SIGTERM 之后给旧实例的优雅退出宽限。
const KILL_GRACE: Duration = Duration::from_secs(3);
/// SIGKILL 之后的最终等待预算。
const KILL_HARD_WAIT: Duration = Duration::from_secs(5);

/// pidfile 与 socket 同目录同名（仅扩展名不同）：`hillstonux.sock` → `hillstonux.pid`。
pub fn pidfile_path(socket: &Path) -> PathBuf {
    socket.with_extension("pid")
}

/// 把本进程 PID 写入 pidfile。
pub fn write_pidfile(socket: &Path) -> std::io::Result<()> {
    std::fs::write(pidfile_path(socket), std::process::id().to_string())
}

/// 尽力删除 pidfile（关闭 / 清理过期条目时）。
pub fn remove_pidfile(socket: &Path) {
    let _ = std::fs::remove_file(pidfile_path(socket));
}

/// 读 `/proc/<pid>/exe`。进程已退出或无权限时返回 `None`；返回的路径可能带
/// 内核为已删除二进制追加的字面量 `" (deleted)"` 后缀。
pub fn exe_of_pid(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

/// exe 路径是否已被内核标记为删除（文件已不在磁盘上，无法再被执行）。
pub fn exe_is_deleted(exe: &Path) -> bool {
    exe.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(DELETED_SUFFIX))
}

/// 当前进程的有效 UID。
fn current_uid() -> u32 {
    // SAFETY: geteuid 始终安全。
    unsafe { libc::geteuid() }
}

/// 进程 `pid` 的属主 UID（读 /proc/<pid> 目录的元数据）。
fn process_uid(pid: u32) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(format!("/proc/{pid}"))
        .ok()
        .map(|md| md.uid())
}

/// `pid` 是否是本守护进程（非 privhelper）的实例，且属于用户 `uid`。
///
/// 校验链逐级过滤，防止 PID 复用误伤无关进程：comm 匹配 → cmdline 不含
/// `--privhelper` → 属主是 `uid` → /proc/<pid>/exe 基名（去掉 deleted 后缀）
/// 匹配二进制名。
/// comm 字段被内核截断为最多 15 个字符（TASK_COMM_LEN-1）。二进制名
/// "hillstonux-daemon" 有 17 个字符，comm 里实际是 "hillstonux-daem"。
/// comm 仅作廉价预过滤（可能与其他名字前 15 字符相同的进程碰撞），最终以
/// /proc/<pid>/exe 的完整基名为准。
fn expected_comm() -> &'static str {
    // 二进制名为 ASCII，字节切片即字符切片。
    &DAEMON_BIN_NAME[..DAEMON_BIN_NAME.len().min(15)]
}

fn is_daemon_process(pid: u32, uid: u32) -> bool {
    let comm = match std::fs::read_to_string(format!("/proc/{pid}/comm")).ok() {
        Some(c) => c,
        None => return false,
    };
    if comm.trim() != expected_comm() {
        return false;
    }
    // privhelper 以 root 运行且 cmdline 带 --privhelper：我们无权杀它，且守护
    // 进程退出时它会随控制连接关闭自行退出，故跳过。
    if let Ok(bytes) = std::fs::read(format!("/proc/{pid}/cmdline")) {
        if bytes.split(|&b| b == 0).any(|arg| arg == b"--privhelper") {
            return false;
        }
    }
    if process_uid(pid) != Some(uid) {
        return false;
    }
    exe_of_pid(pid).is_some_and(|exe| exe_basename_is_daemon(&exe))
}

/// exe 路径的基名（去掉内核 deleted 后缀）是否等于守护进程二进制名。
fn exe_basename_is_daemon(exe: &Path) -> bool {
    let name = match exe.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };
    let clean = name.strip_suffix(DELETED_SUFFIX).unwrap_or(name);
    clean == DAEMON_BIN_NAME
}

/// 找出当前用户所有"守护进程模式"的 hillstonux-daemon 实例 PID（不含自身）。
pub fn find_daemon_pids() -> Vec<u32> {
    let self_pid = std::process::id();
    let uid = current_uid();
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return found;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pid == self_pid || !is_daemon_process(pid, uid) {
            continue;
        }
        found.push(pid);
    }
    found
}

/// 进程是否还活着。进程不存在、无权向其发信号、或已是僵尸（已退出、等待父
/// 进程收割）都视为"已消失"——否则 wait 循环会对僵尸空等到超时（kill(pid,0)
/// 对僵尸仍成功）。
pub fn process_alive(pid: u32) -> bool {
    // SAFETY: kill(pid, 0) 不发送信号，仅探测存在性与信号权限。
    if (unsafe { libc::kill(pid as libc::pid_t, 0) }) != 0 {
        return false;
    }
    proc_state(pid) != Some('Z')
}

/// /proc/<pid>/stat 中的进程状态字符（'R'、'S'、'Z'…），不可读时返回 None。
fn proc_state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm 字段用括号包裹且可能含空格，必须定位最后一个 ')' 才能正确取到
    // 其后第一个字段（state）。
    let rest = stat.rfind(')')? + 1;
    stat[rest..].trim_start().chars().next()
}

/// 向 `pid` 发 SIGTERM；宽限期内未退出则升级 SIGKILL。返回进程最终是否已消失。
pub fn kill_daemon_pid(pid: u32) -> bool {
    // SAFETY: kill 本身安全，错误经返回值体现。
    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } != 0 {
        return !process_alive(pid);
    }
    if wait_exit(pid, KILL_GRACE) {
        return true;
    }
    tracing::warn!(pid, "daemon ignored SIGTERM, escalating to SIGKILL");
    // SAFETY: 同上。
    let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    wait_exit(pid, KILL_HARD_WAIT)
}

fn wait_exit(pid: u32, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if !process_alive(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// 守护进程启动时调用：停掉"同一 socket 上"仍在运行的旧实例，返回被停掉的
/// PID。
///
/// 归属判定（防止误杀其他实例）：只有 pidfile 明确指向 `socket` 同目录的
/// daemon 才被视为旧实例。同名同 uid 但服务别处 socket 的进程（例如使用
/// /tmp 测试 socket 的测试实例）绝不会被杀掉。
///
/// 只有"新启动"的进程会调用本函数，旧实例不会反过来杀新进程，因此不存在互杀
/// 循环。本函数含阻塞等待，调用方应放在 blocking 线程池执行。
pub fn take_over_previous_instances(socket: &Path) -> Vec<u32> {
    let mut replaced = Vec::new();
    for pid in find_daemon_pids() {
        if !serves_socket_dir(pid, socket) {
            tracing::info!(
                pid,
                "leaving daemon instance alone (serves a different socket)"
            );
            continue;
        }
        tracing::info!(pid, "stopping previous daemon instance before taking over");
        if kill_daemon_pid(pid) {
            replaced.push(pid);
        } else {
            tracing::warn!(pid, "previous daemon instance did not exit");
        }
    }
    replaced
}

/// `pid` 是否服务于 `socket` 的守护进程。唯一采信的证据：`socket` 同目录下
/// 的 pidfile 内容等于 `pid`（本版本 daemon 在绑定 socket 前即写入 pidfile，
/// 优雅退出时移除；覆盖"重编译后残留旧二进制"的全部真实场景）。
///
/// 曾尝试用 `/proc/<pid>/fd` 的 socket inode 作兜底证据，实测不可行：
/// Unix socket 磁盘文件的 inode 与内核 socket 对象的 inode 是两个编号
/// （stat /proc/<pid>/fd/N 返回的又是第三个），无法关联。无证据 → 不杀。
fn serves_socket_dir(pid: u32, socket: &Path) -> bool {
    std::fs::read_to_string(pidfile_path(socket))
        .ok()
        .is_some_and(|text| text.trim() == pid.to_string())
}

/// GUI 连接前调用：`socket` 后面的守护进程若已过期（其二进制已被内核标记删除，
/// 或与 `candidate`——GUI 即将拉起的二进制——不是同一个磁盘文件），停掉它并返回
/// `true`，让调用方走"拉起新守护进程"路径。健康的同版本实例原样保留。
///
/// 本函数含阻塞等待，调用方应放在 blocking 线程池执行。
pub fn replace_stale_daemon(socket: &Path, candidate: &Path) -> bool {
    let Some(pid) = locate_daemon_pid(socket) else {
        return false;
    };
    let Some(exe) = exe_of_pid(pid) else {
        return false;
    };
    let stale = exe_is_deleted(&exe) || different_on_disk(&exe, candidate);
    if !stale {
        return false;
    }
    tracing::info!(
        pid,
        ?exe,
        ?candidate,
        "stopping stale daemon so a fresh build can take over"
    );
    kill_daemon_pid(pid)
}

/// 定位 `socket` 后面的守护进程 PID：优先 pidfile；pidfile 缺失或失效时退回
/// /proc 扫描（覆盖尚未写 pidfile 的旧版本守护进程）。退回扫描时只接受
/// 确实持有本 socket 的进程，避免把服务别处 socket 的实例（例如 /tmp 测试
/// 实例）误认成本 socket 的守护进程。
fn locate_daemon_pid(socket: &Path) -> Option<u32> {
    let uid = current_uid();
    if let Ok(text) = std::fs::read_to_string(pidfile_path(socket)) {
        if let Ok(pid) = text.trim().parse::<u32>() {
            if process_alive(pid) && is_daemon_process(pid, uid) {
                return Some(pid);
            }
            // 过期 pidfile（进程已退出，或 PID 已被复用）：清掉以免反复命中。
            remove_pidfile(socket);
        }
    }
    find_daemon_pids()
        .into_iter()
        .find(|pid| serves_socket_dir(*pid, socket))
}

/// 两个路径是否指向不同的磁盘文件（dev/ino 不同）。任一侧无法 stat 时视为
/// 相同（宁可漏判也不误杀）。
fn different_on_disk(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Some(ma), Some(mb)) = (std::fs::metadata(a).ok(), std::fs::metadata(b).ok()) else {
        return false;
    };
    ma.ino() != mb.ino() || ma.dev() != mb.dev()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pidfile_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("hillstonux.sock");
        write_pidfile(&socket).unwrap();
        let text = std::fs::read_to_string(pidfile_path(&socket)).unwrap();
        assert_eq!(text, std::process::id().to_string());
        remove_pidfile(&socket);
        assert!(!pidfile_path(&socket).exists());
    }

    #[test]
    fn pidfile_path_derives_pid_extension() {
        let p = pidfile_path(Path::new("/run/user/1000/hillstonux/hillstonux.sock"));
        assert_eq!(p, Path::new("/run/user/1000/hillstonux/hillstonux.pid"));
    }

    #[test]
    fn expected_comm_matches_kernel_truncation() {
        // 内核 comm 上限 15 字符；"hillstonux-daemon" 为 17 字符，必须比较
        // 截断形式，否则永远匹配不上（真实 /proc 行为）。
        assert_eq!(expected_comm(), "hillstonux-daem");
        assert_eq!(expected_comm().len(), 15);
    }

    #[test]
    fn deleted_suffix_detection() {
        assert!(exe_is_deleted(Path::new(
            "/a/b/hillstonux-daemon (deleted)"
        )));
        assert!(!exe_is_deleted(Path::new("/a/b/hillstonux-daemon")));
    }

    #[test]
    fn find_daemon_pids_never_reports_self() {
        let pids = find_daemon_pids();
        assert!(!pids.contains(&std::process::id()));
    }

    #[test]
    fn kill_daemon_pid_terminates_a_live_process() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        assert!(kill_daemon_pid(pid));
        // Reap so we don't leave a zombie behind.
        let status = child.wait().unwrap();
        assert!(!status.success());
    }

    #[test]
    fn stale_pidfile_is_cleaned_up() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("hillstonux.sock");
        // A PID that is not a live daemon instance of ours.
        std::fs::write(pidfile_path(&socket), "999999").unwrap();
        let _ = locate_daemon_pid(&socket);
        // The unusable pidfile entry was cleaned up.
        assert!(!pidfile_path(&socket).exists());
    }

    /// Regression (2026-10-23): a smoke-test daemon instance on a /tmp socket
    /// used to SIGTERM the user's real daemon at startup, because takeover
    /// killed every same-user daemon by name. Ownership now requires
    /// evidence (matching pidfile or matching socket inode).
    #[test]
    fn take_over_ignores_instances_without_ownership_evidence() {
        let our = tempfile::tempdir().unwrap();
        let our_socket = our.path().join("hillstonux.sock");

        // A foreign long-running process (proxy for a daemon serving some
        // other socket, e.g. a /tmp test socket).
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        assert!(
            !serves_socket_dir(pid, &our_socket),
            "process with no pidfile must not be considered ours"
        );
        assert!(
            take_over_previous_instances(&our_socket).is_empty(),
            "takeover must not kill a process without ownership evidence"
        );
        assert!(
            process_alive(pid),
            "foreign process must have survived takeover"
        );
        child.kill().expect("kill sleep");
        child.wait().expect("reap sleep");
    }

    /// Evidence logic of the takeover guard: only a pidfile in our socket
    /// dir naming the candidate counts; anything else (including a live
    /// daemon serving a different socket) is left alone. The positive kill
    /// path of the loop itself is covered by `kill_daemon_pid_terminates_a_live_process`
    /// plus the real incident of 2026-10-23; a full end-to-end masquerade is
    /// not possible in a unit test because `is_daemon_process` validates the
    /// /proc/<pid>/exe basename, which a re-executed test binary cannot
    /// satisfy without spawning the real daemon binary (whose startup
    /// residue recovery could disturb a live session).
    #[test]
    fn serves_socket_dir_pidfile_evidence() {
        let our = tempfile::tempdir().unwrap();
        let our_socket = our.path().join("hillstonux.sock");

        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();

        // No pidfile → no evidence → not ours.
        assert!(!serves_socket_dir(pid, &our_socket));

        // A pidfile in our dir naming this pid → ours.
        std::fs::write(pidfile_path(&our_socket), pid.to_string()).unwrap();
        assert!(serves_socket_dir(pid, &our_socket));

        // A pidfile naming a different pid does not match this candidate.
        let other = pid + 1;
        assert!(!serves_socket_dir(other, &our_socket));

        // A stale pidfile (dead pid) must not be treated as live ownership.
        std::fs::write(pidfile_path(&our_socket), "999999").unwrap();
        assert!(!serves_socket_dir(999999, &our_socket) || !process_alive(999999));

        child.kill().expect("kill sleep");
        child.wait().expect("reap sleep");
    }
}
