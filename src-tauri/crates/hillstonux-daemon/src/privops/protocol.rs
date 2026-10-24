//! Protocol between the unprivileged daemon and the privileged helper.
//!
//! 守护进程通常以普通用户身份运行。创建 TUN、修改路由 / DNS 这类需要 root
//! 的操作被委托给 hillstonux-privhelper：该辅助进程通过 pkexec 按需拉起，
//! 会触发 polkit 认证弹窗（用户首次连接时输入密码）。两者通过一条私有 Unix
//! 套接字通信，使用长度前缀 JSON 帧（复用 ipc 的帧格式），并通过
//! SCM_RIGHTS 辅助消息把 TUN 文件描述符回传给守护进程。

use std::io;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;

use serde::{Deserialize, Serialize};

use hillstonux_core::client::Route;

/// 守护进程 -> 辅助进程 的请求。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HelperRequest {
    /// 创建 TUN 设备。辅助进程先回复 Ok { name }，再以 SCM_RIGHTS 消息回传
    /// 设备 fd。
    TunCreate { name: String },
    /// 拆除 TUN 设备（尽力而为地 ip link del）。
    TunDestroy { name: String },
    /// 快照主路由表并下发 VPN 路由。`full_tunnel` 为 true 时接管默认路由，
    /// 否则只把 `routes` 里的子网路由进隧道（分流，外网保持直连）；
    /// `routes` 为空时只有 VPN 子网走隧道，绝不隐式接管默认路由。
    RoutesApply {
        client_ip: Ipv4Addr,
        netmask: u8,
        gateway: Ipv4Addr,
        server_host: Ipv4Addr,
        tun_name: String,
        routes: Vec<Route>,
        full_tunnel: bool,
    },
    /// 恢复 RoutesApply 时保存的路由表快照。
    RoutesRestore,
    /// 探测 DNS 后端并应用给定的 DNS 服务器。
    DnsApply { dns: Vec<Ipv4Addr> },
    /// 恢复 DNS 到连接前状态。
    DnsRestore,
}

/// 辅助进程 -> 守护进程的回复。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HelperResponse {
    Ok { name: Option<String> },
    Err { message: String },
}

/// 同步把一段 JSON 帧写入 W（长度前缀 + JSON 字节）。
#[allow(dead_code)]
pub fn write_frame_sync<W: io::Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let json =
        serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = (json.len() as u32).to_be_bytes();
    w.write_all(&len)?;
    w.write_all(&json)?;
    w.flush()?;
    Ok(())
}

/// 同步从 R 读取一段 JSON 帧。
#[allow(dead_code)]
pub fn read_frame_sync<R: io::Read, T: serde::de::DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut json = vec![0u8; len];
    r.read_exact(&mut json)?;
    serde_json::from_slice(&json).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

// ---------------------------------------------------------------------------
// SCM_RIGHTS 文件描述符传递。仅在守护进程与辅助进程之间的私有控制套接字上使用。
// ---------------------------------------------------------------------------

fn cmsg_align(len: usize) -> usize {
    let align = std::mem::size_of::<libc::size_t>();
    (len + align - 1) & !(align - 1)
}

fn cmsg_space(len: usize) -> usize {
    cmsg_align(std::mem::size_of::<libc::cmsghdr>()) + cmsg_align(len)
}

fn cmsg_len(len: usize) -> usize {
    std::mem::size_of::<libc::cmsghdr>() + len
}

fn set_blocking(fd: RawFd, blocking: bool) -> io::Result<()> {
    unsafe {
        // SAFETY: `fd` 是调用方持有的有效已打开套接字 fd；F_GETFL/F_SETFL
        // 只读写文件状态标志，不触碰任何指针。
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let new_flags = if blocking {
            flags & !libc::O_NONBLOCK
        } else {
            flags | libc::O_NONBLOCK
        };
        if libc::fcntl(fd, libc::F_SETFL, new_flags) < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// 读取套接字当前的阻塞状态。
fn is_blocking(fd: RawFd) -> io::Result<bool> {
    unsafe {
        // SAFETY: 同 `set_blocking` —— 有效 fd 上只读文件状态标志。
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(flags & libc::O_NONBLOCK == 0)
    }
}

/// 临时切到阻塞模式执行 `op`，之后恢复调用方原本的模式。
///
/// 传输 fd 时必须阻塞：对端可能还没把控制消息发过来。但也不能把阻塞状态
/// 留在套接字上——守护进程随后把同一个套接字交给 tokio 运行时，普通的
/// `std` 调用方也期望自己的设置不被改动。
fn with_blocking<T>(fd: RawFd, op: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let was_blocking = is_blocking(fd)?;
    if !was_blocking {
        set_blocking(fd, true)?;
    }
    let result = op();
    if !was_blocking {
        let _ = set_blocking(fd, false);
    }
    result
}

/// 通过 Unix 套接字把文件描述符发送给对端（SCM_RIGHTS）。
///
/// target_fd 为已连接的 Unix 套接字 fd；fd_to_send 会被复制到对端进程，
/// 发送方这一侧仍然保持打开。
pub fn send_fd(target_fd: RawFd, fd_to_send: RawFd) -> io::Result<()> {
    unsafe {
        // SAFETY: `buf`/`cmsg_buf` 是栈上局部变量，生命周期覆盖整个调用；
        // `msghdr` zeroed 后逐字段显式初始化，`msg_control` 指向 `cmsg_buf`；
        // `cmsg_buf` 按 `cmsg_space` 精确容纳一条 SCM_RIGHTS 控制消息，
        // `CMSG_DATA` 落在其内部。
        let mut buf = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let cmsg_space = cmsg_space(std::mem::size_of::<RawFd>());
        let mut cmsg_buf = vec![0u8; cmsg_space];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len() as _;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::other("CMSG_FIRSTHDR returned null"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = cmsg_len(std::mem::size_of::<RawFd>()) as _;
        std::ptr::copy_nonoverlapping(
            &fd_to_send as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );

        // 暂时切到阻塞模式，避免对端尚未就绪时返回 EAGAIN。
        with_blocking(target_fd, || {
            let n = libc::sendmsg(target_fd, &msg, 0);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })
    }
}

/// 从 Unix 套接字接收对端通过 SCM_RIGHTS 发送的文件描述符。
pub fn recv_fd(target_fd: RawFd) -> io::Result<RawFd> {
    unsafe {
        // SAFETY: msghdr/iov/cmsg_buf 的构造与 `send_fd` 相同（局部变量、
        // 完整初始化、缓冲尺寸精确匹配一条 SCM_RIGHTS 消息）；recvmsg 同步
        // 填充 `msg`，后续读取前校验了控制消息的 level/type/长度。
        let mut buf = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let cmsg_space = cmsg_space(std::mem::size_of::<RawFd>());
        let mut cmsg_buf = vec![0u8; cmsg_space];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len() as _;

        with_blocking(target_fd, || {
            let n = libc::recvmsg(target_fd, &mut msg, 0);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n)
        })?;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::other("no control message received"));
        }
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::other("unexpected control message"));
        }
        // 校验控制消息长度：防止对端发来截断的 SCM_RIGHTS 时读到未初始化数据。
        if (*cmsg).cmsg_len < cmsg_len(std::mem::size_of::<RawFd>()) {
            return Err(io::Error::other("truncated SCM_RIGHTS control message"));
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            &mut fd as *mut RawFd as *mut u8,
            std::mem::size_of::<RawFd>(),
        );
        if fd < 0 {
            return Err(io::Error::other("received invalid fd"));
        }
        Ok(fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn frame_roundtrip() {
        let mut buf: Vec<u8> = Vec::new();
        let req = HelperRequest::TunCreate {
            name: "hillstonux0".into(),
        };
        write_frame_sync(&mut buf, &req).unwrap();
        let back: HelperRequest = read_frame_sync(&mut buf.as_slice()).unwrap();
        match back {
            HelperRequest::TunCreate { name } => assert_eq!(name, "hillstonux0"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn fd_passing_roundtrip() {
        // 通过 socketpair 在进程内验证 SCM_RIGHTS 传递，不依赖 root。
        use std::os::unix::net::UnixListener;
        let (a, b) = UnixListener::bind("/tmp/hlx-test-sock")
            .and_then(|l| {
                let a = std::os::unix::net::UnixStream::connect("/tmp/hlx-test-sock")?;
                let (b, _) = l.accept()?;
                let _ = std::fs::remove_file("/tmp/hlx-test-sock");
                Ok((a, b))
            })
            .expect("socketpair");
        let sent = a.as_raw_fd();
        let handle = std::thread::spawn(move || {
            send_fd(a.as_raw_fd(), sent).unwrap();
        });
        let received = recv_fd(b.as_raw_fd()).unwrap();
        handle.join().unwrap();
        assert!(received >= 0);
        unsafe {
            libc::close(received);
        }
    }
}
