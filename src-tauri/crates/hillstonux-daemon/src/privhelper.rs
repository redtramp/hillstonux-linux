//! 特权辅助进程逻辑。
//!
//! 该模块由守护进程经 pkexec 以 root 重新执行自身（--privhelper <sock>）
//! 进入。它连接到守护进程创建的私有控制套接字，在会话期间为守护进程执行
//! 需要 root 的操作（创建 TUN、改路由 / DNS），并在断开时随连接关闭退出。
//!
//! 与守护进程之间的通信使用长度前缀 JSON 帧（复用 ipc::framing），TUN fd
//! 则通过 SCM_RIGHTS 回传（见 privops::protocol::send_fd）。

use hillstonux_core::client::NetworkConfig;
use hillstonux_net::{DnsManager, RouteManager, TunDevice};

use crate::privops::protocol::{send_fd, HelperRequest, HelperResponse};
use std::os::unix::io::AsRawFd;

/// 进入辅助进程主循环：连接到 socket_path，逐个处理请求直到守护进程关闭
/// 连接（EOF）。
pub async fn run(socket_path: &str) -> anyhow::Result<()> {
    let mut stream = tokio::net::UnixStream::connect(socket_path).await?;

    // 会话期间保存的路由 / DNS 状态，断开时据此恢复。
    let mut route_mgr: Option<RouteManager> = None;
    let mut dns_mgr: Option<DnsManager> = None;

    loop {
        let req: HelperRequest = match crate::ipc::framing::read_frame(&mut stream).await {
            Ok(r) => r,
            Err(_) => break, // 守护进程关闭连接 → 退出
        };

        match req {
            HelperRequest::TunCreate { name } => {
                match TunDevice::create(&name) {
                    Ok(dev) => {
                        let raw = dev.as_raw_fd();
                        crate::ipc::framing::write_frame(
                            &mut stream,
                            &HelperResponse::Ok {
                                name: Some(name.clone()),
                            },
                        )
                        .await?;
                        // 通过 SCM_RIGHTS 把 TUN fd 回传给守护进程。
                        if let Err(e) = send_fd(stream.as_raw_fd(), raw) {
                            tracing::error!(?e, "privhelper: send_fd failed");
                        }
                        // 丢弃本地的 TunDevice（关闭辅助进程侧的 fd 副本）；
                        // 守护进程已持有 dup 出来的另一份，设备不会因此消失。
                        drop(dev);
                    }
                    Err(e) => {
                        let _ = crate::ipc::framing::write_frame(
                            &mut stream,
                            &HelperResponse::Err {
                                message: e.to_string(),
                            },
                        )
                        .await;
                    }
                }
            }
            HelperRequest::TunDestroy { name } => {
                let _ = std::process::Command::new("ip")
                    .args(["link", "del", "dev", &name])
                    .status();
                let _ = crate::ipc::framing::write_frame(
                    &mut stream,
                    &HelperResponse::Ok { name: None },
                )
                .await;
            }
            HelperRequest::RoutesApply {
                client_ip,
                netmask,
                gateway,
                server_host,
                tun_name,
                routes,
                full_tunnel,
            } => {
                let cfg = NetworkConfig {
                    client_ip,
                    netmask,
                    gateway,
                    dns: vec![],
                    server_udp_port: 0,
                    routes,
                };
                match RouteManager::snapshot(&tun_name, server_host).await {
                    Ok(mut mgr) => match mgr.apply_vpn_routes(&cfg, full_tunnel).await {
                        Ok(()) => {
                            route_mgr = Some(mgr);
                            let _ = crate::ipc::framing::write_frame(
                                &mut stream,
                                &HelperResponse::Ok { name: None },
                            )
                            .await;
                        }
                        Err(e) => {
                            // 部分下发失败（例如服务器绕行路由已添加）：回滚快照，
                            // 保证系统状态干净，重试时能重新取快照。
                            let _ = mgr.restore().await;
                            let _ = crate::ipc::framing::write_frame(
                                &mut stream,
                                &HelperResponse::Err {
                                    message: e.to_string(),
                                },
                            )
                            .await;
                        }
                    },
                    Err(e) => {
                        let _ = crate::ipc::framing::write_frame(
                            &mut stream,
                            &HelperResponse::Err {
                                message: e.to_string(),
                            },
                        )
                        .await;
                    }
                }
            }
            HelperRequest::RoutesRestore => {
                if let Some(mut mgr) = route_mgr.take() {
                    let _ = mgr.restore().await;
                }
                let _ = crate::ipc::framing::write_frame(
                    &mut stream,
                    &HelperResponse::Ok { name: None },
                )
                .await;
            }
            HelperRequest::DnsApply { dns } => {
                // 状态文件目录 = 控制 socket 所在目录（$XDG_RUNTIME_DIR/hillstonux）。
                // 辅助进程以 root 运行且不继承守护进程的环境变量，故从 socket 路径推导。
                let socket_dir = std::path::Path::new(socket_path)
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
                let mut mgr = DnsManager::for_helper_socket_dir(socket_dir);
                // 孤儿状态预检：若上一次异常退出遗留了 VPN DNS，先恢复原状，
                // 保证本次快照取自干净状态。
                mgr.restore_orphaned().await;
                match mgr.apply(&dns).await {
                    Ok(()) => {
                        dns_mgr = Some(mgr);
                        let _ = crate::ipc::framing::write_frame(
                            &mut stream,
                            &HelperResponse::Ok { name: None },
                        )
                        .await;
                    }
                    Err(e) => {
                        let _ = crate::ipc::framing::write_frame(
                            &mut stream,
                            &HelperResponse::Err {
                                message: e.to_string(),
                            },
                        )
                        .await;
                    }
                }
            }
            HelperRequest::DnsRestore => {
                if let Some(mut mgr) = dns_mgr.take() {
                    let _ = mgr.restore().await;
                }
                let _ = crate::ipc::framing::write_frame(
                    &mut stream,
                    &HelperResponse::Ok { name: None },
                )
                .await;
            }
        }
    }

    Ok(())
}
