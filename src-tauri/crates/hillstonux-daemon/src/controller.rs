//! VPN connection state machine.
//!
//! Owns the entire VPN session lifecycle:
//! - Connect: TLS → AUTH → CLNT_INFO → SET_IP/SET_ROUTE/KEY_DONE → NEW_KEY →
//!   create TUN → apply routes → set DNS → spawn data-plane tasks
//! - Disconnect: stop data-plane tasks → tear down DNS → restore routes →
//!   drop TUN → logout
//! - Auto-reconnect: on data-plane error / SERV_DISCONN, exponential backoff
//!   1/2/4/8/16/30s, up to N attempts (configurable; default 5)
//! - No periodic KEEP_ALIVE: the reference client (Python) sends no
//!   keepalives after NEW_KEY, and the server RSTs the control channel ~20s
//!   into sessions that do. A single KEEP_ALIVE is still sent once at
//!   connect time to arm the server's ESP SA.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hillstonux_core::client::{ClientCore, KeyMaterial, NetworkConfig};
use hillstonux_core::ipsec::expand;
use hillstonux_net::{EspSocket, TunDevice};
use thiserror::Error;
use tokio::sync::{broadcast, Mutex, RwLock};

use crate::privops::{ensure_privileged_ops, PrivError, PrivilegedOps};

use crate::ipc::{ConnectParams, LogLevel, VpnEvent, VpnStateDto};

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("vpn error: {0}")]
    Vpn(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("not connected")]
    NotConnected,
    #[error("config error: {0}")]
    Config(String),
    /// The user declined (or did not complete) the privilege escalation.
    /// Not retryable: retrying would raise another authorization prompt for
    /// something the user already said no to.
    #[error("{0}")]
    Auth(String),
}

impl From<hillstonux_core::error::ProtocolError> for ControllerError {
    fn from(e: hillstonux_core::error::ProtocolError) -> Self {
        ControllerError::Vpn(e.to_string())
    }
}

impl From<std::io::Error> for ControllerError {
    fn from(e: std::io::Error) -> Self {
        ControllerError::Io(e.to_string())
    }
}

impl From<hillstonux_net::route::RouteError> for ControllerError {
    fn from(e: hillstonux_net::route::RouteError) -> Self {
        ControllerError::Vpn(format!("route: {}", e))
    }
}

impl From<hillstonux_net::dns::DnsError> for ControllerError {
    fn from(e: hillstonux_net::dns::DnsError) -> Self {
        ControllerError::Vpn(format!("dns: {}", e))
    }
}

impl From<PrivError> for ControllerError {
    fn from(e: PrivError) -> Self {
        match e {
            PrivError::AuthCancelled(_) => ControllerError::Auth(format!("priv: {}", e)),
            other => ControllerError::Vpn(format!("priv: {}", other)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub auto_reconnect: bool,
    pub max_reconnect_attempts: u32,
    /// Reserved for a future watchdog: if no response / no data-plane
    /// traffic arrives within this window, the daemon would tear down and
    /// trigger an auto-reconnect. For now the data plane itself surfaces
    /// connection loss via task-exit, so this is unused.
    #[allow(dead_code)]
    pub keepalive_timeout: Duration,
    pub reconnect_backoff: Vec<Duration>, // index = attempt - 1
    pub tun_name: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_reconnect: true,
            max_reconnect_attempts: 5,
            keepalive_timeout: Duration::from_secs(30),
            reconnect_backoff: vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(16),
                Duration::from_secs(30),
            ],
            tun_name: "hillstonux0".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VpnState {
    pub phase: VpnStateDto,
}

impl VpnState {
    pub fn idle() -> Self {
        Self {
            phase: VpnStateDto::Idle,
        }
    }
}

/// Public handle to the controller. Cloning is cheap; all clones share the
/// same internal state via `Arc<RwLock<...>>`.
#[derive(Clone)]
pub struct Controller {
    inner: Arc<RwLock<ControllerInner>>,
    settings: Arc<Settings>,
    events: broadcast::Sender<VpnEvent>,
    /// 尚未交到 Session 手里的特权操作句柄。一次连接失败后把它留在这里，
    /// 下一次重试就能直接复用，不再重复弹出 polkit 认证框。
    priv_ops: Arc<Mutex<Option<Box<dyn PrivilegedOps>>>>,
}

struct ControllerInner {
    state: VpnState,
    session: Option<Session>,
}

/// Per-connection resources. Drop semantics handle most cleanup; the
/// `disconnect` path additionally restores routes and DNS.
#[allow(dead_code)]
struct Session {
    net: NetworkConfig,
    keymat: KeyMaterial,
    /// ClientCore kept on the TLS control channel for the session's lifetime
    /// (e.g. CLNT_LOGOUT on disconnect).
    client: Arc<Mutex<ClientCore>>,
    tun: std::sync::Arc<TunDevice>,
    /// 特权操作句柄：root 时直接执行，否则指向经 pkexec 拉起的辅助进程。
    priv_ops: Box<dyn PrivilegedOps>,
    udp: EspSocket,
    /// SPI we put in outbound ESP headers (= peer sees this as their inbound SPI).
    out_spi: u32,
    /// ESP SecurityAssociation material (inbound = decrypt, outbound = encrypt).
    sa_in: hillstonux_core::ipsec::ExpandedKeys,
    sa_out: hillstonux_core::ipsec::ExpandedKeys,
    /// Channels used to signal data-plane tasks to stop.
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Join handles for the data-plane tasks. Awaited on disconnect so we
    /// can guarantee TUN/UDP are released before DNS/routes are restored.
    data_plane_handles: Option<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)>,
    /// Stats forwarder (drains `data_plane::StatsEvent` into the controller's
    /// events channel). Held so we can drop it (closing the channel) on disconnect.
    stats_forwarder: Option<tokio::task::JoinHandle<()>>,
    /// Periodic stats broadcaster: re-emits the Connected phase (byte
    /// counters + uptime) every 2 s so the GUI's traffic display updates
    /// without a phase transition.
    stats_ticker: Option<tokio::task::JoinHandle<()>>,
    /// When this connection completed.
    since: Instant,
    /// Total bytes sent/received (populated by the stats forwarder).
    bytes_in: u64,
    bytes_out: u64,
}

impl Controller {
    pub fn new(settings: Settings, events: broadcast::Sender<VpnEvent>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ControllerInner {
                state: VpnState::idle(),
                session: None,
            })),
            settings: Arc::new(settings),
            events,
            priv_ops: Arc::new(Mutex::new(None)),
        }
    }

    #[allow(dead_code)]
    pub async fn state(&self) -> VpnState {
        self.inner.read().await.state.clone()
    }

    /// Synchronous, non-blocking snapshot of the current state. Used by the
    /// IPC handler when the request was issued from a sync context (the
    /// `RequestHandler::handle` trait method is sync). Returns `None` if
    /// the lock is held by a writer — caller should fall back to the async
    /// variant in that case.
    pub fn try_state(&self) -> Option<VpnState> {
        self.inner.try_read().ok().map(|g| g.state.clone())
    }

    /// Resolve the VPN password. The GUI resolves the Secret Service
    /// reference and passes the cleartext in `params.password` over the local
    /// 0600 daemon socket (trusted, same-user). Falls back to `password_ref`
    /// for backwards compatibility.
    async fn resolve_password(&self, params: &ConnectParams) -> Result<String, ControllerError> {
        if !params.password.is_empty() {
            return Ok(params.password.clone());
        }
        if !params.password_ref.is_empty() {
            return Ok(params.password_ref.clone());
        }
        Err(ControllerError::Config("empty password".into()))
    }

    pub async fn connect(&self, params: ConnectParams) -> Result<(), ControllerError> {
        // 辅助进程在整次连接（含重试）期间复用：连接失败时把它放回缓存，
        // 下一次尝试就不必再弹一次 polkit 认证框。
        let mut priv_ops: Option<Box<dyn PrivilegedOps>> = None;
        let result = self.connect_inner(params, &mut priv_ops).await;
        if result.is_err() {
            if let Some(ops) = priv_ops.take() {
                *self.priv_ops.lock().await = Some(ops);
            }
        }
        result
    }

    async fn connect_inner(
        &self,
        params: ConnectParams,
        priv_ops: &mut Option<Box<dyn PrivilegedOps>>,
    ) -> Result<(), ControllerError> {
        self.transition(VpnStateDto::Connecting { step: "tcp".into() })
            .await;
        let password = self.resolve_password(&params).await?;
        let mut client = ClientCore::new();
        if let Err(e) = client.connect_tcp(&params.server, params.port).await {
            self.fail(&ControllerError::from(e)).await;
            return Err(ControllerError::NotConnected);
        }
        self.transition(VpnStateDto::Connecting {
            step: "auth".into(),
        })
        .await;
        if let Err(e) = client.auth(&params.user, &password, "", "").await {
            self.fail(&ControllerError::from(e)).await;
            return Err(ControllerError::NotConnected);
        }
        self.transition(VpnStateDto::Connecting {
            step: "client_info".into(),
        })
        .await;
        if let Err(e) = client.client_info().await {
            self.fail(&ControllerError::from(e)).await;
            return Err(ControllerError::NotConnected);
        }
        self.transition(VpnStateDto::Connecting {
            step: "wait_network".into(),
        })
        .await;
        let net = match client.wait_network().await {
            Ok(n) => n,
            Err(e) => {
                self.fail(&ControllerError::from(e)).await;
                return Err(ControllerError::NotConnected);
            }
        };
        self.transition(VpnStateDto::Connecting {
            step: "exchange_key".into(),
        })
        .await;
        let keymat = match client.exchange_key().await {
            Ok(k) => k,
            Err(e) => {
                self.fail(&ControllerError::from(e)).await;
                return Err(ControllerError::NotConnected);
            }
        };

        // Data-plane activation: the real Hillstone server only arms the ESP
        // SA after it receives a KEEP_ALIVE. Send one immediately, before the
        // TUN/routes/data-plane tasks start, so the first outbound ESP is not
        // silently dropped by the server (verified in examples/live_probe.rs).
        if let Err(_e) = client.send_keepalive().await {
            // initial keepalive failed
        }

        // Use the address that connect_tcp actually resolved. Users normally
        // enter a hostname; parsing `params.server` here only works for IP
        // literals and used to reject every hostname after a successful
        // handshake. The data plane needs an IPv4 literal for the route bypass
        // and the UDP peer. Resolve this before spawning the privileged helper
        // so a bad address fails without a polkit prompt.
        let server_ip: Ipv4Addr = match client.resolved_ip() {
            Some(IpAddr::V4(ip)) => ip,
            Some(IpAddr::V6(ip)) => {
                let _ = client.logout().await;
                self.fail(&ControllerError::Config(format!(
                    "IPv6 server address {} is not supported",
                    ip
                )))
                .await;
                return Err(ControllerError::NotConnected);
            }
            None => {
                let _ = client.logout().await;
                self.fail(&ControllerError::Config(format!(
                    "could not resolve server IP from {}",
                    params.server
                )))
                .await;
                return Err(ControllerError::NotConnected);
            }
        };

        // 通过特权抽象获取系统级资源：已是 root 时直接执行，否则经 pkexec
        // 拉起辅助进程（首次连接会弹出 polkit 认证对话框等待用户输入密码）。
        // 单独上报这个阶段，避免用户在认证对话框出现前一直看到
        // "exchange_key" 而以为程序卡死。
        self.transition(VpnStateDto::Connecting {
            step: "privileged".into(),
        })
        .await;
        if priv_ops.is_none() {
            // 优先复用上一次尝试留下的辅助进程：重新拉起会再弹一次
            // polkit 认证框，用户不应为一次连接输多次密码。
            if let Some(ops) = self.priv_ops.lock().await.take() {
                *priv_ops = Some(ops);
            }
        }
        if priv_ops.is_none() {
            match ensure_privileged_ops().await {
                Ok(p) => *priv_ops = Some(p),
                Err(e) => {
                    // Propagate the real error: a declined authorization must be
                    // distinguishable from a transient failure so the retry loop
                    // does not raise another polkit prompt.
                    let err = ControllerError::from(e);
                    self.fail(&err).await;
                    return Err(err);
                }
            }
        }
        let ops = priv_ops.as_mut().expect("priv ops acquired above");
        let tun = match ops.tun_create(&self.settings.tun_name).await {
            Ok(t) => t,
            Err(e) => {
                let err = ControllerError::from(e);
                self.fail(&err).await;
                return Err(err);
            }
        };
        if let Err(e) = ops
            .routes_apply(&net, server_ip, &self.settings.tun_name, params.full_tunnel)
            .await
        {
            // 辅助进程侧已回滚路由快照（见 privhelper 的失败分支）；这里再显式
            // 拆除 TUN，释放设备名供重试使用。
            let _ = ops.tun_destroy(&self.settings.tun_name).await;
            self.fail(&ControllerError::from(e)).await;
            return Err(ControllerError::NotConnected);
        }
        if let Err(e) = ops.dns_apply(&net.dns).await {
            tracing::warn!(?e, "dns apply via privhelper failed; continuing");
        }

        // Derive ESP SecurityAssociation keys.
        let sa_in = expand(
            &keymat.keymat,
            keymat.crypt_size,
            keymat.auth_size,
            keymat.iv_size,
        );
        let sa_out = expand(
            &keymat.keymat,
            keymat.crypt_size,
            keymat.auth_size,
            keymat.iv_size,
        );

        // Open UDP socket for ESP.
        let udp = match EspSocket::bind_any().await {
            Ok(u) => u,
            Err(e) => {
                // 回滚已下发的系统改动（DNS → 路由 → TUN），让重试从干净状态
                // 开始；否则辅助进程持有的快照会指向 VPN 修改后的状态。
                let _ = ops.dns_restore().await;
                let _ = ops.routes_restore().await;
                let _ = ops.tun_destroy(&self.settings.tun_name).await;
                self.fail(&ControllerError::Io(e.to_string())).await;
                return Err(ControllerError::NotConnected);
            }
        };

        // Spawn data-plane tasks.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut shutdown_for_ticker = shutdown_rx.clone();

        // Derive encryption algorithm from the negotiated key sizes.
        let enc_alg = if keymat.crypt_size == 0x10 {
            hillstonux_core::ipsec::EncAlg::AesCbc
        } else {
            hillstonux_core::ipsec::EncAlg::TripleDes
        };
        let use_sha1 = keymat.auth_size == 0x14; // 20 bytes = SHA1, 16 bytes = MD5

        let tun_arc = std::sync::Arc::new(tun);
        let server_addr =
            std::net::SocketAddr::new(std::net::IpAddr::V4(server_ip), net.server_udp_port);
        let (stats_tx_inner, stats_rx_inner) =
            tokio::sync::mpsc::unbounded_channel::<crate::data_plane::StatsEvent>();

        let dp_params = crate::data_plane::SpawnParams {
            tun: tun_arc.clone(),
            udp: udp.clone(),
            server: server_addr,
            sa_out: sa_out.clone(),
            out_spi: keymat.outbound_spi,
            sa_in: sa_in.clone(),
            enc_alg,
            use_sha1,
            iv_size: keymat.iv_size,
            shutdown: shutdown_rx,
            stats_tx: stats_tx_inner,
        };
        let (handle_a, handle_b) = crate::data_plane::spawn(dp_params);

        // Wrap ClientCore in an Arc so the session keeps the TLS control
        // channel alive (logout etc.). Note: there is deliberately NO
        // periodic keepalive task here — the Python reference sends nothing
        // after NEW_KEY and this server RSTs control channels that do
        // (observed at ~20s). The one-shot KEEP_ALIVE above is what arms
        // the server's ESP SA; the UDP data plane is independent of the
        // control channel afterwards.
        let client = Arc::new(Mutex::new(client));

        // Stats forwarder: drains data-plane stats and emits VpnEvent::Stats
        // while also bumping the session's bytes_in/out.
        let inner_for_stats = self.inner.clone();
        let stats_forwarder = tokio::spawn(async move {
            use crate::data_plane::StatsEvent as SE;
            let mut stats_rx = stats_rx_inner;
            while let Some(evt) = stats_rx.recv().await {
                match evt {
                    SE::BytesIn(n) => {
                        let mut g = inner_for_stats.write().await;
                        if let Some(sess) = g.session.as_mut() {
                            sess.bytes_in = sess.bytes_in.saturating_add(n);
                            let phase = connected_phase(sess);
                            g.state.phase = phase;
                        }
                    }
                    SE::BytesOut(n) => {
                        let mut g = inner_for_stats.write().await;
                        if let Some(sess) = g.session.as_mut() {
                            sess.bytes_out = sess.bytes_out.saturating_add(n);
                            let phase = connected_phase(sess);
                            g.state.phase = phase;
                        }
                    }
                }
            }
        });

        // Periodic stats broadcaster: the data plane reports bytes per packet
        // and the forwarder accumulates them, but between phase transitions
        // nothing would reach the IPC clients — the GUI's traffic counters
        // would stay frozen at zero. Re-emit the Connected phase (bytes +
        // uptime) every 2 s while a session exists.
        let inner_for_ticker = self.inner.clone();
        let events_for_ticker = self.events.clone();
        let stats_ticker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            interval.tick().await; // the first tick fires immediately; skip it
            loop {
                tokio::select! {
                    _ = shutdown_for_ticker.changed() => break,
                    _ = interval.tick() => {
                        let g = inner_for_ticker.read().await;
                        if let Some(sess) = g.session.as_ref() {
                            let phase = connected_phase(sess);
                            let _ = events_for_ticker.send(VpnEvent::StateChanged { state: phase });
                        }
                    }
                }
            }
        });

        let since = Instant::now();
        let session = Session {
            net,
            keymat: keymat.clone(),
            client,
            tun: tun_arc,
            priv_ops: match priv_ops.take() {
                Some(ops) => ops,
                None => {
                    let err = ControllerError::Vpn("privileged helper vanished".into());
                    self.fail(&err).await;
                    return Err(err);
                }
            },
            udp,
            out_spi: keymat.outbound_spi,
            sa_in,
            sa_out,
            shutdown_tx,
            data_plane_handles: Some((handle_a, handle_b)),
            stats_forwarder: Some(stats_forwarder),
            stats_ticker: Some(stats_ticker),
            since,
            bytes_in: 0,
            bytes_out: 0,
        };

        // Record state.
        {
            let mut g = self.inner.write().await;
            g.state.phase = VpnStateDto::Connected {
                since_secs: 0,
                bytes_in: 0,
                bytes_out: 0,
            };
            g.session = Some(session);
        }
        let _ = self.events.send(VpnEvent::StateChanged {
            state: VpnStateDto::Connected {
                since_secs: 0,
                bytes_in: 0,
                bytes_out: 0,
            },
        });
        Ok(())
    }

    pub async fn disconnect(&self) -> Result<(), ControllerError> {
        // Set state to disconnecting and notify the GUI.
        {
            let mut g = self.inner.write().await;
            g.state.phase = VpnStateDto::Disconnecting;
        }
        let _ = self.events.send(VpnEvent::StateChanged {
            state: VpnStateDto::Disconnecting,
        });

        // Take the session out, signal tasks to exit, await them, then
        // restore system resources (DNS → routes → drop TUN/UDP).
        let session = self.get_cleanup_session().await;
        if let Some(mut sess) = session {
            self.teardown_session(&mut sess).await;
        }

        {
            let mut g = self.inner.write().await;
            g.state.phase = VpnStateDto::Idle;
        }
        // 释放上一次连接失败后缓存的辅助进程，避免 root 进程在会话外长期驻留。
        if let Some(ops) = self.priv_ops.lock().await.take() {
            drop(ops);
        }
        let _ = self.events.send(VpnEvent::StateChanged {
            state: VpnStateDto::Idle,
        });
        Ok(())
    }

    async fn transition(&self, phase: VpnStateDto) {
        {
            let mut g = self.inner.write().await;
            g.state.phase = phase.clone();
        }
        let _ = self.events.send(VpnEvent::StateChanged { state: phase });
    }

    /// Tear down a session's resources: stop data-plane/stats tasks, then
    /// restore DNS → routes → drop TUN. Shared by the clean `disconnect()`
    /// path and the `fail()` path — a failed connect that already created
    /// TUN/routes/DNS must clean up exactly the same way, otherwise the
    /// machine is left with routes pointing into a dead tunnel.
    ///
    /// All task handles are `Option`: a session assembled partway through
    /// `connect()` may not have the data-plane tasks spawned yet, and
    /// teardown has to handle that gracefully.
    async fn teardown_session(&self, sess: &mut Session) {
        // Tell data-plane and stats forwarder to exit.
        let _ = sess.shutdown_tx.send(true);

        // The stats forwarder sees EOF on its channel and exits on its own.
        if let Some(h) = sess.stats_forwarder.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), h).await;
        }

        // The stats ticker exits on the shutdown signal sent above.
        if let Some(h) = sess.stats_ticker.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), h).await;
        }

        // Await data-plane tasks (if they were started).
        if let Some((ha, hb)) = sess.data_plane_handles.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                let _ = tokio::join!(ha, hb);
            })
            .await;
        }

        // Restore DNS → routes in that order (least destructive first).
        if let Err(e) = sess.priv_ops.dns_restore().await {
            tracing::warn!(?e, "dns restore failed");
        }
        if let Err(e) = sess.priv_ops.routes_restore().await {
            tracing::warn!(?e, "route restore failed");
        }
        // 显式拆除 TUN 设备（辅助进程侧或 root 侧），随后 Arc<TunDevice>
        // 随 Session 析构关闭本端 fd。
        let _ = sess.priv_ops.tun_destroy(&self.settings.tun_name).await;
        // TUN drops on Session::drop (closes /dev/net/tun fd).
    }

    /// Take the current session out of state for teardown (disconnect or
    /// fail). Returns None when no session exists (e.g. the failure
    /// happened before any privileged resources were created).
    async fn get_cleanup_session(&self) -> Option<Session> {
        let mut g = self.inner.write().await;
        g.session.take()
    }

    async fn fail(&self, e: &ControllerError) {
        tracing::warn!(?e, "controller entering error state");
        // Clean up any partially-built session (TUN/routes/DNS) BEFORE
        // reporting the error, so the network recovers immediately instead
        // of blackholing on dead-tunnel routes until a manual disconnect.
        if let Some(mut sess) = self.get_cleanup_session().await {
            self.teardown_session(&mut sess).await;
        }
        let code = match &e {
            ControllerError::Vpn(_) => 1,
            ControllerError::Io(_) => 2,
            ControllerError::NotConnected => 3,
            ControllerError::Config(_) => 4,
            ControllerError::Auth(_) => 5,
        };
        let phase = VpnStateDto::Error {
            code,
            message: e.to_string(),
        };
        {
            let mut g = self.inner.write().await;
            g.state.phase = phase.clone();
        }
        let _ = self.events.send(VpnEvent::StateChanged { state: phase });
        let _ = self.events.send(VpnEvent::LogLine {
            level: LogLevel::Error,
            msg: format!("controller error: {}", e),
        });
    }

    /// Look up the running session without taking a write lock.
    #[allow(dead_code)]
    pub async fn session_snapshot(&self) -> Option<NetworkConfig> {
        self.inner
            .read()
            .await
            .session
            .as_ref()
            .map(|s| s.net.clone())
    }

    /// Connect with exponential-backoff retry. Honors
    /// `Settings::auto_reconnect` and `max_reconnect_attempts`.
    ///
    /// Calls `connect()` repeatedly until success or attempts are exhausted.
    /// User-initiated `disconnect()` cancels the loop (the loop checks the
    /// current state before each attempt).
    pub async fn connect_with_retry(&self, params: ConnectParams) -> Result<(), ControllerError> {
        let max = if self.settings.auto_reconnect {
            self.settings.max_reconnect_attempts as usize
        } else {
            1
        };
        let mut last_err: Option<ControllerError> = None;
        for attempt in 1..=max {
            // 首次连接（初始状态为 Idle）必须放行；只有重连等待期间才需要
            // 检查用户是否发起了断开——此时 phase 为 Disconnecting / Idle，
            // 说明正在拆除，不应再拉起新连接。
            if attempt > 1 {
                let delay = self
                    .settings
                    .reconnect_backoff
                    .get(attempt - 2)
                    .copied()
                    .unwrap_or(Duration::from_secs(30));
                self.transition(VpnStateDto::Reconnecting {
                    attempt: attempt as u32,
                    next_in_secs: delay.as_secs(),
                })
                .await;
                tokio::time::sleep(delay).await;
                // 重连等待结束后，若用户已点击断开（正在拆除），则中止重连。
                let g = self.inner.read().await;
                if matches!(
                    g.state.phase,
                    VpnStateDto::Disconnecting | VpnStateDto::Idle
                ) {
                    return Err(ControllerError::NotConnected);
                }
            }
            match self.connect(params.clone()).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!(attempt, ?e, "connect attempt failed");
                    // A declined authorization is a user decision, not a
                    // transient failure: retrying would raise another polkit
                    // prompt for something the user just refused.
                    if matches!(e, ControllerError::Auth(_)) {
                        return Err(e);
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or(ControllerError::NotConnected))
    }
}

fn connected_phase(sess: &Session) -> VpnStateDto {
    let since_secs = sess.since.elapsed().as_secs();
    VpnStateDto::Connected {
        since_secs,
        bytes_in: sess.bytes_in,
        bytes_out: sess.bytes_out,
    }
}
