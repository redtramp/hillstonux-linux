# Hillstonux GUI 设计文档

> **状态：** 草案（待批准）
> **作者：** ZCode（基于与用户的可行性讨论）
> **日期：** 2026-10-19
> **关联源码：** `../hillstonux/`（Python 原版）

---

## 1. 意图与背景

### 1.1 为什么做这件事

用户有一个能在 Linux 上稳定运行的 Python CLI 项目 `hillstonux`，它实现了 Hillstone Secure Connect 这个非标准 SSL VPN 协议的 Linux 客户端。日常使用中需要：

- 在桌面会话里点几下就连上/断开，而不是开终端跑 sudo 命令；
- 关闭主窗口时程序继续留在托盘保持连接；
- 在同一台机器上多个用户/桌面会话场景下，不需要每次都重新输入密码。

Python 版本能用，但缺乏 GUI、不便最小化、与桌面环境割裂。Rust + Tauri 是把"控制面"和"数据面"重新分层、并提供原生桌面体验的合适载体。

### 1.2 这次交付什么

一个 Linux 桌面应用 **Hillstonux GUI**：

- 提供图形界面填写 VPN 服务器地址、端口、用户名、密码，并发起连接/断开；
- 关闭窗口后常驻系统托盘，托盘菜单可一键连接/断开/退出；
- 后端实际拨号、走 TUN、加密流量与 Python 版完全等价（同服务器、相同凭据应能互通）。

### 1.3 这次不交付什么（Out of Scope）

以下功能**不**在本次范围内：

- macOS / Windows 适配；
- iOS / Android 客户端；
- 多 VPN 隧道并发（同时连多台服务器）；
- 流量统计图形化（仅日志面板）；
- 服务端模拟器、协议模糊测试框架；
- 与企业级 MDM / 集中策略管理对接；
- 内置"自动测速并选择最快节点"功能。

---

## 2. 目标 / 非目标 / 反目标

### 2.1 Goals（成功时必须做到）

| ID | 目标 | 验收条件 |
|---|---|---|
| G1 | GUI 在普通用户权限下运行，不以 root 启动 | `ps -o user` 显示当前登录用户，不是 root |
| G2 | 与现有 Python 版连接同一台服务器行为等价 | 同一账号，连上后能访问 `routes` 中的内网网段；`/etc/resolv.conf` 出现 VPN DNS；ping 服务器私有网关通 |
| G3 | 关闭主窗口后 VPN 保持在线，托盘可恢复窗口 | 关窗后 30 秒 ping VPN 内网网关不中断；托盘右键菜单含"显示窗口/连接/断开/退出"四项 |
| G4 | 断开后系统路由、DNS 还原到拨号前状态 | 断开后 `ip route show table main` 与连接前一致；`/etc/resolv.conf` 字节级一致 |
| G5 | 异常退出（kill -9、崩溃、断电）不会留下错误路由断网 | 守护进程启动时检测残留路由/DNS 状态并自动恢复 |
| G6 | 密码不落盘 | 配置文件中只存引用，密码走 Secret Service（libsecret） |
| G7 | 网络抖动 / 服务端断开时自动重连 | 默认开启；指数退避 1/2/4/8/16/30s，最多 5 次；UI 设置可关闭 |

### 2.2 Non-Goals（明确不做）

- 不实现 Hillstone 协议所有 message type（仅实现 MVP 必需子集）；
- 不做协议兼容性回归测试套件（仅保证与本机 Python 版互通）；
- 不内嵌 nmcli 之外的桌面环境适配层（NetworkManager / systemd-resolved 见 §7.3）；
- 不做开机自启动的 GUI 自动连接（systemd 服务仍保留命令行模式兼容）。

### 2.3 Anti-Goals（做了就是失败）

- **不要**把整个 Tauri GUI 进程设为 setuid root；
- **不要**在 GUI 进程里直接持有长期 root 权限；
- **不要**在 `/etc/resolv.conf` 之外的地方写 DNS 状态而不还原；
- **不要**把用户密码写入 `config.json` 或任何 dotfile；
- **不要**让守护进程监听 TCP / 任何对外端口（仅 unix domain socket）。

---

## 3. 约束

### 3.1 平台约束

- 仅 Linux（kernel ≥ 5.4，glibc ≥ 2.31）；不考虑其他 Unix-like；
- **桌面环境：KDE Plasma 5.20+ / 6.x**（覆盖 X11 与 Wayland 会话；Plasma 6 默认 Wayland）；
- 体系架构：MVP 仅 `x86_64-unknown-linux-gnu`；后续可加 `aarch64-unknown-linux-gnu`（KDE 同款多数笔记本需求，待后续追加）；
- 包格式：**`.deb`** 唯一发布产物（依赖 Debian/Ubuntu 系发行版的 apt 依赖管理，KDE 桌面用户主流发行版覆盖）；
- 系统依赖（运行时）：`libwebkit2gtk-4.1-0`、`libgtk-3-0`、`libayatana-appindicator3-1`、`librsvg2-2`、`libssl3`（由 deb Depends 自动装）；
- 系统依赖（构建期）：`libwebkit2gtk-4.1-dev`、`libgtk-3-dev`、`libayatana-appindicator3-dev`、`librsvg2-dev`、`libssl-dev`、`build-essential`、`pkg-config`、`rustc`、`cargo`、`nodejs`、`npm`。

**不**支持的场景（明确排除）：

- GNOME / XFCE / Sway / Cinnamon 等非 KDE 桌面；
- Wayland 下非 Plasma 合成器（KDE KWin 之外的 Wayland 合成器）；
- 纯 CLI / 无 GUI 服务器环境。

### 3.2 安全约束（来自项目安全规范）

- **服务端请求 URL 时**：仅允许 http/https；发请求前校验 host，拒绝 localhost、环回、私有、保留地址；
- 本应用主动出站仅限 TLS 控制信道（指向用户填写的 VPN 服务器）和 ESP/UDP 数据信道，二者目标地址均来自用户输入的"服务器地址"，不做额外网络请求；
- 若日后加入"自动获取服务器列表/检查更新"等功能，新增出站必须经过同一 host 校验函数（见 §7.5）。

### 3.3 工程约束

- Rust 工具链：stable ≥ 1.78，`edition = "2021"`；
- Tauri 2.x 最新稳定版；
- **依赖版本策略：始终使用 latest（caret 约束，让 cargo 自动选最新兼容版）**；CI 跑 `cargo update` 升级；
- 测试覆盖：核心库（`hillstonux-core`）≥ 80% 行覆盖；UI 仅做端到端冒烟；
- 提交粒度：每个 Task 一次提交，commit message 遵循 Conventional Commits；
- **License：MIT**（仓库根 `LICENSE` 文件）。原项目 `https://github.com/zCanek/hillstonux` 未声明 license，本次新代码以 MIT 贡献；不以"fork"形式发布。

### 3.4 协议兼容性约束

- 必须与 `/home/redtramp/Green/Network/hillstonux` Python 版二进制级兼容；
- 控制信道：TLS 1.2+，不校验服务端证书（与原版一致，遵循用户网络环境惯例）；
- 数据信道：UDP 端口（由服务端在 SET_IP 阶段下发）；
- 加密：AES-CBC + HMAC-MD5-96（MVP 必选）；3DES + HMAC-SHA1-96 作为可选项保留但不参与首轮端到端验证。

---

## 4. 架构决策

### 4.1 进程拓扑

```
┌─────────────────────────────────────────────────────────────┐
│ 用户桌面会话（普通用户权限）                                  │
│                                                              │
│  ┌──────────────────┐    unix socket     ┌──────────────┐  │
│  │  hillstonux-gui  │ ◄───────────────► │ hillstonux-   │  │
│  │  (Tauri + 前端)  │  $XDG_RUNTIME_DIR  │   daemon     │  │
│  │                  │   /hillstonux.sock │  (root 启动) │  │
│  └──────────────────┘                    └──────┬───────┘  │
│         │                                       │           │
│         ▼                                       ▼           │
│   tray icon + D-Bus                  /dev/net/tun (TUN)     │
│                                      ESP/UDP socket         │
│                                      ip route / DNS 管理    │
└─────────────────────────────────────────────────────────────┘
```

**为什么分两个进程：**

- GUI 不能以 root 运行（违反 G1 / 反目标 1）；
- VPN 数据面需要 `CAP_NET_ADMIN`、`/dev/net/tun`、原始 socket，必须 root 或具备 cap；
- 分离后 GUI 崩溃不影响 VPN；守护进程可以被 systemd 管理（保留原 `hilldustWrapper.service` 的运维模式）；
- 安全审计面小：守护进程只接受来自 `XDG_RUNTIME_DIR` 域 socket 的本地连接，不对外暴露。

### 4.2 IPC 协议

- 传输：Unix domain socket（`SOCK_STREAM`，长度前缀 + JSON 载荷）；
- 路径：`$XDG_RUNTIME_DIR/hillstonux.sock`，权限 `0600`，属主当前用户；
- 请求 / 响应模型，单连接；守护进程可主动推送状态变更事件；
- 不使用 D-Bus（避免与桌面会话总线耦合，未来若需要再加 adapter）。

请求示例：
```json
{ "id": 1, "method": "connect", "params": { "server": "vpn.example.com", "port": 4433, "user": "alice", "password_ref": "secret-service-uuid" } }
```

事件推送（守护进程 → GUI）：
```json
{ "event": "state_changed", "data": { "state": "Connecting", "detail": "AUTH" } }
```

### 4.3 状态机

守护进程内部维护一个 6 态连接状态机：

```
            ┌─────────┐
   start ──►│  Idle   │
            └────┬────┘
                 │ connect()
                 ▼
            ┌─────────┐  失败   ┌─────────┐
            │Connecting│────────►│  Error  │
            └────┬────┘         └────┬────┘
                 │ KEY_DONE          │ 重试 / 放弃
                 ▼                   │
            ┌─────────┐ ◄────────────┘
            │ Handshaking │
            └────┬────┘
                 │ 路由配置完成
                 ▼
            ┌─────────┐
            │Connected│
            └────┬────┘
                 │ ESP/UDP 错误 / SERV_DISCONN / keepalive 超时
                 ▼
            ┌──────────┐
            │Reconnecting{ attempt: u32, next_in: Duration }
            └────┬─────┘
                 │ 重连成功           │ 5 次均失败
                 ▼                   ▼
            (Connected)            (Error{...})
                 │
                 │ disconnect() / 信号
                 ▼
            ┌─────────┐
            │Disconnecting│
            └────┬────┘
                 │ 路由还原完成
                 ▼
              (Idle)
```

每个状态转换都推 `state_changed` 事件给 GUI。Error 状态保留最近一次错误码，前端可展示。

### 4.4 前端技术栈

- Tauri 2.x；
- 前端框架：**Svelte 5 + TypeScript**（理由：包体积小、桌面应用普遍合适、官方 starter 完善；用户偏好若有变化可改为 Vue 3 或 React 18）；
- UI 组件：原生 HTML + 轻量 CSS（不引入 Tailwind / shadcn，保持二进制小）；
- 状态：Svelte stores；
- IPC 客户端：`@tauri-apps/api/core` 的 `invoke` + `listen`；
- 单页面：主面板（连接参数 + 状态 + 日志折叠面板）+ 设置抽屉（开机自启、托盘行为、自定义路由）。

---

## 5. 模块分解

### 5.1 crate 划分

```
hillstonux/                         # workspace 根
├── Cargo.toml                      # workspace manifest
├── crates/
│   ├── hillstonux-core/            # 纯逻辑库（不依赖 tokio 运行时选择，可单测）
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── protocol.rs         # hillstone.py 协议移植
│   │   │   ├── message.rs          # Message 序列化 / TLV 编解码
│   │   │   ├── error.rs            # 错误类型
│   │   │   ├── config.rs           # 配置数据结构
│   │   │   ├── crypto.rs           # AES / 3DES / HMAC 原语封装
│   │   │   └── ipsec/
│   │   │       ├── mod.rs
│   │   │       ├── esp.rs          # ESP 报文构造 / 解析
│   │   │       └── sa.rs           # SecurityAssociation 状态
│   │   └── tests/
│   │       ├── message_roundtrip.rs
│   │       ├── protocol_vectors.rs  # 与 Python 版字节级对比
│   │       └── esp_vectors.rs
│   ├── hillstonux-net/             # 系统集成层（root 权限依赖）
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── tun.rs              # /dev/net/tun 封装
│   │   │   ├── route.rs            # 路由表管理（基于 rtnetlink）
│   │   │   ├── dns.rs              # /etc/resolv.conf / resolvectl
│   │   │   └── udp.rs              # ESP/UDP socket 封装
│   │   └── tests/
│   ├── hillstonux-daemon/          # 后台守护进程
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── server.rs           # unix socket 服务
│   │   │   ├── controller.rs       # 连接生命周期编排
│   │   │   └── supervisor.rs       # 信号 / 残留清理
│   │   └── systemd/hillstonux-daemon.service
│   └── hillstonux-gui/             # Tauri 应用
│       ├── src/
│       │   ├── main.rs
│       │   ├── tray.rs
│       │   ├── commands.rs         # Tauri command handlers
│       │   └── ipc_client.rs       # 守护进程 socket 客户端
│       ├── src/                    # 前端（src-tauri/src 不含前端）
│       └── tauri.conf.json
└── ui/                             # Svelte 前端
    ├── src/
    │   ├── App.svelte
    │   ├── lib/
    │   │   ├── stores.ts
    │   │   └── ipc.ts
    │   └── components/
    │       ├── ConnectionForm.svelte
    │       ├── StatusBadge.svelte
    │       └── LogPanel.svelte
    └── package.json
```

### 5.2 模块职责一览

| 模块 | 职责 | 不做的事 |
|---|---|---|
| `hillstonux-core` | Hillstone 协议报文编解码、加密原语、ESP 封装、配置数据结构 | 不打开任何 socket，不读写任何文件，不调用任何系统调用 |
| `hillstonux-net` | TUN 设备、UDP 原始 socket、路由表、DNS 配置 | 不解析协议、不持有连接状态机 |
| `hillstonux-daemon` | 守护进程：编排连接生命周期、IPC、信号处理、残留清理 | 不含 UI，不写 GUI 用的配置文件 |
| `hillstonux-gui` | Tauri shell、托盘、前端 host（vite dev server / static build） | 不实现协议、不操作 TUN |
| `ui/` | 前端 SPA | 不直接调用系统命令，全部通过 `invoke` |

---

## 6. 接口契约（关键签名）

### 6.1 `hillstonux-core::protocol`

```rust
pub struct ClientCore { /* ... */ }

impl ClientCore {
    pub async fn connect_tcp(&mut self, host: &str, port: u16) -> Result<(), ProtocolError>;
    pub async fn auth(&mut self, user: &str, pass: &str) -> Result<(), AuthError>;
    pub async fn client_info(&mut self) -> Result<(), ClientInfoError>;
    pub async fn wait_network(&mut self) -> Result<NetworkConfig, NetworkInfoError>;
    pub async fn exchange_key(&mut self) -> Result<KeyMaterial, NewKeyError>;
    pub async fn logout(&mut self) -> Result<(), IoError>;
}

pub struct NetworkConfig {
    pub client_ipv4: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub routes: Vec<Cidr>,
    pub server_udp_port: u16,
}

pub struct KeyMaterial {
    pub inbound_spi: u32,
    pub outbound_spi: u32,
    pub keymat: [u8; 48],
    pub enc_size: usize,    // 16 for AES-CBC, 24 for 3DES
    pub iv_size: usize,
    pub auth_size: usize,   // 12 for HMAC-MD5-96
    pub enc_alg: EncAlg,
    pub auth_alg: AuthAlg,
}
```

### 6.2 `hillstonux-core::ipsec`

```rust
pub struct SecurityAssociation {
    spi: u32,
    seq: AtomicU64,                  // 出向序号
    crypt_key: Vec<u8>,
    auth_key: Vec<u8>,
    iv_size: usize,
    enc_alg: EncAlg,
    auth_alg: AuthAlg,
}

impl SecurityAssociation {
    pub fn encapsulate(&self, plaintext: &[u8]) -> Result<Vec<u8>, IpsecError>;
    pub fn decapsulate(&self, packet: &[u8]) -> Result<Vec<u8>, IpsecError>;
}
```

ESP 报文格式（出向）：
```
| SPI (4) | Seq (8) | IV (iv_size) | Ciphertext | Pad | PadLen (1) | NextHdr (1) | ICV (auth_size) |
```
反序列化顺序与 Python `scapy.all.SecurityAssociation.encrypt` 完全对齐。

### 6.3 `hillstonux-net::tun`

```rust
pub struct TunDevice {
    fd: OwnedFd,
    name: String,
}

impl TunDevice {
    pub fn create(name: &str) -> Result<Self, IoError>;
    pub async fn read_packet(&mut self) -> Result<Vec<u8>, IoError>;
    pub async fn write_packet(&mut self, pkt: &[u8]) -> Result<(), IoError>;
    pub fn name(&self) -> &str;
    pub fn into_fd(self) -> OwnedFd;
}
```

### 6.4 `hillstonux-net::route`

```rust
pub struct RouteManager {
    snapshot: RouteSnapshot,           // 拨号前快照
    tun_name: String,
}

impl RouteManager {
    pub async fn snapshot() -> Result<Self, RouteError>;
    pub async fn apply_vpn_routes(&mut self, cfg: &NetworkConfig) -> Result<(), RouteError>;
    pub async fn restore(&mut self) -> Result<(), RouteError>;
    pub async fn detect_residue_and_recover() -> Result<(), RouteError>;
}
```

### 6.5 `hillstonux-daemon::controller`

```rust
pub enum VpnState {
    Idle, Connecting { step: &'static str },
    Handshaking, Connected { since: Instant, bytes: Arc<AtomicU64> },
    Disconnecting, Error { code: u32, message: String },
}

pub trait StateSink: Send + Sync {
    fn emit(&self, evt: VpnEvent);
}

pub struct Controller {
    state: Arc<RwLock<VpnState>>,
    sink: Arc<dyn StateSink>,
    tun: Option<TunDevice>,
    routes: Option<RouteManager>,
    session: Option<SessionHandle>,
}

impl Controller {
    pub async fn connect(&mut self, req: ConnectRequest) -> Result<(), ControllerError>;
    pub async fn disconnect(&mut self) -> Result<(), ControllerError>;
    pub fn state(&self) -> VpnState;
}
```

### 6.6 `hillstonux-gui` 的 Tauri 命令

```rust
#[tauri::command]
async fn vpn_connect(app: AppHandle, params: ConnectParams) -> Result<(), String>;

#[tauri::command]
async fn vpn_disconnect(app: AppHandle) -> Result<(), String>;

#[tauri::command]
async fn vpn_state(app: AppHandle) -> Result<VpnState, String>;

#[tauri::command]
async fn save_profile(app: AppHandle, profile: Profile) -> Result<(), String>;

#[tauri::command]
async fn load_profiles(app: AppHandle) -> Result<Vec<Profile>, String>;
```

---

## 7. 关键流程

### 7.1 连接流程（守护进程视角）

1. 监听端收到 `connect` 请求（带密码引用）；
2. `Controller` 进入 `Connecting { step: "TCP" }`；
3. `ClientCore::connect_tcp` → `auth` → `client_info` → `wait_network` → `exchange_key`；
   - 失败时推 `state_changed(Error{...})` 并退出控制器；
4. 进入 `Handshaking`：`TunDevice::create("hillstonux0")` → `RouteManager::apply_vpn_routes`；
5. DNS：备份当前状态并写入 VPN DNS；
6. 进入 `Connected`：派生两个 tokio 任务循环；
   - 任务 A：`tun.read_packet() → sa.encapsulate() → udp.sendto(server, server_udp_port)`；
   - 任务 B：`udp.recvfrom() → sa.decapsulate() → tun.write_packet()`；
7. 任务任何一方错误：进入 `Reconnecting`（见 §7.6），**不**直接 `disconnect`。

### 7.6 自动重连（G7）

**触发条件**（任一）：

- UDP socket `recv_from` 连续 3 次返回错误；
- 服务端发送 `SERV_DISCONN`（`MessageType(0x08)`）；
- keepalive 超时（守护进程每 10s 发 `KEEP_ALIVE`，30s 未收到服务端响应视为断开）；
- 任务 A 或任务 B panic（tokio `JoinHandle` 终止）。

**重连策略**：

| 字段 | 值 | 备注 |
|---|---|---|
| 退避序列（秒） | 1, 2, 4, 8, 16, 30 | 第 6 次及以后固定 30s |
| 最大尝试次数 | 5 | 超过后进入 `Error` 状态 |
| 重置 | 成功 Connected 持续 ≥ 60s 后，下一次断开的 attempt 计数清零 | 避免长期在线后突然断就被算作"老问题" |
| 用户取消优先 | 用户在重连期间点"断开" → 立即终止重连循环、清理路由 | 重连不能阻塞用户主动断开 |

**重连时的资源处理**：

- 不重建 TUN 设备（`hillstonux0` 复用）；
- 不重做 KEYMAT 协商（新 KEYMAT 是新会话，重连沿用上次成功的 KEYMAT；如服务端拒绝则退化为完整重连流程）；
- 不重写 DNS（保留 VPN 期间的状态；新会话认证失败需重连时再刷一次）；
- 路由表保持。

**配置**：

```toml
[settings]
auto_reconnect = true       # 默认 true（G7）
max_reconnect_attempts = 5  # 0 = 无限重试
```

**用户可见**：

- 状态徽章显示 `Reconnecting (2/5)` + 倒计时；
- 系统托盘图标变化（红→黄→绿 状态指示）；
- 设置面板可关闭。

### 7.2 断开流程

1. 推 `Disconnecting`；
2. 取消任务 A/B（tokio `JoinHandle::abort`）；
3. `RouteManager::restore`：恢复路由表；
4. DNS：还原 `/etc/resolv.conf` 或 `resolvectl revert`；
5. `TunDevice` 关闭（`Drop` 触发 `close(fd)`）；
6. `ClientCore::logout()`（发送 `CLNT_LOGOUT`，容忍失败）；
7. 推 `Idle`；
8. 等待 GUI 断开 socket 或等待下一次连接。

### 7.3 DNS 策略

KDE 桌面默认组合：NetworkManager + systemd-resolved。MVP 只支持这两种后端，不再做 PlainFile 直写：

```rust
enum DnsBackend {
    Resolved,                       // 调用 `resolvectl` 设置 DNS（KDE 默认路径）
    NetworkManager { iface: String }, // 调用 `nmcli con mod ... ipv4.dns ...`（少数 NM-only 发行版）
}
```

探测顺序：

1. 环境变量 `HILLSTONUX_DNS_BACKEND` 强制指定；
2. `resolvectl --version` 成功 → `Resolved`；
3. `nmcli --version` 成功 → `NetworkManager`；
4. 都失败 → 拒绝启动并提示用户安装其中一个。

**DNS 切换时记录原始状态**：每个后端都对应自己的"还原路径"（`resolvectl revert` 或 `nmcli con mod ... -ipv4.dns`）。

### 7.4 残留恢复

守护进程启动时：

1. 调用 `RouteManager::detect_residue_and_recover`：
   - 检查是否存在指向 `hillstonux*` tun 的路由；
   - 若存在，尝试移除并恢复 main table（与正常 disconnect 同路径）；
2. 检查 `/etc/resolv.conf` 头部是否存在守护进程写入的 sentinel 注释（`# hillstonux-managed`），若有则还原备份；
3. 探测并关闭残留的 `hillstonux*` tun（`ip tuntap delete`）。

### 7.5 URL 校验函数（公共）

```rust
pub fn validate_outbound_host(host: &str) -> Result<(), SecurityError> {
    // 仅允许 http/https（用于未来可能的更新检查或服务器列表同步）
    // 拒绝：localhost、127.0.0.0/8、::1、RFC1918、RFC6598、RFC4193、loopback / link-local
    // 注：本应用 MVP 不主动发起 URL 请求；保留以备后续功能
}
```

---

## 8. 数据模型

### 8.1 配置文件（`~/.config/hillstonux/profiles.toml`）

```toml
[settings]
minimize_to_tray = true
start_minimized = false
auto_reconnect = true            # G7：默认开启
max_reconnect_attempts = 5
log_level = "info"

[[profile]]
name = "default"
server = "sslvpn.geovisearth.com"
port = 4433
username = "konglh"
password_ref = "libsecret:hillstonux:default:password"
auto_connect = false
custom_routes = ["10.6.0.0/24", "10.7.0.0/24"]
```

- MVP 仅一个 `[[profile]]`；多 profile 数据结构已预留，UI 暂不暴露切换；
- `password_ref`：libsecret 项的唯一标识符（`account` 字段），密码本身仅存 Secret Service；
- 旧版 `config.json` 平移：`hillstonux-migrate` 二进制（见 §11.4）。

### 8.2 IPC 消息协议

请求 / 响应：

```rust
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpcRequest {
    Connect { id: u64, params: ConnectParams },
    Disconnect { id: u64 },
    State { id: u64 },
    Ping { id: u64 },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpcResponse {
    Ok { id: u64, data: Option<Value> },
    Err { id: u64, code: u32, message: String },
    Event(VpnEvent),
}
```

长度前缀：4 字节大端 + JSON UTF-8 字节。

### 8.3 VpnEvent

```rust
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VpnEvent {
    StateChanged { state: VpnState },
    LogLine { level: LogLevel, msg: String },
    Stats { bytes_in: u64, bytes_out: u64 },
}
```

---

## 9. 安全模型

### 9.1 权限边界

| 进程 | 启动权限 | 运行期权限 | 关键操作 |
|---|---|---|---|
| GUI | 普通用户 | 普通用户 | 通过 unix socket 调守护进程；不触碰网络配置 |
| 守护进程 | root（systemd 启动） | 全程 root | TUN、路由、DNS、原始 socket |
| 守护进程（polkit 路径，可选） | 用户态 | 启动时向 polkit 申请 net_admin + net_raw | 同上，但仅本次会话有效 |

MVP 推荐 systemd 启动路径（用户已熟悉）。polkit 路径作为可选 milestone。

### 9.2 凭据生命周期

- 密码：仅在 GUI 输入 → 经 unix socket 传给守护进程 → 写入 ESP `SecurityAssociation`（短期内存）→ 不写盘；
- 长期保存：写入 libsecret（GNOME Keyring / KWallet），由 `org.freedesktop.secrets` 提供；
- 守护进程退出时清零内存中的密码字节（`zeroize` crate）。

### 9.3 主机校验

- 控制信道 TLS 不校验服务端证书（与 Python 版一致）；
- 若用户启用"严格模式"（GUI 开关）：加载本地 CA 证书并校验；
- ESP/UDP 数据信道无校验（与 Python 版一致）。

### 9.4 日志脱敏

- 守护进程日志过滤：连接请求中的 `password` 字段、KEYMAT、SPI 都不入日志；
- 仅记录状态转换与错误码。

---

## 10. 测试策略

### 10.1 单元测试（`hillstonux-core`）

- `message.rs`：对每种 MessageType 构造样例，与 Python 版同输入对比字节输出（hex fixture 来自 Python 端 `Message.finish()` 现场抓取）；
- `protocol.rs`：用本地 TCP echo 服务（带 TLS 终止）模拟服务端，验证请求顺序；
- `ipsec/esp.rs`：固定 KEYMAT + plaintext 与 Python `SecurityAssociation.encrypt/decrypt` 对比；
- `config.rs`：profile 序列化往返、`password_ref` 缺失报错。

目标覆盖率：≥ 80% 行。

### 10.2 集成测试（`hillstonux-net`）

- TUN：需要 root 或 `CAP_NET_ADMIN`，CI 中以 sudo 运行；
- 路由：用 netns 隔离（`network_namespaces` test fixture），避免污染主机；
- DNS：mock `/etc/resolv.conf`（tmpfs 挂载）。

### 10.3 端到端冒烟

- 手动测试矩阵：
  - 启动 → 输入凭据 → 连接 → ping 内网 → 关闭主窗口 → 仍在线 → 托盘断开 → 路由还原；
  - 启动 → 连接 → `kill -9` 守护进程 → 重启 → 残留恢复验证；
  - Wayland / X11 桌面分别测试托盘行为。

### 10.4 协议兼容验证

建立一次性脚本 `tools/cross_check.py`：
- 启动 Python 客户端连接本地 mock 服务器；
- 抓取原始 TCP 流 hex；
- 用 Rust `hillstonux-core` 同样输入做协议交互，hex diff 必须为空。

---

## 11. 构建与发布

### 11.1 工具链与依赖

```toml
# workspace Cargo.toml 关键依赖
[workspace.dependencies]
tokio = { version = "1.40", features = ["full"] }
rustls = "0.23"
byteorder = "1.5"
aes = "0.8"
hmac = "0.12"
md-5 = "0.10"
sha1 = "0.10"
des = "0.8"
cbc = "0.1"
rtnetlink = "0.13"
tun = "0.7"
zeroize = "1.8"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
keyring = "3"
thiserror = "1"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[workspace.dependencies.tauri]
version = "2"
```

### 11.2 构建脚本

- `xtask build`：编译三个二进制（`hillstonux-daemon`、`hillstonux-gui`、`hillstonux-migrate`），产出到 `dist/`；
- `xtask package`：用 `cargo deb` 生成 `.deb`（仅此一种包格式）；
- `xtask lint`：clippy + fmt check + cargo-deny；
- `xtask test`：workspace 全量测试。

deb 包元数据（`debian/control` 关键字段）：

```
Package: hillstonux-gui
Version: 0.1.0
Architecture: amd64
Depends:
  libwebkit2gtk-4.1-0,
  libgtk-3-0,
  libayatana-appindicator3-1,
  librsvg2-2,
  libssl3,
  systemd,
  dbus
Recommends:
  network-manager,
  systemd-resolved
Description: Hillstone Secure Connect VPN GUI client (Linux/KDE)
```

deb 安装产物：

- `/usr/bin/hillstonux-gui`（Tauri 应用）
- `/usr/bin/hillstonux-migrate`（配置迁移 CLI）
- `/usr/lib/systemd/system/hillstonux-daemon.socket`（systemd socket unit）
- `/usr/lib/systemd/system/hillstonux-daemon.service`（systemd 服务单元，socket-activated）
- `/usr/share/dbus-1/system.d/com.hillstonux.daemon.conf`（DBus 策略，可选，socket 已够）
- `/usr/share/applications/hillstonux-gui.desktop`（KDE 启动器）
- `/usr/share/icons/hicolor/{16,22,32,48,64,128,256,512}/apps/hillstonux.png`（托盘图标，按 §15.1 候选 C）

### 11.3 系统集成产物

- `/etc/systemd/system/hillstonux-daemon.service`（systemd 单元，root 启动）；
- `~/.config/hillstonux/profiles.toml`（运行时由 GUI 创建）；
- `~/.local/share/hillstonux/`（日志目录）。

### 11.4 配置文件迁移工具

提供独立二进制 `hillstonux-migrate`（与 daemon、GUI 同 deb 包安装），用于将 Python 版 `config.json` 中的明文密码平滑迁移到 Secret Service：

```
Usage: hillstonux-migrate <config.json>
```

行为：

1. 读取 `<config.json>`，找到 `server/port/user/pass` 字段；
2. 用 `keyring` crate 创建 Secret Service 项 `libsecret:hillstonux:migrated:<user>@<server>`，密码为 `pass` 字段；
3. 生成 `~/.config/hillstonux/profiles.toml`，`password_ref` 指向刚创建的 Secret Service 项，`server/port/user` 来自配置；
4. **将原 `config.json` 重命名为 `config.json.migrated.bak`**（不删除），打印迁移摘要；
5. 用户在 GUI 中验证连通后，可手动删除 `.migrated.bak`。

幂等：重复运行会覆盖同 ID 的 Secret Service 项并刷新 profile（保留用户在 GUI 中改过的字段）。

---

## 12. 里程碑

### Milestone 0：脚手架（半日）

- 创建 workspace、四个 crate、Tauri 应用；
- CI（GitHub Actions / GitLab CI 任一）：lint + test + build；
- 占位 README + LICENSE。

### Milestone 1：`hillstonux-core` 协议层 + 字节级兼容（3–5 日）

- `message.rs`、`protocol.rs`；
- 与 Python 端 cross-check 通过；
- 单测覆盖 ≥ 80%。

### Milestone 2：ESP / IPsec（3–5 日）

- `ipsec/esp.rs`、`ipsec/sa.rs`；
- 与 scapy `SecurityAssociation` 对比测试通过；
- 出向 / 入向报文互通验证。

### Milestone 3：`hillstonux-net`（2–3 日）

- TUN、UDP socket、路由、DNS；
- netns 集成测试。

### Milestone 4：守护进程 + IPC（2 日）

- unix socket 服务、Controller、Supervisor；
- systemd 单元文件、安装脚本；
- polkit 路径（可选）。

### Milestone 5：Tauri GUI + 托盘（2–3 日）

- 前端表单、状态展示、日志面板；
- 系统托盘、关窗最小化；
- 连接配置 profiles 与 Secret Service 集成。

### Milestone 6：端到端验证与发布（2 日）

- 与 Python 版同服务器对比；
- `.deb` 打包（含 daemon socket/service + migrate + GUI）；
- README / 用户文档（含 `migrate` 使用说明）。

**总计：约 2.5–3.5 周。**

---

## 13. 风险与回退

| 风险 | 影响 | 回退方案 |
|---|---|---|
| ESP 用户态实现有 bug | 数据面完全不通 | 保留 Python 守护进程为 fallback；GUI 提供"高级 → 切换到兼容模式" |
| Wayland 托盘不兼容 | 关闭主窗口后无入口 | 仅 KDE Plasma 范围，Plasma 6 在 Wayland 下 StatusNotifierItem 原生支持 |
| systemd-resolved DNS 切换失败 | DNS 泄漏 / 无法解析内网 | 退到 `nmcli con mod ... ipv4.dns` 路径（已纳入 §7.3） |
| libsecret / KWallet 不可用 | 密码无法保存 | fallback 到 `~/.local/share/hillstonux/.pw`（权限 0600）并明确 UI 提示风险 |
| socket-activated 守护进程行为反直觉 | 用户期望 daemon 一直跑 | 设置面板可切换为 `enabled` 常驻模式 |
| .deb 打包时 cargo-deb 与 Tauri 集成 | 打包脚本复杂 | 退路：手写 `debian/control` + `cargo build --release` 后用 `dpkg-deb` 手动打包 |

---

## 14. 留给实现者的自由度

以下事项**不**在本文档决策范围内，由实现阶段确定：

- 前端组件的具体样式（色板、字号、间距）— 参考 GNOME HIG；
- 日志格式（tracing subscriber 风格 + 颜色）；
- 单元测试的 helper crate 选择（用 rstest 还是手写 fixture）；
- CI 选型（GitHub Actions / GitLab CI / Drone）；
- AppImage 签名密钥管理；
- 国际化（i18n）字符串提取方式 — 若 MVP 不做 i18n 可跳过；
- 性能 profiling 工具（cargo flamegraph / perf）。

---

## 15. 已确认的决策（来自对话）

| 议题 | 决策 | 备注 |
|---|---|---|
| 目标平台 | 仅 Linux | 用户明确 |
| GUI 框架 | Rust + Tauri 2.x | 用户明确 |
| 桌面环境 | **仅 KDE Plasma 5.20+ / 6.x**（X11 + Wayland） | 用户明确 |
| 前端框架 | Svelte 5 + TypeScript | 默认；用户偏好可改 |
| 进程模型 | 守护进程 + GUI 分离 | 推荐方案 |
| 凭据存储 | libsecret（Secret Service） | 反目标 #4 排除明文 |
| 包格式 | **仅 `.deb`** | 用户明确不需 AppImage |
| 守护进程运行用户 | **root** | systemd `hillstonux-daemon.service` 以 root 启动 |
| 守护进程启动时机 | **方案 B：socket-activated** | 闲置 0 资源；GUI 连入即拉起 |
| polkit 路径 | 不需要 | 仅 systemd 路径 |
| License | **MIT** | 仓库根 `LICENSE`，新代码以 MIT 贡献 |
| 品牌 / 名称 | **沿用 hillstonux** | 名称统一 |
| 托盘图标 | **候选 C：favicon PNG 系列** | `…/cropped-未标题-1_画板-1-{32,48,64,128,192,256}.png` |
| 配置文件迁移工具 | **提供** `hillstonux-migrate` 二进制 | 将 Python 版 `config.json` 平移到 Secret Service + TOML |
| 多 profile | **MVP 单 profile**（数据结构预留多 profile） | UI 不暴露切换 |
| **自动重连** | **开启（G7）**：退避 1/2/4/8/16/30s，最多 5 次 | 用户明确要求 |
| autostart GUI | **不自动启动** | 用户从应用菜单启动 |
| 架构 target | **amd64 only** | `x86_64-unknown-linux-gnu`；aarch64 后置 |
| 协议实现范围 | MVP 仅 AES-CBC + HMAC-MD5-96 | 3DES 保留但不端到端验证 |
| 依赖版本策略 | **始终 latest**（caret 约束） | CI 跑 `cargo update` 升级 |
| 参考源 | **以用户修改后的 `/home/redtramp/Green/Network/hillstonux` 为准**，不是 GitHub 上游 | 上游 `https://github.com/zCanek/hillstonux` |

### 15.1 已锁定的托盘图标

来源：`https://www.hillstonenet.com.cn/`，选定候选 C（站点 favicon PNG 系列）：

```
https://www.hillstonenet.com.cn/wp-content/uploads/2023/03/cropped-未标题-1_画板-1-32x32.png
https://www.hillstonenet.com.cn/wp-content/uploads/2023/03/cropped-未标题-1_画板-1-180x180.png
https://www.hillstonenet.com.cn/wp-content/uploads/2023/03/cropped-未标题-1_画板-1-192x192.png
https://www.hillstonenet.com.cn/wp-content/uploads/2023/03/cropped-未标题-1_画板-1-270x270.png
```

打包时按需下载并放入 `assets/icons/{16,22,32,48,64,128,256,512}.png`，由 `tauri.conf.json` 的 `bundle.icon` 引用。来源记录在 `assets/icons/SOURCES.md`。

---

## 16. 设计文档状态

**所有开放问题已解决。** 文档可批准。

审批 checklist：

- [ ] §2 Goals 与 Anti-Goals 是要做的核心（新增 G7 自动重连）
- [ ] §3 约束（仅 KDE / 仅 deb / latest deps / MIT / 用户修改后的参考源）确认
- [ ] §5 模块划分边界合理
- [ ] §6 接口签名符合预期（含 §7.6 自动重连的状态机扩展）
- [ ] §11 打包路径（deb + systemd socket-activated + migrate 工具）确认
- [ ] §12 里程碑节奏可接受
- [ ] §15 全部决策都已落到具体章节

---

**审阅 checklist**：

- [ ] §2 Goals 是否仍是要做的核心
- [ ] §3 约束是否漏掉（Wayland 特殊处理、glibc 版本、musl？）
- [ ] §5 模块划分边界是否合理
- [ ] §6 接口签名是否符合你的预期
- [ ] §11 依赖版本是否需要锁定到特定版本
- [ ] §12 里程碑节奏是否可接受
- [ ] §16 开放问题是否要先解决再批准

批准后我会用 `superpowers:writing-plans` 把它转成 Task 级实施计划（带 TDD 步骤、可逐任务验收）。
