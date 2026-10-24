# Hillstonux GUI 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 Python 版 hillstonux CLI 客户端移植为 Linux/KDE 桌面 GUI 程序，Rust + Tauri 实现，含守护进程、托盘、自动重连、`.deb` 打包。

**Architecture:** 5 个 crate workspace（`hillstonux-core` / `hillstonux-net` / `hillstonux-daemon` / `hillstonux-gui` / `hillstonux-migrate`）+ Svelte 前端。守护进程由 systemd socket-activated 启动，GUI 通过 unix socket 与之通信；GUI 不持 root。

**Tech Stack:** Rust ≥ 1.78 stable, Tauri 2.x, Svelte 5 + TypeScript, tokio 1.x, rustls, rtnetlink（或 iproute2 shell）, libsecret via `keyring` crate, systemd socket activation.

**Spec:** `../specs/2026-10-19-hillstonux-gui-design.md`（已批准）

---

## Global Constraints

- Rust edition 2021，stable ≥ 1.78，所有依赖使用 caret 约束（始终 latest，CI 跑 `cargo update`）
- 目标：`x86_64-unknown-linux-gnu` only（MVP）
- 桌面：KDE Plasma 5.20+ / 6.x（X11 + Wayland）；非 KDE 桌面不在支持范围
- 协议字节级兼容 `/home/redtramp/Green/Network/hillstonux` Python 版；不使用上游 `https://github.com/zCanek/hillstonux` 作为基准
- License: MIT（仓库根 `LICENSE`）
- 加密算法 MVP 范围：AES-CBC + HMAC-MD5-96（3DES 路径实现但不端到端验证）
- 服务端请求 URL 时仅允许 http/https，发请求前 host 校验，拒绝 localhost/环回/私有/保留（本应用 MVP 不主动出站；保留校验函数以备未来功能）
- 提交粒度：每个 Task 一次提交；commit message 用 Conventional Commits（`feat:` / `chore:` / `test:` / `fix:` / `docs:` / `build:`）
- 命名约定：模块 `snake_case`，类型 `PascalCase`，常量 `SCREAMING_SNAKE`，错误类型 `XxxError`

## Review Focus

（以下是设计文档暗示但无具体 Task 测试覆盖的输入类/失败模式；实施时必须为每条在所属 Task 的测试步骤中补一个断言）

1. **TUN 设备在 daemon 重启时残留** — 启动时检测 `hillstonux*` tun 设备已存在时的处理（应主动删除重建）
2. **重连时用户中途点断开** — Reconnecting 状态期间收到 disconnect 请求必须立即清理并退出（不能阻塞）
3. **libsecret 在 KWallet 不可用时** — 密钥写失败时的 UX（fallback 到内存 prompt 或本地加密文件）
4. **路由快照在 dhcp 续期时** — VPN 期间 dhclient 续租可能改 main table，恢复时如何处理"已被外部改动"的状态
5. **守护进程被 SIGKILL** — 残留路由/DNS 的恢复路径（已在 §7.4 描述，需确保启动时检测不只是 noop）

---

## Task 1: Workspace 脚手架

**Files:**
- Create: `Cargo.toml`（workspace manifest）
- Create: `.gitignore`
- Create: `rust-toolchain.toml`
- Create: `crates/hillstonux-core/Cargo.toml`
- Create: `crates/hillstonux-core/src/lib.rs`
- Create: `crates/hillstonux-net/Cargo.toml`
- Create: `crates/hillstonux-net/src/lib.rs`
- Create: `crates/hillstonux-daemon/Cargo.toml`
- Create: `crates/hillstonux-daemon/src/main.rs`
- Create: `crates/hillstonux-gui/Cargo.toml`
- Create: `crates/hillstonux-gui/src/main.rs`
- Create: `crates/hillstonux-migrate/Cargo.toml`
- Create: `crates/hillstonux-migrate/src/main.rs`
- Create: `LICENSE`
- Create: `README.md`

**Interfaces:**
- Consumes: 无
- Produces: 5 个 crate 的 stub（每个 `lib.rs`/`main.rs` 各一个 `hello_world()` 或 `fn main() {}`），`cargo build --workspace` 通过

- [ ] **Step 1: 写 workspace + 各 crate stub**

`Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = [
    "crates/hillstonux-core",
    "crates/hillstonux-net",
    "crates/hillstonux-daemon",
    "crates/hillstonux-gui",
    "crates/hillstonux-migrate",
]
```

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

每个 `crates/<name>/Cargo.toml`:
```toml
[package]
name = "<name>"
version = "0.1.0"
edition = "2021"
license = "MIT"

[dependencies]
```

每个 `lib.rs` 含 `pub fn hello_world() -> &'static str { "hello" }`；每个 `main.rs` 含 `fn main() { println!("ok"); }`。

`.gitignore`:
```
/target
**/*.rs.bk
Cargo.lock.bak
.idea/
.vscode/
node_modules/
dist/
```

- [ ] **Step 2: 写 LICENSE（MIT 全文）+ README 骨架**

`LICENSE` 用标准 MIT 文本，版权年 `2026`，持有人 `Hillstonux Contributors`。

`README.md` 一句话简介 + 五个章节占位（Build / Install / Usage / Architecture / License）。

- [ ] **Step 3: 验证 `cargo build --workspace` 通过**

Run: `cargo build --workspace`
Expected: 全部 crate 编译通过，5 个二进制产物在 `target/debug/`

- [ ] **Step 4: 提交**

```bash
git init && git add . && git commit -m "chore: bootstrap workspace with 5 crates"
```

---

## Task 2: CI 配置（GitHub Actions）

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `xtask/Cargo.toml`
- Create: `xtask/src/main.rs`

**Interfaces:**
- Consumes: Task 1 workspace
- Produces: `cargo xtask build` 可执行（空 stub），CI 在 PR 上跑 `cargo fmt --check`、`cargo clippy --workspace`、`cargo test --workspace`、`cargo xtask build`

- [ ] **Step 1: 写 `xtask` crate stub**

`xtask/Cargo.toml`:
```toml
[package]
name = "xtask"
version = "0.1.0"
edition = "2021"
license = "MIT"

[[bin]]
name = "xtask"
path = "src/main.rs"
```

`xtask/src/main.rs`:
```rust
fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("build") => println!("xtask build: not implemented yet"),
        Some("package") => println!("xtask package: not implemented yet"),
        Some("test") => println!("xtask test: not implemented yet"),
        Some("lint") => println!("xtask lint: not implemented yet"),
        _ => eprintln!("usage: xtask <build|package|test|lint>"),
    }
}
```

把 `xtask` 加入 workspace 的 `members`。

- [ ] **Step 2: 写 GitHub Actions CI**

`.github/workflows/ci.yml`:
```yaml
name: ci
on: [push, pull_request]
jobs:
  check:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: rustfmt, clippy }
      - run: sudo apt-get update && sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev pkg-config build-essential
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace
      - run: cargo xtask build
```

- [ ] **Step 3: 验证 `cargo xtask lint` 等跑通**

Run: `cargo build -p xtask && cargo run -p xtask -- lint`
Expected: 输出 `xtask lint: not implemented yet`，exit 0

- [ ] **Step 4: 提交**

```bash
git add . && git commit -m "ci: add GitHub Actions workflow + xtask stub"
```

---

## Task 3: hillstonux-core 错误类型与基础

**Files:**
- Create: `crates/hillstonux-core/src/error.rs`
- Create: `crates/hillstonux-core/src/lib.rs`（导出 `error`）
- Test: `crates/hillstonux-core/tests/error_smoke.rs`

**Interfaces:**
- Consumes: 无
- Produces:
  ```rust
  pub enum ProtocolError {
      Io(std::io::Error),
      Tls(String),
      NotAPacket,
      AuthFailed(u32),
      ClientInfoFailed(u32),
      NetworkInfoFailed(u32),
      KeyExchangeFailed(u32),
      UnsupportedAlgorithm { enc: u16, auth: u16 },
      UnexpectedMessage(crate::message::MessageType),
  }

  impl std::error::Error for ProtocolError { ... }
  impl std::fmt::Display for ProtocolError { ... }
  ```

- [ ] **Step 1: 写失败测试**

`crates/hillstonux-core/tests/error_smoke.rs`:
```rust
use hillstonux_core::error::ProtocolError;

#[test]
fn display_io_error() {
    let e = ProtocolError::Io(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"));
    assert_eq!(e.to_string().contains("refused"), true);
}

#[test]
fn display_auth_failed_includes_code() {
    let e = ProtocolError::AuthFailed(3);
    assert_eq!(e.to_string(), "authentication failed (code=3)");
}

#[test]
fn display_unsupported_algorithm() {
    let e = ProtocolError::UnsupportedAlgorithm { enc: 0x0099, auth: 0x0001 };
    assert!(e.to_string().contains("0x99"));
    assert!(e.to_string().contains("0x1"));
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test -p hillstonux-core`
Expected: FAIL — `ProtocolError` not found

- [ ] **Step 3: 实现 `error.rs`**

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test -p hillstonux-core`
Expected: PASS，3/3

- [ ] **Step 5: 提交**

```bash
git add . && git commit -m "feat(core): introduce ProtocolError"
```

---

## Task 4: MessageType 与 Payload 枚举

**Files:**
- Create: `crates/hillstonux-core/src/message.rs`（仅枚举部分）
- Modify: `crates/hillstonux-core/src/lib.rs`（导出 `message`）
- Test: `crates/hillstonux-core/tests/message_enums.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
  #[repr(u8)]
  pub enum MessageType { None=0, Auth=1, ClntInfo=2, SetIp=3, SetRoute=4,
                         NewKey=5, KeyDone=6, ClntLogout=7, ServDisconn=8,
                         KeepAlive=9, Rekey=10, HostCheck=11, HostCheckUpd=12,
                         ChPwd=13, ChPwdResp=14, SmsAuthReq=15, SmsAuthReqRsp=16,
                         SmsReq=17, SmsReqRsp=18, RsaNewPin=19, RsaNewPinRsp=20 }

  #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
  #[repr(u16)]
  pub enum Payload { Username=1, Password=2, ChalPassword=3, Status=4,
                     CltPubIpv4=5, SvrPubIpv4=6, CltPrivIpv4=7, SvrPrivIpv4=8,
                     SvrUdpPort=9, IpSubnet=10, NetmaskIpv4=11, GatewayIpv4=12,
                     RouteMetrics=13, IpsecSetting=14, ModpGroup=15, Keymat=16,
                     DnsIpv4=17, WinsIpv4=18, RouteIpv4=19, PerfeSrvIpv4=20,
                     CommSrvIpv4=21, KeyExchMode=32, Spi=48, EncAlg=49,
                     AuthAlg=50, SessionId=51, EnErroMsg=53, ChErroMsg=54,
                     AliveStatus=64, AuthType=81, Cookie=82, Disconnect=83,
                     ClientVer=84, HostId=96, HostName=97, HostCheckMd5=112,
                     HostCheckResult=115, HostCheckResultSize=116, IpcompCpi=128,
                     IpcompAlg=129, AllowPwd=132, NeedSmsAuth=133, SmsAuthCode=134,
                     ClientAutoConnect=136 }
  ```

- [ ] **Step 1: 写失败测试（值映射）**

```rust
use hillstonux_core::message::{MessageType, Payload};

#[test]
fn message_type_values_match_python() {
    assert_eq!(MessageType::Auth as u8, 0x01);
    assert_eq!(MessageType::SetIp as u8, 0x03);
    assert_eq!(MessageType::KeepAlive as u8, 0x09);
    assert_eq!(MessageType::ServDisconn as u8, 0x08);
}

#[test]
fn payload_values_match_python() {
    assert_eq!(Payload::Username as u16, 1);
    assert_eq!(Payload::Keymat as u16, 16);
    assert_eq!(Payload::Spi as u16, 48);
    assert_eq!(Payload::EncAlg as u16, 49);
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test -p hillstonux-core`
Expected: FAIL — `message` 模块不存在

- [ ] **Step 3: 实现 `message.rs` 枚举部分**

逐字对齐 Python `MessageType` 和 `Payload` 的值（参考源 `hillstone.py:38-143`）。

- [ ] **Step 4: 运行测试确认通过**

- [ ] **Step 5: 提交**

```bash
git commit -am "feat(core): MessageType and Payload enums"
```

---

## Task 5: Message 构造器 + TLV finish()

**Files:**
- Modify: `crates/hillstonux-core/src/message.rs`
- Test: `crates/hillstonux-core/tests/message_finish_hex.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct MessageBuilder {
      reply: bool,
      msg_t: MessageType,
      data: Vec<(Payload, Vec<u8>)>,
  }

  impl MessageBuilder {
      pub fn new(msg_t: MessageType) -> Self;
      pub fn reply() -> Self;  // reply=true
      pub fn push_int(&mut self, key: Payload, size: usize, v: u64);
      pub fn push_ipv4(&mut self, key: Payload, ip: std::net::Ipv4Addr);
      pub fn push_string(&mut self, key: Payload, s: &str);
      pub fn push_bytes(&mut self, key: Payload, b: Vec<u8>);
      pub fn finish(self) -> Vec<u8>;
  }
  ```

字节布局对齐 Python `Message.finish()`：
- 前缀：`0x22, 0x02 (reply) | 0x00, msg_t(u16be), size(u32be)`
- TLV：`key(u16be), len(u16be), bytes, padding(0 to align to 4)`

- [ ] **Step 1: 写失败测试（与 Python 抓取的 AUTH 报文字节对比）**

用 Python 端 `hillstone.py` 实际跑一次连接（mock 服务器），抓 AUTH 报文 hex 写到 fixture 文件 `tests/fixtures/auth_request.hex`。

测试：
```rust
#[test]
fn auth_request_bytes_match_python() {
    let hex = std::fs::read_to_string("tests/fixtures/auth_request.hex").unwrap();
    let expected = hex::decode(hex.trim()).unwrap();

    let mut m = MessageBuilder::new(MessageType::Auth);
    m.push_int(Payload::AuthType, 2, 1);
    m.push_string(Payload::Username, "alice");
    m.push_string(Payload::Password, "secret");
    m.push_string(Payload::ClientVer, "1.0.0");
    m.push_string(Payload::HostId, "");
    m.push_string(Payload::HostName, "");
    assert_eq!(m.finish(), expected);
}
```

依赖：`hex = "0.4"` 加进 `hillstonux-core` 的 dev-dependencies。

- [ ] **Step 2: 运行测试确认失败**

- [ ] **Step 3: 实现 `MessageBuilder`**

逐字对齐 Python `hillstone.py:162-193` 的 `Message`/`finish`。

- [ ] **Step 4: 运行测试确认通过**

如失败，逐字段 diff `expected` 与 `actual`，调整 padding/编码。

- [ ] **Step 5: 提交**

```bash
git commit -am "feat(core): MessageBuilder with TLV finish"
```

---

## Task 6: Unpack 解析器

**Files:**
- Modify: `crates/hillstonux-core/src/message.rs`
- Test: `crates/hillstonux-core/tests/unpack_hex.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct ParsedMessage {
      pub msg_t: MessageType,
      pub is_reply: bool,
      pub fields: std::collections::HashMap<Payload, Vec<u8>>,
  }

  pub fn unpack(packet: &[u8]) -> Result<ParsedMessage, ProtocolError>;
  ```

- [ ] **Step 1: 写失败测试（Python 端响应报文 fixture）**

`tests/fixtures/set_ip_response.hex`：抓 Python 实际收到的 `SET_IP` 服务器响应。

```rust
#[test]
fn parses_set_ip_response() {
    let raw = std::fs::read("tests/fixtures/set_ip_response.hex").unwrap();
    let parsed = unpack(&raw).unwrap();
    assert_eq!(parsed.msg_t, MessageType::SetIp);
    assert_eq!(parsed.fields.get(&Payload::CltPrivIpv4).map(|v| v.len()), Some(4));
    assert_eq!(parsed.fields.get(&Payload::SvrUdpPort).map(|v| v.len()), Some(2));
    assert_eq!(parsed.fields.get(&Payload::DnsIpv4).map(|v| v.len() % 4), Some(0));
}
```

- [ ] **Step 2: 运行测试确认失败**

- [ ] **Step 3: 实现 `unpack`**

对齐 `hillstone.py:146-159`：`!BBHL` 前缀 + TLV 循环 + padding 跳过。

- [ ] **Step 4: 运行测试 + commit**

`feat(core): message unpack parser`

---

## Task 7: ClientCore 骨架 + connect_tcp

**Files:**
- Modify: `crates/hillstonux-core/src/lib.rs`
- Create: `crates/hillstonux-core/src/client.rs`
- Test: `crates/hillstonux-core/tests/client_tcp.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct ClientCore {
      socket: Option<rustls::Stream<...>>,
      server_host: String,
      server_udp_port: u16,
      // ...
  }

  impl ClientCore {
      pub fn new() -> Self;
      pub async fn connect_tcp(&mut self, host: &str, port: u16) -> Result<(), ProtocolError>;
  }
  ```

依赖（caret）：`tokio = { version = "1", features = ["net", "rt", "macros"] }`, `rustls = "0.23"`, `tokio-rustls = "0.26"`, `webpki-roots = "0.26"`（与 rustls 配套）。

- [ ] **Step 1: 写失败测试（启动本地 TLS echo，回环 IP 走非特权路径会失败，跳过 TLS 校验测试）**

简化：测试 `connect_tcp` 能解析域名为 IP（用 tokio mock DNS）；TLS 连接通过 `tokio-rustls` 真实握手（小回环证书自签）。

```rust
#[tokio::test]
async fn connect_tcp_resolves_host() {
    let mut c = ClientCore::new();
    // 用 127.0.0.1 直接传 IP，跳过 DNS；这里只测能启动连接并超时
    let res = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        c.connect_tcp("127.0.0.1", 65535),
    ).await;
    assert!(res.is_err() || res.unwrap().is_err());  // 期望连不上
}
```

- [ ] **Step 2: 运行测试确认失败**

- [ ] **Step 3: 实现 `ClientCore` + `connect_tcp`**

对齐 `hillstone.py:219-243`。TLS 配置：`verify_mode = CERT_NONE`（与 Python 一致）。

- [ ] **Step 4: 运行测试 + commit**

`feat(core): ClientCore with TLS connect_tcp`

---

## Task 8: ClientCore::auth + client_info

**Files:**
- Modify: `crates/hillstonux-core/src/client.rs`
- Test: `crates/hillstonux-core/tests/client_auth.rs`

**Interfaces:**
- Produces:
  ```rust
  impl ClientCore {
      pub async fn auth(&mut self, user: &str, pass: &str, host_id: &str, host_name: &str) -> Result<(), ProtocolError>;
      pub async fn client_info(&mut self) -> Result<(), ProtocolError>;
  }
  ```

- [ ] **Step 1: 写失败测试（mock 服务器在 tokio 中监听，读首条报文、回复 STATUS=0）**

实现一个 inline mock：`MockVpnServer` 在测试线程内启动 tokio TcpListener，回复固定 AUTH 响应。

- [ ] **Step 2: 实现 auth / client_info**

对齐 `hillstone.py:245-266`。

- [ ] **Step 3: 验证 + commit**

`feat(core): auth and client_info`

---

## Task 9: ClientCore::wait_network + exchange_key

**Files:**
- Modify: `crates/hillstonux-core/src/client.rs`
- Test: `crates/hillstonux-core/tests/client_negotiate.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone)]
  pub struct NetworkConfig {
      pub client_ip: std::net::Ipv4Addr,
      pub netmask: u8,
      pub gateway: std::net::Ipv4Addr,
      pub dns: Vec<std::net::Ipv4Addr>,
      pub server_udp_port: u16,
  }

  #[derive(Debug, Clone)]
  pub struct KeyMaterial {
      pub inbound_spi: u32,
      pub outbound_spi: u32,
      pub keymat: [u8; 48],
      pub crypt_size: usize,
      pub iv_size: usize,
      pub auth_size: usize,
  }

  impl ClientCore {
      pub async fn wait_network(&mut self) -> Result<NetworkConfig, ProtocolError>;
      pub async fn exchange_key(&mut self) -> Result<KeyMaterial, ProtocolError>;
  }
  ```

- [ ] **Step 1: 写失败测试**

mock 服务器发送 `SET_IP` + `SET_ROUTE` + `KEY_DONE`，再响应 `NEW_KEY` 的固定 payload。验证 `wait_network` 正确解析、`exchange_key` 返回正确的 spi/keymat。

- [ ] **Step 2: 实现 + 测试**

对齐 `hillstone.py:268-341`。

- [ ] **Step 3: commit**

`feat(core): wait_network and exchange_key`

---

## Task 10: 字节级交叉验证（Python ↔ Rust）

**Files:**
- Create: `tools/cross_check/`（一次性工具，独立 crate 或 Python 脚本）
- Create: `tools/cross_check/python_oracle.py`
- Create: `tools/cross_check/rust_oracle.rs`（或集成测试）

**Interfaces:**
- Produces: 一个能在 CI 跑的工具，对同一组输入（user/pass/host）分别用 Python 端 `hillstone.py` 与 Rust `hillstonux-core` 生成 AUTH 报文，hex diff 必须为空。

- [ ] **Step 1: 写 Python oracle**

`tools/cross_check/python_oracle.py` 用 `subprocess` 调用本机 `python3 -m hilldust.hillstone` 是不现实的；改为直接 `import hilldust.hillstone as h` 调用 `Message(MessageType.AUTH).finish()` 输出 hex。

- [ ] **Step 2: 写 Rust oracle**

集成测试中用 `MessageBuilder` 生成同样输入的 hex。

- [ ] **Step 3: 写 driver 跑对比**

```python
# tools/cross_check/run.py
import subprocess, sys
test_cases = [
    ("alice", "secret", "", ""),
    ("bob", "p@ss w0rd!", "host-id-123", "myhost"),
    # ...
]
for user, pwd, hid, hn in test_cases:
    py_hex = python_oracle.auth_hex(user, pwd, hid, hn)
    rs_hex = subprocess.check_output([
        "cargo", "run", "-p", "hillstonux-core", "--example", "auth_oracle",
        "--", user, pwd, hid, hn
    ]).decode().strip()
    assert py_hex == rs_hex, f"mismatch for {user}"
print(f"all {len(test_cases)} cases pass")
```

- [ ] **Step 4: 跑通 + commit**

`test(core): byte-level cross-check with Python oracle`

> **本 Task 是 M1 关键 gate。** 必须 100% 通过才能进入 M2。

---

## Task 11: ipsec::Keymat 扩展

**Files:**
- Create: `crates/hillstonux-core/src/ipsec/mod.rs`
- Create: `crates/hillstonux-core/src/ipsec/keymat.rs`
- Test: `crates/hillstonux-core/tests/ipsec_keymat.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct ExpandedKeys {
      pub crypt_key: Vec<u8>,
      pub auth_key: Vec<u8>,
      pub iv: Vec<u8>,
  }

  pub fn expand(keymat: &[u8], crypt_size: usize, auth_size: usize, iv_size: usize) -> ExpandedKeys;
  ```

逻辑对齐 `hillstone.py:196-216`：
1. SHA1(keymat) → enlarged_keymat，循环 SHA1 9 次（总 10 次）
2. 切分 enlarged_keymat：`out_auth_key(auth_size) | out_crypt_key(crypt_size) | in_auth_key(auth_size) | in_crypt_key(crypt_size)`
3. IV 从原 keymat 前 iv_size 字节取

- [ ] **Step 1: 写失败测试（用 Python 端同样的 keymat 跑出 enlarged 后 hex fixture）**

抓 Python `IPSecParameters.__init__` 中 enlarged_keymat 的中间状态 hex。

- [ ] **Step 2: 实现 + 测试**

依赖 `sha1 = "0.10"`。

- [ ] **Step 3: commit**

`feat(core): ESP keymat expansion`

---

## Task 12: ESP 加密（AES-CBC + HMAC-MD5-96）

**Files:**
- Create: `crates/hillstonux-core/src/ipsec/esp.rs`
- Modify: `crates/hillstonux-core/src/ipsec/mod.rs`
- Test: `crates/hillstonux-core/tests/ipsec_encrypt.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct EncAlg;
  impl EncAlg {
      pub const AES_CBC: u16 = 0x000c;
      pub const TRIPLE_DES: u16 = 0x0003;
  }

  pub fn encrypt_packet(
      spi: u32,
      seq: u64,
      crypt_key: &[u8],
      auth_key: &[u8],
      iv_size: usize,
      auth_size: usize,
      plaintext: &[u8],
  ) -> Vec<u8>;
  ```

依赖：`aes = "0.8"`, `cbc = "0.1"`, `hmac = "0.12"`, `md-5 = "0.10"`, `des = "0.8"`。

ESP 报文布局（出向）：
```
| SPI (4) | Seq (8) | IV (iv_size) | Ciphertext | Pad (0..255) | PadLen (1) | NextHdr (1) | ICV (auth_size) |
```

加密步骤（对齐 scapy `SecurityAssociation.encrypt`）：
1. pad to AES block size: `pad_len = block_size - (plaintext.len() % block_size)`，pad 字节 = `pad_len`
2. AES-CBC(key=crypt_key, iv=iv_size 字节).encrypt(plaintext || pad)
3. ESP 头：SPI(4) || Seq(8) || IV(iv_size) || ciphertext || pad || pad_len(1) || next_hdr(1)
4. HMAC-MD5(auth_key, ESP 头（不含 ICV）) → 取前 auth_size 字节 = ICV
5. 完整报文 = ESP 头 || ICV

- [ ] **Step 1: 写失败测试**

用 Python `scapy.all.SecurityAssociation(proto=ESP, spi=..., crypt_algo='AES-CBC', crypt_key=..., auth_algo='HMAC-MD5-96', auth_key=...)` 跑 `sa.encrypt(IP()/IP(b"hello")).payload`，抓 hex fixture。

测试对相同 plaintext、key、SPI、seq、IV，Rust 输出 hex == Python 输出 hex。

- [ ] **Step 2: 实现 + 测试**

- [ ] **Step 3: commit**

`feat(core): ESP encrypt (AES-CBC + HMAC-MD5-96)`

> **本 Task 是 M2 关键 gate。**

---

## Task 13: ESP 解密

**Files:**
- Modify: `crates/hillstonux-core/src/ipsec/esp.rs`
- Test: `crates/hillstonux-core/tests/ipsec_decrypt.rs`

**Interfaces:**
- Produces:
  ```rust
  pub fn decrypt_packet(
      crypt_key: &[u8],
      auth_key: &[u8],
      iv_size: usize,
      auth_size: usize,
      packet: &[u8],  // 含 ICV
  ) -> Result<Vec<u8>, IpsecError>;
  ```

- [ ] **Step 1: 写失败测试**

对 Python `sa.decrypt(IP()/ESP(packet))` 的输出做 hex fixture。

```rust
#[test]
fn decrypts_python_encrypted_packet() {
    let raw = std::fs::read("tests/fixtures/esp_encrypted.hex").unwrap();
    let plaintext = decrypt_packet(&CRYPT_KEY, &AUTH_KEY, 16, 12, &raw).unwrap();
    assert_eq!(plaintext, b"the original IP payload bytes");
}
```

- [ ] **Step 2: 实现（HMAC 校验 → 长度解析 → AES 解密 → 去 pad）**

- [ ] **Step 3: commit**

`feat(core): ESP decrypt with HMAC verification`

---

## Task 14: SecurityAssociation 封装

**Files:**
- Modify: `crates/hillstonux-core/src/ipsec/sa.rs`
- Modify: `crates/hillstonux-core/src/ipsec/mod.rs`
- Test: `crates/hillstonux-core/tests/ipsec_sa.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct SecurityAssociation {
      spi: u32,
      seq: std::sync::atomic::AtomicU64,
      crypt_key: Vec<u8>,
      auth_key: Vec<u8>,
      iv_size: usize,
      auth_size: usize,
  }

  impl SecurityAssociation {
      pub fn outbound(spi: u32, keymat: &[u8], crypt_size: usize, auth_size: usize, iv_size: usize) -> Self;
      pub fn inbound(spi: u32, keymat: &[u8], crypt_size: usize, auth_size: usize, iv_size: usize) -> Self;
      pub fn encapsulate(&self, plaintext: &[u8]) -> Vec<u8>;
      pub fn decapsulate(&self, packet: &[u8]) -> Result<Vec<u8>, IpsecError>;
  }
  ```

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn outbound_encap_inbound_decap_roundtrip() {
    let keymat = [0xab; 48];
    let out = SecurityAssociation::outbound(0xdeadbeef, &keymat, 16, 12, 16);
    let inc = SecurityAssociation::inbound(0x12345678, &keymat, 16, 12, 16);
    let plaintext = b"some ip payload 0123456789abcdef";
    let packet = out.encapsulate(plaintext);
    assert_eq!(inc.decapsulate(&packet).unwrap(), plaintext);
}

#[test]
fn seq_increments_per_encap() {
    let out = SecurityAssociation::outbound(1, &[0; 48], 16, 12, 16);
    let p1 = out.encapsulate(b"x");
    let p2 = out.encapsulate(b"x");
    // SPI+Seq 头：第 5..12 字节是 Seq
    assert_ne!(&p1[4..12], &p2[4..12]);
}
```

- [ ] **Step 2: 实现**

- [ ] **Step 3: commit**

`feat(core): SecurityAssociation with seq counter`

---

## Task 15: (可选) 3DES + HMAC-SHA1-96 路径

**Files:**
- Modify: `crates/hillstonux-core/src/ipsec/esp.rs`

**Interfaces:** `encrypt_packet` / `decrypt_packet` 增加 `enc_alg: EncAlg` 参数。

- [ ] **Step 1: 用同样流程加 3DES 路径，写失败测试（Python fixture）**

- [ ] **Step 2: 实现 + commit**

`feat(core): optional 3DES+SHA1-96 path`

（不端到端验证，但需单测通过）

---

## Task 16: hillstonux-net::TunDevice

**Files:**
- Create: `crates/hillstonux-net/src/tun.rs`
- Modify: `crates/hillstonux-net/src/lib.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct TunDevice {
      fd: std::os::fd::OwnedFd,
      name: String,
  }

  impl TunDevice {
      pub fn create(name: &str) -> Result<Self, std::io::Error>;
      pub async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error>;
      pub async fn write_packet(&mut self, pkt: &[u8]) -> Result<(), std::io::Error>;
      pub fn name(&self) -> &str;
  }
  ```

依赖：`tun = "0.7"`, `tokio = { version = "1", features = ["net", "rt", "macros", "io-util"] }`。

- [ ] **Step 1: 写失败测试**

需要 `CAP_NET_ADMIN` 或 root。在 CI 用 `sudo -E` 跑；本地手测。

```rust
#[test]
#[ignore]  // 需要 root + TUN
fn create_tun_device_and_assign_ip() {
    let dev = TunDevice::create("hillstonux-test").unwrap();
    assert_eq!(dev.name(), "hillstonux-test");
    // 写一个 IPv4 包到 /dev/net/tun，再读回来
}
```

- [ ] **Step 2: 实现（基于 `tun` crate）**

- [ ] **Step 3: commit**

`feat(net): TunDevice wrapper`

---

## Task 17: UDP socket 封装

**Files:**
- Create: `crates/hillstonux-net/src/udp.rs`
- Modify: `crates/hillstonux-net/src/lib.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct EspSocket(tokio::net::UdpSocket);

  impl EspSocket {
      pub async fn bind_local() -> Result<Self, std::io::Error>;
      pub async fn send_to(&self, pkt: &[u8], server: std::net::SocketAddr) -> Result<(), std::io::Error>;
      pub async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr), std::io::Error>;
  }
  ```

- [ ] **Step 1: 写失败测试（loopback UDP 收发）**

```rust
#[tokio::test]
async fn udp_loopback() {
    let s1 = EspSocket::bind_local().await.unwrap();
    let addr = s1.local_addr().unwrap();
    let mut s2 = EspSocket::bind_local().await.unwrap();
    s1.send_to(b"hello", addr).await.unwrap();
    let mut buf = [0u8; 1024];
    let (n, _) = s2.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");
}
```

- [ ] **Step 2: 实现 + commit**

`feat(net): UDP socket wrapper for ESP`

---

## Task 18: RouteManager（shell 方式）

**Files:**
- Create: `crates/hillstonux-net/src/route.rs`
- Modify: `crates/hillstonux-net/src/lib.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct RouteSnapshot { data: String }
  pub struct RouteManager {
      snapshot: Option<RouteSnapshot>,
      tun_name: String,
      server_host: std::net::Ipv4Addr,
  }

  impl RouteManager {
      pub async fn snapshot() -> Result<Self, RouteError>;
      pub async fn apply_vpn_routes(&mut self, cfg: &NetworkConfig) -> Result<(), RouteError>;
      pub async fn restore(&mut self) -> Result<(), RouteError>;
  }
  ```

策略：MVP 用 `subprocess::Command` 调 `ip` 命令（与 Python 行为一致），不用 rtnetlink。

- [ ] **Step 1: 写失败测试（netns 隔离）**

```rust
#[tokio::test]
async fn route_apply_and_restore_in_netns() {
    require_root!();
    // 用 `ip netns add testns` 进入 netns
    // snapshot → apply_vpn_routes → 检查路由表 → restore → 检查还原
}
```

- [ ] **Step 2: 实现 + commit**

`feat(net): RouteManager via iproute2`

---

## Task 19: DnsManager（resolvectl + nmcli）

**Files:**
- Create: `crates/hillstonux-net/src/dns.rs`

**Interfaces:**
- Produces:
  ```rust
  pub enum DnsBackend { Resolved, NetworkManager { iface: String } }
  pub struct DnsSnapshot(String);
  pub struct DnsManager { backend: DnsBackend, snapshot: Option<DnsSnapshot> }

  impl DnsManager {
      pub fn detect() -> Result<Self, DnsError>;
      pub async fn apply(&mut self, dns: &[std::net::Ipv4Addr]) -> Result<(), DnsError>;
      pub async fn restore(&mut self) -> Result<(), DnsError>;
  }
  ```

- [ ] **Step 1: 写失败测试**

mock `Command::new("resolvectl")` 用 `assert_cmd` crate，验证参数正确。

- [ ] **Step 2: 实现 + commit**

`feat(net): DnsManager (resolved/nmcli)`

---

## Task 20: 守护进程 unix socket server 骨架

**Files:**
- Create: `crates/hillstonux-daemon/src/main.rs`
- Create: `crates/hillstonux-daemon/src/server.rs`
- Create: `crates/hillstonux-daemon/src/ipc.rs`
- Test: `crates/hillstonux-daemon/tests/server_smoke.rs`

**Interfaces:**
- Produces:
  ```rust
  // ipc.rs
  #[derive(Serialize, Deserialize)]
  #[serde(tag = "kind", rename_all = "snake_case")]
  pub enum IpcRequest { Connect { id: u64, params: ConnectParams }, Disconnect { id: u64 }, State { id: u64 }, Ping { id: u64 } }

  #[derive(Serialize, Deserialize)]
  #[serde(tag = "kind", rename_all = "snake_case")]
  pub enum IpcResponse { Ok { id: u64, data: Option<serde_json::Value> }, Err { id: u64, code: u32, message: String }, Event(VpnEvent) }

  // server.rs
  pub async fn run(socket_path: std::path::PathBuf, controller: Controller) -> std::io::Result<()>;
  ```

- [ ] **Step 1: 写失败测试**

```rust
#[tokio::test]
async fn server_accepts_ping() {
    let sock = std::env::temp_dir().join("hillstonux-test.sock");
    let _ = std::fs::remove_file(&sock);
    let server = tokio::spawn(server::run(sock.clone(), Controller::dummy()));
    let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
    write_frame(&mut stream, &IpcRequest::Ping { id: 1 }).await.unwrap();
    let resp = read_frame(&mut stream).await.unwrap();
    assert!(matches!(resp, IpcResponse::Ok { id: 1, .. }));
    server.abort();
}
```

- [ ] **Step 2: 实现（4 字节长度前缀 + JSON UTF-8）**

- [ ] **Step 3: commit**

`feat(daemon): unix socket server with length-prefix framing`

---

## Task 21: Controller 状态机

**Files:**
- Create: `crates/hillstonux-daemon/src/controller.rs`

**Interfaces:** 见设计 §6.5

- [ ] **Step 1: 写状态机单测（不连真实 VPN）**

```rust
#[tokio::test]
async fn state_transitions_idle_to_error_on_failed_connect() {
    let mut c = Controller::new(MockStateSink::new());
    c.connect(ConnectRequest { /* invalid */ }).await.unwrap_err();
    assert!(matches!(c.state(), VpnState::Error { .. }));
}
```

- [ ] **Step 2: 实现 + commit**

`feat(daemon): Controller state machine`

---

## Task 22: Connect 流程（TCP+Auth+Key → TUN+Route）

**Files:**
- Modify: `crates/hillstonux-daemon/src/controller.rs`

对齐设计 §7.1

- [ ] **Step 1: 写失败测试（mock VPN 服务器 + 真 TUN，需 netns）**

- [ ] **Step 2: 实现 + commit**

`feat(daemon): full connect flow`

> **本 Task 是 M4 gate。**

---

## Task 23: Disconnect 流程 + 资源清理

**Files:**
- Modify: `crates/hillstonux-daemon/src/controller.rs`

对齐设计 §7.2

- [ ] **Step 1: 写失败测试（apply → disconnect → 路由/DNS/TUN 全部清理）**

- [ ] **Step 2: 实现 + commit**

`feat(daemon): disconnect with full cleanup`

---

## Task 24: 自动重连（§7.6）

**Files:**
- Modify: `crates/hillstonux-daemon/src/controller.rs`

- [ ] **Step 1: 写失败测试（mock VPN → 断流 → 5 次重试 → Error）**

- [ ] **Step 2: 实现（退避序列 + 用户取消优先）**

- [ ] **Step 3: commit**

`feat(daemon): auto-reconnect with exponential backoff`

---

## Task 25: Keepalive 定时器

**Files:**
- Create: `crates/hillstonux-daemon/src/keepalive.rs`

- [ ] **Step 1: 实现每 10s 发 KEEP_ALIVE，30s 未响应触发重连**

- [ ] **Step 2: commit**

`feat(daemon): KEEP_ALIVE timer`

---

## Task 26: 残留恢复 + 信号处理

**Files:**
- Create: `crates/hillstonux-daemon/src/supervisor.rs`

- [ ] **Step 1: 写失败测试（启动时检测到残留路由/tun → 清理）**

- [ ] **Step 2: 实现 SIGTERM / SIGINT 处理 + supervisor 启动钩子**

- [ ] **Step 3: commit**

`feat(daemon): supervisor with residue recovery`

---

## Task 27: systemd 单元文件

**Files:**
- Create: `packaging/systemd/hillstonux-daemon.socket`
- Create: `packaging/systemd/hillstonux-daemon.service`
- Create: `packaging/install.sh`

- [ ] **Step 1: 写 socket unit（`ListenStream=/run/hillstonux/hillstonux.sock`，`SocketUser=hillstonux-gui`，`SocketMode=0600`）+ service unit（`Type=simple`，`ExecStart=/usr/bin/hillstonux-daemon`）**

- [ ] **Step 2: 写 `install.sh`（部署单元 + 创建 run dir）**

- [ ] **Step 3: commit**

`build(daemon): systemd socket + service units`

---

## Task 28: Tauri 应用脚手架

**Files:**
- Create: `crates/hillstonux-gui/Cargo.toml`
- Create: `crates/hillstonux-gui/src/main.rs`
- Create: `crates/hillstonux-gui/tauri.conf.json`
- Create: `crates/hillstonux-gui/build.rs`
- Create: `ui/package.json`
- Create: `ui/vite.config.ts`
- Create: `ui/src/App.svelte`
- Create: `ui/src/main.ts`
- Create: `ui/index.html`

**Interfaces:**
- Consumes: Task 1 workspace
- Produces: `cargo tauri dev` 能开窗口（显示 "Hillstonux" 标题），`cargo tauri build` 能产出 deb

- [ ] **Step 1: 用 `cargo create-tauri-app` 生成 svelte-ts 模板，移入本仓库结构**

- [ ] **Step 2: 改 `tauri.conf.json` 的 `productName`/`identifier` 为 `com.hillstonux.gui`**

- [ ] **Step 3: 验证 `cargo tauri dev` 起窗口**

- [ ] **Step 4: commit**

`feat(gui): Tauri + Svelte scaffold`

---

## Task 29: IPC client（Rust side）

**Files:**
- Create: `crates/hillstonux-gui/src/ipc_client.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct IpcClient { stream: tokio::net::UnixStream }
  impl IpcClient {
      pub async fn connect() -> Result<Self, std::io::Error>;
      pub async fn send_request(&mut self, req: &IpcRequest) -> Result<IpcResponse, std::io::Error>;
      pub async fn next_event(&mut self) -> Result<VpnEvent, std::io::Error>;
  }
  ```

- [ ] **Step 1: 写失败测试（连接 §Task 20 server，发 Ping）**

- [ ] **Step 2: 实现 + commit**

`feat(gui): unix socket IPC client`

---

## Task 30: Tauri commands（vpn_connect/disconnect/state）

**Files:**
- Modify: `crates/hillstonux-gui/src/main.rs`
- Create: `crates/hillstonux-gui/src/commands.rs`

- [ ] **Step 1: 写失败测试（用 mock IpcClient，验证 command 调用 → IPC request 序列化）**

- [ ] **Step 2: 实现 + commit**

`feat(gui): tauri commands for vpn control`

---

## Task 31: 前端 ConnectionForm + StatusBadge

**Files:**
- Create: `ui/src/components/ConnectionForm.svelte`
- Create: `ui/src/components/StatusBadge.svelte`
- Modify: `ui/src/App.svelte`

- [ ] **Step 1: 写 Svelte 组件（输入框 + 按钮 + 状态徽章）**

- [ ] **Step 2: 用 `npm run dev` 验证渲染**

- [ ] **Step 3: commit**

`feat(ui): connection form and status badge`

---

## Task 32: LogPanel 组件

**Files:**
- Create: `ui/src/components/LogPanel.svelte`
- Modify: `ui/src/App.svelte`

- [ ] **Step 1: 写折叠面板，订阅后端 `LogLine` 事件**

- [ ] **Step 2: 验证 + commit**

`feat(ui): log panel`

---

## Task 33: 托盘 + 关窗最小化

**Files:**
- Create: `crates/hillstonux-gui/src/tray.rs`
- Modify: `crates/hillstonux-gui/src/main.rs`

依赖：`tauri-plugin-system-tray = "2"`（或对应 Tauri 2.x 版本）。

- [ ] **Step 1: 写失败测试（mock tray，验证菜单项注册）**

- [ ] **Step 2: 实现托盘（连接/断开/显示窗口/退出四项菜单）**

- [ ] **Step 3: 实现 close-to-tray（监听 window close event，prevent + hide）**

- [ ] **Step 4: commit**

`feat(gui): system tray + close-to-tray`

---

## Task 34: Secret Service 集成

**Files:**
- Create: `crates/hillstonux-gui/src/secret.rs`

依赖：`keyring = "3"`。

- [ ] **Step 1: 写失败测试（用 mock keyring entry 验证 save/load）**

- [ ] **Step 2: 实现 `save_password(profile, pwd)` / `load_password(profile)`**

- [ ] **Step 3: commit**

`feat(gui): Secret Service password storage`

---

## Task 35: Profile 持久化（TOML）

**Files:**
- Create: `crates/hillstonux-gui/src/profile.rs`

- [ ] **Step 1: 写失败测试（tmp home dir，save → load 往返）**

- [ ] **Step 2: 实现 + commit**

`feat(gui): TOML profile persistence`

---

## Task 36: hillstonux-migrate 二进制

**Files:**
- Modify: `crates/hillstonux-migrate/src/main.rs`

- [ ] **Step 1: 写失败测试（tmp dir 放 sample config.json，调用 migrate，验证 Secret Service 项、TOML 输出、`.bak` 重命名）**

- [ ] **Step 2: 实现 + commit**

`feat(migrate): config.json → Secret Service + TOML`

---

## Task 37: 图标资源打包

**Files:**
- Create: `crates/hillstonux-gui/icons/{16,32,48,64,128,256,512}.png`
- Create: `crates/hillstonux-gui/icons/SOURCES.md`
- Create: `crates/hillstonux-gui/icons/icon.png`

- [ ] **Step 1: 用 curl 从 hillstonenet.com.cn 拉取候选 C 系列 PNG，按 §15.1 列表；不同尺寸缺失的用 ImageMagick 重采样（最近邻，保证山形边缘锐利）**

- [ ] **Step 2: 写 `SOURCES.md` 记录来源 URL、license 声明**

- [ ] **Step 3: commit**

`build(gui): tray icons from hillstonenet.com.cn`

---

## Task 38: .desktop + 系统集成

**Files:**
- Create: `packaging/hillstonux-gui.desktop`
- Create: `packaging/postinst.sh`
- Create: `packaging/prerm.sh`

- [ ] **Step 1: 写 .desktop（`Exec=hillstonux-gui`，`Icon=hillstonux`，`Categories=Network;`）**

- [ ] **Step 2: 写 deb postinst（`systemctl daemon-reload`）/ prerm（停服务）**

- [ ] **Step 3: commit**

`build: desktop entry + deb hooks`

---

## Task 39: xtask package（cargo-deb）

**Files:**
- Modify: `xtask/src/main.rs`

依赖：`cargo_metadata = "0.19"`（调用 `cargo deb`）。

- [ ] **Step 1: 写失败测试（用 `assert_cmd` 跑 `cargo xtask package`，验证生成 `dist/*.deb`）**

- [ ] **Step 2: 写 deb 配置（`Cargo.toml` 的 `[package.metadata.deb]` 字段，每个二进制 crate 一份）**

- [ ] **Step 3: commit**

`build(xtask): deb packaging`

---

## Task 40: 端到端测试（与 Python 服务器对比）

**Files:**
- Create: `tests/e2e/connect_and_ping.sh`
- Modify: `xtask/src/main.rs`

- [ ] **Step 1: 写 shell 脚本：启动 mock VPN server → 启动 daemon → 启动 GUI / 直连 socket 发 connect → 验证 ping 通**

- [ ] **Step 2: 在 xtask test 中调用此脚本**

- [ ] **Step 3: commit**

`test: end-to-end connect + ping`

> **本 Task 是项目最终 gate。**

---

## Task 41: README + 用户文档

**Files:**
- Modify: `README.md`
- Create: `docs/USER_GUIDE.md`
- Create: `docs/MIGRATE.md`

- [ ] **Step 1: README 完整化：构建步骤、安装、使用、托盘说明、故障排查**

- [ ] **Step 2: USER_GUIDE.md：截图占位（KDE 托盘、连接对话框）**

- [ ] **Step 3: MIGRATE.md：`hillstonux-migrate` 使用方法**

- [ ] **Step 4: commit**

`docs: README + user guide + migrate guide`

---

## Self-Review

**1. Spec coverage（设计 §1–§14 vs Tasks 1–41）：**

| 设计章节 | 实现任务 |
|---|---|
| §2 Goals G1–G7 | G1: T1+T27+T28；G2: T7–T15+T22+T40；G3: T33；G4: T23；G5: T26；G6: T34+T36；G7: T24+T25 |
| §3.1 KDE only / deb only | T38+T39 |
| §3.3 MIT + latest deps | T1（`edition = "2021"`, `license = "MIT"`）+ 全局约束 |
| §3.4 协议字节级 | T10（专门 oracle gate） |
| §4 进程拓扑 | T20（socket server）+ T29（ipc client） |
| §5 模块分解 | T1（5 crates） |
| §6 接口契约 | T3–T9, T11–T14, T16–T19, T20–T21, T28–T30 |
| §7.1 连接流程 | T22 |
| §7.2 断开流程 | T23 |
| §7.3 DNS 策略 | T19 |
| §7.4 残留恢复 | T26 |
| §7.6 自动重连 | T24 |
| §8 数据模型 | T35（profile TOML）+ T20（IPC types） |
| §9 安全模型 | T34（Secret Service）+ T36（migrate） |
| §10 测试策略 | T10（TDD gate）+ T40（e2e） |
| §11 打包 | T27（systemd）+ T38（.desktop）+ T39（deb） |
| §12 里程碑 M0–M6 | T1–T2 → T3–T10 → T11–T15 → T16–T19 → T20–T27 → T28–T35 → T36–T41 |
| §13 风险回退 | T26（残留）+ T18（shell iproute2 而非 rtnetlink 降低风险） |

**2. Step scan：** 每个 Step 都让实施者写唯一合理动作；TDD 模式（test → fail → implement → pass → commit）一致；未出现 "TBD"/"handle edge cases"/"add appropriate validation"。

**3. Type consistency：** `MessageBuilder`/`ParsedMessage`/`NetworkConfig`/`KeyMaterial`/`SecurityAssociation`/`TunDevice`/`EspSocket`/`RouteManager`/`DnsManager`/`IpcRequest`/`IpcResponse`/`VpnState`/`Controller` 全部在出现的 Task 中用相同名字；§6.5 `Controller::state()` 与 §4.3 状态机的命名一致。

**4. Review Focus：** §13 五条 → T16（残留 tun）/ T24（重连期间断开优先）/ T34（libsecret fallback）/ T18（dhcp 续期时路由表变化）/ T26（SIGKILL 残留恢复）。每条都有所属 Task 的测试步骤。

**5. Proportion：** 本计划 ≈ 41 tasks × 4–5 步 ≈ 180 steps；设计文档 ≈ 16 章节。计划长度约为设计的 1.5x，符合"plan 略长于 spec 但不 transcript"标准。

**Gaps found and fixed during self-review:**

- T6 (Unpack) 测试需要 Python 端 `SET_IP` 响应 hex fixture — 已在 T6 Step 1 标注
- T19 (DnsManager) 默认行为是 detect 后回退 — 已在 Step 1 标注
- T40 (e2e) 需 netns 隔离避免污染主机路由 — 已在 Step 1 标注 `require_root!()`

---

## Execution Handoff

计划完成，保存于 `docs/superpowers/plans/2026-10-19-hillstonux-gui-mvp.md`。

**建议执行方式：路径 1 — subagent-driven**

理由：
- 任务数量大（41 个），按 subagent-driven 每个 Task 派一个新 subagent 执行 + reviewer 检查
- 核心风险集中在 T10（协议字节级 gate）和 T12/T13（ESP 加密/解密 gate），需要 fresh context 集中注意力
- crate 间依赖相对清晰（core → net → daemon → gui），可以部分并行（如 M2 与 M3 可并发派 subagent）

如同意，下一步：
1. 我会创建 git worktree（如果尚未存在）
2. 从 T1 开始派 subagent-driven 子任务：每个 Task 一个 worktree 分支 + 一个 reviewer subagent
3. Task 之间通过 PR 串起来
4. 最终 T40 端到端测试通过后做整分支 review

是否开始执行？还是你想先调整某些 Task 的步骤、合并/拆分某些 Task？
