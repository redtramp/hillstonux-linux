# Hillstonux

**English version: [README.md](README.md)**

**Hillstone Secure Connect** SSL VPN 客户端的 Rust + Tauri GUI 重实现，
面向 Linux（KDE Plasma）。上游 Python `hillstonux` CLI 的直接替代品：
协议与服务端兼容性完全一致，同时提供系统托盘 GUI、自动重连和纯二进制
安装路径。

> **状态：** MVP。协议层已与 Python 参考实现逐字节验证一致（由交叉校验
> 夹具保证）；GUI 可在 KDE Plasma 上启动并通过 daemon 管理连接。数据面、
> 自动重连、daemon 残留恢复、profile/钥匙串集成均已实现并有单元测试。
> 端到端 VPN 流量仍需要一个真实的 Hillstone 服务器进行验证。

> **说明：本项目由 AI 生成。** 本仓库中的代码由 AI 编程代理（AtomCode）
> 在维护者的指导与审查下编写。

## 项目结构

布局遵循 Tauri v2 标准项目结构：JavaScript（Svelte）项目位于顶层，
整个 Rust 项目位于 `src-tauri/`（同时也是 Cargo 工作区根目录）。

```
.
├── index.html
├── package.json            # pnpm 脚本（dev / build / tauri / build:daemon）
├── svelte.config.js
├── tsconfig.json
├── vite.config.ts
├── src/                    # Svelte 前端
├── src-tauri/              # Rust 项目（Cargo 工作区根）
│   ├── Cargo.toml          # workspace 定义 + hillstonux-gui 包
│   ├── Cargo.lock
│   ├── build.rs
│   ├── tauri.conf.json
│   ├── rust-toolchain.toml
│   ├── capabilities/       # Tauri ACL 能力声明
│   ├── gen/schemas/        # 生成的 ACL schema
│   ├── icons/
│   ├── src/                # Tauri 命令、IPC 客户端、配置持久化
│   ├── tests/
│   └── crates/
│       ├── hillstonux-core/    # 协议编解码 + ESP/IPsec 原语
│       ├── hillstonux-net/     # TUN、UDP、路由、DNS
│       ├── hillstonux-daemon/  # 特权守护进程：连接生命周期 + IPC 服务
│       └── hillstonux-migrate/ # 一次性 Python 配置迁移工具
├── docs/                   # 设计文档
└── LICENSE
```

## 构建

系统依赖（Debian/Ubuntu）：

```sh
sudo apt install -y \
  libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
  librsvg2-dev libssl-dev pkg-config build-essential nodejs
```

Rust 工具链（1.78+）：

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

构建全部 Rust 二进制（GUI、daemon、migrate）：

```sh
cd src-tauri && cargo build --workspace --release
```

或在仓库根目录使用 Tauri CLI 一行命令：

- `pnpm tauri:dev` — 完整开发循环：构建 debug 版 daemon，同时启动
  vite 开发服务器（`localhost:5173` HMR）和 GUI。
- `pnpm gui:standalone` — 构建自包含的 debug 版 GUI 二进制
  （`src-tauri/target/debug/hillstonux-gui`，已内嵌前端），可直接运行，
  无需开发服务器。

## 安装（从源码）

```sh
cd src-tauri && cargo build --workspace --release
sudo cp target/release/hillstonux-gui target/release/hillstonux-daemon \
         target/release/hillstonux-migrate /usr/local/bin/
```

然后从桌面启动 **Hillstonux**（或运行 `hillstonux-gui`）。daemon 进程会在
首次连接时由 GUI 自动拉起，无需 systemd 配置。

### 从 Python 客户端迁移

如果你有上游 Python 客户端的 `config.json`：

```sh
hillstonux-migrate /path/to/config.json
```

它会把密码存入 OS 钥匙串（Secret Service / KWallet），并生成引用它的
`~/.config/hillstonux/profiles.toml`。原 JSON 会被重命名为
`config.json.migrated.bak`。

## 使用

1. 从 KDE 应用菜单（或 `hillstonux-gui`）启动 **Hillstonux**。
2. 主窗口有 Server / Port / Username / Password 字段和连接按钮，以及
   *全隧道* 复选框（默认分流：只有服务端声明的子网走 VPN，其余流量
   仍走上行链路）。
3. 关闭窗口会把应用最小化到系统托盘。点击托盘图标唤回窗口，右键打开
   菜单（显示 / 退出）。

### 行为细节

- **默认分流**：daemon 只把服务端在 `SET_ROUTE` 中宣告的子网经 TUN
  接口下发。默认路由保留在上行链路，因此没有互联网出口的服务端也能
  正常工作外部流量。
- **自动重连**：默认开启。失败后 daemon 按指数退避重试（1/2/4/8/16/30
  秒，默认上限 5 次）。当前尝试次数与下次等待时间显示在状态徽标的
  *Reconnecting* 阶段。
- **残留恢复**：启动时 daemon 会探测并清理上次崩溃遗留的 TUN 设备 /
  路由，然后再绑定 socket。
- **实例接管**：daemon 是按用户的单实例。启动时检测并安全接管旧的运行
  实例（例如二进制被重新编译、显示为 `... (deleted)` 的实例）。
- **DNS**：daemon 备份 `/etc/resolv.conf` 并把服务端 DNS 直接写入
  （处理符号链接），不触碰 NetworkManager。断开时恢复备份。
- **资料恢复**：如果 `profiles.toml` 里有上次会话的 profile，启动时表单
  会自动回填。密码在连接时从钥匙串读取。

## 架构

工作区共五个 crate（除 GUI 是 `src-tauri` 包本身外，均位于
`src-tauri/crates/`）：

| Crate                | 职责                                               |
| -------------------- | -------------------------------------------------- |
| `hillstonux-core`    | 纯逻辑：协议编解码 + ESP/IPsec 原语               |
| `hillstonux-net`     | 系统集成：TUN、UDP、路由、DNS                      |
| `hillstonux-daemon`  | 特权进程：连接生命周期 + IPC 服务器                |
| `hillstonux-gui`     | Tauri/Svelte GUI：托盘、表单、设置、IPC 客户端     |
| `hillstonux-migrate` | 一次性 Python `config.json` 迁移工具               |

数据流：

```
+----------+   unix socket   +-------------+   TLS+UDP   +----------------+
| GUI      | <--------------> | daemon      | <---------> | Hillstone VPN  |
| (Tauri)  |   length-prefix | (started    |             | server         |
|          |     JSON        |  by GUI)    |             +----------------+
+----------+                 +------+------+
                                   |
                                   | TUN + UDP + ip route + resolv.conf
                                   v
                              +----------+
                              | kernel   |
                              +----------+
```

详细设计见
[`docs/superpowers/specs/2026-10-19-hillstonux-gui-design.md`](docs/superpowers/specs/2026-10-19-hillstonux-gui-design.md)。

## 测试

```sh
cd src-tauri && cargo test --workspace
```

协议层有逐字节交叉校验夹具（提交在 `crates/hillstonux-core/tests/fixtures/`
下），由同目录的 oracle 脚本（`python_oracle.py`、`keymat_oracle.py`、
`esp_oracle.py`）从 Python 参考实现 / scapy 生成。

前端类型检查：

```sh
pnpm exec svelte-check
```

## 安全说明

- GUI 从不持有 root。所有特权操作都经过 daemon；daemon 按用户启动，
  断开时清理资源。
- 密码存放在 OS 钥匙串（Secret Service / KWallet）中，绝不落盘。登录
  表单缓存（`~/.config/hillstonux/config.json`）以 `0600` 权限写入。
- 到 VPN 服务器的 TLS 使用 `rustls` 且为 `CERT_NONE`（与 Python 参考
  实现一致；部署签发受信任证书后，可在 `ClientCore::new` 中开启证书
  校验）。
- 完整安全模型见
  [`docs/superpowers/specs/2026-10-19-hillstonux-gui-design.md`](docs/superpowers/specs/2026-10-19-hillstonux-gui-design.md)。

## 参考

- [zCanek/hillstonux](https://github.com/zCanek/hillstonux) — 本项目用
  Rust 重新实现的上游 Python `hillstonux` CLI（Hillstone Secure Connect
  VPN 客户端）。协议行为已与该实现逐字节交叉验证；
  `src-tauri/crates/hillstonux-core/tests/fixtures/` 下的交叉校验夹具与
  Python oracle 脚本保留了它的参考输出。

## 许可证

本项目采用 MIT 许可证。完整文本见 [LICENSE](LICENSE)。

内置托盘图标取自
[`hillstonenet.com.cn`](https://www.hillstonenet.com.cn/)，仍是其所有者的
商标；见 [`src-tauri/icons/SOURCES.md`](src-tauri/icons/SOURCES.md)。
