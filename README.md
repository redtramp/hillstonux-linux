# Hillstonux

**中文版本：[README.zh-CN.md](README.zh-CN.md)**

A Rust + Tauri GUI reimplementation of the **Hillstone Secure Connect** SSL
VPN client for Linux (KDE Plasma). Drop-in replacement for the upstream
Python [`hillstonux`](https://github.com/zCanek/hillstonux) CLI: same protocol, same server compatibility, but with
a system-tray GUI, automatic reconnect, and a plain binary install path.

> **Status:** MVP. The protocol layer has byte-level parity with the Python
> reference (verified by cross-check fixtures); the GUI launches on KDE
> Plasma and can manage a connection through the daemon. The data plane,
> auto-reconnect, daemon-residue recovery, and profile/keyring integration
> are all implemented and unit-tested. End-to-end VPN traffic still requires
> a live Hillstone server to validate against.

> **Note: this project is AI-generated.** The code in this repository was
> written by an AI coding agent (AtomCode) under the maintainer's direction
> and review.

## Project structure

The layout follows the standard Tauri v2 project structure: the JavaScript
(Svelte) project lives at the top level, and the entire Rust project lives
in `src-tauri/` (which is also the Cargo workspace root).

```
.
├── index.html
├── package.json            # pnpm scripts (dev / build / tauri / build:daemon)
├── svelte.config.js
├── tsconfig.json
├── vite.config.ts
├── src/                    # Svelte frontend
├── src-tauri/              # Rust project (Cargo workspace root)
│   ├── Cargo.toml          # workspace definition + hillstonux-gui package
│   ├── Cargo.lock
│   ├── build.rs
│   ├── tauri.conf.json
│   ├── rust-toolchain.toml
│   ├── capabilities/       # Tauri ACL capabilities
│   ├── gen/schemas/        # generated ACL schemas
│   ├── icons/
│   ├── src/                # Tauri commands, IPC client, config persistence
│   ├── tests/
│   └── crates/
│       ├── hillstonux-core/    # protocol codec + ESP/IPsec primitives
│       ├── hillstonux-net/     # TUN, UDP, routes, DNS
│       ├── hillstonux-daemon/  # privileged daemon: lifecycle + IPC server
│       └── hillstonux-migrate/ # one-shot Python config migration tool
├── docs/                   # design specs
└── LICENSE
```

## Build

System dependencies (Debian/Ubuntu):

```sh
sudo apt install -y \
  libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
  librsvg2-dev libssl-dev pkg-config build-essential nodejs
```

Rust toolchain (1.78+):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Build all Rust binaries (GUI, daemon, migrate):

```sh
cd src-tauri && cargo build --workspace --release
```

Or use the Tauri CLI one-liners from the repo root:

- `pnpm tauri:dev` — full dev loop: builds the debug daemon, starts
  the vite dev server (HMR on `localhost:5173`) and the GUI together.
- `pnpm gui:standalone` — builds a self-contained debug GUI binary at
  `src-tauri/target/debug/hillstonux-gui` with the frontend bundled. Run it
  directly; no dev server required.

## Install (from source)

```sh
cd src-tauri && cargo build --workspace --release
sudo cp target/release/hillstonux-gui target/release/hillstonux-daemon \
         target/release/hillstonux-migrate /usr/local/bin/
```

Then launch **Hillstonux** from the desktop (or `hillstonux-gui`). The
daemon process is started automatically by the GUI on first connect; no
systemd setup is required.

### Migrating from the Python client

If you have the upstream Python client's `config.json`:

```sh
hillstonux-migrate /path/to/config.json
```

This stores your password in the OS keyring (Secret Service / KWallet) and
generates `~/.config/hillstonux/profiles.toml` referencing it. The original
JSON is renamed to `config.json.migrated.bak`.

## Usage

1. Launch **Hillstonux** from the KDE application menu (or `hillstonux-gui`).
2. The main window has Server / Port / Username / Password fields and a
   Connect button, plus a *full tunnel* checkbox (default is split tunnel:
   only the server-declared subnets go through the VPN, everything else
   stays on the uplink).
3. Closing the window hides the app to the system tray. Click the tray icon
   to bring the window back; right-click for the menu (Show / Quit).

### Behavior details

- **Split tunnel by default**: the daemon installs only the subnets the
  server advertises in `SET_ROUTE` via the TUN interface. The default route
  stays on the uplink, so servers without internet egress keep external
  traffic working.
- **Auto-reconnect**: enabled by default. On failure the daemon retries
  with exponential backoff (1/2/4/8/16/30 s, capped at 5 attempts by
  default). The current attempt + next delay are visible as the
  *Reconnecting* phase in the status badge.
- **Residue recovery**: on startup the daemon probes for leftover TUN
  devices / routes from a previous crash and cleans them up before
  binding the socket.
- **Instance takeover**: the daemon is a per-user single instance. On
  startup it detects and safely replaces an older running instance
  (e.g. one whose binary was recompiled, showing as `... (deleted)`).
- **DNS**: the daemon backs up `/etc/resolv.conf` and writes the server
  DNS straight into it (symlinks handled); it does not touch
  NetworkManager. On disconnect the backup is restored.
- **Re-hydration**: if `profiles.toml` has a profile from a previous
  session, the form rehydrates on launch. The password is fetched from the
  keyring at connect time.

## Architecture

The workspace has five crates (all under `src-tauri/crates/` except the
GUI, which is the `src-tauri` package itself):

| Crate                | Responsibility                                         |
| -------------------- | ------------------------------------------------------ |
| `hillstonux-core`    | Pure logic: protocol codec + ESP/IPsec primitives     |
| `hillstonux-net`     | System integration: TUN, UDP, routes, DNS              |
| `hillstonux-daemon`  | Privileged process: connection lifecycle + IPC server  |
| `hillstonux-gui`     | Tauri/Svelte GUI: tray, forms, settings, IPC client    |
| `hillstonux-migrate` | One-shot migration tool from Python `config.json`      |

Data flow:

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

Detailed design lives at
[`docs/superpowers/specs/2026-10-19-hillstonux-gui-design.md`](docs/superpowers/specs/2026-10-19-hillstonux-gui-design.md).

## Testing

```sh
cd src-tauri && cargo test --workspace
```

The protocol layer has byte-level cross-check fixtures (committed under
`crates/hillstonux-core/tests/fixtures/`), generated from the Python
reference / scapy by the oracle scripts in the same directory
(`python_oracle.py`, `keymat_oracle.py`, `esp_oracle.py`).

Frontend type check:

```sh
pnpm exec svelte-check
```

## Security notes

- The GUI never holds root. All privileged operations go through the
  daemon, which is started per-user and cleaned up on disconnect.
- Passwords are stored in the OS keyring (Secret Service / KWallet),
  never on disk. The login form cache
  (`~/.config/hillstonux/config.json`) is written with `0600` permissions.
- TLS to the VPN server uses `rustls` with `CERT_NONE` (matches the Python
  reference; turn on certificate verification in `ClientCore::new` once
  your deployment issues trusted certs).
- See [`docs/superpowers/specs/2026-10-19-hillstonux-gui-design.md`](docs/superpowers/specs/2026-10-19-hillstonux-gui-design.md)
  for the full security model.

## References

- [zCanek/hillstonux](https://github.com/zCanek/hillstonux) — the upstream
  Python `hillstonux` CLI (Hillstone Secure Connect VPN client) that this
  project reimplements in Rust. Protocol behavior was cross-checked
  byte-for-byte against that implementation; the cross-check fixtures and
  Python oracle scripts under
  `src-tauri/crates/hillstonux-core/tests/fixtures/` capture its reference
  output.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for
the full text.

The bundled tray icon is fetched from
[`hillstonenet.com.cn`](https://www.hillstonenet.com.cn/) and remains the
trademark of its respective owner; see
[`src-tauri/icons/SOURCES.md`](src-tauri/icons/SOURCES.md).
