//! Routing-table manipulation via iproute2 (`ip`).
//!
//! Mirrors Python `platform_linux.set_network` / `restore_network`. Snapshot
//! the main table before connecting (text, diagnostics only); apply VPN routes
//! on connect; on disconnect remove exactly the routes we added (surgical
//! deletion). Never flushes the whole table — the old flush+restore approach
//! corrupted the binary `ip route save` snapshot in a UTF-8 round-trip, and a
//! failed restore left the machine with an empty routing table.
//!
//! Requires CAP_NET_ADMIN (or root). All `ip` invocations are async via
//! `tokio::process::Command` so they don't block the reactor.

use std::net::Ipv4Addr;
use thiserror::Error;
use tokio::process::Command;

use hillstonux_core::client::NetworkConfig;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ip command failed: {0}")]
    Ip(String),
}

#[derive(Debug, Clone)]
pub struct RouteSnapshot {
    /// Raw `ip route show table main` output, kept for diagnostics
    /// (e.g. logged when restore fails so the pre-connect table is known).
    pub data: String,
}

#[derive(Debug)]
pub struct RouteManager {
    snapshot: Option<RouteSnapshot>,
    pub tun_name: String,
    pub server_host: Ipv4Addr,
    /// Route argument lists (`ip route del <...>`, route part only) for the
    /// routes installed by `apply_vpn_routes`, in installation order.
    /// `restore()` removes exactly these routes and nothing else.
    applied_del: Vec<Vec<String>>,
}

impl RouteManager {
    /// Snapshot the main routing table and return a manager ready to apply
    /// VPN routes. Pass `server_host` (the VPN server's IP) so the manager
    /// can install a host-route to bypass the VPN for that IP (otherwise the
    /// tunnel's default route would blackhole packets to the server itself).
    pub async fn snapshot(tun_name: &str, server_host: Ipv4Addr) -> Result<Self, RouteError> {
        // `ip route show` (text) instead of `ip route save` (binary): the
        // binary format is mangled by a String round-trip, which made the old
        // flush+restore fail and leave an empty routing table.
        let output = Command::new("ip")
            .args(["route", "show", "table", "main"])
            .output()
            .await?;
        if !output.status.success() {
            return Err(RouteError::Ip(format!(
                "ip route show failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let data = String::from_utf8_lossy(&output.stdout).into_owned();
        Ok(Self {
            snapshot: Some(RouteSnapshot { data }),
            tun_name: tun_name.to_string(),
            server_host,
            applied_del: Vec::new(),
        })
    }

    /// Install VPN routes:
    /// 1. `ip addr add dev <tun> <client_ip>/<prefix>`
    /// 2. `ip link set dev <tun> up`
    /// 3. `ip route add <server_host> via <original-gw>`  (bypass for VPN server)
    /// 4. `ip route replace <gateway> dev <tun>`          (via tunnel)
    /// 5. `ip route replace <vpn_network> via <gateway>`  (split-tunnel catch)
    /// 6. Full-tunnel mode: `ip route replace default metric 0 via <gateway>`.
    ///    Split-tunnel mode (`full_tunnel == false`): route only the subnets
    ///    advertised by the server in SET_ROUTE (`cfg.routes`) via the VPN
    ///    gateway — the default route stays on the uplink, so normal internet
    ///    access keeps working. When the server advertised no parseable
    ///    routes, split-tunnel keeps only the VPN subnet (steps 4-5) routed
    ///    via the tunnel and never takes over the default route — a silent
    ///    full-tunnel fallback would black-hole normal internet access on
    ///    servers without internet egress. A SET_ROUTE entry of 0.0.0.0/0
    ///    means the server itself wants full tunnel.
    pub async fn apply_vpn_routes(
        &mut self,
        cfg: &NetworkConfig,
        full_tunnel: bool,
    ) -> Result<(), RouteError> {
        let tun_ip = cfg.client_ip;
        let prefix = cfg.netmask;
        let gw = cfg.gateway;

        // Step 1: assign IP to TUN.
        run_ip(&[
            "addr",
            "add",
            "dev",
            &self.tun_name,
            &format!("{}/{}", tun_ip, prefix),
        ])
        .await?;
        // Step 2: bring TUN up.
        run_ip(&["link", "set", "dev", &self.tun_name, "up"]).await?;

        // Step 3: ensure a route to the server IP exists via the original gateway
        // (so we don't lose connectivity to the VPN server itself once the default
        // route is replaced). Idempotent — ignore "file exists" errors.
        let server_gw = original_gateway(self.server_host).await?;
        let _ = run_ip(&[
            "route",
            "add",
            &self.server_host.to_string(),
            "via",
            &server_gw.to_string(),
        ])
        .await;
        self.track_del(vec![format!("{}/32", self.server_host)]);

        // Step 4: route the VPN gateway through the tunnel. `replace` keeps
        // this idempotent if a previous attempt left the route behind.
        run_ip(&["route", "replace", &gw.to_string(), "dev", &self.tun_name]).await?;
        self.track_del(vec![format!("{}/32", gw)]);

        // Step 5: route the negotiated VPN network via the gateway. Two
        // subtleties:
        // 1. `cfg.client_ip` is a host address, but a route prefix must be a
        //    masked network address (iproute2 rejects non-zero host bits), so
        //    mask it first.
        // 2. step 1's `addr add` makes the kernel auto-install a connected
        //    route for the same prefix (`<net>/<prefix> dev <tun>`); `add`
        //    collides with it ("File exists"), so use `replace`.
        let vpn_net = format!("{}/{}", network_address(cfg.client_ip, prefix), prefix);
        run_ip(&["route", "replace", &vpn_net, "via", &gw.to_string()]).await?;
        self.track_del(vec![vpn_net.clone()]);

        // Step 6: default route (full tunnel) vs. advertised subnets only
        // (split tunnel). See the method docs for the fallback rules.
        if full_tunnel {
            run_ip(&[
                "route",
                "replace",
                "default",
                "metric",
                "0",
                "via",
                &gw.to_string(),
            ])
            .await?;
            self.track_del(vec![
                "default".to_string(),
                "via".to_string(),
                gw.to_string(),
            ]);
        } else {
            if cfg.routes.is_empty() {
                tracing::warn!(
                    "server advertised no parseable SET_ROUTE routes; \
                     split-tunnel routes only the VPN subnet (default route \
                     stays on the uplink)"
                );
            }
            for r in &cfg.routes {
                if r.dest.is_unspecified() {
                    // 0.0.0.0/0: the server explicitly wants full tunnel.
                    run_ip(&[
                        "route",
                        "replace",
                        "default",
                        "metric",
                        "0",
                        "via",
                        &gw.to_string(),
                    ])
                    .await?;
                    self.track_del(vec![
                        "default".to_string(),
                        "via".to_string(),
                        gw.to_string(),
                    ]);
                } else {
                    let cidr = r.to_string();
                    run_ip(&["route", "replace", &cidr, "via", &gw.to_string()]).await?;
                    self.track_del(vec![cidr]);
                }
            }
        }

        Ok(())
    }

    /// Record a route spec for surgical deletion during `restore`, skipping
    /// duplicates (a SET_ROUTE entry can repeat the VPN network that step 5
    /// already tracks; a second `route del` would fail spuriously).
    fn track_del(&mut self, spec: Vec<String>) {
        if !self.applied_del.contains(&spec) {
            self.applied_del.push(spec);
        }
    }

    /// Remove exactly the routes installed by `apply_vpn_routes` (surgical
    /// deletion, best-effort per route).
    ///
    /// Never flushes the whole table: the old implementation wiped `main`
    /// first and then restored from a corrupted snapshot, so a failed restore
    /// left the machine with an empty routing table (network dead until NM
    /// re-established the routes). Routes referencing the TUN are also
    /// auto-removed by the kernel when the TUN device is destroyed; deletion
    /// failures below cover that case (and routes that were never installed).
    pub async fn restore(&mut self) -> Result<(), RouteError> {
        let mut failures = 0;
        for spec in self.applied_del.drain(..) {
            let mut args: Vec<&str> = vec!["route", "del"];
            args.extend(spec.iter().map(String::as_str));
            if let Err(e) = run_ip(&args).await {
                tracing::warn!(
                    route = %spec.join(" "),
                    %e,
                    "route delete during restore failed (likely already gone)"
                );
                failures += 1;
            }
        }
        if failures > 0 {
            if let Some(snap) = &self.snapshot {
                tracing::warn!(table = %snap.data, "routing table before connect (diagnostics)");
            }
            return Err(RouteError::Ip(format!(
                "{failures} route deletion(s) failed during restore"
            )));
        }
        Ok(())
    }

    /// Scan for any leftover `hillstonux*` tun devices or routes via our
    /// tun_name and clean them up. Called at daemon startup.
    pub async fn detect_residue_and_recover() -> Result<(), RouteError> {
        // Best-effort: remove any hillstonux* tun device and flush routes that
        // reference it. Failure here is non-fatal — log and continue.
        let out = Command::new("ip")
            .args(["-o", "link", "show"])
            .output()
            .await?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            // Each line: "2: eth0: <BROADCAST,...> mtu 1500 ..."
            if let Some(name) = line
                .split(':')
                .nth(1)
                .map(|s| s.trim().split('@').next().unwrap_or("").to_string())
            {
                if name.starts_with("hillstonux") {
                    let _ = Command::new("ip")
                        .args(["link", "del", "dev", &name])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .await;
                }
            }
        }
        Ok(())
    }
}

async fn run_ip(args: &[&str]) -> Result<(), RouteError> {
    let output = Command::new("ip").args(args).output().await?;
    if !output.status.success() {
        return Err(RouteError::Ip(format!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Compute the network address of `ip` under a `/prefix_len` mask (ip AND mask).
/// `ip route add` requires the host bits to be zero, so a client's host address
/// must be masked down to its network address before being used as a route prefix.
fn network_address(ip: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Addr::from(u32::from(ip) & mask)
}

/// Look up the system default gateway that would route to `target` (the
/// VPN server) before the tunnel is up. Used to install a host-route bypass.
async fn original_gateway(target: Ipv4Addr) -> Result<Ipv4Addr, RouteError> {
    let out = Command::new("ip")
        .args(["route", "get", &target.to_string()])
        .output()
        .await?;
    if !out.status.success() {
        return Err(RouteError::Ip(format!(
            "ip route get failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Sample output: "1.2.3.4 via 192.168.1.1 dev eth0 src 192.168.1.42 uid 0 cache"
    parse_gateway(&stdout).ok_or_else(|| {
        RouteError::Ip(format!(
            "could not parse gateway from `ip route get` output: {}",
            stdout
        ))
    })
}

/// 从 `ip route get` 输出中提取网关：`via` 关键字**之后**的下一个 token
/// （`via` 与网关地址是两个独立 token）。目标直连（无 `via`）或输出格式异常
/// 时返回 None。
fn parse_gateway(stdout: &str) -> Option<Ipv4Addr> {
    let mut after_via = false;
    for token in stdout.split_whitespace() {
        if after_via {
            return token.parse::<Ipv4Addr>().ok();
        }
        after_via = token == "via";
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gateway_production_wpa_output() {
        // 生产环境真实输出（新版 iproute2 会追加 "uid 0 cache"）。
        let out = "112.30.185.147 via 172.16.248.1 dev wlan0 src 172.16.248.27 uid 0 cache\n";
        assert_eq!(parse_gateway(out), Some(Ipv4Addr::new(172, 16, 248, 1)));
    }

    #[test]
    fn parse_gateway_classic_output() {
        let out = "1.2.3.4 via 192.168.1.1 dev eth0 src 192.168.1.42 uid 0\n";
        assert_eq!(parse_gateway(out), Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn parse_gateway_directly_connected_has_no_gateway() {
        let out = "192.168.1.100 dev eth0 src 192.168.1.42 uid 0 cache\n";
        assert_eq!(parse_gateway(out), None);
    }

    #[test]
    fn parse_gateway_malformed_returns_none() {
        assert_eq!(parse_gateway("1.2.3.4 via\ndevice down\n"), None);
        assert_eq!(parse_gateway(""), None);
    }

    #[test]
    fn network_address_masks_client_ip_to_network() {
        // The production config that failed: client 10.250.255.176 with /22 must
        // become network 10.250.252.0 (255 AND 252 = 252), not the host address.
        assert_eq!(
            network_address(Ipv4Addr::new(10, 250, 255, 176), 22),
            Ipv4Addr::new(10, 250, 252, 0)
        );
        // Already-aligned network address is unchanged.
        assert_eq!(
            network_address(Ipv4Addr::new(10, 250, 252, 0), 22),
            Ipv4Addr::new(10, 250, 252, 0)
        );
        // Edge prefix lengths.
        assert_eq!(
            network_address(Ipv4Addr::new(1, 2, 3, 4), 0),
            Ipv4Addr::new(0, 0, 0, 0)
        );
        assert_eq!(
            network_address(Ipv4Addr::new(1, 2, 3, 4), 32),
            Ipv4Addr::new(1, 2, 3, 4)
        );
    }
}
