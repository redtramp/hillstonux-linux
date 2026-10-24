//! DNS apply/restore 手动验证（直写 /etc/resolv.conf，需 root 运行）。
//!
//! 用法: sudo cargo run -p hillstonux-net --example dns_cycle
use std::net::Ipv4Addr;

use hillstonux_net::dns::DnsManager;

fn resolv_conf() -> String {
    std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default()
}

#[tokio::main]
async fn main() {
    let before_conf = resolv_conf();
    println!("--- resolv.conf BEFORE ---\n{}", before_conf.trim());

    let mut mgr = DnsManager::with_paths("/etc/resolv.conf", "/tmp/hillstonux-dns-state.json");
    mgr.restore_orphaned().await;
    mgr.apply(&[Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)])
        .await
        .expect("dns apply failed");
    let after_conf = resolv_conf();
    println!("--- resolv.conf AFTER apply ---\n{}", after_conf.trim());

    mgr.restore().await.expect("dns restore failed");
    let restored = resolv_conf();
    println!("--- resolv.conf AFTER restore ---\n{}", restored.trim());
    assert_eq!(restored, before_conf, "restore 结果与原始状态不一致");
    println!("OK: restored to original state");
}
