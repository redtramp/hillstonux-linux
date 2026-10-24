//! 无头实服务器联调探针（headless live probe）。
//!
//! 驱动 Rust 控制面连上真实 Hillstone SSL VPN 服务器，并发送一个格式正确的
//! ESP 数据包（内层为发往隧道 DNS 服务器的 UDP DNS 查询；通过原始 UDP 套接字
//! 发出，无需 CAP_NET_ADMIN / TUN），验证服务器能解密我们的出向 ESP 并把
//! 应答以入向 ESP 回送。
//!
//! 运行（凭据从环境变量读取，不写入仓库）：
//! ```bash
//! HS_SERVER=sslvpn.example.com HS_PORT=4433 \
//! HS_USER=your_user HS_PASS='your_pass' \
//! cargo run -p hillstonux-core --example live_probe
//! ```
//!
//! 成功判据：收到一个可被入向密钥成功解密的入向 ESP 包，即证明控制面握手 +
//! 数据面 SA（密钥派生 / ESP 线格式）与真实服务器互通。

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use hillstonux_core::client::{ClientCore, KeyMaterial, NetworkConfig};
use hillstonux_core::ipsec::{decrypt_packet, encrypt_packet, expand, EncAlg};

/// 标准因特网校验和（RFC 1071）。
fn internet_checksum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < buf.len() {
        sum += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }
    if buf.len() % 2 == 1 {
        sum += (buf[buf.len() - 1] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// 在 src->dst 之间封装一个 IPv4 报文，载荷为 `payload`，协议号 `proto`。
fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut ip = vec![0u8; total_len];
    ip[0] = 0x45;
    ip[1] = 0;
    ip[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&0x3412u16.to_be_bytes());
    ip[6..8].copy_from_slice(&0u16.to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = proto;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let cs = internet_checksum(&ip);
    ip[10..12].copy_from_slice(&cs.to_be_bytes());
    ip[20..].copy_from_slice(payload);
    ip
}

/// 构造 UDP DNS 查询（发往隧道 DNS 服务器，几乎必然回送应答）。
fn build_udp_dns_query(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    // DNS 报文：查询 example.com A 记录
    let mut q = Vec::new();
    q.extend_from_slice(&0x1234u16.to_be_bytes()); // transaction id
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    q.extend_from_slice(&0x0001u16.to_be_bytes()); // qdcount=1
    q.extend_from_slice(&0x0000u16.to_be_bytes());
    q.extend_from_slice(&0x0000u16.to_be_bytes());
    q.extend_from_slice(&0x0000u16.to_be_bytes());
    q.extend_from_slice(b"\x07example\x03com\x00"); // 域名
    q.extend_from_slice(&0x0001u16.to_be_bytes()); // type A
    q.extend_from_slice(&0x0001u16.to_be_bytes()); // class IN

    // UDP 数据报
    let udp_len = 8 + q.len();
    let mut udp = vec![0u8; udp_len];
    udp[0..2].copy_from_slice(&0x3039u16.to_be_bytes()); // sport 12345
    udp[2..4].copy_from_slice(&53u16.to_be_bytes()); // dport 53
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[6..8].copy_from_slice(&0u16.to_be_bytes()); // checksum (IPv4 上可为 0)
    udp[8..].copy_from_slice(&q);

    build_ipv4(src, dst, 17, &udp) // protocol 17 = UDP
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = std::env::var("HS_SERVER").expect("HS_SERVER 未设置");
    let port: u16 = std::env::var("HS_PORT")
        .unwrap_or_else(|_| "4433".into())
        .parse()?;
    let user = std::env::var("HS_USER").expect("HS_USER 未设置");
    let pass = std::env::var("HS_PASS").expect("HS_PASS 未设置");

    // --- 控制面握手 ---
    let mut client = ClientCore::new();
    client.connect_tcp(&server, port).await?;
    println!("[1] TLS 控制通道已建立");

    client.auth(&user, &pass, "", "").await?;
    println!("[2] AUTH 通过");

    client.client_info().await?;
    println!("[3] CLNT_INFO 通过");

    let net: NetworkConfig = client.wait_network().await?;
    println!(
        "[4] 网络配置: client_ip={}/{} gateway={} dns={:?} udp_port={}",
        net.client_ip, net.netmask, net.gateway, net.dns, net.server_udp_port
    );

    let km: KeyMaterial = client.exchange_key().await?;
    println!(
        "[5] 密钥协商: out_spi={:08x} in_spi={:08x} crypt={} iv={} auth={}",
        km.outbound_spi, km.inbound_spi, km.crypt_size, km.iv_size, km.auth_size
    );

    // --- 选择算法 ---
    let (enc_alg, use_sha1) = match (km.crypt_size, km.iv_size, km.auth_size) {
        (0x10, 0x10, 0x10) => (EncAlg::AesCbc, false), // AES-CBC + HMAC-MD5-96
        (0x10, 0x10, 0x14) => (EncAlg::AesCbc, true),  // AES-CBC + HMAC-SHA1-96
        (0x18, 8, 0x10) => (EncAlg::TripleDes, false), // 3DES + HMAC-MD5-96
        (0x18, 8, 0x14) => (EncAlg::TripleDes, true),  // 3DES + HMAC-SHA1-96
        _ => panic!(
            "不支持的算法组合: crypt={} iv={} auth={}",
            km.crypt_size, km.iv_size, km.auth_size
        ),
    };

    let exp = expand(&km.keymat, km.crypt_size, km.auth_size, km.iv_size);

    // --- 数据面：发送一个格式正确的出向 ESP ---
    let server_ip = tokio::net::lookup_host((server.as_str(), port))
        .await?
        .next()
        .ok_or("无法解析服务器地址")?
        .ip();

    // 内层：发往隧道 DNS 服务器的 UDP DNS 查询（最可能被回送应答）。
    let dns_dst = net
        .dns
        .first()
        .copied()
        .unwrap_or(Ipv4Addr::new(8, 8, 8, 8));
    let inner = build_udp_dns_query(net.client_ip, dns_dst);
    let _esp_out = encrypt_packet(
        km.outbound_spi,
        1,
        &exp.out_crypt_key,
        &exp.out_auth_key,
        &exp.out_iv,
        km.iv_size,
        enc_alg,
        use_sha1,
        &inner,
    );

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let target = SocketAddr::new(server_ip, net.server_udp_port);

    // 先发一次保活，部分服务器据此激活数据面 SA。
    let _ = client.send_keepalive().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 连续发送两次出向 ESP（seq=1,2），覆盖可能的 SA 激活延迟。
    for seq in [1u32, 2] {
        let esp = encrypt_packet(
            km.outbound_spi,
            seq,
            &exp.out_crypt_key,
            &exp.out_auth_key,
            &exp.out_iv,
            km.iv_size,
            enc_alg,
            use_sha1,
            &inner,
        );
        let sent = sock.send_to(&esp, target).await?;
        println!(
            "[6] 已发送出向 ESP(seq={}) {} 字节到 {}:{} (内层目标 DNS {})",
            seq, sent, server_ip, net.server_udp_port, dns_dst
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let _ = client.send_keepalive().await;

    // --- 等待入向 ESP 应答 ---
    let mut buf = [0u8; 65535];
    match tokio::time::timeout(Duration::from_secs(12), sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _from))) => {
            let pkt = &buf[..n];
            match decrypt_packet(
                &exp.in_crypt_key,
                &exp.in_auth_key,
                km.iv_size,
                enc_alg,
                use_sha1,
                pkt,
            ) {
                Ok(inner_back) => {
                    let ok_ipv4 = inner_back.len() >= 20 && (inner_back[0] >> 4) == 4;
                    println!(
                        "[7] 成功：收到入向 ESP（{} 字节）并被入向密钥成功解密；内层 {} 字节，IPv4={}",
                        n, inner_back.len(), ok_ipv4
                    );
                    println!("    => 控制面 + 数据面 SA 与真实服务器互通验证通过");
                }
                Err(e) => {
                    println!("[7] 收到 {} 字节入向包但解密失败：{:?}", n, e);
                    if n >= 36 {
                        println!(
                            "    入向 SPI={:08x}",
                            u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]])
                        );
                    }
                }
            }
        }
        Ok(Err(e)) => println!("[7] 接收错误：{}", e),
        Err(_) => {
            println!("[7] 8 秒内未收到入向 ESP。可能为服务器路由策略未回送（不代表格式错误）。");
        }
    }

    let _ = client.logout().await;
    Ok(())
}
