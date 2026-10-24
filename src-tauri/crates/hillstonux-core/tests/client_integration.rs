//! End-to-end client tests using a mock TLS server.

use std::sync::Arc;

use hillstonux_core::client::{ClientCore, KeyMaterial, NetworkConfig};
use hillstonux_core::message::{MessageBuilder, MessageType, Payload};
use std::net::Ipv4Addr;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsStream};

/// Build a self-signed TLS cert + key pair for the mock server. Returns PEM
/// strings (cert, key).
fn self_signed_cert() -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();
    (cert_pem, key_pem)
}

/// Spawn a mock VPN server. Returns the bound port.
async fn spawn_mock_server() -> u16 {
    let (cert_pem, key_pem) = self_signed_cert();
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key);

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // Spawn the accept loop and verify it actually reaches `accept` before we
    // return. Use a Notify so the caller doesn't race the scheduler.
    let ready = Arc::new(tokio::sync::Notify::new());
    let ready_clone = ready.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            ready_clone.notify_one();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    handle_client(TlsStream::Server(tls)).await;
                }
            });
        }
    });

    // First connection's `accept` callback will fire `notify_one`. We don't
    // wait for that here (the listener may never get a connection if no test
    // runs); instead, give the runtime a beat to schedule the accept loop.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    port
}

async fn read_packet(tls: &mut TlsStream<tokio::net::TcpStream>) -> Result<(), std::io::Error> {
    let mut header = [0u8; 8];
    tls.read_exact(&mut header).await?;
    let size = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    let body_len = size.saturating_sub(8);
    let mut body = vec![0u8; body_len];
    if body_len > 0 {
        tls.read_exact(&mut body).await?;
    }
    Ok(())
}

async fn handle_client(mut tls: TlsStream<tokio::net::TcpStream>) {
    use tokio::io::AsyncWriteExt;
    // Read first packet (AUTH).
    read_packet(&mut tls).await.unwrap();
    let mut m = MessageBuilder::reply(MessageType::Auth);
    m.push_int(Payload::Status, 4, 0);
    tls.write_all(&m.finish()).await.unwrap();
    tls.flush().await.unwrap();

    // Read CLNT_INFO.
    read_packet(&mut tls).await.unwrap();
    let mut m = MessageBuilder::reply(MessageType::ClntInfo);
    m.push_int(Payload::Status, 4, 0);
    tls.write_all(&m.finish()).await.unwrap();
    tls.flush().await.unwrap();

    // Send SET_IP with full network config.
    let mut m = MessageBuilder::reply(MessageType::SetIp);
    m.push_ipv4(
        Payload::CltPrivIpv4,
        "10.7.0.42".parse::<Ipv4Addr>().unwrap(),
    );
    m.push_ipv4(
        Payload::NetmaskIpv4,
        "255.255.255.0".parse::<Ipv4Addr>().unwrap(),
    );
    m.push_ipv4(
        Payload::SvrPrivIpv4,
        "10.7.0.1".parse::<Ipv4Addr>().unwrap(),
    );
    m.push_int(Payload::SvrUdpPort, 2, 4444);
    m.push_ipv4(Payload::DnsIpv4, "10.7.0.1".parse::<Ipv4Addr>().unwrap());
    tls.write_all(&m.finish()).await.unwrap();
    tls.flush().await.unwrap();

    // Send KEY_DONE so the client can exit wait_network.
    let m = MessageBuilder::reply(MessageType::KeyDone);
    tls.write_all(&m.finish()).await.unwrap();
    tls.flush().await.unwrap();

    // Read NEW_KEY.
    read_packet(&mut tls).await.unwrap();

    // Respond with NEW_KEY reply: enc=AES-CBC, auth=HMAC-MD5-96.
    let mut m = MessageBuilder::reply(MessageType::NewKey);
    m.push_int(Payload::IpcompAlg, 2, 0);
    m.push_int(Payload::EncAlg, 2, 0x000c);
    m.push_int(Payload::AuthAlg, 2, 0x0001);
    m.push_int(Payload::Spi, 4, 0xdeadbeef);
    m.push_bytes(Payload::SessionId, b"test-session".to_vec());
    tls.write_all(&m.finish()).await.unwrap();
    tls.flush().await.unwrap();

    // Read CLNT_LOGOUT.
    let _ = read_packet(&mut tls).await;
}

#[tokio::test]
async fn full_handshake_with_mock_server() {
    let port = spawn_mock_server().await;

    let mut client = ClientCore::new();
    client
        .connect_tcp("127.0.0.1", port)
        .await
        .expect("connect_tcp");
    assert_eq!(
        client.resolved_ip(),
        Some("127.0.0.1".parse::<std::net::IpAddr>().unwrap())
    );

    client.auth("alice", "secret", "", "").await.expect("auth");

    client.client_info().await.expect("client_info");

    let net: NetworkConfig = client.wait_network().await.expect("wait_network");
    assert_eq!(net.client_ip, "10.7.0.42".parse::<Ipv4Addr>().unwrap());
    assert_eq!(net.gateway, "10.7.0.1".parse::<Ipv4Addr>().unwrap());
    assert_eq!(net.netmask, 24);
    assert_eq!(net.server_udp_port, 4444);
    assert_eq!(net.dns, vec!["10.7.0.1".parse::<Ipv4Addr>().unwrap()]);
    assert_eq!(client.server_udp_port, 4444);

    let km: KeyMaterial = client.exchange_key().await.expect("exchange_key");
    assert_eq!(km.crypt_size, 0x10);
    assert_eq!(km.iv_size, 0x10);
    assert_eq!(km.auth_size, 0x10);
    assert_eq!(km.outbound_spi, 0xdeadbeef);
    assert_eq!(km.keymat.len(), 48);

    client.logout().await.expect("logout");
}
