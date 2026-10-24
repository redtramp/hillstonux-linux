//! UDP loopback test for EspSocket.

use hillstonux_net::EspSocket;

#[tokio::test]
async fn udp_loopback_roundtrip() {
    let s1 = EspSocket::bind_any().await.expect("bind s1");
    let s1_addr = s1.local_addr().expect("local_addr s1");
    let s2 = EspSocket::bind_any().await.expect("bind s2");

    s1.send_to(b"hello from s1", s2.local_addr().unwrap())
        .await
        .expect("send s1->s2");

    let mut buf = [0u8; 1024];
    let (n, from) = s2.recv_from(&mut buf).await.expect("recv s2");
    assert_eq!(&buf[..n], b"hello from s1");
    // The socket is bound to the wildcard address, so the peer sees the
    // concrete source address the kernel picked — the port must still be
    // the one the socket was bound to.
    assert_eq!(from.port(), s1_addr.port());
    assert!(from.ip().is_loopback());
}

/// A socket bound to the loopback address cannot talk to a non-loopback
/// peer: the kernel rejects the send with EINVAL. The ESP transport talks
/// to the VPN server's public address, so the data-plane socket has to be
/// bound to the wildcard address.
#[tokio::test]
async fn wildcard_bind_does_not_reject_non_loopback_peers() {
    let peer = "192.0.2.1:4433".parse().expect("addr"); // TEST-NET-1

    let wildcard = EspSocket::bind_any().await.expect("bind wildcard");
    if let Err(e) = wildcard.send_to(b"x", peer).await {
        assert_ne!(
            e.kind(),
            std::io::ErrorKind::InvalidInput,
            "wildcard-bound socket refused a non-loopback peer: {e}"
        );
    }

    // Contrast: the loopback-bound socket is the bug this guards against.
    let loopback = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let err = loopback.send_to(b"x", peer).await.expect_err("must fail");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidInput,
        "expected EINVAL for a loopback-bound socket, got {err}"
    );
}

#[tokio::test]
async fn udp_loopback_reverse_direction() {
    let s1 = EspSocket::bind_any().await.unwrap();
    let s2 = EspSocket::bind_any().await.unwrap();

    s2.send_to(b"reply from s2", s1.local_addr().unwrap())
        .await
        .unwrap();

    let mut buf = [0u8; 1024];
    let (n, _from) = s1.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"reply from s2");
}
