use hillstonux_core::error::ProtocolError;

#[test]
fn display_io_error() {
    let e = ProtocolError::Io(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "refused",
    ));
    let msg = e.to_string();
    assert!(msg.contains("refused"), "expected 'refused' in '{}'", msg);
}

#[test]
fn display_auth_failed_includes_code() {
    let e = ProtocolError::AuthFailed(3);
    assert_eq!(e.to_string(), "authentication failed (code=3)");
}

#[test]
fn display_client_info_failed_includes_code() {
    let e = ProtocolError::ClientInfoFailed(7);
    assert_eq!(e.to_string(), "client info failed (code=7)");
}

#[test]
fn display_network_info_failed_includes_code() {
    let e = ProtocolError::NetworkInfoFailed(11);
    assert_eq!(e.to_string(), "network info failed (code=11)");
}

#[test]
fn display_key_exchange_failed_includes_code() {
    let e = ProtocolError::KeyExchangeFailed(13);
    assert_eq!(e.to_string(), "key exchange failed (code=13)");
}

#[test]
fn display_unsupported_algorithm() {
    let e = ProtocolError::UnsupportedAlgorithm {
        enc: 0x0099,
        auth: 0x0001,
    };
    let msg = e.to_string();
    assert!(msg.contains("0x99"), "missing enc '0x99' in '{}'", msg);
    assert!(msg.contains("0x01"), "missing auth '0x01' in '{}'", msg);
}

#[test]
fn display_not_a_packet() {
    let e = ProtocolError::NotAPacket;
    assert_eq!(e.to_string(), "not a valid packet");
}

#[test]
fn display_tls_error() {
    let e = ProtocolError::Tls("handshake failed".to_string());
    assert_eq!(e.to_string(), "tls error: handshake failed");
}

#[test]
fn error_implements_std_error_trait() {
    fn assert_error<E: std::error::Error>() {}
    assert_error::<ProtocolError>();
}
