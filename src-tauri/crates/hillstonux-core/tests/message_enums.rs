use hillstonux_core::message::{MessageType, Payload};

#[test]
fn message_type_values_match_python() {
    assert_eq!(MessageType::Auth as u8, 0x01);
    assert_eq!(MessageType::ClntInfo as u8, 0x02);
    assert_eq!(MessageType::SetIp as u8, 0x03);
    assert_eq!(MessageType::SetRoute as u8, 0x04);
    assert_eq!(MessageType::NewKey as u8, 0x05);
    assert_eq!(MessageType::KeyDone as u8, 0x06);
    assert_eq!(MessageType::ClntLogout as u8, 0x07);
    assert_eq!(MessageType::ServDisconn as u8, 0x08);
    assert_eq!(MessageType::KeepAlive as u8, 0x09);
    assert_eq!(MessageType::Rekey as u8, 0x0A);
    assert_eq!(MessageType::HostCheck as u8, 0x0B);
}

#[test]
fn message_type_from_u8_round_trip() {
    for v in 0u8..=0x14 {
        let mt = MessageType::from_u8(v).expect("known variant");
        assert_eq!(mt as u8, v);
    }
}

#[test]
fn message_type_from_u8_unknown() {
    assert!(MessageType::from_u8(0xFF).is_none());
    assert!(MessageType::from_u8(0x15).is_none());
}

#[test]
fn payload_values_match_python() {
    assert_eq!(Payload::Username as u16, 1);
    assert_eq!(Payload::Password as u16, 2);
    assert_eq!(Payload::Status as u16, 4);
    assert_eq!(Payload::CltPrivIpv4 as u16, 7);
    assert_eq!(Payload::SvrUdpPort as u16, 9);
    assert_eq!(Payload::Keymat as u16, 16);
    assert_eq!(Payload::DnsIpv4 as u16, 17);
    assert_eq!(Payload::RouteIpv4 as u16, 19);
    assert_eq!(Payload::KeyExchMode as u16, 32);
    assert_eq!(Payload::Spi as u16, 48);
    assert_eq!(Payload::EncAlg as u16, 49);
    assert_eq!(Payload::AuthAlg as u16, 50);
    assert_eq!(Payload::SessionId as u16, 51);
    assert_eq!(Payload::AuthType as u16, 81);
    assert_eq!(Payload::Cookie as u16, 82);
    assert_eq!(Payload::Disconnect as u16, 83);
    assert_eq!(Payload::ClientVer as u16, 84);
    assert_eq!(Payload::HostId as u16, 96);
    assert_eq!(Payload::HostName as u16, 97);
    assert_eq!(Payload::ClientAutoConnect as u16, 136);
}
