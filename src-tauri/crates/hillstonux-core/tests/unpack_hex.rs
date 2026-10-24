//! Byte-level cross-check for `unpack()` against Python fixtures.

use hillstonux_core::message::{unpack, MessageType, Payload};
use std::net::Ipv4Addr;

const AUTH_SUCCESS: &str = include_str!("fixtures/auth_response_success.hex");
const AUTH_FAIL: &str = include_str!("fixtures/auth_response_fail.hex");
const SET_IP: &str = include_str!("fixtures/set_ip_response.hex");
const KEY_DONE: &str = include_str!("fixtures/key_done.hex");

fn parse(hex: &str) -> Vec<u8> {
    hex::decode(hex.trim()).expect("valid hex")
}

#[test]
fn unpack_rejects_bad_magic() {
    let bad = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08];
    let result = unpack(&bad);
    assert!(matches!(
        result,
        Err(hillstonux_core::error::ProtocolError::NotAPacket)
    ));
}

#[test]
fn unpack_zero_packet_signals_none() {
    let raw = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let parsed = unpack(&raw).expect("parse ok");
    assert_eq!(parsed.msg_t, MessageType::None);
    assert!(!parsed.is_reply);
    assert!(parsed.fields.is_empty());
}

#[test]
fn unpack_auth_success_extracts_status_zero() {
    let raw = parse(AUTH_SUCCESS);
    let parsed = unpack(&raw).expect("parse ok");
    assert_eq!(parsed.msg_t, MessageType::Auth);
    assert!(parsed.is_reply);
    let status = parsed.fields.get(&Payload::Status).expect("status field");
    assert_eq!(status, &b"\x00\x00\x00\x00".to_vec());
}

#[test]
fn unpack_auth_fail_extracts_status_three() {
    let raw = parse(AUTH_FAIL);
    let parsed = unpack(&raw).expect("parse ok");
    assert_eq!(parsed.msg_t, MessageType::Auth);
    let status = parsed.fields.get(&Payload::Status).expect("status field");
    assert_eq!(status, &b"\x00\x00\x00\x03".to_vec());
}

#[test]
fn unpack_set_ip_extracts_all_fields() {
    let raw = parse(SET_IP);
    let parsed = unpack(&raw).expect("parse ok");
    assert_eq!(parsed.msg_t, MessageType::SetIp);
    assert!(parsed.is_reply);

    // CltPrivIpv4 = 10.0.0.5
    let client_ip = parsed.fields.get(&Payload::CltPrivIpv4).expect("client ip");
    assert_eq!(
        Ipv4Addr::from(<[u8; 4]>::try_from(client_ip.as_slice()).unwrap()),
        "10.0.0.5".parse::<Ipv4Addr>().unwrap()
    );

    // NetmaskIpv4 = 255.255.255.0
    let netmask = parsed.fields.get(&Payload::NetmaskIpv4).expect("netmask");
    assert_eq!(
        Ipv4Addr::from(<[u8; 4]>::try_from(netmask.as_slice()).unwrap()),
        "255.255.255.0".parse::<Ipv4Addr>().unwrap()
    );

    // SvrPrivIpv4 = 10.0.0.1
    let gateway = parsed.fields.get(&Payload::SvrPrivIpv4).expect("gateway");
    assert_eq!(
        Ipv4Addr::from(<[u8; 4]>::try_from(gateway.as_slice()).unwrap()),
        "10.0.0.1".parse::<Ipv4Addr>().unwrap()
    );

    // SvrUdpPort = 4433
    let port = parsed.fields.get(&Payload::SvrUdpPort).expect("port");
    let port_val = u16::from_be_bytes(<[u8; 2]>::try_from(port.as_slice()).unwrap());
    assert_eq!(port_val, 4433);

    // DnsIpv4 = "10.0.0.1" (8 ASCII bytes)
    let dns = parsed.fields.get(&Payload::DnsIpv4).expect("dns");
    assert_eq!(dns.as_slice(), b"10.0.0.1");
}

#[test]
fn unpack_key_done_has_no_fields() {
    let raw = parse(KEY_DONE);
    let parsed = unpack(&raw).expect("parse ok");
    assert_eq!(parsed.msg_t, MessageType::KeyDone);
    assert!(parsed.fields.is_empty());
}
