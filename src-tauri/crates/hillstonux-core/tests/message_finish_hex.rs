//! Byte-level cross-check with Python `hillstone.Message.finish()`.
//!
//! Fixture at `tests/fixtures/auth_request.hex` was produced by running
//! `dump_auth_hex.py` against the user's modified Python implementation.

use hillstonux_core::message::{MessageBuilder, MessageType, Payload};

const FIXTURE_HEX: &str = include_str!("fixtures/auth_request.hex");

#[test]
fn auth_request_bytes_match_python() {
    let expected = hex::decode(FIXTURE_HEX.trim()).expect("valid hex fixture");

    let mut m = MessageBuilder::new(MessageType::Auth);
    m.push_int(Payload::AuthType, 2, 1);
    m.push_string(Payload::Username, "alice");
    m.push_string(Payload::Password, "secret");
    m.push_string(Payload::ClientVer, "1.0.0");
    m.push_string(Payload::HostId, "");
    m.push_string(Payload::HostName, "");

    let actual = m.finish();
    assert_eq!(
        actual.len(),
        expected.len(),
        "length mismatch: rust={} python={}",
        actual.len(),
        expected.len()
    );
    if actual != expected {
        // Provide a useful diff for debugging.
        for (i, (a, e)) in actual.iter().zip(expected.iter()).enumerate() {
            if a != e {
                panic!(
                    "byte {} differs: rust=0x{:02x} python=0x{:02x} (offset {})",
                    i, a, e, i
                );
            }
        }
    }
}

#[test]
fn empty_message_minimum_size() {
    // MessageType::None with no payloads → just the 8-byte header (size=8).
    let m = MessageBuilder::new(MessageType::None);
    let bytes = m.finish();
    assert_eq!(bytes.len(), 8);
    assert_eq!(&bytes[0..4], &[0x22, 0x00, 0x00, 0x00]);
    assert_eq!(&bytes[4..8], &[0x00, 0x00, 0x00, 0x08]);
}

#[test]
fn reply_flag_sets_second_byte() {
    let m = MessageBuilder::reply(MessageType::Auth);
    let bytes = m.finish();
    assert_eq!(bytes[1], 0x02);
}

#[test]
fn push_ipv4_serializes_as_4_bytes_big_endian() {
    let mut m = MessageBuilder::new(MessageType::ClntInfo);
    m.push_ipv4(Payload::CltPubIpv4, "10.0.0.1".parse().unwrap());
    let bytes = m.finish();
    // payload bytes for CltPubIpv4 start at offset 12 (8 hdr + 4 key/len)
    assert_eq!(&bytes[12..16], &[10, 0, 0, 1]);
}
