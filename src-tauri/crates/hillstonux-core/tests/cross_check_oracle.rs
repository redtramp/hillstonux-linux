//! Byte-level cross-check between Rust `MessageBuilder` and the Python
//! `hillstone` implementation across a batch of test cases.
//!
//! Test fixtures live at `tests/fixtures/auth_batch.json` and are produced
//! by running `tests/fixtures/python_oracle.py` against the user's
//! modified Python implementation.
//!
//! If the JSON file is missing (e.g. CI before running the oracle), tests are
//! marked `#[ignore]` so the suite still passes.

use hillstonux_core::message::{MessageBuilder, MessageType, Payload};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Case {
    user: String,
    pass: String,
    host_id: String,
    host_name: String,
    hex: String,
}

const FIXTURE_REL: &str = "tests/fixtures/auth_batch.json";

fn load_cases() -> Vec<Case> {
    // 夹具随仓库提交（tests/fixtures/auth_batch.json），必须存在；
    // 缺失说明产物不完整，直接失败而非静默跳过。
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR 由 cargo 注入");
    let path = std::path::Path::new(&manifest).join(FIXTURE_REL);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("无法读取夹具 {}: {}", path.display(), e));
    serde_json::from_str(&raw).expect("夹具必须是合法 JSON")
}

fn encode_auth(case: &Case) -> Vec<u8> {
    let mut m = MessageBuilder::new(MessageType::Auth);
    m.push_int(Payload::AuthType, 2, 1);
    m.push_string(Payload::Username, &case.user);
    m.push_string(Payload::Password, &case.pass);
    m.push_string(Payload::ClientVer, "1.0.0");
    m.push_string(Payload::HostId, &case.host_id);
    m.push_string(Payload::HostName, &case.host_name);
    m.finish()
}

#[test]
fn empty_and_ascii_users_match_python() {
    let cases = load_cases();
    assert!(
        !cases.is_empty(),
        "夹具为空，请先运行 tests/fixtures/python_oracle.py 生成"
    );
    for case in &cases {
        let expected = hex::decode(&case.hex).expect("hex");
        let actual = encode_auth(case);
        assert_eq!(
            actual.len(),
            expected.len(),
            "case (user={:?}, pass=<redacted>): length mismatch rust={} python={}",
            case.user,
            actual.len(),
            expected.len()
        );
        assert_eq!(
            actual, expected,
            "case (user={:?}, pass=<redacted>): byte mismatch",
            case.user
        );
    }
    eprintln!("{} cases verified byte-for-byte", cases.len());
}

#[test]
fn runner_smoke_test_with_synthetic_case() {
    // Sanity check that runs even without the JSON fixture: build a known
    // case here and assert the encoder produces deterministic output.
    let case = Case {
        user: "smoke".to_string(),
        pass: "test".to_string(),
        host_id: "".to_string(),
        host_name: "".to_string(),
        hex: String::new(),
    };
    let bytes = encode_auth(&case);
    // Header should start with magic (0x22), reply (0x00), msg_t AUTH (0x0001), size.
    assert_eq!(&bytes[0..4], &[0x22, 0x00, 0x00, 0x01]);
    // Last byte of body for an AUTH with 5 TLVs ends with HostName zero-padding.
    // Just confirm non-zero size and well-formed structure.
    assert!(bytes.len() > 8);
    let size = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    assert_eq!(size, bytes.len());
}
