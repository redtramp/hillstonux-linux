//! Rust ESP 实现与 scapy 的逐字节对照。
//!
//! scapy 正是那个能正常工作的 Python 客户端（impl_scapy.Client._encap）走的
//! 代码路径。夹具 `tests/fixtures/esp_batch.json` 由
//! `tests/fixtures/esp_oracle.py` 生成（hillstone.IPSecParameters 派生密钥 +
//! scapy.SecurityAssociation.encrypt 加密）。
//!
//! 本测试证明三件事：
//! 1. keymat 展开与参考实现一致（out_iv / out_auth_key / out_crypt_key）；
//! 2. 入站方向：我们的解密能解出 scapy 加密的包（即服务器发来的包）；
//! 3. 出站方向：我们的加密与 scapy 输出逐字节一致（即服务器必须接受的格式）。
//!
//! 重新生成夹具: python3 tests/fixtures/esp_oracle.py > tests/fixtures/esp_batch.json

use hillstonux_core::ipsec::{decrypt_packet, encrypt_packet, expand, EncAlg};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    iv_size: u8,
    auth_size: u8,
    crypt_size: u8,
    out_iv: String,
    out_auth_key: String,
    out_crypt_key: String,
    encrypted: String,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    keymat: String,
    out_spi: u32,
    seq: u32,
    plaintext: String,
    cases: Vec<Case>,
}

const FIXTURE_REL: &str = "tests/fixtures/esp_batch.json";

fn load_fixture() -> Fixture {
    // 夹具随仓库提交（tests/fixtures/esp_batch.json），必须存在；
    // 缺失说明产物不完整，直接失败而非静默跳过。
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR 由 cargo 注入");
    let path = std::path::Path::new(&manifest).join(FIXTURE_REL);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("无法读取夹具 {}: {}", path.display(), e));
    serde_json::from_str(&raw).expect("夹具必须是合法 JSON")
}

fn params_for(case: &Case) -> (EncAlg, bool) {
    match case.name.as_str() {
        "aes-cbc_hmac-sha1-96" => (EncAlg::AesCbc, true),
        "3des_hmac-md5-96" => (EncAlg::TripleDes, false),
        other => panic!("未知算法组合: {other}"),
    }
}

#[test]
fn rust_matches_scapy_byte_for_byte() {
    let fx = load_fixture();
    assert!(!fx.cases.is_empty(), "夹具为空，请重新运行 esp_oracle.py");
    let keymat = hex::decode(&fx.keymat).expect("keymat hex");
    let plaintext = hex::decode(&fx.plaintext).expect("plaintext hex");

    for case in &fx.cases {
        let (enc_alg, use_sha1) = params_for(case);
        let iv_size = case.iv_size as usize;
        let out_iv = hex::decode(&case.out_iv).expect("out_iv hex");
        let out_auth = hex::decode(&case.out_auth_key).expect("out_auth hex");
        let out_crypt = hex::decode(&case.out_crypt_key).expect("out_crypt hex");
        let py_packet = hex::decode(&case.encrypted).expect("encrypted hex");

        // 1. keymat 展开与参考实现一致。
        let keys = expand(
            &keymat,
            case.crypt_size as usize,
            case.auth_size as usize,
            iv_size,
        );
        assert_eq!(keys.out_iv, out_iv, "out_iv 不一致 ({})", case.name);
        assert_eq!(
            keys.out_auth_key, out_auth,
            "out_auth_key 不一致 ({})",
            case.name
        );
        assert_eq!(
            keys.out_crypt_key, out_crypt,
            "out_crypt_key 不一致 ({})",
            case.name
        );

        // 2. 入站方向：我们的解密能解出 scapy 加密的包。
        let decoded = decrypt_packet(
            &out_crypt, &out_auth, iv_size, enc_alg, use_sha1, &py_packet,
        )
        .unwrap_or_else(|e| panic!("无法解密 scapy 包 ({}): {e}", case.name));
        assert_eq!(decoded, plaintext, "解密结果不一致 ({})", case.name);

        // 3. 出站方向：我们的加密与 scapy 输出逐字节一致。
        let rust_packet = encrypt_packet(
            fx.out_spi, fx.seq, &out_crypt, &out_auth, &out_iv, iv_size, enc_alg, use_sha1,
            &plaintext,
        );
        assert_eq!(
            rust_packet,
            py_packet,
            "出站字节不一致 ({}):\nrust  = {:?}\nscapy = {:?}",
            case.name,
            hex::encode(&rust_packet),
            hex::encode(&py_packet)
        );
    }
}
