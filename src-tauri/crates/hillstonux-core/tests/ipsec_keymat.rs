//! Cross-check keymat expansion with Python `hillstone.IPSecParameters`.

use hillstonux_core::ipsec::expand;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Case {
    keymat_hex: String,
    auth_size: usize,
    crypt_size: usize,
    iv_size: usize,
    out_iv_hex: String,
    in_iv_hex: String,
    enlarged_keymat_hex: String,
    out_auth_key_hex: String,
    out_crypt_key_hex: String,
    in_auth_key_hex: String,
    in_crypt_key_hex: String,
}

const FIXTURE_REL: &str = "tests/fixtures/keymat_batch.json";

fn load_cases() -> Vec<Case> {
    // 夹具随仓库提交（tests/fixtures/keymat_batch.json），必须存在；
    // 缺失说明产物不完整，直接失败而非静默跳过。
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR 由 cargo 注入");
    let path = std::path::Path::new(&manifest).join(FIXTURE_REL);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("无法读取夹具 {}: {}", path.display(), e));
    serde_json::from_str(&raw).expect("夹具必须是合法 JSON")
}

#[test]
fn keymat_expansion_matches_python() {
    let cases = load_cases();
    assert!(
        !cases.is_empty(),
        "夹具为空，请先运行 tests/fixtures/keymat_oracle.py 生成"
    );
    for case in &cases {
        let keymat = hex::decode(&case.keymat_hex).expect("hex");
        let expanded = expand(&keymat, case.crypt_size, case.auth_size, case.iv_size);

        assert_eq!(
            hex::encode(&expanded.out_iv),
            case.out_iv_hex,
            "out_iv mismatch"
        );
        assert_eq!(
            hex::encode(&expanded.in_iv),
            case.in_iv_hex,
            "in_iv mismatch"
        );
        assert_eq!(
            hex::encode(&expanded.out_auth_key),
            case.out_auth_key_hex,
            "out_auth_key mismatch"
        );
        assert_eq!(
            hex::encode(&expanded.out_crypt_key),
            case.out_crypt_key_hex,
            "out_crypt_key mismatch"
        );
        assert_eq!(
            hex::encode(&expanded.in_auth_key),
            case.in_auth_key_hex,
            "in_auth_key mismatch"
        );
        assert_eq!(
            hex::encode(&expanded.in_crypt_key),
            case.in_crypt_key_hex,
            "in_crypt_key mismatch"
        );

        // 校验拆分出的 4 段密钥恰好拼成 enlarged_keymat 的前导密钥区
        // （auth_size + crypt_size + auth_size + crypt_size 字节），
        // 确保切分无间隙、无重叠。完整 enlarged_keymat 还包含后续冗余 SHA1 段，
        // 不在此比较。
        let mut reconstructed = Vec::new();
        reconstructed.extend_from_slice(&expanded.out_auth_key);
        reconstructed.extend_from_slice(&expanded.out_crypt_key);
        reconstructed.extend_from_slice(&expanded.in_auth_key);
        reconstructed.extend_from_slice(&expanded.in_crypt_key);
        let key_region_len =
            (case.auth_size + case.crypt_size + case.auth_size + case.crypt_size) * 2;
        let expected_region = &case.enlarged_keymat_hex[..key_region_len];
        assert_eq!(
            hex::encode(&reconstructed),
            expected_region,
            "enlarged_keymat 前导密钥区重建不一致"
        );
    }
    eprintln!("{} keymat cases verified", cases.len());
}
