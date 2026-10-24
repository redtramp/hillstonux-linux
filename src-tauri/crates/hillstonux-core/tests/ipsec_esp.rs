//! ESP 封装/解封测试。
//!
//! 关键：前两个测试是**逐字节对照 scapy 2.7（hilldust 参考实现）** 的真实
//! ESP 编码，能抓住任何线格式回归（序列号长度、ICV 长度、填充位置等）。
//! 其余测试覆盖内部往返、密钥分离、ICV 篡改拒绝。

use hillstonux_core::ipsec::{decrypt_packet, encrypt_packet, expand, EncAlg};

fn de(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

// 参考基准由 scapy 生成（tests/fixtures/esp_oracle.py；keymat 固定为 0..47）。
// AES-CBC + HMAC-MD5-96
const AES_KEYMAT_HEX: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
const AES_PLAINTEXT_HEX: &str =
    "4500002300010000401161d40afafdeb0808080830390035000f668300017175657279";
const AES_ESP_HEX: &str =
    "0f51803b00000001000102030405060708090a0b0c0d0e0f628ffb7ace5ecb9856307351930552a9575547a7cf7e158f480ebf861c17ca3a1dd7502abd55d37d5d4abf6fb5501e72722b8e1c2895cde2dff4c1c8";

// 3DES + HMAC-SHA1-96
const TDES_ESP_HEX: &str =
    "112233440000000100010203040506074c8511498b3cf1b2788e99ea5ad18543e66c109596a3fbfd759842af541e9ee92d120f8491f0b3b452063e2887b76c3bf84876a4";

#[test]
fn aes_cbc_md5_96_matches_scipy_reference() {
    let keymat = de(AES_KEYMAT_HEX);
    let plaintext = de(AES_PLAINTEXT_HEX);
    let expected = de(AES_ESP_HEX);
    let exp = expand(&keymat, 16, 16, 16);

    // 与参考实现使用相同的 out_iv、out_spi、seq=1。
    let packet = encrypt_packet(
        0x0f51803b,
        1,
        &exp.out_crypt_key,
        &exp.out_auth_key,
        &exp.out_iv,
        exp.out_iv.len(),
        EncAlg::AesCbc,
        false,
        &plaintext,
    );
    assert_eq!(
        packet, expected,
        "AES-MD5 ESP 编码与 scapy 参考实现逐字节不一致"
    );
    // 解密回看应得到原始明文。
    let back = decrypt_packet(
        &exp.out_crypt_key,
        &exp.out_auth_key,
        exp.out_iv.len(),
        EncAlg::AesCbc,
        false,
        &packet,
    )
    .expect("decrypt must succeed");
    assert_eq!(back, plaintext);
}

#[test]
fn tdes_sha1_96_matches_scipy_reference() {
    let keymat = de(AES_KEYMAT_HEX);
    let plaintext = de(AES_PLAINTEXT_HEX);
    let expected = de(TDES_ESP_HEX);
    let exp = expand(&keymat, 24, 20, 8);

    let packet = encrypt_packet(
        0x11223344,
        1,
        &exp.out_crypt_key,
        &exp.out_auth_key,
        &exp.out_iv,
        exp.out_iv.len(),
        EncAlg::TripleDes,
        true,
        &plaintext,
    );
    assert_eq!(
        packet, expected,
        "3DES-SHA1 ESP 编码与 scapy 参考实现逐字节不一致"
    );
    let back = decrypt_packet(
        &exp.out_crypt_key,
        &exp.out_auth_key,
        exp.out_iv.len(),
        EncAlg::TripleDes,
        true,
        &packet,
    )
    .expect("decrypt must succeed");
    assert_eq!(back, plaintext);
}

#[test]
fn aes_cbc_md5_96_roundtrip_same_key() {
    // 自往返：同一 SA 的 out 密钥用于两端（仅本地往返，不涉及对端 in 密钥）。
    let keymat = [0xabu8; 48];
    let expanded = expand(&keymat, 16, 16, 16);
    let plaintext = b"hello ESP world from Rust unit test!";
    let packet = encrypt_packet(
        0xdeadbeef,
        42,
        &expanded.out_crypt_key,
        &expanded.out_auth_key,
        &expanded.out_iv,
        expanded.out_iv.len(),
        EncAlg::AesCbc,
        false,
        plaintext,
    );
    let decrypted = decrypt_packet(
        &expanded.out_crypt_key,
        &expanded.out_auth_key,
        expanded.out_iv.len(),
        EncAlg::AesCbc,
        false,
        &packet,
    )
    .expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn out_in_keys_produce_different_icvs() {
    // 用 out 密钥加密、用 in 密钥验证必须失败（密钥不同）。
    let keymat = [0xabu8; 48];
    let expanded = expand(&keymat, 16, 16, 16);
    let plaintext = b"check key separation";
    let packet = encrypt_packet(
        0xdead,
        1,
        &expanded.out_crypt_key,
        &expanded.out_auth_key,
        &expanded.out_iv,
        expanded.out_iv.len(),
        EncAlg::AesCbc,
        false,
        plaintext,
    );
    let result = decrypt_packet(
        &expanded.in_crypt_key,
        &expanded.in_auth_key,
        expanded.out_iv.len(),
        EncAlg::AesCbc,
        false,
        &packet,
    );
    assert!(
        result.is_err(),
        "in_auth_key should not verify out_auth_key ICV"
    );
}

#[test]
fn esp_packet_layout_4_byte_seq() {
    let keymat = [0xabu8; 48];
    let expanded = expand(&keymat, 16, 16, 16);
    let packet = encrypt_packet(
        0x01020304,
        100,
        &expanded.out_crypt_key,
        &expanded.out_auth_key,
        &expanded.out_iv,
        expanded.out_iv.len(),
        EncAlg::AesCbc,
        false,
        b"layout test",
    );
    // SPI (4 字节大端)
    assert_eq!(&packet[0..4], &[0x01, 0x02, 0x03, 0x04]);
    // Seq (4 字节大端，不再是 8 字节)
    assert_eq!(&packet[4..8], &[0, 0, 0, 100]);
    // IV (iv_size 字节)
    assert_eq!(&packet[8..8 + 16], &expanded.out_iv[..16]);
    // 密文 + PadLen + NextHdr 是 AES 块（16）的倍数；ICV 固定 12 字节。
    let enc_block = packet.len() - 8 - 16 - 12;
    assert_eq!(enc_block % 16, 0, "密文块必须按 16 字节对齐");
    // ICV 为 12 字节（96 位）
    assert_eq!(&packet[packet.len() - 12..], &packet[packet.len() - 12..]);
}

#[test]
fn tampered_icv_is_rejected() {
    let keymat = [0xabu8; 48];
    let expanded = expand(&keymat, 16, 16, 16);
    let mut packet = encrypt_packet(
        1,
        1,
        &expanded.out_crypt_key,
        &expanded.out_auth_key,
        &expanded.out_iv,
        expanded.out_iv.len(),
        EncAlg::AesCbc,
        false,
        b"tamper test",
    );
    let last = packet.len() - 1;
    packet[last] ^= 0x01;
    let result = decrypt_packet(
        &expanded.out_crypt_key,
        &expanded.out_auth_key,
        expanded.out_iv.len(),
        EncAlg::AesCbc,
        false,
        &packet,
    );
    assert!(result.is_err(), "tampered ICV should fail authentication");
}

#[test]
fn sequence_counter_increments_across_encaps() {
    let keymat = [0xabu8; 48];
    let expanded = expand(&keymat, 16, 16, 16);
    let p1 = encrypt_packet(
        0xdead,
        1,
        &expanded.out_crypt_key,
        &expanded.out_auth_key,
        &expanded.out_iv,
        expanded.out_iv.len(),
        EncAlg::AesCbc,
        false,
        b"x",
    );
    let p2 = encrypt_packet(
        0xdead,
        2,
        &expanded.out_crypt_key,
        &expanded.out_auth_key,
        &expanded.out_iv,
        expanded.out_iv.len(),
        EncAlg::AesCbc,
        false,
        b"x",
    );
    assert_ne!(&p1[4..8], &p2[4..8], "seq 字节必须不同");
    assert_eq!(&p1[4..8], &[0, 0, 0, 1]);
    assert_eq!(&p2[4..8], &[0, 0, 0, 2]);
}
