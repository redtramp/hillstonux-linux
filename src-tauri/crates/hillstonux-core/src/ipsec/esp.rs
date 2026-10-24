//! ESP packet encapsulation (outbound) and decapsulation (inbound).
//!
//! 线格式（与 scapy `SecurityAssociation.encrypt/decrypt` 及 hilldust 参考实现
//! 逐字节一致；已用真实服务器 + scapy 2.7 验证）：
//! ```text
//! | SPI (4) | Seq (4) | IV (iv_size) | 密文 | ICV (12) |
//! ```
//! 其中“密文”是下列内容的 CBC 加密结果（**不做额外 PKCS#7 填充**，靠 ESP
//! 填充对齐到块边界）：
//! ```text
//! | 明文 | ESP填充(1,2,3,...) | PadLen (1) | NextHdr (1) |
//! ```
//! - 序列号为 **4 字节**（标准 ESP / scapy，非 8 字节）。
//! - ICV 为 **96 位（12 字节）**截断，对应 HMAC-MD5-96 / HMAC-SHA1-96。
//! - NextHdr 对 ESP 封装的 IPv4 为 4。
//!
//! 支持的算法：AES-CBC + HMAC-MD5-96（MVP）、3DES + HMAC-SHA1-96。

use aes::cipher::{block_padding::NoPadding, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use sha1::Sha1;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Des3CbcEnc = cbc::Encryptor<des::TdesEde3>;
type Des3CbcDec = cbc::Decryptor<des::TdesEde3>;
type HmacMd5 = Hmac<Md5>;
type HmacSha1 = Hmac<Sha1>;

/// 96 位 ICV：HMAC-MD5-96 与 HMAC-SHA1-96 均截断到 12 字节。
const ICV_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncAlg {
    AesCbc,
    TripleDes,
}

#[derive(Debug, thiserror::Error)]
pub enum IpsecError {
    #[error("packet too short")]
    PacketTooShort,
    #[error("authentication failed")]
    AuthFailed,
    #[error("invalid padding")]
    InvalidPadding,
}

/// Compute HMAC over a buffer and truncate to 12 bytes (96-bit ICV).
fn hmac_truncated(auth_key: &[u8], data: &[u8], use_sha1: bool) -> [u8; ICV_LEN] {
    let full = if use_sha1 {
        let mut mac = HmacSha1::new_from_slice(auth_key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    } else {
        let mut mac = HmacMd5::new_from_slice(auth_key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    };
    let mut out = [0u8; ICV_LEN];
    out.copy_from_slice(&full[..ICV_LEN]);
    out
}

/// Verify HMAC over the packet's header portion. Returns the header bytes on
/// success.
fn verify_hmac<'a>(
    auth_key: &[u8],
    packet: &'a [u8],
    use_sha1: bool,
) -> Result<&'a [u8], IpsecError> {
    if packet.len() < ICV_LEN {
        return Err(IpsecError::PacketTooShort);
    }
    let split = packet.len() - ICV_LEN;
    let (header, icv) = packet.split_at(split);
    let expected = hmac_truncated(auth_key, header, use_sha1);
    if expected.as_slice() != icv {
        return Err(IpsecError::AuthFailed);
    }
    Ok(header)
}

/// Encrypt and frame an ESP packet.
///
/// `iv` 取自 keymat 的前 `iv_size` 字节（Hillstone 约定），与解密端一致。
#[allow(clippy::too_many_arguments)]
pub fn encrypt_packet(
    spi: u32,
    seq: u32,
    crypt_key: &[u8],
    auth_key: &[u8],
    iv: &[u8],
    iv_size: usize,
    enc_alg: EncAlg,
    use_sha1: bool,
    plaintext: &[u8],
) -> Vec<u8> {
    // ESP 填充：使 [明文 | 填充 | PadLen(1) | NextHdr(1)] 长度为块大小倍数。
    let block = match enc_alg {
        EncAlg::AesCbc => 16,
        EncAlg::TripleDes => 8,
    };
    let pad_total = (block - ((plaintext.len() + 2) % block)) % block;
    let mut to_enc = Vec::with_capacity(plaintext.len() + pad_total + 2);
    to_enc.extend_from_slice(plaintext);
    for i in 1..=pad_total {
        to_enc.push(i as u8); // 1,2,3,...（RFC 4303 / scapy 约定）
    }
    to_enc.push(pad_total as u8); // PadLen
    to_enc.push(4u8); // NextHdr = IPv4

    // CBC 加密（NoPadding：ESP 填充已对齐到块边界）
    let mut buf = to_enc;
    let len = buf.len();
    let ciphertext = match enc_alg {
        EncAlg::AesCbc => Aes128CbcEnc::new_from_slices(crypt_key, iv)
            .expect("密钥/IV 长度必须符合 AES-128-CBC")
            .encrypt_padded::<NoPadding>(&mut buf, len)
            .expect("ESP 负载已按块大小对齐，NoPadding 不会失败")
            .to_vec(),
        EncAlg::TripleDes => Des3CbcEnc::new_from_slices(crypt_key, iv)
            .expect("密钥/IV 长度必须符合 3DES-CBC")
            .encrypt_padded::<NoPadding>(&mut buf, len)
            .expect("ESP 负载已按块大小对齐，NoPadding 不会失败")
            .to_vec(),
    };

    // 组帧：SPI(4) | Seq(4) | IV | 密文 | ICV(12)
    let mut out = Vec::with_capacity(8 + iv_size + ciphertext.len() + ICV_LEN);
    out.extend_from_slice(&spi.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(iv);
    out.extend_from_slice(&ciphertext);
    let icv = hmac_truncated(auth_key, &out, use_sha1);
    out.extend_from_slice(&icv);
    out
}

/// Decrypt and verify an ESP packet. Returns the inner plaintext.
///
/// IV 取自包头（字节 8..8+iv_size），因此调用方无需单独传入。
pub fn decrypt_packet(
    crypt_key: &[u8],
    auth_key: &[u8],
    iv_size: usize,
    enc_alg: EncAlg,
    use_sha1: bool,
    packet: &[u8],
) -> Result<Vec<u8>, IpsecError> {
    let header = verify_hmac(auth_key, packet, use_sha1)?;

    // 剥去 SPI(4) + Seq(4) + IV(iv_size) → 密文（含 PadLen/NextHdr）
    let prefix_len = 4 + 4 + iv_size;
    if header.len() < prefix_len + 2 {
        return Err(IpsecError::PacketTooShort);
    }
    let iv = &header[4 + 4..prefix_len];
    let ciphertext = &header[prefix_len..];
    let mut ct = ciphertext.to_vec();

    let plaintext_block = match enc_alg {
        EncAlg::AesCbc => Aes128CbcDec::new_from_slices(crypt_key, iv)
            .expect("密钥/IV 长度必须符合 AES-128-CBC")
            .decrypt_padded::<NoPadding>(&mut ct)
            .map_err(|_| IpsecError::InvalidPadding)?,
        EncAlg::TripleDes => Des3CbcDec::new_from_slices(crypt_key, iv)
            .expect("密钥/IV 长度必须符合 3DES-CBC")
            .decrypt_padded::<NoPadding>(&mut ct)
            .map_err(|_| IpsecError::InvalidPadding)?,
    };

    let n = plaintext_block.len();
    if n < 2 {
        return Err(IpsecError::InvalidPadding);
    }
    let pad_len = plaintext_block[n - 2] as usize;
    let _next_hdr = plaintext_block[n - 1];
    if pad_len > n - 2 {
        return Err(IpsecError::InvalidPadding);
    }
    Ok(plaintext_block[..n - 2 - pad_len].to_vec())
}
