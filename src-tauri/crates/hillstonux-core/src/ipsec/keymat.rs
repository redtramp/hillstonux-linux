//! Keymat expansion (Hillstone-specific derivation).
//!
//! Mirrors Python `hillstone.IPSecParameters.__init__`:
//! 1. IV is the first `iv_size` bytes of the original keymat (used for both
//!    inbound and outbound).
//! 2. Enlarged keymat 由 10 段 SHA1 拼接而成（1 次初始 + 9 次迭代）：
//!    每次迭代对**当前已累积的缓冲区**再做一次 SHA1，而不是只哈希上一步的输出。
//!    即 `enlarged = H1; enlarged += SHA1(enlarged); ...`，已对照 Python
//!    参考实现（tests/fixtures/keymat_oracle.py）逐字节验证一致。
//! 3. Split the enlarged keymat into four sections, in order:
//!    `out_auth_key (auth_size) | out_crypt_key (crypt_size) | in_auth_key (auth_size) | in_crypt_key (crypt_size)`.

use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct ExpandedKeys {
    pub out_iv: Vec<u8>,
    pub in_iv: Vec<u8>,
    pub out_auth_key: Vec<u8>,
    pub out_crypt_key: Vec<u8>,
    pub in_auth_key: Vec<u8>,
    pub in_crypt_key: Vec<u8>,
}

pub fn expand(keymat: &[u8], crypt_size: usize, auth_size: usize, iv_size: usize) -> ExpandedKeys {
    let out_iv = keymat[..iv_size].to_vec();
    let in_iv = out_iv.clone();

    // Chain SHA1 ten times: 1 initial + 9 iterations.
    let mut hasher = Sha1::new();
    hasher.update(keymat);
    let mut enlarged = hasher.finalize().to_vec();
    for _ in 0..9 {
        let mut h = Sha1::new();
        h.update(&enlarged);
        enlarged.extend_from_slice(&h.finalize());
    }

    let mut buf = enlarged.as_slice();
    let out_auth_key = take(&mut buf, auth_size);
    let out_crypt_key = take(&mut buf, crypt_size);
    let in_auth_key = take(&mut buf, auth_size);
    let in_crypt_key = take(&mut buf, crypt_size);

    ExpandedKeys {
        out_iv,
        in_iv,
        out_auth_key,
        out_crypt_key,
        in_auth_key,
        in_crypt_key,
    }
}

fn take(buf: &mut &[u8], size: usize) -> Vec<u8> {
    let (head, tail) = buf.split_at(size);
    *buf = tail;
    head.to_vec()
}
