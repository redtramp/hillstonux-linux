#!/usr/bin/env python3
"""Dump Hillstone IPSecParameters keymat expansion output for Rust fixture.

Usage:
    python3 keymat_oracle.py > keymat_batch.json
"""
import sys, os, json

sys.path.insert(0, "/home/redtramp/Green/Network/hillstonux/hilldust")

from hillstone import IPSecParameters

# (keymat, in_spi, out_spi, auth_size, crypt_size, iv_size)
CASES = [
    # AES-CBC + HMAC-MD5-96 case
    (b"\xab" * 48, 0x12345678, 0xdeadbeef, 0x10, 0x10, 0x10),
    # 3DES + HMAC-SHA1-96 case
    (b"\xcd" * 48, 0xcafef00d, 0xfeedface, 0x14, 0x18, 8),
    # All zeros (edge case)
    (b"\x00" * 48, 0, 0, 0x10, 0x10, 0x10),
    # Mixed bytes
    (bytes(range(48)), 0x01020304, 0x05060708, 0x10, 0x10, 0x10),
]


def main():
    out = []
    for i, (km, in_spi, out_spi, auth, crypt, iv) in enumerate(CASES):
        p = IPSecParameters(in_spi, out_spi, km, auth_size=auth, crypt_size=crypt, iv_size=iv)
        out.append({
            "index": i,
            "keymat_hex": km.hex(),
            "in_spi": in_spi,
            "out_spi": out_spi,
            "auth_size": auth,
            "crypt_size": crypt,
            "iv_size": iv,
            "out_iv_hex": p.out_iv.hex(),
            "in_iv_hex": p.in_iv.hex(),
            "enlarged_keymat_hex": p.enlarged_keymat.hex(),
            "out_auth_key_hex": p.out_auth_key.hex(),
            "out_crypt_key_hex": p.out_crypt_key.hex(),
            "in_auth_key_hex": p.in_auth_key.hex(),
            "in_crypt_key_hex": p.in_crypt_key.hex(),
        })
    # Write to stdout; caller redirects to capture.
    sys.stdout.write(json.dumps(out, indent=2))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
