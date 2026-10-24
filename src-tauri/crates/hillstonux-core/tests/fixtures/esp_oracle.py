#!/usr/bin/env python3
"""Generate deterministic Hillstone ESP wire fixtures using scapy — the same
code path the working Python client uses (impl_scapy.Client._encap):

  1. hillstone.IPSecParameters derives out_iv / out_auth_key / out_crypt_key
     from a fixed 48-byte keymat (pure hashlib, the reference implementation).
  2. scapy.SecurityAssociation.encrypt (ESP, no NAT-T) produces the exact
     byte stream the Python client sends to the server.

The Rust integration test `tests/esp_scapy_cross.rs` consumes the hex output:
  - decrypts PY_ENCRYPTED with `decrypt_packet` and expects PLAINTEXT back;
  - encrypts PLAINTEXT with `encrypt_packet` (same keymat/iv/spi/seq) and
    expects byte-for-byte equality with PY_ENCRYPTED.

Run: python3 tools/cross_check/esp_oracle.py   (prints JSON to stdout)
"""
import json
import os
import sys

# 参考实现位于本仓库的兄弟目录: <...>/Network/hillstonux/hilldust
sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "hillstonux", "hilldust"))

from hillstone import IPSecParameters  # noqa: E402
import scapy.all  # noqa: E402

# Fixed inputs (deterministic fixture).
KEYMAT = bytes(range(48))  # 0x00..0x2f
OUT_SPI = 0x11223344  # SPI the client sends outbound (server's inbound SPI).
IN_SPI = 0x55667788  # SPI the client expects inbound (unused by _encap).
SEQ = 1  # fixed sequence number (see oracle notes in the Rust test).

# A fixed inner IPv4 packet (ICMP echo request 10.250.255.176 -> 10.1.111.154).
PLAINTEXT = bytes(scapy.all.raw(
    scapy.all.IP(src="10.250.255.176", dst="10.1.111.154") /
    scapy.all.ICMP() / scapy.all.Raw(b"hillstonux-esp-oracle-pad!!")))

# The two algorithm combinations the protocol supports (hillstone.new_key):
#   enc_alg 0x000c = AES-CBC (crypt 16, iv 16), 0x0003 = 3DES (crypt 24, iv 8)
#   auth_alg 0x0001 = HMAC-MD5-96 (16), 0x0002 = HMAC-SHA1-96 (20)
CASES = [
    {
        "name": "aes-cbc_hmac-sha1-96",
        "crypt_algo": "AES-CBC",
        "auth_algo": "HMAC-SHA1-96",
        "crypt_size": 0x10,
        "iv_size": 0x10,
        "auth_size": 0x14,
    },
    {
        "name": "3des_hmac-md5-96",
        "crypt_algo": "3DES",
        "auth_algo": "HMAC-MD5-96",
        "crypt_size": 0x18,
        "iv_size": 8,
        "auth_size": 0x10,
    },
]


def encap_like_reference(param, crypt_algo, auth_algo):
    """Byte-for-byte the same construction as impl_scapy.Client._encap,
    with a fixed seq_num so the fixture is deterministic."""
    sa = scapy.all.SecurityAssociation(
        proto=scapy.all.ESP,
        spi=param.out_spi,
        crypt_algo=crypt_algo,
        crypt_key=param.out_crypt_key,
        auth_algo=auth_algo,
        auth_key=param.out_auth_key,
    )
    raw = scapy.all.raw(scapy.all.IP() / scapy.all.IP(PLAINTEXT))
    full = sa.encrypt(scapy.all.IP(raw), seq_num=SEQ, iv=param.out_iv)
    esp_layer = full.getlayer(scapy.all.ESP)
    return bytes(scapy.all.raw(esp_layer))


def main():
    out = {
        "keymat": KEYMAT.hex(),
        "out_spi": OUT_SPI,
        "in_spi": IN_SPI,
        "seq": SEQ,
        "plaintext": PLAINTEXT.hex(),
        "cases": [],
    }
    for c in CASES:
        param = IPSecParameters(
            IN_SPI,
            OUT_SPI,
            KEYMAT,
            iv_size=c["iv_size"],
            auth_size=c["auth_size"],
            crypt_size=c["crypt_size"],
        )
        pkt = encap_like_reference(param, c["crypt_algo"], c["auth_algo"])
        out["cases"].append({
            "name": c["name"],
            "iv_size": c["iv_size"],
            "auth_size": c["auth_size"],
            "crypt_size": c["crypt_size"],
            # Derived keys (for the Rust test to assert the same derivation).
            "out_iv": param.out_iv.hex(),
            "out_auth_key": param.out_auth_key.hex(),
            "out_crypt_key": param.out_crypt_key.hex(),
            "encrypted": pkt.hex(),
        })
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
