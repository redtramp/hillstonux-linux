#!/usr/bin/env python3
"""Generate a batch of Hillstone AUTH hex fixtures by running the Python
`hillstone` module against many user/pass/host_id combinations.

Used by the Rust cross-check integration test (`tests/cross_check_oracle.rs`)
to compare byte-for-byte against the Rust `MessageBuilder`.

Usage: dump_auth_hex.py [output_dir]
"""
import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../../../hillstonux/hilldust"))

from hillstone import Message, MessageType, Payload

TEST_CASES = [
    # (user, password, host_id, host_name)
    ("alice", "secret", "", ""),
    ("bob", "p@ss w0rd!", "host-id-123", "myhost"),
    ("konglh", "Ey4qcCLpr(Z9", "abc", "linux-box"),
    ("", "", "", ""),
    ("user_with_very_long_name_" + "x" * 50,
     "very_long_password_" + "y" * 50,
     "hid", "hname"),
    ("unicode_user_üñîçødé", "pässwörd", "", ""),
    ("user\twith\ncontrol", "pass\"with'quotes", "", ""),
]


def main():
    """Print JSON fixtures to stdout. Redirect with the shell to capture."""
    results = []
    for i, (user, pwd, hid, hn) in enumerate(TEST_CASES):
        m = Message(MessageType.AUTH)
        m.push_int(Payload.AUTH_TYPE, 2, 1)
        m.push_string(Payload.USERNAME, user)
        m.push_string(Payload.PASSWORD, pwd)
        m.push_string(Payload.CLIENT_VER, "1.0.0")
        m.push_string(Payload.HOST_ID, hid)
        m.push_string(Payload.HOST_NAME, hn)
        raw = m.finish()
        results.append({
            "index": i,
            "user": user,
            "pass": pwd,
            "host_id": hid,
            "host_name": hn,
            "hex": raw.hex(),
        })

    sys.stdout.write(json.dumps(results, indent=2, ensure_ascii=False))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
