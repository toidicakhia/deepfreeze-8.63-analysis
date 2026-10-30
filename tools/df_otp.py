#!/usr/bin/env python3
"""
df_otp.py - generate Deep Freeze 8.63 One Time Passwords from a Persi0.sys.

Model (driver 8.63.020.5634):

  config+0x0C  u32  AdminOTPKey (also called CCH)
  config+0x10  char[260] OTP token shown by the logon dialog

  day        = local Unix seconds / 86400
  salt       = day << 8
  challenge  = "%08X:%08X" % (token_value ^ salt, hash("%08X" % salt))
  pass       = keyed_hash(challenge, AdminOTPKey)          # 8 hex
  prefix     = first 4 chars of "%X" % hash(pass.lower())
  OTP        = prefix + "-" + pass

The keyed hash is sub_2E350 in the driver; the unkeyed hash is
sub_2E300 (the "Igor Zagoruchenko" constant is part of the keyed hash).
The driver verifies the OTP in sub_2E690 / sub_2E540, called from the
login fallback in sub_1D030.

The OTP is valid for the local calendar day (Deep Freeze docs: it
expires at midnight). Use only on systems you own or are authorized to
test.

Usage:
  python3 tools/df_otp.py Persi0.sys
  python3 tools/df_otp.py Persi0.sys --date 2026-10-30
  python3 tools/df_otp.py Persi0.sys --days 3
  python3 tools/df_otp.py Persi0.sys --key 0x11223344 --token 00000000
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from df_persi import CONFIG_OFFSET, CONFIG_SIZE, load  # noqa: E402

NAME_CONSTANT = "Igor Zagoruchenko"
NAME_HASH = 0x03F705CF  # hash(NAME_CONSTANT), computed at runtime by the driver


def s16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def trunc_div(a: int, b: int) -> int:
    q = abs(a) // b
    return -q if a < 0 else q


def df_hash(text: str) -> int:
    """sub_2E300: case-insensitive 32-bit hash used by the token/MAC code."""
    result = 0
    for ch in text:
        c = ord(ch)
        if 65 <= c <= 90:
            c |= 0x20
        v5 = (c + 16 * result) & 0xFFFFFFFF
        top = v5 & 0xF0000000
        if top:
            v5 ^= top >> 24
        result = (~top & v5) & 0xFFFFFFFF
    return result


def parse_hex(text: str) -> int:
    """Approximate sub_2E8E0 in base 16; stops at the first non-hex char."""
    text = text.strip()
    if text.startswith("-"):
        text = text[1:]
    elif text.startswith("+"):
        text = text[1:]
    if text[:2].lower() == "0x":
        text = text[2:]

    value = 0
    for ch in text:
        if "0" <= ch <= "9":
            digit = ord(ch) - 48
        elif "a" <= ch.lower() <= "f":
            digit = ord(ch.lower()) - 87
        else:
            break
        value = (value * 16 + digit) & 0xFFFFFFFF
    return value


def make_challenge(day_index: int, config_token: str) -> tuple[str, int, int, int]:
    """sub_2E5C0: build the daily challenge from config+0x10 and the day."""
    token_value = parse_hex(config_token)
    salt = (day_index << 8) & 0xFFFFFFFF
    salt_hash = df_hash(f"{salt:08X}")
    challenge = f"{token_value ^ salt:08X}:{salt_hash:08X}"
    return challenge, token_value, salt, salt_hash


def make_pass(challenge: str, key: int) -> str:
    """sub_2E350: keyed 8-hex pass from the challenge and AdminOTPKey."""
    v8 = (key ^ NAME_HASH ^ parse_hex(challenge)) & 0xFFFFFFFF

    if key != 0:
        x = s16(v8 ^ (v8 >> 16))
        q = trunc_div(x, 177)
        r = x - q * 177
        v9 = (32597 * r + 2 * q) & 0xFFFF

        hi = s16(v8 >> 16)
        q2 = trunc_div(hi, 177)
        r2 = hi - q2 * 177
        v10 = (v8 ^ ((2 * q2 + 32597 * r2) & 0xFFFF)) & 0xFFFF
    else:
        x = s16(v8)
        q = trunc_div(x, 177)
        r = x - q * 177
        v9 = (32597 * r + 2 * q) & 0xFFFF

        hi = s16(v8 >> 16)
        q2 = trunc_div(hi, 177)
        r2 = hi - q2 * 177
        v10 = (2 * q2 + 32597 * r2) & 0xFFFF

    return f"{v9:04X}{v10:04X}"


def make_otp(day_index: int, config_token: str, key: int) -> dict:
    challenge, token_value, salt, salt_hash = make_challenge(day_index, config_token)
    pass_value = make_pass(challenge, key)
    prefix = f"{df_hash(pass_value.lower()):X}"[:4].rjust(4)
    otp = f"{prefix}-{pass_value}"
    return {
        "day_index": day_index,
        "salt": f"{salt:08X}",
        "salt_hash": f"{salt_hash:08X}",
        "token_value": f"{token_value:08X}",
        "challenge": challenge,
        "pass": pass_value,
        "otp": otp,
    }


def verify_otp(challenge: str, otp: str, key: int) -> tuple[bool, str]:
    """sub_2E690 / sub_2E540 verification logic."""
    dash = otp.find("-")
    if dash != -1:
        prefix = otp[:dash]
        suffix = otp[dash + 1 :]
        expected_prefix = f"{df_hash(suffix):X}"[:4].rjust(4)
        if prefix.lower() != expected_prefix.lower():
            return False, f"prefix mismatch: expected {expected_prefix!r}, got {prefix!r}"
    else:
        suffix = otp

    expected_pass = make_pass(challenge, key)
    if expected_pass.lower() != suffix.lower():
        return False, f"pass mismatch: expected {expected_pass}, got {suffix}"
    return True, "OK"


def read_config(path: Path) -> tuple[int, str, bytes]:
    _entries, records = load(path)
    if 0 not in records:
        raise ValueError("record 0 not found")
    cfg = records[0][CONFIG_OFFSET : CONFIG_OFFSET + CONFIG_SIZE]
    if len(cfg) != CONFIG_SIZE:
        raise ValueError("record 0 is too short")
    key = struct.unpack_from("<I", cfg, 0x0C)[0]
    raw_token = cfg[0x10 : 0x10 + 260].split(b"\x00", 1)[0]
    token = raw_token.decode("ascii", "replace")
    return key, token, cfg


def parse_date(text: str) -> dt.date:
    return dt.datetime.strptime(text, "%Y-%m-%d").date()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("persi0", type=Path, help="path to Persi0.sys")
    parser.add_argument("--date", type=parse_date, help="local date (YYYY-MM-DD), default today")
    parser.add_argument("--days", type=int, default=1, help="number of days to print")
    parser.add_argument("--key", help="override AdminOTPKey (hex, e.g. 0x11223344)")
    parser.add_argument("--token", help="override the logon OTP token")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    try:
        key, token, _cfg = read_config(args.persi0)
    except (OSError, ValueError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.key is not None:
        key = int(args.key, 0)
    if args.token is not None:
        token = args.token

    start = args.date or dt.date.today()
    rows = []
    for offset in range(max(1, args.days)):
        day = start + dt.timedelta(days=offset)
        day_index = (day - dt.date(1970, 1, 1)).days
        row = make_otp(day_index, token, key)
        row["date"] = day.isoformat()
        ok, message = verify_otp(row["challenge"], row["otp"], key)
        row["verify"] = ok
        row["verify_message"] = message
        rows.append(row)

    if args.json:
        json.dump(
            {
                "file": str(args.persi0),
                "admin_otp_key": f"0x{key:08X}",
                "config_token": token,
                "rows": rows,
            },
            sys.stdout,
            indent=2,
        )
        print()
        return 0

    print(f"file: {args.persi0}")
    print(f"config_token: {token!r}")
    print(f"admin_otp_key: 0x{key:08X}")
    print()
    print(f"{'date':>10} {'token/challenge':>20} {'pass':>8} {'OTP':>14}  verify")
    for row in rows:
        print(
            f"{row['date']:>10} {row['challenge']:>20} {row['pass']:>8} "
            f"{row['otp']:>14}  {'OK' if row['verify'] else 'FAIL'}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
