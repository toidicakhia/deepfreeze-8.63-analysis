#!/usr/bin/env python3
"""
df_persi.py - decode Faronics Deep Freeze 8.x Persi0.sys records and password slots.

This is a clean-room reimplementation of the on-disk format observed in
Deep Freeze 8.63.020.5634. It does not contain any Faronics code or keys.

Usage:
  python3 df_persi.py Persi0.sys
  python3 df_persi.py Persi0.sys --dump-records out/
  python3 df_persi.py Persi0.sys --json

The password slot layout (relative to the 3221-byte config blob):
  +0x00 u32 flags/id
  +0x04 u32 StartDateTime (Delphi TDateTime, days since 1899-12-30)
  +0x08 u32 StopDateTime
  +0x0C u32 seed
  +0x10 u16 encoded byte length (2 + 2 * character_count)
  +0x12 u16[64] encoded password, only the low byte of each UTF-16 unit is used

Slot decoder:
  state = seed
  repeat character_count times:
      state = (32597 * (state % 177) + 2 * (state // 177)) & 0xFFFF
      char  = (state & 0xFF) ^ encoded_low_byte
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

MAGIC1 = 0x69123496
MAGIC2 = 0x67910617
RECORD_INITIAL_STATE = 30747
DIVISOR = 177
MULTIPLIER = 32597

CONFIG_OFFSET = 0x27D
CONFIG_SIZE = 3221
SLOT_TABLE_OFFSET = 301
SLOT_SIZE = 146
MAX_SLOTS = 20
SLOT_STRING_OFFSET = 0x10
SLOT_STRING_DATA_OFFSET = 0x12


def _record_step(state: int) -> int:
    """One step of the Persi0.sys record XOR stream (driver sub_29590).

    The driver performs signed 16-bit division with truncation toward zero.
    """
    sv = state if state < 0x8000 else state - 0x10000
    q = abs(sv) // DIVISOR
    if sv < 0:
        q = -q
    r = sv - q * DIVISOR
    return (2 * q + MULTIPLIER * r) & 0xFFFF


def _slot_step(state: int) -> int:
    """One step of the password-slot stream (driver sub_2DFC0, unsigned)."""
    return (MULTIPLIER * (state % DIVISOR) + 2 * (state // DIVISOR)) & 0xFFFF


def decrypt_record(blob: bytes) -> bytes:
    """Decrypt one Persi0.sys record payload."""
    out = bytearray(len(blob))
    state = RECORD_INITIAL_STATE
    for i, value in enumerate(blob):
        state = _record_step(state)
        out[i] = value ^ (state & 0xFF)
    return bytes(out)


def parse_index(data: bytes) -> list[tuple[int, int, int]]:
    """Return (record_id, offset, size) triples from the Persi0.sys index."""
    if len(data) < 12:
        raise ValueError("file is too small for a Persi0.sys header")
    count, magic1, magic2 = struct.unpack_from("<III", data, 0)
    if magic1 != MAGIC1 or magic2 != MAGIC2:
        raise ValueError(f"bad Persi0.sys magic: {magic1:08x} {magic2:08x}")
    if count > 256:
        raise ValueError(f"unreasonable record count: {count}")

    entries: list[tuple[int, int, int]] = []
    for i in range(count):
        record_id, offset, size = struct.unpack_from("<III", data, 12 + 12 * i)
        if offset + size > len(data):
            raise ValueError(f"record {record_id:#x} extends past end of file")
        entries.append((record_id, offset, size))
    return entries


def signed_record_id(record_id: int) -> int:
    return record_id - 0x100000000 if record_id >= 0x80000000 else record_id


def decode_slot(slot: bytes) -> str | None:
    """Decode the password string from one 146-byte slot.

    Returns "" for an empty password, None for a malformed length.
    A slot with seed == 0 cannot be decoded from disk: the driver replaces a
    zero seed with a random runtime seed (sub_2E100).
    """
    if len(slot) < SLOT_SIZE:
        return None
    seed = struct.unpack_from("<I", slot, 0x0C)[0]
    length = struct.unpack_from("<H", slot, SLOT_STRING_OFFSET)[0]
    if length == 0:
        return ""
    if length < 2 or length > 130 or (length - 2) % 2:
        return None
    if seed == 0:
        return None

    char_count = (length - 2) // 2
    state = seed & 0xFFFF
    chars: list[str] = []
    for i in range(char_count):
        state = _slot_step(state)
        encoded_low = slot[SLOT_STRING_DATA_OFFSET + 2 * i]
        chars.append(chr((state & 0xFF) ^ encoded_low))
    return "".join(chars)


def parse_config(record0: bytes) -> tuple[dict, list[dict]]:
    """Parse the 3221-byte config blob from decrypted record 0."""
    cfg = record0[CONFIG_OFFSET : CONFIG_OFFSET + CONFIG_SIZE]
    if len(cfg) != CONFIG_SIZE:
        raise ValueError("record 0 is too short to contain the config blob")

    slot_size, max_passwords, enable_otp, admin_otp_key = struct.unpack_from(
        "<IIII", cfg, 0
    )
    header = {
        "slot_size": slot_size,
        "max_passwords": max_passwords,
        "enable_otp": enable_otp,
        "admin_otp_key": admin_otp_key,
        "signature_area": cfg[CONFIG_SIZE:CONFIG_SIZE].hex(),  # empty; kept for clarity
    }

    slots: list[dict] = []
    count = max_passwords if 0 < max_passwords <= MAX_SLOTS else MAX_SLOTS
    for index in range(count):
        offset = SLOT_TABLE_OFFSET + index * SLOT_SIZE
        slot = cfg[offset : offset + SLOT_SIZE]
        if len(slot) != SLOT_SIZE:
            break
        flags, start, stop, seed = struct.unpack_from("<IIII", slot, 0)
        length = struct.unpack_from("<H", slot, SLOT_STRING_OFFSET)[0]
        slots.append(
            {
                "index": index,
                "config_offset": offset,
                "flags": flags,
                "start": start,
                "stop": stop,
                "seed": seed,
                "length": length,
                "password": decode_slot(slot),
            }
        )
    return header, slots


def load(path: Path) -> tuple[list[tuple[int, int, int]], dict[int, bytes]]:
    data = path.read_bytes()
    entries = parse_index(data)
    records: dict[int, bytes] = {}
    for record_id, offset, size in entries:
        records[record_id] = decrypt_record(data[offset : offset + size])
    return entries, records


def dump_records(records: dict[int, bytes], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for record_id, blob in records.items():
        (out_dir / f"rec_{record_id:08x}.bin").write_bytes(blob)


def print_report(path: Path, entries: list[tuple[int, int, int]], records: dict[int, bytes]) -> None:
    print(f"file: {path}")
    print(f"records: {len(entries)}")
    print()
    print(f"{'id':>10} {'offset':>10} {'size':>10} {'len@+0':>8} {'magic@+2':>8}")
    for record_id, offset, size in entries:
        blob = records[record_id]
        length = struct.unpack_from("<H", blob, 0)[0] if len(blob) >= 2 else 0
        magic = struct.unpack_from("<H", blob, 2)[0] if len(blob) >= 4 else 0
        print(
            f"{signed_record_id(record_id):>10} "
            f"0x{offset:08x} 0x{size:08x} 0x{length:04x} 0x{magic:04x}"
        )

    record0 = records.get(0)
    if record0 is None:
        print("\nrecord 0 not found; cannot parse config")
        return

    header, slots = parse_config(record0)
    print("\nconfig header:")
    print(f"  slot_size      = {header['slot_size']} (0x{header['slot_size']:x})")
    print(f"  max_passwords  = {header['max_passwords']}")
    print(f"  enable_otp     = {header['enable_otp']}")
    print(f"  admin_otp_key  = 0x{header['admin_otp_key']:08x}")
    print()
    print(f"{'slot':>4} {'flags':>10} {'start':>8} {'stop':>8} {'seed':>10} {'len':>4}  password")
    for slot in slots:
        password = slot["password"]
        if password is None:
            shown = "<malformed/seed=0>"
        elif password == "":
            shown = "<empty>"
        else:
            shown = password
        print(
            f"{slot['index']:>4} 0x{slot['flags']:08x} "
            f"0x{slot['start']:08x} 0x{slot['stop']:08x} "
            f"0x{slot['seed']:08x} {slot['length']:>4}  {shown}"
        )


def to_json(path: Path, entries: list[tuple[int, int, int]], records: dict[int, bytes]) -> dict:
    result: dict = {
        "file": str(path),
        "records": [
            {
                "id": signed_record_id(record_id),
                "offset": offset,
                "size": size,
                "header_length": struct.unpack_from("<H", records[record_id], 0)[0]
                if len(records[record_id]) >= 2
                else None,
                "header_magic": struct.unpack_from("<H", records[record_id], 2)[0]
                if len(records[record_id]) >= 4
                else None,
            }
            for record_id, offset, size in entries
        ],
    }
    if 0 in records:
        header, slots = parse_config(records[0])
        result["config"] = header
        result["slots"] = slots
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("persi0", type=Path, help="path to Persi0.sys")
    parser.add_argument("--dump-records", type=Path, metavar="DIR", help="write decrypted records")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = parser.parse_args(argv)

    try:
        entries, records = load(args.persi0)
    except (OSError, ValueError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.dump_records:
        dump_records(records, args.dump_records)
        print(f"wrote {len(records)} records to {args.dump_records}", file=sys.stderr)

    if args.json:
        json.dump(to_json(args.persi0, entries, records), sys.stdout, indent=2)
        print()
    else:
        print_report(args.persi0, entries, records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
