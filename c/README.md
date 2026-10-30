# df_otp.c

Portable C11 implementation of the Deep Freeze 8.63 `Persi0.sys` reader and
daily One Time Password generator. The code is a clean-room port of the
findings in [`../REPORT.md`](../REPORT.md); it contains no Faronics code,
private keys, or real OTP values.

## Build

```bash
cd c
make
```

Or directly:

```bash
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -o df_otp df_otp.c
```

## Usage

```bash
# Read AdminOTPKey and token from Persi0.sys, generate today's OTP
./df_otp ../Persi0.sys

# Specific date, or a range of days
./df_otp ../Persi0.sys --date 2026-10-30
./df_otp ../Persi0.sys --date 2026-10-30 --days 3

# Inspect all 20 credential slots
./df_otp ../Persi0.sys --slots

# Override values for testing
./df_otp ../Persi0.sys --key 0x11223344 --token 00000000 --date 2026-10-30

# JSON output
./df_otp ../Persi0.sys --date 2026-10-30 --json

# Built-in synthetic vectors; no Persi0.sys required
./df_otp --self-test
```

Exit codes: `0` success, `1` usage/format error, `2` self-test failure.

## Scope

- Offline parser for `Persi0.sys`; works on Linux, macOS and Windows.
- Implements the 8.63 record XOR cipher, config layout, slot decoder, OTP
  challenge/pass/prefix algorithm and verifier.
- Supports the runtime token override; on a live machine the token is the
  value shown by the Deep Freeze logon dialog / `0x72074` IOCTL.
- No live driver IOCTL access is included in this file. Use Meltdown's
  `OpenVolume()` plus `0x7207C`/`0x72074` if live extraction is needed.

## Safety

Use only on systems you own or are authorized to test. Do not commit the
original binaries, real `AdminOTPKey`, license key, tokens, or generated OTPs.
