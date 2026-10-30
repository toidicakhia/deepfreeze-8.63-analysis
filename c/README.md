# Deep Freeze 8.63 OTP tools (C)

Portable C11 reader for the Deep Freeze 8.63 `Persi0.sys` file and a
daily OTP generator, plus a native Win32 GUI. The code is a clean-room port of
the findings in [`../REPORT.md`](../REPORT.md); it contains no Faronics code,
private keys, or real OTP values.

## Files

- `df_otp_core.c` / `df_otp_core.h` - record parser, slot decoder, OTP core.
- `df_otp.c` - command line front end.
- `df_otp_gui.c` - native Win32 GUI front end (Unicode, no runtime DLLs).
- `Makefile` - CLI, GUI and self-test targets.

## Build

```bash
cd c
make          # CLI: df_otp
make test     # built-in synthetic vectors
make gui      # Windows GUI: df_otp_gui.exe (cross-compiled with mingw-w64)
```

Direct CLI build:

```bash
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -o df_otp df_otp.c df_otp_core.c
```

Direct Windows GUI build with MinGW-w64:

```bash
x86_64-w64-mingw32-gcc -O2 -std=c11 -Wall -Wextra -Wpedantic \
  -mwindows -static -static-libgcc -DUNICODE -D_UNICODE \
  -o df_otp_gui.exe df_otp_gui.c df_otp_core.c \
  -lcomdlg32 -lgdi32 -luser32
```

The GUI was built and smoke-tested with mingw-w64 + Wine. It is a native
Windows GUI executable and does not require a separate runtime.

## CLI usage

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

## GUI usage

Run `df_otp_gui.exe`. On launch it automatically searches for `Persi0.sys` in:

- the current working directory
- the directory containing the EXE
- the system drive root
- `Program Files`, `Program Files (x86)` and `ProgramData` under
  `Faronics\Deep Freeze` (including `Install C-0` and subdirectories)

If found, it loads the file and generates today's OTP immediately. If not
found, it opens the file dialog; after selecting a file it generates
automatically. You can then change the date/days, override `AdminOTPKey` or
token, tick `Show credential slots`, press `Generate OTP`, and use
`Copy first OTP`.

## Scope

- Offline parser for `Persi0.sys`; works on Linux, macOS and Windows.
- Implements the 8.63 record XOR cipher, config layout, slot decoder, OTP
  challenge/pass/prefix algorithm and verifier.
- Supports the runtime token override; on a live machine the token is the
  value shown by the Deep Freeze logon dialog / `0x72074` IOCTL.
- No live driver IOCTL access is included. Use Meltdown's `OpenVolume()` plus
  `0x7207C`/`0x72074` if live extraction is needed.

## Safety

Use only on systems you own or are authorized to test. Do not commit the
original binaries, real `AdminOTPKey`, license key, tokens, or generated OTPs.
