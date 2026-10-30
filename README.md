# Deep Freeze 8.63.020.5634 - Persi0.sys analysis

Private reverse-engineering notes for a local Deep Freeze 8.63.020.5634 sample.

**Result:** the active password slot is empty (`length = 0`); no admin password is set in this `Persi0.sys`. See [REPORT.md](REPORT.md) for the full analysis and [tools/df_persi.py](tools/df_persi.py) for the decoder.

## Contents

- `REPORT.md` - Vietnamese analysis report: container format, record cipher, config layout, slot decoder, driver authentication flow, findings, and AdminOTPKey/OTP analysis.
- `tools/df_persi.py` - standalone Python 3 decoder for `Persi0.sys` records and password slots.
- `tools/df_otp.py` - Deep Freeze 8.63 OTP generator from the `AdminOTPKey` and logon token (valid for the local calendar day).
- `c/df_otp.c` - portable C11 reader/OTP generator; builds with `make -C c`, self-tests with `c/df_otp --self-test`.
- `.gitignore` - excludes proprietary binaries, decrypted records and local secrets.

## Reproduce

```bash
python3 tools/df_persi.py Persi0.sys
python3 tools/df_persi.py Persi0.sys --dump-records out/
python3 tools/df_otp.py Persi0.sys --date 2026-10-30

make -C c
c/df_otp Persi0.sys --date 2026-10-30
c/df_otp --self-test
```

## Safety

This repository intentionally does **not** contain the original binaries, full license key, full AdminOTPKey, or decrypted configuration dumps. Use only on systems you own or are authorized to test.
