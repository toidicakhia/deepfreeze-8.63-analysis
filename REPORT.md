# Báo cáo phân tích Deep Freeze 8.63.020.5634

**Ngày thực hiện:** 2026-10-30  
**Mẫu:** `Persi0.sys` + driver `DeepFrz.sys`  
**Phiên bản:** 8.63.020.5634  
**Kết luận ngắn:** Mẫu này **không có mật khẩu admin được đặt**. Slot active duy nhất có trường độ dài mật khẩu bằng `0`; luồng kiểm tra trong driver chấp nhận mật khẩu rỗng (nhấn Enter, không nhập gì).

> Báo cáo chỉ chứa thông tin kỹ thuật, offset và hash. Không đưa binary gốc, license key hay OTP key đầy đủ vào repository.

---

## 1. Mục tiêu và phạm vi

Mục tiêu ban đầu là reverse `Persi0.sys` và driver Deep Freeze 8.63 để xác định mật khẩu admin được lưu ở đâu và khôi phục nó.

Phạm vi đã thực hiện:

- Phân tích container `Persi0.sys`.
- Dịch ngược driver `DeepFrz.sys` (PE32+ x64).
- Xác định thuật toán mã hoá record và thuật toán encode/decode mật khẩu trong slot.
- Đối chiếu với luồng UI `DFServ.exe` / `FrzState2k.exe`.
- Kiểm tra các record còn lại và các giá trị cấu hình khác.

---

## 2. Mẫu và hash

| File | Kích thước | SHA-256 |
|---|---:|---|
| `Persi0.sys` | 16.903.996 | `9f1a8dcc61a866d276d36535f1280a9357fc60e0c70fbcbcee0ca9129557a793` |
| `DeepFrz.sys` | 234.376 | `ebb017235fa4bbf68cc40495699c76ce464966a89fbf163a39430c506e117358` |
| `DFServ.exe` | 1.953.162 | `ff781b1a2a7987e2fe2b53c4e6e4fbee8f123fbed693f974efca0cd040c03bf5` |
| `FrzState2k.exe` | 2.663.408 | `4c7c960e8298a066da74a5927b36cb57f778617629ede6bb1604fea738d2270b` |
| `DeepFreezeAdapter.dll` | 1.687.536 | `a9ee04e61d4ba28412220a210d4f19715092a9fd63830f6d02ff821093eb1dc7` |

Các binary không được commit vào repository.

---

## 3. Tóm tắt kết quả

1. `Persi0.sys` dùng một bảng index gồm 14 record, mỗi record được XOR bằng một bộ sinh trạng thái 16-bit.
2. Record `0` chứa cấu hình chính (config blob) kích thước `3221` byte tại offset `0x27D`.
3. Config có 20 slot mật khẩu, mỗi slot `146` byte, bắt đầu tại offset `301` của config.
4. Chỉ slot `0` đang active (`flags = 0x80000011`), với:
   - `StartDateTime = 0xAD67` (2021-07-16)
   - `StopDateTime = 0xAD68` (2021-07-17)
   - `seed = 0x12F734CB`
   - `length = 0`
5. `length = 0` nghĩa là chuỗi mật khẩu rỗng. Hàm `sub_2DFC0` trong driver trả về `true` khi input rỗng và slot có length 0.
6. Slot 0 có bit `0x2` không bật, nên bước kiểm tra ngày bị bỏ qua; hàm `sub_1D030` trả về flags `0x80000011`.
7. 128 byte sau trường length là padding chưa khởi tạo, không phải ciphertext mật khẩu. Decode bằng seed cho ra dữ liệu ngẫu nhiên, không phải chuỗi hợp lệ.
8. Các giá trị bí mật khác có trong config nhưng không phải mật khẩu admin:
   - `AdminOTPKey`: có, đã redacted.
   - License/activation key dạng 40 ký tự: có, đã redacted.
9. Các record khác không chứa mật khẩu admin:
   - Record `0x7`: danh sách/URL (`http://`).
   - Record `0x13`: danh sách tên file (`DFWks.exe`, `FrzState2k.exe`, ...).
   - Record `0x14`, `0x17`: PE image nhúng.
   - Record `-0x10`: 16 byte + chuỗi `IVZIRNAHER`, nhiều khả năng là định danh volume/partition.

---

## 4. Định dạng `Persi0.sys`

### 4.1 Header và bảng index

Header bắt đầu tại offset `0`:

| Offset | Kiểu | Giá trị | Ý nghĩa |
|---:|---|---:|---|
| `0x00` | `u32` | `14` | Số record |
| `0x04` | `u32` | `0x69123496` | Magic 1 |
| `0x08` | `u32` | `0x67910617` | Magic 2 |
| `0x0C` | `(u32,u32,u32)[14]` | — | Bảng `(record_id, offset, size)` |

Các record:

| ID | Offset | Size |
|---:|---:|---:|
| `0x0` | `0xB4` | `0xB9B7` |
| `0x7` | `0xBA6B` | `0x556` |
| `0x8` | `0xBFC1` | `0x8011` |
| `0xF` | `0x13FD2` | `0x10` |
| `0x11` | `0x13FE2` | `0xBC` |
| `-0x10` | `0x1409E` | `0x22` |
| `0xE` | `0x140C0` | `0x10` |
| `0x12` | `0x140D0` | `0x10` |
| `0x14` | `0x140E0` | `0xA00000` |
| `0x15` | `0xA140E0` | `0x100000` |
| `0x16` | `0xB140E0` | `0x80000` |
| `0x17` | `0xB940E0` | `0x28A3F0` |
| `0x18` | `0xE1E4D0` | `0x200000` |
| `0x13` | `0x101E4D0` | `0xA6C` |

### 4.2 Thuật toán XOR record

Driver dùng hàm `sub_29590` với trạng thái ban đầu `30747` (`0x781B`). Mỗi byte:

```python
state = 30747
for i in range(len(blob)):
    sv = state if state < 0x8000 else state - 0x10000
    q = abs(sv) // 177
    if sv < 0:
        q = -q
    r = sv - q * 177
    state = (2 * q + 32597 * r) & 0xFFFF
    plain[i] = blob[i] ^ (state & 0xFF)
```

Điểm quan trọng: phép chia phải dùng **số có dấu 16-bit** và truncate về 0. Nếu dùng unsigned sẽ giải mã sai header record 0.

Sau khi giải mã, record 0 có:

| Offset | Giá trị |
|---:|---|
| `0x00` | `u16 length = 0xB9B7` |
| `0x02` | `u16 magic = 0x1712` |
| `0xBC` | Chuỗi `8.63.020.5634` |
| `0x130` | UTF-16 `DepFrz` |
| `0x27D` | Config blob (3221 byte) |
| `0xF12` | Vùng signature (toàn số 0 trong mẫu này) |
| `0x261D` | License/activation string (redacted) |
| `0x2AF2` | Các marker `0xFF`, stride `0x468` |

---

## 5. Config blob

Config bắt đầu tại `0x27D`, dài `3221` byte:

```text
+0x000  u32 slot_size        = 146
+0x004  u32 max_passwords    = 20
+0x008  u32 enable_otp       = 1
+0x00C  u32 admin_otp_key    = <redacted>
+0x010  ...                   = 0
+0x12D  slot[0]              = 146 byte
+0x1BF  slot[1]
...
+0xC03  slot[19]
```

20 slot × 146 byte = 2920 byte; `301 + 2920 = 3221`, vừa khít config.

### 5.1 Layout một slot

| Offset slot | Kiểu | Ý nghĩa |
|---:|---|---|
| `0x00` | `u32` | Flags/ID |
| `0x04` | `u32` | `StartDateTime` |
| `0x08` | `u32` | `StopDateTime` |
| `0x0C` | `u32` | Seed |
| `0x10` | `u16` | Độ dài chuỗi đã encode (bao gồm 2 byte length) |
| `0x12` | `u16[64]` | Chuỗi mật khẩu đã encode; chỉ dùng byte thấp của mỗi UTF-16 unit |

### 5.2 Bảng slot trong mẫu

Offset dưới đây là offset trong config blob; offset tuyệt đối trong record 0 = `0x27D + offset`.

| Slot | Config offset | Flags | Start | Stop | Seed | Length | Mật khẩu |
|---:|---:|---:|---:|---:|---:|---:|---|
| 0 | `0x12D` | `0x80000011` | `0xAD67` | `0xAD68` | `0x12F734CB` | `0` | `<empty>` |
| 1 | `0x1BF` | `0x00000010` | `0` | `0` | `0` | `0` | `<empty>` |
| 2 | `0x251` | `0x00000010` | `0` | `0` | `0` | `0` | `<empty>` |
| 3 | `0x2E3` | `0x00000010` | `0` | `0` | `0` | `0` | `<empty>` |
| 4 | `0x375` | `0x00000010` | `0` | `0` | `0` | `0` | `<empty>` |
| 5 | `0x407` | `0x00000010` | `0` | `0` | `0` | `0` | `<empty>` |
| 6 | `0x499` | `0x00000010` | `0` | `0` | `0` | `0` | `<empty>` |
| 7 | `0x52B` | `0x00000010` | `0` | `0` | `0` | `0` | `<empty>` |
| 8 | `0x5BD` | `0x00000010` | `0` | `0` | `0` | `0` | `<empty>` |
| 9 | `0x64F` | `0x00000010` | `0` | `0` | `0` | `0` | `<empty>` |
| 10 | `0x6E1` | `0x00000010` | `0` | `0` | `0` | `0` | `<empty>` |
| 11 | `0x773` | `0x00000010` | `0` | `0` | `0` | `0` | `<empty>` |
| 12 | `0x805` | `0x00000010` | `0` | `0` | `0` | `0` | `<empty>` |
| 13 | `0x897` | `0x00000010` | `0` | `0` | `0` | `0` | `<empty>` |
| 14 | `0x929` | `0x00000010` | `0` | `0` | `0` | `0` | `<empty>` |
| 15 | `0x9BB` | `0x00000000` | `0` | `0` | `0` | `0` | `<empty>` |
| 16 | `0xA4D` | `0x00000000` | `0` | `0` | `0` | `0` | `<empty>` |
| 17 | `0xADF` | `0x00000000` | `0` | `0` | `0` | `0` | `<empty>` |
| 18 | `0xB71` | `0x00000000` | `0` | `0` | `0` | `0` | `<empty>` |
| 19 | `0xC03` | `0x00000000` | `0` | `0` | `0` | `0` | `<empty>` |

Chỉ slot 0 có bit 31 (`0x80000000`) bật, tức là slot active. Các slot còn lại không được kiểm tra trong luồng đăng nhập.

---

## 6. Logic xác thực trong driver

### 6.1 Ánh xạ IOCTL

| IOCTL | Handler | Chức năng |
|---:|---|---|
| `0x72024` | `sub_15B00` | Đọc record |
| `0x72028` | `sub_156B0(0)` | Ghi record |
| `0x7206C` | `sub_156B0(1)` | Ghi record / slot |
| `0x72070` | `sub_12E40` | **Kiểm tra mật khẩu** |
| `0x72074` | `sub_13F20` | Đọc chuỗi tại `config+653` |
| `0x72078` | `sub_12BF0` | Kiểm tra/ghi signature license |
| `0x7207C` | `sub_12B70` | Đọc `AdminOTPKey` |
| `0x72084` | `sub_131F0` | Kiểm tra mật khẩu có rỗng không |
| `0x72088` | `sub_12FB0` | Kiểm tra có slot active không |
| `0x7208C` | `sub_13030` | Đổi mật khẩu |
| `0x72090` | `sub_156B0(2)` | Ghi record |
| `0x72094` | `sub_156B0(4)` | Ghi record |
| `0x72098` | `sub_156B0(3)` | Ghi record |

### 6.2 Luồng `sub_1D030`

```text
sub_1D030(input, input_type, config, result):
    if config.admin_otp_key == input.first_u32:
        return input_type == 1

    copy 3221-byte config
    for each of 20 slots:
        if slot.flags >= 0: continue
        if (slot.flags & 8) == 0 or input_type != 3:
            if (slot.flags & 0x10) == 0: continue
            if input_type == 3: continue

        decoded = decode_slot(slot.seed, slot.encoded)
        if case_insensitive_equal(input.string, decoded):
            if (slot.flags & 2) == 0:
                result = slot.flags
                return true
            if now within [slot.start, slot.stop]:
                result = slot.flags
                return true
            continue

    # fallback: license signature at config+653
    check_mac(config+653, config.admin_otp_key)
    return true with rights 32 or 4
```

Với slot 0:

- `flags = 0x80000011` → active, có bit `0x10`, không có bit `0x8`, không có bit `0x2`.
- `encoded length = 0` → `sub_2DFC0` chỉ trả `true` nếu input rỗng.
- Vì bit `0x2` không bật, kiểm tra ngày bị bỏ qua.
- Kết quả: input rỗng khớp slot 0 và trả về `0x80000011`.

### 6.3 Hàm so sánh `sub_2DFC0`

```text
if encoded_length == 0:
    return strlen(input) == 0

if strlen(input) != (encoded_length - 2) / 2:
    return false

state = seed
for i in range(strlen(input)):
    state = (32597 * (state % 177) + 2 * (state // 177)) & 0xFFFF
    decoded_char = (state & 0xFF) ^ encoded_utf16[i].low_byte
    if toupper(input[i]) != toupper(decoded_char):
        return false
return true
```

So sánh **không phân biệt hoa/thường**.

---

## 7. Thuật toán decode mật khẩu slot

Công thức đầy đủ:

```python
def decode_slot(slot):
    seed = u32(slot, 0x0C)
    length = u16(slot, 0x10)
    if length == 0:
        return ""
    if length < 2 or length > 130 or (length - 2) % 2 != 0:
        return None
    if seed == 0:
        return None  # driver thay seed 0 bằng seed random runtime

    n = (length - 2) // 2
    state = seed & 0xFFFF
    out = []
    for i in range(n):
        state = (32597 * (state % 177) + 2 * (state // 177)) & 0xFFFF
        out.append(chr((state & 0xFF) ^ slot[0x12 + 2 * i]))
    return "".join(out)
```

Mã hoá là phép đảo chiều của cùng công thức:

```python
state = seed
for i, ch in enumerate(new_password):
    state = (32597 * (state % 177) + 2 * (state // 177)) & 0xFFFF
    encoded[i] = (state & 0xFF) ^ ord(ch)
```

Hàm encode tương ứng trong driver là `sub_2E1D0`; hàm tạo seed là `sub_2E100`.

---

## 8. Vì sao 128 byte cuối slot là padding

Slot 0 có `length = 0`. Trong hàm `sub_2E1D0`, khi chuỗi rỗng:

- Độ dài được ghi là `0`.
- Vùng 128 byte phía sau không được ghi đè, nên vẫn giữ dữ liệu ngẫu nhiên từ lúc cấp phát.

Đã thử decode 128 byte này bằng seed `0x12F734CB` với nhiều độ dài khác nhau; kết quả là byte ngẫu nhiên, không phải UTF-16/ASCII hợp lệ. Vì vậy đây không phải mật khẩu bị mã hoá.

---

## 9. Các giá trị khác trong mẫu

| Vị trí | Giá trị | Ghi chú |
|---|---|---|
| Config `+0x0C` | `AdminOTPKey` | Đã redacted; dùng cho OTP/license |
| Record 0 `0x261D` | License/activation string 40 ký tự | Đã redacted; không phải mật khẩu admin |
| Record `0x7` | `http://` | Danh sách URL |
| Record `0x13` | `DFWks.exe`, `FrzState2k.exe`, ... | Danh sách file |
| Record `0x14` | PE image ~10 MB | Gói cài đặt nhúng |
| Record `0x17` | PE image ~2.6 MB | Gói cài đặt nhúng |
| Record `-0x10` | 16 byte + `IVZIRNAHER` | Định danh volume/partition |

---

## 10. Kết luận

Với mẫu `Persi0.sys` được cung cấp:

- **Không có mật khẩu admin nào được đặt.**
- Slot active duy nhất có mật khẩu rỗng (`length = 0`).
- Luồng đăng nhập chuẩn của driver chấp nhận mật khẩu rỗng.
- Các giá trị `AdminOTPKey` và license key không phải mật khẩu admin.

Nếu máy thực tế đang bị khoá bởi Deep Freeze, rất có thể:

1. `Persi0.sys` này là bản backup/cài đặt ban đầu chưa đặt mật khẩu, hoặc
2. Mật khẩu được lưu ở nơi khác (registry, AD/Enterprise Management) và cần mẫu khác để phân tích.

Để khôi phục mật khẩu từ một máy khác, cần lấy đúng file `Persi0.sys` hiện tại của máy đó (hoặc export registry/AD liên quan) rồi chạy lại decoder.

---

## 11. Tái lập

```bash
python3 tools/df_persi.py Persi0.sys
python3 tools/df_persi.py Persi0.sys --dump-records out/
python3 tools/df_persi.py Persi0.sys --json
```

Output mẫu:

```text
file: Persi0.sys
records: 14
...
config header:
  slot_size      = 146 (0x92)
  max_passwords  = 20
  enable_otp     = 1
  admin_otp_key  = <redacted>

slot      flags    start     stop       seed  len  password
   0 0x80000011 0x0000ad67 0x0000ad68 0x12f734cb    0  <empty>
   1 0x00000010 0x00000000 0x00000000 0x00000000    0  <empty>
...
```

---

## 12. Ghi chú pháp lý

Phân tích chỉ nên thực hiện trên hệ thống do bạn sở hữu hoặc có quyền kiểm thử. Repository không chứa binary gốc, license key hay OTP key đầy đủ.
