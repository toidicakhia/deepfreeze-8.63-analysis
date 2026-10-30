/*
 * df_otp.c - portable C decoder for Faronics Deep Freeze 8.63 Persi0.sys
 *            and One Time Password generator.
 *
 * This is a clean-room reimplementation of the on-disk format and the
 * OTP path observed in Deep Freeze 8.63.020.5634. It contains no Faronics
 * code, no private keys and no real OTPs.
 *
 * Build:
 *   cc -O2 -std=c11 -Wall -Wextra -Wpedantic -o df_otp df_otp.c
 *
 * Usage:
 *   ./df_otp Persi0.sys
 *   ./df_otp Persi0.sys --date 2026-10-30 --days 3
 *   ./df_otp Persi0.sys --slots
 *   ./df_otp --self-test
 *
 * Exit codes: 0 success, 1 usage/format error, 2 self-test failure.
 */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAGIC1 0x69123496u
#define MAGIC2 0x67910617u
#define RECORD_INITIAL_STATE 30747u
#define DIVISOR 177
#define MULTIPLIER 32597
#define CONFIG_OFFSET 0x27Du
#define CONFIG_SIZE 3221u
#define SLOT_TABLE_OFFSET 301u
#define SLOT_SIZE 146u
#define MAX_SLOTS 20
#define SLOT_STRING_OFFSET 0x10u
#define SLOT_STRING_DATA_OFFSET 0x12u
#define NAME_CONSTANT "Igor Zagoruchenko"
#define NAME_HASH 0x03F705CFu

typedef struct {
    int32_t day_index;
    uint32_t salt;
    uint32_t salt_hash;
    uint32_t token_value;
    char challenge[32];
    char pass[9];
    char otp[16];
} otp_result;

static uint16_t rd16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int16_t to_s16(uint16_t v)
{
    return v < 0x8000u ? (int16_t)v : (int16_t)((int)v - 0x10000);
}

static int ci_equal(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        unsigned char ca = (unsigned char)tolower((unsigned char)*a);
        unsigned char cb = (unsigned char)tolower((unsigned char)*b);
        if (ca != cb) {
            return 0;
        }
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

/* sub_2E300: case-insensitive 32-bit hash used by token, prefix and MAC. */
static uint32_t df_hash(const char *s)
{
    uint32_t result = 0;
    for (; *s != '\0'; ++s) {
        unsigned char c = (unsigned char)*s;
        if (c >= 'A' && c <= 'Z') {
            c = (unsigned char)(c | 0x20u);
        }
        uint32_t v5 = (uint32_t)c + 16u * result;
        uint32_t top = v5 & 0xF0000000u;
        if (top != 0) {
            v5 ^= top >> 24;
        }
        result = (~top) & v5;
    }
    return result;
}

/* Approximate sub_2E8E0(base 16), stopping at the first non-hex character. */
static uint32_t parse_hex(const char *s)
{
    int negative = 0;
    uint32_t value = 0;

    while (isspace((unsigned char)*s)) {
        ++s;
    }
    if (*s == '-') {
        negative = 1;
        ++s;
    } else if (*s == '+') {
        ++s;
    }
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }

    for (;;) {
        unsigned char c = (unsigned char)*s;
        unsigned int digit;
        if (c >= '0' && c <= '9') {
            digit = (unsigned int)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = (unsigned int)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            digit = (unsigned int)(c - 'A' + 10);
        } else {
            break;
        }
        value = value * 16u + digit;
        ++s;
    }
    return negative ? 0u - value : value;
}

/* sub_2E350: keyed 8-hex pass from a challenge and AdminOTPKey. */
static void make_pass(const char *challenge, uint32_t key, char out[9])
{
    uint32_t v8 = key ^ NAME_HASH ^ parse_hex(challenge);
    uint16_t v9;
    uint16_t v10;

    if (key != 0) {
        int16_t x = to_s16((uint16_t)(v8 ^ (v8 >> 16)));
        int q = (int)x / DIVISOR;
        int r = (int)x % DIVISOR;
        v9 = (uint16_t)(MULTIPLIER * r + 2 * q);

        int16_t hi = to_s16((uint16_t)(v8 >> 16));
        int q2 = (int)hi / DIVISOR;
        int r2 = (int)hi % DIVISOR;
        v10 = (uint16_t)(v8 ^ (uint16_t)(2 * q2 + MULTIPLIER * r2));
    } else {
        int16_t x = to_s16((uint16_t)v8);
        int q = (int)x / DIVISOR;
        int r = (int)x % DIVISOR;
        v9 = (uint16_t)(MULTIPLIER * r + 2 * q);

        int16_t hi = to_s16((uint16_t)(v8 >> 16));
        int q2 = (int)hi / DIVISOR;
        int r2 = (int)hi % DIVISOR;
        v10 = (uint16_t)(2 * q2 + MULTIPLIER * r2);
    }

    (void)snprintf(out, 9, "%04X%04X", (unsigned)v9, (unsigned)v10);
}

static void prefix_from_hash(uint32_t h, char prefix[5])
{
    char hex[16];
    size_t n;

    (void)snprintf(hex, sizeof(hex), "%X", (unsigned)h);
    n = strlen(hex);
    if (n > 4) {
        n = 4;
    }
    memset(prefix, ' ', 4);
    memcpy(prefix + (4 - n), hex, n);
    prefix[4] = '\0';
}

/* sub_2E5C0 + sub_2E350 + prefix: build the daily OTP. */
static void make_otp(int32_t day_index, const char *token, uint32_t key, otp_result *r)
{
    char salt_string[9];
    char prefix[5];

    r->day_index = day_index;
    r->salt = (uint32_t)day_index << 8;
    r->token_value = parse_hex(token);
    (void)snprintf(salt_string, sizeof(salt_string), "%08X", (unsigned)r->salt);
    r->salt_hash = df_hash(salt_string);
    (void)snprintf(r->challenge, sizeof(r->challenge), "%08X:%08X",
                   (unsigned)(r->token_value ^ r->salt),
                   (unsigned)r->salt_hash);
    make_pass(r->challenge, key, r->pass);
    prefix_from_hash(df_hash(r->pass), prefix);
    (void)snprintf(r->otp, sizeof(r->otp), "%s-%s", prefix, r->pass);
}

/* sub_2E690 / sub_2E540 verification logic. */
static int verify_otp(const char *challenge, const char *otp, uint32_t key,
                      char *message, size_t message_size)
{
    const char *dash = strchr(otp, '-');
    char suffix[16];

    if (dash != NULL) {
        size_t prefix_len = (size_t)(dash - otp);
        char prefix[5];
        char expected_prefix[5];

        memset(prefix, ' ', 4);
        prefix[4] = '\0';
        if (prefix_len >= 4) {
            memcpy(prefix, otp, 4);
        } else {
            memcpy(prefix, otp, prefix_len);
        }
        (void)snprintf(suffix, sizeof(suffix), "%s", dash + 1);
        prefix_from_hash(df_hash(suffix), expected_prefix);
        if (!ci_equal(prefix, expected_prefix)) {
            (void)snprintf(message, message_size,
                           "prefix mismatch: expected %s, got %s",
                           expected_prefix, prefix);
            return 0;
        }
    } else {
        (void)snprintf(suffix, sizeof(suffix), "%s", otp);
    }

    {
        char expected_pass[9];
        make_pass(challenge, key, expected_pass);
        if (!ci_equal(expected_pass, suffix)) {
            (void)snprintf(message, message_size,
                           "pass mismatch: expected %s, got %s",
                           expected_pass, suffix);
            return 0;
        }
    }
    (void)snprintf(message, message_size, "OK");
    return 1;
}

/* Civil date <-> days since 1970-01-01 (Howard Hinnant's algorithms). */
static int32_t days_from_civil(int y, unsigned m, unsigned d)
{
    int era;
    unsigned yoe;
    unsigned mp;
    unsigned doy;
    unsigned doe;

    y -= (m <= 2u);
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (unsigned)(y - era * 400);
    mp = (m > 2u) ? (m - 3u) : (m + 9u);
    doy = (153u * mp + 2u) / 5u + d - 1u;
    doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return (int32_t)era * 146097 + (int32_t)doe - 719468;
}

static void civil_from_days(int32_t z, int *y, unsigned *m, unsigned *d)
{
    int era;
    unsigned doe;
    unsigned yoe;
    int yy;
    unsigned doy;
    unsigned mp;

    z += 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = (unsigned)(z - era * 146097);
    yoe = (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
    yy = (int)yoe + era * 400;
    doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);
    mp = (5u * doy + 2u) / 153u;
    *d = doy - (153u * mp + 2u) / 5u + 1u;
    *m = mp + (mp < 10u ? 3u : (unsigned)-9);
    *y = yy + (*m <= 2u);
}

static void format_date(int32_t day_index, char out[11])
{
    int y;
    unsigned m;
    unsigned d;
    civil_from_days(day_index, &y, &m, &d);
    if (y < 0) {
        y = 0;
    } else if (y > 9999) {
        y = 9999;
    }
    out[0] = (char)('0' + (y / 1000) % 10);
    out[1] = (char)('0' + (y / 100) % 10);
    out[2] = (char)('0' + (y / 10) % 10);
    out[3] = (char)('0' + y % 10);
    out[4] = '-';
    out[5] = (char)('0' + (m / 10) % 10);
    out[6] = (char)('0' + m % 10);
    out[7] = '-';
    out[8] = (char)('0' + (d / 10) % 10);
    out[9] = (char)('0' + d % 10);
    out[10] = '\0';
}

static int parse_date(const char *text, int32_t *day_index)
{
    int y;
    int m;
    int d;
    if (sscanf(text, "%d-%d-%d", &y, &m, &d) != 3) {
        return -1;
    }
    if (y < 1970 || y > 3000 || m < 1 || m > 12 || d < 1 || d > 31) {
        return -1;
    }
    *day_index = days_from_civil(y, (unsigned)m, (unsigned)d);
    return 0;
}

static int32_t today_day_index(void)
{
    time_t now = time(NULL);
    struct tm *lt = localtime(&now);
    if (lt == NULL) {
        return 0;
    }
    return days_from_civil(lt->tm_year + 1900, (unsigned)(lt->tm_mon + 1),
                           (unsigned)lt->tm_mday);
}

static void decrypt_record(const uint8_t *in, uint8_t *out, size_t size)
{
    uint16_t state = (uint16_t)RECORD_INITIAL_STATE;
    size_t i;

    for (i = 0; i < size; ++i) {
        int sv = (state & 0x8000u) ? (int)state - 0x10000 : (int)state;
        int q = sv / DIVISOR;
        int r = sv % DIVISOR;
        state = (uint16_t)(2 * q + MULTIPLIER * r);
        out[i] = (uint8_t)(in[i] ^ (uint8_t)(state & 0xFFu));
    }
}

static uint8_t *read_file(const char *path, size_t *size_out)
{
    FILE *f;
    long length;
    uint8_t *data;

    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "error: cannot open %s: %s\n", path, strerror(errno));
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (length = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "error: cannot stat %s\n", path);
        fclose(f);
        return NULL;
    }
    if ((unsigned long)length > (unsigned long)SIZE_MAX) {
        fprintf(stderr, "error: file too large\n");
        fclose(f);
        return NULL;
    }
    data = (uint8_t *)malloc((size_t)length);
    if (data == NULL) {
        fprintf(stderr, "error: out of memory\n");
        fclose(f);
        return NULL;
    }
    if (fread(data, 1, (size_t)length, f) != (size_t)length) {
        fprintf(stderr, "error: short read on %s\n", path);
        free(data);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *size_out = (size_t)length;
    return data;
}

static void print_escaped(const uint8_t *data, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i) {
        unsigned char c = data[i];
        if (c >= 0x20 && c < 0x7F) {
            putchar((int)c);
        } else {
            printf("\\x%02X", c);
        }
    }
}

static void print_slots(const uint8_t *cfg)
{
    unsigned i;

    printf("\n%4s %10s %10s %10s %10s %4s  %s\n",
           "slot", "flags", "start", "stop", "seed", "len", "value");
    for (i = 0; i < MAX_SLOTS; ++i) {
        const uint8_t *slot = cfg + SLOT_TABLE_OFFSET + (size_t)i * SLOT_SIZE;
        uint32_t flags = rd32le(slot);
        uint32_t start = rd32le(slot + 4);
        uint32_t stop = rd32le(slot + 8);
        uint32_t seed = rd32le(slot + 12);
        uint16_t length = rd16le(slot + SLOT_STRING_OFFSET);

        printf("%4u 0x%08X 0x%08X 0x%08X 0x%08X %4u  ",
               i, (unsigned)flags, (unsigned)start, (unsigned)stop,
               (unsigned)seed, (unsigned)length);

        if (length == 0) {
            printf("<empty>");
        } else if (length < 2 || length > 130 || ((length - 2u) & 1u) != 0) {
            printf("<malformed>");
        } else if (seed == 0) {
            printf("<seed=0>");
        } else {
            uint16_t state = (uint16_t)seed;
            size_t count = (size_t)((length - 2u) / 2u);
            uint8_t decoded[65];
            size_t j;
            for (j = 0; j < count; ++j) {
                state = (uint16_t)(MULTIPLIER * (state % DIVISOR) +
                                   2 * (state / DIVISOR));
                decoded[j] = (uint8_t)((state & 0xFFu) ^
                                       slot[SLOT_STRING_DATA_OFFSET + 2u * j]);
            }
            print_escaped(decoded, count);
        }
        putchar('\n');
    }
}

static void print_json_string(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    putchar('"');
    for (; *p != '\0'; ++p) {
        unsigned char c = *p;
        switch (c) {
        case '"':
            fputs("\\\"", stdout);
            break;
        case '\\':
            fputs("\\\\", stdout);
            break;
        case '\n':
            fputs("\\n", stdout);
            break;
        case '\r':
            fputs("\\r", stdout);
            break;
        case '\t':
            fputs("\\t", stdout);
            break;
        default:
            if (c < 0x20) {
                printf("\\u%04X", (unsigned)c);
            } else {
                putchar((int)c);
            }
            break;
        }
    }
    putchar('"');
}

static int self_test(void)
{
    static const struct {
        uint32_t key;
        const char *token;
        int32_t day;
        const char *challenge;
        const char *pass;
        const char *otp;
    } tests[] = {
        { 0x11223344u, "00000000", 20756, "00511400:03844400", "C46C868D", "7C6B-C46C868D" },
        { 0x00000000u, "00000000", 20756, "00511400:03844400", "A6B05F4F", "C53B-A6B05F4F" },
    };
    size_t i;

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        otp_result r;
        char message[128];
        int ok;
        make_otp(tests[i].day, tests[i].token, tests[i].key, &r);
        ok = verify_otp(r.challenge, r.otp, tests[i].key, message, sizeof(message));
        if (strcmp(r.challenge, tests[i].challenge) != 0 ||
            strcmp(r.pass, tests[i].pass) != 0 ||
            strcmp(r.otp, tests[i].otp) != 0 || !ok) {
            fprintf(stderr,
                    "self-test %zu failed: challenge=%s pass=%s otp=%s verify=%d (%s)\n",
                    i, r.challenge, r.pass, r.otp, ok, message);
            return 1;
        }
    }
    printf("self-test: OK\n");
    return 0;
}

static void usage(const char *program)
{
    printf("usage: %s [Persi0.sys] [options]\n\n", program);
    printf("  --date YYYY-MM-DD   local date (default: today)\n");
    printf("  --days N            print N consecutive days (default: 1)\n");
    printf("  --key HEX           override AdminOTPKey\n");
    printf("  --token TOKEN       override logon token\n");
    printf("  --slots             print the 20 credential slots\n");
    printf("  --json              emit JSON\n");
    printf("  --self-test         run built-in synthetic vectors\n");
    printf("  --help              show this help\n");
}

int main(int argc, char **argv)
{
    const char *path = NULL;
    const char *date_text = NULL;
    const char *token_override = NULL;
    uint32_t key = 0;
    int have_key = 0;
    int days = 1;
    int show_slots = 0;
    int json = 0;
    int do_self_test = 0;
    int32_t day_index;
    uint8_t *file_data = NULL;
    size_t file_size = 0;
    uint8_t *record0 = NULL;
    size_t record0_size = 0;
    const uint8_t *cfg;
    char token[261];
    int i;

    for (i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(arg, "--self-test") == 0) {
            do_self_test = 1;
        } else if (strcmp(arg, "--slots") == 0) {
            show_slots = 1;
        } else if (strcmp(arg, "--json") == 0) {
            json = 1;
        } else if (strcmp(arg, "--date") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "error: --date needs YYYY-MM-DD\n");
                return 1;
            }
            date_text = argv[i];
        } else if (strcmp(arg, "--days") == 0) {
            char *end = NULL;
            long n;
            if (++i >= argc) {
                fprintf(stderr, "error: --days needs a number\n");
                return 1;
            }
            errno = 0;
            n = strtol(argv[i], &end, 10);
            if (errno != 0 || end == argv[i] || *end != '\0' || n < 1 || n > 3660) {
                fprintf(stderr, "error: bad --days value\n");
                return 1;
            }
            days = (int)n;
        } else if (strcmp(arg, "--key") == 0) {
            char *end = NULL;
            unsigned long value;
            if (++i >= argc) {
                fprintf(stderr, "error: --key needs a value\n");
                return 1;
            }
            errno = 0;
            value = strtoul(argv[i], &end, 0);
            if (errno != 0 || end == argv[i] || *end != '\0' || value > 0xFFFFFFFFul) {
                fprintf(stderr, "error: bad --key value\n");
                return 1;
            }
            key = (uint32_t)value;
            have_key = 1;
        } else if (strcmp(arg, "--token") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "error: --token needs a value\n");
                return 1;
            }
            token_override = argv[i];
        } else if (arg[0] == '-') {
            fprintf(stderr, "error: unknown option %s\n", arg);
            return 1;
        } else if (path == NULL) {
            path = arg;
        } else {
            fprintf(stderr, "error: multiple input files\n");
            return 1;
        }
    }

    if (do_self_test) {
        return self_test() == 0 ? 0 : 2;
    }

    if (path == NULL) {
        path = "Persi0.sys";
    }

    file_data = read_file(path, &file_size);
    if (file_data == NULL) {
        return 1;
    }
    if (file_size < 12) {
        fprintf(stderr, "error: file too small\n");
        free(file_data);
        return 1;
    }
    if (rd32le(file_data) > 256) {
        fprintf(stderr, "error: unreasonable record count\n");
        free(file_data);
        return 1;
    }
    if (rd32le(file_data + 4) != MAGIC1 || rd32le(file_data + 8) != MAGIC2) {
        fprintf(stderr, "error: bad Persi0.sys magic\n");
        free(file_data);
        return 1;
    }

    {
        uint32_t count = rd32le(file_data);
        uint32_t index;
        for (index = 0; index < count; ++index) {
            size_t entry = 12u + (size_t)index * 12u;
            uint32_t id;
            uint32_t offset;
            uint32_t size;
            if (entry + 12u > file_size) {
                fprintf(stderr, "error: truncated index\n");
                free(file_data);
                return 1;
            }
            id = rd32le(file_data + entry);
            offset = rd32le(file_data + entry + 4);
            size = rd32le(file_data + entry + 8);
            if ((uint64_t)offset + (uint64_t)size > (uint64_t)file_size) {
                fprintf(stderr, "error: record %u past end of file\n", (unsigned)id);
                free(file_data);
                return 1;
            }
            if ((int32_t)id == 0) {
                record0 = (uint8_t *)malloc((size_t)size);
                if (record0 == NULL) {
                    fprintf(stderr, "error: out of memory\n");
                    free(file_data);
                    return 1;
                }
                decrypt_record(file_data + offset, record0, (size_t)size);
                record0_size = (size_t)size;
                break;
            }
        }
    }
    free(file_data);

    if (record0 == NULL) {
        fprintf(stderr, "error: record 0 not found\n");
        return 1;
    }
    if (record0_size < CONFIG_OFFSET + CONFIG_SIZE) {
        fprintf(stderr, "error: record 0 too small for config\n");
        free(record0);
        return 1;
    }

    cfg = record0 + CONFIG_OFFSET;
    if (!have_key) {
        key = rd32le(cfg + 0x0Cu);
    }

    if (token_override != NULL) {
        (void)snprintf(token, sizeof(token), "%s", token_override);
    } else {
        size_t n = 0;
        while (n < 260u && cfg[0x10u + n] != 0) {
            token[n] = (char)cfg[0x10u + n];
            ++n;
        }
        token[n] = '\0';
    }

    if (date_text != NULL) {
        if (parse_date(date_text, &day_index) != 0) {
            fprintf(stderr, "error: bad date %s\n", date_text);
            free(record0);
            return 1;
        }
    } else {
        day_index = today_day_index();
    }

    if (json) {
        printf("{\n  \"file\": ");
        print_json_string(path);
        printf(",\n  \"admin_otp_key\": \"0x%08X\",\n  \"config_token\": ",
               (unsigned)key);
        print_json_string(token);
        printf(",\n  \"rows\": [\n");
    } else {
        printf("file: %s\n", path);
        printf("config_token: \"%s\"\n", token);
        printf("admin_otp_key: 0x%08X\n", (unsigned)key);
        if (show_slots) {
            print_slots(cfg);
        }
        printf("\n%10s %20s %8s %14s  verify\n",
               "date", "challenge", "pass", "OTP");
    }

    for (i = 0; i < days; ++i) {
        otp_result r;
        char date_string[11];
        char message[128];
        int ok;
        make_otp(day_index + i, token, key, &r);
        format_date(r.day_index, date_string);
        ok = verify_otp(r.challenge, r.otp, key, message, sizeof(message));
        if (json) {
            printf("    {\"date\": \"%s\", \"day_index\": %d, "
                   "\"salt\": \"%08X\", \"salt_hash\": \"%08X\", "
                   "\"challenge\": \"%s\", \"pass\": \"%s\", "
                   "\"otp\": \"%s\", \"verify\": %s}%s\n",
                   date_string, (int)r.day_index, (unsigned)r.salt,
                   (unsigned)r.salt_hash, r.challenge, r.pass, r.otp,
                   ok ? "true" : "false", (i + 1 < days) ? "," : "");
        } else {
            printf("%10s %20s %8s %14s  %s\n",
                   date_string, r.challenge, r.pass, r.otp,
                   ok ? "OK" : "FAIL");
        }
    }

    if (json) {
        printf("  ]\n}\n");
    }

    free(record0);
    return 0;
}
