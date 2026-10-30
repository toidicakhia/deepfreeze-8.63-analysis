#include "df_otp_core.h"

#include <ctype.h>
#include <errno.h>
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
#define SLOT_STRING_OFFSET 0x10u
#define SLOT_STRING_DATA_OFFSET 0x12u
#define NAME_HASH 0x03F705CFu

static uint16_t rd16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int16_t to_s16(uint16_t value)
{
    return value < 0x8000u ? (int16_t)value : (int16_t)((int)value - 0x10000);
}

static void set_error(char *error, size_t error_size, const char *text)
{
    if (error != NULL && error_size > 0) {
        (void)snprintf(error, error_size, "%s", text);
    }
}

uint32_t df_hash(const char *text)
{
    uint32_t result = 0;
    for (; *text != '\0'; ++text) {
        unsigned char c = (unsigned char)*text;
        uint32_t v5;
        uint32_t top;
        if (c >= 'A' && c <= 'Z') {
            c = (unsigned char)(c | 0x20u);
        }
        v5 = (uint32_t)c + 16u * result;
        top = v5 & 0xF0000000u;
        if (top != 0) {
            v5 ^= top >> 24;
        }
        result = (~top) & v5;
    }
    return result;
}

uint32_t df_parse_hex(const char *text)
{
    int negative = 0;
    uint32_t value = 0;

    while (isspace((unsigned char)*text)) {
        ++text;
    }
    if (*text == '-') {
        negative = 1;
        ++text;
    } else if (*text == '+') {
        ++text;
    }
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text += 2;
    }
    for (;;) {
        unsigned char c = (unsigned char)*text;
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
        ++text;
    }
    return negative ? 0u - value : value;
}

static void make_pass(const char *challenge, uint32_t key, char out[9])
{
    uint32_t v8 = key ^ NAME_HASH ^ df_parse_hex(challenge);
    uint16_t v9;
    uint16_t v10;

    if (key != 0) {
        int16_t x = to_s16((uint16_t)(v8 ^ (v8 >> 16)));
        int q = (int)x / DIVISOR;
        int r = (int)x % DIVISOR;
        int16_t hi = to_s16((uint16_t)(v8 >> 16));
        int q2 = (int)hi / DIVISOR;
        int r2 = (int)hi % DIVISOR;
        v9 = (uint16_t)(MULTIPLIER * r + 2 * q);
        v10 = (uint16_t)(v8 ^ (uint16_t)(2 * q2 + MULTIPLIER * r2));
    } else {
        int16_t x = to_s16((uint16_t)v8);
        int q = (int)x / DIVISOR;
        int r = (int)x % DIVISOR;
        int16_t hi = to_s16((uint16_t)(v8 >> 16));
        int q2 = (int)hi / DIVISOR;
        int r2 = (int)hi % DIVISOR;
        v9 = (uint16_t)(MULTIPLIER * r + 2 * q);
        v10 = (uint16_t)(2 * q2 + MULTIPLIER * r2);
    }
    (void)snprintf(out, 9, "%04X%04X", (unsigned)v9, (unsigned)v10);
}

static void prefix_from_hash(uint32_t hash, char prefix[5])
{
    char hex[16];
    size_t n;

    (void)snprintf(hex, sizeof(hex), "%X", (unsigned)hash);
    n = strlen(hex);
    if (n > 4) {
        n = 4;
    }
    memset(prefix, ' ', 4);
    memcpy(prefix + (4 - n), hex, n);
    prefix[4] = '\0';
}

void df_make_otp(int32_t day_index, const char *token, uint32_t key,
                 df_otp_result *result)
{
    char salt_string[9];
    char prefix[5];

    result->day_index = day_index;
    result->salt = (uint32_t)day_index << 8;
    result->token_value = df_parse_hex(token);
    (void)snprintf(salt_string, sizeof(salt_string), "%08X",
                   (unsigned)result->salt);
    result->salt_hash = df_hash(salt_string);
    (void)snprintf(result->challenge, sizeof(result->challenge),
                   "%08X:%08X", (unsigned)(result->token_value ^ result->salt),
                   (unsigned)result->salt_hash);
    make_pass(result->challenge, key, result->pass);
    prefix_from_hash(df_hash(result->pass), prefix);
    (void)snprintf(result->otp, sizeof(result->otp), "%s-%s", prefix,
                   result->pass);
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

int df_verify_otp(const char *challenge, const char *otp, uint32_t key,
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

int32_t df_days_from_civil(int y, unsigned m, unsigned d)
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

void df_civil_from_days(int32_t z, int *y, unsigned *m, unsigned *d)
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

void df_format_date(int32_t day_index, char out[11])
{
    int y;
    unsigned m;
    unsigned d;
    df_civil_from_days(day_index, &y, &m, &d);
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

int df_parse_date(const char *text, int32_t *day_index)
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
    *day_index = df_days_from_civil(y, (unsigned)m, (unsigned)d);
    return 0;
}

int32_t df_today_day_index(void)
{
    time_t now = time(NULL);
    struct tm *lt = localtime(&now);
    if (lt == NULL) {
        return 0;
    }
    return df_days_from_civil(lt->tm_year + 1900,
                              (unsigned)(lt->tm_mon + 1),
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

int df_parse_persi(const uint8_t *data, size_t size, df_config *config,
                   char *error, size_t error_size)
{
    uint32_t count;
    uint32_t index;
    const uint8_t *record0 = NULL;
    size_t record0_size = 0;
    uint8_t *decrypted;
    const uint8_t *cfg;
    size_t n;

    if (data == NULL || config == NULL) {
        set_error(error, error_size, "invalid argument");
        return 0;
    }
    memset(config, 0, sizeof(*config));
    if (size < 12) {
        set_error(error, error_size, "file too small");
        return 0;
    }
    count = rd32le(data);
    if (count > 256) {
        set_error(error, error_size, "unreasonable record count");
        return 0;
    }
    if (rd32le(data + 4) != MAGIC1 || rd32le(data + 8) != MAGIC2) {
        set_error(error, error_size, "bad container magic");
        return 0;
    }
    for (index = 0; index < count; ++index) {
        size_t entry = 12u + (size_t)index * 12u;
        uint32_t id;
        uint32_t offset;
        uint32_t length;
        if (entry + 12u > size) {
            set_error(error, error_size, "truncated index");
            return 0;
        }
        id = rd32le(data + entry);
        offset = rd32le(data + entry + 4);
        length = rd32le(data + entry + 8);
        if ((uint64_t)offset + (uint64_t)length > (uint64_t)size) {
            set_error(error, error_size, "record past end of file");
            return 0;
        }
        if ((int32_t)id == 0) {
            record0 = data + offset;
            record0_size = (size_t)length;
            break;
        }
    }
    if (record0 == NULL) {
        set_error(error, error_size, "record 0 not found");
        return 0;
    }
    if (record0_size < CONFIG_OFFSET + CONFIG_SIZE) {
        set_error(error, error_size, "record 0 too small for config");
        return 0;
    }
    decrypted = (uint8_t *)malloc(record0_size);
    if (decrypted == NULL) {
        set_error(error, error_size, "out of memory");
        return 0;
    }
    decrypt_record(record0, decrypted, record0_size);
    cfg = decrypted + CONFIG_OFFSET;
    config->key = rd32le(cfg + 0x0Cu);
    n = 0;
    while (n < DF_TOKEN_MAX && cfg[0x10u + n] != 0) {
        config->token[n] = (char)cfg[0x10u + n];
        ++n;
    }
    config->token[n] = '\0';

    for (index = 0; index < DF_SLOT_MAX; ++index) {
        const uint8_t *raw = cfg + SLOT_TABLE_OFFSET + (size_t)index * SLOT_SIZE;
        df_slot *slot = &config->slots[index];
        size_t j;
        uint16_t state;

        slot->flags = rd32le(raw);
        slot->start = rd32le(raw + 4);
        slot->stop = rd32le(raw + 8);
        slot->seed = rd32le(raw + 12);
        slot->length = rd16le(raw + SLOT_STRING_OFFSET);
        slot->value_length = 0;
        slot->value[0] = '\0';
        if (slot->length == 0) {
            slot->state = 0;
            continue;
        }
        if (slot->length < 2 || slot->length > 130 ||
            ((slot->length - 2u) & 1u) != 0) {
            slot->state = 2;
            continue;
        }
        if (slot->seed == 0) {
            slot->state = 3;
            continue;
        }
        state = (uint16_t)slot->seed;
        slot->value_length = (uint16_t)((slot->length - 2u) / 2u);
        for (j = 0; j < slot->value_length; ++j) {
            state = (uint16_t)(MULTIPLIER * (state % DIVISOR) +
                               2 * (state / DIVISOR));
            slot->value[j] = (char)((state & 0xFFu) ^
                                    raw[SLOT_STRING_DATA_OFFSET + 2u * j]);
        }
        slot->value[slot->value_length] = '\0';
        slot->state = 1;
    }
    free(decrypted);
    return 1;
}

int df_load_persi(const char *path, df_config *config,
                  char *error, size_t error_size)
{
    FILE *file;
    long length;
    uint8_t *data;
    int ok;

    file = fopen(path, "rb");
    if (file == NULL) {
        if (error != NULL && error_size > 0) {
            (void)snprintf(error, error_size, "cannot open file: %s",
                           strerror(errno));
        }
        return 0;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        set_error(error, error_size, "cannot stat file");
        fclose(file);
        return 0;
    }
    if ((unsigned long)length > (unsigned long)SIZE_MAX) {
        set_error(error, error_size, "file too large");
        fclose(file);
        return 0;
    }
    data = (uint8_t *)malloc((size_t)length);
    if (data == NULL) {
        set_error(error, error_size, "out of memory");
        fclose(file);
        return 0;
    }
    if (fread(data, 1, (size_t)length, file) != (size_t)length) {
        set_error(error, error_size, "short read");
        free(data);
        fclose(file);
        return 0;
    }
    fclose(file);
    ok = df_parse_persi(data, (size_t)length, config, error, error_size);
    free(data);
    return ok;
}
