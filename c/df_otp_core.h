#ifndef DF_OTP_CORE_H
#define DF_OTP_CORE_H

#include <stddef.h>
#include <stdint.h>

#define DF_TOKEN_MAX 260
#define DF_SLOT_MAX 20
#define DF_SLOT_VALUE_MAX 64

typedef struct {
    uint32_t flags;
    uint32_t start;
    uint32_t stop;
    uint32_t seed;
    uint16_t length;
    uint16_t value_length;
    int state; /* 0 empty, 1 decoded, 2 malformed, 3 seed zero */
    char value[DF_SLOT_VALUE_MAX + 1];
} df_slot;

typedef struct {
    uint32_t key;
    char token[DF_TOKEN_MAX + 1];
    df_slot slots[DF_SLOT_MAX];
} df_config;

typedef struct {
    int32_t day_index;
    uint32_t salt;
    uint32_t salt_hash;
    uint32_t token_value;
    char challenge[32];
    char pass[9];
    char otp[16];
} df_otp_result;

int df_parse_persi(const uint8_t *data, size_t size, df_config *config,
                   char *error, size_t error_size);
int df_load_persi(const char *path, df_config *config,
                  char *error, size_t error_size);

uint32_t df_hash(const char *text);
uint32_t df_parse_hex(const char *text);
void df_make_otp(int32_t day_index, const char *token, uint32_t key,
                 df_otp_result *result);
int df_verify_otp(const char *challenge, const char *otp, uint32_t key,
                  char *message, size_t message_size);

int32_t df_days_from_civil(int year, unsigned month, unsigned day);
void df_civil_from_days(int32_t day_index, int *year, unsigned *month,
                        unsigned *day);
void df_format_date(int32_t day_index, char out[11]);
int df_parse_date(const char *text, int32_t *day_index);
int32_t df_today_day_index(void);

#endif
