/*
 * df_otp.c - command line front end for the Deep Freeze 8.63 OTP core.
 *
 * Build:
 *   cc -O2 -std=c11 -Wall -Wextra -Wpedantic -o df_otp df_otp.c df_otp_core.c
 */

#include "df_otp_core.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_escaped(const char *data, size_t length)
{
    size_t i;
    for (i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)data[i];
        if (c >= 0x20 && c < 0x7F) {
            putchar((int)c);
        } else {
            printf("\\x%02X", c);
        }
    }
}

static void print_slots(const df_config *config)
{
    unsigned i;

    printf("\n%4s %10s %10s %10s %10s %4s  %s\n",
           "slot", "flags", "start", "stop", "seed", "len", "value");
    for (i = 0; i < DF_SLOT_MAX; ++i) {
        const df_slot *slot = &config->slots[i];
        printf("%4u 0x%08X 0x%08X 0x%08X 0x%08X %4u  ",
               i, (unsigned)slot->flags, (unsigned)slot->start,
               (unsigned)slot->stop, (unsigned)slot->seed,
               (unsigned)slot->length);
        switch (slot->state) {
        case 0:
            printf("<empty>");
            break;
        case 2:
            printf("<malformed>");
            break;
        case 3:
            printf("<seed=0>");
            break;
        default:
            print_escaped(slot->value, slot->value_length);
            break;
        }
        putchar('\n');
    }
}

static void print_json_string(const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
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
        df_otp_result result;
        char message[128];
        int ok;
        df_make_otp(tests[i].day, tests[i].token, tests[i].key, &result);
        ok = df_verify_otp(result.challenge, result.otp, tests[i].key,
                           message, sizeof(message));
        if (strcmp(result.challenge, tests[i].challenge) != 0 ||
            strcmp(result.pass, tests[i].pass) != 0 ||
            strcmp(result.otp, tests[i].otp) != 0 || !ok) {
            fprintf(stderr,
                    "self-test %zu failed: challenge=%s pass=%s otp=%s verify=%d (%s)\n",
                    i, result.challenge, result.pass, result.otp, ok, message);
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
    df_config config;
    char token[DF_TOKEN_MAX + 1];
    char error[256];
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
            if (errno != 0 || end == argv[i] || *end != '\0' ||
                n < 1 || n > 3660) {
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
            if (errno != 0 || end == argv[i] || *end != '\0' ||
                value > 0xFFFFFFFFul) {
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

    if (!df_load_persi(path, &config, error, sizeof(error))) {
        fprintf(stderr, "error: %s\n", error);
        return 1;
    }
    if (!have_key) {
        key = config.key;
    }
    if (token_override != NULL) {
        (void)snprintf(token, sizeof(token), "%s", token_override);
    } else {
        memcpy(token, config.token, sizeof(token));
    }
    if (date_text != NULL) {
        if (df_parse_date(date_text, &day_index) != 0) {
            fprintf(stderr, "error: bad date %s\n", date_text);
            return 1;
        }
    } else {
        day_index = df_today_day_index();
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
            print_slots(&config);
        }
        printf("\n%10s %20s %8s %14s  verify\n",
               "date", "challenge", "pass", "OTP");
    }

    for (i = 0; i < days; ++i) {
        df_otp_result result;
        char date_string[11];
        char message[128];
        int ok;
        df_make_otp(day_index + i, token, key, &result);
        df_format_date(result.day_index, date_string);
        ok = df_verify_otp(result.challenge, result.otp, key,
                           message, sizeof(message));
        if (json) {
            printf("    {\"date\": \"%s\", \"day_index\": %d, "
                   "\"salt\": \"%08X\", \"salt_hash\": \"%08X\", "
                   "\"challenge\": \"%s\", \"pass\": \"%s\", "
                   "\"otp\": \"%s\", \"verify\": %s, "
                   "\"verify_message\": ",
                   date_string, (int)result.day_index, (unsigned)result.salt,
                   (unsigned)result.salt_hash, result.challenge, result.pass,
                   result.otp, ok ? "true" : "false");
            print_json_string(message);
            printf("}%s\n", (i + 1 < days) ? "," : "");
        } else {
            printf("%10s %20s %8s %14s  %s\n",
                   date_string, result.challenge, result.pass, result.otp,
                   ok ? "OK" : "FAIL");
        }
    }
    if (json) {
        printf("  ]\n}\n");
    }
    return 0;
}
