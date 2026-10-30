/*
 * df_otp_gui.c - native Win32 GUI for the Deep Freeze 8.63 OTP core.
 *
 * Build on Linux:
 *   make -C c gui
 * Build on Windows with MinGW-w64:
 *   gcc -O2 -std=c11 -mwindows -DUNICODE -D_UNICODE -o df_otp_gui.exe ^
 *       df_otp_gui.c df_otp_core.c -lcomdlg32 -lgdi32 -luser32
 */

#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "df_otp_core.h"

#define ID_PATH 1001
#define ID_BROWSE 1002
#define ID_DATE 1003
#define ID_DAYS 1004
#define ID_KEY 1005
#define ID_TOKEN 1006
#define ID_SLOTS 1007
#define ID_GENERATE 1008
#define ID_COPY 1009
#define ID_CLEAR 1010
#define ID_OUTPUT 1011

static HWND g_window;
static HWND g_path;
static HWND g_date;
static HWND g_days;
static HWND g_key;
static HWND g_token;
static HWND g_slots;
static HWND g_output;
static HWND g_status;
static HFONT g_font;
static wchar_t g_last_otp[32];

typedef struct {
    wchar_t *data;
    size_t length;
    size_t capacity;
} wide_buffer;

static void ascii_to_wide(const char *source, wchar_t *dest, size_t dest_size)
{
    size_t i;
    if (dest_size == 0) {
        return;
    }
    for (i = 0; source[i] != '\0' && i + 1 < dest_size; ++i) {
        dest[i] = (wchar_t)(unsigned char)source[i];
    }
    dest[i] = L'\0';
}

static void wide_to_ascii(const wchar_t *source, char *dest, size_t dest_size)
{
    size_t i;
    if (dest_size == 0) {
        return;
    }
    for (i = 0; source[i] != L'\0' && i + 1 < dest_size; ++i) {
        wchar_t c = source[i];
        dest[i] = (c >= 0x20 && c < 0x7F) ? (char)c : '?';
    }
    dest[i] = '\0';
}

static int wide_buffer_append(wide_buffer *buffer, const wchar_t *text)
{
    size_t text_length = wcslen(text);
    if (buffer->length + text_length + 1 > buffer->capacity) {
        size_t capacity = buffer->capacity == 0 ? 4096 : buffer->capacity;
        wchar_t *data;
        while (capacity < buffer->length + text_length + 1) {
            capacity *= 2;
        }
        data = (wchar_t *)realloc(buffer->data, capacity * sizeof(wchar_t));
        if (data == NULL) {
            return 0;
        }
        buffer->data = data;
        buffer->capacity = capacity;
    }
    memcpy(buffer->data + buffer->length, text,
           (text_length + 1) * sizeof(wchar_t));
    buffer->length += text_length;
    return 1;
}

static HWND create_control(const wchar_t *class_name, const wchar_t *text,
                           DWORD style, DWORD ex_style, int x, int y,
                           int width, int height, int id)
{
    HWND control = CreateWindowExW(
        ex_style, class_name, text, WS_CHILD | WS_VISIBLE | style,
        x, y, width, height, g_window, (HMENU)(INT_PTR)id,
        GetModuleHandleW(NULL), NULL);
    if (control != NULL) {
        SendMessageW(control, WM_SETFONT, (WPARAM)g_font, TRUE);
    }
    return control;
}

static void set_status(const wchar_t *text)
{
    SetWindowTextW(g_status, text);
}

static int read_file_wide(const wchar_t *path, uint8_t **data, size_t *size,
                          wchar_t *error, size_t error_size)
{
    HANDLE file;
    LARGE_INTEGER length;
    uint8_t *buffer;
    size_t total = 0;

    file = CreateFileW(path, GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        swprintf(error, error_size, L"Cannot open file (error %lu)",
                 (unsigned long)GetLastError());
        return 0;
    }
    if (!GetFileSizeEx(file, &length) || length.QuadPart < 0 ||
        (uint64_t)length.QuadPart > (uint64_t)SIZE_MAX) {
        swprintf(error, error_size, L"Cannot read file size");
        CloseHandle(file);
        return 0;
    }
    *size = (size_t)length.QuadPart;
    buffer = (uint8_t *)malloc(*size == 0 ? 1 : *size);
    if (buffer == NULL) {
        swprintf(error, error_size, L"Out of memory");
        CloseHandle(file);
        return 0;
    }
    while (total < *size) {
        size_t remaining = *size - total;
        DWORD chunk = remaining > 0x10000000u ? 0x10000000u : (DWORD)remaining;
        DWORD read_count = 0;
        if (!ReadFile(file, buffer + total, chunk, &read_count, NULL) ||
            read_count == 0) {
            swprintf(error, error_size, L"Cannot read file (error %lu)",
                     (unsigned long)GetLastError());
            free(buffer);
            CloseHandle(file);
            return 0;
        }
        total += read_count;
    }
    CloseHandle(file);
    *data = buffer;
    return 1;
}

static int browse_for_file(void)
{
    static const wchar_t filter[] =
        L"Persi0.sys\0Persi0.sys\0All files\0*.*\0\0";
    OPENFILENAMEW dialog;
    wchar_t file_name[MAX_PATH];

    memset(&dialog, 0, sizeof(dialog));
    file_name[0] = L'\0';
    GetWindowTextW(g_path, file_name, MAX_PATH);
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = g_window;
    dialog.lpstrFilter = filter;
    dialog.lpstrFile = file_name;
    dialog.nMaxFile = MAX_PATH;
    dialog.lpstrTitle = L"Select Persi0.sys";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameW(&dialog)) {
        SetWindowTextW(g_path, file_name);
        return 1;
    }
    return 0;
}

static void append_slot_value(wide_buffer *buffer, const df_slot *slot)
{
    wchar_t value[DF_SLOT_VALUE_MAX * 4 + 1];
    size_t i;
    size_t position = 0;

    if (slot->state == 0) {
        wide_buffer_append(buffer, L"<empty>");
        return;
    }
    if (slot->state == 2) {
        wide_buffer_append(buffer, L"<malformed>");
        return;
    }
    if (slot->state == 3) {
        wide_buffer_append(buffer, L"<seed=0>");
        return;
    }
    for (i = 0; i < slot->value_length; ++i) {
        unsigned char c = (unsigned char)slot->value[i];
        if (c >= 0x20 && c < 0x7F) {
            value[position++] = (wchar_t)c;
        } else {
            swprintf(value + position, 5, L"\\x%02X", (unsigned)c);
            position += 4;
        }
    }
    value[position] = L'\0';
    wide_buffer_append(buffer, value);
}

static void show_error(const wchar_t *message)
{
    MessageBoxW(g_window, message, L"Deep Freeze OTP", MB_OK | MB_ICONERROR);
    set_status(message);
}

static void generate_otp(void)
{
    wchar_t path[MAX_PATH];
    wchar_t date_text[32];
    wchar_t days_text[16];
    wchar_t key_text[64];
    wchar_t token_text[DF_TOKEN_MAX + 1];
    wchar_t error[256];
    wchar_t line[1024];
    uint8_t *data = NULL;
    size_t size = 0;
    df_config config;
    uint32_t key;
    char token[DF_TOKEN_MAX + 1];
    char date_ascii[32];
    int32_t day_index;
    long days = 1;
    int show_slots;
    int i;
    wide_buffer output;

    GetWindowTextW(g_path, path, MAX_PATH);
    if (path[0] == L'\0') {
        show_error(L"Select a Persi0.sys file first.");
        return;
    }
    GetWindowTextW(g_date, date_text, 32);
    GetWindowTextW(g_days, days_text, 16);
    GetWindowTextW(g_key, key_text, 64);
    GetWindowTextW(g_token, token_text, DF_TOKEN_MAX + 1);

    if (days_text[0] != L'\0') {
        wchar_t *end = NULL;
        days = wcstol(days_text, &end, 10);
        if (end == days_text || *end != L'\0' || days < 1 || days > 3660) {
            show_error(L"Days must be a number from 1 to 3660.");
            return;
        }
    }

    if (!read_file_wide(path, &data, &size, error,
                        sizeof(error) / sizeof(error[0]))) {
        show_error(error);
        return;
    }
    {
        char parse_error[256];
        if (!df_parse_persi(data, size, &config, parse_error,
                            sizeof(parse_error))) {
            wchar_t wide_error[256];
            ascii_to_wide(parse_error, wide_error, 256);
            free(data);
            show_error(wide_error);
            return;
        }
    }
    free(data);

    if (key_text[0] != L'\0') {
        char key_ascii[64];
        wide_to_ascii(key_text, key_ascii, sizeof(key_ascii));
        key = df_parse_hex(key_ascii);
    } else {
        key = config.key;
    }

    if (token_text[0] != L'\0') {
        wide_to_ascii(token_text, token, sizeof(token));
    } else {
        memcpy(token, config.token, sizeof(token));
    }

    if (date_text[0] != L'\0') {
        wide_to_ascii(date_text, date_ascii, sizeof(date_ascii));
        if (df_parse_date(date_ascii, &day_index) != 0) {
            show_error(L"Date must be YYYY-MM-DD.");
            return;
        }
    } else {
        day_index = df_today_day_index();
    }

    memset(&output, 0, sizeof(output));
    if (!wide_buffer_append(&output, L"Deep Freeze 8.63 OTP\r\n\r\n")) {
        show_error(L"Out of memory.");
        return;
    }
    swprintf(line, 1024, L"File: %ls\r\n", path);
    wide_buffer_append(&output, line);
    swprintf(line, 1024, L"AdminOTPKey: 0x%08X\r\n", (unsigned)key);
    wide_buffer_append(&output, line);
    {
        wchar_t wide_token[DF_TOKEN_MAX + 1];
        ascii_to_wide(token, wide_token, DF_TOKEN_MAX + 1);
        swprintf(line, 1024, L"Token: \"%ls\"\r\n\r\n", wide_token);
        wide_buffer_append(&output, line);
    }

    swprintf(line, 1024,
             L"%-10ls %-20ls %-8ls %-16ls %ls\r\n",
             L"Date", L"Challenge", L"Pass", L"OTP", L"Verify");
    wide_buffer_append(&output, line);
    wide_buffer_append(&output,
                       L"--------------------------------------------------------------------\r\n");

    g_last_otp[0] = L'\0';
    for (i = 0; i < days; ++i) {
        df_otp_result result;
        char date_string[11];
        char message[128];
        wchar_t wide_date[11];
        wchar_t wide_challenge[32];
        wchar_t wide_pass[9];
        wchar_t wide_otp[16];
        wchar_t wide_message[128];
        int ok;

        df_make_otp(day_index + i, token, key, &result);
        df_format_date(result.day_index, date_string);
        ok = df_verify_otp(result.challenge, result.otp, key,
                           message, sizeof(message));
        ascii_to_wide(date_string, wide_date, 11);
        ascii_to_wide(result.challenge, wide_challenge, 32);
        ascii_to_wide(result.pass, wide_pass, 9);
        ascii_to_wide(result.otp, wide_otp, 16);
        ascii_to_wide(message, wide_message, 128);
        swprintf(line, 1024, L"%-10ls %-20ls %-8ls %-16ls %ls\r\n",
                 wide_date, wide_challenge, wide_pass, wide_otp,
                 ok ? L"OK" : L"FAIL");
        wide_buffer_append(&output, line);
        if (i == 0) {
            wcscpy(g_last_otp, wide_otp);
        }
        if (!ok) {
            swprintf(line, 1024, L"  verification: %ls\r\n", wide_message);
            wide_buffer_append(&output, line);
        }
    }

    show_slots = (SendMessageW(g_slots, BM_GETCHECK, 0, 0) == BST_CHECKED);
    if (show_slots) {
        wide_buffer_append(&output,
                           L"\r\nCredential slots:\r\n");
        swprintf(line, 1024,
                 L"%4ls %10ls %10ls %10ls %10ls %4ls  %ls\r\n",
                 L"slot", L"flags", L"start", L"stop", L"seed", L"len",
                 L"value");
        wide_buffer_append(&output, line);
        for (i = 0; i < DF_SLOT_MAX; ++i) {
            const df_slot *slot = &config.slots[i];
            swprintf(line, 1024,
                     L"%4d 0x%08X 0x%08X 0x%08X 0x%08X %4u  ",
                     i, (unsigned)slot->flags, (unsigned)slot->start,
                     (unsigned)slot->stop, (unsigned)slot->seed,
                     (unsigned)slot->length);
            wide_buffer_append(&output, line);
            append_slot_value(&output, slot);
            wide_buffer_append(&output, L"\r\n");
        }
    }

    SendMessageW(g_output, EM_SETLIMITTEXT, 0, 0);
    SetWindowTextW(g_output, output.data != NULL ? output.data : L"");
    free(output.data);

    swprintf(line, 1024, L"Generated %ld day(s).", days);
    set_status(line);
}

static void copy_first_otp(void)
{
    HGLOBAL memory;
    size_t bytes;
    void *destination;

    if (g_last_otp[0] == L'\0') {
        set_status(L"No OTP to copy.");
        return;
    }
    bytes = (wcslen(g_last_otp) + 1) * sizeof(wchar_t);
    memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (memory == NULL) {
        show_error(L"Cannot allocate clipboard memory.");
        return;
    }
    destination = GlobalLock(memory);
    if (destination == NULL) {
        GlobalFree(memory);
        show_error(L"Cannot lock clipboard memory.");
        return;
    }
    memcpy(destination, g_last_otp, bytes);
    GlobalUnlock(memory);
    if (!OpenClipboard(g_window)) {
        GlobalFree(memory);
        show_error(L"Cannot open clipboard.");
        return;
    }
    EmptyClipboard();
    if (SetClipboardData(CF_UNICODETEXT, memory) == NULL) {
        GlobalFree(memory);
        CloseClipboard();
        show_error(L"Cannot set clipboard data.");
        return;
    }
    CloseClipboard();
    set_status(L"OTP copied to clipboard.");
}

static void clear_output(void)
{
    SetWindowTextW(g_output, L"");
    g_last_otp[0] = L'\0';
    set_status(L"Cleared.");
}

static void create_interface(HWND window)
{
    char today[11];
    wchar_t wide_today[16];

    g_window = window;
    g_font = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                         DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                         CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                         DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

    create_control(L"BUTTON", L"Input", BS_GROUPBOX, 0,
                   12, 10, 716, 170, 0);
    create_control(L"STATIC", L"Persi0.sys:", SS_LEFT, 0,
                   24, 36, 100, 22, 0);
    g_path = create_control(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL,
                            WS_EX_CLIENTEDGE, 126, 33, 500, 26, ID_PATH);
    create_control(L"BUTTON", L"Browse...", BS_PUSHBUTTON, 0,
                   634, 33, 86, 26, ID_BROWSE);
    create_control(L"STATIC", L"Date:", SS_LEFT, 0,
                   24, 73, 44, 22, 0);
    g_date = create_control(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL,
                            WS_EX_CLIENTEDGE, 70, 70, 120, 26, ID_DATE);
    create_control(L"STATIC", L"Days:", SS_LEFT, 0,
                   210, 73, 44, 22, 0);
    g_days = create_control(L"EDIT", L"1", WS_BORDER | ES_NUMBER,
                            WS_EX_CLIENTEDGE, 258, 70, 56, 26, ID_DAYS);
    create_control(L"STATIC", L"AdminOTPKey:", SS_LEFT, 0,
                   334, 73, 94, 22, 0);
    g_key = create_control(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL,
                           WS_EX_CLIENTEDGE, 430, 70, 290, 26, ID_KEY);
    create_control(L"STATIC", L"Token:", SS_LEFT, 0,
                   24, 110, 50, 22, 0);
    g_token = create_control(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL,
                             WS_EX_CLIENTEDGE, 78, 107, 642, 26, ID_TOKEN);
    g_slots = create_control(L"BUTTON", L"Show credential slots",
                             BS_AUTOCHECKBOX, 0,
                             24, 143, 190, 24, ID_SLOTS);
    create_control(L"BUTTON", L"Generate OTP", BS_DEFPUSHBUTTON, 0,
                   550, 137, 170, 32, ID_GENERATE);

    create_control(L"BUTTON", L"Result", BS_GROUPBOX, 0,
                   12, 188, 716, 390, 0);
    g_output = create_control(L"EDIT", L"",
                              WS_BORDER | WS_VSCROLL | ES_MULTILINE |
                              ES_AUTOVSCROLL | ES_READONLY | ES_LEFT,
                              WS_EX_CLIENTEDGE, 24, 212, 692, 310, ID_OUTPUT);
    create_control(L"BUTTON", L"Copy first OTP", BS_PUSHBUTTON, 0,
                   24, 530, 140, 30, ID_COPY);
    create_control(L"BUTTON", L"Clear", BS_PUSHBUTTON, 0,
                   174, 530, 80, 30, ID_CLEAR);
    g_status = create_control(L"STATIC", L"Select Persi0.sys and press Generate OTP.",
                              SS_LEFT, 0, 268, 535, 448, 22, 0);

    df_format_date(df_today_day_index(), today);
    ascii_to_wide(today, wide_today, 16);
    SetWindowTextW(g_date, wide_today);
    if (GetFileAttributesW(L"Persi0.sys") != INVALID_FILE_ATTRIBUTES) {
        SetWindowTextW(g_path, L"Persi0.sys");
    }
}

static LRESULT CALLBACK window_proc(HWND window, UINT message,
                                    WPARAM w_param, LPARAM l_param)
{
    switch (message) {
    case WM_CREATE:
        create_interface(window);
        return 0;
    case WM_COMMAND:
        switch (LOWORD(w_param)) {
        case ID_BROWSE:
            browse_for_file();
            return 0;
        case ID_GENERATE:
            generate_otp();
            return 0;
        case ID_COPY:
            copy_first_otp();
            return 0;
        case ID_CLEAR:
            clear_output();
            return 0;
        default:
            break;
        }
        break;
    case WM_DESTROY:
        if (g_font != NULL) {
            DeleteObject(g_font);
            g_font = NULL;
        }
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(window, message, w_param, l_param);
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous_instance,
                   LPSTR command_line, int show_command)
{
    WNDCLASSEXW window_class;
    HWND window;
    MSG message;

    (void)previous_instance;
    (void)command_line;
    memset(&window_class, 0, sizeof(window_class));
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(NULL, IDC_ARROW);
    window_class.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    window_class.hIconSm = LoadIconW(NULL, IDI_APPLICATION);
    window_class.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    window_class.lpszClassName = L"DeepFreezeOTPWindow";
    if (!RegisterClassExW(&window_class)) {
        MessageBoxW(NULL, L"Cannot register window class.", L"Deep Freeze OTP",
                    MB_OK | MB_ICONERROR);
        return 1;
    }
    window = CreateWindowExW(
        WS_EX_APPWINDOW, window_class.lpszClassName,
        L"Deep Freeze 8.63 OTP", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU |
        WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 756, 620,
        NULL, NULL, instance, NULL);
    if (window == NULL) {
        MessageBoxW(NULL, L"Cannot create window.", L"Deep Freeze OTP",
                    MB_OK | MB_ICONERROR);
        return 1;
    }
    ShowWindow(window, show_command);
    UpdateWindow(window);

    while (GetMessageW(&message, NULL, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return (int)message.wParam;
}
