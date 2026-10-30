CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic
WINCC ?= x86_64-w64-mingw32-gcc
WINCFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic -mwindows -static -static-libgcc -DUNICODE -D_UNICODE

TARGET := df_otp
GUI := df_otp_gui.exe
CORE := df_otp_core.c df_otp_core.h

.PHONY: all gui clean test

all: $(TARGET)

$(TARGET): df_otp.c $(CORE)
	$(CC) $(CFLAGS) -o $@ df_otp.c df_otp_core.c

gui: $(GUI)

$(GUI): df_otp_gui.c $(CORE)
	$(WINCC) $(WINCFLAGS) -o $@ df_otp_gui.c df_otp_core.c -lcomdlg32 -lgdi32 -luser32

test: $(TARGET)
	./$(TARGET) --self-test

clean:
	rm -f $(TARGET) $(GUI)
