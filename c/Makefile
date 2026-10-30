CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic
TARGET := df_otp

.PHONY: all clean test

all: $(TARGET)

$(TARGET): df_otp.c
	$(CC) $(CFLAGS) -o $@ $<

test: $(TARGET)
	./$(TARGET) --self-test

clean:
	rm -f $(TARGET)
