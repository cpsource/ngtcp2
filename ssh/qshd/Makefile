CC       = gcc
CFLAGS   = -Wall -Wextra -O2 -DWOLFSSL_USE_OPTIONS_H \
           $(shell pkg-config --cflags libngtcp2 libngtcp2_crypto_wolfssl wolfssl)
LDFLAGS  = $(shell pkg-config --libs libngtcp2 libngtcp2_crypto_wolfssl wolfssl) -lutil

TARGET   = qshd

.PHONY: all clean

all: $(TARGET)

$(TARGET): qshd.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
