CC       = gcc
CFLAGS   = -Wall -Wextra -O2 -DWOLFSSL_USE_OPTIONS_H \
           $(shell pkg-config --cflags libngtcp2 libngtcp2_crypto_wolfssl wolfssl)

# Fully static linking
STATIC_LIBS = /usr/local/lib/libngtcp2.a \
              /usr/local/lib/libngtcp2_crypto_wolfssl.a \
              /usr/local/lib/libwolfssl.a
LDFLAGS  = $(STATIC_LIBS) -lm -lpthread

TARGET   = qsh

.PHONY: all clean

all: $(TARGET)

$(TARGET): qsh.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
