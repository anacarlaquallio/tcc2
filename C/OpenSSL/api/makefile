CC = gcc
CFLAGS = -Wall -Wextra -I/usr/include/openssl
LDFLAGS = -lssl -lcrypto

SRCS = rsa_t.c
OBJS = $(SRCS:.c=.o)
EXECUTABLE = rsa_t

.PHONY: all clean

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(EXECUTABLE) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(EXECUTABLE)
