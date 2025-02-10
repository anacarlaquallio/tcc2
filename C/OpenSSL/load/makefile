CC = gcc
CFLAGS = -Wall -Wextra -I/usr/include/openssl
LDFLAGS = -lssl -lcrypto -lm

SRCS = main.c
OBJS = $(SRCS:.c=.o)
EXECUTABLE = main

.PHONY: all clean

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(EXECUTABLE) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(EXECUTABLE)
