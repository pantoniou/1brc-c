.PHONY: all clean

CC=gcc
# CC=clang
# CFLAGS=-O1 -Wall -g -fsanitize=address -fno-omit-frame-pointer -DCHECKS
# CFLAGS=-O3 -Wall -march=native -mtune=native -flto
# CFLAGS=-O2 -Wall -g -fno-omit-frame-pointer
CFLAGS=-O2 -Wall

all: 1brc-c

1brc-c: 1brc-c.c
	$(CC) $(CFLAGS) -o $@ $< -lm -lpthread

clean:
	@rm -f 1brc-c
