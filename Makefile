.PHONY: all clean check run

CC=gcc
# CC=clang
# CFLAGS=-O3 -Wall -march=native -mtune=native -flto
# CFLAGS=-O2 -Wall -g -fno-omit-frame-pointer
CFLAGS=-O3 -Wall -fno-sanitize=address

all: 1brc-c

1brc-c: 1brc-c.c Makefile
	$(CC) $(CFLAGS) -o $@ $< -lm -lpthread

clean:
	@rm -f 1brc-c

check: 1brc-c
	@./run-check.sh

run: 1brc-c measurements.txt
	/usr/bin/time -p ./1brc-c measurements.txt >/dev/null

measurements.txt: create-measurements.sh
	@./create-measurements.sh 1000000000

