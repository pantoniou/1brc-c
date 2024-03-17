.PHONY: all clean check

CC=gcc
# CC=clang-15
# CFLAGS=-O1 -Wall -g -fsanitize=address -fno-omit-frame-pointer -DCHECKS 
# CFLAGS=-O3 -Wall -march=native -mtune=native -flto
# CFLAGS=-O2 -Wall -g -fno-omit-frame-pointer
CFLAGS=-O2 -Wall -g -fno-sanitize=address

all: 1brc-c

1brc-c: 1brc-c.c
	$(CC) $(CFLAGS) -o $@ $< -lm -lpthread

clean:
	@rm -f 1brc-c

check: 1brc-c
	@for t in samples/*.txt ; do \
		echo $$t `basename $$t`.out; \
	done

		# ./1brc-c $${t} | diff -u - $(basename 
