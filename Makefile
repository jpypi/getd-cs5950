CC=gcc
CFLAGS=-pedantic -Wall -std=c99

getd: getd.c error.o jlibc/hashmap/hashmap.c
	${CC} $(CFLAGS) -o $@ $^ -lnanomsg

error.o: error.c
	${CC} $(CFLAGS) -c $^

.PHONY: clean
clean:
	rm getd error.o
