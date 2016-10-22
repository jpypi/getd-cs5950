CC=gcc
CFLAGS=-pedantic -Wall -std=c99


getd: getd.c error.o acl.o jlibc/hashmap/hashmap.c
	${CC} $(CFLAGS) -o $@ $^ -lnanomsg

acl.o: acl.c error.o
	${CC} $(CFLAGS) -c $^

error.o: error.c
	${CC} $(CFLAGS) -c $^


.PHONY: clean
clean:
	rm getd error.o acl.o
