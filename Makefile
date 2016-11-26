CC=gcc
CFLAGS=-pedantic -Wall -std=c99


sgetd: getd.c error.o acl.o jlibc/hashmap/hashmap.c
	${CC} $(CFLAGS) -o $@ $^ -lnanomsg

acl.o: acl.c error.o
	${CC} $(CFLAGS) -c $^

error.o: error.c
	${CC} $(CFLAGS) -c $^

client: client.c error.o
	${CC} $(CFLAGS) -o $@ $^ -lnanomsg

.PHONY: clean
clean:
	rm -f *.o
	rm -f getd client
