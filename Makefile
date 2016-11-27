CC=gcc
CFLAGS=-pedantic -Wall -std=c99


sgetd: sgetd.c error.o acl.o util.o jlibc/hashmap/hashmap.c
	$(CC) $(CFLAGS) -o $@ $^ -lnanomsg

acl.o: acl.c error.o
	$(CC) $(CFLAGS) -c $^

util.o: util.c error.o
	$(CC) $(CFLAGS) -c $^

error.o: error.c
	$(CC) $(CFLAGS) -c $^


client: client.c error.o
	$(CC) $(CFLAGS) -o $@ $^ -lnanomsg

.PHONY: clean
clean:
	rm -f *.o
	rm -f sgetd client
