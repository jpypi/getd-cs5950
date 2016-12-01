CC=gcc
CFLAGS=-pedantic -Wall -std=c99


sgetd: sgetd.c error.o acl.o util.o encryption.o
	$(CC) $(CFLAGS) -o $@ $^ -lnanomsg -lcl -ldl -lresolv -lpthread -Wno-unused-result

acl.o: acl.c
	$(CC) $(CFLAGS) -c $^

util.o: util.c
	$(CC) $(CFLAGS) -c $^

encryption.o: encryption.c
	$(CC) $(CFLAGS) -c $^

error.o: error.c
	$(CC) $(CFLAGS) -c $^


client: client.c error.o
	$(CC) $(CFLAGS) -o $@ $^ -lnanomsg

.PHONY: clean
clean:
	rm -f *.o
	rm -f sgetd client
