all: client server

client: client.o
	gcc -o client client.o -lnanomsg

server: server.o
	gcc -o server server.o -lnanomsg

client.o: client.c
	gcc -c client.c

server.o: server.c
	gcc -c server.c

.PHONY:
clean:
	rm *.o client server
