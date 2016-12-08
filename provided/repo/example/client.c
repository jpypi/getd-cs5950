#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nanomsg/nn.h>
#include <nanomsg/pair.h>

int main(const int argc, const char **argv)
{
    // create a socket, setting type to REQUEST
    int sock = nn_socket(AF_SP, NN_PAIR);
    // connect to the socket
    nn_connect(sock, "ipc:///tmp/pair.ipc");

    for(;;) {
        // request buffer for user input
        char *request = calloc(256, sizeof(char));

        // prompt user for input
        printf("> ");
        fgets(request, 255, stdin);
        // flush stdin and remove newline
        fseek(stdin, 0, SEEK_END);
        request[strlen(request) - 1] = 0;

        // send the request to the socket
        nn_send(sock, request, strlen(request), 0);

        // if "quit" was sent, shutdown
        if (strncmp("quit", request, 4) == 0) return nn_shutdown(sock, 0);

        free(request);

        // receive and print response from socket
        char *buf;
        nn_recv(sock, &buf, NN_MSG, 0);
        printf("%s\n", buf);

        nn_freemsg(buf);
    }
}

