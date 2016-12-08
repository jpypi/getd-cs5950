#include <stdio.h>
#include <string.h>
#include <nanomsg/nn.h>
#include <nanomsg/pair.h>

int main(const int argc, const char **argv)
{
    // create a socket, setting type to REPLY
    int sock = nn_socket(AF_SP, NN_PAIR);
    // connect to the socket
    nn_bind(sock, "ipc:///tmp/pair.ipc");

    for(;;) {
        // receive buffer
        char *buf = NULL;

        // receive message from socket and display
        nn_recv(sock, &buf, NN_MSG, 0);
        printf("> %s\n", buf);

        // if received message was "quit" shutdown
        if (strncmp("quit", buf, 5) == 0) return nn_shutdown(sock, 0);
        // otherwise, echo request back to socket
        else {
            printf("< %s\n", buf);
            nn_send(sock, buf, strlen(buf), 0);
        }

        nn_freemsg(buf);
    }
}

