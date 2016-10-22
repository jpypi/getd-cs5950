/*
 * Reference(s):
 * http://tim.dysinger.net/posts/2013-09-16-getting-started-with-nanomsg.html
 */
#define _XOPEN_SOURCE 700

#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

#include <nanomsg/nn.h>
#include <nanomsg/pair.h>

#include "apue.h"
#include "jlibc/hashmap/hashmap.h"
#include "message.h"
#include "acl.h"


#define initmsgtype(N) {.header.messageType = N,\
                        .header.messageLength = sizeof(MessageType ## N)}
#define initsidtype(N) {.header.messageType = N,\
                        .header.messageLength = sizeof(MessageType ## N),\
                        .sidLength=SID_LENGTH}
#define sendtype(N, sock, obj) nn_send(sock, obj, sizeof(MessageType ## N), 0)

HashMap *sessions;


/*
 * A safe copy for session ids. Always only use nlength and set a null byte at
 * the end of the dest.
 */
void safe_sid_copy(char *dest, char const *src)
{
    strncpy(dest, src, SID_LENGTH);
    dest[SID_LENGTH] = 0;
}


/*
 * Checks that a path is a full path spec
 * Return:
 *   1 if path starts with a / (aka is a full path) and is not NULL
 *   0 otherwise
 */
int is_full_path(char *path)
{
    return (path != NULL && path[0] == '/');
}


/* TYPE 2
 * Send a NULL terminated length-limited error message to the client.
 *
 * Returns: Results of nn_send
 */
int send_error(int sock, char *error_text)
{
    MessageType2 err_msg = initmsgtype(2);
    err_msg.msgLength = strnlen(error_text, MAX_ERROR_MESSAGE);
    strncpy(err_msg.errorMessage, error_text, MAX_ERROR_MESSAGE);
    err_msg.errorMessage[MAX_ERROR_MESSAGE] = 0;

    return sendtype(2, sock, &err_msg);
}


/* TYPE 1
 * Generate a session ID for the connecting user and send it to them.
 */
void establish_session(int sock, char const *username)
{
    MessageType1 response = initsidtype(1);

    char random_id[SID_LENGTH];
    for (int i = 0; i < SID_LENGTH; i += sizeof(long int))
        *(random_id+i) = random();

    for (int i = 0; i < SID_LENGTH; i++)
        random_id[i] = (random_id[i] & 0x3f) + 'A';

    safe_sid_copy(response.sessionId, random_id);

    // TODO: Double check this is safe. Probably use strnlen.
    unsigned int un_len = strlen(username);
    char *un = malloc(un_len+1);
    strncpy(un, username, un_len+1);

    putElement(sessions, random_id, un);

    sendtype(1, sock, &response);
}


/* TYPE 5
 * End the session with the client
 */
void end_session(int sock, char const *session_id)
{
    MessageType5 response = initsidtype(5);
    safe_sid_copy(response.sessionId, session_id);
    sendtype(5, sock, &response);
}


/*
 * A user is requesting to start a session
 */
void handle0(int sock, MessageType0 *buffer)
{
    printf("Requesting User: %s\n", buffer->distinguishedName);
    establish_session(sock, buffer->distinguishedName);
}


/*
 * User is sending ACK of a type 4 (file send) message.
 * TODO: Validate the session id
 */
int expect_ack(int sock, char const *session_id)
{
    printf("Expecting an ack\n");
    MessageType6 *buffer = NULL;

    int bytes_read = nn_recv(sock, &buffer, NN_MSG, 0);
    if (bytes_read != sizeof(MessageType6)) {
        send_error(sock, "Invalid ACK (message type 6) session id!");
        return 0;
    }

    printf("Ack sid: %s\n", buffer->sessionId);
    return 1;
}


/*
 * Send chuncks of the file to the client
 */
void file_transfer(int sock, char *session_id, char *path)
{
    MessageType4 response = initsidtype(4);
    safe_sid_copy(response.sessionId, session_id);

    FILE *src_file = fopen(path, "r");

    while (1) {
        // Zero the content buffer
        for (int i = 0; i < MAX_CONTENT_LENGTH; i++)
            response.contentBuffer[i] = 0;

        response.contentLength = fread(response.contentBuffer, 1,
                                       MAX_CONTENT_LENGTH, src_file);

        if (response.contentLength < 1) {
            break;
        }

        sendtype(4, sock, &response);
        expect_ack(sock, session_id);
    }

    end_session(sock, session_id);
    expect_ack(sock, session_id);
}


/*
 * A user is requesting a file
 */
void handle3(int sock, MessageType3 *buffer)
{
    printf("Handling 3\n");
    if (buffer->sidLength != SID_LENGTH || buffer->sessionId[SID_LENGTH] != 0) {
        send_error(sock, "Invalid session id.");
        return;
    } else {
        printf("Session id: %s\n", buffer->sessionId);
        printf("Path: %s\n", buffer->pathName);
        file_transfer(sock, buffer->sessionId, buffer->pathName);
    }
}


void server_loop(int sock)
{
    int bytes_read = 0;

    while(1) {
        void *buffer = NULL;
        Header *msg_header;

        bytes_read = nn_recv(sock, &buffer, NN_MSG, 0);
        if (bytes_read > 0) {
            msg_header = (Header*)buffer;

            printf("Bytes read: %d\n", bytes_read);
            printf("Message type: %d\n", msg_header->messageType);
            printf("Message size: %d\n", msg_header->messageLength);
        } else {
            err_quit("Error: %s", nn_strerror(errno));
        }


        switch(msg_header->messageType) {
            case TYPE0:
                handle0(sock, (MessageType0*)buffer);
                break;
            case TYPE3:
                handle3(sock, (MessageType3*)buffer);
                break;
            default:
                break;
        }

        nn_freemsg(buffer);
    }
}


int main(int argc, char *argv[])
{
    printf("PATH_MAX: %d\n", PATH_MAX);

    // Seed the prng
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    srandom((unsigned int)ts.tv_nsec);

    // Initialize sessions hashmap
    sessions = initHashMap(20, NULL);

    // Create a nn_socket
    int sock = nn_socket(AF_SP, NN_PAIR);
    if (sock < 0)
        err_quit("Couldn't build a socket");

    if (nn_bind(sock, "ipc:///tmp/getd.ipc") < 0)
        err_quit("We've got an error yo.");

    server_loop(sock);

    // Clean up after ourselves
    nn_shutdown(sock, 0);

    freeHashMap(sessions, free);

    return 0;
}
