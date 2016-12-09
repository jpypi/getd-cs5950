/*
 * Reference(s):
 * http://tim.dysinger.net/posts/2013-09-16-getting-started-with-nanomsg.html
 */
#define _XOPEN_SOURCE 700

#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <nanomsg/nn.h>
#include <nanomsg/pair.h>
#include "cryptlib.h"

#include "apue.h"
#include "message.h"
#include "acl.h"
#include "util.h"
#include "encryption.h"

// So functions can be ordered more freely/logically
#include "sgetd.h"

#define initmsgtype(N) {.header.messageType = N,\
                        .header.messageLength = sizeof(MessageType ## N)}
#define initsidtype(N) {.header.messageType = N,\
                        .header.messageLength = sizeof(MessageType ## N),\
                        .sidLength=SID_LENGTH}
#define sendtype(N, sock, obj) nn_send(sock, obj, sizeof(MessageType ## N), 0)

#define ERR_MSG "Reset"

struct Session {
    char username[DN_LENGTH+1];
    char session_id[SID_LENGTH+1];
    char session_key[SYM_KEY_LENGTH];
};

struct Session global_session;


/* TYPE 0
 * A user is requesting to start a session
 */
int handle0(int sock, char *buffer, unsigned int buffer_size)
{
    int decrypted_size = 0;

    MessageType0 *msg = (MessageType0*)pgp_decrypt(buffer, buffer_size,
                                                   sizeof(MessageType0),
                                                   &decrypted_size);

    if (!msg_ok(TYPE0, decrypted_size, msg, sock, 1)) {
        printf("WELL THAT WAS EXPECTED\n");
        return -1;
    }

    printf("Requesting User: %s\n", msg->distinguishedName);
    establish_session(sock, msg->distinguishedName);

    free(msg);
    return 0;
}


/* TYPE 1
 * Generate a session ID for the connecting user and send it to them.
 */
void establish_session(int sock, char const *username)
{
    printf("Sending type 1; Username: %s\n", username);
    MessageType1 response = initsidtype(1);

    char random_id[SID_LENGTH];
    for (int i = 0; i < SID_LENGTH; i += sizeof(long int))
        *(random_id+i) = random();

    for (int i = 0; i < SID_LENGTH; i++)
        random_id[i] = (random_id[i] & 0x3f) + 'A';

    // Save the SID
    safe_sid_copy(response.sessionId, random_id);

    // Save the username
    unsigned int un_len = strnlen(username, DN_LENGTH);
    strncpy(global_session.username, username, un_len);
    global_session.username[un_len] = 0;

    // Generate session, save, and put in message
    char *session_key = gen_symmetric_key(SYM_KEY_LENGTH);
    memcpy(global_session.session_key, session_key, SYM_KEY_LENGTH);
    memcpy(response.symmetricKey, session_key, SYM_KEY_LENGTH);

    memset(session_key, 0, SYM_KEY_LENGTH);
    munlock(session_key, SYM_KEY_LENGTH);
    free(session_key);

    printf("Session ID: %s\n", response.sessionId);
    char *enc_buffer = NULL;
    int length = pgp_encrypt((char*)&response, sizeof(response), &enc_buffer);

    nn_send(sock, enc_buffer, length, 0);
}


/* TYPE 2
 * Send a NULL terminated length-limited error message to the client.
 *
 * Returns: Results of nn_send
 */
int send_error(int sock, char *error_text, int phase)
{
    printf("Sending Type 2 Message (phase: %d): %s\n", phase, error_text);

    MessageType2 err_msg = initmsgtype(2);
    err_msg.msgLength = strnlen(ERR_MSG, MAX_ERROR_MESSAGE);
    strncpy(err_msg.errorMessage, ERR_MSG, MAX_ERROR_MESSAGE);
    err_msg.errorMessage[MAX_ERROR_MESSAGE] = 0;

    char *enc_buffer = NULL;
    int length = 0;

    if (phase == 1) {
        length = pgp_encrypt((char*)&err_msg, sizeof(err_msg), &enc_buffer);
    } else if (phase == 2) {
        length = sym_encrypt((char*)&err_msg, sizeof(err_msg),
                             &enc_buffer, global_session.session_key);
    }

    int res = nn_send(sock, enc_buffer, length, 0);

    free(enc_buffer);

    return res;
}


/*
 * A user is requesting a file
 */
void handle3(int sock, char *buffer, unsigned int buffer_size)
{
    printf("Handling 3\n");
    int bytes_decrypted = 0;
    MessageType3 *msg = (MessageType3*)sym_decrypt(buffer, buffer_size,
                                                   sizeof(MessageType3),
                                                   global_session.session_key,
                                                   &bytes_decrypted);

    // NOTE TO ANDREW: Does this stuff just happen in msg_ok though?
    if (msg->sidLength != SID_LENGTH || msg->sessionId[SID_LENGTH] != 0) {
        send_error(sock, "Invalid session id.", 2);
        return;
    } else {
        printf("Session id: %s\n", msg->sessionId);
        printf("Path: %s\n", msg->pathName);

        //TODO: Assert that the session ID matches and userID matches
        char *username = global_session.username;
        printf("User: %s\n", username);
        if (check_acl_access(msg->pathName, username) == 1) {
            file_transfer(sock, msg->sessionId, msg->pathName);
        } else {
            send_error(sock, "Access to file denied.", 2);
        }
    }
}


/* TYPE 5
 * End the session with the client
 */
void end_session(int sock, char const *session_id)
{
    char *enc_buffer = NULL;
    int length = 0;

    MessageType5 response = initsidtype(5);
    safe_sid_copy(response.sessionId, session_id);

    length = sym_encrypt((char*)&response, sizeof(response),
                         &enc_buffer, global_session.session_key);

    nn_send(sock, enc_buffer, length, 0);
}


/*
 * User is sending ACK of a type 4 (file send) message.
 * TODO: Validate the session id
 */
int expect_ack(int sock, char const *session_id)
{
    printf("Expecting an ack\n");
    //MessageType6 *buffer = NULL;

    char buffer[MAX_BUFFER_SIZE];
    memset(buffer, 0, MAX_BUFFER_SIZE);

    int bytes_read = nn_recv(sock, &buffer, MAX_BUFFER_SIZE, 0);
    //if (bytes_read != sizeof(MessageType6)) {
    //    send_error(sock, "Invalid ACK (message type 6) session id!");
    //    return 0;
    //}

    int decrypted_size = 0;
    char *decrypted_data = sym_decrypt(buffer, bytes_read,
                                       MAX_BUFFER_SIZE,
                                       global_session.session_key,
                                       &decrypted_size);

    if (!msg_ok(TYPE6, decrypted_size, decrypted_data, sock, 2))
        return 0;

    printf("Ack sid: %s\n", ((MessageType6*)decrypted_data)->sessionId);

    free(decrypted_data);

    return 1;
}


/*
 * Send chuncks of the file to the client
 */
void file_transfer(int sock, char *session_id, char *path)
{
    printf("beginning file transfer\n");
    MessageType4 response = initsidtype(4);
    safe_sid_copy(response.sessionId, session_id);

    char *enc_buffer = NULL;
    int length = 0;

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

        length = sym_encrypt((char*)&response, sizeof(response),
                             &enc_buffer, global_session.session_key);

        nn_send(sock, enc_buffer, length, 0);

        free(enc_buffer);

        if (expect_ack(sock, session_id) == 0) {
            return;
        }
    }

    end_session(sock, session_id);
    expect_ack(sock, session_id);
}


/*
 * Runs all validation checks for received messages
 * Should flag any non-conformant message
 * Does not verify contents of strings
 */
int msg_ok(char expect,int bytes_read,void * buffer, int sock, int phase)
{
    //printf("bufaddr: %p\n", buffer);

    Header *msg_header;
        //check that the message wasn't empty somehow
    if (bytes_read <= 0) {
        msg_header = (Header*)buffer;
        err_quit("Error: %s", nn_strerror(errno));
        //check that at least a full header was read
    } else if (bytes_read <= sizeof(Header)) {
        send_error(sock, "Invalid message length: could not read header", phase);
        return 0;
    } else {
        msg_header = (Header*)buffer;

        printf("Bytes read: %d\n", bytes_read);
        printf("Message type: %d\n", msg_header->messageType);
        printf("Message size: %d\n", msg_header->messageLength);
    }
/********************************************************/
    printf("sizeof(buffer): %d\n", strlen((char*)buffer) );
    printf("bytes_read: %d\n", bytes_read);
    printf("msg_header->messageLength: %d\n", msg_header->messageLength);
    printf("sizeof(MessageType0): %d\n", sizeof(MessageType0));
/*******************************************************/
        //check actual message size against reported
    if (bytes_read != msg_header->messageLength) {
        send_error(sock, "Malformed message header", phase);
        return 0;
    }
        //check expected message type against reported
    if (expect != msg_header->messageType) {
        if (msg_header->messageType != TYPE2) {
            send_error(sock, "unexpected message type received", phase);
            return 0;
        }
    }
        //handle each message type
    switch (msg_header->messageType) {
        case TYPE0:
                //check actual message size against correct message size
            if (sizeof(MessageType0) != bytes_read) {
                send_error(sock, "Malformed Message: invalid message length for TYPE0", phase);
                return 0;
            } else {
                MessageType0 *msg = (MessageType0*)buffer;
                    //check reported distinguishes name length within bounds
                if (msg->dnLength <= 0 || msg->dnLength > DN_LENGTH) {
                    send_error(sock, "Malformed Message: invalid distinguished name length", phase);
                    return 0;
                    //check reported distinguished name length against actual distinguished name length
                } else if(msg->dnLength != strnlen(msg->distinguishedName, DN_LENGTH+1)) {
                    send_error(sock, "Malformed Message: distinguished name length does not match", phase);
                    return 0;
                }
            }
            break;
        case TYPE2:
                //check actual message size against correct message size
            if (sizeof(MessageType2) != bytes_read) {
                send_error(sock, "Malformed Message: invalid message length for TYPE2", phase);
                return 0;
            } else {
                MessageType2 *msg = (MessageType2*)buffer;
                    //check reported error message length within bounds
                if (msg->msgLength <= 0 || msg->msgLength > MAX_ERROR_MESSAGE) {
                    send_error(sock, "Malformed Message: invalid error message length", phase);
                    return 0;
                    //check reported error message length against actual error message length
                } else if(msg->msgLength != strnlen(msg->errorMessage, MAX_ERROR_MESSAGE+1)) {
                    send_error(sock, "Malformed Message: error message length does not match", phase);
                    return 0;
                } else { //print error message
                    printf("Received type 2 message:%s\n", msg->errorMessage);
                    return 0;
                }
            }
            break;
        case TYPE3:
                //check actual message size against correct message size
            if (sizeof(MessageType3) != bytes_read) {
                send_error(sock, "Malformed Message: invalid message length for TYPE3", phase);
                return 0;
            } else {
                MessageType3 *msg = (MessageType3*)buffer;
                    //check reported sid length and path length within bounds
                if (msg->sidLength <= 0 || msg->sidLength > SID_LENGTH ||
                      msg->pathLength <= 0 || msg->pathLength > PATH_MAX) {
                    send_error(sock, "Malformed Message: invalid sid/path length", phase);
                    return 0;
                    //check reported sid and path length against actual sid and path length
                } else if(msg->sidLength != strnlen(msg->sessionId, SID_LENGTH+1) ||
                            msg->pathLength != strnlen(msg->pathName, PATH_MAX+1)) {
                    send_error(sock, "Malformed Message: sid/path length does not match", phase);
                    return 0;
                    //check if sid is valid
                } else if(strcmp(global_session.session_id, msg->sessionId) != 0) {
                    send_error(sock, "T3: Invalid session id", phase);
                }
            }
            break;
        case TYPE6:
                //check actual message size against correct message size
            if (sizeof(MessageType6) != bytes_read) {
                send_error(sock, "Malformed Message: invalid message length for TYPE6", phase);
                return 0;
            } else {
                MessageType6 *msg = (MessageType6*)buffer;
                    //check reported sid length within bounds
                if (msg->sidLength <= 0 || msg->sidLength > SID_LENGTH) {
                    send_error(sock, "Malformed Message: invalid sid length", phase);
                    return 0;
                    //check reported sid length against actual sid length
                } else if(msg->sidLength != strnlen(msg->sessionId, SID_LENGTH+1)) {
                    send_error(sock, "Malformed Message: sid length does not match", phase);
                    return 0;
                    //check if sid is valid
                } else if(strcmp(global_session.session_id, msg->sessionId) != 0) {
                    send_error(sock, "T6: Invalid session id", phase);
                }

                //test
            }
            break;
        default: //should never be reached, but just in case
            send_error(sock, "Unexpected Message Type", phase);
            return 0;
            break;
    }
    return 1;
}


void server_loop(int sock)
{
    int bytes_read = 0;
    char expect = TYPE0;

    //char buffer[MAX_BUFFER_SIZE];

    while(1) {
        //memset(buffer, 0, MAX_BUFFER_SIZE);
        void *buffer = NULL;
        int ret = 0;

        printf("Receiving\n");
        bytes_read = nn_recv(sock, &buffer, NN_MSG, 0);
        //bytes_read = nn_recv(sock, &buffer, MAX_BUFFER_SIZE, 0);

        if (bytes_read <= 0)
            err_quit("Error: %s", nn_strerror(errno));

        switch(expect) {
            case TYPE0:
                ret = handle0(sock, (char*)buffer, bytes_read);
                if (ret < 0) {
                    expect = TYPE0;
                } else {
                    expect = TYPE3;
                }
                break;
            case TYPE3:
                handle3(sock, (char*)buffer, bytes_read);
                expect = TYPE0;
                //TODO: END THE SESSION
                break;
            default:
                break;
        }

        /*
        if (!msg_ok(expect, bytes_read, buffer, sock)) {
            //printf("!!!!335!!!!\n");
            expect = TYPE0;
            freeHashMap(sessions, free);
            sessions = initHashMap(20, NULL);
            //nn_freemsg(buffer);
            continue;
        }
        */

        nn_freemsg(buffer);
    }
}


int main(int argc, char *argv[])
{
    // Limit coredump file sizes to 0 so that we don't leak any important info.
    struct rlimit core_limit = {.rlim_cur=0, .rlim_max=0};
    setrlimit(RLIMIT_CORE, &core_limit);

    // Initialize crypt lib
    cryptInit();
    int ret = cryptAddRandom(NULL, CRYPT_RANDOM_SLOWPOLL);
    checkCryptNormal(ret, "cryptAddRandom", __LINE__);

    // Seed the session id prng
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    srandom((unsigned int)ts.tv_nsec);

    // Create a nn_socket
    int sock = nn_socket(AF_SP, NN_PAIR);
    if (sock < 0)
        err_quit("Couldn't build a socket");

    if (nn_bind(sock, "ipc:///tmp/sgetd.ipc") < 0)
        err_quit("We've got an error yo.");

    server_loop(sock);

    // Clean up after ourselves
    nn_shutdown(sock, 0);

    return 0;
}
