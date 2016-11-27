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

#include "apue.h"
#include "jlibc/hashmap/hashmap.h"
#include "message.h"
#include "acl.h"
#include "util.h"

#include "cryptlib.h"

// This is used so that functions can be ordered more logically
#include "sgetd.h"

#define initmsgtype(N) {.header.messageType = N,\
                        .header.messageLength = sizeof(MessageType ## N)}
#define initsidtype(N) {.header.messageType = N,\
                        .header.messageLength = sizeof(MessageType ## N),\
                        .sidLength=SID_LENGTH}
#define sendtype(N, sock, obj) nn_send(sock, obj, sizeof(MessageType ## N), 0)

static char GPG_SEC[] = "/.gnupg/secring.gpg";
static char GPG_PUB[] = "/.gnupg/pubring.gpg";

HashMap *sessions;

struct Session {
    char username[DN_LENGTH+1];
    char session_key[SYM_KEY_LENGTH];
};


/*
 * Error handler wrapper for cryptlib functions. Borrowed from gpgEncDec.c
 * example.
 */
void checkCryptNormal(int returnCode, char *routineName, int line){
    if (cryptStatusError(returnCode)){
        printf("Error in %s at line %d, return value %d\n",
               routineName, line, returnCode);
        exit(returnCode);
    }
}


/*
 * Abstraction around opening cryptlib keysets from a given file
 */
void open_keyset(char *file, CRYPT_KEYSET *keyset) {
    struct passwd *user_info = getpwuid(getuid());
    char *keyring_file = malloc(strlen(user_info->pw_dir) + strlen(file) + 1);
    strcpy(keyring_file, user_info->pw_dir);
    strcat(keyring_file, file);
    printf("Reading keyring from: <%s>\n", keyring_file);

    int ret = cryptKeysetOpen(keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
                              keyring_file, CRYPT_KEYOPT_READONLY);
    checkCryptNormal(ret,"cryptKeysetOpen",__LINE__);

    free(keyring_file);
}


/*
 * Decrypts the initial request sent from the client. (via pub key crypto)
 * Returns: pointer to decrypted data
 */
char * pgp_decrypt(char *encrypted_buffer, int data_size, int expect_size) {
    printf("Data size: %d Decrypted size: %d Type0 size: %d\n",
           data_size, data_size-1028-1, sizeof(MessageType0));

    int ret = 0;
    int bytes_copied = 0;
    CRYPT_KEYSET keyset;
    CRYPT_ENVELOPE data_envelope;

    // Open the keyset
    open_keyset(GPG_SEC, &keyset);

    // Create envelope
    ret = cryptCreateEnvelope(&data_envelope, CRYPT_UNUSED, CRYPT_FORMAT_AUTO);
    checkCryptNormal(ret,"cryptCreateEnvelope",__LINE__);

    // Set the keyset for the envelope
    ret = cryptSetAttribute(data_envelope, CRYPT_ENVINFO_KEYSET_DECRYPT, keyset);
    checkCryptNormal(ret,"cryptSetAttribute",__LINE__);

    // Put data in the envelope
    cryptPushData(data_envelope, encrypted_buffer, data_size, &bytes_copied);
    int req_attrib = 0;
    ret = cryptGetAttribute(data_envelope, CRYPT_ATTRIBUTE_CURRENT, &req_attrib);
    if (req_attrib != CRYPT_ENVINFO_PRIVATEKEY)
        err_quit("Decrypt error");

    // TODO: Put the actual passphrase here for testing
    // TODO: DON'T LEAVE THIS HERE FOR PRODUCTION
    ret = cryptSetAttributeString(data_envelope, CRYPT_ENVINFO_PASSWORD,
                                  "", 0);
    if (ret != CRYPT_OK) {
        if (ret == CRYPT_ERROR_WRONGKEY)
            err_quit("Wrong key");
        else
            err_quit("cryptSetAttributeString line %d returned <%d>\n",
                     __LINE__, ret);
    }

    ret = cryptFlushData(data_envelope);
    checkCryptNormal(ret, "cryptFlushData", __LINE__);

    char *cleartext = malloc(expect_size);

    // Pull out the clear text
    cryptPopData(data_envelope, cleartext, expect_size, &bytes_copied);
    printf("Decrypted size: %d\n", bytes_copied);

    // Time to wrap up
    cryptDestroyEnvelope(data_envelope);
    cryptKeysetClose(keyset);

    return cleartext;
}


/*
 * Does pubkey encryption used for the initial respons to the client.
 * Returns: length of encrypted data
 */
int pgp_encrypt(char *buffer, unsigned int size, char **enc_data) {
    int ret = 0;
    int bytes_copied = 0;
    CRYPT_KEYSET keyset;
    CRYPT_ENVELOPE data_envelope;
    // TODO: This is fine for testing, but needs to be fixed for prod
    char *recipient = "vagrant";
    unsigned int recipient_len = strlen(recipient);

    // Open the keyset
    open_keyset(GPG_PUB, &keyset);

    // Create an envelope
    ret = cryptCreateEnvelope(&data_envelope, CRYPT_UNUSED, CRYPT_FORMAT_PGP);
    checkCryptNormal(ret, "cryptCreateEnvelope", __LINE__);

    // Set the keyset for the envelope
    ret = cryptSetAttribute(data_envelope, CRYPT_ENVINFO_KEYSET_ENCRYPT, keyset);
    checkCryptNormal(ret, "cryptSetAttribute", __LINE__);


    // Pick the pub key to use
    ret = cryptSetAttributeString(data_envelope, CRYPT_ENVINFO_RECIPIENT,
                                  recipient, recipient_len);
    checkCryptNormal(ret, "cryptSetAttributeString", __LINE__);

    // Set envelope data size and push data
    ret = cryptSetAttribute(data_envelope, CRYPT_ENVINFO_DATASIZE, size);
    ret = cryptPushData(data_envelope, buffer, size, &bytes_copied);
    checkCryptNormal(ret, "cryptPushData", __LINE__);

    // Flush the data
    ret = cryptFlushData(data_envelope);
    checkCryptNormal(ret, "cryptFlushData", __LINE__);

    int enc_size = size+291+1024;
    *enc_data = malloc(enc_size);
    if (*enc_data == NULL)
        err_sys("malloc error line %d", __LINE__);

    ret = cryptPopData(data_envelope, *enc_data, enc_size, &bytes_copied);
    enc_size = bytes_copied;

    ret = cryptDestroyEnvelope(data_envelope);
    checkCryptNormal(ret, "cryptDestroyEnvelope", __LINE__);
    cryptKeysetClose(keyset);
    checkCryptNormal(ret, "cryptKeysetClose", __LINE__);

    return enc_size;
}


/* TYPE 0
 * A user is requesting to start a session
 */
void handle0(int sock, MessageType0 *buffer)
{
    printf("Requesting User: %s\n", buffer->distinguishedName);
    establish_session(sock, buffer->distinguishedName);
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

    safe_sid_copy(response.sessionId, random_id);

    struct Session *sess = malloc(sizeof(*sess));

    unsigned int un_len = strnlen(username, DN_LENGTH);
    strncpy(sess->username, username, un_len);
    sess->username[un_len] = 0;

    char *session_key = gen_symmetric_key(SYM_KEY_LENGTH);
    memcpy(sess->session_key, session_key, SYM_KEY_LENGTH);

    memset(session_key, 0, SYM_KEY_LENGTH);
    munlock(session_key, SYM_KEY_LENGTH);
    free(session_key);

    // Using response.sessionId because this one will be properly null
    // terminated from using safe_sid_copy.
    putElement(sessions, response.sessionId, sess);

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
int send_error(int sock, char *error_text)
{
    printf("Sending Type 2 Message: %s\n", error_text);

    MessageType2 err_msg = initmsgtype(2);
    err_msg.msgLength = strnlen(error_text, MAX_ERROR_MESSAGE);
    strncpy(err_msg.errorMessage, error_text, MAX_ERROR_MESSAGE);
    err_msg.errorMessage[MAX_ERROR_MESSAGE] = 0;

    return sendtype(2, sock, &err_msg);
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

        char *username = (char*)getElement(sessions, buffer->sessionId);

        printf("User: %s\n", username);
        if (check_acl_access(buffer->pathName, username) == 1) {
            file_transfer(sock, buffer->sessionId, buffer->pathName);
        } else {
            send_error(sock, "Access to file denied.");
        }
    }
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


    if (!msg_ok(TYPE6, bytes_read, buffer, sock)) {
        //printf("!!!!173!!!!\n");
        freeHashMap(sessions, free);
        sessions = initHashMap(20, NULL);
        return 0;
    }

    printf("Ack sid: %s\n", ((MessageType6*)buffer)->sessionId);
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
int msg_ok(char expect,int bytes_read,void * buffer, int sock)
{
    //printf("bufaddr: %p\n", buffer);

    Header *msg_header;
        //check that the message wasn't empty somehow
    if (bytes_read <= 0) {
        msg_header = (Header*)buffer;
        err_quit("Error: %s", nn_strerror(errno));
        //check that at least a full header was read
    } else if (bytes_read <= sizeof(Header)) {
        send_error(sock, "Invalid message length: could not read header");
        return 0;
    } else {
        msg_header = (Header*)buffer;

        printf("Bytes read: %d\n", bytes_read);
        printf("Message type: %d\n", msg_header->messageType);
        printf("Message size: %d\n", msg_header->messageLength);
    }
        //check actual message size against reported
    if (bytes_read != msg_header->messageLength) {
        send_error(sock, "Malformed message header");
        return 0;
    }
        //check expected message type against reported
    if (expect != msg_header->messageType) {
        if (msg_header->messageType != TYPE2) {
            send_error(sock, "unexpected message type received");
            return 0;
        }
    }
        //handle each message type
    switch (msg_header->messageType) {
        case TYPE0:
                //check actual message size against correct message size
            if (sizeof(MessageType0) != bytes_read) {
                send_error(sock, "Malformed Message: invalid message length for TYPE0");
                return 0;
            } else {
                MessageType0 *msg = (MessageType0*)buffer;
                    //check reported distinguishes name length within bounds
                if (msg->dnLength <= 0 || msg->dnLength > DN_LENGTH) {
                    send_error(sock, "Malformed Message: invalid distinguished name length");
                    return 0;
                    //check reported distinguished name length against actual distinguished name length
                } else if(msg->dnLength != strnlen(msg->distinguishedName, DN_LENGTH+1)) {
                    send_error(sock, "Malformed Message: distinguished name length does not match");
                    return 0;
                }
            }
            break;
        case TYPE2:
                //check actual message size against correct message size
            if (sizeof(MessageType2) != bytes_read) {
                send_error(sock, "Malformed Message: invalid message length for TYPE2");
                return 0;
            } else {
                MessageType2 *msg = (MessageType2*)buffer;
                    //check reported error message length within bounds
                if (msg->msgLength <= 0 || msg->msgLength > MAX_ERROR_MESSAGE) {
                    send_error(sock, "Malformed Message: invalid error message length");
                    return 0;
                    //check reported error message length against actual error message length
                } else if(msg->msgLength != strnlen(msg->errorMessage, MAX_ERROR_MESSAGE+1)) {
                    send_error(sock, "Malformed Message: error message length does not match");
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
                send_error(sock, "Malformed Message: invalid message length for TYPE3");
                return 0;
            } else {
                MessageType3 *msg = (MessageType3*)buffer;
                    //check reported sid length and path length within bounds
                if (msg->sidLength <= 0 || msg->sidLength > SID_LENGTH ||
                      msg->pathLength <= 0 || msg->pathLength > PATH_MAX) {
                    send_error(sock, "Malformed Message: invalid sid/path length");
                    return 0;
                    //check reported sid and path length against actual sid and path length
                } else if(msg->sidLength != strnlen(msg->sessionId, SID_LENGTH+1) ||
                            msg->pathLength != strnlen(msg->pathName, PATH_MAX+1)) {
                    send_error(sock, "Malformed Message: sid/path length does not match");
                    return 0;
                    //check if sid is valid
                } else if(getElement(sessions, msg->sessionId) == NULL) {
                    send_error(sock, "T3: Invalid session id");
                }
            }
            break;
        case TYPE6:
                //check actual message size against correct message size
            if (sizeof(MessageType6) != bytes_read) {
                send_error(sock, "Malformed Message: invalid message length for TYPE6");
                return 0;
            } else {
                MessageType6 *msg = (MessageType6*)buffer;
                    //check reported sid length within bounds
                if (msg->sidLength <= 0 || msg->sidLength > SID_LENGTH) {
                    send_error(sock, "Malformed Message: invalid sid length");
                    return 0;
                    //check reported sid length against actual sid length
                } else if(msg->sidLength != strnlen(msg->sessionId, SID_LENGTH+1)) {
                    send_error(sock, "Malformed Message: sid length does not match");
                    return 0;
                    //check if sid is valid
                } else if(getElement(sessions, msg->sessionId) == NULL) {
                    send_error(sock, "T6: Invalid session id");
                }
                //test
            }
            break;
        default: //should never be reached, but just in case
            send_error(sock, "Unexpected Message Type");
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
        void *data = NULL;
        Header *msg_header;

        printf("receiving\n");
        bytes_read = nn_recv(sock, &data, NN_MSG, 0);

        char *buffer = pgp_decrypt((char*) data,
                                   bytes_read,
                                   sizeof(MessageType0));

        //bytes_read = nn_recv(sock, &buffer, MAX_BUFFER_SIZE, 0);

        //if (bytes_read > 0) {
        //    msg_header = (Header*)buffer;

        //    printf("Bytes read: %d\n", bytes_read);
        //    printf("Message type: %d\n", msg_header->messageType);
        //    printf("Message size: %d\n", msg_header->messageLength);
        //} else {
        //    err_quit("Error: %s", nn_strerror(errno));
        //}

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

        msg_header = (Header*)buffer;

        switch(msg_header->messageType) {
            case TYPE0:
                handle0(sock, (MessageType0*)buffer);
                expect = TYPE3;
                break;
            case TYPE3:
                handle3(sock, (MessageType3*)buffer);
                expect = TYPE0;
                freeHashMap(sessions, free);
                sessions = initHashMap(20, NULL);
                break;
            default:
                break;
        }

        //printf("!!!!356!!!!\n");

        //nn_freemsg(buffer);
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

    // Initialize sessions hashmap
    sessions = initHashMap(20, NULL);

    // Create a nn_socket
    int sock = nn_socket(AF_SP, NN_PAIR);
    if (sock < 0)
        err_quit("Couldn't build a socket");

    if (nn_bind(sock, "ipc:///tmp/sgetd.ipc") < 0)
        err_quit("We've got an error yo.");

    server_loop(sock);

    // Clean up after ourselves
    nn_shutdown(sock, 0);

    freeHashMap(sessions, free);

    return 0;
}
