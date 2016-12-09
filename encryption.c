#define _XOPEN_SOURCE 700

#include <stdlib.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <termios.h>
#include <string.h>

#include "cryptlib.h"

#include "apue.h"
#include "message.h"
#include "encryption.h"
#include <unistd.h>


#define SYMMETRIC_ALG CRYPT_ALGO_BLOWFISH
#define ccall(func, ...) ret = func(__VA_ARGS__);\
                         checkCryptNormal(ret, #func, __LINE__)


static char GPG_SEC[] = "/.gnupg/secring.gpg";
static char GPG_PUB[] = "/.gnupg/pubring.gpg";


/*
 * Generates a unique random key for use with symmetric key encryption.
 * This function also locks the section of memory from swapping out the where
 * the key resides.
 * Returns: Pointer to the key on the heap
 */
char * gen_symmetric_key(unsigned int length) {
    unsigned int total = 0;
    unsigned int bytes_read = 0;

    char *key = malloc(length);
    /*// To demonstrate that a str* function is in use on the client
    memset(key, 1, length);
    key[4] = 0;
    */
    if (key == NULL)
        err_sys("Could not allocate space for symmetric key on heap");

    if (mlock(key, length) < 0)
        err_sys("Could not lock private session encryption key in memory");

    int urand_fd = open("/dev/urandom", O_RDONLY);
    if (urand_fd == -1) err_sys("Could not open /dev/urandom for entropy");

    while (total < length) {
        bytes_read = read(urand_fd, &key[total], length - total);
        total += bytes_read;
    }

    // Make sure the key has no nulls in it (to account for client issues)
    for (int i = 0; i < length; i++) {
        if (key[i] == 0)
            key[i] = 1;
    }

    close(urand_fd);

    return key;
}


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
    int ret = 0;
    struct passwd *user_info = getpwuid(getuid());
    char *keyring_file = malloc(strlen(user_info->pw_dir) + strlen(file) + 1);
    strcpy(keyring_file, user_info->pw_dir);
    strcat(keyring_file, file);
    printf("Reading keyring from: <%s>\n", keyring_file);

    ccall(cryptKeysetOpen, keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
                              keyring_file, CRYPT_KEYOPT_READONLY);

    free(keyring_file);
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
    //char *recipient = "vagrant";
    char *recipient = calloc(sizeof(char), 129);
    ret = getlogin_r(recipient, 128);
    if (ret < 0) {
        printf("Could not get server userid");
        exit(100);
    }
    //printf("%s\n", recip);
    unsigned int recipient_len = strlen(recipient);

    // Open the keyset
    open_keyset(GPG_PUB, &keyset);

    // Create an envelope
    ccall(cryptCreateEnvelope, &data_envelope, CRYPT_UNUSED, CRYPT_FORMAT_PGP);

    // Set the keyset for the envelope
    ccall(cryptSetAttribute, data_envelope, CRYPT_ENVINFO_KEYSET_ENCRYPT, keyset);

    // Pick the pub key to use
    ret = cryptSetAttributeString(data_envelope, CRYPT_ENVINFO_RECIPIENT,
                                  recipient, recipient_len);
    checkCryptNormal(ret, "cryptSetAttributeString", __LINE__);

    // Set envelope data size and push data
    ret = cryptSetAttribute(data_envelope, CRYPT_ENVINFO_DATASIZE, size);
    ccall(cryptPushData, data_envelope, buffer, size, &bytes_copied);

    // Flush the data
    ccall(cryptFlushData, data_envelope);

    int enc_size = size+291+1024;
    *enc_data = malloc(enc_size);
    if (*enc_data == NULL)
        err_sys("malloc error line %d", __LINE__);

    ccall(cryptPopData, data_envelope, *enc_data, enc_size, &bytes_copied);
    ccall(cryptDestroyEnvelope, data_envelope);
    ccall(cryptKeysetClose, keyset);

    return bytes_copied;
}


/*
 * Decrypts the initial request sent from the client. (via pub key crypto)
 * Returns: pointer to decrypted data
 */
char * pgp_decrypt(char *enc_buffer, int data_size, int expect_size,
                   int *bytes_decrypted) {
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
    cryptPushData(data_envelope, enc_buffer, data_size, &bytes_copied);
    int req_attrib = 0;
    ret = cryptGetAttribute(data_envelope, CRYPT_ATTRIBUTE_CURRENT, &req_attrib);
    if (req_attrib != CRYPT_ENVINFO_PRIVATEKEY)
        err_quit("Decrypt error");

    // TODO: Put the actual passphrase here for testing
    // TODO: DON'T LEAVE THIS HERE FOR PRODUCTION
    // TODO: Use a prompt for the password
    char pass[100];
    int pLen = getPassword(pass, 100);
    printf("%s : %d\n", pass, pLen);

    ret = cryptSetAttributeString(data_envelope, CRYPT_ENVINFO_PASSWORD,
                                  pass, pLen);
    int i;
    for (i = 0; i < pLen; i++) {
        pass[i] = '\0';
    }

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
    cryptPopData(data_envelope, cleartext, expect_size, bytes_decrypted);
    printf("Decrypted size: %d\n", *bytes_decrypted);

    // Time to wrap up
    cryptDestroyEnvelope(data_envelope);
    cryptKeysetClose(keyset);

    return cleartext;
}


/*
 * Returns: size of encrypted data
 */
int sym_encrypt(char *buffer, unsigned int size, char **enc_data, char *key) {
    int ret = 0;
    int bytes_copied = 0;
    CRYPT_ENVELOPE data_envelope;
    CRYPT_CONTEXT symmetric_context;

    // Create an envelope
    ret = cryptCreateEnvelope(&data_envelope, CRYPT_UNUSED,
                              CRYPT_FORMAT_CRYPTLIB);
    checkCryptNormal(ret, "cryptCreateEnvelope", __LINE__);

    // Initialize symmetric encryption context
    ccall(cryptCreateContext, &symmetric_context, CRYPT_UNUSED, SYMMETRIC_ALG);

    // Load the session encryption key into the context
    ccall(cryptSetAttributeString, symmetric_context, CRYPT_CTXINFO_KEY,
          key, SYM_KEY_LENGTH);

    // Load the context to the envelope
    ccall(cryptSetAttribute, data_envelope, CRYPT_ENVINFO_SESSIONKEY,
            symmetric_context);

    // Destroy the context
    ccall(cryptDestroyContext, symmetric_context);

    // Prep and push the data in to the envelope
    ccall(cryptSetAttribute, data_envelope, CRYPT_ENVINFO_DATASIZE, size);

    ccall(cryptPushData, data_envelope, buffer, size, &bytes_copied);
    ccall(cryptFlushData, data_envelope);

    // Make space for the encrypted data and pop it out
    unsigned int enc_size = size + 2048;
    *enc_data = malloc(enc_size);
    if (*enc_data == NULL)
        err_sys("malloc error line %d", __LINE__);

    ccall(cryptPopData, data_envelope, *enc_data, enc_size, &bytes_copied);

    // Destroy the envelope
    ccall(cryptDestroyEnvelope, data_envelope);

    return bytes_copied;
}


/*
 * Used for decrypting session messages
 */
char * sym_decrypt(char *enc_buffer, int data_size, int expect_size, char *key)
{
    int ret = 0;
    int bytes_copied = 0;
    CRYPT_ENVELOPE data_envelope;
    CRYPT_CONTEXT sym_context;

    ccall(cryptCreateEnvelope, &data_envelope, CRYPT_UNUSED, CRYPT_FORMAT_AUTO);

    cryptPushData(data_envelope, enc_buffer, data_size, &bytes_copied);

    ccall(cryptCreateContext, &sym_context, CRYPT_UNUSED, SYMMETRIC_ALG);

    ccall(cryptSetAttributeString, sym_context, CRYPT_CTXINFO_KEY,
          key, SYM_KEY_LENGTH);
    ccall(cryptSetAttribute, data_envelope, CRYPT_ENVINFO_SESSIONKEY, sym_context);

    ccall(cryptDestroyContext, sym_context);
    ret = cryptFlushData(data_envelope);
    printf("Sym decrypt flush returend: %d\n", ret);

    char *cleartext = malloc(expect_size);
    ccall(cryptPopData, data_envelope, cleartext, expect_size, &bytes_copied);

    ccall(cryptDestroyEnvelope, data_envelope);

    return cleartext;
}


/*
 * Used to read in a pass phrase
 */
int getPassword(char* password, int size)
{
    static struct termios oldt, newt;
    int i = 0;
    //int c;
    printf("Enter private key pass phrase: ");
    /*saving the old settings of STDIN_FILENO and copy settings for resetting*/
    tcgetattr( STDIN_FILENO, &oldt);
    newt = oldt;

    /*setting the approriate bit in the termios struct*/
    newt.c_lflag &= ~(ECHO);

    /*setting the new bits*/
    tcsetattr( STDIN_FILENO, TCSANOW, &newt);

    /*reading the password from the console*/
    //while ((c = getchar())!= '\n' && c != EOF && i < SIZE){
    //    password[i++] = c;
    //}
    fgets(password, size, stdin);
    i = strnlen(password, size);
    password[i-1] = '\0';

    /*resetting our old STDIN_FILENO*/
    tcsetattr( STDIN_FILENO, TCSANOW, &oldt);

    printf("\n");

    return i-1;
}
