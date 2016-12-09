#ifndef _ENCRYPTION_H
#define _ENCRYPTION_H

// This is for the type CRYPT_KEYSET
#include "cryptlib.h"


char * gen_symmetric_key(unsigned int length);

void checkCryptNormal(int returnCode, char *routineName, int line);

void open_keyset(char *file, CRYPT_KEYSET *keyset);

int pgp_encrypt(char *buffer, unsigned int size, char **enc_data);
char * pgp_decrypt(char *enc_buffer, int data_size, int expect_size);

int sym_encrypt(char *buffer, unsigned int size, char **enc_data, char *key);
char * sym_decrypt(char *enc_buffer, int data_size, int expect_size, char *key);

int getPassword(char* password, int size);

#endif
