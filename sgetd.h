#ifndef _SGETD_H_
#define _SGETD_H_

#define MAX_BUFFER_SIZE 5120

int handle0(int sock, char *buffer, unsigned int buffer_size);
void establish_session(int sock, char const *username);
int send_error(int sock, char *error_text, int phase);
void end_session(int sock, char const *session_id);
int expect_ack(int sock, char const *session_id);
void handle3(int sock, char *buffer, unsigned int buffer_size);
void file_transfer(int sock, char *session_id, char *path);
int msg_ok(char expect, int bytes_read, void * buffer, int sock);
void clean_buffer(char *buffer, int size);


#endif
