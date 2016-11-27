#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <fcntl.h>

#include "apue.h"
#include "message.h"
#include "util.h"

/*
 * Generates a unique random key for use with symmetric key encryption.
 * This function also locks the section of memory from swapping out the where
 * the key resides.
 * Returns: Pointer to the key on the heap
 */
char * gen_symmetric_key() {
    unsigned int total = 0;
    unsigned int bytes_read = 0;

    char *key = malloc(SYM_KEY_LENGTH);
    if (key == NULL)
        err_sys("Could not allocate space for symmetric key on heap");

    if (mlock(key, SYM_KEY_LENGTH) < 0)
        err_sys("Could not lock private session encryption key in memory");

    int urand_fd = open("/dev/urandom", O_RDONLY);
    if (urand_fd == -1) err_sys("Could not open /dev/urandom for entropy");

    while (total < SYM_KEY_LENGTH) {
        bytes_read = read(urand_fd, &key[total], SYM_KEY_LENGTH - total);
        total += bytes_read;
    }

    close(urand_fd);

    return key;
}

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
