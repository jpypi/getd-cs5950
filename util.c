#include <string.h>

#include "message.h"
#include "util.h"


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
