#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "apue.h"
#include "acl.h"
#include "common.h"


/*
 * Trys to open basename.acl file, read it and determine if username is in it.
 * There are many error conditions some of which cause the program to end
 * immediately.
 * Returns:
 *   1 if the user has access
 *   0 Otherwise
 */
int
check_acl_access(char const *restrict basename, char const *restrict username) {
    int str_len = strlen(basename);
    // len(.acl\0) == 5
    char *acl_path = malloc(str_len + 5);
    // Doesn't copy the NULL
    strncpy(acl_path, basename, str_len);
    // This copies the NULL in for us
    strncpy(acl_path + str_len, ".acl", 5);

    // Only raise our privleges for as long as we need them
    FILE *fd = fopen(acl_path, "r");

    if (fd != NULL) {
        struct stat file_stat;
        if (fstat(fileno(fd), &file_stat) != 0) {
            err_sys(BROKEN_OR_EVIL);
            return 0;
        }

        if ((file_stat.st_mode & S_IRWXG) > 0 ||
                (file_stat.st_mode & S_IRWXO) > 0)
            // The ACL file has wrong permissions DON'T DO ANYTHING!
            // (And by wrong permissions it is meant there are some kind of
            //  world or group perms which is a red flag. ABORT!)
            DEBUG0(err_quit("ERROR: ACL file for %s has the wrong permissions.",
                     basename));

        if (file_stat.st_uid != geteuid())
            DEBUG0(err_quit("ERROR: Owner does not own the ACL file."));

        char *line = NULL;
        size_t linecap = 0;
        ssize_t line_len = 0;

        while((line_len = getline(&line, &linecap, fd)) > 0) {
            // Null out the newline at the end of the line so strcmp works
            if (line[line_len-1] == '\n')
                line[line_len-1] = 0;

            // Just return now if we found a match
            if (strcmp(username, line) == 0) {
                free(line);
                return 1;
            }
        }

        // Make sure we clean up after ourselves
        if (line != NULL) free(line);

    } else if (errno == ENOENT || errno == EACCES) {
        DEBUG0(err_sys("%s", acl_path));
    }

    // Well, guess the user isn't allowed!
    return 0;
}
