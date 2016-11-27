#ifndef _SGETD_UTIL_H
#define _SGETD_UTIL_H

char * gen_symmetric_key();

void safe_sid_copy(char *dest, char const *src);

int is_full_path(char *path);

#endif