#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <uuid/uuid.h>

#include <systemFuncs.h>

#include <pwd.h>

char *getUserName() {

  struct passwd *info = getpwuid(getuid());

  if (info == NULL) {
    fprintf(stderr,"Error finding passwd entry\n");
    exit(-1);
  }

  return info->pw_name;
}
