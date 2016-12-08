#include <stdio.h>
#include <stdlib.h>

#include <exit.h>
#include <message.h>

extern int socket;
extern int eid;
extern FILE *destFile;

void exitProgram(char *msg) {

   fprintf(stderr,"%s\n",msg);
   shutdownSocket(socket,eid);
   if (destFile != NULL)
     fclose(destFile);
   exit(-1);
}
