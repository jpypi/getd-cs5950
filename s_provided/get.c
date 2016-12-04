#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <util/message.h>
#include <clientProtocol.h>

int socket;
int eid;
FILE *destFile;

static char *verifyPath(char *path) {
   int length = strlen(path);

   if (length < 1) 
     return NULL;

   char *str = (char *)malloc(length+1);
   
   if (str == NULL) {
     fprintf(stderr,"malloc() error\n");
     exit(-1);
   }

   strncpy(str,path,length+1);

   return str;
}

static void getFile(char *source, char *dest) {

  setUpClientSocket(&socket,&eid);
  startClientProtocol(socket,source,dest);
  shutdownSocket(socket,eid);
}

int main(int argc, char **argv) {

  char *source;
  char *dest;

  if (argc == 3 ) {
    source = verifyPath(argv[1]);
    if (source == NULL) {
      fprintf(stderr,"Invalid path specification %s\n",argv[1]);
      exit(-1);
    }

    dest = verifyPath(argv[2]);
    if (dest == NULL) {
      fprintf(stderr,"Invalid path specification %s\n",argv[2]);
      exit(-1);
    }

    getFile(source,dest);
  }

}
