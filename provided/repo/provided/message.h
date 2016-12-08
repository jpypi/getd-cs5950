#ifndef _MESSAGE_H_
#define _MESSAGE_H_

#include <limits.h>

#define DEBUG_MSG

#define TYPE0 0
#define TYPE1 1
#define TYPE2 2
#define TYPE3 3
#define TYPE4 4
#define TYPE5 5
#define TYPE6 6
#define TYPE7 7

#define DN_LENGTH 32
#define SID_LENGTH 128
#define MAX_CONTENT_LENGTH 4096
#define MAX_ERROR_MESSAGE 256

#define INVALID_MESSAGE_RECVD -1
#define INVALID_MESSAGE_TYPE -2
#define INVALID_MESSAGE_LENGTH -3
#define INVALID_TYPE0_MSG -4
#define INVALID_TYPE1_MSG -5
#define INVALID_TYPE2_MSG -6
#define INVALID_TYPE3_MSG -7
#define INVALID_TYPE4_MSG -8
#define INVALID_TYPE5_MSG -9
#define INVALID_TYPE6_MSG -10
#define INVALID_TYPE7_MSG -11

#define IPC_ADDR "ipc:///tmp/getd.ipc"

typedef struct _header {
  unsigned char messageType;
  unsigned int messageLength;
} Header;


typedef struct _type0 {
  Header header;
  unsigned int dnLength;
  char distinguishedName[DN_LENGTH+1];
} MessageType0;

typedef struct _type1 {
  Header header;
  unsigned int sidLength;
  char sessionId[SID_LENGTH+1];
} MessageType1;

typedef struct _type2 {
  Header header;
  unsigned int msgLength;
  char errorMessage[MAX_ERROR_MESSAGE+1];
} MessageType2;

typedef struct _type3 {
  Header header;
  unsigned int sidLength;
  unsigned int pathLength;
  char sessionId[SID_LENGTH+1];
  char pathName[PATH_MAX+1];
} MessageType3; 

typedef struct _type4 {
  Header header;
  unsigned int sidLength;
  unsigned int contentLength;
  char sessionId[SID_LENGTH+1];
  char contentBuffer[MAX_CONTENT_LENGTH+1]; 
} MessageType4;

typedef struct _type5 {
  Header header;
  unsigned int sidLength;
  char sessionId[SID_LENGTH+1];
} MessageType5;
  
typedef struct _type6 {
  Header header;
  unsigned int sidLength;
  char sessionId[SID_LENGTH+1];
} MessageType6;

#endif

