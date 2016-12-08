#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <message.h>
#include <nanomsg/nn.h>
#include <nanomsg/pair.h>
#include <exit.h>
#include <util/string_util.h>

unsigned char getMessageType (char *msg) {
   return ((Header *)msg)->messageType;  
}

static unsigned int getMessageLength (char *msg) {
   return ((Header *)msg)->messageLength;  
}

static void verifyType0Message(char *msg) {
   MessageType0 *message = (MessageType0 *)msg;

   if (message->header.messageLength != sizeof(MessageType0))
     messageError(INVALID_TYPE0_MSG,msg);
}

static void verifyType1Message(char *msg) {
   MessageType1 *message = (MessageType1 *)msg;

   if (message->header.messageLength != sizeof(MessageType1))
     messageError(INVALID_TYPE1_MSG,msg);
   else if (message->sidLength != SID_LENGTH)
     messageError(INVALID_TYPE1_MSG,msg);
   else if (strnlen(message->sessionId,SID_LENGTH+1) != SID_LENGTH)
     messageError(INVALID_TYPE1_MSG,msg);
}

static void verifyType2Message(char *msg) {
   MessageType2 *message = (MessageType2*)msg;

   if (message->header.messageLength != sizeof(MessageType2))
     messageError(INVALID_TYPE2_MSG,msg);
   else if (message->msgLength == 0 || message->msgLength > MAX_ERROR_MESSAGE)
     messageError(INVALID_TYPE2_MSG,msg);
   else if (message->msgLength != strnlen(message->errorMessage,MAX_ERROR_MESSAGE+1))
     messageError(INVALID_TYPE2_MSG,msg);
}

static void verifyType3Message(char *msg) {
   MessageType3 *message = (MessageType3*)msg;

   if (message->header.messageLength != sizeof(MessageType3))
     messageError(INVALID_TYPE3_MSG,msg);
   else if (message->sidLength != SID_LENGTH)
     messageError(INVALID_TYPE3_MSG,msg);
   else if (strnlen(message->sessionId,SID_LENGTH+1) != SID_LENGTH)
     messageError(INVALID_TYPE3_MSG,msg);
   else if (message->pathLength == 0 || message->pathLength > PATH_MAX)
     messageError(INVALID_TYPE3_MSG,msg);
   else if (message->pathLength != strnlen(message->pathName,PATH_MAX+1))
     messageError(INVALID_TYPE3_MSG,msg);
}

static void verifyType4Message(char *msg) {
   MessageType4 *message = (MessageType4*)msg;

   if (message->header.messageLength != sizeof(MessageType4))
     messageError(INVALID_TYPE4_MSG,msg);
   else if (message->sidLength != SID_LENGTH)
     messageError(INVALID_TYPE4_MSG,msg);
   else if (strnlen(message->sessionId,SID_LENGTH+1) != SID_LENGTH)
     messageError(INVALID_TYPE4_MSG,msg);
   else if (message->contentLength == 0 || message->contentLength > MAX_CONTENT_LENGTH)
     messageError(INVALID_TYPE4_MSG,msg);
   else if (message->contentLength != strnlen(message->contentBuffer,MAX_CONTENT_LENGTH+1))
     messageError(INVALID_TYPE3_MSG,msg);
}

static void verifyType5Message(char *msg) {
   MessageType5 *message = (MessageType5*)msg;

   if (message->header.messageLength != sizeof(MessageType5))
     messageError(INVALID_TYPE5_MSG,msg);
   else if (message->sidLength != SID_LENGTH)
     messageError(INVALID_TYPE5_MSG,msg);
   else if (strnlen(message->sessionId,SID_LENGTH+1) != SID_LENGTH)
     messageError(INVALID_TYPE5_MSG,msg);
}

static void verifyType6Message(char *msg) {
   MessageType6 *message = (MessageType6*)msg;

   if (message->header.messageLength != sizeof(MessageType6))
     messageError(INVALID_MESSAGE_TYPE,msg);
   else if (message->sidLength != SID_LENGTH)
     messageError(INVALID_TYPE6_MSG,msg);
   else if (strnlen(message->sessionId,SID_LENGTH+1) != SID_LENGTH)
     messageError(INVALID_TYPE5_MSG,msg);
}

static void verifyType7Message(char *msg) {

   messageError(INVALID_MESSAGE_TYPE,msg);
}

static void verifyMessage(char *msg) {

   switch(getMessageType(msg)) {

     case TYPE0:
       verifyType0Message(msg);
       break;

     case TYPE1:
       verifyType1Message(msg);
       break;

     case TYPE2:
       verifyType2Message(msg);
       break;

     case TYPE3:
       verifyType3Message(msg);
       break;

     case TYPE4:
       verifyType4Message(msg);
       break;

     case TYPE5:
       verifyType5Message(msg);
       break;

     case TYPE6:
       verifyType6Message(msg);
       break;

     case TYPE7:
       verifyType7Message(msg);
       break;

     default:
       messageError(INVALID_MESSAGE_TYPE,msg);
   }

}

char *getValidMessage(int socket) {
  char *buff = NULL;

#ifdef DEBUG_MSG
   printf("Receiving message on socket %d\n",socket);
#endif
  int numBytes = nn_recv(socket,&buff,NN_MSG,0);

  if (numBytes < sizeof(Header)) 
     messageError(INVALID_MESSAGE_RECVD,buff);
  else if (numBytes != getMessageLength(buff)) 
     messageError(INVALID_MESSAGE_LENGTH,buff);

  char *msg = (char *)malloc(numBytes);
  memcpy(msg,buff,numBytes);

  if (nn_freemsg(buff))
    exitProgram("failure to free message buffer\n");

  verifyMessage(msg);
   
#ifdef DEBUG_MSG
   printf("Received Type %u Message\n",((Header*)msg)->messageType);
#endif
  return msg;
}

static void sendMessage(int socket, char *buff,unsigned int size) {
  void *msgBuffer = nn_allocmsg(size,0);

  memcpy(msgBuffer,buff,size);
  int numBytes = nn_send(socket, msgBuffer, size , 0);

  if (numBytes != size)
    exitProgram(nssave(2,"Send Error: ",nn_strerror(nn_errno())));
}

void sendMessageType0(int socket, char *distinguishedName) {

   MessageType0 *message = (MessageType0 *)malloc(sizeof(MessageType0));

#ifdef DEBUG_MSG
   printf("Server Sending Type 0 Message on socket %d\n",socket);
#endif
   if (message == NULL) {
     perror("Error: ");
     exit(-1);
   } 
     
   unsigned int dn_length = strnlen(distinguishedName,DN_LENGTH+2);

   if (dn_length == 0 || dn_length > DN_LENGTH) 
     messageError(INVALID_TYPE0_MSG,distinguishedName);

   message->dnLength = dn_length;
   strcpy(message->distinguishedName,distinguishedName);

   message->header.messageType = TYPE0;
   message->header.messageLength = sizeof(MessageType0);

   sendMessage(socket,(char *)message, sizeof(MessageType0));
}

void sendMessageType1(int socket, char *sessionId) {

   MessageType1 *message = (MessageType1 *)malloc(sizeof(MessageType1));

#ifdef DEBUG_MSG
   printf("Sending Type 1 Message\n");
#endif
   if (message == NULL) {
     perror("Error: ");
     exit(-1);
   } 
     
   unsigned int sidLength = strnlen(sessionId,SID_LENGTH+2);

   if (sidLength != SID_LENGTH)
     messageError(INVALID_TYPE1_MSG,sessionId);

   message->sidLength = sidLength;
   strcpy(message->sessionId,sessionId);

   message->header.messageType = TYPE1;
   message->header.messageLength = sizeof(MessageType1);

   sendMessage(socket,(char *)message, sizeof(MessageType1));
}

void sendMessageType2(int socket, char *errorMessage) {

#ifdef DEBUG_MSG
   printf("Sending Type 2 Message\n");
#endif
   MessageType2 *message = (MessageType2 *)malloc(sizeof(MessageType2));

   if (message == NULL) {
     perror("Error: ");
     exit(-1);
   } 
     
   int errorMsgLength = strnlen(errorMessage,MAX_ERROR_MESSAGE+2);

   if (errorMsgLength < 1 || errorMsgLength > MAX_ERROR_MESSAGE)
     messageError(INVALID_TYPE2_MSG,errorMessage);

   message->msgLength = errorMsgLength;
   strcpy(message->errorMessage,errorMessage);

   message->header.messageType = TYPE2;
   message->header.messageLength = sizeof(MessageType2);

   sendMessage(socket,(char *)message, sizeof(MessageType2));
}

void sendMessageType3(int socket, char *sessionId, char *pathName) {

   MessageType3 *message = (MessageType3 *)malloc(sizeof(MessageType3));

#ifdef DEBUG_MSG
   printf("Sending Type 3 Message\n");
#endif
   if (message == NULL) {
     perror("Error: ");
     exit(-1);
   } 
     
   unsigned int sidLength = strnlen(sessionId,SID_LENGTH+2);

   if (sidLength != SID_LENGTH)
     messageError(INVALID_TYPE3_MSG,sessionId);

   message->sidLength = sidLength;
   strcpy(message->sessionId,sessionId);

   unsigned int pathLength = strnlen(pathName,PATH_MAX+2);

   if (pathLength == 0 || pathLength > PATH_MAX) 
     messageError(INVALID_TYPE3_MSG,pathName);

   message->pathLength = pathLength;
   strcpy(message->pathName,pathName);

   message->header.messageType = TYPE3;
   message->header.messageLength = sizeof(MessageType3);

   sendMessage(socket,(char *)message, sizeof(MessageType3));
}

void sendMessageType4(int socket, char *sessionId, char *contentBuffer) {

   MessageType4 *message = (MessageType4 *)malloc(sizeof(MessageType4));

#ifdef DEBUG_MSG
   printf("Sending Type 4 Message\n");
#endif
   if (message == NULL) {
     perror("Error: ");
     exit(-1);
   } 
     
   unsigned int sidLength = strnlen(sessionId,SID_LENGTH+2);

   if (sidLength != SID_LENGTH)
     messageError(INVALID_TYPE4_MSG,sessionId);

   message->sidLength = sidLength;
   strcpy(message->sessionId,sessionId);

   unsigned int contentLength = strnlen(contentBuffer,MAX_CONTENT_LENGTH+2);

   if (contentLength == 0 || contentLength > MAX_CONTENT_LENGTH) 
     messageError(INVALID_TYPE4_MSG,contentBuffer);

   message->contentLength = contentLength;
   strcpy(message->contentBuffer,contentBuffer);

   message->header.messageType = TYPE4;
   message->header.messageLength = sizeof(MessageType4);

   sendMessage(socket,(char *)message, sizeof(MessageType4));
}

void sendMessageType5(int socket, char *sessionId) {

   MessageType5 *message = (MessageType5 *)malloc(sizeof(MessageType5));

#ifdef DEBUG_MSG
   printf("Sending Type 5 Message\n");
#endif
   if (message == NULL) {
     perror("Error: ");
     exit(-5);
   } 
     
   unsigned int sidLength = strnlen(sessionId,SID_LENGTH+2);

   if (sidLength != SID_LENGTH)
     messageError(INVALID_TYPE5_MSG,sessionId);

   message->sidLength = sidLength;
   strcpy(message->sessionId,sessionId);

   message->header.messageType = TYPE5;
   message->header.messageLength = sizeof(MessageType5);

   sendMessage(socket,(char *)message, sizeof(MessageType5));
}

void sendMessageType6(int socket, char *sessionId) {

   MessageType6 *message = (MessageType6 *)malloc(sizeof(MessageType6));

#ifdef DEBUG_MSG
   printf("Sending Type 6 Message\n");
#endif
   if (message == NULL) {
     perror("Error: ");
     exit(-1);
   } 
     
   unsigned int sidLength = strnlen(sessionId,SID_LENGTH+2);

   if (sidLength != SID_LENGTH)
     messageError(INVALID_TYPE5_MSG,sessionId);

   message->sidLength = sidLength;
   strcpy(message->sessionId,sessionId);

   message->header.messageType = TYPE6;
   message->header.messageLength = sizeof(MessageType6);

   sendMessage(socket,(char *)message, sizeof(MessageType6));
}

void setUpClientSocket(int *socket, int *eid) {
  *socket = nn_socket(AF_SP,NN_PAIR);

  if (*socket == -1) {
    perror("Error: ");
    exit(-1);
  }

  *eid = nn_connect(*socket, IPC_ADDR);

  if (*eid < 0) {
    perror("Error: ");
    exit(-1);
  }

  printf("Client Socket = %d, eid = %d\n",*socket,*eid);
}

void setUpServerSocket(int *socket,int *eid) {

  *socket = nn_socket(AF_SP,NN_PAIR);

  if (*socket == -1) {
    perror("Error: ");
    exit(-1);
  }

  *eid = nn_bind(*socket, IPC_ADDR);

  if (*eid < 0) {
    perror("Error: ");
    exit(-1);
  }
  printf("Server Socket = %d, eid = %d\n",*socket,*eid);
}

void shutdownSocket(int socket, int eid) {
  
  if (nn_shutdown(socket,eid) < 0) {
    perror("Error: ");
    exit(-1);
  }
}

void messageError(int errorNumber, char *buff) {

  int buffLength = strnlen(buff,8192) + 33 < 8192 ? strnlen(buff,8192) + 33 : 8192;
  char *errorMessage = (char *)malloc(buffLength);

  switch(errorNumber) {

    case INVALID_MESSAGE_RECVD:
      if (buff == NULL)
        snprintf(errorMessage,buffLength,"Null message\n");
      else
        snprintf(errorMessage,buffLength,"Message too small: %s\n",buff); 
      break;

    case INVALID_MESSAGE_TYPE:
      snprintf(errorMessage,buffLength,"Invalid message type %c\n",getMessageType(buff));
      break;

    case INVALID_MESSAGE_LENGTH:
      snprintf(errorMessage,buffLength,"Invalid message length %u\n",getMessageLength(buff));
      break;

    case INVALID_TYPE0_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 0 message %s\n",buff);
      break;

    case INVALID_TYPE1_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 1 message %s\n",buff);
      break;

    case INVALID_TYPE2_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 2 message %s\n",buff);
      break;

    case INVALID_TYPE3_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 3 message %s\n",buff);
      break;

    case INVALID_TYPE4_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 4 message %s\n",buff);
      break;

    case INVALID_TYPE5_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 5 message %s\n",buff);
      break;

    case INVALID_TYPE6_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 6 message %s\n",buff);
      break;

    case INVALID_TYPE7_MSG:
      snprintf(errorMessage,buffLength,"Invalid type 7 message %s\n",buff);
      break;

    default: 
      snprintf(errorMessage,buffLength, "Invalid error number %u\n",errorNumber);
  }

  exitProgram(errorMessage);
}
