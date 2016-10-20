#define responsen(N) {.header.messageType = N,\
                      .header.messageLength = sizeof(MessageType ## N)}

responsen(1)
