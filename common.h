#ifndef _COMMON_H_
#define _COMMON_H_


// These are used to control how verbose the program is. Defining SILENT will
// cause the program to produce less output and thus be more difficult to attack
#ifndef SILENT
#define DEBUG0(X) X
#define DEBUGR(X) X
#define DEBUG(X) X
#define NDEBUG(X)
#else
#define DEBUG0(X) return 0
#define DEBUGR(X) return
#define DEBUG(X)
#define NDEBUG(X) X
#endif


#define BROKEN_OR_EVIL "Something is broken or maybe you're being naughty."


#endif
