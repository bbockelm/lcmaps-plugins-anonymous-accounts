
#ifndef __ANCESTRY_HASH_H
#define __ANCESTRY_HASH_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

char * getHash(pid_t);
int getParentIDs(pid_t, pid_t*, uid_t*, gid_t*);

#ifdef __cplusplus
}
#endif

#endif

