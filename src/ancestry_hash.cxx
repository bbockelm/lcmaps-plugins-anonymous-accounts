
/*
 * Originally written for lcmaps-plugins-condor-update, create a 'batch system hash'
 * for a given process.
 *
 * That is, create an opaque string for a PID that associates it with a batch job.
 * If any two PIDs have the same hash, we assume they are in the same job.
 *
 * We implement this via finding the last real UID transition (i.e., from "root"
 * to user "batch" or from "pilot" to "payload"), and recording a tuple of
 * (ppid, pid, timestamp), where ppid / pid are the parent/child PIDs from the
 * transition and timestamp is the time, in seconds, when the child was launched.
 *
 */

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <list>
#include <signal.h>
#include <pwd.h>
#include <stdarg.h>
#include <syslog.h> 
#include <errno.h>
#include <dirent.h>

#ifdef HAVE_UNORDERED_MAP
#include <unordered_map>
#else
#include <ext/hash_map>
#endif

#include <string.h>
#include <stdio.h>
#include <iostream>

extern "C" {
#include "lcmaps/lcmaps_log.h"
}

#include "ancestry_hash.h"

#define PROC "/proc"
static const char * logstr = "ancestry_hash";

// Global variable
class AncestryHash;
AncestryHash *gAH;

#ifdef HAVE_UNORDERED_MAP
typedef std::unordered_map<pid_t, pid_t, std::hash<pid_t>, std::equal_to<pid_t> > PidPidMap;
typedef std::unordered_map<pid_t, int, std::hash<pid_t>, std::equal_to<pid_t> > PidIntMap;
#else
struct eqpid {
    bool operator()(const pid_t pid1, const pid_t pid2) const {
        return pid1 == pid2;
    }
};  
typedef __gnu_cxx::hash_map<pid_t, pid_t, __gnu_cxx::hash<pid_t>, eqpid> PidPidMap;
typedef __gnu_cxx::hash_map<pid_t, int, __gnu_cxx::hash<pid_t>, eqpid> PidIntMap;
#endif
typedef std::list<pid_t> PidList;

static char * match_column(const char* key, const char *buf) {
    const char *next_tab, *next_line;
    const char *next_col = strchr(buf, '\t');
    if (!next_col) {
        return NULL;
    }
    if (strncmp(buf, key, (next_col-buf)) != 0) {
        return NULL;
    }
    next_col++;
    size_t column_len;
    next_tab = strchr(next_col, '\t');
    next_line = strchr(next_col, '\n');
    if (!next_tab && !next_line) return NULL;
    if (!next_line || (next_tab < next_line)) {
        column_len = next_tab - next_col;
    } else {
        column_len = next_line - next_col;
    }
    char * result = (char *)malloc(column_len+1);
    result[column_len] = '\0';
    if (!result) return NULL;
    strncpy(result, next_col, column_len);
    return result;
}

#define buf_size 4096
static int get_proc_info(int fd, int *uid, int *gid, int *ppid) {
    int retval = 0;
    *uid = -1;
    *gid = -1;
    *ppid = -1;
    const char *buf;
    char buffer[buf_size]; buffer[buf_size-1] = '\0';
    char * cuid, *cgid, *cppid;
    if (read(fd, buffer, buf_size-1) < 0) {
        retval = -errno;
        goto finalize;
    }
    buf = buffer;
    cuid = NULL;
    cgid = NULL;
    cppid = NULL;
    while (buf != NULL) {
        if (*ppid == -1) {
            cppid = match_column("PPid:", buf);
            if (cppid) {
                errno = 0;
                *ppid = strtol(cppid, NULL, 0);
                free(cppid);
                if (errno != 0) *ppid = -1;
            }
        } else if (*uid == -1) {
            cuid = match_column("Uid:", buf);
            if (cuid) {
                errno = 0;
                *uid = strtol(cuid, NULL, 0);
                free(cuid);
                if (errno != 0) *uid = -1;
            }
        } else if (*gid == -1) {
            cgid = match_column("Gid:", buf);
            if (cgid) { 
                errno = 0;
                *gid = strtol(cgid, NULL, 0);
                free(cgid);
                if (errno != 0) *gid = -1;
            }
            if (*gid != -1) {
                retval = 0;
                goto finalize;
            }
        } else {
            break;
        }
        buf = strchr(buf, '\n');
        if (buf != NULL) {
            buf++;
            if (*buf == '\0') break;
        }
    }
    retval = 1;

finalize:
    return retval;

}

// From a PID / PPID, create a unique hash, including the PID's creation timestamp.
// The callee is responsible for 'free'ing the memory returned.
// If this function returns NULL, it has encountered a fatal error.
static char * create_hash(pid_t pid, pid_t ppid) {
    char proc_file[20];
    if (snprintf(proc_file, 20, "/proc/%d",pid) >= 20) {
        lcmaps_log(0, "%s: Unable to open file in proc due to large PID %d.\n", logstr, pid);
        return NULL;
    }
    struct stat stat_buf;
    if (stat(proc_file, &stat_buf) == -1) {
        lcmaps_log(0, "%s: Unable to stat %s to get creation timestamp.\n", logstr, proc_file);
        return NULL;
    }
    char fixed_string[50];
    int necessary_size = snprintf(fixed_string, 50, "%d:%d:%ld", pid, ppid, stat_buf.st_mtime);
    char * result = (char *)malloc(necessary_size+1);
    if (result == NULL) {
        lcmaps_log(0, "%s: Unable to allocate final string for the hash function.\n", logstr);
        return NULL;
    }
    if (snprintf(result, necessary_size+1, "%d:%d:%ld", pid, ppid, stat_buf.st_mtime) >= necessary_size+1) {
        lcmaps_log(0, "%s: Logic error in create_hash.\n", logstr);
        return NULL;
    }
    lcmaps_log(5, "%s: Hash %s.\n", logstr, result);
    return result;
}

class AncestryHash {

public:
    char * getHash(pid_t); // Note: Caller takes ownership of returned pointer on heap.
    int makeAncestry(pid_t, PidList&);
    int mineProc();
    int getParentIDs(pid_t, pid_t*, uid_t*, gid_t*);

private:
    PidPidMap reverse_parentage_mapping;
    PidIntMap process_uid_mapping;
    PidIntMap process_gid_mapping;
};

int AncestryHash::mineProc() {
    DIR * dirp;
    struct dirent64 *dp;
    const char * name;
    if ((dirp = opendir(PROC)) == NULL) {
        lcmaps_log(0, "%s: Error - Unable to open /proc: %d %s\n", logstr, errno, strerror(errno));
        return errno;
    }
    int dfd = dirfd(dirp);
    int proc;
    do {
        errno = 0;
        if ((dp = readdir64(dirp)) != NULL) {
            if (dp->d_type != DT_DIR && dp->d_type != DT_UNKNOWN)
                continue;
            name = dp->d_name;
            if (sscanf(name, "%d", &proc) != 1)
                continue;
            if (proc < 2)
                continue;
            char path[PATH_MAX];
            if (snprintf(path, sizeof(path), "%s/status", name) >= PATH_MAX) {
                lcmaps_log(0, "%s: Error - overly long directory file name: %s %d\n", logstr, name, strlen(name));
                continue;
            }
            int fd = openat(dfd, path, O_RDONLY);
            if (fd == -1) {
                lcmaps_log(0, "%s: Error - unable to open PID %s status file: %d %s\n", logstr, name, errno, strerror(errno));
                continue;
            }
            int uid, gid, result;
            pid_t ppid;
            if ((result = get_proc_info(fd, &uid, &gid, &ppid))) {
                lcmaps_log(0, "%s: Error - unable to parse status file for PID %s: %d\n", logstr, name, result);
                close(fd);
                continue;
            }
            close(fd);
            //std::cout << "Running process: " << name << " (uid=" << uid << ", gid=" << gid << ", ppid= " << ppid << ")" << std::endl;
            //lcmaps_log(0, "%s: Running process %s (uid=%d, gid=%d, ppid=%d)\n", name, uid, gid, ppid);
            reverse_parentage_mapping[proc] = ppid;
            process_uid_mapping[proc] = uid;
            process_gid_mapping[proc] = gid;
        }
    } while (dp != NULL);

    if (errno != 0) {
        lcmaps_log(0, "%s: Error reading /proc directory: %d %s\n", logstr, errno, strerror(errno));
    }
    closedir(dirp);
    return 0;
}

int AncestryHash::makeAncestry(pid_t pid, PidList& ancestry) {
    pid_t curpid = pid;
    PidPidMap::const_iterator it;
    int result = 0;
    while (curpid != 1) {
        ancestry.push_back(curpid);
        if ((it = reverse_parentage_mapping.find(curpid)) == reverse_parentage_mapping.end()) {
            result = 1;
            lcmaps_log(0, "%s: Unable to find parent of %d, ancestor of %d.\n", logstr, curpid, pid);
            break;
        }
        curpid = it->second;
    }
    if (curpid == 1) {
        ancestry.push_back(1);
    }
    return result;
}

char * AncestryHash::getHash(pid_t pid) {
    /* General algorithm:
       1) Create a PidList "ancestry" where ancestry[0] = pid, ancestry[-1] = 1, and ancestry[n]'s PPID is ancestry[n+1]
       2) Set idx=0, orig_uid=uid(ancestry[0]), (ppid, pid) to NULL
       3) If uid(ancestry[idx]) != orig_uid, return (ppid, pid)
       4) Update (ppid, pid).
       5) Increment idx by one; goto 3.
     */
    PidList ancestry;
    int orig_uid = -1;
    int rc;
    if ((rc = makeAncestry(pid, ancestry))) {
        lcmaps_log(0, "%s: Error: unable to determine ancestry of %d: %d\n", logstr, pid, rc);
        return NULL;
    }

    if (ancestry.size() < 3) { // glexec, pid, parent are required.
        lcmaps_log(0, "%s: Error - ancestry of %d is implausibly small.\n", logstr, pid);
        return NULL;
    }
    PidList::const_iterator it;
    PidIntMap::const_iterator it2;
    it = ancestry.begin();
    it++; // skip the glexec invocation.
    int ppid = *it, pid_it = *it;
    for (; it != ancestry.end(); it++) {
        ppid = *it;
        lcmaps_log(5, "%s: Considering ancestry of %d.\n", logstr, pid_it);
        if ((it2 = process_uid_mapping.find(*it)) == process_uid_mapping.end()) {
            lcmaps_log(0, "%s: Error - ancestor %d is not in UID map.\n", logstr, *it);
            return NULL; // If we don't know the UID of an ancestor, something fishy is happening.  Bail.
        }
        int uid = it2->second;
        if (orig_uid == -1) {
            orig_uid = uid;
        }

        // getParentIDs will verify the parentage, reducing the likelihood of a race attack.
        if (getParentIDs(pid_it, NULL, NULL, NULL) == -1) {
            return NULL;
        }

        if (uid != orig_uid) { // Identified the UID transition
            lcmaps_log(5, "%s: Found a UID transition from %d to %d.\n", logstr, ppid, pid_it);
            return create_hash(pid_it, ppid);
        }
        pid_it = *it;
    }
    lcmaps_log(0, "%s: Error - unable to determine hash from ancestry.");
    return NULL;
}

int AncestryHash::getParentIDs(pid_t pid, pid_t *ppid, uid_t *uid, gid_t *gid) {
    // We need to re-read the process's PPID first.
    // Why?  In case if the process's parent exited, and some
    // other process has replaced it (with a different UID).
    // If the process's PPID has changed, then we return -1.

    // Make sure uid and gid are valid pointers
    uid_t internal_uid;
    gid_t internal_gid;
    if (!uid) {
        uid = &internal_uid;
    }
    if (!gid) {
        gid = &internal_gid;
    }
    pid_t internal_ppid;
    if (!ppid) {
        ppid = &internal_ppid;
    }

    PidPidMap::const_iterator it;
    PidIntMap::const_iterator it2;
    pid_t old_ppid, new_ppid;
    int result, fd;
    char path[PATH_MAX];

    if ((it = reverse_parentage_mapping.find(pid)) == reverse_parentage_mapping.end()) {
        lcmaps_log(0, "%s: Error - Unknown PPID of %d", logstr, pid);
        return -1;
    }
    old_ppid = it->second;
    if (snprintf(path, PATH_MAX, "/proc/%d/status", pid) >= PATH_MAX) {
        lcmaps_log(0, "%s: Error - overly long PID: %d\n", logstr, pid);
        return -1;
    }
    if ((fd = open(path, O_RDONLY)) == -1) {
        lcmaps_log(0, "%s: Error opening process %d status file: %d %s\n", logstr, pid, errno, strerror(errno));
        return -1;
    }
    if ((result = get_proc_info(fd, (int *)uid, (int *)gid, &new_ppid))) {
        lcmaps_log(0, "%s: Error - unable to parse status file for PID %d: %d\n", logstr, pid, result);
        close(fd);
        return -1;
    }
    close(fd);
    lcmaps_log(5, "%s: PPID %d (new %d) for PID %d.\n", logstr, old_ppid, new_ppid, pid);
    if (new_ppid != old_ppid) {
        lcmaps_log(0, "%s: Error - parent PID changed.  Possible race attack.  Old %d; new %d\n", logstr, old_ppid, new_ppid);
        return -1;
    }

    *ppid = new_ppid;

    if ((it2 = process_uid_mapping.find(new_ppid)) == process_uid_mapping.end()) {
        lcmaps_log(0, "%s: Error - ancestor of %d is not in UID map.\n", logstr, pid);
        return -1; // If we don't know the UID of an ancestor, something fishy is happening.  Bail.
    }
    *uid = it2->second;

    if ((it2 = process_gid_mapping.find(new_ppid)) == process_gid_mapping.end()) {
        lcmaps_log(0, "%s: Error - ancestor of %d is not in GID map.\n", logstr, pid);
        return -1; // If we don't know the UID of an ancestor, something fishy is happening.  Bail.
    }
    *gid = it2->second;

    return 0;

}

char * getHash(pid_t proc) {
    if (!gAH) {
        gAH = new AncestryHash;
        gAH->mineProc();
    }
    lcmaps_log(5, "%s: Computing ancestry hash of %d.\n", logstr, proc);
    return gAH->getHash(proc);
}

int getParentIDs(pid_t proc, pid_t *ppid, uid_t *uid, gid_t *gid) {
    if (!gAH) {
        gAH = new AncestryHash;
        gAH->mineProc();
    }
    int retval = gAH->getParentIDs(proc, ppid, uid, gid);
    lcmaps_log(5, "%s: PPID %d for PID %d.\n", logstr, ppid ? *ppid : -1, proc);
    return retval;
}

