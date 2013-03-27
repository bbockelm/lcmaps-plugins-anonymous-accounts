
/*
 * lcmaps-plugins-pool-accounts
 * By Brian Bockelman, 2012 
 * This code is licensed under Apache v2.0
 */

/*****************************************************************************
                            Include header files
******************************************************************************/

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>

#include "lcmaps/lcmaps_modules.h"
#include "lcmaps/lcmaps_cred_data.h"
#include "lcmaps/lcmaps_arguments.h"

#include "ancestry_hash.h"

// Various necessary strings
#define MINUID_ARG "-minuid"
#define MAXUID_ARG "-maxuid"
#define UID_DEFAULT -1
#define LOCKPATH_ARG "-lockpath"
#define LOCKPATH_DEFAULT "/var/lock/lcmaps-plugins-pool-accounts"

// Refuse to hand out a UID lower than this one.
// Selection of 1000 is done based on current (2012) RHEL guidelines.
#define SYSTEM_UID 1000

const char * logstr = "lcmaps-pool-accounts";

// Plugin configurations
static char * lockdir = NULL;
static int min_uid = UID_DEFAULT;
static int max_uid = UID_DEFAULT;

// Open the directory, do basic permission checks.
// Returns -1 on failure and an open FD on success
static int open_lockdir() {

  DIR * dir = opendir(lockdir);
  if (dir == NULL) {
    lcmaps_log_time(0, "%s: Unable to open directory %s: (errno=%d, %s)\n", logstr, lockdir, errno, strerror(errno));
    return -1;
  }
  int dir_fd = dirfd(dir);
  if (dir_fd == -1) {
    lcmaps_log_time(0, "%s: Unable to get directory fd %s: (errno=%d, %s)\n", logstr, lockdir, errno, strerror(errno));
    return -1;
  }
  struct stat stat_buf;
  if (fstat(dir_fd, &stat_buf) == -1) {
    lcmaps_log_time(0, "%s: Unable to stat the lock directory %s: (errno=%d, %s)\n", logstr, lockdir, errno, strerror(errno));
    return -1;
  }
  if (stat_buf.st_uid != 0) {
    lcmaps_log_time(0, "%s: Lock directory (%s) not owned by root.\n", logstr, lockdir);
    return -1;
  }
  if ((stat_buf.st_gid != 0) && ((stat_buf.st_mode & S_IWGRP) == S_IWGRP)) {
    lcmaps_log_time(0, "%s: Lock directory (%s) is not owned by root group and is group writable.\n", logstr, lockdir);
    return -1;
  }
  if (stat_buf.st_mode & S_IWOTH) {
    lcmaps_log_time(0, "%s: Lock directory (%s) is world-writable.\n", logstr, lockdir);
    return -1;
  }
  return dir_fd;
}

// Given a UID and an open FD, see if we are allowed to use it.
//
// We can use it if there is no process hash or the existing hash matches
// ours.
//
// Returns 0 on success, -1 on failure, 1 if the account should not be used.
//
static int check_account(int uid, int fd, char **account_hash) {
  FILE * file = fdopen(fd, "r");
  if (file == NULL) {
    lcmaps_log(0, "%s: Unable to allocate file pointer for account %d.\n", logstr, uid);
    return -1;
  }
  rewind(file);

  int pid, ppid;
  time_t timestamp;
  lcmaps_log(5, "%s: Checking validity of UID %d.\n", logstr, uid);

  // Compute our hash.
  char * new_hash = getHash(getpid());
  if (new_hash == NULL) {
    lcmaps_log(0, "%s: Unable to compute hash for my current process.\n", logstr);
    return -1;
  }
  *account_hash = new_hash;

  // Look for an existing hash.  No hash means we can use the account.
  int matches = fscanf(file, "%d:%d:%ld", &pid, &ppid, &timestamp);
  if (matches != 3) {
    lcmaps_log(5, "%s: Invalid hash string in lock file (%d matches), so we can reuse it.\n", logstr, matches);
    return 0;
  }

  int mypid, myppid;
  time_t mytimestamp;
  if (sscanf(new_hash, "%d:%d:%ld", &mypid, &myppid, &mytimestamp) != 3) {
    lcmaps_log(0, "%s: Incorrect format of new hash (%s).\n", logstr, new_hash);
    return -1;
  }

  // If hash on-disk is the same as ours, we can reuse this account.
  if ((mypid == pid) && (myppid == ppid) && (mytimestamp == timestamp)) {
    lcmaps_log(5, "%s: On-disk hash matches in-memory one; using account.\n", logstr);
    return 0;
  }

  // From here on out, we need to see if the hash on-disk is still valid.
  // If it is not valid (process exited, information changes), return 0
  // because we can reuse the account.
  //
  // If we determine the hash is still valid, we cannot use this account (return 1).

  // Check to see if the process's birthday is still correct.
  char proc_file[20];
  if (snprintf(proc_file, 20, "/proc/%d",pid) >= 20) {
    lcmaps_log(0, "%s: Unable to open file in proc due to large PID %d.\n", logstr, pid);
    return 1;
  }
  lcmaps_log(5, "%s: Checking age of %s.\n", logstr, proc_file);
  struct stat stat_buf;
  if (stat(proc_file, &stat_buf) == -1) {
    if (errno != ENOENT) {
      lcmaps_log(0, "%s: Unable to stat %s to get creation timestamp.\n", logstr, proc_file);
      return -1;
    }
    lcmaps_log(5, "%s: Re-using account because previous PID from hash disappeared.\n", logstr);
    return 0;
  }
  if (timestamp != stat_buf.st_mtime) {
    lcmaps_log(5, "%s: Re-using account because PID birthday does not match on-disk hash.\n", logstr);
    return 0;
  }

  int real_ppid;
  if (getParentIDs(pid, &real_ppid, NULL, NULL)) {
    lcmaps_log(0, "%s: Unable to retrieve parent of process %d.\n", logstr, pid);
    return 0;
  }

  if (real_ppid != ppid) {
    lcmaps_log(5, "%s: Re-using account because PPID (%d) changed for PID %d from on-disk hash (%d).\n", logstr, real_ppid, pid, ppid);
    return 0;
  }

  // Hash is still valid, and it does not match ours.  Try again.
  lcmaps_log(5, "%s: Cannot re-use account - hash is still valid, and it does not match ours.\n", logstr);
  return 1;
}

// Given a lock directory file descriptor, iterate through the possible
// user names and select an unlocked account.
//
// On success, account_name, hash and lockfile are changed to the name, hash
// and location of the lockfile, respectively.  The callee is responsible for
// calling 'free' on the memory.
//
// Return -1 on failure.
int select_account(int dir_fd, char **account_name, char **account_lockfile, char **account_hash, int *account_uid, int *account_gid) {

  struct passwd *account;
  int uid;
  for (uid = min_uid; uid <= max_uid; uid++) {
    int excl_failed = 0;
    errno = 0; // errno set to 0 explicitly per comments in man page of getpwuid.
    account = getpwuid(uid);
    if (account == NULL) {
      if (errno)
        lcmaps_log(2, "%s: UID %d not found on system but is in UID range (errno=%d, %s).\n", logstr, uid, errno, strerror(errno));
      else
        lcmaps_log(4, "%s: UID %d not found on system but is in UID range.\n", logstr, uid);
      continue;
    }
    const char * name = account->pw_name;
    lcmaps_log(4, "%s: Considering mapping to account %s.\n", logstr, name);
    int fd = openat(dir_fd, name, O_RDWR|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (fd == -1) {
      if (errno == EEXIST) {
        excl_failed = 1;
        fd = openat(dir_fd, name, O_RDWR, 0);
        if (fd == -1) {
          if (errno == ENOENT) {
            lcmaps_log(2, "%s: Race issue when trying to lock %s; trying another account.\n", logstr, name);
          } else {
            lcmaps_log(2, "%s: Error when trying to open lock %s; trying another account (errno=%d, %s).\n", logstr, name, errno, strerror(errno));
          }
          continue;
        }
      } else {
        lcmaps_log(2, "%s: Error trying to create lockfile %s (errno=%d, %s).\n", logstr, name, errno, strerror(errno));
        continue;
      }
    }

    if (flock(fd, LOCK_EX|LOCK_NB) == -1) {
      if (errno == EWOULDBLOCK) {
        lcmaps_log(5, "%s: Not assigning account %s because it is in use by another process.\n", logstr, name);
      } else {
        lcmaps_log(2, "%s: Not assigning account %s because of error (errno=%d, %s).\n", logstr, name, errno, strerror(errno));
      }
      close(fd);
      continue;
    } else if (excl_failed) {
      // Per new hashing scheme, this isn't necessary.
      //lcmaps_log(1, "%s: Locked an existing account file %s; likely means the monitoring process died unexpectedly or misconfiguration.\n", logstr, name);
    }

    int account_validity = check_account(uid, fd, account_hash);
    if (account_validity == -1) {
      lcmaps_log(0, "%s: Fatal error while checking account validity.\n", logstr);
      close(fd);
      return -1;
    } else if (account_validity == 1) {
      lcmaps_log(4, "%s: Tried account %s but it appears it is in use; will try another.\n", logstr, name);
      close(fd);
      continue;
    }

    *account_name = strdup(name);
    size_t lockfile_len = strlen(lockdir) + 1 + strlen(name) + 1;
    *account_lockfile = malloc(lockfile_len);
    if (!account_name || !account_lockfile) {
      lcmaps_log(0, "%s: Unable to allocate memory for account name.\n", logstr);
      close(fd);
      return -1;
    }
    *account_uid = account->pw_uid;
    *account_gid = account->pw_gid;
    sprintf(*account_lockfile, "%s/%s", lockdir, name);
    return fd;
  }

  return -1;
}

/******************************************************************************
Function:   plugin_initialize
Description:
    Initialize plugin; a no-op, but required by LCMAPS
Parameters:
    argc, argv
    argv[0]: the name of the plugin
Returns:
    LCMAPS_MOD_SUCCESS : success
    LCMAPS_MOD_FAIL    : failure
******************************************************************************/
int plugin_initialize(int argc, char **argv)
{
  int idx;

  // Notice that we start at 1, as argv[0] is the plugin name.
  for (idx=1; idx<argc; idx++) {
    lcmaps_log(5, "%s: arg %d is %s\n", logstr, idx, argv[idx]);
    if ((strncasecmp(argv[idx], MINUID_ARG, strlen(MINUID_ARG)) == 0) && ((idx+1) < argc)) {
      idx++;
      if ((sscanf(argv[idx], "%d", &min_uid) != 1) || (min_uid < 0)) {
        lcmaps_log(0, "%s: Unable to convert min UID argument %s to an integer\n", logstr, argv[idx]);
        return LCMAPS_MOD_FAIL;
      }
      lcmaps_log(4, "%s: Min UID: %d.\n", logstr, min_uid);
    } else if ((strncasecmp(argv[idx], MAXUID_ARG, strlen(MAXUID_ARG)) == 0) && ((idx+1) < argc)) {
      idx++;
      if ((sscanf(argv[idx], "%d", &max_uid) != 1) || (max_uid < 0)) {
        lcmaps_log(0, "%s: Unable to convert max UID argument %s to an integer\n", logstr, argv[idx]);
        return LCMAPS_MOD_FAIL;
      }
      lcmaps_log(4, "%s: Max UID: %d.\n", logstr, max_uid);
    } else if ((strncasecmp(argv[idx], LOCKPATH_ARG, strlen(LOCKPATH_ARG)) == 0) && ((idx+1) < argc)) {
      idx++;
      lockdir = strdup(argv[idx]);
      if (lockdir == NULL) {
        lcmaps_log(0, "%s: Unable to allocate memory for lockdir\n", logstr);
        return LCMAPS_MOD_FAIL;
      }
      lcmaps_log(4, "%s: Lock directory: %s.\n", logstr, lockdir);
    } else {
      lcmaps_log(0, "%s: Invalid plugin option: %s\n", logstr, argv[idx]);
      return LCMAPS_MOD_FAIL;
    }
  }
  if (lockdir == NULL)
    lockdir = strdup(LOCKPATH_DEFAULT);
  if (lockdir == NULL) {
    lcmaps_log(0, "%s: Unable to allocate memory for lockdir\n", logstr);
    return LCMAPS_MOD_FAIL;
  }

  if (min_uid == UID_DEFAULT) {
    lcmaps_log(0, "%s: %s argument is not set!\n", logstr, MINUID_ARG);
    return LCMAPS_MOD_FAIL;
  }
  if (max_uid == UID_DEFAULT) {
    lcmaps_log(0, "%s: %s argument is not set!\n", logstr, MAXUID_ARG);
    return LCMAPS_MOD_FAIL;
  }
  if (min_uid <= SYSTEM_UID) {
    lcmaps_log(0, "%s: %s argument cannot be less than %d to avoid possible"
      " system accounts.\n", logstr, MINUID_ARG, SYSTEM_UID);
    return LCMAPS_MOD_FAIL;
  }
  if (max_uid < min_uid) {
    lcmaps_log(0, "%s: %s argument must be greater than or equal to %s\n",
      logstr, MINUID_ARG, MAXUID_ARG);
    return LCMAPS_MOD_FAIL;
  }

  lcmaps_log(5, "%s: UID pool range: %d-%d, inclusive.\n", logstr, min_uid, max_uid);

  return LCMAPS_MOD_SUCCESS;

}


/******************************************************************************
Function:   plugin_introspect
Description:
    return list of required arguments
Parameters:

Returns:
    LCMAPS_MOD_SUCCESS : success
******************************************************************************/
int plugin_introspect(int *argc, lcmaps_argument_t **argv)
{
  static lcmaps_argument_t argList[] = {
    {NULL        ,  NULL    , -1, NULL}
  };

  *argv = argList;
  *argc = lcmaps_cntArgs(argList);

  return LCMAPS_MOD_SUCCESS;
}




/******************************************************************************
Function:   plugin_run
Description:
    Try to lock a UID out of the pool for this glexec invocation.
Parameters:
    argc: number of arguments
    argv: list of arguments
Returns:
    LCMAPS_MOD_SUCCESS: authorization succeeded
    LCMAPS_MOD_FAIL   : authorization failed
******************************************************************************/
int plugin_run(int argc, lcmaps_argument_t *argv)
{

// Open the directory, do basic permission checks.
  int dir_fd = open_lockdir();
  if (dir_fd == -1) {
    goto opendir_failed;
  }

  char * account_name = NULL;
  char * account_hash = NULL, *account_lock = NULL;
  int account_uid = -1;
  int account_gid = -1;
  int new_fd = select_account(dir_fd, &account_name, &account_lock, &account_hash, &account_uid, &account_gid);
  if (new_fd == -1) {
    goto select_account_failed;
  }

  lcmaps_log_time(0, "%s: Assigning %s to glexec invocation from pool accounts.\n", logstr, account_name);
  free(account_name);
  addCredentialData(UID, &account_uid);
  addCredentialData(PRI_GID, &account_gid);

  if (ftruncate(new_fd, 0) == -1) {
    lcmaps_log(0, "%s: Unable to truncate lock file (errno=%d, %s).\n", logstr, errno, strerror(errno));
    goto truncate_failed;
  }

  int nleft, nwritten;
  nleft = strlen(account_hash);
  lcmaps_log(5, "%s: Will write the following to the lockfile %s: %s (len %d)\n", logstr, account_lock, account_hash, strlen(account_hash));
  lseek(new_fd, 0, SEEK_SET);
  char * ptr = account_hash;
  while (nleft > 0) {
    nwritten = write(new_fd, ptr, nleft);
    if (nwritten < 0) {
      if (errno == EINTR) {
        continue;
      }
      lcmaps_log(0, "%s: Error when writing into the lockfile %s (errno=%d, %s).\n", logstr, account_lock, errno, strerror(errno));
      goto write_failed;
    }
    nleft -= nwritten;
    ptr += nwritten;
  }
  close(new_fd);
  close(dir_fd);
  if (account_lock) free(account_lock);
  if (account_hash) free(account_hash);

  return LCMAPS_MOD_SUCCESS;

write_failed:
  if (account_lock)
    unlink(account_lock);
truncate_failed:
  close(new_fd);
  if (account_lock) free(account_lock);
  if (account_hash) free(account_hash);
select_account_failed:
  close(dir_fd);
opendir_failed:
  lcmaps_log_time(0, "%s: Pool accounts plugin failed.\n", logstr);

  return LCMAPS_MOD_FAIL;
}

int plugin_verify(int argc, lcmaps_argument_t * argv)
{
    return plugin_run(argc, argv);
}

/******************************************************************************
Function:   plugin_terminate
Description:
    Terminate plugin.  Boilerplate - doesn't do anything
Parameters:

Returns:
    LCMAPS_MOD_SUCCESS : success
******************************************************************************/
int plugin_terminate()
{
  if (lockdir)
    free(lockdir);

  return LCMAPS_MOD_SUCCESS;
}
