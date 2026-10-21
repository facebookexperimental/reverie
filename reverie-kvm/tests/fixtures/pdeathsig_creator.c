/* Actual creator THREAD death; its process leader survives and joins it.
 * Enrollment permits regular-file handshakes, not pipe I/O. No sleeps or
 * ready-before-pause claim: controlled parked modes require the Tool's
 * actual original-syscall callback witness before creator SYS_exit.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* The uid a signal from this process carries: its own. KVM leaves getuid to
   the Tool (Detcore) and refuses it in a run without one, and its signals
   then carry uid 0. errno is preserved, as this may run in a signal handler. */
static uid_t sender_uid(void) {
  int saved = errno;
  long uid = syscall(SYS_getuid);
  uid_t result = uid == -1 && errno == ENOSYS ? 0 : (uid_t)uid;
  errno = saved;
  return result;
}

static int record_fd;
static int mode;
static int resumed;
static pid_t parent_pid;
static uid_t parent_uid;
static pid_t child_pid;
static pid_t creator_tid;
static volatile sig_atomic_t calls;
static volatile sig_atomic_t valid_info;

static void fail(int code) { _exit(code); }
static void store(off_t offset, char value) {
  if (pwrite(record_fd, &value, 1, offset) != 1) fail(30);
}
static void await(off_t offset) {
  char value;
  do {
    if (pread(record_fd, &value, 1, offset) != 1) fail(31);
    if (!value) syscall(SYS_sched_yield);
  } while (!value);
}
static void caught(int signal, siginfo_t *info, void *context) {
  (void)context;
  ++calls;
  valid_info = signal == SIGUSR1 && info->si_signo == SIGUSR1 &&
      info->si_errno == 0 && info->si_code == SI_USER &&
      info->si_pid == parent_pid && info->si_uid == parent_uid;
}
static void recipient(void) {
  sigset_t one;
  sigemptyset(&one);
  sigaddset(&one, SIGUSR1);
  /* A blocked ignored signal is retained by Linux at generation. An
   * unblocked ignored signal is discarded (or observed and then ignored by
   * a tracing Tool); installing a later handler must not resurrect it. */
  if (mode == 4 && sigprocmask(SIG_BLOCK, &one, 0)) fail(33);
  if (mode == 5 && sigprocmask(SIG_UNBLOCK, &one, 0)) fail(33);
  if (mode == 6 && !resumed && sigprocmask(SIG_BLOCK, &one, 0)) fail(33);
  if (resumed) {
    sigset_t inherited;
    struct sigaction previous;
    if (sigprocmask(SIG_SETMASK, 0, &inherited) ||
        sigismember(&inherited, SIGUSR1) != 1 ||
        sigaction(SIGUSR1, 0, &previous) || previous.sa_handler != SIG_DFL) fail(47);
  }
  struct sigaction action = {0};
  action.sa_sigaction = caught;
  action.sa_flags = SA_SIGINFO;
  if (mode == 4 || mode == 5) {
    action.sa_handler = SIG_IGN;
    action.sa_flags = 0;
  }
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGUSR1, &action, 0)) fail(32);
  if (mode <= 1 && sigprocmask(SIG_BLOCK, &one, 0)) fail(33);
  if (!resumed && prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0)) fail(34);
  int setting = -1;
  if (prctl(PR_GET_PDEATHSIG, &setting, 0, 0, 0) || setting != SIGUSR1) fail(35);
  if (mode == 1 && prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0)) fail(36);
  if (mode == 6 && !resumed) {
    char fd_arg[32], pid_arg[32], uid_arg[32];
    if (snprintf(fd_arg, sizeof(fd_arg), "%d", record_fd) <= 0 ||
        snprintf(pid_arg, sizeof(pid_arg), "%d", parent_pid) <= 0 ||
        snprintf(uid_arg, sizeof(uid_arg), "%u", parent_uid) <= 0) fail(48);
    /* Enrolled exec admits only the authenticated retained static image,
     * not a fresh pathname open after a Tool's metadata side effects. */
    execl("/proc/self/exe", "/proc/self/exe", "6", "resumed", fd_arg, pid_arg, uid_arg, (char *)0);
    fail(49);
  }
  store(0, 1);

  if (mode <= 1) {
    /* The surviving leader writes this only AFTER pthread_join(creator).
     * A dropped publication therefore fails sigpending, not a timeout. */
    await(1);
    sigset_t pending;
    if (sigpending(&pending) || calls != 0 ||
        sigismember(&pending, SIGUSR1) != (mode == 0)) fail(37);
    if (sigprocmask(SIG_UNBLOCK, &one, 0)) fail(38);
    if (calls != (mode == 0) || valid_info != (mode == 0)) fail(39);
  } else if (mode == 4 || mode == 5) {
    /* The leader releases only after joining the creator. In controlled
     * mode the second sigaction hook additionally asserts the real ignored
     * dequeue/NoHandler receipt already exists before replacing SIG_IGN;
     * syscall frequency is not taken as proof of observer completion. */
    await(1);
    sigset_t pending;
    if (sigpending(&pending) || calls != 0 || valid_info != 0 ||
        sigismember(&pending, SIGUSR1) != (mode == 4)) fail(42);
    action.sa_sigaction = caught;
    action.sa_flags = SA_SIGINFO;
    if (sigaction(SIGUSR1, &action, 0) || calls != 0) fail(43);
    if (sigprocmask(SIG_UNBLOCK, &one, 0)) fail(44);
    if (calls != (mode == 4) || valid_info != (mode == 4)) fail(45);
    if (sigpending(&pending) || sigismember(&pending, SIGUSR1) != 0) fail(46);
  } else if (mode == 6) {
    if (!resumed) fail(50);
    await(1);
    sigset_t pending;
    if (sigpending(&pending) || sigismember(&pending, SIGUSR1) != 1 ||
        calls != 0 || valid_info != 0) fail(51);
    if (sigprocmask(SIG_UNBLOCK, &one, 0)) fail(52);
    if (calls != 1 || valid_info != 1) fail(53);
  } else {
    /* Only run these modes with the observing Tool, which keeps the creator
     * alive until this exact pause/nanosleep callback is Pending. */
    errno = 0;
    long result;
    if (mode == 2) {
      result = syscall(SYS_pause);
    } else {
      const struct timespec requested = {60, 0};
      result = syscall(SYS_nanosleep, &requested, 0);
    }
    if (result != -1 || errno != EINTR || calls != 1 || valid_info != 1) fail(40);
  }
  if (getppid() != parent_pid) fail(41);
  store(2, 1);
  _exit(0);
}
static void *creator(void *unused) {
  (void)unused;
  creator_tid = (pid_t)syscall(SYS_gettid);
  if (creator_tid <= 0 || creator_tid == parent_pid) fail(19);
  child_pid = fork();
  if (child_pid < 0) fail(20);
  if (child_pid == 0) recipient();
  await(0);
  /* pthread return reaches real SYS_exit of this nonleader, not exit_group. */
  return 0;
}
int main(int argc, char **argv) {
  if (argc == 6 && !strcmp(argv[1], "6") && !strcmp(argv[2], "resumed")) {
    mode = 6; resumed = 1;
    record_fd = atoi(argv[3]); parent_pid = (pid_t)atoi(argv[4]);
    parent_uid = (uid_t)strtoul(argv[5], 0, 10);
    recipient();
    fail(54);
  }
  if (argc != 2) return 10;
  mode = atoi(argv[1]);
  if (mode < 0 || mode > 6) return 11;
  parent_pid = getpid(); parent_uid = sender_uid();
  record_fd = open("creator.record", O_CREAT | O_TRUNC | O_RDWR, 0600);
  if (record_fd < 0 || ftruncate(record_fd, 3)) return 12;
  pthread_t worker;
  if (pthread_create(&worker, 0, creator, 0)) return 13;
  if (pthread_join(worker, 0)) return 14;
  /* Linux clears the pthread join word in exit_mm/mm_release, before
   * exit_notify generates the parent-death signal. Complete task retirement
   * is the causal witness: PID lookup removal follows forget_original_parent.
   * No new thread is created in this TGID, so a reused numeric TID cannot be
   * mistaken for this creator. This is not a retry of the pending assertion.
   * Keep the existing outer test deadline; no sleeps or new timeout.
   */
  for (;;) {
    errno = 0;
    long exists = syscall(SYS_tgkill, parent_pid, creator_tid, 0);
    if (exists == -1 && errno == ESRCH) break;
    if (exists != 0) return 19;
    syscall(SYS_sched_yield);
  }
  store(1, 1);
  int status = 0;
  if (waitpid(child_pid, &status, 0) != child_pid ||
      !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    fprintf(stderr, "recipient status=%d\n", status);
    return 15;
  }
  char completed = 0;
  if (pread(record_fd, &completed, 1, 2) != 1 || completed != 1) return 16;
  if (close(record_fd)) return 17;
  printf("pdeathsig creator-thread mode=%d parent-alive=1 child-completed=1\n", mode);
  return 0;
}
