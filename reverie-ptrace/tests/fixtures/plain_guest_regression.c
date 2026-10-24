/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Guest for the plain ptrace regression tests
 * (reverie-ptrace/src/plain_guest_regression_tests.rs).
 *
 * Usage: plain_guest_regression <mode> <report-file>
 *
 * Every observation is appended to the report file as text. Absolute
 * addresses are comparable because the tracer disables address
 * randomisation. PID values are never printed.
 *
 * `tp_site` is a shared generic syscall site: `tp_site_fn(nr, a1..a6)` issues
 * one `syscall` there. A call whose sixth argument (r9) carries TP_MAGIC asks
 * the test Tool for a handler shape or for tracer-side signals (see the Rust
 * side).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#define TP_MAGIC 0x7e57000000000000L
/* Handler shapes (low byte) and tracer actions, decoded by the test Tool. */
#define SHAPE_INJECT 0
#define SHAPE_TAIL 1
#define SHAPE_EMULATE 2
#define SHAPE_PRIVATE 3
#define SHAPE_TWO_INJECTS 4
#define SHAPE_TWO_PRIVATE 5
#define SHAPE_BLOCK_ALL 6
#define SHAPE_PRIVATE_CALL 7
#define SHAPE_PPOLL_THEN_CALL 8
#define SEND_SIGUSR1 0x100
#define SEND_SIGWINCH 0x200
#define SEND_QUEUE 0x400
/* The tracer leaves SIGUSR1 pending for its final resume of the stop. */
#define SEND_RESUME 0x800
/* The Tool requests a precise timer of a5 (r8) branches at this stop. */
#define ARM_TIMER 0x1000
/* The Tool sends SIGSTOP to the calling thread at this stop. */
#define SEND_SIGSTOP 0x2000
#define CHECK_KERNEL_PPID 0x8000

long tp_site_fn(long nr, long a1, long a2, long a3, long a4, long a5, long a6);
extern char tp_site[], tp_site_end[];
/* rcx and r11 right after `syscall` at tp_site, split by whether the call
 * returned zero (a new child) or not (a parent or any other result). */
long tp_nz_rcx, tp_nz_r11, tp_z_rcx, tp_z_r11;

__asm__(
    ".pushsection .text\n"
    ".globl tp_site_fn\n"
    ".type tp_site_fn, @function\n"
    "tp_site_fn:\n"
    "  mov %rdi, %rax\n"
    "  mov %rsi, %rdi\n"
    "  mov %rdx, %rsi\n"
    "  mov %rcx, %rdx\n"
    "  mov %r8, %r10\n"
    "  mov %r9, %r8\n"
    "  mov 8(%rsp), %r9\n"
    /* Fix the arithmetic flags, so that r11 (rflags at the syscall) does
     * not inherit the caller's `sub $8, %rsp`, whose parity follows the
     * randomized stack address. */
    "  cmp %rax, %rax\n"
    ".globl tp_site\n"
    "tp_site:\n"
    "  syscall\n"
    ".globl tp_site_end\n"
    "tp_site_end:\n"
    /* Clear the tag, so that a later libc call does not carry it. */
    "  xor %r9d, %r9d\n"
    "  test %rax, %rax\n"
    "  jz 1f\n"
    "  mov %rcx, tp_nz_rcx(%rip)\n"
    "  mov %r11, tp_nz_r11(%rip)\n"
    "  ret\n"
    "1:\n"
    "  mov %rcx, tp_z_rcx(%rip)\n"
    "  mov %r11, tp_z_r11(%rip)\n"
    "  ret\n"
    ".size tp_site_fn, .-tp_site_fn\n"
    ".popsection\n");

/* A site that loads rcx/r11 sentinels immediately before `syscall` and
 * captures both right after it. rdi = nr, rsi = 1 to set DF, 2 to set AC. */
long t8_rcx, t8_r11;
long t8_fn(long nr, long flags);
extern char t8_site[], t8_site_end[];
__asm__(
    ".pushsection .text\n"
    ".globl t8_fn\n"
    ".type t8_fn, @function\n"
    "t8_fn:\n"
    "  mov %rdi, %rax\n"
    "  cmp $1, %rsi\n"
    "  jne 2f\n"
    "  std\n"
    "2:\n"
    "  cmp $2, %rsi\n"
    "  jne 3f\n"
    "  pushf\n"
    "  orl $0x40000, (%rsp)\n"
    "  popf\n"
    "3:\n"
    "  mov $0x1111, %rcx\n"
    "  mov $0x2222, %r11\n"
    ".globl t8_site\n"
    "t8_site:\n"
    "  syscall\n"
    ".globl t8_site_end\n"
    "t8_site_end:\n"
    "  mov %rcx, t8_rcx(%rip)\n"
    "  mov %r11, t8_r11(%rip)\n"
    "  cld\n"
    "  pushf\n"
    "  andl $0xfffbffff, (%rsp)\n"
    "  popf\n"
    "  ret\n"
    ".size t8_fn, .-t8_fn\n"
    ".popsection\n");

/* Five more generic sites, `tp_genN_fn(nr)`, one per unknown-number case,
 * so that each case runs through a warmed site of its own. */
long tp_gen_rcx, tp_gen_r11;
#define GEN_SITE(n)                \
  ".globl tp_gen" #n               \
  "_fn\n"                          \
  ".type tp_gen" #n                \
  "_fn, @function\n"               \
  "tp_gen" #n                      \
  "_fn:\n"                         \
  "  mov %rdi, %rax\n"             \
  "  cmp %rax, %rax\n"             \
  ".globl tp_gen" #n               \
  "\n"                             \
  "tp_gen" #n                      \
  ":\n"                            \
  "  syscall\n"                    \
  "  mov %rcx, tp_gen_rcx(%rip)\n" \
  "  mov %r11, tp_gen_r11(%rip)\n" \
  "  ret\n"                        \
  ".size tp_gen" #n "_fn, .-tp_gen" #n "_fn\n"
long tp_gen0_fn(long nr), tp_gen1_fn(long nr), tp_gen2_fn(long nr),
    tp_gen3_fn(long nr), tp_gen4_fn(long nr);
extern char tp_gen0[], tp_gen1[], tp_gen2[], tp_gen3[], tp_gen4[];
__asm__(".pushsection .text\n" GEN_SITE(0) GEN_SITE(1) GEN_SITE(2) GEN_SITE(3)
            GEN_SITE(4) ".popsection\n");

/* A signal restorer that runs rt_sigreturn through the shared site. */
void tp_restorer(void);
__asm__(
    ".pushsection .text\n"
    ".globl tp_restorer\n"
    ".type tp_restorer, @function\n"
    "tp_restorer:\n"
    "  mov $15, %eax\n"
    "  jmp tp_site\n"
    ".size tp_restorer, .-tp_restorer\n"
    ".popsection\n");

#define SITE(nr, a1, a2, a3, a4, a5) \
  tp_site_fn(                        \
      (long)(nr),                    \
      (long)(a1),                    \
      (long)(a2),                    \
      (long)(a3),                    \
      (long)(a4),                    \
      (long)(a5),                    \
      0)
/* r9 carries TP_MAGIC, a sequence number (bits 16-47) and the action. The
 * sequence number lets the tool act once per call even when the kernel
 * restarts it. */
static long tp_seq;
#define SITEM(nr, a1, a2, a3, a4, a5, act) \
  tp_site_fn(                              \
      (long)(nr),                          \
      (long)(a1),                          \
      (long)(a2),                          \
      (long)(a3),                          \
      (long)(a4),                          \
      (long)(a5),                          \
      TP_MAGIC | ((++tp_seq) << 16) | (act))

static int report_fd = -1;
static char** main_argv;
extern char** environ;

static void say(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vdprintf(report_fd, fmt, ap);
  va_end(ap);
}

static void die(const char* what) {
  say("FATAL %s errno=%d\n", what, errno);
  _exit(99);
}

static const char* where(long rip) {
  static char buf[64];
  if (rip == (long)tp_site_end)
    return "tp_site_end";
  if (rip == (long)tp_site)
    return "tp_site";
  if (rip == (long)t8_site_end)
    return "t8_site_end";
  /* The fixture is linked -no-pie: its own text addresses are the same in
   * every run, while library and stack addresses are not. */
  if (rip >= 0x400000 && rip < 0x1000000) {
    snprintf(buf, sizeof buf, "%#lx", rip);
    return buf;
  }
  return "other";
}

/* Warms tp_site: runs getpid through it three times. */
static void warm(void) {
  for (int i = 0; i < 3; i++) {
    if (SITE(SYS_getpid, 0, 0, 0, 0, 0) != getpid())
      die("warm getpid");
  }
}

struct rec {
  int sig, code, value;
  long rip, rax, rcx, r11, trapno, err;
};
static struct rec recs[64];
static volatile int nrec;

static void handler(int sig, siginfo_t* si, void* uc_) {
  ucontext_t* uc = uc_;
  if (nrec >= 64)
    return;
  struct rec* r = &recs[nrec++];
  r->sig = sig;
  r->code = si->si_code;
  r->value = si->si_code == SI_QUEUE ? si->si_value.sival_int : -1;
  r->rip = uc->uc_mcontext.gregs[REG_RIP];
  r->rax = uc->uc_mcontext.gregs[REG_RAX];
  r->rcx = uc->uc_mcontext.gregs[REG_RCX];
  r->r11 = uc->uc_mcontext.gregs[REG_R11];
  r->trapno = uc->uc_mcontext.gregs[REG_TRAPNO];
  r->err = uc->uc_mcontext.gregs[REG_ERR];
}

static int restart_pipe_wr = -1;
static int* restart_futex;

/* The same recorder, plus the side effects that let a restarted call finish. */
static void restart_handler(int sig, siginfo_t* si, void* uc) {
  handler(sig, si, uc);
  if (restart_pipe_wr >= 0) {
    char c = 'x';
    if (write(restart_pipe_wr, &c, 1) != 1)
      _exit(98);
  }
  if (restart_futex)
    *restart_futex = 1;
}

static void install(int sig, int flags, void (*fn)(int, siginfo_t*, void*)) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = fn;
  sa.sa_flags = SA_SIGINFO | flags;
  sigemptyset(&sa.sa_mask);
  if (sigaction(sig, &sa, NULL) != 0)
    die("sigaction");
}

static void dump(const char* tag) {
  long pid = getpid();
  for (int i = 0; i < nrec; i++) {
    struct rec* r = &recs[i];
    char rax[32];
    if (r->rax == pid)
      snprintf(rax, sizeof rax, "<pid>");
    else
      snprintf(rax, sizeof rax, "%ld", r->rax);
    say("%s %d: sig=%d code=%d value=%d rip=%s rax=%s rcx=%s",
        tag,
        i,
        r->sig,
        r->code,
        r->value,
        where(r->rip),
        rax,
        where(r->rcx));
    say(" r11=%#lx trapno=%ld err=%ld\n", r->r11, r->trapno, r->err);
  }
  nrec = 0;
}

static void report_result(const char* tag, long r) {
  say("%s ret=%ld errno=%d rcx=%s r11=%#lx\n",
      tag,
      r,
      r < 0 && r > -4096 ? (int)-r : 0,
      where(r == 0 ? tp_z_rcx : tp_nz_rcx),
      r == 0 ? tp_z_r11 : tp_nz_r11);
}

static void site_bytes(const char* tag) {
  unsigned char* p = (unsigned char*)tp_site;
  say("%s site bytes %02x %02x\n", tag, p[0], p[1]);
}

/* A signal sent while a call at the site is parked at its stop. */
static void mode_sig_pending(void) {
  install(SIGUSR1, 0, handler);
  warm();
  long r = SITEM(SYS_getpid, 0, 0, 0, 0, 0, SHAPE_INJECT | SEND_SIGUSR1);
  say("getpid returned pid=%d\n", r == getpid());
  dump("sig_pending");
  r = SITEM(SYS_getpid, 0, 0, 0, 0, 0, SHAPE_TAIL | SEND_SIGUSR1);
  say("tail getpid returned pid=%d\n", r == getpid());
  dump("sig_pending_tail");
}

/* A clone without CLONE_THREAD and with exit signal 0 is reported as a clone
 * event, but it is its own process. The Tool signals a parked call by its
 * process and thread id, so the signal reaches this child only if the Tool
 * sees the child's own process id. */
static int raw_clone_process_child(void* arg) {
  (void)arg;
  int before = nrec;
  long r = SITEM(SYS_getpid, 0, 0, 0, 0, 0, SHAPE_INJECT | SEND_SIGUSR1);
  int got = nrec == before + 1 && recs[before].sig == SIGUSR1;
  return r == getpid() && got ? 7 : 1;
}

static char raw_clone_stack[64 * 1024] __attribute__((aligned(16)));

static void mode_raw_clone_process(void) {
  install(SIGUSR1, 0, handler);
  warm();
  int c = clone(
      raw_clone_process_child,
      raw_clone_stack + sizeof raw_clone_stack,
      0,
      NULL);
  if (c < 0)
    die("clone without CLONE_THREAD");
  int status;
  if (waitpid(c, &status, __WCLONE) != c)
    die("waitpid raw clone");
  say("raw clone child status exited=%d code=%d\n",
      WIFEXITED(status),
      WEXITSTATUS(status));
}

/* A CLONE_PARENT raw clone whose Tool-side parent must be the root, as the
 * kernel's getppid says, not its creator. The creator stays alive on a pipe
 * until the tagged child's getppid completes, so no timing is involved. */
static int clone_parent_ppid_child(void* arg) {
  int fd = (int)(intptr_t)arg;
  long actual = SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_INJECT | CHECK_KERNEL_PPID);
  if (actual <= 0 || write(fd, "x", 1) != 1)
    return 92;
  close(fd);
  return 7;
}

static char clone_parent_ppid_stack[64 * 1024] __attribute__((aligned(16)));

static void mode_raw_clone_parent_ppid(void) {
  warm();
  int release[2];
  if (pipe(release) != 0)
    die("clone parent pipe");
  pid_t creator = fork();
  if (creator < 0)
    die("clone parent fork");
  if (creator == 0) {
    int child = clone(clone_parent_ppid_child,
        clone_parent_ppid_stack + sizeof clone_parent_ppid_stack,
        CLONE_PARENT | SIGUSR1, (void*)(intptr_t)release[1]);
    if (child <= 0)
      _exit(93);
    close(release[1]);
    char byte = 0;
    int got = read(release[0], &byte, 1) == 1 && byte == 'x';
    _exit(got ? 11 : 94);
  }
  close(release[0]);
  close(release[1]);
  int checked_child = 0;
  int checked_creator = 0;
  for (int i = 0; i < 2; i++) {
    int status = 0;
    pid_t got = waitpid(-1, &status, __WALL);
    if (got <= 0 || !WIFEXITED(status))
      die("clone parent wait");
    if (got == creator && WEXITSTATUS(status) == 11)
      checked_creator++;
    else if (got != creator && WEXITSTATUS(status) == 7)
      checked_child++;
    else
      _exit(95);
  }
  say("clone parent checked child=%d creator=%d\n", checked_child, checked_creator);
}

/* Queued thread- and process-directed signals (standard signals only; see
 * the Rust side). */
static void mode_rt_queue(void) {
  int sigs[] = {SIGUSR1, SIGUSR2, SIGHUP, SIGALRM, SIGURG, SIGTERM};
  for (unsigned i = 0; i < sizeof sigs / sizeof sigs[0]; i++)
    install(sigs[i], 0, handler);
  warm();
  long r = SITEM(SYS_getpid, 0, 0, 0, 0, 0, SHAPE_INJECT | SEND_QUEUE);
  say("getpid returned pid=%d\n", r == getpid());
  dump("queue");
  r = SITEM(SYS_getpid, 0, 0, 0, 0, 0, SHAPE_TAIL | SEND_QUEUE);
  say("tail getpid returned pid=%d\n", r == getpid());
  dump("queue_tail");
}

/* Signals the call at the site raises itself. */
static void mode_self_raise(void) {
  install(SIGUSR1, 0, handler);
  install(SIGPIPE, 0, handler);
  install(SIGUSR2, 0, handler);
  warm();
  long r = SITE(SYS_kill, getpid(), SIGUSR1, 0, 0, 0);
  report_result("kill", r);
  dump("kill");
  int fds[2];
  if (pipe(fds) != 0)
    die("pipe");
  close(fds[0]);
  char c = 'p';
  r = SITE(SYS_write, fds[1], &c, 1, 0, 0);
  report_result("write-epipe", r);
  dump("sigpipe");
  close(fds[1]);
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR2);
  if (sigprocmask(SIG_BLOCK, &set, NULL) != 0)
    die("block");
  raise(SIGUSR2);
  r = SITE(SYS_rt_sigprocmask, SIG_UNBLOCK, &set, NULL, 8, 0);
  report_result("unblock", r);
  dump("unblock");
}

static void sigtrap_state(const char* tag) {
  struct sigaction sa;
  sigset_t set;
  if (sigaction(SIGTRAP, NULL, &sa) != 0 ||
      sigprocmask(SIG_SETMASK, NULL, &set) != 0)
    die("read sigtrap state");
  const char* disp = sa.sa_handler == SIG_IGN ? "ign"
      : sa.sa_handler == SIG_DFL              ? "dfl"
                                              : "fn";
  say("%s sigtrap=%s blocked=%d\n", tag, disp, sigismember(&set, SIGTRAP));
  raise(SIGUSR1);
  dump(tag);
}

static void sigtrap_reset(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = SIG_IGN;
  if (sigaction(SIGTRAP, &sa, NULL) != 0)
    die("ignore sigtrap");
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGTRAP);
  if (sigprocmask(SIG_BLOCK, &set, NULL) != 0)
    die("block sigtrap");
}

/* The SIGTRAP disposition, mask and trap number each handler shape leaves. */
static void mode_sigtrap_profile(void) {
  install(SIGUSR1, 0, handler);
  for (int i = 0; i < 3; i++)
    SITE(SYS_getppid, 0, 0, 0, 0, 0);
  static const struct {
    const char* name;
    long shape;
  } shapes[] = {
      {"inject", SHAPE_INJECT},
      {"tail", SHAPE_TAIL},
      {"emulate", SHAPE_EMULATE},
      {"private", SHAPE_PRIVATE},
      {"two-injects", SHAPE_TWO_INJECTS},
      {"two-private", SHAPE_TWO_PRIVATE},
  };
  for (unsigned i = 0; i < sizeof shapes / sizeof shapes[0]; i++) {
    sigtrap_reset();
    long r = SITEM(SYS_getppid, 0, 0, 0, 0, 0, shapes[i].shape);
    say("%s getppid=%s\n",
        shapes[i].name,
        r == getppid()      ? "ppid"
            : r == getpid() ? "pid"
            : r == 4242     ? "4242"
                            : "other");
    sigtrap_state(shapes[i].name);
  }
}

static void trap_handler(int sig) {
  (void)sig;
}

/* SIGTRAP's whole action and mask bit, as a line that names the handler,
 * the flags this mode sets and whether sa_mask holds SIGUSR2. */
static void sigtrap_full_state(const char* tag) {
  struct sigaction sa;
  sigset_t set;
  if (sigaction(SIGTRAP, NULL, &sa) != 0 ||
      sigprocmask(SIG_SETMASK, NULL, &set) != 0)
    die("read sigtrap state");
  const char* disp = sa.sa_handler == SIG_IGN    ? "ign"
      : sa.sa_handler == SIG_DFL                 ? "dfl"
      : sa.sa_handler == trap_handler            ? "trap_handler"
                                                 : "other";
  say("%s sigtrap=%s flags=%#lx usr2-in-mask=%d blocked=%d\n",
      tag,
      disp,
      (unsigned long)(sa.sa_flags & (SA_RESTART | SA_NODEFER)),
      sigismember(&sa.sa_mask, SIGUSR2),
      sigismember(&set, SIGTRAP));
}

static void sigtrap_set(void (*action)(int), int block) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = action;
  sa.sa_flags = SA_RESTART | SA_NODEFER;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGUSR2);
  if (sigaction(SIGTRAP, &sa, NULL) != 0)
    die("set sigtrap");
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGTRAP);
  if (sigprocmask(block ? SIG_BLOCK : SIG_UNBLOCK, &set, NULL) != 0)
    die("mask sigtrap");
}

/* Each SIGTRAP state through each handler shape: natively the call leaves
 * the action (handler, flags, mask) and the mask bit as they were
 * (https://github.com/rrnewton/hermit/issues/4409). */
static void mode_sigtrap_states(void) {
  for (int i = 0; i < 3; i++)
    SITE(SYS_getppid, 0, 0, 0, 0, 0);
  static const struct {
    const char* name;
    void (*action)(int);
    int block;
  } states[] = {
      {"ign-blocked", SIG_IGN, 1},
      {"ign", SIG_IGN, 0},
      {"handler-blocked", trap_handler, 1},
      {"handler", trap_handler, 0},
      {"dfl-blocked", SIG_DFL, 1},
  };
  static const struct {
    const char* name;
    long shape;
  } shapes[] = {
      {"inject", SHAPE_INJECT},
      {"tail", SHAPE_TAIL},
      {"emulate", SHAPE_EMULATE},
      {"private", SHAPE_PRIVATE},
      {"two-injects", SHAPE_TWO_INJECTS},
      {"two-private", SHAPE_TWO_PRIVATE},
      {"block-all", SHAPE_BLOCK_ALL},
  };
  for (unsigned i = 0; i < sizeof states / sizeof states[0]; i++) {
    for (unsigned j = 0; j < sizeof shapes / sizeof shapes[0]; j++) {
      sigtrap_set(states[i].action, states[i].block);
      SITEM(SYS_getppid, 0, 0, 0, 0, 0, shapes[j].shape);
      char tag[64];
      snprintf(tag, sizeof tag, "%s %s", states[i].name, shapes[j].name);
      sigtrap_full_state(tag);
    }
  }
}

static void exec_self(const char* mode);

static void segv_handler(int sig) {
  (void)sig;
}

/* SIGSEGV's whole action and mask bit, as sigtrap_full_state reports
 * SIGTRAP's. */
static void segv_full_state(const char* tag) {
  struct sigaction sa;
  sigset_t set;
  if (sigaction(SIGSEGV, NULL, &sa) != 0 ||
      sigprocmask(SIG_SETMASK, NULL, &set) != 0)
    die("read sigsegv state");
  const char* disp = sa.sa_handler == SIG_IGN ? "ign"
      : sa.sa_handler == SIG_DFL              ? "dfl"
      : sa.sa_handler == segv_handler         ? "segv_handler"
                                              : "other";
  say("%s sigsegv=%s flags=%#lx usr2-in-mask=%d blocked=%d\n",
      tag,
      disp,
      (unsigned long)(sa.sa_flags & (SA_RESTART | SA_NODEFER | SA_RESETHAND)),
      sigismember(&sa.sa_mask, SIGUSR2),
      sigismember(&set, SIGSEGV));
}

static void segv_set(void (*action)(int), int block) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = action;
  sa.sa_flags = SA_RESTART;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGUSR2);
  if (sigaction(SIGSEGV, &sa, NULL) != 0)
    die("set sigsegv");
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGSEGV);
  if (sigprocmask(block ? SIG_BLOCK : SIG_UNBLOCK, &set, NULL) != 0)
    die("mask sigsegv");
}

/* rdtsc (0) or cpuid (1), each of which the tracer traps with a SIGSEGV
 * where it can (cpuid only where the CPU can fault it). */
static void segv_trapped_instruction(int cpuid) {
  if (cpuid) {
    unsigned a = 0, b, c = 0, d;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
    (void)b;
    (void)d;
  } else {
    unsigned lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    (void)lo;
    (void)hi;
  }
}

static char segv_handler_tag[64];

/* A SIGUSR1 handler whose first instruction is a trapped rdtsc: SIGSEGV is
 * in its sa_mask, so the handler runs with it blocked whatever the mask
 * before, and no stop comes between the delivery and the trap. */
static void segv_usr1_handler(int sig) {
  (void)sig;
  segv_trapped_instruction(0);
  segv_full_state(segv_handler_tag);
}

/* Each SIGSEGV state through a trapped rdtsc, a trapped cpuid, a trapped
 * rdtsc first thing in a handler, and a trapped rdtsc after the handler's
 * rt_sigreturn with no syscall between. Natively neither instruction faults,
 * so the action and the mask bit stay as they were
 * (https://github.com/rrnewton/hermit/issues/4485). */
static void mode_segv_states(void) {
  static const struct {
    const char* name;
    void (*action)(int);
    int block;
  } states[] = {
      {"ign", SIG_IGN, 0},
      {"ign-blocked", SIG_IGN, 1},
      {"handler", segv_handler, 0},
      {"handler-blocked", segv_handler, 1},
      {"dfl", SIG_DFL, 0},
      {"dfl-blocked", SIG_DFL, 1},
  };
  struct sigaction usr1;
  memset(&usr1, 0, sizeof usr1);
  usr1.sa_handler = segv_usr1_handler;
  sigemptyset(&usr1.sa_mask);
  sigaddset(&usr1.sa_mask, SIGSEGV);
  if (sigaction(SIGUSR1, &usr1, NULL) != 0)
    die("set sigusr1");
  for (unsigned i = 0; i < sizeof states / sizeof states[0]; i++) {
    char tag[64];
    for (int cpuid = 0; cpuid < 2; cpuid++) {
      segv_set(states[i].action, states[i].block);
      segv_trapped_instruction(cpuid);
      snprintf(
          tag, sizeof tag, "%s %s", states[i].name, cpuid ? "cpuid" : "rdtsc");
      segv_full_state(tag);
    }
    segv_set(states[i].action, states[i].block);
    snprintf(
        segv_handler_tag,
        sizeof segv_handler_tag,
        "%s in-handler",
        states[i].name);
    raise(SIGUSR1);
    segv_trapped_instruction(0);
    snprintf(tag, sizeof tag, "%s after-handler", states[i].name);
    segv_full_state(tag);
  }
}

/* A SIGSEGV handler whose first instruction is a trapped rdtsc: the
 * delivery blocks SIGSEGV for the handler (no SA_NODEFER), so the trap's
 * forced SIGSEGV would reset the handler being run. */
static void segv_rdtsc_handler(int sig) {
  (void)sig;
  segv_trapped_instruction(0);
  segv_full_state("segv-handler in-handler");
}

static void mode_segv_in_segv_handler(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = segv_rdtsc_handler;
  sa.sa_flags = SA_RESTART;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGUSR2);
  if (sigaction(SIGSEGV, &sa, NULL) != 0)
    die("set sigsegv");
  raise(SIGSEGV);
  segv_trapped_instruction(0);
  /* The handler is not segv_handler, so it reads as "other". */
  segv_full_state("segv-handler after-handler");
}

static const char* segv_flags_tag;

static void segv_flags_handler(int sig) {
  (void)sig;
  segv_trapped_instruction(0);
  segv_full_state(segv_flags_tag);
}

/* A SIGSEGV handler with SA_NODEFER, which runs with SIGSEGV unblocked, so
 * its trap resets nothing; and one with SA_RESETHAND, whose delivery resets
 * it to SIG_DFL before it runs with SIGSEGV blocked, so its trap unblocks
 * SIGSEGV and resets nothing more. */
static void mode_segv_handler_flags(void) {
  static const struct {
    const char* name;
    int flags;
  } cases[] = {
      {"nodefer", SA_RESTART | SA_NODEFER},
      {"resethand", SA_RESTART | SA_RESETHAND},
  };
  for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = segv_flags_handler;
    sa.sa_flags = cases[i].flags;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR2);
    if (sigaction(SIGSEGV, &sa, NULL) != 0)
      die("set sigsegv");
    char in[64], after[64];
    snprintf(in, sizeof in, "%s in-handler", cases[i].name);
    snprintf(after, sizeof after, "%s after-handler", cases[i].name);
    segv_flags_tag = in;
    raise(SIGSEGV);
    segv_trapped_instruction(0);
    segv_full_state(after);
  }
}

static void* segv_thread_main(void* arg) {
  (void)arg;
  segv_trapped_instruction(0);
  segv_full_state("thread rdtsc");
  return NULL;
}

/* A second thread's trap, on the signal-action table it shares: the
 * thread inherits the blocked mask, and its repair is the process's. */
static void mode_segv_thread(void) {
  segv_set(SIG_IGN, 1);
  pthread_t thread;
  if (pthread_create(&thread, NULL, segv_thread_main, NULL) != 0)
    die("pthread_create");
  if (pthread_join(thread, NULL) != 0)
    die("pthread_join");
  segv_full_state("thread main-after");
  segv_trapped_instruction(0);
  segv_full_state("thread main-rdtsc");
}

/* Makes a thread of this process, sharing the signal actions, that spins on
 * its own stack and makes no syscall; with CLONE_UNTRACED (argv "untraced")
 * the tracer never sees it. The process's exit ends it. */
static void segv_spinning_sharer(int untraced) {
  static char stack[16384] __attribute__((aligned(16)));
  long flags = CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | (untraced ? CLONE_UNTRACED : 0);
  long ret;
  register long r10 __asm__("r10") = 0;
  register long r8 __asm__("r8") = 0;
  __asm__ volatile(
      "syscall\n\t"
      "test %%rax, %%rax\n\t"
      "jnz 1f\n\t"
      "2: pause\n\t"
      "jmp 2b\n\t"
      "1:"
      : "=a"(ret)
      : "0"((long)SYS_clone), "D"(flags), "S"(stack + sizeof stack), "d"(0L), "r"(r10),
        "r"(r8)
      : "rcx", "r11", "memory");
  if (ret < 0)
    die("clone sharer");
}

/* An ignored SIGSEGV through a trapped rdtsc after a thread sharing the
 * actions was made: traced (kept), or with CLONE_UNTRACED, whose thread
 * could change the action unseen, so that Reverie leaves the reset as
 * before. */
static void mode_segv_sharer(void) {
  int untraced = main_argv[1][strlen(main_argv[1]) - 1] == 'u';
  segv_set(SIG_IGN, 0);
  segv_spinning_sharer(untraced);
  segv_trapped_instruction(0);
  segv_full_state(untraced ? "sharer untraced rdtsc" : "sharer traced rdtsc");
}

/* A fork child's trap, on its copy of the actions, and the parent's. */
static void mode_segv_fork(void) {
  segv_set(SIG_IGN, 1);
  pid_t child = fork();
  if (child < 0)
    die("fork");
  if (child == 0) {
    segv_trapped_instruction(0);
    segv_full_state("fork child-rdtsc");
    _exit(0);
  }
  int status;
  if (waitpid(child, &status, 0) != child)
    die("waitpid");
  segv_trapped_instruction(0);
  segv_full_state("fork parent-rdtsc");
}

/* Across exec: an ignored SIGSEGV stays ignored, a handler becomes SIG_DFL
 * with no flags or mask, and the mask is kept. The new image traps first
 * thing in its mode. */
static void mode_segv_exec(void) {
  segv_set(SIG_IGN, 1);
  exec_self("segv_after_exec_ign");
}

static void mode_segv_after_exec_ign(void) {
  segv_trapped_instruction(0);
  segv_full_state("exec ign-blocked rdtsc");
  segv_set(segv_handler, 1);
  exec_self("segv_after_exec_handler");
}

static void mode_segv_after_exec_handler(void) {
  segv_trapped_instruction(0);
  segv_full_state("exec handler-blocked rdtsc");
}

/* A clone3 child made with CLONE_CLEAR_SIGHAND, whose copy of the actions
 * is flushed: the parent's blocked handler becomes SIG_DFL with no flags or
 * mask in the child, which keeps the blocked mask. */
static void mode_segv_clear_sighand(void) {
  segv_set(segv_handler, 1);
  struct {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack,
        stack_size, tls;
  } args;
  memset(&args, 0, sizeof args);
  args.flags = 0x100000000ULL; /* CLONE_CLEAR_SIGHAND */
  args.exit_signal = SIGCHLD;
  long child = syscall(SYS_clone3, &args, sizeof args);
  if (child < 0) {
    /* Before Linux 5.5: nothing to compare. */
    say("clear-sighand unsupported\n");
    return;
  }
  if (child == 0) {
    segv_trapped_instruction(0);
    segv_full_state("clear-sighand child-rdtsc");
    _exit(0);
  }
  int status;
  if (waitpid((pid_t)child, &status, 0) != child)
    die("waitpid");
  segv_trapped_instruction(0);
  segv_full_state("clear-sighand parent-rdtsc");
}

/* A SIGUSR1 handler whose first instruction is a trapped rdtsc, with an
 * empty sa_mask: it runs under ppoll's temporary mask. */
static void segv_ppoll_handler(int sig) {
  (void)sig;
  segv_trapped_instruction(0);
  segv_full_state("ppoll in-handler");
}

/* SIGSEGV blocked, and a SIGUSR1 that ppoll's empty temporary mask lets
 * through: the handler runs with SIGSEGV unblocked, under the temporary
 * mask, though the mask ppoll restores (which PTRACE_GETSIGMASK reports
 * while the restore is pending) blocks it. Back from ppoll, a trapped rdtsc
 * runs under the restored mask. */
static void mode_segv_ppoll_handler(void) {
  segv_set(SIG_DFL, 1);
  struct sigaction usr1;
  memset(&usr1, 0, sizeof usr1);
  usr1.sa_handler = segv_ppoll_handler;
  sigemptyset(&usr1.sa_mask);
  if (sigaction(SIGUSR1, &usr1, NULL) != 0)
    die("set sigusr1");
  sigset_t block, empty;
  sigemptyset(&block);
  sigaddset(&block, SIGUSR1);
  sigemptyset(&empty);
  if (sigprocmask(SIG_BLOCK, &block, NULL) != 0)
    die("block sigusr1");
  raise(SIGUSR1);
  struct timespec timeout = {5, 0};
  int r = ppoll(NULL, 0, &timeout, &empty);
  say("ppoll returned %d errno=%d\n", r, r < 0 ? errno : 0);
  segv_trapped_instruction(0);
  segv_full_state("ppoll after");
}

static void segv_dropped_handler(int sig) {
  (void)sig;
  segv_full_state("dropped in-handler");
}

/* A SIGUSR1 the tracer hands to its resume of a seccomp stop, where ptrace
 * drops it: no handler runs, so the trapped rdtsc after the call runs with
 * SIGSEGV unblocked, as natively, though the handler would block it. */
static void mode_segv_resume_signal_dropped(void) {
  struct sigaction usr1;
  memset(&usr1, 0, sizeof usr1);
  usr1.sa_handler = segv_dropped_handler;
  sigemptyset(&usr1.sa_mask);
  sigaddset(&usr1.sa_mask, SIGSEGV);
  if (sigaction(SIGUSR1, &usr1, NULL) != 0)
    die("set sigusr1");
  segv_set(SIG_DFL, 0);
  SITEM(SYS_getpid, 0, 0, 0, 0, 0, SHAPE_TAIL | SEND_RESUME);
  segv_trapped_instruction(0);
  segv_full_state("dropped after");
}

/* Many trapped rdtscs with SIGSEGV neither blocked nor ignored, which no
 * trap resets: the repair makes no request for them. */
static void mode_segv_quiet(void) {
  segv_set(segv_handler, 0);
  for (int i = 0; i < 200; i++)
    segv_trapped_instruction(0);
  segv_full_state("quiet handler");
  segv_set(SIG_DFL, 0);
  for (int i = 0; i < 200; i++)
    segv_trapped_instruction(0);
  segv_full_state("quiet dfl");
}

/* SIGTRAP blocked through each handler shape, with the thread named by raw
 * bytes that are not UTF-8: procfs reports the name as set, and Reverie's
 * reads of the thread's status must still parse. */
static void mode_sigtrap_raw_name(void) {
  static const char raw[] = {'r', (char)0xff, (char)0xfe, 'n', 0};
  if (prctl(PR_SET_NAME, raw, 0, 0, 0) != 0)
    die("prctl PR_SET_NAME");
  for (int i = 0; i < 3; i++)
    SITE(SYS_getppid, 0, 0, 0, 0, 0);
  static const long shapes[] = {
      SHAPE_INJECT,
      SHAPE_TAIL,
      SHAPE_EMULATE,
      SHAPE_PRIVATE,
      SHAPE_TWO_INJECTS,
      SHAPE_TWO_PRIVATE,
      SHAPE_BLOCK_ALL,
  };
  for (unsigned j = 0; j < sizeof shapes / sizeof shapes[0]; j++) {
    sigtrap_set(trap_handler, 1);
    SITEM(SYS_getppid, 0, 0, 0, 0, 0, shapes[j]);
    char tag[32];
    snprintf(tag, sizeof tag, "raw-name shape=%u", j);
    sigtrap_full_state(tag);
  }
}

/* SIGTRAP flipped between SIG_DFL and SIG_IGN, each time followed by calls
 * the Tool emulates, whose syscall skips single-step and consult Reverie's
 * remembered disposition: each flip must reach it. */
static void mode_sigtrap_cache_flip(void) {
  for (int i = 0; i < 3; i++)
    SITE(SYS_getppid, 0, 0, 0, 0, 0);
  static const struct {
    const char* name;
    void (*action)(int);
  } flips[] = {
      {"dfl", SIG_DFL},
      {"ign", SIG_IGN},
      {"dfl-again", SIG_DFL},
      {"ign-again", SIG_IGN},
  };
  for (unsigned i = 0; i < sizeof flips / sizeof flips[0]; i++) {
    sigtrap_set(flips[i].action, 0);
    for (int k = 0; k < 3; k++)
      SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_EMULATE);
    char tag[32];
    snprintf(tag, sizeof tag, "flip %s", flips[i].name);
    sigtrap_full_state(tag);
  }
}

/* SIGTRAP's bit in the hex value of status field `name` within `buf`, or -1. */
static int status_sigtrap_bit(const char* buf, const char* name) {
  const char* p = strstr(buf, name);
  if (!p)
    return -1;
  unsigned long long v = strtoull(p + strlen(name), NULL, 16);
  return (int)((v >> (SIGTRAP - 1)) & 1);
}

/* Each SIGTRAP state, read back from the thread's own procfs status by a read
 * the Tool injects in each injecting shape: natively the read reports the
 * mask the thread runs under, so a blocked SIGTRAP is in SigBlk. An injected
 * read that the instrumentation runs with SIGTRAP unblocked reports the
 * instrumentation's mask instead (https://github.com/rrnewton/hermit/issues/4485). */
static void sigblk_matrix(const char* prefix) {
  static const struct {
    const char* name;
    void (*action)(int);
    int block;
  } states[] = {
      {"ign-blocked", SIG_IGN, 1},
      {"ign", SIG_IGN, 0},
      {"handler-blocked", trap_handler, 1},
      {"handler", trap_handler, 0},
      {"dfl-blocked", SIG_DFL, 1},
  };
  static const struct {
    const char* name;
    long shape;
  } shapes[] = {
      {"inject", SHAPE_INJECT},
      {"two-injects", SHAPE_TWO_INJECTS},
      {"private-call", SHAPE_PRIVATE_CALL},
      {"tail", SHAPE_TAIL},
  };
  for (unsigned i = 0; i < sizeof states / sizeof states[0]; i++) {
    for (unsigned j = 0; j < sizeof shapes / sizeof shapes[0]; j++) {
      sigtrap_set(states[i].action, states[i].block);
      char buf[4096];
      int fd = open("/proc/thread-self/status", O_RDONLY);
      if (fd < 0)
        die("open /proc/thread-self/status");
      long n = SITEM(SYS_read, fd, (long)buf, sizeof buf - 1, 0, 0, shapes[j].shape);
      close(fd);
      if (n <= 0)
        die("read /proc/thread-self/status");
      buf[n] = 0;
      sigset_t set;
      if (sigprocmask(SIG_SETMASK, NULL, &set) != 0)
        die("read the mask");
      say("%s%s %s SigBlk=%d SigIgn=%d SigCgt=%d blocked=%d\n",
          prefix,
          states[i].name,
          shapes[j].name,
          status_sigtrap_bit(buf, "SigBlk:"),
          status_sigtrap_bit(buf, "SigIgn:"),
          status_sigtrap_bit(buf, "SigCgt:"),
          sigismember(&set, SIGTRAP));
    }
  }
}

static void mode_sigtrap_sigblk(void) {
  for (int i = 0; i < 3; i++)
    SITE(SYS_getppid, 0, 0, 0, 0, 0);
  sigblk_matrix("");
}

static int parked_pipe[2];

static void* parked_thread(void* arg) {
  (void)arg;
  char c;
  if (read(parked_pipe[0], &c, 1) != 1)
    die("parked read");
  return NULL;
}

/* The same matrix while a second thread of this process is parked in a read,
 * so that the signal-action table is shared: there Reverie keeps the step
 * shield exactly as before injected calls ran under the guest's own mask,
 * and a private-page read sees a blocked SIGTRAP unblocked. */
static void mode_sigtrap_sigblk_shared(void) {
  for (int i = 0; i < 3; i++)
    SITE(SYS_getppid, 0, 0, 0, 0, 0);
  if (pipe(parked_pipe) != 0)
    die("pipe");
  pthread_t thread;
  if (pthread_create(&thread, NULL, parked_thread, NULL) != 0)
    die("pthread_create");
  sigblk_matrix("shared ");
  if (write(parked_pipe[1], "x", 1) != 1)
    die("unpark");
  if (pthread_join(thread, NULL) != 0)
    die("pthread_join");
}

static void untraced_entry(void);
static volatile long untraced_ret, untraced_rcx;
static volatile int untraced_done;

/* The SigBlk matrix after a CLONE_SIGHAND | CLONE_THREAD | CLONE_UNTRACED
 * thread, which gives no new-child stop, has started spinning: it shares the
 * signal-action table, so Reverie keeps the step shield exactly as before
 * injected calls ran under the guest's own mask. The thread spins until the
 * run's exit_group ends it. */
static void mode_sigtrap_sigblk_untraced(void) {
  for (int i = 0; i < 3; i++)
    SITE(SYS_getppid, 0, 0, 0, 0, 0);
  size_t size = 64 * 1024;
  char* stack = mmap(
      NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stack == MAP_FAILED)
    die("mmap stack");
  uintptr_t* top = (uintptr_t*)(stack + size - 64);
  top[0] = (uintptr_t)untraced_entry;
  long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
      CLONE_THREAD | CLONE_SYSVSEM | CLONE_UNTRACED;
  if (syscall(SYS_clone, flags, top, NULL, NULL, 0) <= 0)
    die("untraced clone");
  while (!__atomic_load_n(&untraced_done, __ATOMIC_SEQ_CST))
    __asm__ volatile("pause");
  sigblk_matrix("untraced ");
}

static volatile int hold_hits;

static void hold_usr1(int sig) {
  (void)sig;
  hold_hits++;
}

/* With a second thread parked (a shared table): for each SIGTRAP state,
 * SIGRTMIN+2 blocked and pending, then a status read the Tool handles by
 * first injecting a ppoll whose empty temporary mask lets SIGRTMIN+2
 * interrupt it (Reverie holds the signal, and the mask's restore is left
 * pending), then the read itself on the private page, which runs with the
 * realtime signals shielded until its syscall entry; SIGRTMIN+2 is
 * unblocked after. */
static void mode_sigtrap_ppoll_hold_then_read(void) {
  for (int i = 0; i < 3; i++)
    SITE(SYS_getppid, 0, 0, 0, 0, 0);
  struct sigaction usr1;
  memset(&usr1, 0, sizeof usr1);
  usr1.sa_handler = hold_usr1;
  if (sigaction(SIGRTMIN + 2, &usr1, NULL) != 0)
    die("install SIGRTMIN+2");
  if (pipe(parked_pipe) != 0)
    die("pipe");
  pthread_t thread;
  if (pthread_create(&thread, NULL, parked_thread, NULL) != 0)
    die("pthread_create");
  static const struct {
    const char* name;
    void (*action)(int);
    int block;
  } states[] = {
      {"ign-blocked", SIG_IGN, 1},
      {"handler-blocked", trap_handler, 1},
      {"dfl-blocked", SIG_DFL, 1},
      {"dfl", SIG_DFL, 0},
  };
  sigset_t usr1_set;
  sigemptyset(&usr1_set);
  sigaddset(&usr1_set, SIGRTMIN + 2);
  for (unsigned i = 0; i < sizeof states / sizeof states[0]; i++) {
    sigtrap_set(states[i].action, states[i].block);
    if (sigprocmask(SIG_BLOCK, &usr1_set, NULL) != 0)
      die("block SIGRTMIN+2");
    hold_hits = 0;
    raise(SIGRTMIN + 2);
    char buf[4096];
    int fd = open("/proc/thread-self/status", O_RDONLY);
    if (fd < 0)
      die("open /proc/thread-self/status");
    long n = SITEM(SYS_read, fd, (long)buf, sizeof buf - 1, 0, 0, SHAPE_PPOLL_THEN_CALL);
    close(fd);
    if (sigprocmask(SIG_UNBLOCK, &usr1_set, NULL) != 0)
      die("unblock SIGRTMIN+2");
    char tag[64];
    if (n <= 0) {
      snprintf(tag, sizeof tag, "hold %s read=%ld hits=%d", states[i].name, n, hold_hits);
      sigtrap_full_state(tag);
      continue;
    }
    buf[n] = 0;
    sigset_t set;
    if (sigprocmask(SIG_SETMASK, NULL, &set) != 0)
      die("read the mask");
    say("hold %s SigBlk=%d SigIgn=%d SigCgt=%d blocked=%d hits=%d\n",
        states[i].name,
        status_sigtrap_bit(buf, "SigBlk:"),
        status_sigtrap_bit(buf, "SigIgn:"),
        status_sigtrap_bit(buf, "SigCgt:"),
        sigismember(&set, SIGTRAP),
        hold_hits);
    snprintf(tag, sizeof tag, "hold %s after", states[i].name);
    sigtrap_full_state(tag);
  }
  if (write(parked_pipe[1], "x", 1) != 1)
    die("unpark");
  if (pthread_join(thread, NULL) != 0)
    die("pthread_join");
}

/* What a sleep's remaining time says, without its host-dependent digits.
 * rem is zeroed before each call, so "unwritten" means the kernel never
 * copied a remaining time out (the sleep was not interrupted). The tracer
 * sends the signal before the call, so an interrupted sleep ends at once and
 * the kernel reports about the whole request: "whole" is more than half and
 * at most one and a half times the request. Timer slack can put the exact
 * value either side of the request, which is why a 10 ms bucket there
 * flaked (rem=0.09 against rem=0.10); these bounds lie 50 ms from it.
 * Anything else ("partial": interrupted after more than half the request
 * elapsed; "invalid": not a normalized timespec or beyond the upper bound)
 * is named without digits too, so it compares exactly across runs. */
static const char* rem_class(
    const struct timespec* req,
    const struct timespec* rem) {
  if (rem->tv_sec == 0 && rem->tv_nsec == 0)
    return "unwritten";
  if (rem->tv_sec < 0 || rem->tv_nsec < 0 || rem->tv_nsec >= 1000000000L)
    return "invalid";
  long long want = (long long)req->tv_sec * 1000000000LL + req->tv_nsec;
  long long left = (long long)rem->tv_sec * 1000000000LL + rem->tv_nsec;
  if (left > want + want / 2)
    return "invalid";
  if (left > want / 2)
    return "whole";
  return "partial";
}

static void report_ts(
    const char* tag,
    long r,
    const struct timespec* req,
    struct timespec* rem) {
  report_result(tag, r);
  say("%s rem=%s\n", tag, rem_class(req, rem));
  dump(tag);
}

/* Interrupted and restarted calls through the shared site. */
static void mode_restart(void) {
  install(SIGUSR1, 0, restart_handler);
  warm();
  struct timespec req = {0, 100 * 1000 * 1000}, rem = {0, 0};
  long r;

  /* RESTARTBLOCK: a suppressed signal restarts through restart_syscall. */
  r = SITEM(SYS_nanosleep, &req, &rem, 0, 0, 0, SEND_SIGWINCH);
  report_ts("nanosleep-suppressed", r, &req, &rem);
  rem.tv_sec = rem.tv_nsec = 0;
  r = SITEM(SYS_nanosleep, &req, &rem, 0, 0, 0, SEND_SIGUSR1);
  report_ts("nanosleep-handled", r, &req, &rem);
  rem.tv_sec = rem.tv_nsec = 0;
  r = SITEM(
      SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &req, &rem, 0, SEND_SIGWINCH);
  report_ts("clock_nanosleep-suppressed", r, &req, &rem);
  rem.tv_sec = rem.tv_nsec = 0;
  r = SITEM(
      SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &req, &rem, 0, SEND_SIGUSR1);
  report_ts("clock_nanosleep-handled", r, &req, &rem);
  rem.tv_sec = rem.tv_nsec = 0;
  r = SITEM(SYS_nanosleep, &req, &rem, 0, 0, 0, SHAPE_TAIL | SEND_SIGWINCH);
  report_ts("nanosleep-suppressed-tail", r, &req, &rem);

  /* ERESTARTSYS: read on an empty pipe, without and with SA_RESTART. */
  int fds[2];
  char c;
  if (pipe(fds) != 0)
    die("pipe");
  restart_pipe_wr = fds[1];
  r = SITEM(SYS_read, fds[0], &c, 1, 0, 0, SEND_SIGUSR1);
  report_result("read-eintr", r);
  dump("read-eintr");
  if (read(fds[0], &c, 1) != 1)
    die("drain");
  install(SIGUSR1, SA_RESTART, restart_handler);
  r = SITEM(SYS_read, fds[0], &c, 1, 0, 0, SEND_SIGUSR1);
  report_result("read-restart", r);
  dump("read-restart");
  r = SITEM(SYS_read, fds[0], &c, 1, 0, 0, SHAPE_TAIL | SEND_SIGUSR1);
  report_result("read-restart-tail", r);
  dump("read-restart-tail");
  restart_pipe_wr = -1;

  /* ERESTARTSYS: a futex wait, with SA_RESTART (the handler changes the
   * word, so the restarted wait fails with EAGAIN) and without. */
  static int word;
  restart_futex = &word;
  word = 0;
  r = SITEM(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 0, NULL, 0, SEND_SIGUSR1);
  report_result("futex-restart", r);
  dump("futex-restart");
  install(SIGUSR1, 0, restart_handler);
  word = 0;
  r = SITEM(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 0, NULL, 0, SEND_SIGUSR1);
  report_result("futex-eintr", r);
  dump("futex-eintr");
  restart_futex = NULL;

  /* ERESTARTNOHAND: ppoll and epoll_pwait, then pause. */
  struct pollfd pfd = {fds[0], POLLIN, 0};
  r = SITEM(SYS_ppoll, &pfd, 1, NULL, NULL, 8, SEND_SIGUSR1);
  report_result("ppoll", r);
  dump("ppoll");
  int ep = epoll_create1(0);
  if (ep < 0)
    die("epoll_create1");
  struct epoll_event ev = {.events = EPOLLIN, .data.u64 = 0}, out;
  if (epoll_ctl(ep, EPOLL_CTL_ADD, fds[0], &ev) != 0)
    die("epoll_ctl");
  r = SITEM(SYS_epoll_pwait, ep, &out, 1, -1, NULL, SEND_SIGUSR1);
  report_result("epoll_pwait", r);
  dump("epoll_pwait");
  r = SITEM(SYS_pause, 0, 0, 0, 0, 0, SEND_SIGUSR1);
  report_result("pause", r);
  dump("pause");
}

static int thread_ctid;

static void thread_entry(void) {
  /* A raw CLONE_THREAD child on its own stack: no libc, no TLS. */
  __asm__ volatile(
      "mov $60, %%eax\n"
      "xor %%edi, %%edi\n"
      "syscall\n" ::
          : "memory");
  __builtin_unreachable();
}

/* fork, vfork, clone3 and a thread through the site. */
static void mode_fork_family(void) {
  warm();
  long r;
  int status;
  /* SIGCHLD stays blocked (and is inherited blocked) until the end, so its
   * one delivery lands at a fixed point in the syscall stream instead of
   * wherever a child's exit happens to overtake its parent. */
  sigset_t chld;
  sigemptyset(&chld);
  sigaddset(&chld, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &chld, NULL) != 0)
    die("block SIGCHLD");

  /* fork through the site; the child forks a grandchild there. */
  r = SITE(SYS_fork, 0, 0, 0, 0, 0);
  if (r == 0) {
    say("fork child rcx=%s r11=%#lx\n", where(tp_z_rcx), tp_z_r11);
    long g = SITE(SYS_fork, 0, 0, 0, 0, 0);
    if (g == 0)
      _exit(7);
    int gs;
    if (waitpid(g, &gs, 0) != g)
      _exit(90);
    _exit(WIFEXITED(gs) ? WEXITSTATUS(gs) : 91);
  }
  if (waitpid(r, &status, 0) != r)
    die("wait fork");
  report_result("fork", r > 0 ? 1 : r);
  say("fork child status exited=%d code=%d\n",
      WIFEXITED(status),
      WEXITSTATUS(status));

  /* vfork: the child exits at once without touching the shared stack. */
  r = SITE(SYS_vfork, 0, 0, 0, 0, 0);
  if (r == 0) {
    __asm__ volatile(
        "mov $231, %%eax\n"
        "mov $7, %%edi\n"
        "syscall\n" ::
            : "memory");
  }
  say("vfork child rcx=%s r11=%#lx\n", where(tp_z_rcx), tp_z_r11);
  report_result("vfork", r > 0 ? 1 : r);
  if (waitpid(r, &status, 0) != r)
    die("wait vfork");
  say("vfork child status exited=%d code=%d\n",
      WIFEXITED(status),
      WEXITSTATUS(status));

  /* clone3 without CLONE_VM (fork-like). */
  struct {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack,
        stack_size, tls;
  } args = {0, 0, 0, 0, SIGCHLD, 0, 0, 0};
  r = SITE(SYS_clone3, &args, sizeof args, 0, 0, 0);
  if (r == 0) {
    say("clone3 child rcx=%s r11=%#lx\n", where(tp_z_rcx), tp_z_r11);
    _exit(7);
  }
  if (waitpid(r, &status, 0) != r)
    die("wait clone3");
  report_result("clone3", r > 0 ? 1 : r);
  say("clone3 child status exited=%d code=%d\n",
      WIFEXITED(status),
      WEXITSTATUS(status));
  site_bytes("before thread");

  /* A thread (CLONE_VM|CLONE_THREAD) through the site: the child returns
   * from tp_site_fn on its own stack into thread_entry. */
  size_t size = 64 * 1024;
  char* stack = mmap(
      NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stack == MAP_FAILED)
    die("mmap stack");
  uintptr_t* top = (uintptr_t*)(stack + size - 64);
  top[0] = (uintptr_t)thread_entry;
  thread_ctid = 1;
  long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
      CLONE_THREAD | CLONE_SYSVSEM | CLONE_CHILD_CLEARTID;
  r = SITE(SYS_clone, flags, top, NULL, &thread_ctid, 0);
  report_result("thread", r > 0 ? 1 : r);
  /* Join without syscalls, so whether the thread has already exited does
   * not change the parent's syscall stream (a futex wait did). */
  while (__atomic_load_n(&thread_ctid, __ATOMIC_SEQ_CST) != 0)
    __builtin_ia32_pause();
  say("thread child rcx=%s r11=%#lx\n", where(tp_z_rcx), tp_z_r11);
  site_bytes("after thread");
  r = SITE(SYS_getpid, 0, 0, 0, 0, 0);
  say("getpid after thread pid=%d\n", r == getpid());
  if (sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0)
    die("unblock SIGCHLD");
}

/* A real IA-32 `int 0x80` in a forked child. */
static void mode_foreign_int80(void) {
  /* SIGCHLD stays blocked across the fork and the wait, so its one delivery
   * lands at the unblock below instead of wherever the child's death
   * happens to overtake the parent's wait4. */
  sigset_t chld;
  sigemptyset(&chld);
  sigaddset(&chld, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &chld, NULL) != 0)
    die("block SIGCHLD");
  pid_t child = fork();
  if (child < 0)
    die("fork");
  if (child == 0) {
    /* No core anywhere: a limit of 1 stops a core file and, unlike 0, a
     * pipe core_pattern helper too. Under a hard limit of 0 the call fails
     * and the limit stays 0. Both backends see the same limit. */
    struct rlimit none = {1, 1};
    setrlimit(RLIMIT_CORE, &none);
    install(SIGSYS, 0, handler);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGSYS);
    sigprocmask(SIG_BLOCK, &set, NULL);
    long ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(20L) : "memory");
    /* Reached only if the IA-32 syscall was serviced. */
    say("int80 returned handler_ran=%d\n", nrec);
    _exit(0);
  }
  int status;
  if (waitpid(child, &status, 0) != child)
    die("waitpid");
  say("child signaled=%d termsig=%d coredump=%d exited=%d\n",
      WIFSIGNALED(status),
      WIFSIGNALED(status) ? WTERMSIG(status) : 0,
      WIFSIGNALED(status) ? WCOREDUMP(status) : 0,
      WIFEXITED(status));
  if (sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0)
    die("unblock SIGCHLD");
}

/* A signal the tracer passes on its final resume of a seccomp stop. */
static void mode_resume_signal(void) {
  install(SIGUSR1, 0, handler);
  warm();
  long r = SITEM(SYS_getpid, 0, 0, 0, 0, 0, SHAPE_INJECT | SEND_RESUME);
  say("getpid returned pid=%d\n", r == getpid());
  dump("resume_inject");
  r = SITEM(SYS_getpid, 0, 0, 0, 0, 0, SHAPE_EMULATE | SEND_RESUME);
  say("emulated getpid returned %ld\n", r);
  dump("resume_emulate");
  r = SITEM(SYS_getpid, 0, 0, 0, 0, 0, SHAPE_TAIL | SEND_RESUME);
  say("tail getpid returned pid=%d\n", r == getpid());
  dump("resume_tail");
}

/* rcx and r11 after `syscall`, including with DF and AC set. */
static void mode_rcx_r11(void) {
  for (int i = 0; i < 4; i++) {
    long r = t8_fn(SYS_getpid, 0);
    say("t8 %d pid=%d rcx=%s r11=%#lx\n",
        i,
        r == getpid(),
        where(t8_rcx),
        t8_r11);
  }
  long r = t8_fn(SYS_getpid, 1);
  say("t8 df pid=%d rcx=%s r11=%#lx\n", r == getpid(), where(t8_rcx), t8_r11);
  r = t8_fn(SYS_getpid, 2);
  say("t8 ac pid=%d rcx=%s r11=%#lx\n", r == getpid(), where(t8_rcx), t8_r11);

  /* A handler interrupting a blocking read at the site sees rcx/r11 too. */
  install(SIGUSR1, 0, handler);
  warm();
  int fds[2];
  char c;
  if (pipe(fds) != 0)
    die("pipe");
  r = SITEM(SYS_read, fds[0], &c, 1, 0, 0, SEND_SIGUSR1);
  report_result("read", r);
  dump("read");
  /* And a fork child created through the site. SIGCHLD stays blocked
   * across the fork and the wait, so its one delivery lands at the unblock
   * instead of wherever the child's exit happens to overtake the parent. */
  sigset_t chld;
  sigemptyset(&chld);
  sigaddset(&chld, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &chld, NULL) != 0)
    die("block SIGCHLD");
  r = SITE(SYS_fork, 0, 0, 0, 0, 0);
  if (r == 0) {
    say("fork child rcx=%s r11=%#lx\n", where(tp_z_rcx), tp_z_r11);
    _exit(0);
  }
  int status;
  if (waitpid(r, &status, 0) != r)
    die("wait fork");
  report_result("fork parent", r > 0 ? 1 : r);
  if (sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0)
    die("unblock SIGCHLD");
}

/* ---- Mapping changes and guest installs ---- */

/* Runs this fixture again, in `mode`, with the same report file. */
static void exec_self(const char* mode) {
  char* args[] = {"/proc/self/exe", (char*)mode, main_argv[2], NULL};
  execve(args[0], args, environ);
  die("execve");
}

/* SIGTRAP's state across a guest fork run in place: Reverie single-steps the
 * parent from its clone event stop. Both processes read the state back. */
static void mode_sigtrap_fork(void) {
  static const struct {
    const char* name;
    void (*action)(int);
    int block;
  } states[] = {
      {"ign-blocked", SIG_IGN, 1},
      {"ign", SIG_IGN, 0},
      {"handler-blocked", trap_handler, 1},
  };
  for (unsigned i = 0; i < sizeof states / sizeof states[0]; i++) {
    sigtrap_set(states[i].action, states[i].block);
    char tag[64];
    pid_t pid = fork();
    if (pid < 0)
      die("fork");
    if (pid == 0) {
      snprintf(tag, sizeof tag, "fork child %s", states[i].name);
      sigtrap_full_state(tag);
      _exit(0);
    }
    int status;
    if (waitpid(pid, &status, 0) != pid)
      die("wait fork child");
    snprintf(tag, sizeof tag, "fork parent %s", states[i].name);
    sigtrap_full_state(tag);
  }
}

/* The kernel's struct sigaction, as rt_sigaction takes it. */
struct ksigaction {
  void (*handler)(int);
  unsigned long flags;
  void (*restorer)(void);
  unsigned long mask;
};

/* Calls that set SIGTRAP's action or the mask, injected on the private page
 * (SHAPE_PRIVATE_CALL), with SIGTRAP blocked or not. */
static void mode_sigtrap_private_calls(void) {
  warm();
  static const struct {
    const char* name;
    void (*action)(int);
  } actions[] = {{"ign", SIG_IGN}, {"handler", trap_handler}};
  for (unsigned i = 0; i < sizeof actions / sizeof actions[0]; i++) {
    sigtrap_set(SIG_DFL, 1);
    struct ksigaction k = {
        .handler = actions[i].action,
        .flags = SA_RESTART | SA_NODEFER | 0x04000000 /* SA_RESTORER */,
        .restorer = (void (*)(void))trap_handler,
        .mask = 1UL << (SIGUSR2 - 1),
    };
    long r = SITEM(SYS_rt_sigaction, SIGTRAP, (long)&k, 0, 8, 0, SHAPE_PRIVATE_CALL);
    if (r != 0)
      die("private rt_sigaction");
    char tag[64];
    snprintf(tag, sizeof tag, "private-sigaction %s", actions[i].name);
    sigtrap_full_state(tag);
  }
  /* The same SIG_IGN from a page the guest made write-only, which the kernel
   * reads but process_vm_readv cannot. */
  {
    sigtrap_set(SIG_DFL, 1);
    struct ksigaction k = {
        .handler = SIG_IGN,
        .flags = SA_RESTART | SA_NODEFER | 0x04000000 /* SA_RESTORER */,
        .restorer = (void (*)(void))trap_handler,
        .mask = 1UL << (SIGUSR2 - 1),
    };
    void* page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
      die("write-only action mmap");
    memcpy(page, &k, sizeof k);
    if (mprotect(page, 4096, PROT_WRITE) != 0)
      die("write-only action mprotect");
    long r = SITEM(SYS_rt_sigaction, SIGTRAP, (long)page, 0, 8, 0, SHAPE_PRIVATE_CALL);
    if (r != 0)
      die("private rt_sigaction from a write-only page");
    sigtrap_full_state("private-sigaction-writeonly ign");
    munmap(page, 4096);
  }
  /* SIG_DFL from a page the guest made inaccessible, over SIG_IGN: the
   * kernel cannot read it and fails with EFAULT before installing anything,
   * so SIG_IGN stays, although ptrace can read the page. */
  {
    sigtrap_set(SIG_IGN, 1);
    struct ksigaction k = {
        .handler = SIG_DFL,
        .flags = 0x04000000 /* SA_RESTORER */,
        .restorer = (void (*)(void))trap_handler,
        .mask = 0,
    };
    void* page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
      die("inaccessible action mmap");
    memcpy(page, &k, sizeof k);
    if (mprotect(page, 4096, PROT_NONE) != 0)
      die("inaccessible action mprotect");
    long r = SITEM(SYS_rt_sigaction, SIGTRAP, (long)page, 0, 8, 0, SHAPE_PRIVATE_CALL);
    char tag[64];
    snprintf(tag, sizeof tag, "private-sigaction-noaccess dfl r=%s", r == -EFAULT ? "efault" : "other");
    sigtrap_full_state(tag);
    munmap(page, 4096);
  }
  /* SIG_DFL from a page whose protection key denies access, over SIG_IGN:
   * procfs maps lists it rw-p and ptrace reads it, but the kernel's copy
   * honours the thread's protection keys and fails with EFAULT before
   * installing anything, so SIG_IGN stays. Without an oldact, then with one.
   * Then a valid SIG_IGN act (which every step's trap resets) with an oldact
   * the kernel cannot write: it installs act, then fails with EFAULT. */
  {
    struct ksigaction k = {
        .handler = SIG_DFL,
        .flags = 0x04000000 /* SA_RESTORER */,
        .restorer = (void (*)(void))trap_handler,
        .mask = 0,
    };
    int pkey = pkey_alloc(0, 0);
    if (pkey < 0) {
      say("private-sigaction-pkey unavailable\n");
      say("private-sigaction-pkey-oldact unavailable\n");
    } else {
      void* page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (page == MAP_FAILED)
        die("pkey action mmap");
      memcpy(page, &k, sizeof k);
      if (pkey_mprotect(page, 4096, PROT_READ | PROT_WRITE, pkey) != 0)
        die("pkey_mprotect");
      static struct ksigaction old;
      for (int with_old = 0; with_old < 2; with_old++) {
        sigtrap_set(SIG_IGN, 1);
        pkey_set(pkey, PKEY_DISABLE_ACCESS);
        long r = SITEM(SYS_rt_sigaction, SIGTRAP, (long)page, with_old ? (long)&old : 0, 8, 0,
                       SHAPE_PRIVATE_CALL);
        pkey_set(pkey, 0);
        char tag[64];
        snprintf(tag, sizeof tag, "private-sigaction-pkey%s dfl r=%s", with_old ? "-oldact" : "",
                 r == -EFAULT ? "efault" : "other");
        sigtrap_full_state(tag);
      }
      munmap(page, 4096);
      pkey_free(pkey);
    }
  }
  {
    sigtrap_set(SIG_DFL, 1);
    struct ksigaction k = {
        .handler = SIG_IGN,
        .flags = SA_RESTART | SA_NODEFER | 0x04000000 /* SA_RESTORER */,
        .restorer = (void (*)(void))trap_handler,
        .mask = 1UL << (SIGUSR2 - 1),
    };
    void* readonly = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (readonly == MAP_FAILED)
      die("read-only oldact mmap");
    long r = SITEM(SYS_rt_sigaction, SIGTRAP, (long)&k, (long)readonly, 8, 0, SHAPE_PRIVATE_CALL);
    char tag[64];
    snprintf(tag, sizeof tag, "private-sigaction-badoldact ign r=%s",
             r == -EFAULT ? "efault" : "other");
    sigtrap_full_state(tag);
    munmap(readonly, 4096);
  }
  static const struct {
    const char* name;
    void (*action)(int);
    int block;
  } states[] = {
      {"handler-blocked", trap_handler, 1},
      {"ign-blocked", SIG_IGN, 1},
      {"handler", trap_handler, 0},
  };
  for (unsigned i = 0; i < sizeof states / sizeof states[0]; i++) {
    sigtrap_set(states[i].action, states[i].block);
    struct timespec ts = {0, 0};
    unsigned long temporary = 1UL << (SIGTRAP - 1);
    long r = SITEM(SYS_ppoll, 0, 0, (long)&ts, (long)&temporary, 8, SHAPE_PRIVATE_CALL);
    if (r != 0)
      die("private ppoll");
    char tag[64];
    snprintf(tag, sizeof tag, "private-ppoll %s", states[i].name);
    sigtrap_full_state(tag);
  }
}

/* SIGTRAP states that survive exec natively: exec keeps SIG_IGN (clearing
 * every action's flags and mask) and the blocked mask. Mode sigtrap_exec_N
 * reads back state N - 1, which the previous image set before exec, before
 * any Tool injection, then sets state N and execs itself as N + 1. Reverie's
 * pre-init single-step of each new image must leave the state
 * (https://github.com/rrnewton/hermit/issues/4409). */
static void mode_sigtrap_exec(int n) {
  static const struct {
    const char* name;
    void (*action)(int);
    int block;
  } states[] = {
      {"ign-blocked", SIG_IGN, 1},
      {"ign", SIG_IGN, 0},
      {"dfl-blocked", SIG_DFL, 1},
  };
  if (n > 0) {
    char tag[64];
    snprintf(tag, sizeof tag, "exec %s", states[n - 1].name);
    sigtrap_full_state(tag);
  }
  if (n == (int)(sizeof states / sizeof states[0]))
    return;
  sigtrap_set(states[n].action, states[n].block);
  char mode[32];
  snprintf(mode, sizeof mode, "sigtrap_exec_%d", n + 1);
  exec_self(mode);
}

/* SIGCHLD stays blocked (and is inherited blocked) from chld_block() to
 * chld_unblock(), so that its one delivery lands at the unblock instead of
 * wherever a child's exit happens to overtake the parent's wait. */
static void chld_block(void) {
  sigset_t chld;
  sigemptyset(&chld);
  sigaddset(&chld, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &chld, NULL) != 0)
    die("block SIGCHLD");
}

static void chld_unblock(void) {
  sigset_t chld;
  sigemptyset(&chld);
  sigaddset(&chld, SIGCHLD);
  if (sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0)
    die("unblock SIGCHLD");
}

/* The image an exec installs: warm() runs the site at the same -no-pie
 * address. */
static void mode_exec_image(void) {
  warm();
  say("exec image getpid ok\n");
}

/* The leader execs. */
static void mode_exec_leader(void) {
  warm();
  exec_self("exec_image");
}

/* Set by the leader after its last syscall (the tail of pthread_create). */
static volatile int exec_leader_done;

static void* exec_thread_entry(void* arg) {
  (void)arg;
  /* Exec only once the leader has made its last syscall, so that its stop
   * sequence is the same in every run: the leader publishes the flag after
   * pthread_create has returned, and never enters the kernel again. Both
   * sides spin without syscalls, so the order is causal, not timed. */
  while (!__atomic_load_n(&exec_leader_done, __ATOMIC_SEQ_CST))
    __builtin_ia32_pause();
  exec_self("exec_image");
  return NULL;
}

/* A non-leader thread execs; the kernel kills the leader first. The
 * leader spins in user space, without syscalls, until the exec kills it:
 * blocking in pause() instead would make its last stops depend on whether
 * the exec landed before or after the tracer let it into the call. */
static void mode_exec_thread(void) {
  warm();
  pthread_t thread;
  if (pthread_create(&thread, NULL, exec_thread_entry, NULL) != 0)
    die("pthread_create");
  __atomic_store_n(&exec_leader_done, 1, __ATOMIC_SEQ_CST);
  for (;;)
    __builtin_ia32_pause();
}

/* x86_64 code `mov $nr, %eax; syscall; ret` after `pad` nops; the syscall is
 * at code + pad + 5. */
static void emit(unsigned char* code, int pad, int nr) {
  for (int i = 0; i < pad; i++)
    code[i] = 0x90;
  unsigned char body[] = {0xb8, (unsigned char)nr, 0, 0, 0, 0x0f, 0x05, 0xc3};
  memcpy(code + pad, body, sizeof body);
}

static unsigned char* map_at(unsigned long address, int prot, int extra) {
  void* p = mmap(
      (void*)address, 4096, prot, MAP_PRIVATE | MAP_ANONYMOUS | extra, -1, 0);
  if (p != (void*)address)
    die("mmap jit");
  return p;
}

static long run_code(unsigned char* code) {
  return ((long (*)(void))code)();
}

static void protect(void* address, int prot) {
  if (mprotect(address, 4096, prot) != 0)
    die("mprotect");
}

static void jit_bytes(const char* tag, unsigned char* site) {
  say("%s bytes %02x %02x\n", tag, site[0], site[1]);
}

/* JIT code, replaced, unmapped, mapped over, moved and left writable, with
 * the guest reading its own syscall bytes after each change. */
static void mode_jit(void) {
  const int rw = PROT_READ | PROT_WRITE, rx = PROT_READ | PROT_EXEC;
  int status;

  unsigned char* a = map_at(0x50000000, rw, MAP_FIXED_NOREPLACE);
  emit(a, 0, SYS_getpid);
  protect(a, rx);
  for (int i = 0; i < 3; i++)
    say("jit a %d pid=%d\n", i, run_code(a) == getpid());
  /* A fork child changes its own copy of the page; the parent's copy runs
   * on unchanged. */
  chld_block();
  pid_t child = fork();
  if (child == 0) {
    protect(a, rw);
    jit_bytes("jit fork child a", a + 5);
    _exit(0);
  }
  if (waitpid(child, &status, 0) != child)
    die("wait jit child");
  say("jit fork child exited=%d code=%d\n",
      WIFEXITED(status),
      WEXITSTATUS(status));
  chld_unblock();
  say("jit a after fork pid=%d\n", run_code(a) == getpid());
  /* Writable again: the guest reads its own bytes, then rewrites the code. */
  protect(a, rw);
  jit_bytes("jit a after mprotect rw", a + 5);
  emit(a, 2, SYS_getppid);
  protect(a, rx);
  for (int i = 0; i < 3; i++)
    say("jit a2 %d ppid=%d\n", i, run_code(a) > 0);

  /* munmap of a JIT page, then new code at the same address. */
  unsigned char* b = map_at(0x50010000, rw, MAP_FIXED_NOREPLACE);
  emit(b, 0, SYS_getpid);
  protect(b, rx);
  for (int i = 0; i < 3; i++)
    say("jit b %d pid=%d\n", i, run_code(b) == getpid());
  if (munmap(b, 4096) != 0)
    die("munmap");
  b = map_at(0x50010000, rw, MAP_FIXED_NOREPLACE);
  jit_bytes("jit b after munmap", b + 5);
  emit(b, 0, SYS_gettid);
  protect(b, rx);
  for (int i = 0; i < 3; i++)
    say("jit b2 %d tid=%d\n", i, run_code(b) == gettid());

  /* mmap(MAP_FIXED) over a JIT page. */
  unsigned char* d = map_at(0x50050000, rw, MAP_FIXED_NOREPLACE);
  emit(d, 0, SYS_getpid);
  protect(d, rx);
  for (int i = 0; i < 3; i++)
    say("jit d %d pid=%d\n", i, run_code(d) == getpid());
  d = map_at(0x50050000, rw, MAP_FIXED);
  jit_bytes("jit d after mmap fixed", d + 5);

  /* mremap moves a JIT page. */
  unsigned char* c = map_at(0x50020000, rw, MAP_FIXED_NOREPLACE);
  emit(c, 0, SYS_getpid);
  protect(c, rx);
  for (int i = 0; i < 3; i++)
    say("jit c %d pid=%d\n", i, run_code(c) == getpid());
  unsigned char* moved =
      mremap(c, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, (void*)0x50030000);
  if (moved != (void*)0x50030000)
    die("mremap");
  jit_bytes("jit c after mremap", moved + 5);
  for (int i = 0; i < 3; i++)
    say("jit c2 %d pid=%d\n", i, run_code(moved) == getpid());

  /* A writable and executable page. */
  unsigned char* e = map_at(0x50040000, rw | PROT_EXEC, MAP_FIXED_NOREPLACE);
  emit(e, 0, SYS_getpid);
  for (int i = 0; i < 3; i++)
    say("jit e %d pid=%d\n", i, run_code(e) == getpid());
  jit_bytes("jit e", e + 5);

  /* madvise(MADV_DONTNEED) on the fixture's own text page. */
  warm();
  if (madvise((void*)((unsigned long)tp_site & ~4095UL), 4096, MADV_DONTNEED) !=
      0)
    die("madvise");
  site_bytes("after madvise");
  warm();
}

/* A one-byte store through /proc/self/mem over a JIT syscall site, then an
 * mprotect: the guest reads its own byte and the original second byte. Then
 * an mremap(MREMAP_FIXED) of another page onto a JIT page, whose moved code
 * runs at its new address. */
static void mode_jit_more(void) {
  const int rw = PROT_READ | PROT_WRITE, rx = PROT_READ | PROT_EXEC;

  unsigned char* a = map_at(0x51000000, rw, MAP_FIXED_NOREPLACE);
  emit(a, 0, SYS_getpid);
  protect(a, rx);
  for (int i = 0; i < 3; i++)
    say("more a %d pid=%d\n", i, run_code(a) == getpid());
  int fd = open("/proc/self/mem", O_RDWR);
  if (fd < 0)
    die("open /proc/self/mem");
  unsigned char nop = 0x90;
  if (pwrite(fd, &nop, 1, (off_t)(unsigned long)(a + 5)) != 1)
    die("pwrite /proc/self/mem");
  close(fd);
  protect(a, rw);
  jit_bytes("more a after self write", a + 5);

  unsigned char* f = map_at(0x51010000, rw, MAP_FIXED_NOREPLACE);
  emit(f, 0, SYS_getpid);
  protect(f, rx);
  for (int i = 0; i < 3; i++)
    say("more f %d pid=%d\n", i, run_code(f) == getpid());
  unsigned char* g = map_at(0x51020000, rw, MAP_FIXED_NOREPLACE);
  emit(g, 2, SYS_gettid);
  protect(g, rx);
  unsigned char* moved =
      mremap(g, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, (void*)f);
  if (moved != f)
    die("mremap onto a JIT page");
  jit_bytes("more f after mremap", f + 5);
  for (int i = 0; i < 3; i++)
    say("more f2 %d tid=%d\n", i, run_code(f) == gettid());
}

/* A fork through the site. Both copies of the address space read the
 * original bytes afterwards. */
static void mode_fork_undecided(void) {
  warm();
  chld_block();
  int status;
  long r = SITE(SYS_fork, 0, 0, 0, 0, 0);
  if (r == 0) {
    site_bytes("undecided fork child");
    _exit(7);
  }
  if (r < 0)
    die("fork");
  if (waitpid(r, &status, 0) != r)
    die("wait undecided fork");
  say("undecided fork child exited=%d code=%d\n",
      WIFEXITED(status),
      WEXITSTATUS(status));
  chld_unblock();
  site_bytes("undecided fork parent");
  warm();
}

/* The two bytes at tp_site as the vfork_undecided child read them. */
unsigned char tp_vfork_child_bytes[2];

/* A vfork through the site. The child shares the parent's stack, so after the vfork it calls no function:
 * in inline assembly it copies the two bytes at tp_site into a global and
 * exits, and the parent reports them. */
static void mode_vfork_undecided(void) {
  warm();
  chld_block();
  int status;
  long r = SITE(SYS_vfork, 0, 0, 0, 0, 0);
  if (r == 0) {
    __asm__ volatile(
        "movzbl tp_site(%%rip), %%eax\n"
        "movb %%al, tp_vfork_child_bytes(%%rip)\n"
        "movzbl tp_site+1(%%rip), %%eax\n"
        "movb %%al, tp_vfork_child_bytes+1(%%rip)\n"
        "mov $231, %%eax\n"
        "mov $7, %%edi\n"
        "syscall\n" ::
            : "rax", "rdi", "rcx", "r11", "memory");
    __builtin_unreachable();
  }
  if (r < 0)
    die("vfork");
  if (waitpid(r, &status, 0) != r)
    die("wait undecided vfork");
  say("undecided vfork child site bytes %02x %02x\n",
      tp_vfork_child_bytes[0],
      tp_vfork_child_bytes[1]);
  say("undecided vfork child exited=%d code=%d\n",
      WIFEXITED(status),
      WEXITSTATUS(status));
  chld_unblock();
  site_bytes("undecided vfork parent");
  warm();
}

/* process_madvise(MADV_DONTNEED) through a pidfd for this process, on the
 * fixture's own text page, with a JIT page the call does not name. The
 * result depends on the host kernel: before Linux 6.13 a process may not
 * pass MADV_DONTNEED for itself (EINVAL). */
static void mode_process_madvise(void) {
  const int rw = PROT_READ | PROT_WRITE, rx = PROT_READ | PROT_EXEC;
  int pidfd = syscall(SYS_pidfd_open, getpid(), 0);
  if (pidfd < 0)
    die("pidfd_open");
  unsigned char* j = map_at(0x52000000, rw, MAP_FIXED_NOREPLACE);
  emit(j, 0, SYS_getpid);
  protect(j, rx);
  for (int i = 0; i < 3; i++)
    say("pm jit %d pid=%d\n", i, run_code(j) == getpid());
  warm();
  struct iovec iov = {(void*)((unsigned long)tp_site & ~4095UL), 4096};
  long r = syscall(SYS_process_madvise, pidfd, &iov, 1, MADV_DONTNEED, 0);
  int err = r < 0 ? errno : 0;
  say("process_madvise ret=%ld errno=%d\n", r, err);
  site_bytes("after process_madvise");
  jit_bytes("after process_madvise jit", j + 5);
  for (int i = 0; i < 3; i++)
    say("pm jit2 %d pid=%d\n", i, run_code(j) == getpid());
  warm();
  close(pidfd);
}

/* The first call through tp_site is process_madvise(MADV_DONTNEED), through
 * a pidfd for this process, on tp_site's own page; the site still reads
 * 0f 05 after the call and after warm(). SITE returns the raw result,
 * -EINVAL before Linux 6.13 (see mode_process_madvise). */
static void mode_process_madvise_first(void) {
  int pidfd = syscall(SYS_pidfd_open, getpid(), 0);
  if (pidfd < 0)
    die("pidfd_open");
  struct iovec iov = {(void*)((unsigned long)tp_site & ~4095UL), 4096};
  long r = SITE(SYS_process_madvise, pidfd, &iov, 1, MADV_DONTNEED, 0);
  say("process_madvise first ret=%ld\n", r);
  site_bytes("after process_madvise first");
  warm();
  site_bytes("after warm");
  close(pidfd);
}

/* A thread (CLONE_VM|CLONE_THREAD) through the site. The thread returns from tp_site_fn on its own stack into thread_entry and exits; the
 * parent joins it without syscalls. */
static void mode_thread_mismatch(void) {
  warm();
  size_t size = 64 * 1024;
  char* stack = mmap(
      NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stack == MAP_FAILED)
    die("mmap stack");
  uintptr_t* top = (uintptr_t*)(stack + size - 64);
  top[0] = (uintptr_t)thread_entry;
  thread_ctid = 1;
  long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
      CLONE_THREAD | CLONE_SYSVSEM | CLONE_CHILD_CLEARTID;
  long r = SITE(SYS_clone, flags, top, NULL, &thread_ctid, 0);
  report_result("mismatch thread", r > 0 ? 1 : r);
  while (__atomic_load_n(&thread_ctid, __ATOMIC_SEQ_CST) != 0)
    __builtin_ia32_pause();
  site_bytes("mismatch thread parent");
  warm();
}

/* posix_spawn and system() (both vfork-style) from a process with a warm
 * site; the parent's site still works after the children exec. */
static void mode_vfork_spawn(void) {
  warm();
  /* Both children's SIGCHLDs coalesce into one delivery at the unblock.
   * system() saves and restores this mask around its own wait. */
  chld_block();
  pid_t child;
  char* args[] = {"/proc/self/exe", "exec_image", main_argv[2], NULL};
  if (posix_spawn(&child, args[0], NULL, NULL, args, environ) != 0)
    die("posix_spawn");
  int status;
  if (waitpid(child, &status, 0) != child)
    die("wait spawn");
  say("spawn child exited=%d code=%d\n",
      WIFEXITED(status),
      WEXITSTATUS(status));
  warm();
  status = system("exit 3");
  say("system exited=%d code=%d\n", WIFEXITED(status), WEXITSTATUS(status));
  chld_unblock();
  warm();
  say("parent getpid ok\n");
}

/* A filter: KILL_PROCESS for any arch other than x86_64, EPERM for getppid,
 * everything else allowed. */
static struct sock_filter guest_filter_code[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
static struct sock_fprog guest_filter = {
    sizeof guest_filter_code / sizeof guest_filter_code[0],
    guest_filter_code,
};

/* The guest's own SECCOMP_RET_TRACE for number 500, which no syscall table
 * knows; everything else allowed. */
static struct sock_filter trace_unknown_code[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 500, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
static struct sock_fprog trace_unknown_filter = {
    sizeof trace_unknown_code / sizeof trace_unknown_code[0],
    trace_unknown_code,
};

/* A ptrace-stop for a number the tracer cannot decode. The tracer's own
 * filter does not trace 500; the guest's filter does. */
static void mode_guest_trace_unknown(void) {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    die("no_new_privs");
  long r =
      prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &trace_unknown_filter, 0, 0);
  say("install ret=%ld\n", r);
  say("unknown ret=%ld\n", syscall(500, 0, 0, 0, 0, 0, 0));
}

static int tsync_pipe[2];
static long tsync_thread_getppid;

/* Test-only ordering knob: spins without syscalls (a few hundred
 * milliseconds) when TP_ORDER equals `when`, so that the other thread or
 * process almost surely finishes first. The runs must be equal either way. */
static void order_delay(const char* when) {
  const char* order = getenv("TP_ORDER");
  if (!order || strcmp(order, when))
    return;
  for (volatile long i = 0; i < 300L * 1000 * 1000; i++)
    ;
}

static void* tsync_thread_entry(void* arg) {
  (void)arg;
  char c;
  if (read(tsync_pipe[0], &c, 1) != 1)
    _exit(97);
  tsync_thread_getppid = SITE(SYS_getppid, 0, 0, 0, 0, 0);
  order_delay("late");
  return NULL;
}

/* A guest seccomp filter. how: "site" installs with seccomp() through the
 * shared site, "tsync" from a two-thread process through libc, "prctl" with
 * prctl(PR_SET_SECCOMP) through libc. */
static void guest_seccomp(const char* how) {
  install(SIGSYS, 0, handler);
  warm();
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    die("no_new_privs");
  pthread_t thread;
  long r;
  if (!strcmp(how, "tsync")) {
    if (pipe(tsync_pipe) != 0)
      die("pipe");
    if (pthread_create(&thread, NULL, tsync_thread_entry, NULL) != 0)
      die("pthread_create");
    r = syscall(
        SYS_seccomp,
        SECCOMP_SET_MODE_FILTER,
        SECCOMP_FILTER_FLAG_TSYNC,
        &guest_filter);
  } else if (!strcmp(how, "prctl")) {
    r = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &guest_filter, 0, 0);
  } else {
    r = SITE(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &guest_filter, 0, 0);
  }
  say("install %s ret=%ld\n", how, r);
  site_bytes("after install");
  for (int i = 0; i < 3; i++)
    say("getpid %d pid=%d\n", i, SITE(SYS_getpid, 0, 0, 0, 0, 0) == getpid());
  say("getppid ret=%ld\n", SITE(SYS_getppid, 0, 0, 0, 0, 0));
  if (!strcmp(how, "tsync")) {
    if (write(tsync_pipe[1], "x", 1) != 1)
      die("write");
    /* Join without syscalls. pthread_join's futex wait is skipped, returns
     * 0, or returns EAGAIN depending on whether the thread's exit (the
     * kernel clearing its tid) came before the tid load, after the futex
     * call, or between them: host scheduling that changed the Tool-visible
     * stream. pthread_tryjoin_np returns EBUSY without a syscall while the
     * tid is set, and once it is clear it joins without a futex call. */
    order_delay("early");
    while (pthread_tryjoin_np(thread, NULL) == EBUSY)
      __builtin_ia32_pause();
    say("thread getppid ret=%ld\n", tsync_thread_getppid);
  }
  /* SIGCHLD stays blocked (and is inherited blocked) across the fork and the
   * wait, so its one delivery lands at the unblock below instead of wherever
   * the child's exit happens to overtake the parent's wait4. */
  sigset_t chld;
  sigemptyset(&chld);
  sigaddset(&chld, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &chld, NULL) != 0)
    die("block SIGCHLD");
  /* A fork child calls the site, then execs: the new image inherits the
   * filter. */
  pid_t child = fork();
  if (child == 0) {
    for (int i = 0; i < 3; i++)
      say("child getpid %d pid=%d\n",
          i,
          SITE(SYS_getpid, 0, 0, 0, 0, 0) == getpid());
    order_delay("late");
    exec_self("exec_image");
  }
  order_delay("early");
  int status;
  if (waitpid(child, &status, 0) != child)
    die("wait child");
  say("child exited=%d code=%d signaled=%d sig=%d\n",
      WIFEXITED(status),
      WEXITSTATUS(status),
      WIFSIGNALED(status),
      WIFSIGNALED(status) ? WTERMSIG(status) : 0);
  if (sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0)
    die("unblock SIGCHLD");
  say("sigsys handled=%d\n", nrec);
}

static volatile unsigned char sud_selector;
static volatile int sud_count, sud_syscall;
static volatile unsigned sud_arch;
static volatile long sud_call_addr;

static void sud_handler(int sig, siginfo_t* si, void* uc_) {
  ucontext_t* uc = uc_;
  (void)sig;
  sud_count++;
  sud_syscall = si->si_syscall;
  sud_arch = si->si_arch;
  sud_call_addr = (long)si->si_call_addr;
  uc->uc_mcontext.gregs[REG_RAX] = 1234;
  sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
}

/* Syscall user dispatch, with the allowed region excluding the site. */
static void mode_sud(void) {
  install(SIGSYS, 0, sud_handler);
  warm();
  sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
  long r = prctl(
      PR_SET_SYSCALL_USER_DISPATCH,
      PR_SYS_DISPATCH_ON,
      (long)t8_fn,
      (long)(t8_site_end - (char*)t8_fn),
      &sud_selector);
  say("sud on ret=%ld\n", r);
  site_bytes("after sud");
  sud_selector = SYSCALL_DISPATCH_FILTER_BLOCK;
  r = SITE(SYS_getpid, 0, 0, 0, 0, 0);
  sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
  say("dispatched getpid ret=%ld count=%d syscall=%d arch=%#x call=%s\n",
      r,
      sud_count,
      sud_syscall,
      sud_arch,
      where(sud_call_addr));
  r = prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0, 0);
  say("sud off ret=%ld\n", r);
  for (int i = 0; i < 3; i++)
    say("getpid %d pid=%d\n", i, SITE(SYS_getpid, 0, 0, 0, 0, 0) == getpid());
  chld_block();
  pid_t child = fork();
  if (child == 0) {
    for (int i = 0; i < 3; i++)
      say("child getpid %d pid=%d\n",
          i,
          SITE(SYS_getpid, 0, 0, 0, 0, 0) == getpid());
    _exit(0);
  }
  int status;
  if (waitpid(child, &status, 0) != child)
    die("wait child");
  say("child exited=%d code=%d\n", WIFEXITED(status), WEXITSTATUS(status));
  chld_unblock();
  say("sud handled=%d\n", sud_count);
}

static volatile long untraced_ret, untraced_rcx;
static volatile int untraced_done;

static void untraced_entry(void) {
  /* An untraced thread: every syscall it makes is refused by the inherited
   * filter (ENOSYS), so it records one call through the shared site and
   * then spins until exit_group ends it. */
  untraced_ret = SITE(SYS_getpid, 0, 0, 0, 0, 0);
  untraced_rcx = tp_nz_rcx;
  __atomic_store_n(&untraced_done, 1, __ATOMIC_SEQ_CST);
  for (;;)
    __asm__ volatile("pause");
}

/* A CLONE_UNTRACED thread gets no new-child stop. `through`: "libc" clones
 * from libc's syscall(), "site" through the shared site itself. */
static void untraced_thread(const char* through) {
  warm();
  size_t size = 64 * 1024;
  char* stack = mmap(
      NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stack == MAP_FAILED)
    die("mmap stack");
  uintptr_t* top = (uintptr_t*)(stack + size - 64);
  top[0] = (uintptr_t)untraced_entry;
  long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
      CLONE_THREAD | CLONE_SYSVSEM | CLONE_UNTRACED;
  long r;
  if (!strcmp(through, "site"))
    r = SITE(SYS_clone, flags, top, NULL, NULL, 0);
  else
    r = syscall(SYS_clone, flags, top, NULL, NULL, 0);
  say("untraced clone ok=%d\n", r > 0);
  /* Spin without syscalls, so that the stop sequence is the same in every
   * run. */
  while (!__atomic_load_n(&untraced_done, __ATOMIC_SEQ_CST))
    __asm__ volatile("pause");
  say("untraced thread getpid ret=%ld rcx=%s\n",
      untraced_ret,
      where(untraced_rcx));
  site_bytes("after untraced");
}

/* What the untraced fork child saw, in memory shared across the fork. */
struct untraced_fork_view {
  long clone_rcx, clone_r11, ret, rcx;
  unsigned char bytes[2];
  int done;
};

/* A fork-like CLONE_UNTRACED child (no CLONE_VM), cloned through the shared
 * site: it gets no new-child stop and its own copy of the parent's text, and
 * starts right after the parent's `syscall`. The child's syscalls are
 * refused by the inherited filter (ENOSYS: no tracer), so it reports through
 * a shared mapping and spins until the parent kills it. */
static void untraced_fork(void) {
  warm();
  struct untraced_fork_view* view = mmap(
      NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (view == MAP_FAILED)
    die("mmap shared");
  chld_block();
  long r = SITE(SYS_clone, CLONE_UNTRACED | SIGCHLD, NULL, NULL, NULL, 0);
  if (r == 0) {
    view->clone_rcx = tp_z_rcx;
    view->clone_r11 = tp_z_r11;
    view->ret = SITE(SYS_getpid, 0, 0, 0, 0, 0);
    view->rcx = tp_nz_rcx;
    view->bytes[0] = ((unsigned char*)tp_site)[0];
    view->bytes[1] = ((unsigned char*)tp_site)[1];
    __atomic_store_n(&view->done, 1, __ATOMIC_SEQ_CST);
    for (;;)
      __builtin_ia32_pause();
  }
  if (r < 0)
    die("clone untraced");
  say("untraced fork clone ok=1\n");
  /* Spin without syscalls, so that the stop sequence is the same in every
   * run; bounded (a few seconds) for a child that never gets that far. */
  for (long spins = 0;
       !__atomic_load_n(&view->done, __ATOMIC_SEQ_CST) && spins < (1L << 28);
       spins++)
    __builtin_ia32_pause();
  say("untraced fork child done=%d clone rcx=%s r11=%#lx getpid ret=%ld rcx=%s bytes %02x %02x\n",
      __atomic_load_n(&view->done, __ATOMIC_SEQ_CST),
      where(view->clone_rcx),
      view->clone_r11,
      view->ret,
      where(view->rcx),
      view->bytes[0],
      view->bytes[1]);
  if (kill(r, SIGKILL) != 0)
    die("kill untraced");
  siginfo_t info;
  memset(&info, 0, sizeof info);
  if (waitid(P_PID, r, &info, WEXITED) != 0)
    die("waitid untraced");
  say("untraced fork child code=%d status=%d\n", info.si_code, info.si_status);
  chld_unblock();
  site_bytes("after untraced fork");
}

/* A child exits while the parent sleeps in a nanosleep at the site. With
 * SIGCHLD at SIG_DFL the sleep restarts through restart_syscall; with a
 * handler it returns EINTR. */
static void sigchld_sleep(const char* tag) {
  pid_t child = fork();
  if (child < 0)
    die("fork");
  if (child == 0) {
    struct timespec d = {0, 30 * 1000 * 1000};
    nanosleep(&d, NULL);
    _exit(5);
  }
  struct timespec req = {0, 300 * 1000 * 1000}, rem = {0, 0}, t0, t1;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  long r = SITE(SYS_nanosleep, &req, &rem, 0, 0, 0);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  long ms =
      (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
  report_result(tag, r);
  /* Coarse buckets: the restarted sleep ends at the full 300 ms; the
   * interrupted one ends near the child's exit. */
  say("%s slept-full=%d rem-set=%d\n",
      tag,
      ms >= 300,
      rem.tv_sec != 0 || rem.tv_nsec != 0);
  dump(tag);
  int status;
  if (waitpid(child, &status, 0) != child)
    die("waitpid");
  say("%s child exited=%d code=%d\n",
      tag,
      WIFEXITED(status),
      WEXITSTATUS(status));
}

static void mode_sigchld_nanosleep(void) {
  warm();
  sigchld_sleep("sigchld-dfl");
  install(SIGCHLD, 0, handler);
  sigchld_sleep("sigchld-handled");
}

static volatile int tl_a = 1, tl_b = 0, tl_c = 1;
static volatile long tl_sum;
/* The number of branch counts k = 1..TL_K a timer covers, which spans
 * one iteration and the next iteration's arming call. */
#define TL_K 9

/* A loop of 200 iterations, each with a getpid at the site and three
 * conditional branches, preempted by a precise timer at branch count
 * k = 1..TL_K after the arming call. */
static void mode_timer_loop(void) {
  warm();
  for (int i = 0; i < 200; i++) {
    long k = (i % TL_K) + 1;
    SITEM(SYS_getppid, 0, 0, 0, 0, k, ARM_TIMER);
    if (tl_a)
      tl_sum++;
    long r = SITE(SYS_getpid, 0, 0, 0, 0, 0);
    if (tl_b)
      tl_sum++;
    if (tl_c)
      tl_sum++;
    if (tp_nz_r11 != 0x246)
      say("iter %d k=%ld r11=%#lx rcx=%s\n", i, k, tp_nz_r11, where(tp_nz_rcx));
    if (r <= 0)
      die("timer loop getpid");
  }
  say("timer loop sum=%ld\n", tl_sum);
}

/* A precise timer far enough out that perf's MARKER signal (not an
 * artificial one) starts the single-steps, targeted at branch counts around
 * the site's getpid that follows a long branch loop. */
#define PM_BRANCHES 3000
static void mode_perf_marker(void) {
  warm();
  for (int c = 0; c < 4; c++) {
    SITEM(SYS_getppid, 0, 0, 0, 0, PM_BRANCHES + 1 + c, ARM_TIMER);
    for (volatile int j = 0; j < PM_BRANCHES; j++)
      ;
    long r = SITE(SYS_getpid, 0, 0, 0, 0, 0);
    if (tl_b)
      tl_sum++;
    if (tl_c)
      tl_sum++;
    say("marker %d getpid=%d r11=%#lx\n", c, r == getpid(), tp_nz_r11);
  }
}

/* Each SIGTRAP state across a precise timer's single-steps: the timer is
 * armed PM_BRANCHES + 1 branches out and fires in the branch loop, whose
 * last branches it single-steps
 * (https://github.com/rrnewton/hermit/issues/4409). */
static void mode_sigtrap_timer(void) {
  warm();
  static const struct {
    const char* name;
    void (*action)(int);
    int block;
  } states[] = {
      {"ign-blocked", SIG_IGN, 1},
      {"ign", SIG_IGN, 0},
      {"handler-blocked", trap_handler, 1},
      {"handler", trap_handler, 0},
      {"dfl-blocked", SIG_DFL, 1},
  };
  for (unsigned i = 0; i < sizeof states / sizeof states[0]; i++) {
    sigtrap_set(states[i].action, states[i].block);
    SITEM(SYS_getppid, 0, 0, 0, 0, PM_BRANCHES + 1, ARM_TIMER);
    for (volatile int j = 0; j < 3 * PM_BRANCHES; j++)
      ;
    char tag[64];
    snprintf(tag, sizeof tag, "timer %s", states[i].name);
    sigtrap_full_state(tag);
  }
}

static volatile long sigreturn_k;

/* Arms a precise timer sigreturn_k branches out from inside a SIGUSR1
 * handler, so that its single-steps run the handler's return: every signal
 * delivery is a stop the Tool sees, which would cancel a timer armed
 * before it. */
static void arming_handler(int sig) {
  (void)sig;
  SITEM(SYS_getppid, 0, 0, 0, 0, sigreturn_k, ARM_TIMER);
}

/* A guest rt_sigreturn single-stepped by a precise timer, from a frame whose
 * mask blocks SIGTRAP while SIGTRAP is caught. */
static void mode_sigtrap_sigreturn_timer(void) {
  warm();
  struct sigaction usr1;
  memset(&usr1, 0, sizeof usr1);
  usr1.sa_handler = arming_handler;
  if (sigaction(SIGUSR1, &usr1, NULL) != 0)
    die("install SIGUSR1");
  sigtrap_set(trap_handler, 1);
  for (int k = 1; k <= 8; k++) {
    sigreturn_k = k;
    raise(SIGUSR1);
    for (volatile int j = 0; j < 16; j++)
      ;
    char tag[64];
    snprintf(tag, sizeof tag, "sigreturn k=%d", k);
    sigtrap_full_state(tag);
  }
}

static void quiet_usr1(int sig) {
  (void)sig;
}

/* SIGTRAP's state across a mask-swapping wait that a handled SIGUSR1
 * interrupts, injected on the private page (SHAPE_PRIVATE_CALL). SIGUSR1 is
 * blocked and pending before the call, so the wait returns at once with its
 * temporary mask's restore pending, and the SIGUSR1 is delivered as the
 * guest resumes. The temporary mask holds SIGTRAP in the -tmask states. */
static void mode_sigtrap_interrupted_waits(void) {
  warm();
  struct sigaction usr1;
  memset(&usr1, 0, sizeof usr1);
  usr1.sa_handler = quiet_usr1;
  if (sigaction(SIGUSR1, &usr1, NULL) != 0)
    die("install SIGUSR1");
  static const struct {
    const char* name;
    void (*action)(int);
    int block;
    int tmask;
  } states[] = {
      {"ign", SIG_IGN, 0, 0},
      {"ign-tmask", SIG_IGN, 0, 1},
      {"handler-tmask", trap_handler, 0, 1},
      {"handler-blocked", trap_handler, 1, 1},
  };
  static const char* const ops[] = {"sigsuspend", "ppoll"};
  sigset_t usr1_set;
  sigemptyset(&usr1_set);
  sigaddset(&usr1_set, SIGUSR1);
  for (int op = 0; op < 2; op++) {
    for (unsigned i = 0; i < sizeof states / sizeof states[0]; i++) {
      sigtrap_set(states[i].action, states[i].block);
      if (sigprocmask(SIG_BLOCK, &usr1_set, NULL) != 0)
        die("block SIGUSR1");
      raise(SIGUSR1);
      unsigned long temporary = states[i].tmask ? 1UL << (SIGTRAP - 1) : 0;
      struct timespec ts = {5, 0};
      long r = op == 0
          ? SITEM(SYS_rt_sigsuspend, (long)&temporary, 8, 0, 0, 0, SHAPE_PRIVATE_CALL)
          : SITEM(SYS_ppoll, 0, 0, (long)&ts, (long)&temporary, 8, SHAPE_PRIVATE_CALL);
      if (sigprocmask(SIG_UNBLOCK, &usr1_set, NULL) != 0)
        die("unblock SIGUSR1");
      char tag[64];
      snprintf(tag, sizeof tag, "wait %s %s r=%s", ops[op], states[i].name,
               r == -EINTR ? "eintr" : "other");
      sigtrap_full_state(tag);
    }
  }
}

/* SIG_IGN, a guest fork (whose parent Reverie steps from its clone event
 * stop), then the guest installs a handler with a call the Tool may run in
 * place, then a private injection: the handler stays. */
static void mode_sigtrap_fork_then_sigaction(void) {
  sigtrap_set(SIG_IGN, 0);
  pid_t pid = fork();
  if (pid < 0)
    die("fork");
  if (pid == 0)
    _exit(0);
  sigtrap_full_state("stale after-fork");
  sigtrap_set(trap_handler, 0);
  sigtrap_full_state("stale after-sigaction");
  SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
  sigtrap_full_state("stale after-private");
  int status;
  if (waitpid(pid, &status, 0) != pid)
    die("wait");
}

/* A guest int3 inside a precise timer's single-stepped window, with SIGTRAP
 * caught and blocked, or ignored: its own force_sig resets SIGTRAP, and the
 * child dies by SIGTRAP, as natively. Each encoding: int3; behind an
 * operand-size prefix; behind REX prefixes that are not last, which the CPU
 * ignores; and int3 in an execute-only page. Every encoding runs the same
 * way, as a snippet (the encoding, then ret) called through a pointer chosen
 * before the counted loop, so that its int3 is the same number of branches
 * out, which the timer offsets c = 2 to 5 put inside the single-stepped
 * window. */
static void mode_sigtrap_int3_timer(void) {
  warm();
  static const struct {
    const char* name;
    const char* bytes;
    size_t len;
  } encodings[] = {
      {"cc", "\xcc\xc3", 2},
      {"66cc", "\x66\xcc\xc3", 3},
      {"4848cc", "\x48\x48\xcc\xc3", 4},
      {"4866cc", "\x48\x66\xcc\xc3", 4},
      {"xo-cc", "\xcc\xc3", 2},
  };
  enum { ENCODINGS = sizeof encodings / sizeof encodings[0] };
  unsigned char* code =
      mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (code == MAP_FAILED)
    die("snippet mmap");
  void (*snippets[ENCODINGS])(void);
  for (unsigned e = 0; e < ENCODINGS; e++) {
    /* The execute-only snippet has the second page to itself. */
    unsigned char* at = e == ENCODINGS - 1 ? code + 4096 : code + 64 * e;
    memcpy(at, encodings[e].bytes, encodings[e].len);
    snippets[e] = (void (*)(void))at;
  }
  if (mprotect(code, 4096, PROT_READ | PROT_EXEC) != 0 ||
      mprotect(code + 4096, 4096, PROT_EXEC) != 0)
    die("snippet mprotect");
  static const struct {
    const char* name;
    void (*action)(int);
    int block;
    int arm;
  } cases[] = {
      {"handler-blocked-notimer", trap_handler, 1, 0},
      {"handler-blocked", trap_handler, 1, 1},
      {"ign", SIG_IGN, 0, 1},
      {"ign-blocked", SIG_IGN, 1, 1},
  };
  for (unsigned e = 0; e < ENCODINGS; e++)
  for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    for (int c = 2; c < 6; c++) {
      pid_t pid = fork();
      if (pid < 0)
        die("fork");
      if (pid == 0) {
        /* No core dump. The host's core pattern can pipe every dump to a
         * collector, which only a limit of exactly 1 stops (a limit of 0 does
         * not, and PR_SET_DUMPABLE would close the tracer's procfs reads). The
         * child still dies by SIGTRAP. */
        struct rlimit core = {1, 1};
        if (setrlimit(RLIMIT_CORE, &core) != 0)
          die("RLIMIT_CORE");
        void (*volatile snippet)(void) = snippets[e];
        sigtrap_set(cases[i].action, cases[i].block);
        if (cases[i].arm)
          SITEM(SYS_getppid, 0, 0, 0, 0, PM_BRANCHES + 1 + c, ARM_TIMER);
        for (volatile int j = 0; j < PM_BRANCHES; j++)
          ;
        snippet();
        _exit(0);
      }
      int status;
      if (waitpid(pid, &status, 0) != pid)
        die("wait int3 child");
      say("int3 %s %s c=%d signaled=%d sig=%d\n",
          encodings[e].name,
          cases[i].name,
          c,
          WIFSIGNALED(status),
          WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    }
  }
}

/* SIGTRAP blocked with one pending, then a private injection, which Reverie
 * must single-step: the run ends with a named failure. */
static void mode_sigtrap_pending_at_step(void) {
  sigtrap_set(trap_handler, 1);
  if (syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGTRAP) != 0)
    die("tgkill SIGTRAP");
  SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
  say("pending SIGTRAP survived a private injection\n");
}

/* Calls the shared site with getppid, `marker` in r9, on the stack `sp`. */
extern long tight_stack_site(void* sp, long marker);
__asm__(".text\n.globl tight_stack_site\n.type tight_stack_site,@function\n"
        "tight_stack_site:\n"
        "push %r12\nmov %rsp,%r12\nmov %rdi,%rsp\n"
        "push %rsi\n"
        "mov $110,%edi\nxor %esi,%esi\nxor %edx,%edx\nxor %ecx,%ecx\n"
        "xor %r8d,%r8d\nxor %r9d,%r9d\ncall tp_site_fn\n"
        "mov %r12,%rsp\npop %r12\nret\n"
        ".size tight_stack_site,.-tight_stack_site\n");

/* An emulated call with SIGTRAP ignored and blocked, on a one-page stack
 * between inaccessible guard pages, `offset` bytes above the lower guard.
 * Reverie's SIGTRAP repair keeps its scratch out of guest memory: the call
 * succeeds, and 32 canary bytes where a scratch below the red zone and a
 * Tool's stack would sit stay unchanged. */
static void mode_sigtrap_tight_stack(void) {
  warm();
  unsigned char* map = mmap(NULL, 12288, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (map == MAP_FAILED || mprotect(map + 4096, 4096, PROT_READ | PROT_WRITE) != 0)
    die("tight stack mapping");
  unsigned char* base = map + 4096;
  static const int offsets[] = {512, 2048};
  for (unsigned i = 0; i < sizeof offsets / sizeof offsets[0]; i++) {
    sigtrap_set(SIG_IGN, 1);
    memset(base, 0xa5, 4096);
    void* sp = base + offsets[i];
    long r = tight_stack_site(sp, TP_MAGIC | ((++tp_seq) << 16) | SHAPE_EMULATE);
    int changed = -1;
    uintptr_t canary = (((uintptr_t)sp - 16) - 1056) & ~(uintptr_t)15;
    if (canary >= (uintptr_t)base) {
      changed = 0;
      for (unsigned b = 0; b < 32; b++)
        changed += ((volatile unsigned char*)canary)[b] != 0xa5;
    }
    char tag[64];
    snprintf(tag, sizeof tag, "tight %d r=%ld changed=%d", offsets[i], r, changed);
    sigtrap_full_state(tag);
  }
  munmap(map, 12288);
}

static _Atomic int observer_request;
static _Atomic int observer_done;
static _Atomic int observer_round;
static _Atomic uintptr_t observer_seen;

/* Reads SIGTRAP's action in each round, while the interrupted thread's
 * SIGUSR1 handler waits for it without a syscall. */
static void* sigtrap_observer(void* unused) {
  (void)unused;
  for (int n = 1; n <= 8; n++) {
    while (atomic_load_explicit(&observer_request, memory_order_acquire) != n)
      __asm__ volatile("pause");
    struct sigaction sa;
    if (sigaction(SIGTRAP, NULL, &sa) != 0)
      _exit(76);
    atomic_store(&observer_seen, (uintptr_t)sa.sa_handler);
    atomic_store_explicit(&observer_done, n, memory_order_release);
  }
  return NULL;
}

static void observed_usr1(int sig) {
  (void)sig;
  int n = atomic_load(&observer_round);
  atomic_store_explicit(&observer_request, n, memory_order_release);
  while (atomic_load_explicit(&observer_done, memory_order_acquire) != n)
    __asm__ volatile("pause");
}

static int sigtrap_observer_process(void* unused) {
  sigtrap_observer(unused);
  return 0;
}

/* The interrupted waits of mode_sigtrap_interrupted_waits, with an observer
 * that reads SIGTRAP's action while the first thread's SIGUSR1 handler runs,
 * before that thread makes another syscall: the action a Reverie trap reset
 * must already be repaired for the observer. The observer is a sibling
 * thread, or (`process`) another process that shares the address space and
 * the signal actions (CLONE_VM | CLONE_SIGHAND, without CLONE_THREAD). */
static void sigtrap_interrupted_waits_observed(int process) {
  warm();
  struct sigaction usr1;
  memset(&usr1, 0, sizeof usr1);
  usr1.sa_handler = observed_usr1;
  if (sigaction(SIGUSR1, &usr1, NULL) != 0)
    die("install SIGUSR1");
  pthread_t observer;
  pid_t observer_pid = -1;
  static char observer_stack[65536] __attribute__((aligned(16)));
  if (process) {
    observer_pid = clone(sigtrap_observer_process, observer_stack + sizeof observer_stack,
                         CLONE_VM | CLONE_SIGHAND | SIGCHLD, NULL);
    if (observer_pid < 0)
      die("observer process");
  } else if (pthread_create(&observer, NULL, sigtrap_observer, NULL) != 0)
    die("observer thread");
  static const struct {
    const char* name;
    void (*action)(int);
    int block;
    int tmask;
  } states[] = {
      {"ign", SIG_IGN, 0, 0},
      {"ign-tmask", SIG_IGN, 0, 1},
      {"handler-tmask", trap_handler, 0, 1},
      {"handler-blocked", trap_handler, 1, 1},
  };
  static const char* const ops[] = {"sigsuspend", "ppoll"};
  sigset_t usr1_set;
  sigemptyset(&usr1_set);
  sigaddset(&usr1_set, SIGUSR1);
  for (int op = 0; op < 2; op++) {
    for (unsigned i = 0; i < sizeof states / sizeof states[0]; i++) {
      sigtrap_set(states[i].action, states[i].block);
      atomic_store(&observer_round, op * 4 + (int)i + 1);
      if (sigprocmask(SIG_BLOCK, &usr1_set, NULL) != 0)
        die("block SIGUSR1");
      raise(SIGUSR1);
      unsigned long temporary = states[i].tmask ? 1UL << (SIGTRAP - 1) : 0;
      struct timespec ts = {5, 0};
      long r = op == 0
          ? SITEM(SYS_rt_sigsuspend, (long)&temporary, 8, 0, 0, 0, SHAPE_PRIVATE_CALL)
          : SITEM(SYS_ppoll, 0, 0, (long)&ts, (long)&temporary, 8, SHAPE_PRIVATE_CALL);
      if (sigprocmask(SIG_UNBLOCK, &usr1_set, NULL) != 0)
        die("unblock SIGUSR1");
      uintptr_t seen = atomic_load(&observer_seen);
      say("observed %s %s r=%s sibling=%s\n",
          ops[op],
          states[i].name,
          r == -EINTR ? "eintr" : "other",
          seen == (uintptr_t)SIG_DFL       ? "dfl"
              : seen == (uintptr_t)SIG_IGN ? "ign"
              : seen == (uintptr_t)trap_handler ? "trap_handler"
                                                : "other");
    }
  }
  if (process) {
    int status;
    if (waitpid(observer_pid, &status, 0) != observer_pid || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
      die("wait observer process");
  } else if (pthread_join(observer, NULL) != 0)
    die("join observer");
}

static void mode_sigtrap_interrupted_waits_observed(void) {
  sigtrap_interrupted_waits_observed(0);
}

static void mode_sigtrap_interrupted_waits_observed_process(void) {
  sigtrap_interrupted_waits_observed(1);
}

/* A caught, unblocked SIGTRAP through each handler shape: no step can reset
 * it, so Reverie makes no repair injection. */
static void mode_sigtrap_caught_unblocked(void) {
  warm();
  static const long shapes[] = {SHAPE_INJECT, SHAPE_TAIL, SHAPE_EMULATE,
                                SHAPE_PRIVATE, SHAPE_TWO_INJECTS, SHAPE_TWO_PRIVATE};
  for (unsigned j = 0; j < sizeof shapes / sizeof shapes[0]; j++) {
    sigtrap_set(trap_handler, 0);
    SITEM(SYS_getppid, 0, 0, 0, 0, 0, shapes[j]);
    char tag[32];
    snprintf(tag, sizeof tag, "caught shape=%ld", shapes[j]);
    sigtrap_full_state(tag);
  }
}

/* A guest int3 right after a wait that a handled SIGUSR1 interrupted, with a
 * caught, unblocked SIGTRAP and SIGTRAP in the wait's temporary mask. The
 * step after the wait reset SIGTRAP, and the repair can run only once the
 * thread reaches its next syscall (the restore is pending until the SIGUSR1
 * is delivered), so the int3 meets SIG_DFL and kills the child. Natively the
 * handler runs and the child exits 0. A phase-0 limit, pinned here. */
static void mode_sigtrap_int3_after_interrupted_wait(void) {
  warm();
  for (int op = 0; op < 2; op++) {
    pid_t pid = fork();
    if (pid < 0)
      die("fork");
    if (pid == 0) {
      struct rlimit core = {1, 1};
      if (setrlimit(RLIMIT_CORE, &core) != 0)
        die("RLIMIT_CORE");
      struct sigaction usr1;
      memset(&usr1, 0, sizeof usr1);
      usr1.sa_handler = quiet_usr1;
      if (sigaction(SIGUSR1, &usr1, NULL) != 0)
        die("install SIGUSR1");
      sigtrap_set(trap_handler, 0);
      sigset_t usr1_set;
      sigemptyset(&usr1_set);
      sigaddset(&usr1_set, SIGUSR1);
      if (sigprocmask(SIG_BLOCK, &usr1_set, NULL) != 0)
        die("block SIGUSR1");
      raise(SIGUSR1);
      unsigned long temporary = 1UL << (SIGTRAP - 1);
      struct timespec ts = {5, 0};
      if (op == 0)
        SITEM(SYS_rt_sigsuspend, (long)&temporary, 8, 0, 0, 0, SHAPE_PRIVATE_CALL);
      else
        SITEM(SYS_ppoll, 0, 0, (long)&ts, (long)&temporary, 8, SHAPE_PRIVATE_CALL);
      __asm__ volatile("int3");
      _exit(0);
    }
    int status;
    if (waitpid(pid, &status, 0) != pid)
      die("wait int3-after-wait child");
    say("after-wait %s signaled=%d sig=%d exited=%d\n",
        op == 0 ? "sigsuspend" : "ppoll",
        WIFSIGNALED(status),
        WIFSIGNALED(status) ? WTERMSIG(status) : 0,
        WIFEXITED(status) ? WEXITSTATUS(status) : -1);
  }
}

static _Atomic int window_in_handler, window_sibling_done;

static void window_spinning_usr1(int sig) {
  (void)sig;
  atomic_store(&window_in_handler, 1);
  while (!atomic_load(&window_sibling_done))
    __asm__ volatile("pause");
}

static void* window_sibling_int3(void* arg) {
  (void)arg;
  while (!atomic_load(&window_in_handler))
    __asm__ volatile("pause");
  __asm__ volatile("int3");
  atomic_store(&window_sibling_done, 1);
  return NULL;
}

static volatile int window_callback_done;

static void window_int3_handler(int sig) {
  (void)sig;
  __asm__ volatile("int3");
  window_callback_done = 1;
}

/* Reports how a window child ended. */
static void window_report(const char* tag, pid_t pid) {
  int status;
  if (waitpid(pid, &status, 0) != pid)
    die("wait window child");
  say("%s signaled=%d sig=%d exited=%d\n",
      tag,
      WIFSIGNALED(status),
      WIFSIGNALED(status) ? WTERMSIG(status) : 0,
      WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

/* The same window, met by another thread: a wait that a handled SIGUSR1
 * interrupted, with a caught, unblocked SIGTRAP in the wait's temporary mask
 * (tmask=1) or not (tmask=0), whose handler spins without a syscall while a
 * sibling executes int3. With tmask=1 the int3 meets SIG_DFL and kills the
 * child; natively, and with tmask=0, the handler runs and it exits 0. Then a
 * POSIX-timer signal whose Tool callback injects (SIGXCPU: between block-all
 * rt_sigprocmask injections, whose trap resets SIGTRAP; SIGPROF: getpid,
 * which the shield covers), and whose guest handler executes int3 before any
 * syscall: the repair waits for a stop outside the callback, so with SIGXCPU
 * the int3 meets SIG_DFL. Phase-0 limits, pinned here. */
static void mode_sigtrap_int3_in_the_other_windows(void) {
  warm();
  for (int op = 0; op < 2; op++) {
    for (int tmask = 0; tmask < 2; tmask++) {
      pid_t pid = fork();
      if (pid < 0)
        die("fork");
      if (pid == 0) {
        struct rlimit core = {1, 1};
        if (setrlimit(RLIMIT_CORE, &core) != 0)
          die("RLIMIT_CORE");
        struct sigaction usr1;
        memset(&usr1, 0, sizeof usr1);
        usr1.sa_handler = window_spinning_usr1;
        if (sigaction(SIGUSR1, &usr1, NULL) != 0)
          die("install SIGUSR1");
        sigtrap_set(trap_handler, 0);
        pthread_t sibling;
        if (pthread_create(&sibling, NULL, window_sibling_int3, NULL) != 0)
          die("pthread_create");
        sigset_t usr1_set;
        sigemptyset(&usr1_set);
        sigaddset(&usr1_set, SIGUSR1);
        if (pthread_sigmask(SIG_BLOCK, &usr1_set, NULL) != 0)
          die("block SIGUSR1");
        if (syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1) != 0)
          die("tgkill SIGUSR1");
        unsigned long temporary = tmask ? 1UL << (SIGTRAP - 1) : 0;
        struct timespec ts = {5, 0};
        if (op == 0)
          SITEM(SYS_rt_sigsuspend, (long)&temporary, 8, 0, 0, 0, SHAPE_PRIVATE_CALL);
        else
          SITEM(SYS_ppoll, 0, 0, (long)&ts, (long)&temporary, 8, SHAPE_PRIVATE_CALL);
        pthread_join(sibling, NULL);
        _exit(0);
      }
      char tag[64];
      snprintf(tag, sizeof tag, "sibling %s tmask=%d", op == 0 ? "sigsuspend" : "ppoll", tmask);
      window_report(tag, pid);
    }
  }
  static const struct {
    const char* name;
    int signo;
  } signals[] = {{"prof", SIGPROF}, {"xcpu", SIGXCPU}};
  for (unsigned s = 0; s < sizeof signals / sizeof signals[0]; s++) {
    pid_t pid = fork();
    if (pid < 0)
      die("fork");
    if (pid == 0) {
      struct rlimit core = {1, 1};
      if (setrlimit(RLIMIT_CORE, &core) != 0)
        die("RLIMIT_CORE");
      sigtrap_set(trap_handler, 0);
      struct sigaction sa;
      memset(&sa, 0, sizeof sa);
      sa.sa_handler = window_int3_handler;
      sigemptyset(&sa.sa_mask);
      if (sigaction(signals[s].signo, &sa, NULL) != 0)
        die("install window handler");
      struct sigevent sev;
      memset(&sev, 0, sizeof sev);
      sev.sigev_notify = SIGEV_SIGNAL;
      sev.sigev_signo = signals[s].signo;
      timer_t timer;
      if (timer_create(CLOCK_MONOTONIC, &sev, &timer) != 0)
        die("timer_create");
      struct itimerspec spec = {{0, 0}, {0, 2000000}};
      if (timer_settime(timer, 0, &spec, NULL) != 0)
        die("timer_settime");
      /* Waits without keeping a value in rax: an injection from a signal
       * callback leaves its return there when the signal stopped user code
       * (restore_context keeps the injection's rax outside a held-signal
       * callback), a separate Reverie defect that would otherwise end this
       * child by SIGSEGV now and then. */
      __asm__ volatile("1: pause\n\tcmpl $0, %0\n\tje 1b" : : "m"(window_callback_done) : "memory", "cc");
      _exit(0);
    }
    char tag[32];
    snprintf(tag, sizeof tag, "callback %s", signals[s].name);
    window_report(tag, pid);
  }
}

/* A sibling that maps pages while another thread's private injections
 * reset an ignored SIGTRAP, so that each one repairs. Thread A makes 4000
 * private injections and reads SIGTRAP's action after each. Thread B loops:
 * with reserved == 0, it finds a hole with mmap(NULL), unmaps it and maps it
 * again at that address (MAP_FIXED on odd rounds, MAP_FIXED_NOREPLACE on even
 * ones), the usual find-a-hole sequence; with reserved == 1 it tries to map
 * Reverie's sealed repair page at 0x71001000 over with MAP_FIXED, which the
 * seal refuses (EPERM, counted as refused). Either way it fills its page, makes a few
 * syscalls, and reads the page back, with process_vm_writev and readv, which
 * fail rather than fault on a page that is gone. Counts: lost (the page was
 * gone), changed (the page changed at all), eexist (a mapping at a hole the sibling found failed), and
 * action-bad (A read SIGTRAP not ignored). Natively all are 0. */
static atomic_int race_stop;
static int race_reserved;
static long race_iters, race_lost, race_changed, race_eexist, race_refused;
static void* race_mapper(void* arg) {
  (void)arg;
  static unsigned char pattern[4096], back[4096];
  memset(pattern, 0x5a, sizeof pattern);
  while (!atomic_load(&race_stop)) {
    void* p;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    if (race_reserved) {
      p = (void*)0x71001000;
      flags |= MAP_FIXED;
    } else {
      p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, flags, -1, 0);
      if (p == MAP_FAILED)
        die("race mmap");
      munmap(p, 4096);
      flags |= (race_iters & 1) ? MAP_FIXED : MAP_FIXED_NOREPLACE;
    }
    void* q = mmap(p, 4096, PROT_READ | PROT_WRITE, flags, -1, 0);
    race_iters++;
    if (q == MAP_FAILED) {
      if (errno == EEXIST) {
        race_eexist++;
        continue;
      }
      if (race_reserved && errno == EPERM) {
        race_refused++;
        continue;
      }
      die("race mmap at hole");
    }
    if (q != p) {
      race_eexist++;
      munmap(q, 4096);
      continue;
    }
    struct iovec local = {pattern, 4096}, remote = {q, 4096};
    if (process_vm_writev(getpid(), &local, 1, &remote, 1, 0) != 4096) {
      race_lost++;
      continue;
    }
    for (int k = 0; k < 3; k++)
      syscall(SYS_getppid);
    struct iovec local2 = {back, 4096};
    if (process_vm_readv(getpid(), &local2, 1, &remote, 1, 0) != 4096) {
      race_lost++;
      continue;
    }
    if (memcmp(back, pattern, 4096))
      race_changed++;
    munmap(q, 4096);
  }
  return NULL;
}

static void sigtrap_mmap_race(int reserved) {
  sigtrap_set(SIG_IGN, 0);
  race_reserved = reserved;
  pthread_t b;
  if (pthread_create(&b, NULL, race_mapper, NULL))
    die("race pthread_create");
  long bad = 0;
  for (int i = 0; i < 4000; i++) {
    SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
    struct sigaction sa;
    if (sigaction(SIGTRAP, NULL, &sa) != 0)
      die("race read sigtrap");
    if (sa.sa_handler != SIG_IGN) {
      bad++;
      sigtrap_set(SIG_IGN, 0);
    }
  }
  atomic_store(&race_stop, 1);
  pthread_join(b, NULL);
  say("race reserved=%d lost=%ld changed=%ld eexist=%ld action-bad=%ld iters-nonzero=%d%s\n",
      reserved, race_lost, race_changed, race_eexist, bad, race_iters > 0,
      reserved ? (race_refused == race_iters ? " refused=all" : " refused=not-all") : "");
}

static void mode_sigtrap_mmap_race(void) {
  sigtrap_mmap_race(0);
}

static void mode_sigtrap_reserved_page_race(void) {
  sigtrap_mmap_race(1);
}

/* Witnesses from the Claude reviewer's re-check of
 * https://github.com/rrnewton/reverie/pull/1070 at 369612ad (rev 8), kept as
 * regressions for Reverie's sealed SIGTRAP repair page
 * (https://github.com/rrnewton/hermit/issues/4409). */
/* W1: MADV_DONTFORK on the sealed rw repair page, then fork. The child has no
 * page at 0x71001000; with own=1 it maps its own page there, fills it, and
 * runs a private injection with SIGTRAP ignored. Natively: changed=0 ign. */
static void rv_dontfork(int own) {
  sigtrap_set(SIG_IGN, 0);
  int adv = madvise((void*)0x71001000, 4096, MADV_DONTFORK) ? errno : 0;
  pid_t pid = fork();
  if (pid < 0)
    die("fork");
  if (pid == 0) {
    unsigned char v;
    int mapped = mincore((void*)0x71001000, 4096, &v) == 0;
    int changed = -1;
    unsigned char* page = NULL;
    static unsigned char copy[4096];
    if (own) {
      page = mmap((void*)0x71001000, 4096, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
      if (page != (void*)0x71001000)
        page = NULL;
      if (page) {
        memset(page, 0xa5, 4096);
        memcpy(copy, page, 4096);
      }
    }
    SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
    syscall(SYS_getppid);
    if (page) {
      changed = 0;
      for (int i = 0; i < 4096; i++)
        changed += page[i] != copy[i];
    }
    char tag[128];
    snprintf(tag, sizeof tag, "rv-dontfork own=%d madvise=%d child-scratch-mapped=%d own-page=%d changed=%d",
             own, adv, mapped, page != NULL, changed);
    sigtrap_full_state(tag);
    _exit(0);
  }
  int status;
  if (waitpid(pid, &status, 0) != pid)
    die("wait");
  say("rv-dontfork child-status=%#x\n", status);
}
static void mode_sigtrap_rv_dontfork_own(void) { rv_dontfork(1); }
static void mode_sigtrap_rv_dontfork_none(void) { rv_dontfork(0); }

/* W2: a guest seccomp filter that refuses mseal (nr 462), installed before an
 * exec. The exec'd image says hello. Natively the child exits 0. */
static void mode_sigtrap_rv_exec_hello(void) {
  say("rv-exec-hello\n");
}
static void rv_seccomp_exec(unsigned int action) {
  pid_t pid = fork();
  if (pid < 0)
    die("fork");
  if (pid == 0) {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 462, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, action),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {sizeof f / sizeof f[0], f};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
      die("nnp");
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
      die("seccomp");
    exec_self("sigtrap_rv_exec_hello");
  }
  int status;
  if (waitpid(pid, &status, 0) != pid)
    die("wait");
  say("rv-seccomp-exec action=%#x exited=%d code=%d signaled=%d sig=%d\n", action,
      WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1,
      WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : -1);
}
static void mode_sigtrap_rv_seccomp_exec_kill(void) { rv_seccomp_exec(SECCOMP_RET_KILL_PROCESS); }
static void mode_sigtrap_rv_seccomp_exec_errno(void) { rv_seccomp_exec(SECCOMP_RET_ERRNO | EPERM); }
static void mode_sigtrap_rv_seccomp_exec_trap(void) { rv_seccomp_exec(SECCOMP_RET_TRAP); }


/* W4 (Codex P2-2 shape): a CLONE_VM process with its own signal-action table
 * (no CLONE_SIGHAND, no CLONE_THREAD) tries to replace the repair page with
 * MAP_FIXED, mremap and shmat(SHM_REMAP), while the parent's private
 * injections repair an ignored SIGTRAP. A replacement that succeeds is
 * filled and checked over the whole page (byte 0 on). Natively: refused=all
 * (sealed) is not native, but changed=0 lost=0 is. */
static atomic_int rvc_stop;
static long rvc_iters, rvc_refused, rvc_mapped, rvc_changed;
static int rvc_child(void* arg) {
  (void)arg;
  static unsigned char pattern[4096];
  memset(pattern, 0x5a, sizeof pattern);
  int shm = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
  void* other = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  while (!atomic_load(&rvc_stop)) {
    void* want = (void*)0x71001000;
    void* q;
    switch (rvc_iters % 3) {
      case 0:
        q = mmap(want, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        break;
      case 1:
        q = mremap(other, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, want);
        if (q == MAP_FAILED)
          break;
        other = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        break;
      default:
        q = shmat(shm, want, SHM_REMAP);
        if (q == (void*)-1)
          q = MAP_FAILED;
        break;
    }
    rvc_iters++;
    if (q == MAP_FAILED) {
      rvc_refused++;
      continue;
    }
    rvc_mapped++;
    memcpy(q, pattern, 4096);
    for (int k = 0; k < 3; k++)
      syscall(SYS_getppid);
    if (memcmp(q, pattern, 4096))
      rvc_changed++;
  }
  shmctl(shm, IPC_RMID, 0);
  return 0;
}
static void mode_sigtrap_rv_clonevm_replace(void) {
  sigtrap_set(SIG_IGN, 0);
  static char stack[1 << 16] __attribute__((aligned(16)));
  pid_t c = clone(rvc_child, stack + sizeof stack, CLONE_VM | SIGCHLD, NULL);
  if (c < 0)
    die("clone");
  long bad = 0;
  for (int i = 0; i < 4000; i++) {
    SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
    struct sigaction sa;
    if (sigaction(SIGTRAP, NULL, &sa) != 0)
      die("rvc read");
    if (sa.sa_handler != SIG_IGN) {
      bad++;
      sigtrap_set(SIG_IGN, 0);
    }
  }
  atomic_store(&rvc_stop, 1);
  int status;
  if (waitpid(c, &status, 0) != c)
    die("rvc wait");
  say("rv-clonevm iters-nonzero=%d refused-all=%d mapped=%ld changed=%ld action-bad=%ld child-status=%#x\n",
      rvc_iters > 0, rvc_refused == rvc_iters, rvc_mapped, rvc_changed, bad, status);
}

/* W3b: as W3, but B stops at its first lost write, has A stop and finish its
 * current injection, and reads SIGTRAP again with no thread mid-step:
 * persistent=1 means B's SIG_DFL is still gone (SIG_IGN) at a quiescent read. */
static atomic_int rvp_stop, rvp_a_done;
static long rvp_rounds;
static int rvp_found, rvp_persistent;
static void* rvp_setter(void* arg) {
  (void)arg;
  while (!atomic_load(&rvp_stop)) {
    sigtrap_set(SIG_DFL, 0);
    struct sigaction sa;
    if (sigaction(SIGTRAP, NULL, &sa) != 0)
      die("rvp read");
    rvp_rounds++;
    if (sa.sa_handler == SIG_IGN) {
      rvp_found = 1;
      atomic_store(&rvp_stop, 1);
      while (!atomic_load(&rvp_a_done))
        ;
      struct sigaction again;
      if (sigaction(SIGTRAP, NULL, &again) != 0)
        die("rvp reread");
      rvp_persistent = again.sa_handler == SIG_IGN;
      return NULL;
    }
    sigtrap_set(SIG_IGN, 0);
  }
  return NULL;
}
static void mode_sigtrap_rv_sibling_dfl_persist(void) {
  sigtrap_set(SIG_IGN, 0);
  pthread_t b;
  if (pthread_create(&b, NULL, rvp_setter, NULL))
    die("rvp pthread_create");
  for (int i = 0; i < 20000 && !atomic_load(&rvp_stop); i++)
    SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
  atomic_store(&rvp_stop, 1);
  atomic_store(&rvp_a_done, 1);
  pthread_join(b, NULL);
  say("rv-sibling-dfl-persist found=%d persistent=%d\n", rvp_found, rvp_persistent);
}


/* Witness N1 from the Claude reviewer's re-check of
 * https://github.com/rrnewton/reverie/pull/1070 at 5f6ca515 (rev 9): a guest
 * seccomp filter installed after exec that acts on rt_sigaction must never
 * meet a SIGTRAP repair's own call (https://github.com/rrnewton/hermit/issues/4409). */
static void rw9_sigtrap(void (*action)(int)) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = action;
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGTRAP, &sa, NULL) != 0)
    die("rw9 set sigtrap");
}
/* SIGTRAP ignored per procfs SigIgn (no rt_sigaction needed). */
static int rw9_sigign(void) {
  char buf[4096];
  int fd = open("/proc/thread-self/status", O_RDONLY);
  if (fd < 0)
    return -1;
  ssize_t n = read(fd, buf, sizeof buf - 1);
  close(fd);
  if (n <= 0)
    return -1;
  buf[n] = 0;
  char* p = strstr(buf, "SigIgn:");
  if (!p)
    return -1;
  unsigned long long v = strtoull(p + 7, NULL, 16);
  return (int)((v >> (SIGTRAP - 1)) & 1);
}

/* N1: a guest that ignores SIGTRAP, then (no exec) installs a seccomp filter
 * that acts on rt_sigaction (nr 13), then makes one private injection. The
 * guest itself never calls rt_sigaction after the filter. Natively the child
 * exits 0 with SIGTRAP still ignored. */
static void rw9_filter_rt_sigaction(unsigned int action) {
  pid_t pid = fork();
  if (pid < 0)
    die("fork");
  if (pid == 0) {
    rw9_sigtrap(SIG_IGN);
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 13, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, action),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {sizeof f / sizeof f[0], f};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
      die("nnp");
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
      die("seccomp");
    SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
    say("rw9-filter-child action=%#x sigign=%d\n", action, rw9_sigign());
    _exit(0);
  }
  int status;
  if (waitpid(pid, &status, 0) != pid)
    die("wait");
  say("rw9-filter action=%#x exited=%d code=%d signaled=%d sig=%d\n", action,
      WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1,
      WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : -1);
}
static void mode_sigtrap_rw9_filter_kill(void) { rw9_filter_rt_sigaction(SECCOMP_RET_KILL_PROCESS); }
static void mode_sigtrap_rw9_filter_errno(void) { rw9_filter_rt_sigaction(SECCOMP_RET_ERRNO | EPERM); }
static void mode_sigtrap_rw9_filter_trap(void) { rw9_filter_rt_sigaction(SECCOMP_RET_TRAP); }

/* Codex's P2-1 at https://github.com/rrnewton/reverie/pull/1070 rev 9: the
 * test's caller installs a seccomp filter that acts on mseal (nr 462) in a
 * pre_exec callback, which runs before Reverie's own callback stops the root
 * and before Reverie's launch filter is loaded. Reverie must inject no mseal
 * into the root's pre-exec image or this one. The guest ignores SIGTRAP and
 * makes one private injection; natively it exits 0 with SIGTRAP ignored
 * (https://github.com/rrnewton/hermit/issues/4409). */
static void mode_sigtrap_caller_preexec_filter(void) {
  rw9_sigtrap(SIG_IGN);
  SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
  say("preexec-filter sigign=%d\n", rw9_sigign());
}

/* Witness T1 from the Claude reviewer's re-check of
 * https://github.com/rrnewton/reverie/pull/1070 at 9303e66b (rev 10): a
 * sibling installs, with SECCOMP_FILTER_FLAG_TSYNC, a filter that acts on
 * rt_sigaction (nr 13) while the other thread's private injections are being
 * repaired (SIGTRAP ignored). Neither thread calls rt_sigaction after the
 * install, so natively every child exits 0. Each child spreads the install
 * over a different delay, to land it inside a repair
 * (https://github.com/rrnewton/hermit/issues/4409). */
static atomic_int tsync_installed;
static unsigned int tsync_action;
static void* tsync_installer(void* arg) {
  unsigned int delay = (unsigned int)(unsigned long)arg;
  struct sock_filter f[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 13, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  f[5].k = tsync_action;
  struct sock_fprog prog = {sizeof f / sizeof f[0], f};
  for (volatile unsigned int spin = 0; spin < delay * 50u; spin++)
    ;
  long rc = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog);
  atomic_store(&tsync_installed, rc == 0 ? 1 : -1);
  return NULL;
}
static void sigtrap_tsync_filter(unsigned int action) {
  int children = 40, ok = 0, sigsys = 0, other = 0;
  for (int i = 0; i < children; i++) {
    pid_t pid = fork();
    if (pid < 0)
      die("fork");
    if (pid == 0) {
      /* A child killed by SIGSYS dumps no core (as in the int3 children). */
      struct rlimit core = {1, 1};
      if (setrlimit(RLIMIT_CORE, &core) != 0)
        die("RLIMIT_CORE");
      rw9_sigtrap(SIG_IGN);
      if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        die("nnp");
      tsync_action = action;
      pthread_t b;
      if (pthread_create(&b, NULL, tsync_installer, (void*)(unsigned long)((i * 397u) % 4000u)))
        die("tsync pthread_create");
      int after = 0;
      for (int k = 0; k < 20000 && after < 20; k++) {
        SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
        if (atomic_load(&tsync_installed))
          after++;
      }
      _exit(atomic_load(&tsync_installed) == 1 ? 0 : 7);
    }
    int status;
    if (waitpid(pid, &status, 0) != pid)
      die("wait");
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
      ok++;
    else if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS)
      sigsys++;
    else
      other++;
  }
  say("tsync-filter action=%#x children=%d ok=%d sigsys=%d other=%d\n", action, children, ok,
      sigsys, other);
}
static void mode_sigtrap_tsync_filter_kill(void) { sigtrap_tsync_filter(SECCOMP_RET_KILL_PROCESS); }
static void mode_sigtrap_tsync_filter_trap(void) { sigtrap_tsync_filter(SECCOMP_RET_TRAP); }
static void mode_sigtrap_tsync_filter_errno(void) { sigtrap_tsync_filter(SECCOMP_RET_ERRNO | EPERM); }

/* Reads /proc/self/maps into buf; returns its length. */
static size_t read_maps(char* buf, size_t size) {
  int fd = open("/proc/self/maps", O_RDONLY);
  if (fd < 0)
    die("open maps");
  size_t len = 0;
  ssize_t n;
  while (len + 1 < size && (n = read(fd, buf + len, size - 1 - len)) > 0)
    len += (size_t)n;
  close(fd);
  buf[len] = 0;
  return len;
}

/* Whether the mapping at addr is sealed (VmFlags "sl" in smaps). */
static int sealed_at(unsigned long addr) {
  FILE* f = fopen("/proc/self/smaps", "r");
  if (!f)
    die("open smaps");
  char line[512];
  int in = 0, sealed = 0;
  while (fgets(line, sizeof line, f)) {
    unsigned long lo, hi;
    if (sscanf(line, "%lx-%lx ", &lo, &hi) == 2)
      in = lo <= addr && addr < hi;
    else if (in && !strncmp(line, "VmFlags:", 8))
      sealed = strstr(line, " sl") != NULL;
  }
  fclose(f);
  return sealed;
}

/* Reverie's SIGTRAP repair page is the page after the trampoline
 * (0x71001000), mapped read-write and sealed at exec: the guest cannot map
 * over it (MAP_FIXED_NOREPLACE: EEXIST; MAP_FIXED, munmap, mprotect: EPERM),
 * which is a pinned difference from native, as for the trampoline page; a
 * repair leaves the guest's mappings as they were; and a forked child's copy
 * keeps the seal, and its repairs too. */
static void say_attempts(const char* who) {
  void* want = (void*)0x71001000;
  void* p = mmap(want, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  int noreplace = p == MAP_FAILED ? errno : 0;
  p = mmap(want, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  int fixed = p == MAP_FAILED ? errno : 0;
  int unmapped = munmap(want, 4096) ? errno : 0;
  int reprotected = mprotect(want, 4096, PROT_READ) ? errno : 0;
  say("overlay %s noreplace=%s fixed=%s munmap=%s mprotect=%s sealed=%d\n", who,
      noreplace == EEXIST ? "eexist" : noreplace ? "other" : "ok",
      fixed == EPERM ? "eperm" : fixed ? "other" : "ok",
      unmapped == EPERM ? "eperm" : unmapped ? "other" : "ok",
      reprotected == EPERM ? "eperm" : reprotected ? "other" : "ok",
      sealed_at(0x71001000));
}

static void mode_sigtrap_scratch_overlay(void) {
  static char before[65536], after[65536];
  read_maps(before, sizeof before);
  for (char* line = strtok(before, "\n"); line; line = strtok(NULL, "\n")) {
    if (!strncmp(line, "71", 2)) {
      char range[64], perms[8];
      if (sscanf(line, "%63s %7s", range, perms) == 2)
        say("overlay maps %s %s\n", range, perms);
    }
  }
  say_attempts("parent");
  sigtrap_set(SIG_IGN, 0);
  read_maps(before, sizeof before);
  SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
  read_maps(after, sizeof after);
  char tag[96];
  snprintf(tag, sizeof tag, "overlay repaired maps-same=%d", !strcmp(before, after));
  sigtrap_full_state(tag);
  pid_t pid = fork();
  if (pid < 0)
    die("fork");
  if (pid == 0) {
    say_attempts("child");
    SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
    sigtrap_full_state("overlay child-repaired");
    _exit(0);
  }
  int status;
  if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
    die("overlay child");
}

static volatile int callback_hits;
static volatile int callback_code;
static volatile long callback_value;

static void callback_handler(int sig, siginfo_t* info, void* context) {
  (void)sig;
  (void)context;
  callback_code = info->si_code;
  callback_value = (long)info->si_value.sival_ptr;
  callback_hits++;
}

/* One POSIX-timer signal (value 1234) per SIGTRAP state, which the Tool's
 * callback answers with injections before resuming it
 * (handle_signal_event): SIGPROF with getpid, SIGXCPU with getpid between
 * block-all rt_sigprocmask injections. The handler must run once, with the
 * timer's siginfo, and SIGTRAP's action must be the guest's afterwards. */
static void mode_sigtrap_signal_callback(void) {
  warm();
  static const struct {
    const char* name;
    int signo;
  } signals[] = {{"prof", SIGPROF}, {"xcpu", SIGXCPU}};
  static const struct {
    const char* name;
    void (*action)(int);
  } states[] = {{"dfl", SIG_DFL}, {"ign", SIG_IGN}, {"handler", trap_handler}};
  for (unsigned s = 0; s < sizeof signals / sizeof signals[0]; s++) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = callback_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(signals[s].signo, &sa, NULL) != 0)
      die("install callback handler");
    for (unsigned i = 0; i < sizeof states / sizeof states[0]; i++) {
      sigtrap_set(states[i].action, 0);
      callback_hits = 0;
      callback_code = 0;
      callback_value = 0;
      struct sigevent sev;
      memset(&sev, 0, sizeof sev);
      sev.sigev_notify = SIGEV_SIGNAL;
      sev.sigev_signo = signals[s].signo;
      sev.sigev_value.sival_ptr = (void*)1234;
      timer_t timer;
      if (timer_create(CLOCK_MONOTONIC, &sev, &timer) != 0)
        die("timer_create");
      struct itimerspec spec = {{0, 0}, {0, 2000000}};
      if (timer_settime(timer, 0, &spec, NULL) != 0)
        die("timer_settime");
      while (callback_hits == 0)
        ;
      /* Long enough for a second delivery, had there been one. */
      usleep(20000);
      timer_delete(timer);
      struct sigaction now;
      if (sigaction(SIGTRAP, NULL, &now) != 0)
        die("read SIGTRAP");
      say("callback %s %s hits=%d code=%d value=%ld sigtrap=%s\n",
          signals[s].name,
          states[i].name,
          callback_hits,
          callback_code,
          callback_value,
          now.sa_handler == SIG_IGN          ? "ign"
              : now.sa_handler == SIG_DFL    ? "dfl"
              : now.sa_handler == trap_handler ? "trap_handler"
                                               : "other");
    }
  }
}

/* A caught SIGTRAP that the guest blocks, through 200 private injections,
 * as Detcore's polling loops run them under a mask that blocks every
 * signal: the handler and the mask bit are the guest's afterwards. */
static void mode_sigtrap_caught_blocked_injections(void) {
  for (int i = 0; i < 3; i++)
    SITE(SYS_getppid, 0, 0, 0, 0, 0);
  sigtrap_set(trap_handler, 1);
  for (int i = 0; i < 200; i++)
    SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
  sigtrap_full_state("caught-blocked after 200");
}

/* A caught SIGTRAP that the guest blocks, after the guest installs a
 * seccomp filter that refuses rt_sigaction with Reverie's repair page
 * (0x71001000) as oldact, so that Reverie cannot read the handler a step's
 * trap would reset, and gives up the page. The guest's own sigaction calls
 * pass a stack address and are allowed. Through 20 private injections the
 * handler and the mask bit must stay the guest's. */
static void mode_sigtrap_caught_blocked_no_repair(void) {
  for (int i = 0; i < 3; i++)
    SITE(SYS_getppid, 0, 0, 0, 0, 0);
  struct sock_filter f[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigaction, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x71001000, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2]) + 4),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
  };
  struct sock_fprog prog = {sizeof f / sizeof f[0], f};
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    die("no_new_privs");
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
    die("seccomp");
  sigtrap_set(trap_handler, 1);
  for (int i = 0; i < 20; i++)
    SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
  sigtrap_full_state("no-repair after 20");
}

/* A caught SIGTRAP that the guest blocks, then a seccomp filter (allowing
 * everything) installed by a call the Tool injects on the private page, then
 * more private injections: Reverie gives up its repair page once the guest
 * has a filter, so the filter-installing step and every later one must leave
 * the handler as the guest set it. */
static void mode_sigtrap_caught_blocked_filter_install(void) {
  for (int i = 0; i < 3; i++)
    SITE(SYS_getppid, 0, 0, 0, 0, 0);
  struct sock_filter f[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
  struct sock_fprog prog = {sizeof f / sizeof f[0], f};
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    die("no_new_privs");
  sigtrap_set(trap_handler, 1);
  /* Earlier private steps, before the filter. */
  for (int i = 0; i < 3; i++)
    SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
  long r = SITEM(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, (long)&prog, 0, 0, SHAPE_PRIVATE_CALL);
  if (r != 0)
    die("seccomp");
  for (int i = 0; i < 5; i++)
    SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
  sigtrap_full_state("filter-install after");
}

static void trap_handler2(int sig) {
  (void)sig;
}

static int sibling_pipe[2];
static pid_t sibling_target_tid;

/* Whether thread `tid` is inside read(`fd`, ...): its procfs `syscall` shows
 * the syscall number (0 on x86-64) and first argument of the call it is
 * blocked in, or "running" while it runs in user space. */
static int thread_in_read_of(pid_t tid, int fd) {
  char path[64], buf[256];
  snprintf(path, sizeof path, "/proc/self/task/%d/syscall", (int)tid);
  int pfd = open(path, O_RDONLY);
  if (pfd < 0)
    return 0;
  ssize_t n = read(pfd, buf, sizeof buf - 1);
  close(pfd);
  if (n <= 0)
    return 0;
  buf[n] = 0;
  long nr = -1;
  unsigned long arg0 = 0;
  if (sscanf(buf, "%ld %lx", &nr, &arg0) != 2)
    return 0;
  return nr == SYS_read && arg0 == (unsigned long)fd;
}

static void* sibling_changes_sigtrap(void* arg) {
  (void)arg;
  /* Not before the main thread is blocked in its private-page read, so that
   * the change below happens while that injected call runs. */
  for (int i = 0; !thread_in_read_of(sibling_target_tid, sibling_pipe[0]); i++) {
    if (i == 100000)
      die("main thread never blocked in its read");
    usleep(1000);
  }
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = trap_handler2;
  sa.sa_flags = SA_RESTART | SA_NODEFER;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGUSR2);
  if (sigaction(SIGTRAP, &sa, NULL) != 0)
    die("sibling sigaction");
  if (write(sibling_pipe[1], "x", 1) != 1)
    die("sibling write");
  return NULL;
}

/* A caught SIGTRAP that this thread blocks, while a private-page read blocks
 * on a pipe; meanwhile a sibling, once procfs shows this thread blocked in
 * that read, installs another handler (same flags and mask) and then writes
 * the pipe. The read's step trap resets whatever
 * action is in force when it returns. Reverie must never write back the
 * handler it knew before the read: that would replace the sibling's. */
static void sibling_change_from(void (*start)(int)) {
  for (int i = 0; i < 3; i++)
    SITE(SYS_getppid, 0, 0, 0, 0, 0);
  if (pipe(sibling_pipe) != 0)
    die("pipe");
  sigtrap_set(start, 1);
  SITEM(SYS_getppid, 0, 0, 0, 0, 0, SHAPE_PRIVATE);
  sibling_target_tid = (pid_t)syscall(SYS_gettid);
  pthread_t thread;
  if (pthread_create(&thread, NULL, sibling_changes_sigtrap, NULL) != 0)
    die("pthread_create");
  char c;
  long r = SITEM(SYS_read, sibling_pipe[0], (long)&c, 1, 0, 0, SHAPE_PRIVATE_CALL);
  if (r != 1)
    die("read");
  if (pthread_join(thread, NULL) != 0)
    die("pthread_join");
  struct sigaction now;
  if (sigaction(SIGTRAP, NULL, &now) != 0)
    die("read sigtrap");
  say("sibling-change sigtrap=%s\n",
      now.sa_handler == trap_handler ? "stale"
      : now.sa_handler == trap_handler2 ? "sibling"
      : now.sa_handler == SIG_DFL ? "dfl"
      : now.sa_handler == SIG_IGN ? "ign"
                                  : "other");
}

static void mode_sigtrap_sibling_change_during_call(void) {
  sibling_change_from(trap_handler);
}

/* The same, starting from a default or an ignored SIGTRAP that this thread
 * blocks: a pinned limit, since the read's step is then not shielded. */
static void mode_sigtrap_sibling_change_from_dfl(void) {
  sibling_change_from(SIG_DFL);
}

static void mode_sigtrap_sibling_change_from_ign(void) {
  sibling_change_from(SIG_IGN);
}

/* A default SIGTRAP that the guest blocks, then a handler installed by an
 * rt_sigaction the Tool injects on the private page: natively the call
 * installs it and nothing resets it. */
static void mode_sigtrap_blocked_installs_handler(void) {
  for (int i = 0; i < 3; i++)
    SITE(SYS_getppid, 0, 0, 0, 0, 0);
  sigtrap_set(SIG_DFL, 1);
  struct ksigaction k = {
      .handler = trap_handler,
      .flags = SA_RESTART | SA_NODEFER | 0x04000000 /* SA_RESTORER */,
      .restorer = (void (*)(void))trap_handler,
      .mask = 1UL << (SIGUSR2 - 1),
  };
  long r = SITEM(SYS_rt_sigaction, SIGTRAP, (long)&k, 0, 8, 0, SHAPE_PRIVATE_CALL);
  if (r != 0)
    die("private rt_sigaction");
  sigtrap_full_state("installs-handler");
}

/* A Tool's injection at a signal stop while a temporary mask's restore is
 * pending: SIGPROF is blocked and pending, and a private-page ppoll whose
 * temporary mask admits it returns -EINTR with the restore pending. At the
 * SIGPROF stop the Tool's callback injects getpid (handle_signal_event);
 * resuming the thread for it restores the saved mask first, so the getpid's
 * trap sees SIGTRAP as the saved mask has it, not as the temporary mask did.
 * In -topen states the saved mask blocks SIGTRAP and the temporary mask
 * admits it; in -tshut states the reverse. Natively SIGTRAP's action and
 * mask bit are the guest's afterwards. */
static void mode_sigtrap_callback_restore(void) {
  warm();
  struct sigaction prof;
  memset(&prof, 0, sizeof prof);
  prof.sa_sigaction = callback_handler;
  prof.sa_flags = SA_SIGINFO;
  sigemptyset(&prof.sa_mask);
  if (sigaction(SIGPROF, &prof, NULL) != 0)
    die("install SIGPROF");
  static const struct {
    const char* name;
    void (*action)(int);
    int block;
    int tmask;
  } states[] = {
      {"handler-blocked-topen", trap_handler, 1, 0},
      {"ign-blocked-topen", SIG_IGN, 1, 0},
      {"dfl-blocked-topen", SIG_DFL, 1, 0},
      {"handler-tshut", trap_handler, 0, 1},
  };
  sigset_t prof_set;
  sigemptyset(&prof_set);
  sigaddset(&prof_set, SIGPROF);
  for (unsigned i = 0; i < sizeof states / sizeof states[0]; i++) {
    sigtrap_set(states[i].action, states[i].block);
    if (sigprocmask(SIG_BLOCK, &prof_set, NULL) != 0)
      die("block SIGPROF");
    callback_hits = 0;
    raise(SIGPROF);
    unsigned long temporary = states[i].tmask ? 1UL << (SIGTRAP - 1) : 0;
    struct timespec ts = {5, 0};
    /* The call's result is not compared: the Tool's injection at the
     * SIGPROF stop replaces it in the guest's return register, natively
     * -EINTR, with getpid's (a separate defect). */
    SITEM(SYS_ppoll, 0, 0, (long)&ts, (long)&temporary, 8, SHAPE_PRIVATE_CALL);
    if (sigprocmask(SIG_UNBLOCK, &prof_set, NULL) != 0)
      die("unblock SIGPROF");
    char tag[64];
    snprintf(tag, sizeof tag, "restore %s hits=%d", states[i].name, callback_hits);
    sigtrap_full_state(tag);
  }
}

/* A timer single-step that reaches the site carrying an untraced number
 * (500, which no syscall table knows). */
static void mode_timer_allow(void) {
  warm();
  SITEM(SYS_getppid, 0, 0, 0, 0, 2, ARM_TIMER);
  long r = SITE(500, 0, 0, 0, 0, 0);
  if (tl_b)
    tl_sum++;
  if (tl_c)
    tl_sum++;
  report_result("timer allow", r);
}

/* A counting-phase precise timer armed at the site's getppid, PM_BRANCHES +
 * 1 branches out, with an untraced number (500) run through a warmed
 * generic site before the branch loop in which the timer fires.
 *
 * The loop is three times the armed distance, as in mode_timer_cancel, so
 * that the timer fires in the middle of it. With a loop of exactly the armed
 * distance the target was the loop's last iteration: a perf overflow signal
 * delayed past the skid margin then arrived after the following getpid's
 * syscall stop, which cancels the timer, and the timer vanished from
 * whichever run was delayed (seen once in a loaded 8-thread run, with no
 * HERMIT_SKID_OVERSHOOT line because the timer never fired). */
static void mode_timer_hop_unknown(void) {
  warm();
  long pid = getpid();
  for (int j = 0; j < 3; j++)
    if (tp_gen0_fn(SYS_getpid) != pid)
      die("warm generic site");
  SITEM(SYS_getppid, 0, 0, 0, 0, PM_BRANCHES + 1, ARM_TIMER);
  long r = tp_gen0_fn(500);
  for (volatile int j = 0; j < 3 * PM_BRANCHES; j++)
    ;
  long g = SITE(SYS_getpid, 0, 0, 0, 0, 0);
  unsigned char* p = (unsigned char*)tp_gen0;
  say("timer hop unknown ret=%ld getpid=%d bytes after %02x %02x\n",
      r,
      g == pid,
      p[0],
      p[1]);
}

/* A syscall site of its own, executed exactly once. */
static long __attribute__((noinline)) getpid_once(void) {
  long r;
  __asm__ volatile("syscall"
                   : "=a"(r)
                   : "a"((long)SYS_getpid)
                   : "rcx", "r11", "memory");
  return r;
}

/* A precise timer armed in a forked child at the site's getppid, far beyond
 * any skid margin, whose signal the child blocks: no notification is ever
 * handled, the limiting case of a late interrupt, as in
 * reverie-ptrace/tests/precise_timer_overtaken.rs. The child then runs well
 * past the target and ends with a foreign int 0x80 (`foreign`), which plain
 * ptrace's filter kills with no stop, or with an ordinary x86_64 getpid,
 * whose stop the tracer reports. */
#define LATE_TIMER_RCBS 100000
static void mode_late_timer(int foreign) {
  warm();
  sigset_t chld;
  sigemptyset(&chld);
  sigaddset(&chld, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &chld, NULL) != 0)
    die("block SIGCHLD");
  pid_t child = fork();
  if (child < 0)
    die("fork");
  if (child == 0) {
    /* A limit of 1, as above. */
    struct rlimit none = {1, 1};
    setrlimit(RLIMIT_CORE, &none);
    install(SIGSYS, 0, handler);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGSYS);
    /* reverie-ptrace's timer signal (PERF_EVENT_SIGNAL). */
    sigaddset(&set, SIGSTKFLT);
    if (sigprocmask(SIG_BLOCK, &set, NULL) != 0)
      die("block SIGSYS and SIGSTKFLT");
    SITEM(SYS_getppid, 0, 0, 0, 0, LATE_TIMER_RCBS, ARM_TIMER);
    for (volatile int j = 0; j < 2 * LATE_TIMER_RCBS; j++)
      ;
    if (foreign) {
      long ret;
      __asm__ volatile("int $0x80" : "=a"(ret) : "a"(20L) : "memory");
      /* Reached only if the IA-32 syscall was serviced. */
      say("int80 returned handler_ran=%d\n", nrec);
      _exit(0);
    }
    long r = getpid_once();
    say("late timer getpid=%d\n", r > 0);
    _exit(0);
  }
  int status;
  if (waitpid(child, &status, 0) != child)
    die("waitpid");
  say("child signaled=%d termsig=%d exited=%d status=%d\n",
      WIFSIGNALED(status),
      WIFSIGNALED(status) ? WTERMSIG(status) : 0,
      WIFEXITED(status),
      WIFEXITED(status) ? WEXITSTATUS(status) : 0);
  if (sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0)
    die("unblock SIGCHLD");
}

/* The same counting-phase timer, cancelled by a Tool-visible stop before
 * the branch loop: first a getpid at the site, then one at a site of its
 * own. A last timer with no stop before its loop fires, so the run's one
 * timer event is that one. */
static void mode_timer_cancel(void) {
  warm();
  long pid = getpid();
  /* A cancelled timer's counter still overflows, as an internal signal
   * stop. The loops after each cancelling call are three times the armed
   * distance, so that overflow lands inside the loop rather than next to
   * the following syscall, where skid alone would order the two stops. The
   * live timer likewise fires in the middle of the last loop. */
  SITEM(SYS_getppid, 0, 0, 0, 0, PM_BRANCHES + 1, ARM_TIMER);
  long site = SITE(SYS_getpid, 0, 0, 0, 0, 0);
  for (volatile int j = 0; j < 3 * PM_BRANCHES; j++)
    ;
  SITEM(SYS_getppid, 0, 0, 0, 0, PM_BRANCHES + 1, ARM_TIMER);
  long ordinary = getpid_once();
  for (volatile int j = 0; j < 3 * PM_BRANCHES; j++)
    ;
  SITEM(SYS_getppid, 0, 0, 0, 0, PM_BRANCHES + 1, ARM_TIMER);
  for (volatile int j = 0; j < 3 * PM_BRANCHES; j++)
    ;
  say("timer cancel site=%d ordinary=%d\n", site == pid, ordinary == pid);
}

/* The distance, in branches, at which timer_hop_handler arms its timer. */
static volatile long timer_hop_distance = PM_BRANCHES + 1;

static void timer_hop_handler(int sig, siginfo_t* si, void* uc_) {
  (void)sig;
  (void)si;
  (void)uc_;
  SITEM(SYS_getppid, 0, 0, 0, 0, timer_hop_distance, ARM_TIMER);
}

/* The same timer, armed at the site's getppid inside a signal handler
 * whose restorer runs rt_sigreturn through that same warmed site, before
 * the branch loop in which the timer fires (three
 * times the armed distance, for the reason given at mode_timer_hop_unknown). */
static void timer_hop_sigreturn(const char* label) {
  warm();
  struct {
    void* handler;
    unsigned long flags;
    void* restorer;
    unsigned long mask;
  } ksa = {
      (void*)timer_hop_handler,
      SA_SIGINFO | 0x04000000 /* SA_RESTORER */,
      (void*)tp_restorer,
      0};
  if (syscall(SYS_rt_sigaction, SIGUSR1, &ksa, NULL, 8) != 0)
    die("rt_sigaction");
  long pid = getpid();
  long tid = syscall(SYS_gettid);
  if (syscall(SYS_tgkill, pid, tid, SIGUSR1) != 0)
    die("tgkill");
  for (volatile long j = 0; j < 3 * timer_hop_distance; j++)
    ;
  long g = SITE(SYS_getpid, 0, 0, 0, 0, 0);
  unsigned char* p = (unsigned char*)tp_site;
  say("%s getpid=%d bytes after %02x %02x\n", label, g == pid, p[0], p[1]);
}

static void mode_timer_hop_sigreturn(void) {
  timer_hop_sigreturn("timer hop sigreturn");
}

/* Blocks reverie-ptrace's timer signal (PERF_EVENT_SIGNAL, SIGSTKFLT) for
 * the rest of the handler, arms the timer PM_BRANCHES + 1 branches out, and
 * runs twice that far before returning, so that the timer's notification is
 * held back past its target until the rt_sigreturn restores the frame's mask,
 * which leaves the signal unblocked. */
static void timer_late_handler(int sig, siginfo_t* si, void* uc_) {
  (void)sig;
  (void)si;
  (void)uc_;
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGSTKFLT);
  if (sigprocmask(SIG_BLOCK, &set, NULL) != 0)
    die("block SIGSTKFLT");
  SITEM(SYS_getppid, 0, 0, 0, 0, PM_BRANCHES + 1, ARM_TIMER);
  for (volatile long j = 0; j < 2 * PM_BRANCHES; j++)
    ;
}

/* A handler that runs past its timer's target with the notification held
 * back (timer_late_handler), returning through the warmed site as in
 * timer_hop_sigreturn, then the same branch loop and getpid. */
static void mode_timer_late_sigreturn(void) {
  warm();
  struct {
    void* handler;
    unsigned long flags;
    void* restorer;
    unsigned long mask;
  } ksa = {
      (void*)timer_late_handler,
      SA_SIGINFO | 0x04000000 /* SA_RESTORER */,
      (void*)tp_restorer,
      0};
  if (syscall(SYS_rt_sigaction, SIGUSR1, &ksa, NULL, 8) != 0)
    die("rt_sigaction");
  long pid = getpid();
  long tid = syscall(SYS_gettid);
  if (syscall(SYS_tgkill, pid, tid, SIGUSR1) != 0)
    die("tgkill");
  for (volatile long j = 0; j < 3 * PM_BRANCHES; j++)
    ;
  long g = SITE(SYS_getpid, 0, 0, 0, 0, 0);
  unsigned char* p = (unsigned char*)tp_site;
  say("timer late sigreturn getpid=%d bytes after %02x %02x\n",
      g == pid,
      p[0],
      p[1]);
}

/* As mode_timer_hop_sigreturn, with reverie-ptrace's timer signal
 * (PERF_EVENT_SIGNAL, SIGSTKFLT) blocked from before the signal until after
 * the branch loop, so that the mask the handler's frame installs blocks it.
 * A notification requested at the handler's return could not arrive before
 * the loop ends. */
static void mode_timer_hop_sigreturn_blocked(void) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGSTKFLT);
  if (sigprocmask(SIG_BLOCK, &set, NULL) != 0)
    die("block SIGSTKFLT");
  timer_hop_sigreturn("timer hop sigreturn blocked");
  if (sigprocmask(SIG_UNBLOCK, &set, NULL) != 0)
    die("unblock SIGSTKFLT");
}

/* As mode_timer_hop_sigreturn, with the timer armed 30001 branches out:
 * more than three times reverie-ptrace's keep margin (10005), so a stop at
 * the handler's rt_sigreturn finds the guest far from the timer's target. */
static void mode_timer_far_sigreturn(void) {
  timer_hop_distance = 10 * PM_BRANCHES + 1;
  timer_hop_sigreturn("timer far sigreturn");
}

/* Under a partial subscription (the Tool does not subscribe to getuid). */
static void mode_partial(void) {
  warm();
  long r = SITE(SYS_getuid, 0, 0, 0, 0, 0);
  say("getuid ok=%d\n", r == (long)getuid());
  r = SITE(SYS_getpid, 0, 0, 0, 0, 0);
  say("getpid after pid=%d\n", r == getpid());
  site_bytes("partial");
}

static void sigreturn_handler(int sig, siginfo_t* si, void* uc_) {
  handler(sig, si, uc_);
  /* The frame's mask must win over the mask saved at delivery. */
  sigaddset(&((ucontext_t*)uc_)->uc_sigmask, SIGUSR2);
}

/* rt_sigreturn through the warmed shared site, from a restorer the
 * guest installed with the raw rt_sigaction. */
static void mode_sigreturn(void) {
  warm();
  struct {
    void* handler;
    unsigned long flags;
    void* restorer;
    unsigned long mask;
  } ksa = {
      (void*)sigreturn_handler,
      SA_SIGINFO | 0x04000000 /* SA_RESTORER */,
      (void*)tp_restorer,
      0};
  if (syscall(SYS_rt_sigaction, SIGUSR1, &ksa, NULL, 8) != 0)
    die("rt_sigaction");
  raise(SIGUSR1);
  dump("sigreturn");
  sigset_t set;
  if (sigprocmask(SIG_SETMASK, NULL, &set) != 0)
    die("sigprocmask");
  say("after sigreturn usr1-blocked=%d usr2-blocked=%d\n",
      sigismember(&set, SIGUSR1),
      sigismember(&set, SIGUSR2));
  long r = SITE(SYS_getpid, 0, 0, 0, 0, 0);
  say("getpid after sigreturn pid=%d rcx=%s r11=%#lx\n",
      r == getpid(),
      where(tp_nz_rcx),
      tp_nz_r11);
  site_bytes("after sigreturn");
  raise(SIGUSR1);
  dump("sigreturn again");
}

/* The private page's `syscall; ud2` return address (reverie's traced stub,
 * mapped under plain ptrace too). */
#define SLOT_RET_ADDR 0x71000006UL
static sigjmp_buf slot_ret_env;
static volatile unsigned long slot_ret_addr, slot_ret_rip;

static void slot_ret_usr1(int sig, siginfo_t* si, void* uc_) {
  (void)sig;
  (void)si;
  ((ucontext_t*)uc_)->uc_mcontext.gregs[REG_RIP] = (greg_t)SLOT_RET_ADDR;
}

static void slot_ret_ill(int sig, siginfo_t* si, void* uc_) {
  (void)sig;
  slot_ret_addr = (unsigned long)si->si_addr;
  slot_ret_rip = ((ucontext_t*)uc_)->uc_mcontext.gregs[REG_RIP];
  siglongjmp(slot_ret_env, 1);
}

/* rt_sigreturn through the warmed shared site to a frame whose saved rip is
 * the private page's `syscall; ud2` return address: the frame's registers
 * win, so the guest executes the ud2 there. */
static void mode_sigreturn_slot_ret(void) {
  warm();
  install(SIGILL, 0, slot_ret_ill);
  struct {
    void* handler;
    unsigned long flags;
    void* restorer;
    unsigned long mask;
  } ksa = {
      (void*)slot_ret_usr1,
      SA_SIGINFO | 0x04000000 /* SA_RESTORER */,
      (void*)tp_restorer,
      0};
  if (syscall(SYS_rt_sigaction, SIGUSR1, &ksa, NULL, 8) != 0)
    die("rt_sigaction");
  if (!sigsetjmp(slot_ret_env, 1)) {
    syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1);
    say("slot-ret no SIGILL\n");
  } else {
    say("slot-ret SIGILL addr-is-slot-ret=%d rip-is-slot-ret=%d\n",
        slot_ret_addr == SLOT_RET_ADDR,
        slot_ret_rip == SLOT_RET_ADDR);
  }
  long r = SITE(SYS_getpid, 0, 0, 0, 0, 0);
  say("slot-ret getpid after pid=%d\n", r == getpid());
  site_bytes("slot-ret after");
}

static sigjmp_buf bad_frame_env;
static volatile long bad_frame_code, bad_frame_rip, bad_frame_rax;

static void bad_frame_segv(int sig, siginfo_t* si, void* uc_) {
  (void)sig;
  ucontext_t* uc = uc_;
  bad_frame_code = si->si_code;
  bad_frame_rip = uc->uc_mcontext.gregs[REG_RIP];
  bad_frame_rax = uc->uc_mcontext.gregs[REG_RAX];
  siglongjmp(bad_frame_env, 1);
}

/* rt_sigreturn through a warmed generic site with rsp at an unmapped page,
 * so the kernel cannot read the frame (and neither can the tracer): the
 * kernel returns 0 at S+2 and forces SIGSEGV, delivered on an alternate
 * stack. */
static void mode_sigreturn_bad_frame(void) {
  long pid = getpid();
  for (int j = 0; j < 3; j++)
    if (tp_gen1_fn(SYS_getpid) != pid)
      die("warm generic site");
  static char altstack[65536];
  stack_t ss = {.ss_sp = altstack, .ss_size = sizeof altstack, .ss_flags = 0};
  if (sigaltstack(&ss, NULL) != 0)
    die("sigaltstack");
  install(SIGSEGV, SA_ONSTACK, bad_frame_segv);
  if (!sigsetjmp(bad_frame_env, 1)) {
    __asm__ volatile(
        "mov $0x10, %%rsp\n"
        "mov $15, %%eax\n"
        "jmp tp_gen1\n" ::
            : "memory");
    __builtin_unreachable();
  }
  unsigned char* p = (unsigned char*)tp_gen1;
  say("bad-frame SIGSEGV code=%ld rip-next=%d rax=%ld bytes after %02x %02x\n",
      bad_frame_code,
      bad_frame_rip == (long)tp_gen1 + 2,
      bad_frame_rax,
      p[0],
      p[1]);
  say("bad-frame getpid after=%d\n", tp_gen1_fn(SYS_getpid) == pid);
}

/* rt_sigreturn through a warmed generic site at a frame on a PROT_NONE page
 * whose saved rip is the private page's return address and whose saved rsp
 * is the frame's own rsp. The kernel's user copies fail on the page, so it
 * returns 0 at S+2 without loading a register and forces SIGSEGV there. */
static void mode_sigreturn_prot_none_frame(void) {
  long pid = getpid();
  for (int j = 0; j < 3; j++)
    if (tp_gen1_fn(SYS_getpid) != pid)
      die("warm generic site");
  static char altstack[65536];
  stack_t ss = {.ss_sp = altstack, .ss_size = sizeof altstack, .ss_flags = 0};
  if (sigaltstack(&ss, NULL) != 0)
    die("sigaltstack");
  install(SIGSEGV, SA_ONSTACK, bad_frame_segv);
  unsigned char* page = mmap(
      NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED)
    die("mmap frame page");
  unsigned long frame_rsp = (unsigned long)page + 64;
  /* ucontext at rsp: uc_mcontext at +40; gregs rsp is index 15, rip 16. */
  unsigned long* gregs = (unsigned long*)(frame_rsp + 40);
  gregs[15] = frame_rsp;
  gregs[16] = SLOT_RET_ADDR;
  if (mprotect(page, 4096, PROT_NONE) != 0)
    die("mprotect frame page");
  if (!sigsetjmp(bad_frame_env, 1)) {
    __asm__ volatile(
        "mov %0, %%rsp\n"
        "mov $15, %%eax\n"
        "jmp tp_gen1\n" ::"r"(frame_rsp)
        : "memory");
    __builtin_unreachable();
  }
  unsigned char* p = (unsigned char*)tp_gen1;
  say("prot-none-frame SIGSEGV code=%ld rip-next=%d rip-is-slot-ret=%d rax=%ld bytes after %02x "
      "%02x\n",
      bad_frame_code,
      bad_frame_rip == (long)tp_gen1 + 2,
      bad_frame_rip == (long)SLOT_RET_ADDR,
      bad_frame_rax,
      p[0],
      p[1]);
  say("prot-none-frame getpid after=%d\n", tp_gen1_fn(SYS_getpid) == pid);
}

static sigjmp_buf probe_env;
static volatile long probe_sig_code;

static void probe_ill(int sig, siginfo_t* si, void* uc_) {
  (void)sig;
  (void)uc_;
  probe_sig_code = si->si_code;
  siglongjmp(probe_env, 1);
}

/* x86_64 335 (uretprobe) and 336 (uprobe), which seccomp passes through
 * without running the filter, through a warmed generic site. Outside a
 * uprobe trampoline 335 raises SIGILL and 336 returns -ENXIO; a kernel
 * without them returns -ENOSYS. */
static void probe_nr(long nr) {
  long pid = getpid();
  for (int j = 0; j < 3; j++)
    if (tp_gen2_fn(SYS_getpid) != pid)
      die("warm generic site");
  install(SIGILL, 0, probe_ill);
  if (!sigsetjmp(probe_env, 1)) {
    long r = tp_gen2_fn(nr);
    say("probe nr=%ld ret=%ld\n", nr, r);
  } else {
    say("probe nr=%ld SIGILL code=%ld\n", nr, probe_sig_code);
  }
}

/* A SIGSTOP the tracer sends (SI_TKILL) while a call at the site is parked.
 * Plain ptrace suppresses every SIGSTOP at its delivery stop
 * (handle_sigstop), after the call completed. */
static void mode_sigstop_hop(void) {
  warm();
  long r = SITEM(SYS_getpid, 0, 0, 0, 0, 0, SHAPE_TAIL | SEND_SIGSTOP);
  say("sigstop tail getpid returned pid=%d\n", r == getpid());
  r = SITEM(SYS_getpid, 0, 0, 0, 0, 0, SHAPE_INJECT | SEND_SIGSTOP);
  say("sigstop inject getpid returned pid=%d\n", r == getpid());
}

/* A traced parent signals its child while the child's call at the shared
 * site is parked. The Tool (at the site's seccomp stop) and the tracer's
 * pre-syscall hook (immediately before the call runs: the final resume of
 * the stop, or the exact inject's resume) each notify the parent with
 * SIGUSR2 and wait until the signal the call's tag names has arrived, so the
 * signal lands at a fixed logical point. */
#define TOOL_PARK(sig) ((long)(sig) << 32)
#define HOOK_PARK(sig) ((long)(sig) << 40)
/* After the call's inject returned, the Tool notifies the parent, waits for
 * its SIGCONT, then sends SIGSTOP to the thread. */
#define TOOL_AFTER_CONT (0x40L << 32)
/* The hook parks at its late point, the second of its two consecutive
 * calls. */
#define HOOK_LATE (0x20L << 40)
/* The hook (tracer) sends SIGSTOP to the process and to the thread. */
#define HOOK_SEND_STOPS (0x40L << 40)
/* The hook (tracer) sends SIGKILL to the process, then stays parked. */
#define HOOK_KILL (0x80L << 40)
/* The Tool also notifies the parent when the kernel restarts the call. */
#define NOTIFY_AGAIN 0x4000
/* park_run: the site call is a blocking read (else a write). */
#define PARK_READ 1
/* park_run: the child blocks SIGCONT until the parent's token arrives, and
 * the parent sends SIGCONT after reading the child's post-call output. */
#define PARK_LATE_CONT 2
/* park_run: the child handles SIGTSTP, SIGTTIN and SIGTTOU (else SIG_DFL). */
#define PARK_TSTP_HANDLER 4
/* park_run: the child has a second thread, which blocks every signal, while
 * it makes the call. */
#define PARK_SIBLING 8
/* A park_run `kills` entry: the parent sends SIGCONT to the process, then
 * `sig` (a positive, process-directed entry). */
#define CONT_THEN(sig) (0x100 | (sig))

struct park_rec {
  int sig, code, from_parent;
  long rip, rax;
};
static struct park_rec park_recs[8];
static volatile int npark;

static void park_handler(int sig, siginfo_t* si, void* uc_) {
  ucontext_t* uc = uc_;
  if (npark >= 8)
    return;
  struct park_rec* r = &park_recs[npark++];
  r->sig = sig;
  r->code = si->si_code;
  r->from_parent = si->si_code <= 0 && si->si_pid == getppid();
  r->rip = uc->uc_mcontext.gregs[REG_RIP];
  r->rax = uc->uc_mcontext.gregs[REG_RAX];
}

/* fds: the read end of the pipe that releases the sibling, then the write
 * end of the pipe that reports its TID. */
static void* park_sibling(void* fds) {
  int* fd = fds;
  pid_t tid = syscall(SYS_gettid);
  char byte;
  if (write(fd[1], &tid, sizeof tid) != sizeof tid ||
      read(fd[0], &byte, 1) != 1)
    die("sibling");
  return NULL;
}

/* Releases the sibling (thread `tid`, blocked reading `release`), waits
 * for it to exit, and joins it. The wait is a poll of a thread pidfd opened
 * while the sibling still runs, which reports the exit whether it happened
 * before or during the poll (a futex wait, as in a bare pthread_join, fails
 * with EAGAIN in the first case), so the child's own syscall results do not
 * depend on how the two threads were scheduled; once it returns, the TID
 * word is clear and pthread_join makes no syscall. */
static void release_and_join(int release, pthread_t thread, pid_t tid) {
  int pidfd = syscall(SYS_pidfd_open, tid, O_EXCL /* PIDFD_THREAD */);
  struct pollfd poll_fd = {.fd = pidfd, .events = POLLIN};
  if (pidfd < 0 || write(release, "s", 1) != 1 || poll(&poll_fd, 1, -1) != 1 ||
      close(pidfd) != 0 || pthread_join(thread, NULL) != 0)
    die("sibling join");
}

static void
park_child(const char* tag, long act, int how, int from_parent, int to_parent) {
  install(SIGCONT, 0, park_handler);
  if (how & PARK_TSTP_HANDLER) {
    install(SIGTSTP, 0, park_handler);
    install(SIGTTIN, 0, park_handler);
    install(SIGTTOU, 0, park_handler);
  }
  sigset_t mask;
  int sibling_pipe[2], tid_pipe[2], sibling_fds[2];
  pthread_t sibling;
  pid_t sibling_tid = 0;
  if (how & PARK_SIBLING) {
    /* The sibling inherits a mask that blocks everything, so every signal
     * goes to this thread, as in a single-threaded child. */
    sigfillset(&mask);
    if (pipe(sibling_pipe) != 0 || pipe(tid_pipe) != 0 ||
        sigprocmask(SIG_SETMASK, &mask, NULL) != 0)
      die("sibling setup");
    sibling_fds[0] = sibling_pipe[0];
    sibling_fds[1] = tid_pipe[1];
    if (pthread_create(&sibling, NULL, park_sibling, sibling_fds) != 0 ||
        read(tid_pipe[0], &sibling_tid, sizeof sibling_tid) !=
            sizeof sibling_tid)
      die("pthread_create sibling");
  }
  sigemptyset(&mask);
  if (how & PARK_LATE_CONT)
    sigaddset(&mask, SIGCONT);
  if (sigprocmask(SIG_SETMASK, &mask, NULL) != 0)
    die("child sigprocmask");
  char buf[8] = {0};
  long r = how & PARK_READ ? SITEM(SYS_read, from_parent, buf, 1, 0, 0, act)
                           : SITEM(SYS_write, to_parent, "data", 4, 0, 0, act);
  if (write(to_parent, "after", 5) != 5)
    die("child write after");
  if (how & PARK_SIBLING) {
    release_and_join(sibling_pipe[1], sibling, sibling_tid);
  }
  char token;
  if (read(from_parent, &token, 1) != 1)
    die("child read token");
  sigemptyset(&mask);
  if (sigprocmask(SIG_SETMASK, &mask, NULL) != 0)
    die("child unblock");
  say("%s child call ret=%ld byte=%d\n", tag, r, buf[0]);
  for (int i = 0; i < npark; i++) {
    struct park_rec* p = &park_recs[i];
    say("%s child signal %d: sig=%d code=%d from-parent=%d rip=%s rax=%ld\n",
        tag,
        i,
        p->sig,
        p->code,
        p->from_parent,
        where(p->rip),
        p->rax);
  }
  _exit(7);
}

/* Waits up to `seconds` for the next notification; 1 if it came. */
static int park_notified(int seconds) {
  sigset_t usr2;
  sigemptyset(&usr2);
  sigaddset(&usr2, SIGUSR2);
  struct timespec timeout = {seconds, 0};
  return sigtimedwait(&usr2, NULL, &timeout) == SIGUSR2;
}

/* Forks a child that runs one tagged call at the warmed shared site; the
 * parent sends `kills` (one per notification), then reports what its
 * waitpid(WUNTRACED | WCONTINUED) and SIGCHLD saw. */
static void
park_run(const char* tag, long act, int how, const int* kills, int nkills) {
  int down[2], up[2];
  if (pipe(down) != 0 || pipe(up) != 0)
    die("pipe");
  sigset_t block, old;
  sigemptyset(&block);
  sigaddset(&block, SIGUSR2);
  sigaddset(&block, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &block, &old) != 0)
    die("sigprocmask");
  pid_t child = fork();
  if (child < 0)
    die("fork");
  if (child == 0) {
    close(down[1]);
    close(up[0]);
    park_child(tag, act, how, down[0], up[1]);
  }
  close(down[0]);
  close(up[1]);
  int notified = 0;
  for (int i = 0; i < nkills; i++) {
    if (!park_notified(10))
      break;
    notified++;
    /* A negative entry is sent to the thread (tgkill), else to the process. */
    int sig = kills[i] > 0 ? kills[i] & 0xff : kills[i];
    if (kills[i] > 0 && (kills[i] & CONT_THEN(0)) && kill(child, SIGCONT) != 0)
      die("kill SIGCONT");
    if (sig < 0 ? syscall(SYS_tgkill, child, child, -sig) != 0
                : kill(child, sig) != 0)
      die("kill");
  }
  char buf[8] = {0};
  long data = -1;
  int restarted = -1;
  if (how & PARK_READ) {
    /* A call interrupted by the SIGSTOP restarts; one that was not blocks
     * until the parent gives up waiting and writes. */
    restarted = park_notified(10);
    if (write(down[1], "d", 1) != 1)
      die("write data");
  } else {
    data = read(up[0], buf, 4);
  }
  long after = read(up[0], buf, 5);
  if (after == 5) {
    if (how & PARK_LATE_CONT)
      kill(child, SIGCONT);
    if (write(down[1], "t", 1) != 1)
      die("write token");
  }
  char statuses[256] = "";
  for (;;) {
    int status;
    pid_t w = waitpid(child, &status, WUNTRACED | WCONTINUED);
    if (w != child)
      die("waitpid");
    char one[64];
    if (WIFEXITED(status))
      snprintf(one, sizeof one, " exited:%d", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
      snprintf(one, sizeof one, " signaled:%d", WTERMSIG(status));
    else if (WIFSTOPPED(status))
      snprintf(one, sizeof one, " stopped:%d", WSTOPSIG(status));
    else if (WIFCONTINUED(status))
      snprintf(one, sizeof one, " continued");
    else
      snprintf(one, sizeof one, " raw:%#x", status);
    strncat(statuses, one, sizeof statuses - strlen(statuses) - 1);
    if (WIFEXITED(status) || WIFSIGNALED(status))
      break;
  }
  say("%s parent notified=%d data=%ld after=%ld restarted=%d waitpid%s\n",
      tag,
      notified,
      data,
      after,
      restarted,
      statuses);
  sigset_t chld;
  sigemptyset(&chld);
  sigaddset(&chld, SIGCHLD);
  struct timespec none = {0, 0};
  siginfo_t si;
  while (sigtimedwait(&chld, &si, &none) == SIGCHLD)
    say("%s parent SIGCHLD code=%d status=%d from-child=%d\n",
        tag,
        si.si_code,
        si.si_status,
        si.si_pid == child);
  close(down[1]);
  close(up[0]);
  /* Drop any notification that arrived after the parent stopped waiting. */
  while (park_notified(0))
    ;
  if (sigprocmask(SIG_SETMASK, &old, NULL) != 0)
    die("sigprocmask restore");
}

/* The parent stops its child at the write's stop, then continues
 * it once the write and the child's next output arrived. */
static void mode_sigstop_parent(void) {
  static const int kills[] = {SIGSTOP};
  warm();
  park_run("tail", SHAPE_TAIL | TOOL_PARK(SIGSTOP), PARK_LATE_CONT, kills, 1);
  park_run(
      "inject", SHAPE_INJECT | TOOL_PARK(SIGSTOP), PARK_LATE_CONT, kills, 1);
}

/* A SIGCONT that arrives inside the window: after the SIGSTOP and before the
 * call runs. It discards the pending SIGSTOP, so neither is a stop. */
static void mode_sigstop_cont_window(void) {
  static const int kills[] = {SIGSTOP, SIGCONT};
  warm();
  park_run(
      "tail",
      SHAPE_TAIL | TOOL_PARK(SIGSTOP) | HOOK_PARK(SIGCONT),
      0,
      kills,
      2);
  park_run(
      "inject",
      SHAPE_INJECT | TOOL_PARK(SIGSTOP) | HOOK_PARK(SIGCONT),
      0,
      kills,
      2);
}

/* SIGTSTP with a handler installed, at the call's stop or immediately
 * before the call runs: handled after the call returns, never a stop. */
static void mode_sigtstp_handler(void) {
  static const int kills[] = {SIGTSTP};
  warm();
  park_run(
      "tool", SHAPE_TAIL | TOOL_PARK(SIGTSTP), PARK_TSTP_HANDLER, kills, 1);
  park_run(
      "hook", SHAPE_TAIL | HOOK_PARK(SIGTSTP), PARK_TSTP_HANDLER, kills, 1);
}

/* SIGKILL at the call's stop, immediately before the call runs, and there
 * after a SIGSTOP, from the parent and (stop-kill) from the tracer: the
 * child dies without the call running. */
static void mode_sigkill_hop(void) {
  static const int kill_only[] = {SIGKILL}, stop_kill[] = {SIGSTOP, SIGKILL},
                   stop[] = {SIGSTOP};
  warm();
  park_run("entry", SHAPE_TAIL | TOOL_PARK(SIGKILL), 0, kill_only, 1);
  park_run("hop", SHAPE_TAIL | HOOK_PARK(SIGKILL), 0, kill_only, 1);
  park_run(
      "stop-hop",
      SHAPE_TAIL | TOOL_PARK(SIGSTOP) | HOOK_PARK(SIGKILL),
      0,
      stop_kill,
      2);
  park_run(
      "stop-kill", SHAPE_TAIL | TOOL_PARK(SIGSTOP) | HOOK_KILL, 0, stop, 1);
}

/* Several SIGSTOPs in one call, into both queues, some sent at the call's
 * stop and some immediately before it runs: each queue delivers one
 * SIGSTOP, with the siginfo
 * of the first sent to it. parent-kill: the tracer's tgkill and the parent's
 * kill at the site's stop, then the tracer's kill and tgkill immediately
 * before the call (the shared queue keeps the parent's siginfo).
 * parent-tgkill: the parent's tgkill, then the tracer's kill and tgkill (the
 * private queue keeps the parent's siginfo). */
static void mode_sigstop_many(void) {
  static const int kill_stop[] = {SIGSTOP}, tgkill_stop[] = {-SIGSTOP};
  warm();
  park_run(
      "parent-kill-tail",
      SHAPE_TAIL | SEND_SIGSTOP | TOOL_PARK(SIGSTOP) | HOOK_SEND_STOPS,
      0,
      kill_stop,
      1);
  park_run(
      "parent-kill-inject",
      SHAPE_INJECT | SEND_SIGSTOP | TOOL_PARK(SIGSTOP) | HOOK_SEND_STOPS,
      0,
      kill_stop,
      1);
  park_run(
      "parent-tgkill-tail",
      SHAPE_TAIL | TOOL_PARK(SIGSTOP) | HOOK_SEND_STOPS,
      0,
      tgkill_stop,
      1);
  park_run(
      "parent-tgkill-inject",
      SHAPE_INJECT | TOOL_PARK(SIGSTOP) | HOOK_SEND_STOPS,
      0,
      tgkill_stop,
      1);
}

/* A SIGSTOP sent at the write's seccomp stop, then a SIGCONT sent at the
 * hook's late point, immediately before the write runs. The SIGCONT discards
 * the pending SIGSTOP, so neither is a stop. */
static void mode_sigstop_cont_late(void) {
  static const int kills[] = {SIGSTOP, SIGCONT};
  warm();
  park_run(
      "tail",
      SHAPE_TAIL | TOOL_PARK(SIGSTOP) | HOOK_PARK(SIGCONT) | HOOK_LATE,
      0,
      kills,
      2);
  park_run(
      "inject",
      SHAPE_INJECT | TOOL_PARK(SIGSTOP) | HOOK_PARK(SIGCONT) | HOOK_LATE,
      0,
      kills,
      2);
}

/* After an injected write with a SIGSTOP pending, a SIGCONT discards it,
 * and the Tool sends a new SIGSTOP (rt_tgsigqueueinfo: SI_QUEUE
 * with value 7, shaped like a re-raise) before the thread returns to user
 * mode: its delivery stop keeps its own siginfo. */
static void mode_sigstop_stale(void) {
  static const int kills[] = {SIGSTOP, SIGCONT};
  warm();
  park_run(
      "inject",
      SHAPE_INJECT | TOOL_PARK(SIGSTOP) | TOOL_AFTER_CONT,
      0,
      kills,
      2);
}

/* A SIGSTOP sent at the write's seccomp stop, then a SIGCONT and the stop
 * signal `sig` (handled) at the hook: `sig` discards the SIGCONT, which
 * discarded the SIGSTOP, so only `sig` is delivered, after the write. */
static void sigstop_cont_then(const char* tag, int sig) {
  const int kills[] = {SIGSTOP, CONT_THEN(sig)};
  warm();
  park_run(
      tag,
      SHAPE_TAIL | TOOL_PARK(SIGSTOP) | HOOK_PARK(sig),
      PARK_TSTP_HANDLER,
      kills,
      2);
}

/* A SIGSTOP then a SIGCONT, with a second thread in the child, which blocks
 * every signal. The SIGSTOP is thread-directed: a process-directed one could
 * be taken by the sibling. */
static void mode_sigstop_threaded(void) {
  static const int stop_cont[] = {-SIGSTOP, SIGCONT}, stop[] = {-SIGSTOP};
  warm();
  park_run(
      "window",
      SHAPE_TAIL | TOOL_PARK(SIGSTOP) | HOOK_PARK(SIGCONT),
      PARK_SIBLING,
      stop_cont,
      2);
  park_run(
      "late-cont",
      SHAPE_INJECT | TOOL_PARK(SIGSTOP),
      PARK_SIBLING | PARK_LATE_CONT,
      stop,
      1);
}

/* A SIGSTOP pending when a blocking read starts interrupts it: the read
 * restarts after the suppressed stop, before any data arrived. */
static void mode_sigstop_blocking_read(void) {
  static const int kills[] = {SIGSTOP};
  warm();
  park_run(
      "tail",
      SHAPE_TAIL | TOOL_PARK(SIGSTOP) | NOTIFY_AGAIN,
      PARK_READ,
      kills,
      1);
  park_run(
      "inject",
      SHAPE_INJECT | TOOL_PARK(SIGSTOP) | NOTIFY_AGAIN,
      PARK_READ,
      kills,
      1);
}

/* The unknown-number cases: each runs through its own warmed site. */
static void mode_unknown(void) {
  static const struct {
    const char* name;
    long nr;
    int prints_bytes;
  } cases[] = {
      {"nr500", 500, 1},
      {"nr-1", -1, 1},
      /* 337, not 335 or 336: x86_64 335 (uretprobe) and 336 (uprobe) are
       * passed through by seccomp without running the filter, by upstream
       * design (see probe_nr). */
      {"gap337", 337, 1},
      {"high-getpid", 0x100000027L, 0},
      {"high500", 0x1000001f4L, 1},
  };
  long (*fns[])(long) = {
      tp_gen0_fn, tp_gen1_fn, tp_gen2_fn, tp_gen3_fn, tp_gen4_fn};
  char* sites[] = {tp_gen0, tp_gen1, tp_gen2, tp_gen3, tp_gen4};
  long pid = getpid();
  for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    for (int j = 0; j < 3; j++)
      if (fns[i](SYS_getpid) != pid)
        die("warm generic site");
    long r = fns[i](cases[i].nr);
    char ret[32];
    if (r == pid)
      snprintf(ret, sizeof ret, "<pid>");
    else
      snprintf(ret, sizeof ret, "%ld", r);
    say("%s ret=%s rcx-next=%d r11=%#lx\n",
        cases[i].name,
        ret,
        tp_gen_rcx == (long)sites[i] + 2,
        tp_gen_r11);
    say("%s getpid after=%d\n", cases[i].name, fns[i](SYS_getpid) == pid);
    if (cases[i].prints_bytes) {
      unsigned char* p = (unsigned char*)sites[i];
      say("%s bytes after %02x %02x\n", cases[i].name, p[0], p[1]);
    }
  }
}

/* Prints the smaps fields of the mapping holding tp_site that a changed
 * page would change. */
static void site_smaps(const char* tag) {
  FILE* f = fopen("/proc/self/smaps", "r");
  if (!f)
    die("open smaps");
  char line[256];
  int in = 0;
  unsigned long site = (unsigned long)tp_site;
  while (fgets(line, sizeof line, f)) {
    unsigned long lo, hi;
    if (sscanf(line, "%lx-%lx ", &lo, &hi) == 2 &&
        strchr(line, '-') < strchr(line, ' ')) {
      in = site >= lo && site < hi;
      continue;
    }
    if (!in)
      continue;
    static const char* fields[] = {
        "Rss:",
        "Shared_Clean:",
        "Shared_Dirty:",
        "Private_Clean:",
        "Private_Dirty:",
        "Anonymous:",
        "AnonHugePages:"};
    for (unsigned i = 0; i < sizeof fields / sizeof fields[0]; i++) {
      size_t n = strlen(fields[i]);
      if (!strncmp(line, fields[i], n)) {
        long kb = strtol(line + n, NULL, 10);
        say("%s smaps %s %ld\n", tag, fields[i], kb);
      }
    }
  }
  fclose(f);
}

static void text_reads(const char* tag) {
  unsigned char* p = (unsigned char*)tp_site;
  say("%s direct %02x %02x\n", tag, p[0], p[1]);
  unsigned char b[2] = {0, 0};
  int fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
  if (fd < 0 || pread(fd, b, 2, (off_t)(unsigned long)tp_site) != 2)
    die("read /proc/self/mem");
  close(fd);
  say("%s procmem %02x %02x\n", tag, b[0], b[1]);
  site_smaps(tag);
}

/* The site's own bytes, read directly and through /proc/self/mem, and its
 * page's smaps, before and after the guest makes the page writable. */
static void mode_text_residual(void) {
  warm();
  text_reads("before");
  void* page = (void*)((unsigned long)tp_site & ~4095UL);
  if (mprotect(page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    die("mprotect rwx");
  text_reads("after");
  long r = SITE(SYS_getpid, 0, 0, 0, 0, 0);
  say("getpid after mprotect pid=%d\n", r == getpid());
}

int main(int argc, char** argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s <mode> <report>\n", argv[0]);
    return 2;
  }
  report_fd = open(argv[2], O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
  if (report_fd < 0)
    return 3;
  main_argv = argv;
  say("mode %s site=%#lx\n", argv[1], (long)tp_site);
  const char* m = argv[1];
  if (!strcmp(m, "sig_pending"))
    mode_sig_pending();
  else if (!strcmp(m, "rt_queue"))
    mode_rt_queue();
  else if (!strcmp(m, "self_raise"))
    mode_self_raise();
  else if (!strcmp(m, "sigtrap_profile"))
    mode_sigtrap_profile();
  else if (!strcmp(m, "sigtrap_states"))
    mode_sigtrap_states();
  else if (!strcmp(m, "segv_states"))
    mode_segv_states();
  else if (!strcmp(m, "segv_in_segv_handler"))
    mode_segv_in_segv_handler();
  else if (!strcmp(m, "segv_handler_flags"))
    mode_segv_handler_flags();
  else if (!strcmp(m, "segv_thread"))
    mode_segv_thread();
  else if (!strcmp(m, "segv_sharer_t") || !strcmp(m, "segv_sharer_u"))
    mode_segv_sharer();
  else if (!strcmp(m, "segv_fork"))
    mode_segv_fork();
  else if (!strcmp(m, "segv_exec"))
    mode_segv_exec();
  else if (!strcmp(m, "segv_after_exec_ign"))
    mode_segv_after_exec_ign();
  else if (!strcmp(m, "segv_after_exec_handler"))
    mode_segv_after_exec_handler();
  else if (!strcmp(m, "segv_clear_sighand"))
    mode_segv_clear_sighand();
  else if (!strcmp(m, "segv_ppoll_handler"))
    mode_segv_ppoll_handler();
  else if (!strcmp(m, "segv_quiet"))
    mode_segv_quiet();
  else if (!strcmp(m, "segv_resume_signal_dropped"))
    mode_segv_resume_signal_dropped();
  else if (!strcmp(m, "sigtrap_raw_name"))
    mode_sigtrap_raw_name();
  else if (!strcmp(m, "sigtrap_cache_flip"))
    mode_sigtrap_cache_flip();
  else if (!strcmp(m, "sigtrap_sigblk"))
    mode_sigtrap_sigblk();
  else if (!strcmp(m, "sigtrap_sigblk_shared"))
    mode_sigtrap_sigblk_shared();
  else if (!strcmp(m, "sigtrap_sigblk_untraced"))
    mode_sigtrap_sigblk_untraced();
  else if (!strcmp(m, "sigtrap_ppoll_hold_then_read"))
    mode_sigtrap_ppoll_hold_then_read();
  else if (!strcmp(m, "sigtrap_callback_restore"))
    mode_sigtrap_callback_restore();
  else if (!strcmp(m, "sigtrap_caught_blocked_injections"))
    mode_sigtrap_caught_blocked_injections();
  else if (!strcmp(m, "sigtrap_caught_blocked_no_repair"))
    mode_sigtrap_caught_blocked_no_repair();
  else if (!strcmp(m, "sigtrap_caught_blocked_filter_install"))
    mode_sigtrap_caught_blocked_filter_install();
  else if (!strcmp(m, "sigtrap_sibling_change_during_call"))
    mode_sigtrap_sibling_change_during_call();
  else if (!strcmp(m, "sigtrap_sibling_change_from_dfl"))
    mode_sigtrap_sibling_change_from_dfl();
  else if (!strcmp(m, "sigtrap_sibling_change_from_ign"))
    mode_sigtrap_sibling_change_from_ign();
  else if (!strcmp(m, "sigtrap_blocked_installs_handler"))
    mode_sigtrap_blocked_installs_handler();
  else if (!strcmp(m, "sigtrap_timer"))
    mode_sigtrap_timer();
  else if (!strcmp(m, "sigtrap_interrupted_waits"))
    mode_sigtrap_interrupted_waits();
  else if (!strcmp(m, "sigtrap_tight_stack"))
    mode_sigtrap_tight_stack();
  else if (!strcmp(m, "sigtrap_signal_callback"))
    mode_sigtrap_signal_callback();
  else if (!strcmp(m, "sigtrap_interrupted_waits_observed"))
    mode_sigtrap_interrupted_waits_observed();
  else if (!strcmp(m, "sigtrap_caught_unblocked"))
    mode_sigtrap_caught_unblocked();
  else if (!strcmp(m, "sigtrap_int3_after_interrupted_wait"))
    mode_sigtrap_int3_after_interrupted_wait();
  else if (!strcmp(m, "sigtrap_fork_then_sigaction"))
    mode_sigtrap_fork_then_sigaction();
  else if (!strcmp(m, "sigtrap_int3_timer"))
    mode_sigtrap_int3_timer();
  else if (!strcmp(m, "sigtrap_int3_in_the_other_windows"))
    mode_sigtrap_int3_in_the_other_windows();
  else if (!strcmp(m, "sigtrap_scratch_overlay"))
    mode_sigtrap_scratch_overlay();
  else if (!strcmp(m, "sigtrap_mmap_race"))
    mode_sigtrap_mmap_race();
  else if (!strcmp(m, "sigtrap_rw9_filter_kill"))
    mode_sigtrap_rw9_filter_kill();
  else if (!strcmp(m, "sigtrap_rw9_filter_errno"))
    mode_sigtrap_rw9_filter_errno();
  else if (!strcmp(m, "sigtrap_rw9_filter_trap"))
    mode_sigtrap_rw9_filter_trap();
  else if (!strcmp(m, "sigtrap_caller_preexec_filter"))
    mode_sigtrap_caller_preexec_filter();
  else if (!strcmp(m, "sigtrap_tsync_filter_kill"))
    mode_sigtrap_tsync_filter_kill();
  else if (!strcmp(m, "sigtrap_tsync_filter_trap"))
    mode_sigtrap_tsync_filter_trap();
  else if (!strcmp(m, "sigtrap_tsync_filter_errno"))
    mode_sigtrap_tsync_filter_errno();
  else if (!strcmp(m, "sigtrap_rv_dontfork_own"))
    mode_sigtrap_rv_dontfork_own();
  else if (!strcmp(m, "sigtrap_rv_dontfork_none"))
    mode_sigtrap_rv_dontfork_none();
  else if (!strcmp(m, "sigtrap_rv_exec_hello"))
    mode_sigtrap_rv_exec_hello();
  else if (!strcmp(m, "sigtrap_rv_seccomp_exec_kill"))
    mode_sigtrap_rv_seccomp_exec_kill();
  else if (!strcmp(m, "sigtrap_rv_seccomp_exec_errno"))
    mode_sigtrap_rv_seccomp_exec_errno();
  else if (!strcmp(m, "sigtrap_rv_seccomp_exec_trap"))
    mode_sigtrap_rv_seccomp_exec_trap();
  else if (!strcmp(m, "sigtrap_rv_clonevm_replace"))
    mode_sigtrap_rv_clonevm_replace();
  else if (!strcmp(m, "sigtrap_rv_sibling_dfl_persist"))
    mode_sigtrap_rv_sibling_dfl_persist();
  else if (!strcmp(m, "sigtrap_reserved_page_race"))
    mode_sigtrap_reserved_page_race();
  else if (!strcmp(m, "sigtrap_interrupted_waits_observed_process"))
    mode_sigtrap_interrupted_waits_observed_process();
  else if (!strcmp(m, "sigtrap_pending_at_step"))
    mode_sigtrap_pending_at_step();
  else if (!strcmp(m, "sigtrap_sigreturn_timer"))
    mode_sigtrap_sigreturn_timer();
  else if (!strcmp(m, "sigtrap_fork"))
    mode_sigtrap_fork();
  else if (!strcmp(m, "sigtrap_private_calls"))
    mode_sigtrap_private_calls();
  else if (!strcmp(m, "sigtrap_exec"))
    mode_sigtrap_exec(0);
  else if (!strncmp(m, "sigtrap_exec_", 13))
    mode_sigtrap_exec(atoi(m + 13));
  else if (!strcmp(m, "restart"))
    mode_restart();
  else if (!strcmp(m, "raw_clone_parent_ppid"))
    mode_raw_clone_parent_ppid();
  else if (!strcmp(m, "raw_clone_process"))
    mode_raw_clone_process();
  else if (!strcmp(m, "fork_family"))
    mode_fork_family();
  else if (!strcmp(m, "foreign_int80"))
    mode_foreign_int80();
  else if (!strcmp(m, "late_timer_int80"))
    mode_late_timer(1);
  else if (!strcmp(m, "late_timer_getpid"))
    mode_late_timer(0);
  else if (!strcmp(m, "rcx_r11"))
    mode_rcx_r11();
  else if (!strcmp(m, "resume_signal"))
    mode_resume_signal();
  else if (!strcmp(m, "exec_image"))
    mode_exec_image();
  else if (!strcmp(m, "exec_leader"))
    mode_exec_leader();
  else if (!strcmp(m, "exec_thread"))
    mode_exec_thread();
  else if (!strcmp(m, "jit"))
    mode_jit();
  else if (!strcmp(m, "jit_more"))
    mode_jit_more();
  else if (!strcmp(m, "fork_undecided"))
    mode_fork_undecided();
  else if (!strcmp(m, "thread_mismatch"))
    mode_thread_mismatch();
  else if (!strcmp(m, "vfork_undecided"))
    mode_vfork_undecided();
  else if (!strcmp(m, "process_madvise"))
    mode_process_madvise();
  else if (!strcmp(m, "process_madvise_first"))
    mode_process_madvise_first();
  else if (!strcmp(m, "vfork_spawn"))
    mode_vfork_spawn();
  else if (!strcmp(m, "guest_seccomp"))
    guest_seccomp("site");
  else if (!strcmp(m, "guest_seccomp_tsync"))
    guest_seccomp("tsync");
  else if (!strcmp(m, "guest_seccomp_prctl"))
    guest_seccomp("prctl");
  else if (!strcmp(m, "guest_trace_unknown"))
    mode_guest_trace_unknown();
  else if (!strcmp(m, "sud"))
    mode_sud();
  else if (!strcmp(m, "untraced_thread"))
    untraced_thread("libc");
  else if (!strcmp(m, "untraced_thread_site"))
    untraced_thread("site");
  else if (!strcmp(m, "untraced_fork"))
    untraced_fork();
  else if (!strcmp(m, "sigchld_nanosleep"))
    mode_sigchld_nanosleep();
  else if (!strcmp(m, "timer_loop"))
    mode_timer_loop();
  else if (!strcmp(m, "perf_marker"))
    mode_perf_marker();
  else if (!strcmp(m, "timer_allow"))
    mode_timer_allow();
  else if (!strcmp(m, "timer_cancel"))
    mode_timer_cancel();
  else if (!strcmp(m, "timer_hop_unknown"))
    mode_timer_hop_unknown();
  else if (!strcmp(m, "timer_hop_sigreturn"))
    mode_timer_hop_sigreturn();
  else if (!strcmp(m, "timer_hop_sigreturn_blocked"))
    mode_timer_hop_sigreturn_blocked();
  else if (!strcmp(m, "timer_late_sigreturn"))
    mode_timer_late_sigreturn();
  else if (!strcmp(m, "timer_far_sigreturn"))
    mode_timer_far_sigreturn();
  else if (!strcmp(m, "sigreturn_slot_ret"))
    mode_sigreturn_slot_ret();
  else if (!strcmp(m, "sigreturn_bad_frame"))
    mode_sigreturn_bad_frame();
  else if (!strcmp(m, "sigreturn_prot_none_frame"))
    mode_sigreturn_prot_none_frame();
  else if (!strcmp(m, "sigstop_hop"))
    mode_sigstop_hop();
  else if (!strcmp(m, "sigstop_parent"))
    mode_sigstop_parent();
  else if (!strcmp(m, "sigstop_cont_window"))
    mode_sigstop_cont_window();
  else if (!strcmp(m, "sigtstp_handler"))
    mode_sigtstp_handler();
  else if (!strcmp(m, "sigkill_hop"))
    mode_sigkill_hop();
  else if (!strcmp(m, "sigstop_blocking_read"))
    mode_sigstop_blocking_read();
  else if (!strcmp(m, "sigstop_many"))
    mode_sigstop_many();
  else if (!strcmp(m, "sigstop_cont_late"))
    mode_sigstop_cont_late();
  else if (!strcmp(m, "sigstop_cont_tstp"))
    sigstop_cont_then("tstp", SIGTSTP);
  else if (!strcmp(m, "sigstop_cont_ttin"))
    sigstop_cont_then("ttin", SIGTTIN);
  else if (!strcmp(m, "sigstop_cont_ttou"))
    sigstop_cont_then("ttou", SIGTTOU);
  else if (!strcmp(m, "sigstop_stale"))
    mode_sigstop_stale();
  else if (!strcmp(m, "sigstop_threaded"))
    mode_sigstop_threaded();
  else if (!strcmp(m, "probe_uretprobe"))
    probe_nr(335);
  else if (!strcmp(m, "probe_uprobe"))
    probe_nr(336);
  else if (!strcmp(m, "partial"))
    mode_partial();
  else if (!strcmp(m, "sigreturn"))
    mode_sigreturn();
  else if (!strcmp(m, "unknown"))
    mode_unknown();
  else if (!strcmp(m, "text_residual"))
    mode_text_residual();
  else
    return 4;
  say("done\n");
  return 0;
}
