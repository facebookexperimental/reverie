/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Guest for the trap-only P2 site-patching tests
 * (reverie-ptrace/src/liteinst_trap_only_p2_tests.rs).
 *
 * Usage: trap_only_p2 <mode> <report-file>
 *
 * Every observation is appended to the report file as text; the test runs
 * the same mode under plain ptrace and under trap-only with site patching on
 * and requires equal reports. Absolute addresses are comparable because the
 * tracer disables address randomisation. PID values are never printed.
 *
 * `tp_site` is a shared generic syscall site: `tp_site_fn(nr, a1..a6)` issues
 * one `syscall` there. Its first execution patches it (the test Tool
 * subscribes to every syscall), so later executions go through the trap-only
 * hop. A call whose sixth argument (r9) carries TP_MAGIC asks the test Tool
 * for a handler shape or for tracer-side signals (see the Rust side).
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
#define SEND_SIGUSR1 0x100
#define SEND_SIGWINCH 0x200
#define SEND_QUEUE 0x400
/* The tracer leaves SIGUSR1 pending for its final resume of the stop. */
#define SEND_RESUME 0x800
/* The Tool requests a precise timer of a5 (r8) branches at this stop. */
#define ARM_TIMER 0x1000
/* The Tool sends SIGSTOP to the calling thread at this stop. */
#define SEND_SIGSTOP 0x2000

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

/* T8: a site that loads rcx/r11 sentinels immediately before `syscall` and
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

/* P2d: five more generic sites, `tp_genN_fn(nr)`, one per unknown-number
 * case: a site that runs an allowed number is restored and never patched
 * again, so each case needs its own warmed site. */
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

/* T4c: a signal restorer that runs rt_sigreturn through the shared site. */
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

/* Warms tp_site: the first call patches it, the next two take the hop. */
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

/* T1a */
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

/* T1c (standard signals only; see the Rust side). */
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

/* T1f */
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

/* T2 */
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

/* T3 */
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

/* T6a */
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

  /* fork through the patched site; the child forks a grandchild there. */
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

/* T7c */
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
    /* No core file in the working directory; core dumping stays host
     * policy either way, and both backends see the same limit. */
    struct rlimit none = {0, 0};
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

/* A signal the tracer passes on its final resume of a patched stop. */
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

/* Guest code running the private page's traced slot outside any hop. */
static void mode_stray_slot(void) {
  warm();
  long ret;
  __asm__ volatile("call *%1"
                   : "=a"(ret)
                   : "r"(0x71000004L), "a"(39L)
                   : "rcx", "r11", "memory");
  say("stray slot returned %ld\n", ret);
}

/* T8 */
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

  /* A handler interrupting a patched blocking read sees rcx/r11 too. */
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

/* ---- P2c: site-table lifecycle (T6b-T6d) and guest installs (T7a-T7b) ---- */

/* Runs this fixture again, in `mode`, with the same report file. */
static void exec_self(const char* mode) {
  char* args[] = {"/proc/self/exe", (char*)mode, main_argv[2], NULL};
  execve(args[0], args, environ);
  die("execve");
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

/* The image an exec installs: its table starts empty, so warm() patches the
 * site again (under trap-only) at the same -no-pie address. */
static void mode_exec_image(void) {
  warm();
  say("exec image getpid ok\n");
}

/* T6b: the leader execs. */
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

/* T6b: a non-leader thread execs; the kernel kills the leader first. The
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

/* T6c: JIT code; its site is patched only while its page is r-xp, and every
 * mapping change restores the bytes before it runs. */
static void mode_jit(void) {
  const int rw = PROT_READ | PROT_WRITE, rx = PROT_READ | PROT_EXEC;
  int status;

  unsigned char* a = map_at(0x50000000, rw, MAP_FIXED_NOREPLACE);
  emit(a, 0, SYS_getpid);
  protect(a, rx);
  for (int i = 0; i < 3; i++)
    say("jit a %d pid=%d\n", i, run_code(a) == getpid());
  /* A fork child changes its own copy of the page: the parent's patch, in
   * the parent's own table, must stay live. */
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

  /* munmap of a patched page, then new code at the same address. */
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

  /* mmap(MAP_FIXED) over a patched page. */
  unsigned char* d = map_at(0x50050000, rw, MAP_FIXED_NOREPLACE);
  emit(d, 0, SYS_getpid);
  protect(d, rx);
  for (int i = 0; i < 3; i++)
    say("jit d %d pid=%d\n", i, run_code(d) == getpid());
  d = map_at(0x50050000, rw, MAP_FIXED);
  jit_bytes("jit d after mmap fixed", d + 5);

  /* mremap moves a patched page. */
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

  /* A writable and executable page is never patched. */
  unsigned char* e = map_at(0x50040000, rw | PROT_EXEC, MAP_FIXED_NOREPLACE);
  emit(e, 0, SYS_getpid);
  for (int i = 0; i < 3; i++)
    say("jit e %d pid=%d\n", i, run_code(e) == getpid());
  jit_bytes("jit e", e + 5);

  /* madvise(MADV_DONTNEED) on the fixture's own patched text page. */
  warm();
  if (madvise((void*)((unsigned long)tp_site & ~4095UL), 4096, MADV_DONTNEED) !=
      0)
    die("madvise");
  site_bytes("after madvise");
  warm();
}

/* T6c, continued. A one-byte store through /proc/self/mem (which no
 * lifecycle stop sees) over a patched JIT site, then an mprotect that
 * restores what is left of the patch: the guest reads its own byte and the
 * original second byte. Then an mremap(MREMAP_FIXED) of another page onto a
 * patched page, which retires the patched page's site. */
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
    die("mremap onto a patched page");
  jit_bytes("more f after mremap", f + 5);
  for (int i = 0; i < 3; i++)
    say("more f2 %d tid=%d\n", i, run_code(f) == gettid());
}

/* T6a, undecided: a fork through the patched site whose clone flags the
 * test makes the tracer forget, as for a Tool-injected clone, or record as
 * CLONE_VM against kcmp, or as CLONE_VFORK against the kind of new-child
 * stop. Both copies of the address space read the original bytes
 * afterwards. */
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

/* T6a, undecided: a vfork through the patched site whose recorded clone
 * flags the test makes disagree with the vfork stop (no CLONE_VFORK). The
 * child shares the parent's stack, so after the vfork it calls no function:
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

/* T6c: process_madvise(MADV_DONTNEED) through a pidfd for this process, on
 * the fixture's own patched text page. The tracer reads neither the iovec
 * nor which process the pidfd names, so every site is restored first,
 * including the patched site of a JIT page the call does not name. The
 * result depends on the host kernel: before Linux 6.13 a process may not
 * pass MADV_DONTNEED for itself (EINVAL); the restore happens either way. */
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

/* T6c: the first call through tp_site is process_madvise(MADV_DONTNEED),
 * through a pidfd for this process, on tp_site's own page. The tracer never
 * patches a site at a process_madvise stop (patched there, a tail-injected
 * call would run after the patch and drop the page copy that holds it), so
 * the site still reads 0f 05 after the call; warm() then patches it through
 * getpid. SITE returns the raw result, -EINVAL before Linux 6.13 (see
 * mode_process_madvise). */
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

/* T6a, undecided: a thread (CLONE_VM|CLONE_THREAD) through the patched
 * site, whose recorded clone flags the test makes disagree with kcmp (no
 * CLONE_VM) or with the kind of new-child stop (CLONE_VFORK). The thread
 * returns from tp_site_fn on its own stack into thread_entry and exits; the
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

/* T6d: posix_spawn and system() (both vfork-style) from a process with warm
 * sites; the parent's sites stay patched after the children exec. */
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

/* T7a. how: "site" installs with seccomp() through the patched site (an I386
 * stop), "tsync" from a two-thread process through libc, "prctl" with
 * prctl(PR_SET_SECCOMP) through libc (x86_64 stops). */
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
   * filter, so its table must start disabled as well. */
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

/* T7b: syscall user dispatch, with the allowed region excluding the site. */
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

/* A CLONE_UNTRACED thread gets no new-child stop, so the site must already
 * be restored when the clone runs. `through`: "libc" clones from libc's
 * syscall() (never patched), "site" through the patched site itself. */
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

/* A fork-like CLONE_UNTRACED child (no CLONE_VM), cloned through the patched
 * site: it gets no new-child stop and its own copy of the parent's text, so
 * the site must already be restored when the clone runs, and the clone must
 * run at the site. The child's syscalls are refused by the inherited filter
 * (ENOSYS: no tracer), so it reports through a shared mapping and spins
 * until the parent kills it. */
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

/* T1b: a child exits while the parent sleeps in a patched nanosleep. With
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
/* T4: the number of branch counts k = 1..TL_K a timer covers, which spans
 * one iteration and the next iteration's arming call. */
#define TL_K 9

/* T4: a loop of 200 iterations, each with a patched getpid and three
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

/* T1d: a precise timer far enough out that perf's MARKER signal (not an
 * artificial one) starts the single-steps, targeted at branch counts around
 * the patched site that follows a long branch loop. */
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

/* T4d: a timer single-step that reaches the patched site carrying an
 * allowed number (500, which no syscall table knows). */
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

/* A counting-phase precise timer armed at a patched getppid, PM_BRANCHES + 1
 * branches out, with an Allow-class number (500) run through a warmed
 * generic site before the branch loop in which the timer fires. The hop's
 * internal stop must not cancel the armed timer.
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

/* A syscall site executed exactly once, so its stop is always an ordinary
 * x86_64 stop (a site is patched only after it has been seen). */
static long __attribute__((noinline)) getpid_once(void) {
  long r;
  __asm__ volatile("syscall"
                   : "=a"(r)
                   : "a"((long)SYS_getpid)
                   : "rcx", "r11", "memory");
  return r;
}

/* A precise timer armed in a forked child at the patched getppid, far beyond
 * any skid margin, whose signal the child blocks: no notification is ever
 * handled, the limiting case of a late interrupt, as in
 * reverie-ptrace/tests/precise_timer_overtaken.rs. The child then runs well
 * past the target and ends with a foreign int 0x80 (`foreign`), which plain
 * ptrace's filter kills with no stop, or with an ordinary x86_64 getpid,
 * whose stop both backends report. The child's other setup is T7c's. */
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
    struct rlimit none = {0, 0};
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
 * the branch loop: first a patched-site getpid, then an ordinary x86_64
 * getpid. A last timer with no stop before its loop fires, so the run's one
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

static void timer_hop_handler(int sig, siginfo_t* si, void* uc_) {
  (void)sig;
  (void)si;
  (void)uc_;
  SITEM(SYS_getppid, 0, 0, 0, 0, PM_BRANCHES + 1, ARM_TIMER);
}

/* The same timer, armed at the patched getppid inside a signal handler
 * whose restorer runs rt_sigreturn through that same warmed site (an
 * Allow-class hop), before the branch loop in which the timer fires (three
 * times the armed distance, for the reason given at mode_timer_hop_unknown). */
static void mode_timer_hop_sigreturn(void) {
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
  for (volatile int j = 0; j < 3 * PM_BRANCHES; j++)
    ;
  long g = SITE(SYS_getpid, 0, 0, 0, 0, 0);
  unsigned char* p = (unsigned char*)tp_site;
  say("timer hop sigreturn getpid=%d bytes after %02x %02x\n",
      g == pid,
      p[0],
      p[1]);
}

/* T4b: under a partial subscription (the Tool does not subscribe to
 * getuid), the shared site is never patched. */
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
  /* The frame's mask must win over the mask the hop saved. */
  sigaddset(&((ucontext_t*)uc_)->uc_sigmask, SIGUSR2);
}

/* T4c: rt_sigreturn through the warmed shared site, from a restorer the
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
 * the slot's own return address: the frame's registers win, so the guest
 * executes the ud2 there, as under plain ptrace. */
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
 * whose saved rip is the slot's return address and whose saved rsp is the
 * frame's own rsp. The kernel's user copies fail on the page, so it returns 0
 * at S+2 without loading a register and forces SIGSEGV. A tracer that reads
 * the frame with FOLL_FORCE (/proc/<tid>/mem) sees rip == SLOT_RET and rsp ==
 * rsp and would keep rip at the slot's return. */
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

/* A SIGSTOP the tracer sends (SI_TKILL) while a patched site's call is
 * parked. Plain ptrace suppresses every SIGSTOP at its delivery stop
 * (handle_sigstop), after the call completed; trap-only defers the one its
 * hop dequeues at the slot and raises it again before the call runs. */
static void mode_sigstop_hop(void) {
  warm();
  long r = SITEM(SYS_getpid, 0, 0, 0, 0, 0, SHAPE_TAIL | SEND_SIGSTOP);
  say("sigstop tail getpid returned pid=%d\n", r == getpid());
  r = SITEM(SYS_getpid, 0, 0, 0, 0, 0, SHAPE_INJECT | SEND_SIGSTOP);
  say("sigstop inject getpid returned pid=%d\n", r == getpid());
}

/* P2d-sigstop (P2-SPEC O1.4): a traced parent signals its child while the
 * child's call at the patched shared site is parked. The Tool (at the
 * site's seccomp stop, before trap-only's hop starts) and the tracer's
 * pre-syscall hook (immediately before the call runs: plain ptrace's resume,
 * trap-only's H3) each notify the parent with SIGUSR2 and wait until the
 * signal the call's tag names has arrived, so the signal lands at the same
 * logical point under both backends. */
#define TOOL_PARK(sig) ((long)(sig) << 32)
#define HOOK_PARK(sig) ((long)(sig) << 40)
/* After the call's inject returned, the Tool notifies the parent, waits for
 * its SIGCONT, then sends SIGSTOP to the thread. */
#define TOOL_AFTER_CONT (0x40L << 32)
/* The hook parks at its late point: under trap-only after the hop read the
 * pending signals, immediately before it raises the deferred SIGSTOPs. */
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

/* T1e: the parent stops its child at a patched write site, then continues
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

/* SIGTSTP with a handler installed: blockable, so the hop's mask holds it;
 * handled after the call returns, never a stop. */
static void mode_sigtstp_handler(void) {
  static const int kills[] = {SIGTSTP};
  warm();
  park_run(
      "tool", SHAPE_TAIL | TOOL_PARK(SIGTSTP), PARK_TSTP_HANDLER, kills, 1);
  park_run(
      "hook", SHAPE_TAIL | HOOK_PARK(SIGTSTP), PARK_TSTP_HANDLER, kills, 1);
}

/* SIGKILL at the site's stop, inside the hop, and inside the hop with a
 * deferred SIGSTOP, from the parent and (stop-kill) from the tracer, which
 * kills before the hop settles the deferred SIGSTOP: the child dies without
 * the call running. */
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

/* Several SIGSTOPs in one call, into both queues, some sent while the hop
 * already deferred others: each queue delivers one SIGSTOP, with the siginfo
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

/* A SIGCONT that arrives after the hop's last read of the pending signals
 * and before it raises the deferred SIGSTOP (plain ptrace: the same instant
 * as mode_sigstop_cont_window's). */
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

/* After an injected write whose SIGSTOP the hop re-raised, a SIGCONT
 * discards it, and the Tool sends a new SIGSTOP (rt_tgsigqueueinfo: SI_QUEUE
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

/* A SIGCONT inside the window, after the SIGSTOP, then the stop signal `sig`
 * (handled) before the hop reads the pending signals: `sig` discards the
 * SIGCONT, which discarded the SIGSTOP, so under plain ptrace only `sig` is
 * delivered, after the write. Trap-only cannot see the SIGCONT and refuses
 * (TrapOnlyHopDeferredStopBehindStopSignal). */
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

/* mode_sigstop_cont_window and T1e with a second thread in the child: the
 * thread's creation retires the sites, so no call hops. The SIGSTOP is
 * thread-directed: a process-directed one could be taken by the sibling. */
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
    int stays_patched;
  } cases[] = {
      {"nr500", 500, 0},
      {"nr-1", -1, 0},
      /* 337, not 335 or 336: x86_64 335 (uretprobe) and 336 (uprobe) are
       * passed through by seccomp without running the filter, by upstream
       * design, so they are no gap (see probe_nr). */
      {"gap337", 337, 0},
      {"high-getpid", 0x100000027L, 1},
      {"high500", 0x1000001f4L, 0},
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
    if (!cases[i].stays_patched) {
      unsigned char* p = (unsigned char*)sites[i];
      say("%s bytes after %02x %02x\n", cases[i].name, p[0], p[1]);
    }
  }
}

/* Prints the smaps fields of the mapping holding tp_site that a patched
 * page can change. */
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

/* T5: the text residual of a patched site, before and after the guest makes
 * the page writable. */
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
  else if (!strcmp(m, "restart"))
    mode_restart();
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
  else if (!strcmp(m, "stray_slot"))
    mode_stray_slot();
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
