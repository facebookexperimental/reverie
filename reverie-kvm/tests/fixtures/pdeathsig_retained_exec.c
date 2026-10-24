/* Freestanding Linux/x86-64 counterpart of pdeathsig_creator.c mode 6 only.
 * No libc, TLS, allocation, sleeps, polling deadline, or extra exec is used.
 * The unchanged Rust controller owns the existing execution deadline.
 * Kernel ABI numbers/layouts below are deliberately independent of libc.
 */
#if !defined(__x86_64__) || !defined(__linux__)
#error "this fixture requires Linux x86-64"
#endif

typedef unsigned long word;
typedef unsigned int u32;
enum {
  SYS_write = 1, SYS_close = 3, SYS_rt_sigaction = 13,
  SYS_rt_sigprocmask = 14, SYS_pread64 = 17, SYS_pwrite64 = 18,
  SYS_sched_yield = 24, SYS_getpid = 39, SYS_clone = 56, SYS_fork = 57,
  SYS_execve = 59, SYS_exit = 60, SYS_wait4 = 61, SYS_ftruncate = 77,
  SYS_getuid = 102, SYS_getppid = 110, SYS_rt_sigpending = 127,
  SYS_prctl = 157, SYS_gettid = 186, SYS_futex = 202,
  SYS_exit_group = 231, SYS_tgkill = 234, SYS_openat = 257,
  SIGUSR1 = 10, SIG_BLOCK = 0, SIG_UNBLOCK = 1, SIG_SETMASK = 2,
  SA_SIGINFO = 4, SA_RESTORER = 0x04000000,
  PR_SET_PDEATHSIG = 1, PR_GET_PDEATHSIG = 2,
  CLONE_VM = 0x100, CLONE_FS = 0x200, CLONE_FILES = 0x400,
  CLONE_SIGHAND = 0x800, CLONE_THREAD = 0x10000,
  CLONE_PARENT_SETTID = 0x100000, CLONE_CHILD_CLEARTID = 0x200000,
  FUTEX_WAIT = 0, ESRCH = 3, EINTR = 4, EAGAIN = 11
};

static long call6(long nr, word a, word b, word c, word d, word e, word f) {
  register word r10 __asm__("r10") = d;
  register word r8 __asm__("r8") = e;
  register word r9 __asm__("r9") = f;
  long result;
  __asm__ volatile("syscall" : "=a"(result)
                   : "a"(nr), "D"(a), "S"(b), "d"(c),
                     "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory", "cc");
  return result;
}
#define call0(n) call6((n), 0, 0, 0, 0, 0, 0)
#define call1(n,a) call6((n), (word)(a), 0, 0, 0, 0, 0)
#define call2(n,a,b) call6((n), (word)(a), (word)(b), 0, 0, 0, 0)
#define call3(n,a,b,c) call6((n), (word)(a), (word)(b), (word)(c), 0, 0, 0)
#define call4(n,a,b,c,d) call6((n), (word)(a), (word)(b), (word)(c), (word)(d), 0, 0)
#define call5(n,a,b,c,d,e) call6((n), (word)(a), (word)(b), (word)(c), (word)(d), (word)(e), 0)

struct kernel_siginfo {
  int signo, error, code, alignment;
  int pid;
  u32 uid;
  unsigned char remaining[104];
};
struct kernel_sigaction {
  void (*handler)(int, struct kernel_siginfo *, void *);
  word flags;
  void (*restorer)(void);
  word mask;
};
_Static_assert(sizeof(word) == 8, "64-bit syscall and kernel sigset ABI");
_Static_assert(sizeof(struct kernel_siginfo) == 128, "Linux siginfo size");
_Static_assert(__builtin_offsetof(struct kernel_siginfo, pid) == 16, "SI_USER pid offset");
_Static_assert(__builtin_offsetof(struct kernel_siginfo, uid) == 20, "SI_USER uid offset");
_Static_assert(sizeof(struct kernel_sigaction) == 32, "x86-64 kernel sigaction ABI");

static int record_fd;
static int parent_pid;
static u32 parent_uid;
static int child_pid;
static int creator_tid;
static volatile int calls;
static volatile int valid_info;
static char **environment;
static unsigned char creator_stack[65536] __attribute__((aligned(16)));

__attribute__((noreturn)) static void fail(int code) {
  call1(SYS_exit_group, code);
  __builtin_unreachable();
}
static void store(word offset, char value) {
  if (call4(SYS_pwrite64, record_fd, &value, 1, offset) != 1) fail(30);
}
static void await(word offset) {
  char value;
  do {
    if (call4(SYS_pread64, record_fd, &value, 1, offset) != 1) fail(31);
    if (!value) call0(SYS_sched_yield);
  } while (!value);
}
static int equal(const char *a, const char *b) {
  while (*a && *a == *b) { ++a; ++b; }
  return *a == *b;
}
static u32 decimal(const char *s) {
  word result = 0;
  if (!*s) fail(48);
  do {
    if (*s < '0' || *s > '9') fail(48);
    result = result * 10 + (word)(*s++ - '0');
    if (result > 0xffffffffUL) fail(48);
  } while (*s);
  return (u32)result;
}
static char *format_u32(char buffer[32], u32 value) {
  char *p = buffer + 31;
  *p = 0;
  do { *--p = (char)('0' + value % 10); value /= 10; } while (value);
  return p;
}
static word length(const char *s) {
  word n = 0;
  while (s[n]) ++n;
  return n;
}
static void caught(int signal, struct kernel_siginfo *info, void *context) {
  (void)context;
  ++calls;
  valid_info = signal == SIGUSR1 && info->signo == SIGUSR1 &&
      info->error == 0 && info->code == 0 /* SI_USER */ &&
      info->pid == parent_pid && info->uid == parent_uid;
}
void restore_signal(void);
__asm__(".text\n"
        ".type restore_signal,@function\n"
        "restore_signal:\n"
        "mov $15,%eax\n" /* __NR_rt_sigreturn; entered by handler ret */
        "syscall\n"
        "ud2\n"
        ".size restore_signal,.-restore_signal\n");

__attribute__((noreturn)) static void recipient(int resumed) {
  const word one = 1UL << (SIGUSR1 - 1);
  if (!resumed && call4(SYS_rt_sigprocmask, SIG_BLOCK, &one, 0, 8)) fail(33);
  if (resumed) {
    word inherited = 0;
    struct kernel_sigaction previous = {0};
    if (call4(SYS_rt_sigprocmask, SIG_SETMASK, 0, &inherited, 8) ||
        !(inherited & one) ||
        call4(SYS_rt_sigaction, SIGUSR1, 0, &previous, 8) ||
        previous.handler != 0 /* SIG_DFL */) fail(47);
  }
  struct kernel_sigaction action = {caught, SA_SIGINFO | SA_RESTORER, restore_signal, 0};
  if (call4(SYS_rt_sigaction, SIGUSR1, &action, 0, 8)) fail(32);
  if (!resumed && call5(SYS_prctl, PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0)) fail(34);
  int setting = -1;
  if (call5(SYS_prctl, PR_GET_PDEATHSIG, &setting, 0, 0, 0) || setting != SIGUSR1) fail(35);
  if (!resumed) {
    char fd_buffer[32], pid_buffer[32], uid_buffer[32];
    char *args[] = {"/proc/self/exe", "6", "resumed",
                   format_u32(fd_buffer, (u32)record_fd),
                   format_u32(pid_buffer, (u32)parent_pid),
                   format_u32(uid_buffer, parent_uid), 0};
    /* Same retained static image; no interpreter, extra SET, or fallback exec. */
    call3(SYS_execve, args[0], args, environment);
    fail(49);
  }
  store(0, 1);
  if (!resumed) fail(50);
  await(1); /* leader releases only after the real creator thread has exited */
  word pending = 0;
  if (call2(SYS_rt_sigpending, &pending, 8) || !(pending & one) ||
      calls != 0 || valid_info != 0) fail(51);
  if (call4(SYS_rt_sigprocmask, SIG_UNBLOCK, &one, 0, 8)) fail(52);
  if (calls != 1 || valid_info != 1) fail(53);
  if (call0(SYS_getppid) != parent_pid) fail(41);
  store(2, 1);
  call1(SYS_exit_group, 0);
  __builtin_unreachable();
}

/* Called only by the child side of the assembly clone trampoline below. */
__attribute__((used, noreturn)) static void creator(void) {
  if (call0(SYS_gettid) == parent_pid) fail(19);
  long child = call0(SYS_fork);
  if (child < 0) fail(20);
  if (child == 0) recipient(0);
  __atomic_store_n(&child_pid, (int)child, __ATOMIC_RELEASE);
  await(0);
  /* Nonleader thread exit, never exit_group. This causes parent-death delivery. */
  call1(SYS_exit, 0);
  __builtin_unreachable();
}
long clone_creator(void *stack_top, int *tid, word flags);
__asm__(".text\n"
        ".type clone_creator,@function\n"
        "clone_creator:\n"
        "mov %rdx,%r9\n"   /* C arg3: flags */
        "mov %rsi,%r10\n"  /* child_tid */
        "mov %rsi,%rdx\n"  /* parent_tid */
        "mov %rdi,%rsi\n"  /* child stack */
        "mov %r9,%rdi\n"   /* clone flags */
        "xor %r8d,%r8d\n"  /* no TLS; fixture never uses TLS */
        "mov $56,%eax\n"
        "syscall\n"
        "test %rax,%rax\n"
        "jz 1f\n"
        "ret\n"           /* parent keeps original C stack */
        "1:\n"
        "xor %ebp,%ebp\n"
        "call creator\n"  /* fresh 16-aligned child stack, normal C ABI */
        "ud2\n"
        ".size clone_creator,.-clone_creator\n");

__attribute__((used, noreturn)) static void start_c(word *initial_stack) {
  word argc = initial_stack[0];
  char **argv = (char **)(initial_stack + 1);
  environment = argv + argc + 1;
  if (argc == 6 && equal(argv[1], "6") && equal(argv[2], "resumed")) {
    record_fd = (int)decimal(argv[3]);
    parent_pid = (int)decimal(argv[4]);
    parent_uid = decimal(argv[5]);
    recipient(1);
  }
  if (argc != 2) fail(10);
  if (!equal(argv[1], "6")) fail(11);
  parent_pid = (int)call0(SYS_getpid);
  /* KVM leaves getuid to the Tool and refuses it (-ENOSYS) in a run without
     one; its signals then carry uid 0. */
  long uid = call0(SYS_getuid);
  parent_uid = uid == -38 ? 0 : (u32)uid;
  record_fd = (int)call4(SYS_openat, -100 /* AT_FDCWD */, "creator.record",
                        0x242 /* O_CREAT | O_TRUNC | O_RDWR */, 0600);
  if (record_fd < 0 || call2(SYS_ftruncate, record_fd, 3)) fail(12);
  creator_tid = -1;
  const word flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                    CLONE_THREAD | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID;
  long tid = clone_creator(creator_stack + sizeof(creator_stack), &creator_tid, flags);
  if (tid <= 0) fail(13);
  for (;;) {
    int observed = __atomic_load_n(&creator_tid, __ATOMIC_ACQUIRE);
    if (!observed) break;
    if (observed != tid) fail(14);
    /* Linux clear_child_tid wakes FUTEX_WAKE without FUTEX_PRIVATE_FLAG.
     * Join the same shared key; EAGAIN/EINTR/spurious wake recheck the predicate.
     * This is the ordinary unbounded join loop under the unchanged outer bound. */
    long result = call4(SYS_futex, &creator_tid, FUTEX_WAIT, observed, 0);
    if (result != 0 && result != -EAGAIN && result != -EINTR) fail(14);
  }
  /* clear_child_tid is in exit_mm, before exit_notify generates PDEATHSIG.
   * The completed join alone is therefore not the publication witness.
   * tgkill(sig=0) keeps succeeding while this exact task remains in PID lookup;
   * nonleader PID removal follows forget_original_parent and signal generation.
   * No later thread is created in this TGID, so numeric reuse cannot alias it.
   * This waits only for task retirement; it never retries the pending assertion.
   */
  for (;;) {
    long exists = call3(SYS_tgkill, parent_pid, tid, 0);
    if (exists == -ESRCH) break;
    if (exists != 0) fail(55);
    call0(SYS_sched_yield);
  }
  store(1, 1);
  int child = __atomic_load_n(&child_pid, __ATOMIC_ACQUIRE);
  int status = 0;
  if (child <= 0 || call4(SYS_wait4, child, &status, 0, 0) != child || status != 0) {
    char number[32];
    char *digits = format_u32(number, (u32)status);
    const char prefix[] = "recipient status=";
    call3(SYS_write, 2, prefix, sizeof(prefix) - 1);
    call3(SYS_write, 2, digits, length(digits));
    call3(SYS_write, 2, "\n", 1);
    fail(15);
  }
  char completed = 0;
  if (call4(SYS_pread64, record_fd, &completed, 1, 2) != 1 || completed != 1) fail(16);
  if (call1(SYS_close, record_fd)) fail(17);
  const char output[] = "pdeathsig creator-thread mode=6 parent-alive=1 child-completed=1\n";
  if (call3(SYS_write, 1, output, sizeof(output) - 1) != (long)sizeof(output) - 1) fail(18);
  call1(SYS_exit_group, 0);
  __builtin_unreachable();
}
__asm__(".text\n"
        ".global _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "xor %ebp,%ebp\n"
        "mov %rsp,%rdi\n"
        "and $-16,%rsp\n"
        "call start_c\n"
        "ud2\n"
        ".size _start,.-_start\n"
        ".pushsection .note.GNU-stack,\"\",@progbits\n"
        ".popsection\n");
