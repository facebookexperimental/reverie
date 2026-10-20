#define _GNU_SOURCE
#include <cpuid.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "handler atomics must be lock-free");
enum { CONTROL, DELIVER, SUPPRESS, MASK, RESTART_CONTROL, RESTART_DELIVER,
       RESTART_SUPPRESS, PPOLL_MASK, MASK_SUPPRESS, MASK_IGNORE };
/* Exported solely for this native API test's client. */
int probe_case, probe_vector_level, probe_use_xsave;
int probe_mask_path;
volatile uint64_t probe_handler_rax = UINT64_MAX;
unsigned probe_xsave_mask;
_Atomic unsigned probe_admission_seen;
unsigned char probe_original[65536] __attribute__((aligned(64)));
unsigned char probe_seed[32][64] __attribute__((aligned(64)));
static unsigned char before[2624] __attribute__((aligned(64)));
static unsigned char after[2624] __attribute__((aligned(64)));
static _Atomic unsigned handled, handler_bad;
static _Atomic unsigned suspend_returned, release_sent;
enum { MASK_UNCHECKED, MASK_KERNEL_OWNED, MASK_EMULATED };
static int physical_mask_mode;
static uint64_t handler_expected_mask;
static int handler_expected_signal = SIGUSR1;
static int channel[2];
static pid_t main_tid, process_pid;
static const uint64_t usr1 = UINT64_C(1) << (SIGUSR1 - 1);
static const uint64_t usr2 = UINT64_C(1) << (SIGUSR2 - 1);

extern long probe_state(void *, void *, const uint64_t *);
extern long probe_read(int, void *, size_t);
extern long probe_sigsuspend(const uint64_t *);
extern void probe_handler_entry(int);
extern void clobber_fp_state(unsigned);

static long raw4(long n, long a, long b, long c, long d) {
  register long r10 __asm__("r10") = d;
  long result;
  __asm__ volatile("syscall" : "=a"(result)
                   : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10)
                   : "rcx", "r11", "cc", "memory");
  return result;
}

static long raw_ppoll(const uint64_t *temporary_mask) {
  register long r10 __asm__("r10") = (long)temporary_mask;
  register long r8 __asm__("r8") = 8;
  long result;
  /* No descriptors or timeout: only the already pending caught signal can
   * complete this wait. The size is Linux's kernel sigset size on x86-64. */
  __asm__ volatile("syscall" : "=a"(result)
                   : "0"((long)SYS_ppoll), "D"(0L), "S"(0L), "d"(0L),
                     "r"(r10), "r"(r8)
                   : "rcx", "r11", "cc", "memory");
  return result;
}

static void require(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "native signal state failure: %s\n", message);
    exit(41);
  }
}

static uint64_t mask_now(void) {
  uint64_t mask = 0;
  require(raw4(SYS_rt_sigprocmask, SIG_SETMASK, 0, (long)&mask, 8) == 0,
          "read signal mask");
  return mask;
}

static uint64_t kernel_signal_set(pid_t tid, const char *field) {
  char path[96], line[256];
  snprintf(path, sizeof(path), "/proc/self/task/%ld/status", (long)tid);
  FILE *file = fopen(path, "r");
  require(file != NULL, "open own thread kernel mask record");
  unsigned long long mask = 0;
  int found = 0;
  while (fgets(line, sizeof(line), file)) {
    if (!strncmp(line, field, strlen(field)) &&
        sscanf(line + strlen(field), "%llx", &mask) == 1) {
      found = 1;
      break;
    }
  }
  require(fclose(file) == 0 && found, "read own thread kernel mask record");
  return (uint64_t)mask;
}

static long mask_call(int how, const uint64_t *input, uint64_t *output, long size) {
  register long set __asm__("rsi") = (long)input;
  register long r10 __asm__("r10") = size;
  long result;
  __asm__ volatile("syscall" : "=a"(result), "+S"(set)
                   : "0"((long)SYS_rt_sigprocmask), "D"((long)how),
                     "d"((long)output), "r"(r10)
                   : "rcx", "r11", "cc", "memory");
  require(set == (long)input, "sigprocmask preserves original input argument register");
  return result;
}

static void check_readonly_sigprocmask(void) {
  const uint64_t intercepted = UINT64_C(1) << (SIGSEGV - 1);
  const uint64_t physical = UINT64_C(1) << (SIGURG - 1);
  const uint64_t bits = intercepted | physical;
  pid_t tid = (pid_t)raw4(SYS_gettid, 0, 0, 0, 0);
  require(kernel_signal_set(tid, "SigCgt:") & intercepted,
          "no-client DR has an actual SIGSEGV handler");
  require(!(kernel_signal_set(tid, "SigCgt:") & physical),
          "no-client partial mode leaves SIGURG without a handler");
  uint64_t original = mask_now();
  uint64_t prior = original & ~bits;
  require(mask_call(SIG_SETMASK, &prior, NULL, 8) == 0, "establish initial mask");
  size_t page = (size_t)sysconf(_SC_PAGESIZE);
  uint64_t *input = mmap(NULL, page, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  require(input != MAP_FAILED, "read-only mask input page");
  *input = bits;
  require(mprotect(input, page, PROT_READ) == 0, "protect sigprocmask input read-only");
  uint64_t old = UINT64_C(0x1234);
  require(mask_call(SIG_BLOCK, input, &old, 7) == -EINVAL &&
              mask_now() == prior && old == UINT64_C(0x1234),
          "invalid sigprocmask size leaves mask and output unchanged");
  require(mask_call(SIG_SETMASK + 1, input, &old, 8) == -EINVAL &&
              mask_now() == prior && old == UINT64_C(0x1234),
          "invalid sigprocmask operation leaves mask and output unchanged");
  require(mask_call(SIG_BLOCK, (const uint64_t *)1, &old, 8) == -EFAULT &&
              mask_now() == prior && old == UINT64_C(0x1234),
          "unreadable sigprocmask input leaves mask and output unchanged");
  static const char marker[] = "readonly sigprocmask input prepared\n";
  require(write(STDERR_FILENO, marker, sizeof(marker) - 1) == (ssize_t)(sizeof(marker) - 1),
          "retain known-readonly pre-call marker");
  require(mask_call(SIG_BLOCK, input, &old, 8) == 0 && old == prior &&
              mask_now() == (prior | bits) && *input == bits,
          "BLOCK accepts read-only input and returns complete old mask");
  require(mask_call(SIG_UNBLOCK, input, &old, 8) == 0 && old == (prior | bits) &&
              mask_now() == prior && *input == bits,
          "UNBLOCK accepts read-only input and returns complete old mask");
  require(mask_call(SIG_SETMASK, input, &old, 8) == 0 && old == prior &&
              mask_now() == bits && *input == bits,
          "SETMASK accepts read-only input and returns complete old mask");
  require(mask_call(SIG_SETMASK, &prior, NULL, 8) == 0, "reset before bad output");
  require(mask_call(SIG_BLOCK, input, (uint64_t *)1, 8) == -EFAULT &&
              mask_now() == (prior | bits) && *input == bits,
          "bad output reports EFAULT after applying valid mask input");
  require(mask_call(SIG_SETMASK + 1, NULL, &old, 8) == 0 && old == (prior | bits) &&
              mask_now() == (prior | bits),
          "null input queries full mask and ignores operation");
  uint64_t alias = 0;
  require(mask_call(SIG_SETMASK, &alias, &alias, 8) == 0 && alias == (prior | bits) &&
              mask_now() == 0,
          "aliased input/output returns old mask after consuming new input");
  require(*input == bits && munmap(input, page) == 0, "input bytes preserved throughout");
  require(mask_call(SIG_SETMASK, &original, NULL, 8) == 0 && mask_now() == original,
          "restore complete initial mask");
  puts("guest completed case=mask-readonly");
}

static void handler(int sig) {
  int saved_errno = errno;
  uint64_t current = 0;
  long rc = raw4(SYS_rt_sigprocmask, SIG_SETMASK, 0, (long)&current, 8);
  if (sig != handler_expected_signal || rc != 0 || current != handler_expected_mask)
    atomic_store_explicit(&handler_bad, 1, memory_order_relaxed);
  /* Deliberately destroy private handler FP state. Linux sigreturn, rather
   * than the C ABI of this call, must restore the interrupted state. */
  clobber_fp_state((unsigned)probe_vector_level);
  atomic_fetch_add_explicit(&handled, 1, memory_order_release);
  errno = saved_errno;
}

void probe_handler_body(int sig) {
  handler(sig);
}

static void detect_vectors(void) {
  unsigned a, b, c, d;
  __cpuid(1, a, b, c, d);
  probe_use_xsave = (c & bit_XSAVE) && (c & bit_OSXSAVE);
  probe_xsave_mask = 3;
  uint64_t enabled = 0;
  if (probe_use_xsave) {
    unsigned lo, hi;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    enabled = ((uint64_t)hi << 32) | lo;
  }
  if ((c & bit_AVX) && (enabled & 6) == 6) {
    probe_vector_level = 1;
    probe_xsave_mask |= 4;
    __cpuid_count(7, 0, a, b, c, d);
    if ((b & bit_AVX512F) && (enabled & 0xe0) == 0xe0) {
      probe_vector_level = 2;
      probe_xsave_mask |= 0xe0;
    }
  }
  if (probe_use_xsave) {
    for (unsigned component = 2; component < 8; ++component) {
      if ((probe_xsave_mask & (1u << component)) == 0) continue;
      __cpuid_count(13, component, a, b, c, d);
      require(a != 0 && (uint64_t)a + b <= sizeof(probe_original),
              "actual selected XSAVE component fits saved-state buffer");
    }
  }
  for (unsigned reg = 0; reg < 32; ++reg)
    for (unsigned byte = 0; byte < 64; ++byte)
      probe_seed[reg][byte] = (unsigned char)(1 + reg * 7 + byte * 3);
}

static void equal_part(size_t offset, size_t count, const char *name) {
  if (memcmp(before + offset, after + offset, count) != 0) {
    fprintf(stderr, "state mismatch component=%s offset=%zu bytes=%zu\n",
            name, offset, count);
    exit(42);
  }
}

static void check_fp(void) {
  equal_part(0, 5, "x87 control/status/abridged tag");
  equal_part(24, 4, "MXCSR");
  for (unsigned reg = 0; reg < 8; ++reg)
    equal_part(32 + 16 * reg, 10, "80-bit x87 data");
  equal_part(160, 256, "XMM0..15");
  if (probe_vector_level >= 1)
    for (unsigned reg = 0; reg < 16; ++reg)
      equal_part(512 + 64 * reg, 32, "YMM0..15");
  if (probe_vector_level == 2) {
    equal_part(512, 2048, "ZMM0..31");
    equal_part(2560, 64, "opmask k0..7");
  }
}

static void queue_usr1(void) {
  require(raw4(SYS_tgkill, process_pid, main_tid, SIGUSR1, 0) == 0,
          "queue blocked SIGUSR1");
  sigset_t pending;
  require(sigpending(&pending) == 0 && sigismember(&pending, SIGUSR1) == 1,
          "SIGUSR1 really pending before unblock");
}

static void *release_read(void *unused) {
  (void)unused;
  char path[96], bytes[256];
  snprintf(path, sizeof(path), "/proc/self/task/%ld/syscall", (long)main_tid);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  require(fd >= 0, "open own main-thread syscall record");
  for (;;) {
    require(lseek(fd, 0, SEEK_SET) == 0, "rewind syscall record");
    ssize_t count = read(fd, bytes, sizeof(bytes) - 1);
    require(count > 0, "read own syscall record");
    bytes[count] = 0;
    long nr;
    unsigned long long arg0;
    if (sscanf(bytes, "%ld %llx", &nr, &arg0) == 2 && nr == SYS_read &&
        arg0 == (unsigned long long)channel[0])
      break;
    sched_yield();
  }
  close(fd);
  if (probe_case != RESTART_CONTROL) {
    require(raw4(SYS_tgkill, process_pid, main_tid, SIGUSR1, 0) == 0,
            "interrupt actual blocked read");
    /* Keep the pipe empty until the delivered handler or test client confirms
     * admission. Thus a late signal after successful read cannot satisfy the
     * restart precondition. An outer test timeout bounds a broken transport. */
    while (!(probe_case == RESTART_DELIVER
                 ? atomic_load_explicit(&handled, memory_order_acquire)
                 : atomic_load_explicit(&probe_admission_seen, memory_order_acquire)))
      sched_yield();
  }
  require(write(channel[1], "x", 1) == 1, "release blocked read");
  return NULL;
}

static void *release_suspend(void *unused) {
  (void)unused;
  char path[96], bytes[256];
  snprintf(path, sizeof(path), "/proc/self/task/%ld/syscall", (long)main_tid);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  require(fd >= 0, "open own suspended main-thread syscall record");
  for (;;) {
    require(!atomic_load_explicit(&suspend_returned, memory_order_acquire),
            "ignored/suppressed signal must not return from sigsuspend");
    require(atomic_load_explicit(&handled, memory_order_acquire) == 0,
            "first signal has no caught handler");
    /* SIG_IGN can be discarded by Linux without a client callback. For the
     * suppression case require the client to have accounted for the first
     * signal before accepting the kernel wait as the completion discriminator.
     */
    if (probe_case == MASK_SUPPRESS &&
        !atomic_load_explicit(&probe_admission_seen, memory_order_acquire)) {
      sched_yield();
      continue;
    }
    require(lseek(fd, 0, SEEK_SET) == 0, "rewind suspend syscall record");
    ssize_t count = read(fd, bytes, sizeof(bytes) - 1);
    require(count > 0, "read own suspend syscall record");
    bytes[count] = 0;
    long nr;
    if (sscanf(bytes, "%ld", &nr) == 1 && nr == SYS_rt_sigsuspend)
      break;
    sched_yield();
  }
  close(fd);
  if (physical_mask_mode != MASK_UNCHECKED) {
    uint64_t urgent = UINT64_C(1) << (SIGURG - 1);
    uint64_t physical = kernel_signal_set(main_tid, "SigBlk:");
    if (physical_mask_mode == MASK_KERNEL_OWNED)
      require(physical & urgent,
              "nonintercepted temporary SIGURG bit remains physically blocked during wait");
    else
      require(!(physical & urgent),
              "emulated temporary SIGURG bit stays physically unblocked during retry");
  }
  atomic_store_explicit(&release_sent, 1, memory_order_release);
  require(raw4(SYS_tgkill, process_pid, main_tid, SIGUSR2, 0) == 0,
          "caught second signal interrupts actual suspend");
  return NULL;
}

static void check_suspend_retry(uint64_t original, uint64_t blocked) {
  const uint64_t temporary_only = UINT64_C(1) << (SIGURG - 1);
  uint64_t prior = (original | blocked) & ~temporary_only;
  require(raw4(SYS_rt_sigprocmask, SIG_SETMASK, (long)&prior, 0, 8) == 0,
          "establish distinct original and temporary masks");
  if (physical_mask_mode != MASK_UNCHECKED) {
    /* Establish actual kernel ownership, not merely the requested DR argv.
     * A client in code_api mode forces full interception; the no-client
     * partial-interception control must leave SIGURG without a DR handler.
     */
    uint64_t caught = kernel_signal_set(main_tid, "SigCgt:");
    if (physical_mask_mode == MASK_KERNEL_OWNED)
      require(!(caught & temporary_only), "kernel-owned SIGURG has no installed handler");
    else
      require(caught & temporary_only, "emulated SIGURG has an installed DR handler");
  }
  size_t page = (size_t)sysconf(_SC_PAGESIZE);
  uint64_t *temporary = mmap(NULL, page, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  require(temporary != MAP_FAILED, "temporary mask page");
  *temporary = (prior & ~blocked) | temporary_only;
  const uint64_t captured = *temporary;
  require(mprotect(temporary, page, PROT_READ) == 0, "read-only suspend input");
  require(raw4(SYS_rt_sigsuspend, (long)temporary, 7, 0, 0) == -EINVAL &&
              mask_now() == prior,
          "invalid mask size leaves original mask unchanged");
  require(raw4(SYS_rt_sigsuspend, 1, 8, 0, 0) == -EFAULT && mask_now() == prior,
          "unreadable mask leaves original mask unchanged");
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = handler;
  action.sa_flags = SA_RESTART;
  sigemptyset(&action.sa_mask);
  sigaddset(&action.sa_mask, SIGUSR1);
  require(sigaction(SIGUSR2, &action, NULL) == 0, "install second caught handler");
  handler_expected_signal = SIGUSR2;
  handler_expected_mask = captured | blocked;
  if (probe_case == MASK_IGNORE) {
    action.sa_handler = SIG_IGN;
    require(sigaction(SIGUSR1, &action, NULL) == 0, "ignore first signal");
    require(raw4(SYS_tgkill, process_pid, main_tid, SIGUSR1, 0) == 0,
            "ignored first signal generation completed");
  } else {
    queue_usr1();
  }
  pthread_t helper;
  require(pthread_create(&helper, NULL, release_suspend, NULL) == 0,
          "suspend discriminator helper");
  long result = raw4(SYS_rt_sigsuspend, (long)temporary, 8, 0, 0);
  atomic_store_explicit(&suspend_returned, 1, memory_order_release);
  require(atomic_load_explicit(&release_sent, memory_order_acquire) == 1,
          "suspend cannot return before separately synchronized caught signal");
  require(result == -EINTR, "caught suspend is EINTR even with SA_RESTART");
  require(pthread_join(helper, NULL) == 0, "join suspend discriminator");
  require(mask_now() == prior, "suspend restores complete original mask");
  if (physical_mask_mode != MASK_UNCHECKED)
    require(!(kernel_signal_set(main_tid, "SigBlk:") & temporary_only),
            "original SIGURG bit is physically unblocked after sigreturn");
  require(*temporary == captured, "suspend never modifies read-only input");
  require(munmap(temporary, page) == 0, "release temporary mask page");
}

int main(int argc, char **argv) {
  require(argc == 2, "one exact case argument");
  if (strcmp(argv[1], "validation-post") == 0) {
    sigset_t mask, old;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    require(sigprocmask(SIG_SETMASK, &mask, &old) == 0, "seed blocked mask");
    uint64_t temporary = 0;
    struct { const void *mask; size_t bytes; } wrapper = { &temporary, sizeof(temporary) };
    struct timespec zero = { 0, 0 };
    require(syscall(SYS_pselect6, 0, NULL, NULL, NULL, &zero, &wrapper) == 0,
            "ordinary pselect seeds actual post metadata");
    require(sigprocmask(SIG_SETMASK, &old, NULL) == 0, "restore original mask");
    puts("pselect validation guest=ok");
    return 0;
  }
  if (strcmp(argv[1], "mask-readonly") == 0) {
    check_readonly_sigprocmask();
    return 0;
  }
  const char *names[] = {"control", "deliver", "suppress", "mask",
                        "restart-control", "restart-deliver", "restart-suppress",
                        "ppoll-mask", "mask-suppress", "mask-ignore"};
  int found = 0;
  for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
    if (strcmp(argv[1], names[i]) == 0) { probe_case = (int)i; found = 1; }
  bool transformed_result = strcmp(argv[1], "mask-tool-result") == 0;
  bool transformed_signal_result = strcmp(argv[1], "mask-signal-result") == 0;
  if (transformed_result || transformed_signal_result) { probe_case = MASK; found = 1; }
  if (strcmp(argv[1], "mask-suppress-emulated") == 0) {
    probe_case = MASK_SUPPRESS;
    physical_mask_mode = MASK_EMULATED;
    found = 1;
  }
  if (strcmp(argv[1], "mask-ignore-physical") == 0) {
    probe_case = MASK_IGNORE;
    physical_mask_mode = MASK_KERNEL_OWNED;
    found = 1;
  }
  require(found, "known case");
  detect_vectors();
  process_pid = getpid();
  main_tid = (pid_t)raw4(SYS_gettid, 0, 0, 0, 0);
  uint64_t blocked = usr1 | usr2;
  uint64_t original = mask_now();
  require(raw4(SYS_rt_sigprocmask, SIG_BLOCK, (long)&blocked, 0, 8) == 0,
          "block both test signals");
  handler_expected_mask = original | blocked;
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = transformed_result ? probe_handler_entry : handler;
  action.sa_flags = SA_RESTART;
  sigemptyset(&action.sa_mask);
  sigaddset(&action.sa_mask, SIGUSR2);
  require(sigaction(SIGUSR1, &action, NULL) == 0, "install caught handler");
  if (probe_case <= SUPPRESS) {
    if (probe_case != CONTROL) queue_usr1();
    require(probe_state(before, after, &usr1) == 0, "raw unblock result");
    check_fp();
    require(mask_now() == ((original | blocked) & ~usr1), "unblock preserves full mask");
  } else if (probe_case == MASK) {
    queue_usr1();
    uint64_t temporary = mask_now() & ~usr1;
    long result = transformed_signal_result ? probe_sigsuspend(&temporary)
        : raw4(SYS_rt_sigsuspend, (long)&temporary, 8, 0, 0);
    if (transformed_signal_result)
      require(result == -EPERM && probe_mask_path == 2,
              "signal policy result and alternate continuation survive suppression");
    else if (transformed_result)
      require(result == -EPERM, "explicit final client result survives caught delivery");
    else
      require(result == -EINTR, "sigsuspend returns EINTR");
    require(mask_now() == (original | blocked), "sigsuspend restores full original mask");
  } else if (probe_case == PPOLL_MASK) {
    queue_usr1();
    uint64_t temporary = mask_now() & ~usr1;
    require(raw_ppoll(&temporary) == -EINTR, "ppoll returns EINTR for caught signal");
    require(mask_now() == (original | blocked), "ppoll restores full original mask");
  } else if (probe_case == MASK_SUPPRESS || probe_case == MASK_IGNORE) {
    check_suspend_retry(original, blocked);
  } else {
    require(pipe(channel) == 0, "pipe");
    pthread_t helper;
    require(pthread_create(&helper, NULL, release_read, NULL) == 0, "helper thread");
    require(raw4(SYS_rt_sigprocmask, SIG_UNBLOCK, (long)&usr1, 0, 8) == 0,
            "unblock before read");
    char byte = 0;
    long result = probe_read(channel[0], &byte, 1);
    require(pthread_join(helper, NULL) == 0, "join helper");
    if (probe_case == RESTART_SUPPRESS) {
      require(result == -EINTR, "suppression resumes ordinary EINTR, not restart frame");
      require(read(channel[0], &byte, 1) == 1 && byte == 'x',
              "suppressed read did not consume released byte");
    } else {
      require(result == 1 && byte == 'x', "control/delivery read returns its payload");
    }
    close(channel[0]); close(channel[1]);
    require(mask_now() == ((original | blocked) & ~usr1), "read preserves full mask");
  }
  unsigned expected = probe_case == DELIVER || probe_case == MASK ||
                      probe_case == RESTART_DELIVER || probe_case == PPOLL_MASK ||
                      probe_case == MASK_SUPPRESS || probe_case == MASK_IGNORE;
  if (transformed_signal_result) expected = 0;
  require(atomic_load_explicit(&handled, memory_order_acquire) == expected,
          "exact handler count");
  require(atomic_load_explicit(&handler_bad, memory_order_relaxed) == 0,
          "handler signal and mask");
  if (transformed_result)
    require(probe_handler_rax == 0,
            "x86-64 caught entry clears live AX independently of saved return result");
  require(raw4(SYS_rt_sigprocmask, SIG_SETMASK, (long)&original, 0, 8) == 0,
          "restore initial mask");
  printf("guest completed case=%s vector_level=%d handler_count=%u\n",
         argv[1], probe_vector_level, expected);
  return 0;
}
