#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <unistd.h>

#define XSAVE_SIGNAL_SIZE 836
#define XMM15_OFFSET (160 + 15 * 16)
#define FP_SW_RESERVED_OFFSET 464
#define XSTATE_BV_OFFSET 512
#define XSTATE_SIZE_WITHOUT_YMM 576
#define TEST_FP_XSTATE_MAGIC1 UINT32_C(0x46505853)
#define TEST_FP_XSTATE_MAGIC2 UINT32_C(0x46505845)
#define XFEATURE_X87_SSE UINT64_C(3)

static int mode;
static _Alignas(64) unsigned char alternate_fpstate[XSAVE_SIGNAL_SIZE];
static _Alignas(64) unsigned char unaligned_xsave[XSAVE_SIGNAL_SIZE + 64];
static _Alignas(64) unsigned char active_altstack[32768];
static _Alignas(64) unsigned char replacement_altstack[32768];
static unsigned char* guarded_legacy_fpstate;

static void handler(int signo, siginfo_t* info, void* raw_context) {
  (void)info;
  if (signo != SIGUSR1)
    _exit(40);
  ucontext_t* context = (ucontext_t*)raw_context;
  context->uc_mcontext.gregs[REG_RAX] = 0x5a;
  if (mode == 1) {
    context->uc_mcontext.fpregs = 0;
    return;
  }
  if (mode == 3) {
    context->uc_mcontext.fpregs = (void*)0x1000;
    return;
  }
  if (mode == 5) {
    context->uc_stack.ss_flags = 0x1234;
  } else if (mode == 8) {
    context->uc_stack.ss_sp = replacement_altstack;
    context->uc_stack.ss_size = sizeof(replacement_altstack);
    context->uc_stack.ss_flags = SS_ONSTACK;
  } else if (mode == 9) {
    context->uc_stack.ss_sp = replacement_altstack;
    context->uc_stack.ss_size = sizeof(replacement_altstack);
    context->uc_stack.ss_flags = 0;
  } else if (mode == 7) {
    memcpy(guarded_legacy_fpstate, context->uc_mcontext.fpregs, 512);
    memset(
        guarded_legacy_fpstate + FP_SW_RESERVED_OFFSET,
        0,
        512 - FP_SW_RESERVED_OFFSET);
    for (unsigned i = 0; i < 16; ++i)
      guarded_legacy_fpstate[XMM15_OFFSET + i] = (unsigned char)(0xa0 + i);
    context->uc_mcontext.fpregs = (void*)guarded_legacy_fpstate;
    return;
  }
  unsigned char* redirected_fpstate = alternate_fpstate;
  if (mode == 10) {
    redirected_fpstate = unaligned_xsave + 16;
    if ((uintptr_t)redirected_fpstate % 16 != 0 ||
        (uintptr_t)redirected_fpstate % 64 == 0)
      _exit(54);
  }
  memcpy(redirected_fpstate, context->uc_mcontext.fpregs, XSAVE_SIGNAL_SIZE);
  if (mode == 4) {
    // Linux accepts the legacy 512-byte FXSAVE form when magic1 is zero.
    memset(
        redirected_fpstate + FP_SW_RESERVED_OFFSET,
        0,
        512 - FP_SW_RESERVED_OFFSET);
  } else if (mode == 6) {
    // A bounded standard-format x87/SSE-only image needs no YMM payload.
    uint32_t magic1 = TEST_FP_XSTATE_MAGIC1;
    uint32_t magic2 = TEST_FP_XSTATE_MAGIC2;
    uint32_t extended_size = XSTATE_SIZE_WITHOUT_YMM + sizeof(uint32_t);
    uint32_t xstate_size = XSTATE_SIZE_WITHOUT_YMM;
    uint64_t features = XFEATURE_X87_SSE;
    memcpy(redirected_fpstate + FP_SW_RESERVED_OFFSET, &magic1, 4);
    memcpy(redirected_fpstate + FP_SW_RESERVED_OFFSET + 4, &extended_size, 4);
    memcpy(redirected_fpstate + FP_SW_RESERVED_OFFSET + 8, &features, 8);
    memcpy(redirected_fpstate + FP_SW_RESERVED_OFFSET + 16, &xstate_size, 4);
    memset(
        redirected_fpstate + FP_SW_RESERVED_OFFSET + 20,
        0,
        512 - (FP_SW_RESERVED_OFFSET + 20));
    memcpy(redirected_fpstate + XSTATE_BV_OFFSET, &features, 8);
    memset(
        redirected_fpstate + XSTATE_BV_OFFSET + 8,
        0,
        XSTATE_SIZE_WITHOUT_YMM - (XSTATE_BV_OFFSET + 8));
    memcpy(redirected_fpstate + XSTATE_SIZE_WITHOUT_YMM, &magic2, 4);
  }
  for (unsigned i = 0; i < 16; ++i) {
    redirected_fpstate[XMM15_OFFSET + i] = (unsigned char)(0xa0 + i);
  }
  context->uc_mcontext.fpregs = (void*)redirected_fpstate;
}

int main(int argc, char** argv) {
  if (argc != 2)
    return 41;
  mode = strcmp(argv[1], "null") == 0            ? 1
      : strcmp(argv[1], "invalid") == 0          ? 3
      : strcmp(argv[1], "legacy") == 0           ? 4
      : strcmp(argv[1], "uc-stack-invalid") == 0 ? 5
      : strcmp(argv[1], "subset") == 0           ? 6
      : strcmp(argv[1], "legacy-guard") == 0     ? 7
      : strcmp(argv[1], "uc-stack-onstack") == 0 ? 8
      : strcmp(argv[1], "uc-stack-replace") == 0 ? 9
      : strcmp(argv[1], "xsave-unaligned") == 0  ? 10
                                                 : 2;
  if (mode == 7) {
    long page = sysconf(_SC_PAGESIZE);
    unsigned char* mapping = mmap(
        0,
        (size_t)page * 2,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);
    if (mapping == MAP_FAILED)
      return 48;
    if (mprotect(mapping + page, (size_t)page, PROT_NONE) != 0)
      return 49;
    // The 512-byte legacy image is 16-byte aligned but deliberately not
    // 64-byte aligned. Only 16 accessible bytes remain after it before the
    // guard page, so an erroneous extended-image read crosses the guard.
    guarded_legacy_fpstate = mapping + page - 512 - 16;
    if ((uintptr_t)guarded_legacy_fpstate % 16 != 0 ||
        (uintptr_t)guarded_legacy_fpstate % 64 == 0)
      return 50;
  }
  int altstack_mode = mode == 8 || mode == 9;
  if (altstack_mode) {
    stack_t stack = {
        .ss_sp = active_altstack,
        .ss_size = sizeof(active_altstack),
        .ss_flags = 0};
    if (sigaltstack(&stack, 0) != 0)
      return 51;
  }
  struct sigaction action = {0};
  action.sa_sigaction = handler;
  action.sa_flags = SA_SIGINFO | (altstack_mode ? SA_ONSTACK : 0);
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGUSR1, &action, 0) != 0)
    return 42;

  static const unsigned char original_xmm[16] = {
      0x10,
      0x11,
      0x12,
      0x13,
      0x14,
      0x15,
      0x16,
      0x17,
      0x18,
      0x19,
      0x1a,
      0x1b,
      0x1c,
      0x1d,
      0x1e,
      0x1f,
  };
  unsigned char restored_xmm[16];
  unsigned short control = 0x077f;
  unsigned short restored_control;
  unsigned int mxcsr = 0x3f80;
  unsigned int restored_mxcsr;
  __asm__ volatile("fldcw %0" : : "m"(control));
  __asm__ volatile("ldmxcsr %0" : : "m"(mxcsr));
  __asm__ volatile("movdqu %0, %%xmm15" : : "m"(original_xmm) : "xmm15");
  int result = kill(getpid(), SIGUSR1);
  __asm__ volatile("movdqu %%xmm15, %0" : "=m"(restored_xmm));
  __asm__ volatile("fnstcw %0" : "=m"(restored_control));
  __asm__ volatile("stmxcsr %0" : "=m"(restored_mxcsr));
  if (result != 0x5a)
    return 43;
  if (mode == 1) {
    static const unsigned char zero[16];
    if (memcmp(restored_xmm, zero, 16) != 0)
      return 44;
    if (restored_control != 0x037f)
      return 45;
    if (restored_mxcsr != 0x1f80)
      return 46;
  } else {
    unsigned char expected[16];
    for (unsigned i = 0; i < 16; ++i)
      expected[i] = (unsigned char)(0xa0 + i);
    if (memcmp(restored_xmm, expected, 16) != 0)
      return 47;
  }
  if (altstack_mode) {
    stack_t observed;
    if (sigaltstack(0, &observed) != 0)
      return 52;
    if (observed.ss_sp != active_altstack ||
        observed.ss_size != sizeof(active_altstack) || observed.ss_flags != 0)
      return 53;
  }
  return 0;
}
