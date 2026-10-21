#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* One real process and an externally retained shared page, including exit127.
 * The provider RSP is post-prologue and is NEVER a first-Rust sample. */
extern char **environ;
uint64_t *generic_fixture_state;
static int getter_armed;
static int getter_active;
__attribute__((noinline)) char *getenv(const char *name) {
  if (!strcmp(name, "REVERIE_LITEINST_TOOL") && getter_armed) {
    uintptr_t rsp;
    __asm__ volatile("mov %%rsp,%0" : "=r"(rsp));
    ++generic_fixture_state[4];
    generic_fixture_state[5] = rsp;
    return getter_active ? (char *)"strace" : NULL;
  }
  size_t n = strlen(name);
  for (char **p = environ; p && *p; ++p)
    if (!strncmp(*p, name, n) && (*p)[n] == '=')
      return *p + n + 1;
  return NULL;
}

/* Slots2/3 count call attempts and genuine returns. Six callee-saved registers
 * are challenged; original caller registers are restored by this wrapper. */
void generic_fixture_call(void (*entry)(void));
__asm__(
    ".text\n.globl generic_fixture_call\n.type generic_fixture_call,@function\n"
    "generic_fixture_call:\n"
    "push %rbp\npush %rbx\npush %r12\npush %r13\npush %r14\npush %r15\nsub "
    "$8,%rsp\n"
    "mov %rdi,%r11\nmov generic_fixture_state(%rip),%rax\nincq 16(%rax)\n"
    "lea -8(%rsp),%rdx\nmov %rdx,56(%rax)\n"
    "mov $0x11223344,%ebx\nmov $0x22334455,%ebp\nmov $0x33445566,%r12d\n"
    "mov $0x44556677,%r13d\nmov $0x55667788,%r14d\nmov $0x66778899,%r15d\n"
    ".globl generic_bootstrap_call_site\ngeneric_bootstrap_call_site:\ncall "
    "*%r11\n"
    ".globl generic_bootstrap_return_site\ngeneric_bootstrap_return_site:\n"
    "mov generic_fixture_state(%rip),%rax\nincq 24(%rax)\nmov "
    "%rsp,64(%rax)\nxor %edx,%edx\n"
    "cmp $0x11223344,%rbx\nsete %cl\nmovzbl %cl,%ecx\nor %rcx,%rdx\n"
    "cmp $0x22334455,%rbp\nsete %cl\nmovzbl %cl,%ecx\nshl $1,%rcx\nor "
    "%rcx,%rdx\n"
    "cmp $0x33445566,%r12\nsete %cl\nmovzbl %cl,%ecx\nshl $2,%rcx\nor "
    "%rcx,%rdx\n"
    "cmp $0x44556677,%r13\nsete %cl\nmovzbl %cl,%ecx\nshl $3,%rcx\nor "
    "%rcx,%rdx\n"
    "cmp $0x55667788,%r14\nsete %cl\nmovzbl %cl,%ecx\nshl $4,%rcx\nor "
    "%rcx,%rdx\n"
    "cmp $0x66778899,%r15\nsete %cl\nmovzbl %cl,%ecx\nshl $5,%rcx\nor "
    "%rcx,%rdx\nmov %rdx,48(%rax)\n"
    "add $8,%rsp\npop %r15\npop %r14\npop %r13\npop %r12\npop %rbx\npop "
    "%rbp\nret\n"
    ".size generic_fixture_call,.-generic_fixture_call\n");

typedef int (*record_fn)(uint64_t *);
typedef int (*kernel_fn)(uint64_t *, size_t);
static int error(const char *why) {
  fprintf(stderr, "generic bootstrap setup: %s\n", why);
  return 2;
}
static void *owned(void *handle, const char *name, const char *path,
                   void *base) {
  void *fn = dlsym(handle, name);
  Dl_info info;
  return fn && dladdr(fn, &info) && !strcmp(info.dli_fname, path) &&
                 (!base || info.dli_fbase == base)
             ? fn
             : NULL;
}
static int prepare(int argc, char **argv) {
  if (argc != 5)
    return error("prepare CASE RUNTIME STATE");
  char *env[512];
  size_t used = 0;
  for (char **p = environ; p && *p; ++p) {
    if (!strncmp(*p, "LD_PRELOAD=", 11) ||
        !strncmp(*p, "REVERIE_LITEINST_TOOL=", 22) ||
        !strncmp(*p, "REVERIE_INGUEST_TOOL=", 21))
      continue;
    if (used == 500)
      return error("environment capacity");
    env[used++] = *p;
  }
  char preload[8192];
  int n = snprintf(preload, sizeof preload, "LD_PRELOAD=%s", argv[3]);
  if (n < 0 || (size_t)n >= sizeof preload)
    return error("preload capacity");
  env[used++] = preload;
  env[used] = NULL;
  char *child[] = {argv[0], (char *)"child", argv[2], argv[3], argv[4], NULL};
  execve(argv[0], child, env);
  return error("execve exact inert real leaf");
}
int main(int argc, char **argv) {
  if (argc >= 2 && !strcmp(argv[1], "prepare"))
    return prepare(argc, argv);
  if (argc != 5 || strcmp(argv[1], "child"))
    return error("child CASE RUNTIME STATE");
  if (strcmp(argv[2], "strace") && strcmp(argv[2], "none") &&
      strcmp(argv[2], "repeat") && strcmp(argv[2], "collision") &&
      strcmp(argv[2], "ordinary"))
    return error("finite case");
  int fd = open(argv[4], O_RDWR | O_CLOEXEC);
  if (fd < 0)
    return error("owned state file");
  generic_fixture_state =
      mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (generic_fixture_state == MAP_FAILED)
    return error("shared state mapping");
  uint64_t *s = generic_fixture_state;
  s[0] = 1;
  void *handle = dlopen(argv[3], RTLD_NOW | RTLD_NOLOAD);
  Dl_info info;
  void *entry =
      handle ? owned(handle, "reverie_liteinst_initialize", argv[3], NULL)
             : NULL;
  if (!entry || !dladdr(entry, &info))
    return error("actual public generic entry");
  s[9] = (uintptr_t)info.dli_fbase;
  s[10] = (uintptr_t)entry;
  s[11] = 1;
  record_fn constructor =
      (record_fn)owned(handle, "reverie_inguest_constructor_stack_query",
                       argv[3], info.dli_fbase);
  record_fn generic = (record_fn)owned(
      handle, "reverie_inguest_generic_stack_query", argv[3], info.dli_fbase);
  kernel_fn kernel =
      (kernel_fn)owned(handle, "m4_generic_query", argv[3], info.dli_fbase);
  if (!constructor || !generic || !kernel)
    return error("actual query owners");
  s[21] = (int64_t)constructor(s + 32);
  s[22] = (int64_t)generic(s + 48);
  if (kernel(s + 96, 81 * 8))
    return error("actual kernel query before");
  s[19] = s[104];
  if (!strcmp(argv[2], "collision")) {
    void *collision =
        mmap((void *)0x600000000000ULL, 4096, PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 4096);
    if (collision != (void *)0x600000000000ULL)
      return error("fresh fixed collision mapping");
    s[13] = (uintptr_t)collision;
    for (size_t i = 0; i < 4096; ++i)
      if (((unsigned char *)collision)[i] != 0xa5)
        return error("collision sentinel before");
    s[14] = 1;
  }
  if (!strcmp(argv[2], "ordinary")) {
    int (*reserve)(void) = owned(handle, "m4_generic_ordinary_owner_setup",
                                 argv[3], info.dli_fbase);
    if (!reserve || reserve())
      return error("actual ordinary reserve");
    s[18] = 1;
  }
  if (kernel(s + 96, 81 * 8))
    return error("actual pre-call kernel query");
  getter_active = !strcmp(argv[2], "strace") || !strcmp(argv[2], "collision") ||
                  !strcmp(argv[2], "ordinary");
  s[12] = getter_active;
  getter_armed = 1;
  s[1] = 1;
  generic_fixture_call(entry);
  s[23] = (int64_t)constructor(s + 64);
  s[24] = (int64_t)generic(s + 80);
  if (kernel(s + 177, 81 * 8))
    return error("actual kernel query after");
  if (!strcmp(argv[2], "repeat")) {
    getter_active = 1;
    s[12] = 1;
    generic_fixture_call(entry);
    s[16] = 1;
  }
  s[17] = 1;
  static const char returned[] = "generic bootstrap returned\n";
  if (write(STDOUT_FILENO, returned, sizeof returned - 1) !=
      (ssize_t)(sizeof returned - 1))
    return error("return marker write");
  return 0;
}
