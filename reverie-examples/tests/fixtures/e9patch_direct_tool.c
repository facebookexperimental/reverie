#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

static int has_environment_entry(const char *expected) {
  for (char **entry = environ; *entry != 0; ++entry) {
    if (strcmp(*entry, expected) == 0) {
      return 1;
    }
  }
  return 0;
}

static long raw_getpid(void) {
  register long rax __asm__("rax") = 39;
  __asm__ volatile("syscall" : "+a"(rax) : : "rcx", "r11", "memory");
  return rax;
}

__attribute__((noreturn)) static void raw_exit_group(int status) {
  register long rax __asm__("rax") = 231;
  register long rdi __asm__("rdi") = status;
  __asm__ volatile("syscall" : "+a"(rax) : "D"(rdi) : "rcx", "r11", "memory");
  __builtin_unreachable();
}

static long raw_write(int fd, const void *buffer, unsigned long size) {
  register long rax __asm__("rax") = 1;
  register long rdi __asm__("rdi") = fd;
  register const void *rsi __asm__("rsi") = buffer;
  register unsigned long rdx __asm__("rdx") = size;
  __asm__ volatile("syscall"
                   : "+a"(rax)
                   : "D"(rdi), "S"(rsi), "d"(rdx)
                   : "rcx", "r11", "memory");
  return rax;
}

static void write_burst(void) {
  static char chunk[16384];
  memset(chunk, 'x', sizeof(chunk));
  for (int i = 0; i < 128; ++i) {
    if (raw_write(1, chunk, sizeof(chunk)) != sizeof(chunk) ||
        raw_write(2, chunk, sizeof(chunk)) != sizeof(chunk)) {
      raw_exit_group(3);
    }
  }
}

int main(void) {
  if (has_environment_entry("REVERIE_E9PATCH_EXPECT_PRESTART_RESIDUAL_FAIL=1")) {
    static const char byte = 'x';
    errno = 0;
    long result = write(1, &byte, 1);
    raw_exit_group(result == -1 && errno == EOPNOTSUPP ? 0 : 6);
  }
  if (has_environment_entry("REVERIE_E9PATCH_EXPECT_BOOTSTRAP_ENV=1")) {
    if (!has_environment_entry(
            "REVERIE_E9PATCH_COORDINATOR=preexisting-coordinator") ||
        !has_environment_entry(
            "REVERIE_E9PATCH_EXAMPLE_TOOL=preexisting-selector") ||
        !has_environment_entry(
            "REVERIE_E9PATCH_BOOTSTRAP_SENTINEL=two  spaces\tand-tab")) {
      raw_exit_group(2);
    }
  }
  if (has_environment_entry("REVERIE_E9PATCH_WRITE_BURST=1")) {
    write_burst();
  }
  if (has_environment_entry("REVERIE_E9PATCH_WRITE_MARKER=1")) {
    static const char marker[] = "e9patch-strace\n";
    if (raw_write(1, marker, sizeof(marker) - 1) != sizeof(marker) - 1) {
      raw_exit_group(4);
    }
  }
  if (has_environment_entry("REVERIE_E9PATCH_EXPECT_NATIVE_GETPID=1")) {
    long native_pid = getpid();
    raw_exit_group(raw_getpid() == native_pid ? 0 : 1);
  }
  if (has_environment_entry("REVERIE_E9PATCH_EXPECT_RAW_GETPID=1")) {
    raw_exit_group(raw_getpid() > 0 ? 0 : 1);
  }
  if (has_environment_entry("REVERIE_E9PATCH_EXPECT_RESIDUAL_WRITE_FAIL=1")) {
    static const char byte = 'x';
    (void)raw_getpid();
    errno = 0;
    long result = write(1, &byte, 1);
    raw_exit_group(result == -1 && errno == EOPNOTSUPP ? 0 : 5);
  }
  raw_exit_group(raw_getpid() == 424242 ? 0 : 1);
}
