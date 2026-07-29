#include <stdint.h>
#include <string.h>

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

int main(void) {
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
  raw_exit_group(raw_getpid() == 424242 ? 0 : 1);
}
