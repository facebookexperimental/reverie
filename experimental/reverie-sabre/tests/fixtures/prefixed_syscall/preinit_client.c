/* Prints PREINIT from its own .preinit_array function, then MAIN. */
#include <stdio.h>
#include <unistd.h>

static void preinit(int argc, char **argv, char **envp) {
  (void)argc;
  (void)argv;
  (void)envp;
  (void)!write(STDOUT_FILENO, "PREINIT\n", 8);
}

__attribute__((section(".preinit_array"), used)) static void (*preinit_entry)(
    int, char **, char **) = preinit;

int main(void) {
  puts("MAIN");
  return 0;
}
