/* Calls getppid with six arguments through a jump-rewritten site and through
 * a short site (the UD0 marker), and prints each answer's offset above the
 * plugin's ANSWERED, or NATIVE. */
#include <stdio.h>

long jump_getppid6(long, long, long, long, long, long);
long short_getppid6(long, long, long, long, long, long);

static void report(const char *label, long result) {
  const long answered = 1L << 30;
  if (result < answered)
    printf("%s=NATIVE ", label);
  else
    printf("%s=%ld ", label, result - answered);
}

int main(void) {
  report("jump", jump_getppid6(11, 12, 13, 14, 15, 16));
  report("marker", short_getppid6(11, 12, 13, 14, 15, 16));
  printf("\n");
  return 0;
}
