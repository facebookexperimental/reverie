#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    return 9;
  }
  FILE *file = fopen(argv[1], "w");
  if (file == NULL) {
    return 10;
  }
  fprintf(file, "%ld\n", (long)getpid());
  if (fclose(file) != 0) {
    return 11;
  }
  for (;;) {
    pause();
  }
}
