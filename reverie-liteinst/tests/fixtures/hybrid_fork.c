#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 3 || prctl(PR_SET_NAME, argv[1], 0, 0, 0) != 0) {
    return 9;
  }
  FILE *pid_file = fopen(argv[2], "w");
  if (pid_file == NULL) {
    return 8;
  }
  fprintf(pid_file, "%ld\n", (long)getpid());
  if (fclose(pid_file) != 0) {
    return 7;
  }
  pid_t child = fork();
  if (child < 0) {
    return 10;
  }
  if (child == 0) {
    _exit(0);
  }
  int status = 0;
  return waitpid(child, &status, 0) == child ? 0 : 11;
}
