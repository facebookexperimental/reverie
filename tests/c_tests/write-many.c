#include <sys/types.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
  write(STDOUT_FILENO, "0", 1);
  write(STDOUT_FILENO, "1", 1);
  write(STDOUT_FILENO, "2", 1);
  write(STDOUT_FILENO, "3", 1);
  write(STDOUT_FILENO, "4", 1);
  write(STDOUT_FILENO, "5", 1);
  write(STDOUT_FILENO, "6", 1);
  write(STDOUT_FILENO, "7", 1);
  write(STDOUT_FILENO, "8", 1);
  write(STDOUT_FILENO, "9", 1);
  write(STDOUT_FILENO, "\n", 1);
}
