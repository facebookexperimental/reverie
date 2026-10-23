/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Prints what a guest can see of its environment, then forks a child that
 * execs this program again by its path, and that child execs it once more
 * through /proc/self/exe; then forks a child that execs it with a NULL argv,
 * and one that execs it with a read-only argv whose argv[0] is
 * /proc/self/exe. Each image prints the same. Used by
 * tests/guest_environment_live.rs.
 *
 * Each line is prefixed with the image ("parent", "child", "grandchild",
 * "readonly", or "emptyargv" for the image started with no arguments):
 *   env <entry>      every entry of environ, in order;
 *   procenv <entry>  every non-empty NUL-separated entry of /proc/self/environ;
 *   execfn <path>    the string AT_EXECFN names, or for the grandchild only
 *                    whether it is non-empty: exec'd through a symlink, its
 *                    AT_EXECFN is the symlink natively and the resolved path
 *                    under DynamoRIO;
 *   execfn-on-stack  whether that string lies in the [stack] mapping, as the
 *                    kernel places it;
 *   failed-exec      the errno of an execve of a missing file whose only
 *                    environment entry is the AT_EXECFN string itself (the
 *                    parent only).
 * Together the procenv lines carry every non-NUL byte of /proc/self/environ.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int on_stack(const void *address) {
  FILE *maps = fopen("/proc/self/maps", "r");
  char line[512];
  int found = 0;
  if (maps == NULL)
    return -1;
  while (fgets(line, sizeof(line), maps) != NULL) {
    unsigned long start, end;
    if (strstr(line, "[stack]") != NULL &&
        sscanf(line, "%lx-%lx", &start, &end) == 2 &&
        (unsigned long)address >= start && (unsigned long)address < end)
      found = 1;
  }
  fclose(maps);
  return found;
}

int main(int argc, char **argv) {
  /* Linux gives an image exec'd with a NULL argv either no arguments or one
   * empty argument, depending on its version.
   */
  int emptyargv = argc == 0 || argv[0][0] == '\0';
  const char *image = emptyargv ? "emptyargv" : argc > 1 ? argv[1] : "parent";
  int grandchild = argc > 1 && strcmp(argv[1], "grandchild") == 0;
  static char buffer[1 << 16];
  size_t length = 0;
  int fd = open("/proc/self/environ", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    perror("open /proc/self/environ");
    return 2;
  }
  for (;;) {
    ssize_t n = read(fd, buffer + length, sizeof(buffer) - 1 - length);
    if (n < 0) {
      perror("read /proc/self/environ");
      return 2;
    }
    if (n == 0)
      break;
    length += (size_t)n;
  }
  close(fd);
  buffer[length] = '\0';

  for (char **entry = environ; *entry != NULL; ++entry)
    printf("%s env %s\n", image, *entry);
  for (size_t at = 0; at < length;) {
    const char *entry = buffer + at;
    size_t entry_length = 0;
    while (at + entry_length < length && entry[entry_length] != '\0')
      ++entry_length;
    if (entry_length > 0)
      printf("%s procenv %.*s\n", image, (int)entry_length, entry);
    at += entry_length + 1;
  }
  const char *execfn = (const char *)getauxval(AT_EXECFN);
  if (grandchild)
    printf("%s execfn %s\n", image,
           execfn != NULL && execfn[0] != '\0' ? "non-empty" : "empty");
  else
    printf("%s execfn %s\n", image, execfn == NULL ? "(none)" : execfn);
  printf("%s execfn-on-stack %d\n", image, on_stack(execfn));
  if (argc == 1 && !emptyargv) {
    char *missing[] = {argv[0], NULL};
    char *borrowed[] = {(char *)execfn, NULL};
    execve("/nonexistent/guest-environment", missing, borrowed);
    printf("%s failed-exec %s\n", image, errno == ENOENT ? "ENOENT" : "other");
  }
  fflush(stdout);

  if (argc > 1 && strcmp(argv[1], "child") == 0) {
    char *next[] = {argv[0], "grandchild", NULL};
    execve("/proc/self/exe", next, environ);
    perror("execve /proc/self/exe");
    return 2;
  }

  if (argc == 1 && !emptyargv) {
    pid_t pid = fork();
    if (pid < 0) {
      perror("fork");
      return 2;
    }
    if (pid == 0) {
      char *child[] = {argv[0], "child", NULL};
      execve(argv[0], child, environ);
      perror("execve");
      _exit(2);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
      fprintf(stderr, "child failed: status %d\n", status);
      return 2;
    }
    pid = fork();
    if (pid < 0) {
      perror("fork");
      return 2;
    }
    if (pid == 0) {
      /* glibc's execve() declares argv non-null; the kernel accepts NULL. */
      syscall(SYS_execve, argv[0], NULL, environ);
      perror("execve with a NULL argv");
      _exit(2);
    }
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
      fprintf(stderr, "emptyargv child failed: status %d\n", status);
      return 2;
    }
    pid = fork();
    if (pid < 0) {
      perror("fork");
      return 2;
    }
    if (pid == 0) {
      char **readonly = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (readonly == MAP_FAILED) {
        perror("mmap");
        _exit(2);
      }
      readonly[0] = "/proc/self/exe";
      readonly[1] = "readonly";
      readonly[2] = NULL;
      if (mprotect(readonly, 4096, PROT_READ) != 0) {
        perror("mprotect");
        _exit(2);
      }
      execve(argv[0], readonly, environ);
      perror("execve with a read-only argv");
      _exit(2);
    }
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
      fprintf(stderr, "readonly child failed: status %d\n", status);
      return 2;
    }
  }
  return 0;
}
