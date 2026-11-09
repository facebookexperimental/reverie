/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* A fork's child reads every page of private memory as its parent did at the
 * fork, and shares a MAP_SHARED file mapping with it afterwards (fork(2)).
 *
 * Before the fork the parent writes private pages of every kind: a data page
 * written in full, a page written with zeros, a page it never wrote, a heap
 * buffer written in part, a run that may be backed by huge pages written in
 * full with sparse bytes after it, and a buffer the kernel writes for it with
 * read(2). It also maps a file MAP_SHARED, as glibc maps its iconv module
 * cache under a UTF-8 locale, writes through it, unmaps it, and maps private
 * anonymous memory at the same address, where it writes one page of two: on
 * KVM those two pages keep a backing of their own after the shared view
 * goes. Three more pages go the same way, all written, and then a view over
 * the first of them alone goes too: on KVM that page takes a backing of its
 * own, and the other two are a run of the first backing that starts one page
 * into it. A second file stays mapped MAP_SHARED through the fork.
 *
 * The child checks every page. Then the parent changes a private page and
 * stores one byte through the shared mapping, the child stores another, and
 * a third process writes a third byte to the file itself: both mappings show
 * all three, and the child still reads the parent's private page as it was
 * at the fork. Last, the parent execs this program while the shared mapping
 * is still mapped, and the new image forks and checks again: on KVM the
 * exec leaves the retired view's pages with a backing of their own.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

enum { PAGE = 4096, HUGE = 2 * 1024 * 1024 };

#define REQUIRE(condition, step)                                               \
  do {                                                                        \
    if (!(condition)) {                                                       \
      fprintf(stderr, "%s failed errno=%d\n", step, errno);                    \
      _exit(1);                                                               \
    }                                                                         \
  } while (0)

static unsigned char data_page[PAGE] __attribute__((aligned(PAGE)));
static unsigned char zeros_written[PAGE] __attribute__((aligned(PAGE)));
static unsigned char never_written[PAGE] __attribute__((aligned(PAGE)));
static unsigned char kernel_written[PAGE] __attribute__((aligned(PAGE)));
static const char kernel_message[] = "written by the kernel for the guest";

/* The private pages a fork must copy. */
struct pages {
  unsigned char *heap;
  unsigned char *huge;
  unsigned char *separate;
  unsigned char *run;
};

static unsigned char pattern(size_t index, unsigned seed) {
  return (unsigned char)((index * 31 + seed) % 251 + 1);
}

/* Writes every kind of private page. */
static void write_pages(struct pages *pages) {
  for (size_t i = 0; i < PAGE; i++) {
    data_page[i] = pattern(i, 1);
  }
  memset(zeros_written, 0, PAGE);
  int pipe_fds[2];
  REQUIRE(pipe(pipe_fds) == 0, "pipe");
  REQUIRE(write(pipe_fds[1], kernel_message, sizeof(kernel_message)) ==
              (ssize_t)sizeof(kernel_message),
          "write message");
  REQUIRE(read(pipe_fds[0], kernel_written + 100, sizeof(kernel_message)) ==
              (ssize_t)sizeof(kernel_message),
          "read into the buffer");
  REQUIRE(close(pipe_fds[0]) == 0 && close(pipe_fds[1]) == 0, "close pipe");
  pages->heap = malloc(16 * PAGE);
  REQUIRE(pages->heap != NULL, "malloc");
  memset(pages->heap, 0, 16 * PAGE);
  for (size_t i = 0; i < 16 * PAGE; i += 3 * PAGE + 17) {
    pages->heap[i] = pattern(i, 2);
  }
  pages->huge = mmap(NULL, 2 * HUGE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(pages->huge != MAP_FAILED, "mmap huge");
  madvise(pages->huge, 2 * HUGE, MADV_HUGEPAGE);
  for (size_t i = 0; i < HUGE; i++) {
    pages->huge[i] = pattern(i, 3);
  }
  for (size_t i = HUGE; i < 2 * HUGE; i += 64 * PAGE + 9) {
    pages->huge[i] = pattern(i, 4);
  }
  /* A shared view that goes, and private memory where it was. */
  int fd = open("fork-copies-every-page.view", O_RDWR | O_CREAT | O_TRUNC, 0600);
  REQUIRE(fd >= 0, "open view file");
  REQUIRE(ftruncate(fd, 2 * PAGE) == 0, "size view file");
  unsigned char *view =
      mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  REQUIRE(view != MAP_FAILED, "mmap view");
  memset(view, 'v', 2 * PAGE);
  REQUIRE(munmap(view, 2 * PAGE) == 0, "munmap view");
  REQUIRE(close(fd) == 0, "close view file");
  pages->separate =
      mmap(view, 2 * PAGE, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  REQUIRE(pages->separate == view, "mmap where the view was");
  for (size_t i = 0; i < PAGE; i++) {
    pages->separate[i] = pattern(i, 5);
  }
  /* Three pages that keep one backing of their own after their view goes, as
   * above, all written; then a second view over the first page alone, which
   * goes too: on KVM the first page takes a backing of its own, and the other
   * two are a run of the first backing that starts one page into it. */
  fd = open("fork-copies-every-page.run", O_RDWR | O_CREAT | O_TRUNC, 0600);
  REQUIRE(fd >= 0, "open run file");
  REQUIRE(ftruncate(fd, 3 * PAGE) == 0, "size run file");
  unsigned char *run =
      mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  REQUIRE(run != MAP_FAILED, "mmap run view");
  memset(run, 'r', 3 * PAGE);
  REQUIRE(munmap(run, 3 * PAGE) == 0, "munmap run view");
  pages->run = mmap(run, 3 * PAGE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  REQUIRE(pages->run == run, "mmap where the run view was");
  for (size_t i = 0; i < 3 * PAGE; i++) {
    pages->run[i] = pattern(i, 6 + i / PAGE);
  }
  REQUIRE(mmap(run, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
               0) == run,
          "mmap a view over the first run page");
  REQUIRE(munmap(run, PAGE) == 0, "munmap the first run page's view");
  REQUIRE(mmap(run, PAGE, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1,
               0) == run,
          "mmap the first run page again");
  for (size_t i = 0; i < PAGE; i++) {
    pages->run[i] = pattern(i, 9);
  }
  REQUIRE(close(fd) == 0, "close run file");
}

/* The first byte of the pages that differ from what write_pages wrote, or
 * -1 when every page reads as written. */
static long first_difference(const struct pages *pages) {
  for (size_t i = 0; i < PAGE; i++) {
    if (data_page[i] != pattern(i, 1)) return 1;
    if (zeros_written[i] != 0) return 2;
    if (never_written[i] != 0) return 3;
  }
  if (memcmp(kernel_written + 100, kernel_message, sizeof(kernel_message)) != 0) {
    return 4;
  }
  for (size_t i = 0; i < 16 * PAGE; i++) {
    unsigned char expected = i % (3 * PAGE + 17) == 0 ? pattern(i, 2) : 0;
    if (pages->heap[i] != expected) return 5;
  }
  for (size_t i = 0; i < 2 * HUGE; i++) {
    unsigned char expected = i < HUGE ? pattern(i, 3)
                             : (i - HUGE) % (64 * PAGE + 9) == 0 ? pattern(i, 4)
                                                                 : 0;
    if (pages->huge[i] != expected) return 6;
  }
  for (size_t i = 0; i < 2 * PAGE; i++) {
    unsigned char expected = i < PAGE ? pattern(i, 5) : 0;
    if (pages->separate[i] != expected) return 7;
  }
  for (size_t i = 0; i < 3 * PAGE; i++) {
    unsigned char expected = i < PAGE ? pattern(i, 9) : pattern(i, 6 + i / PAGE);
    if (pages->run[i] != expected) return 8;
  }
  return -1;
}

static void write_byte(int fd, char byte) {
  REQUIRE(write(fd, &byte, 1) == 1, "write pipe");
}

static void read_byte(int fd) {
  char byte;
  REQUIRE(read(fd, &byte, 1) == 1, "read pipe");
}

static int wait_exit(pid_t child) {
  int status;
  REQUIRE(waitpid(child, &status, 0) == child, "waitpid");
  return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

/* The image the first one execs while its shared mapping is mapped. */
static int after_exec(void) {
  struct pages pages;
  write_pages(&pages);
  fflush(stdout);
  pid_t child = fork();
  REQUIRE(child >= 0, "fork after exec");
  if (child == 0) {
    long difference = first_difference(&pages);
    if (difference < 0) {
      printf("after exec: child: every page ok\n");
    } else {
      printf("after exec: child: kind %ld differs\n", difference);
    }
    return 0;
  }
  printf("after exec: parent: child exit %d\n", wait_exit(child));
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "after-exec") == 0) {
    return after_exec();
  }
  REQUIRE(argc == 1, "usage");
  struct pages pages;
  write_pages(&pages);
  int fd = open("fork-copies-every-page.data", O_RDWR | O_CREAT | O_TRUNC, 0600);
  REQUIRE(fd >= 0, "open shared file");
  REQUIRE(ftruncate(fd, PAGE) == 0, "size shared file");
  volatile unsigned char *shared =
      mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  REQUIRE(shared != MAP_FAILED, "mmap shared file");
  memset((void *)shared, '.', PAGE);
  int to_child[2];
  int to_parent[2];
  REQUIRE(pipe(to_child) == 0 && pipe(to_parent) == 0, "pipes");
  fflush(stdout);
  pid_t child = fork();
  REQUIRE(child >= 0, "fork");
  if (child == 0) {
    long difference = first_difference(&pages);
    if (difference < 0) {
      printf("child: every page ok\n");
    } else {
      printf("child: kind %ld differs\n", difference);
    }
    fflush(stdout);
    /* The parent has changed its data page and stored 'P'. */
    read_byte(to_child[0]);
    shared[1] = 'C';
    write_byte(to_parent[1], 'c');
    /* Another process has written 'O' to the file. */
    read_byte(to_child[0]);
    printf("child: shared %c%c%c, private page %s\n", shared[0], shared[1],
           shared[2], data_page[0] == pattern(0, 1) ? "kept" : "changed");
    return 0;
  }
  data_page[0] = 'X';
  shared[0] = 'P';
  write_byte(to_child[1], 'p');
  read_byte(to_parent[0]);
  pid_t other = fork();
  REQUIRE(other >= 0, "fork other");
  if (other == 0) {
    REQUIRE(pwrite(fd, "O", 1, 2) == 1, "pwrite");
    _exit(0);
  }
  REQUIRE(wait_exit(other) == 0, "other");
  write_byte(to_child[1], 'o');
  int status = wait_exit(child);
  char file_bytes[3];
  REQUIRE(pread(fd, file_bytes, 3, 0) == 3, "pread");
  printf("parent: child exit %d, shared %c%c%c, file %.3s\n", status, shared[0],
         shared[1], shared[2], file_bytes);
  fflush(stdout);
  /* Exec with the shared mapping still mapped. */
  char *exec_argv[] = {argv[0], "after-exec", NULL};
  execve(argv[0], exec_argv, environ);
  REQUIRE(0, "execve");
  return 1;
}
