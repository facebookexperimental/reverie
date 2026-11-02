/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Shared file views in an address space with several threads
 * (https://github.com/rrnewton/reverie/issues/1108). Two worker threads start
 * first; then, by argv[1]:
 * - "use": the main thread maps a MAP_SHARED read-write view of a file; each
 *   worker stores its own byte through the view and, after a barrier, reads
 *   every worker's byte back; the main thread checks the file with pread.
 *   Then, with the workers alive, it unmaps the view and maps a new view of
 *   the file, and the workers use the new view the same way.
 * - "mprotect": the main thread maps the view and makes it PROT_READ; a
 *   worker's gettimeofday(2) into the view then fails with EFAULT and stores
 *   nothing. The call is made with syscall(2): the kernel's put_user checks
 *   that the page is writable, where a vDSO store would fault instead. (A
 *   read(2) into the view would not do: KVM's copy-out stores into a
 *   read-only page, https://github.com/rrnewton/reverie/issues/1239.)
 * - "fork": the main thread maps the view, stores a byte and forks while the
 *   workers live; the child reads the byte and exits 0.
 * - "futex": a worker waits with FUTEX_WAIT_PRIVATE on a word in a private
 *   page; the main thread maps a view over that page with MAP_FIXED, stores 1
 *   through it and wakes the word's address with FUTEX_WAKE_PRIVATE. Linux
 *   keys a private futex by address alone, so the wake reaches the waiter,
 *   which then reads the view.
 * - "leader-exit": the main thread exits with pthread_exit while it holds
 *   the view and the workers live; a worker joins it, which returns once the
 *   exit clears the main thread's TID word, prints a line and exits 0.
 * - "fork-leader-exit": with no workers yet, the main thread maps the view
 *   and forks; the child creates a worker and its main thread exits with
 *   pthread_exit; the worker joins it, which again needs the exit to clear
 *   the TID word, prints a line and exits 0; the parent waits for the child.
 * Every step prints one line.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { PAGE = 4096, WORKERS = 2 };

#define REQUIRE(condition, step)                                               \
  do {                                                                        \
    if (!(condition)) {                                                       \
      fprintf(stderr, "%s failed errno=%d\n", step, errno);                    \
      _exit(1);                                                               \
    }                                                                         \
  } while (0)

static const char path[] = "shared-file-threads.data";
static const char *mode;
static pthread_barrier_t barrier;
static unsigned char *volatile view;
static unsigned int *volatile word;
static pthread_t main_thread;

static unsigned char mark(int round, long worker) {
  return (unsigned char)('a' + round * WORKERS + worker);
}

static void wait_all(void) {
  int rc = pthread_barrier_wait(&barrier);
  REQUIRE(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD, "pthread_barrier_wait");
}

static void *worker(void *argument) {
  long index = (long)argument;
  wait_all(); /* the first view is mapped */
  if (strcmp(mode, "use") == 0) {
    for (int round = 0; round < 2; round++) {
      view[index] = mark(round, index);
      wait_all(); /* every worker stored */
      for (long other = 0; other < WORKERS; other++) {
        REQUIRE(view[other] == mark(round, other), "a worker's read of the view");
      }
      wait_all(); /* every worker read */
      if (round == 0) {
        wait_all(); /* the view is mapped again */
      }
    }
  } else if (strcmp(mode, "mprotect") == 0) {
    wait_all(); /* the view is read-only */
    if (index == 0) {
      errno = 0;
      long result = syscall(SYS_gettimeofday, (void *)view, NULL);
      REQUIRE(result == -1 && errno == EFAULT, "gettimeofday into the read-only view");
      for (int offset = 0; offset < 16; offset++) {
        REQUIRE(view[offset] == 0, "the read-only view's bytes");
      }
    }
    wait_all(); /* the call is done */
  } else if (strcmp(mode, "futex") == 0) {
    if (index == 0) {
      while (__atomic_load_n(word, __ATOMIC_ACQUIRE) == 0) {
        long result = syscall(SYS_futex, word, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
        REQUIRE(result == 0 || errno == EAGAIN || errno == EINTR, "FUTEX_WAIT");
      }
    }
    wait_all(); /* the waiter woke */
  } else if (strcmp(mode, "leader-exit") == 0) {
    if (index == 0) {
      REQUIRE(pthread_join(main_thread, NULL) == 0, "joining the main thread");
      printf("a worker joined the main thread after it exited\n");
      fflush(stdout);
      exit(0);
    }
  } else {
    wait_all(); /* the child was forked and reaped */
  }
  return NULL;
}

static void *join_main_thread(void *argument) {
  (void)argument;
  REQUIRE(pthread_join(main_thread, NULL) == 0, "joining the child's main thread");
  printf("the child's worker joined the child's main thread after it exited\n");
  fflush(stdout);
  exit(0);
}

/* Mode "fork-leader-exit": the child's main thread exits beside a worker. */
static int fork_leader_exit(int fd) {
  view = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  REQUIRE(view != MAP_FAILED, "mmap before the fork");
  printf("mapped a shared view, then forked\n");
  fflush(stdout);
  pid_t child = fork();
  REQUIRE(child >= 0, "fork");
  if (child == 0) {
    main_thread = pthread_self();
    pthread_t thread;
    REQUIRE(pthread_create(&thread, NULL, join_main_thread, NULL) == 0,
            "pthread_create in the child");
    pthread_exit(NULL);
  }
  int status = 0;
  REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
              WEXITSTATUS(status) == 0,
          "the child");
  printf("the child exited 0\n");
  return 0;
}

int main(int argc, char **argv) {
  REQUIRE(argc == 2, "usage");
  mode = argv[1];
  int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  REQUIRE(fd >= 0 && ftruncate(fd, PAGE) == 0, "the file");
  if (strcmp(mode, "fork-leader-exit") == 0) {
    return fork_leader_exit(fd);
  }
  REQUIRE(pthread_barrier_init(&barrier, NULL, WORKERS + 1) == 0, "pthread_barrier_init");
  word = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(word != MAP_FAILED, "the futex word's page");
  main_thread = pthread_self();
  pthread_t threads[WORKERS];
  for (long index = 0; index < WORKERS; index++) {
    REQUIRE(pthread_create(&threads[index], NULL, worker, (void *)index) == 0,
            "pthread_create");
  }
  view = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  REQUIRE(view != MAP_FAILED, "mmap with threads alive");
  printf("mapped a shared view with %d threads alive\n", WORKERS);
  fflush(stdout);
  wait_all();
  if (strcmp(mode, "use") == 0) {
    for (int round = 0; round < 2; round++) {
      wait_all();
      wait_all();
      unsigned char bytes[WORKERS];
      REQUIRE(pread(fd, bytes, WORKERS, 0) == WORKERS, "pread");
      for (long index = 0; index < WORKERS; index++) {
        REQUIRE(bytes[index] == mark(round, index), "the file's bytes");
      }
      printf("round %d: the file holds every thread's store, and every thread read them all\n",
             round);
      if (round == 0) {
        REQUIRE(munmap(view, PAGE) == 0, "munmap with threads alive");
        view = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        REQUIRE(view != MAP_FAILED, "a new mmap with threads alive");
        printf("unmapped the view and mapped it again with threads alive\n");
        wait_all();
      }
    }
  } else if (strcmp(mode, "mprotect") == 0) {
    REQUIRE(mprotect(view, PAGE, PROT_READ) == 0, "mprotect with threads alive");
    wait_all();
    wait_all();
    printf("a thread's gettimeofday into the read-only view failed with EFAULT\n");
  } else if (strcmp(mode, "fork") == 0) {
    view[0] = 'f';
    fflush(stdout);
    /* Let the workers reach their next barrier wait first. A run that ends
     * while a worker is entering a host futex wait can miss that worker's
     * cancellation on KVM (https://github.com/rrnewton/reverie/issues/1238). */
    struct timespec settle = {0, 100 * 1000 * 1000};
    REQUIRE(nanosleep(&settle, NULL) == 0, "nanosleep");
    pid_t child = fork();
    REQUIRE(child >= 0, "fork");
    if (child == 0) {
      _exit(view[0] == 'f' ? 0 : 3);
    }
    int status = 0;
    REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                WEXITSTATUS(status) == 0,
            "the child");
    printf("the forked child read the view\n");
    wait_all();
  } else if (strcmp(mode, "futex") == 0) {
    /* Let worker 0 block in its FUTEX_WAIT first. */
    struct timespec settle = {0, 100 * 1000 * 1000};
    REQUIRE(nanosleep(&settle, NULL) == 0, "nanosleep");
    void *over = mmap((void *)word, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    REQUIRE(over == (void *)word, "a view over a waiting thread's futex word");
    printf("mapped a view over a waiting thread's futex word\n");
    __atomic_store_n(word, 1, __ATOMIC_RELEASE);
    REQUIRE(syscall(SYS_futex, word, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0) >= 0, "FUTEX_WAKE");
    wait_all();
    printf("the waiter woke and read 1 through the view\n");
  } else if (strcmp(mode, "leader-exit") == 0) {
    /* With a worker alive, the exit stores zero to this thread's TID word
     * and wakes it, which ends the worker's join (Linux's mm_release). */
    pthread_exit(NULL);
  } else {
    REQUIRE(0, "the mode");
  }
  for (long index = 0; index < WORKERS; index++) {
    REQUIRE(pthread_join(threads[index], NULL) == 0, "pthread_join");
  }
  printf("threads joined\n");
  return 0;
}
