/*
 * Copyright (c) 2020-, Facebook, Inc. and its affiliates.
 *
 *  All rights reserved.
 */

// create `NTHREADS`, all doing blocking or non blocking syscall in a tight
// loop, while the thread group leader calling `SYS_exit_group`. This is to test
// while `SYS_exit_group` is called, the remaining threads can exit gracefully.
//
// NB: When running this program under a ptracer, due to doing syscalls in a
// tight loop, the syscall (`sched_yield`) might return
//
//   - interrupted, by ptrace event exit
//   - interrupted, by the real exit (WEXITED)
//   - unavailable, waitpid returned ECHILD (_yes_, strace has this state)
//   - returns normally even `exit_group` started in another thread, but
//   subsequent waitpid
//     should still indicate the thread (doing sched_yield) is exiting.
// while blocking syscalls (`futex`) most likely would get interrupted (by exit
// or event exit)
//
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define NTESTS 100
#define NTHREADS 16

struct thread_param {
  pthread_mutex_t* mutex;
  _Atomic unsigned long* counter;
  int thread_id;
};

// Call `sched_yield` repeatly, which should always return 0 on Linux.
// we use `sched_yield` to simulate various outcomes when our main thread
// calls `exit_group`.
static inline void forever_yield(struct thread_param* param) {
  while (1) {
    sched_yield();
  }
}

// call pthread_mutex_lock(), the lock should have been held by the thread
// group leader, hence this should translate to a futex syscall which would
// never return.
static inline void forever_block(struct thread_param* param) {
  pthread_mutex_lock(param->mutex);
}

static void* thread_pfn(void* param) {
  struct thread_param* p = (struct thread_param*)param;

  atomic_fetch_add(p->counter, 1);

  if (p->thread_id % 2 == 0) {
    forever_yield(p);
  } else {
    forever_block(p);
  }

  return NULL;
}

static __attribute__((noreturn)) void test_exit_group() {
  struct thread_param param;
  _Atomic unsigned long counter = 0;
  pthread_t threads[NTHREADS];
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

  param.counter = &counter;
  param.mutex = &mutex;

  for (int i = 0; i < NTHREADS; i++) {
    param.thread_id = i;
    if (pthread_create(&threads[i], NULL, thread_pfn, (void*)&param) != 0) {
      fprintf(
          stderr,
          "pthread_create to create thread #%d failed: %s\n",
          i,
          strerror(errno));
      abort();
    }
  }

  // Spin while we wait for the threads to finish initializing.
  while (atomic_load(&counter) != NTHREADS) {
    // Yield so that other threads have a chance to run.
    sched_yield();
  }

  // do SYS_exit_group. All threads should be still blocked by mutex.
  // SYS_exit_group should force all threads begin to exit.
  syscall(SYS_exit_group, 0);

  // should not reach here!
  abort();
}

static int test_exit_group_helper(void) {
  pid_t pid = fork();

  if (pid < 0) {
    perror("fork");
    return -1;
  } else if (pid > 0) {
    int status;
    pid_t child_pid;

    if ((child_pid = waitpid(-1, &status, 0)) < 0) {
      perror("waitpid");
      return -1;
    } else {
      if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        pid_t child;
        status = 0;
        // The second waitpid with WNOHANG should return ECHILD only. meaning
        // all children has exited in previous waitpid without WNOHANG.
        if ((child = waitpid(-1, &status, WNOHANG)) != -1 && errno != ECHILD) {
          fprintf(
              stderr,
              "Second waitpid should return ECHILD, but returned %d with status 0x%x, errno: %d\n",
              child,
              status,
              errno);
          return -2;
        } else {
          return 0;
        }
      } else {
        fprintf(stderr, "waitpid returned unknown status: 0x%x\n", status);
        return -1;
      }
    }
  } else {
    test_exit_group();
  }
}

unsigned long time_getus(void) {
  struct timespec tp = {
      0,
  };

  clock_gettime(CLOCK_MONOTONIC, &tp);

  return tp.tv_sec * 1000000 + tp.tv_nsec / 1000;
}

int main(int argc, char* argv[], char* envp[]) {
  long i, ntests = NTESTS;
  unsigned long begin, elapsed;

  if (argc == 2) {
    ntests = strtol(argv[1], NULL, 0);
  }

  if (ntests <= 0) {
    ntests = 1;
  }

  long increment = (99 + ntests) / 100, curr = increment;

  begin = time_getus();

  for (i = 0; i < ntests; i++) {
    if (test_exit_group_helper() < 0) {
      fprintf(stdout, "stress test failed at %ld/%ld\n", 1 + i, ntests);
      exit(1);
    } else {
      if (i >= curr) {
        fputs(".", stdout);
        fflush(stdout);
        curr += increment;
      }
    }
  }
  elapsed = time_getus() - begin;

  printf("  passed %ld tests\n", ntests);
  printf(
      "time elapsed: %.3lf secs, time/test: %ld milli secs.\n",
      elapsed * 1.0 / 1000000,
      elapsed / 1000 / ntests);
  return 0;
}
