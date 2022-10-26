/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// create `NTHREADS`, half doing blocking futex, half doing `SYS_exit`, while
// the thread group leader doing `SYS_exit_group`.
// This is to test `SYS_exit` and `SYS_exit_group` have below behavior:
//
//   - `SYS_exit` should exit the call thread *only*
//   - `SYS_exit_group` should exit all the threads in the same thread group
//
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define NTHREADS 8

struct thread_param {
  int* sem;
  long thread_id;
};

static int futex(
    int* uaddr,
    int futex_op,
    int val,
    const struct timespec* timeout,
    int* uaddr2,
    int val3) {
  return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr, val3);
}

// do `exit` syscall directly, avoid libc doing sth smart by replacing
// `_exit` with `exit_group`.
static void sys_exit(int code) {
  (void)syscall(SYS_exit, code);
}

static _Atomic unsigned long counter;

// do futex wait with timeout 600s. 600s is to make sure it can timeout
// on sandcastle default configuration.
void* thread_pfn(void* param) {
  struct thread_param* tp = (struct thread_param*)param;
  struct timespec ts = {600, 0};

  atomic_fetch_add(&counter, 1);
  if (tp->thread_id % 2 == 0) {
    futex(tp->sem, FUTEX_PRIVATE_FLAG | FUTEX_WAIT, 0, &ts, NULL, 0);
  } else {
    sys_exit(0);
  }
  return NULL;
}

#define SECRET_PARAM "__my_secret_param"
int main(int argc, char* argv[], char* envp[]) {
  if (argc == 2 && strcmp(argv[1], SECRET_PARAM) == 0) {
    // Guest mode: do the test.
    void* page = mmap(
        NULL,
        0x1000,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);
    if (page == (void*)-1) {
      fprintf(stderr, "mmap failed: %s\n", strerror(errno));
      exit(1);
    }
    struct thread_param params[NTHREADS];
    pthread_t threads[NTHREADS];
    for (int i = 0; i < NTHREADS; i++) {
      params[i].sem = (int*)page;
      params[i].thread_id = (long)i;

      if (pthread_create(&threads[i], NULL, thread_pfn, (void*)&params[i]) !=
          0) {
        fprintf(
            stderr,
            "pthread_create to create thread #%d failed: %s\n",
            i,
            strerror(errno));
        abort();
      }
    }

    struct timespec tp = {1, 0};
    clock_nanosleep(CLOCK_MONOTONIC, 0, &tp, NULL);

    long nb = atomic_load(&counter);

    fprintf(stderr, "Heard from %ld threads before killing them.\n", nb);
    fwrite(&nb, sizeof(nb), 1, stdout);
    fflush(stdout);
    // do SYS_exit_group. All threads should be still blocked by mutex.
    // SYS_exit_group should force all threads begin to exit.
    syscall(SYS_exit_group, 0);
  } else {
    // Host mode: as test runner, run guest and check output.
    char command[PATH_MAX] =
        {
            0,
        },
         program_path[PATH_MAX] = {
             0,
         };

    char* prog = realpath(argv[0], program_path);
    snprintf(command, PATH_MAX, "%s %s", prog, SECRET_PARAM);
    FILE* output = popen(command, "r");
    if (!output) {
      fprintf(
          stderr, "failed to run `%s`, error: %s\n", command, strerror(errno));
      exit(1);
    }

    long val = 0;
    size_t nb = fread(&val, sizeof(val), 1, output);
    if (nb != 1 || val != NTHREADS) {
      fprintf(
          stderr,
          "expecting %s output to be value %ld, got %ld\n",
          command,
          (long)NTHREADS,
          val);
      exit(1);
    }
    fprintf(stderr, "Success.\n");
    pclose(output);
  }
  return 0;
}
