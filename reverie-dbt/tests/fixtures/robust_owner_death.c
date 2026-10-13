/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* A robust mutex whose owner dies is marked owner-dead, so the next lock
 * returns EOWNERDEAD. glibc writes the owner word from its pthread struct's
 * TID word, and Linux marks the word only if it names the dying thread's TID.
 *
 * 1. fork_child: a forked child's main thread locks a process-shared mutex
 *    and calls _exit (exit_group).
 * 2. thread: a thread locks a private mutex and exits (exit).
 * 3. exit_group_thread: a forked child's second thread locks a process-shared
 *    mutex and stays alive while the child's main thread calls _exit, so
 *    exit_group kills the owner.
 * 4. waited_thread: a thread locks a private mutex and exits only once the
 *    main thread is asleep in pthread_mutex_lock on it (glibc has set
 *    FUTEX_WAITERS in the owner word), so the owner's death must also wake
 *    that sleeper.
 * 5. exec_child: a forked child locks a process-shared mutex and execs.
 * 6. exec_killed_thread: a forked child's second thread holds a
 *    process-shared mutex while the child's main thread execs, which kills
 *    the holder.
 * 7. failed_exec: in a forked child, the main thread and a second thread each
 *    hold a mutex while the main thread's exec fails; both unlocks must still
 *    succeed afterwards.
 * 8. sigkill: a forked child locks a process-shared mutex and is SIGKILLed.
 *    Printed as the later lock's result rather than checked, because DBT does
 *    not mark this case yet
 *    (https://github.com/rrnewton/hermit/issues/4239).
 * 9. walk_stop: a thread registers its own two-entry robust list, whose first
 *    entry has a misaligned owner word and whose second names the thread's
 *    TID, and exits. Linux stops the walk at the misaligned word, so the
 *    second word must keep the thread's TID: neither marked nor rewritten.
 *    The same list without the misaligned entry is marked (Claude re-check of
 *    https://github.com/rrnewton/reverie/pull/1020).
 *
 * Each later lock in cases 1 to 3, 5, 6 and 8 waits at most one second:
 * ETIMEDOUT means the owner's death was missed. Case 4 blocks; a missed wake
 * hangs it until the test's timeout. */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t* make_mutex(int shared) {
  pthread_mutex_t* mutex = mmap(
      NULL,
      sizeof(*mutex),
      PROT_READ | PROT_WRITE,
      (shared ? MAP_SHARED : MAP_PRIVATE) | MAP_ANONYMOUS,
      -1,
      0);
  pthread_mutexattr_t attributes;
  if (mutex == MAP_FAILED || pthread_mutexattr_init(&attributes) != 0 ||
      pthread_mutexattr_setrobust(&attributes, PTHREAD_MUTEX_ROBUST) != 0 ||
      (shared &&
       pthread_mutexattr_setpshared(&attributes, PTHREAD_PROCESS_SHARED) !=
           0) ||
      pthread_mutex_init(mutex, &attributes) != 0) {
    perror("robust mutex");
    _exit(1);
  }
  return mutex;
}

static int lock_within_a_second(pthread_mutex_t* mutex) {
  struct timespec deadline;
  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec += 1;
  return pthread_mutex_timedlock(mutex, &deadline);
}

static pthread_mutex_t* thread_mutex;
static pthread_mutex_t* held_mutex;
static _Atomic int held;

static void* lock_and_exit(void* argument) {
  (void)argument;
  pthread_mutex_lock(thread_mutex);
  return NULL;
}

static pthread_mutex_t* waited_mutex;

static void* lock_and_exit_once_waited(void* argument) {
  (void)argument;
  pthread_mutex_lock(waited_mutex);
  atomic_store(&held, 1);
  while (!(__atomic_load_n(&waited_mutex->__data.__lock, __ATOMIC_SEQ_CST) &
           FUTEX_WAITERS))
    sched_yield();
  return NULL;
}

static void* lock_and_stay(void* argument) {
  (void)argument;
  pthread_mutex_lock(held_mutex);
  atomic_store(&held, 1);
  for (;;)
    pause();
  return NULL;
}

static _Atomic int unlock_now;

static void* lock_until_told(void* argument) {
  (void)argument;
  pthread_mutex_lock(held_mutex);
  atomic_store(&held, 1);
  while (!atomic_load(&unlock_now))
    sched_yield();
  return (void*)(long)pthread_mutex_unlock(held_mutex);
}

/* Runs `how` in a forked child holding a fresh process-shared mutex, then
 * returns the parent's later lock result. */
static int child_dies(int how) {
  held_mutex = make_mutex(1);
  atomic_store(&held, 0);
  pid_t child = fork();
  if (child == 0) {
    if (how == 6) {
      pthread_t holder;
      if (pthread_create(&holder, NULL, lock_and_stay, NULL) != 0)
        _exit(2);
      while (!atomic_load(&held))
        sched_yield();
    } else {
      pthread_mutex_lock(held_mutex);
    }
    if (how == 8)
      raise(SIGKILL);
    execl("/bin/true", "true", (char*)NULL);
    _exit(3);
  }
  if (child < 0 || waitpid(child, NULL, 0) != child) {
    perror("fork");
    _exit(1);
  }
  return lock_within_a_second(held_mutex);
}

static int failed_exec(void) {
  pid_t child = fork();
  if (child == 0) {
    pthread_mutex_t* mine = make_mutex(0);
    held_mutex = make_mutex(0);
    pthread_t holder;
    void* holder_unlock;
    pthread_mutex_lock(mine);
    if (pthread_create(&holder, NULL, lock_until_told, NULL) != 0)
      _exit(2);
    while (!atomic_load(&held))
      sched_yield();
    execl("/nonexistent/robust-owner-death", "missing", (char*)NULL);
    int own_unlock = pthread_mutex_unlock(mine);
    atomic_store(&unlock_now, 1);
    if (pthread_join(holder, &holder_unlock) != 0)
      _exit(2);
    _exit(own_unlock == 0 && holder_unlock == NULL ? 0 : 1);
  }
  int status;
  if (child < 0 || waitpid(child, &status, 0) != child) {
    perror("fork");
    _exit(1);
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

struct walk_list {
  struct walk_list* next;
};
struct walk_head {
  struct walk_list list;
  long futex_offset;
  struct walk_list* pending;
};

static _Alignas(64) unsigned char walk_buffer[256];
static struct walk_head walk_head;
static int walk_with_bad_entry;
static uint32_t* walk_word;
static pid_t walk_tid;

static void* walk_body(void* argument) {
  (void)argument;
  walk_tid = (pid_t)syscall(SYS_gettid);
  memset(walk_buffer, 0, sizeof(walk_buffer));
  walk_head.futex_offset = 8;
  walk_head.pending = NULL;
  /* Entry 2's owner word is at walk_buffer + 72, aligned. */
  struct walk_list* second = (struct walk_list*)(walk_buffer + 64);
  walk_word = (uint32_t*)(walk_buffer + 72);
  *walk_word = (uint32_t)walk_tid;
  second->next = &walk_head.list;
  if (walk_with_bad_entry) {
    /* Entry 1's owner word is at walk_buffer + 10, misaligned. */
    struct walk_list* first = (struct walk_list*)(walk_buffer + 2);
    memcpy(first, &second, sizeof(second));
    walk_head.list.next = first;
  } else {
    walk_head.list.next = second;
  }
  syscall(SYS_set_robust_list, &walk_head, sizeof(walk_head));
  syscall(SYS_exit, 0);
  return NULL;
}

/* Returns the second owner word after the thread exits, through `owner_died`
 * and `tid_kept`. */
static void walk_run(int bad, int* owner_died, int* tid_kept) {
  pthread_t thread;
  walk_with_bad_entry = bad;
  if (pthread_create(&thread, NULL, walk_body, NULL) != 0 ||
      pthread_join(thread, NULL) != 0) {
    perror("walk thread");
    _exit(1);
  }
  uint32_t word = __atomic_load_n(walk_word, __ATOMIC_SEQ_CST);
  *owner_died = (word & FUTEX_OWNER_DIED) != 0;
  *tid_kept = (word & FUTEX_TID_MASK) == (uint32_t)walk_tid;
}

static int walk_stops_at_a_misaligned_word(void) {
  int control_died, control_kept, died, kept;
  walk_run(0, &control_died, &control_kept);
  walk_run(1, &died, &kept);
  return control_died && !control_kept && !died && kept;
}

static const char* lock_result_name(int result) {
  return result == EOWNERDEAD ? "EOWNERDEAD"
      : result == ETIMEDOUT   ? "ETIMEDOUT"
                              : "other";
}

int main(void) {
  pthread_mutex_t* forked_mutex = make_mutex(1);
  pid_t child = fork();
  if (child == 0) {
    pthread_mutex_lock(forked_mutex);
    _exit(0);
  }
  if (child < 0 || waitpid(child, NULL, 0) != child) {
    perror("fork");
    return 1;
  }
  int fork_child = lock_within_a_second(forked_mutex);

  thread_mutex = make_mutex(0);
  pthread_t thread;
  if (pthread_create(&thread, NULL, lock_and_exit, NULL) != 0 ||
      pthread_join(thread, NULL) != 0) {
    perror("thread");
    return 1;
  }
  int exited_thread = lock_within_a_second(thread_mutex);

  held_mutex = make_mutex(1);
  child = fork();
  if (child == 0) {
    pthread_t holder;
    if (pthread_create(&holder, NULL, lock_and_stay, NULL) != 0)
      _exit(2);
    while (!atomic_load(&held))
      sched_yield();
    _exit(0);
  }
  if (child < 0 || waitpid(child, NULL, 0) != child) {
    perror("fork");
    return 1;
  }
  int exit_group_thread = lock_within_a_second(held_mutex);

  waited_mutex = make_mutex(0);
  atomic_store(&held, 0);
  if (pthread_create(&thread, NULL, lock_and_exit_once_waited, NULL) != 0) {
    perror("thread");
    return 1;
  }
  while (!atomic_load(&held))
    sched_yield();
  int waited_thread = pthread_mutex_lock(waited_mutex);
  pthread_join(thread, NULL);

  int exec_child = child_dies(5);
  int exec_killed_thread = child_dies(6);
  atomic_store(&held, 0);
  int failed = failed_exec();
  int sigkill = child_dies(8);
  int walk_stop = walk_stops_at_a_misaligned_word();

  printf(
      "robust fork_child=%d thread=%d exit_group_thread=%d waited_thread=%d "
      "exec_child=%d exec_killed_thread=%d failed_exec=%d sigkill=%s "
      "walk_stop=%d\n",
      fork_child == EOWNERDEAD,
      exited_thread == EOWNERDEAD,
      exit_group_thread == EOWNERDEAD,
      waited_thread == EOWNERDEAD,
      exec_child == EOWNERDEAD,
      exec_killed_thread == EOWNERDEAD,
      failed,
      lock_result_name(sigkill),
      walk_stop);
  return fork_child == EOWNERDEAD && exited_thread == EOWNERDEAD &&
          exit_group_thread == EOWNERDEAD && waited_thread == EOWNERDEAD &&
          exec_child == EOWNERDEAD && exec_killed_thread == EOWNERDEAD &&
          failed && walk_stop
      ? 0
      : 1;
}
