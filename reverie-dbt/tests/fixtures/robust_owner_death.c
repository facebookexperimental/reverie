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
 *    Printed as the later lock's result and checked by the Rust test, including
 *    the former translated-owner gap in
 *    https://github.com/rrnewton/hermit/issues/4239.
 * 9. walk_stop: a thread registers its own two-entry robust list, whose first
 *    entry has a misaligned owner word and whose second names the thread's
 *    TID, and exits. Linux stops the walk at the misaligned word, so the
 *    second word must keep the thread's TID: neither marked nor rewritten.
 *    The same list without the misaligned entry is marked (Claude re-check of
 *    https://github.com/rrnewton/reverie/pull/1020).
 * 10. tgid_exec: in a forked child, a second thread locks a process-shared
 *    mutex, sets its owner field to the thread group ID (as a hand-written
 *    lock may), and execs. de_thread gives that caller the thread group ID
 *    before Linux walks its list, so Linux marks the word
 *    (https://github.com/rrnewton/reverie/issues/1052).
 * 11. tgid_failed_exec: the same, but the exec fails, so the owner field must
 *    name the thread group ID again afterwards, as the guest left it.
 *
 * With ROBUST_OWNER_DEATH_FIRST set, the process instead runs one case as the
 * first thing it does, so that its worker is the first thread it creates. In
 * a fresh PID namespace this also checks the process whose kernel PID is one.
 * The worker's TID must remain distinct from its process ID. Each case prints
 * id_overlap: whether the two IDs were equal.
 * - failed-exec: the worker locks a mutex of its own (the owner field names
 *   its TID) and its exec fails: the field must be unchanged and the unlock
 *   must succeed.
 * - exec: a forked child waits on a process-shared mutex that the worker
 *   locks before it execs this program again. de_thread gives the worker the
 *   thread group ID before Linux walks its list, so Linux leaves a word
 *   naming the worker's old TID alone, and the child's lock times out. Once
 *   the new image has told the child (through an inherited pipe) that the
 *   exec is complete, the word must still be unmarked and must not name the
 *   thread group's host ID (the child's host parent ID, from /proc):
 *   rewriting the worker's TID and then that output as the group's virtual
 *   ID would have Linux mark it.
 *
 * Each later lock in cases 1 to 3, 5, 6, 8 and 10 waits at most one second:
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
#include <stdlib.h>
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

static void* lock_as_group_and_exec(void* argument) {
  (void)argument;
  pthread_mutex_lock(held_mutex);
  _Atomic uint32_t* word = (_Atomic uint32_t*)&held_mutex->__data.__lock;
  uint32_t value = atomic_load(word);
  while (!atomic_compare_exchange_strong(
      word, &value, (value & ~FUTEX_TID_MASK) | (uint32_t)getpid())) {
  }
  execl("/bin/true", "true", (char*)NULL);
  _exit(3);
  return NULL;
}

static void* lock_as_group_and_fail_exec(void* argument) {
  (void)argument;
  pthread_mutex_t* mine = make_mutex(0);
  pthread_mutex_lock(mine);
  _Atomic uint32_t* word = (_Atomic uint32_t*)&mine->__data.__lock;
  uint32_t value = atomic_load(word);
  uint32_t as_group = (value & ~FUTEX_TID_MASK) | (uint32_t)getpid();
  while (!atomic_compare_exchange_strong(word, &value, as_group)) {
    as_group = (value & ~FUTEX_TID_MASK) | (uint32_t)getpid();
  }
  execl("/nonexistent/robust-owner-death", "missing", (char*)NULL);
  _exit(atomic_load(word) == as_group ? 0 : 1);
  return NULL;
}

/* A field ("Pid" or "PPid") of the calling thread's /proc status, which
 * holds host IDs. */
static int host_status_id(const char* field) {
  int id = -1;
  char format[16];
  snprintf(format, sizeof(format), "%s: %%d", field);
  FILE* status = fopen("/proc/thread-self/status", "r");
  if (status != NULL) {
    char line[256];
    while (fgets(line, sizeof(line), status) != NULL) {
      if (strncmp(line, field, strlen(field)) == 0 && line[strlen(field)] == ':')
        sscanf(line, format, &id);
    }
    fclose(status);
  }
  return id;
}

/* Whether the calling thread's host TID equals the process's virtual PID. */
static int id_overlap(void) {
  return host_status_id("Pid") == getpid();
}

static const char* self_path;
static _Atomic int* first_locked;
static _Atomic int* first_waiter_ready;
static char first_exec_done_fd[16];

static void* first_failed_exec(void* argument) {
  (void)argument;
  int overlap = id_overlap();
  pthread_mutex_t* mine = make_mutex(0);
  pthread_mutex_lock(mine);
  _Atomic uint32_t* word = (_Atomic uint32_t*)&mine->__data.__lock;
  uint32_t before = atomic_load(word);
  execl("/nonexistent/robust-owner-death", "missing", (char*)NULL);
  int kept = atomic_load(word) == before &&
      (before & FUTEX_TID_MASK) == (uint32_t)syscall(SYS_gettid);
  int unlocked = pthread_mutex_unlock(mine) == 0;
  printf(
      "robust first_failed_exec=%d id_overlap=%d\n", kept && unlocked, overlap);
  fflush(stdout);
  _exit(kept && unlocked ? 0 : 1);
  return NULL;
}

static void* first_exec(void* argument) {
  (void)argument;
  int overlap = id_overlap();
  pthread_mutex_lock(held_mutex);
  atomic_store(first_locked, 1);
  while (!atomic_load(first_waiter_ready))
    sched_yield();
  execl(
      self_path,
      self_path,
      "after-exec",
      overlap ? "1" : "0",
      first_exec_done_fd,
      (char*)NULL);
  _exit(3);
  return NULL;
}

static int run_first(const char* which) {
  pthread_t worker;
  if (strcmp(which, "failed-exec") == 0) {
    if (pthread_create(&worker, NULL, first_failed_exec, NULL) != 0)
      return 2;
    pthread_join(worker, NULL);
    return 1;
  }
  if (strcmp(which, "exec") != 0)
    return 2;
  held_mutex = make_mutex(1);
  _Atomic int* flags = mmap(
      NULL,
      2 * sizeof(*flags),
      PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_ANONYMOUS,
      -1,
      0);
  if (flags == MAP_FAILED)
    return 2;
  first_locked = &flags[0];
  first_waiter_ready = &flags[1];
  int done[2];
  if (pipe(done) != 0)
    return 2;
  snprintf(first_exec_done_fd, sizeof(first_exec_done_fd), "%d", done[1]);
  // The worker is created first, so that it is the process's first thread.
  if (pthread_create(&worker, NULL, first_exec, NULL) != 0)
    return 2;
  while (!atomic_load(first_locked))
    sched_yield();
  pid_t waiter = fork();
  if (waiter == 0) {
    uint32_t host_group = (uint32_t)host_status_id("PPid");
    close(done[1]);
    atomic_store(first_waiter_ready, 1);
    int result = lock_within_a_second(held_mutex);
    char byte;
    if (read(done[0], &byte, 1) != 1)
      _exit(2);
    uint32_t word =
        __atomic_load_n(&held_mutex->__data.__lock, __ATOMIC_SEQ_CST);
    if (result == EOWNERDEAD || (word & FUTEX_OWNER_DIED) != 0)
      _exit(1);
    if ((word & FUTEX_TID_MASK) == host_group)
      _exit(3);
    _exit(result == ETIMEDOUT ? 0 : 2);
  }
  if (waiter < 0)
    return 2;
  for (;;)
    pause();
}

/* The image first_exec execs: tell the waiter the exec is complete, then
 * report what it found. */
static int after_first_exec(const char* overlap, const char* done_fd) {
  if (write(atoi(done_fd), "x", 1) != 1)
    return 2;
  int status;
  if (wait(&status) < 0)
    return 2;
  int code = WIFEXITED(status) ? WEXITSTATUS(status) : 2;
  printf(
      "robust first_exec=%s id_overlap=%s\n",
      code == 0       ? "ETIMEDOUT"
          : code == 1 ? "EOWNERDEAD"
          : code == 3 ? "the-word-names-the-host-group"
                      : "other",
      overlap);
  return code == 0 ? 0 : 1;
}

static int tgid_failed_exec(void) {
  pid_t child = fork();
  if (child == 0) {
    pthread_t caller;
    if (pthread_create(&caller, NULL, lock_as_group_and_fail_exec, NULL) != 0)
      _exit(2);
    for (;;)
      pause();
  }
  int status;
  if (child < 0 || waitpid(child, &status, 0) != child) {
    perror("fork");
    _exit(1);
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* Runs `how` in a forked child holding a fresh process-shared mutex, then
 * returns the parent's later lock result. */
static int child_dies(int how) {
  held_mutex = make_mutex(1);
  atomic_store(&held, 0);
  pid_t child = fork();
  if (child == 0) {
    if (how == 10) {
      pthread_t caller;
      if (pthread_create(&caller, NULL, lock_as_group_and_exec, NULL) != 0)
        _exit(2);
      for (;;)
        pause();
    }
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

int main(int argc, char** argv) {
  self_path = argv[0];
  if (argc == 4 && strcmp(argv[1], "after-exec") == 0)
    return after_first_exec(argv[2], argv[3]);
  const char* first = getenv("ROBUST_OWNER_DEATH_FIRST");
  if (first != NULL)
    return run_first(first);
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
  int tgid_exec = child_dies(10);
  int tgid_failed = tgid_failed_exec();

  printf(
      "robust fork_child=%d thread=%d exit_group_thread=%d waited_thread=%d "
      "exec_child=%d exec_killed_thread=%d failed_exec=%d sigkill=%s "
      "walk_stop=%d tgid_exec=%d tgid_failed_exec=%d\n",
      fork_child == EOWNERDEAD,
      exited_thread == EOWNERDEAD,
      exit_group_thread == EOWNERDEAD,
      waited_thread == EOWNERDEAD,
      exec_child == EOWNERDEAD,
      exec_killed_thread == EOWNERDEAD,
      failed,
      lock_result_name(sigkill),
      walk_stop,
      tgid_exec == EOWNERDEAD,
      tgid_failed);
  return fork_child == EOWNERDEAD && exited_thread == EOWNERDEAD &&
          exit_group_thread == EOWNERDEAD && waited_thread == EOWNERDEAD &&
          exec_child == EOWNERDEAD && exec_killed_thread == EOWNERDEAD &&
          failed && walk_stop && tgid_exec == EOWNERDEAD && tgid_failed
      ? 0
      : 1;
}
