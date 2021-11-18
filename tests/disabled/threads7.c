#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define assert(b) \
  if (!(b))       \
    abort();

#define NR_THREADS 8L

#define NSECS_PER_SEC 1000000000L
#define FIVE_SECONDS (5UL * NSECS_PER_SEC)

static int ts_printf(const char* fmt, ...) {
  va_list ap;
  struct timespec ts;
  char buf[8192];
  int n;

  clock_gettime(CLOCK_REALTIME, &ts);

  va_start(ap, fmt);
  n = snprintf(buf, 8192, "%lu.%06lu|", ts.tv_sec, ts.tv_nsec / 1000);
  if (n < 8192) {
    n += vsnprintf(buf + n, 8192 - n, fmt, ap);
  }
  va_end(ap);

  fputs(buf, stdout);

  return n;
}

static pid_t gettid(void) {
  return syscall(SYS_gettid, 0, 0, 0, 0, 0, 0);
}

static void thread_delay(unsigned long ns) {
  struct timespec req = {
      .tv_sec = ns / NSECS_PER_SEC,
      .tv_nsec = ns % NSECS_PER_SEC,
  };
  struct timespec rem;
  int ret;

  do {
    ret = nanosleep(&req, &rem);
    memcpy(&req, &rem, sizeof(req));
  } while (ret != 0 && errno == EINTR);
}

static void run_exec(long k) {
  ts_printf(
      "thread %lu pid %lu tid %lu ready to run exec.\n", k, getpid(), gettid());
  char* const args[] = {
      (char* const)"cat",
      (char* const)"/proc/self/stat",
      (char* const)NULL,
  };
  char* const envp[] = {
      (char* const)"PATH=/bin;/usr/bin",
      (char* const)"SHELL=/bin/bash",
      (char* const)NULL,
  };
  execvpe(args[0], args, envp);
  perror("exec");
  exit(1);
}

static void* threaded(void* param) {
  long k = (long)param;
  unsigned long delay = FIVE_SECONDS;

  if (k == 5) {
    delay = NSECS_PER_SEC;
  }

  ts_printf("thread %lu enter. pid=%u, tid=%u\n", k, getpid(), gettid());
  thread_delay(delay);
  if (k == 5) {
    ts_printf("thread %lu call fork.\n", k);

    pid_t pid = fork();

    assert(pid >= 0);

    if (pid > 0) {
      int status;
      ts_printf(
          "after fork, I'm parent pid = %u, child pid = %u, tid = %u\n",
          getpid(),
          pid,
          gettid());
      run_exec(k);
      waitpid(pid, &status, 0);
      ts_printf("parent pid = %u exit\n", getpid());
    } else {
      ts_printf(
          "after fork, I'm child pid = %u, parent = %u, tid = %u\n",
          getpid(),
          getppid(),
          gettid());
      thread_delay(NSECS_PER_SEC);
      ts_printf("child pid = %u exit\n", getpid());
    }
  }

  ts_printf("thread %lu exit. pid=%u, tid=%u\n", k, getpid(), gettid());

  return 0;
}

static void atfork_prepare(void) {
  ts_printf("pthread_atfork prepare.\n");
}

static void atfork_parent(void) {
  ts_printf(
      "pthread_atfork parent pid = %u, ppid = %u, tid = %u.\n",
      getpid(),
      getppid(),
      gettid());
}

static void atfork_child(void) {
  ts_printf(
      "pthread_atfork child pid = %u, ppid = %u, tid = %u.\n",
      getpid(),
      getppid(),
      gettid());
}

int main(int argc, char* argv[]) {
  pthread_attr_t attr;
  pthread_t threadid[NR_THREADS];

  assert(pthread_attr_init(&attr) == 0);

  pthread_atfork(atfork_prepare, atfork_parent, atfork_child);

  for (long i = 0; i < NR_THREADS; i++) {
    assert(pthread_create(&threadid[i], &attr, threaded, (void*)i) == 0);
  }

  for (long i = 0; i < NR_THREADS; i++) {
    assert(pthread_join(threadid[i], NULL) == 0);
  }

  assert(pthread_attr_destroy(&attr) == 0);

  return 0;
}
