#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#define NR_THREADS 2L
#define TIME_100MS 100000000UL

__attribute__((noinline)) void bkpt(void) {}

static void test_clock_nanosleep(unsigned long ns) {
  struct timespec req = {
      .tv_sec = 0,
      .tv_nsec = ns,
  };
  struct timespec rem;
  int ret;

  do {
    ret = clock_nanosleep(CLOCK_REALTIME, 0, &req, &rem);
    bkpt();
    memcpy(&req, &rem, sizeof(req));
  } while (ret != 0 && errno == EINTR);
}

static void* threaded(void* param) {
  long k = (long)param;

  printf("thread %ld enter.\n", k);

  test_clock_nanosleep(TIME_100MS);

  printf("thread %ld exit.\n", k);

  return 0;
}

int main(int argc, char* argv[]) {
  // sleep in a non-threpaded context
  test_clock_nanosleep(TIME_100MS);

  pthread_attr_t attr;
  pthread_t threadid[NR_THREADS];

  assert(pthread_attr_init(&attr) == 0);

  for (long i = 0; i < NR_THREADS; i++) {
    assert(pthread_create(&threadid[i], &attr, threaded, (void*)i) == 0);
  }

  for (long i = 0; i < NR_THREADS; i++) {
    assert(pthread_join(threadid[i], NULL) == 0);
  }

  assert(pthread_attr_destroy(&attr) == 0);

  return 0;
}
