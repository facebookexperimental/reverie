#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) ((sizeof(x)) / sizeof((x)[0]))
#endif

#define NR_THREADS 5

static _Atomic unsigned int threads_started;

static pthread_cond_t conds[NR_THREADS] = {
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
};

static pthread_mutex_t mutexes[NR_THREADS] = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
};

void* thread_entry(void* param) {
  long id = (long)param;

  printf("this is thread #%lu\n", id);

  pthread_mutex_lock(&mutexes[0]);

  atomic_fetch_add(&threads_started, 1);
  pthread_cond_wait(&conds[0], &mutexes[0]);

  pthread_mutex_unlock(&mutexes[0]);

  printf("%lu exited.\n", id);

  return 0;
}

int main(int argc, char* argv[]) {
  pthread_t ids[NR_THREADS];
  struct timespec tp = {0, 100000000};

  for (long i = 0; i < NR_THREADS; i++) {
    pthread_create(&ids[i], NULL, thread_entry, (void*)i);
  }

  while (atomic_load(&threads_started) != NR_THREADS)
    ;

  nanosleep(&tp, NULL);

  pthread_cond_broadcast(&conds[0]);

  for (int i = 0; i < NR_THREADS; i++) {
    pthread_join(ids[i], NULL);
  }

  for (int i = 0; i < NR_THREADS; i++) {
    pthread_cond_destroy(&conds[i]);
  }

  return 0;
}
