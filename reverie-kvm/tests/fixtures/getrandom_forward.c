#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>

/* One line per getrandom(2) call: its result, its errno, and what it did to
 * the buffer. A caller compares the whole output with a native run's, so
 * every line must be a function of Linux's semantics alone, never of the
 * random bytes themselves. */

#define SENTINEL 0xa5

static void report(const char* name, long result, int error, const char* buffer) {
  printf("%s result=%ld errno=%d buffer=%s\n", name, result, error, buffer);
}

/* Fill `length` bytes of `buffer` (with `slack` sentinel bytes after them) by
 * getrandom and report whether exactly the returned count was written: the
 * bytes past the result keep the sentinel, and the bytes up to it do not
 * all keep it (a 1 in 2^(8*16) chance at the smallest count used here). */
static void fill(const char* name, unsigned char* buffer, size_t length, size_t slack, unsigned flags) {
  memset(buffer, SENTINEL, length + slack);
  errno = 0;
  long result = syscall(SYS_getrandom, buffer, length, flags);
  int error = errno;
  size_t written = result > 0 ? (size_t)result : 0;
  int tail_kept = 1, head_changed = written == 0;
  for (size_t i = written; i < length + slack; ++i)
    tail_kept &= buffer[i] == SENTINEL;
  for (size_t i = 0; i < written; ++i)
    head_changed |= buffer[i] != SENTINEL;
  report(name, result, error, tail_kept && head_changed ? "exact" : "WRONG");
}

static void call(const char* name, void* address, size_t length, unsigned flags) {
  errno = 0;
  long result = syscall(SYS_getrandom, address, length, flags);
  report(name, result, errno, "-");
}

/* For a Tool that answers getrandom itself: print the whole buffer, so a
 * caller can check that the guest sees exactly the Tool's bytes and result. */
static int decided(void) {
  unsigned char buffer[64];
  memset(buffer, SENTINEL, sizeof(buffer));
  errno = 0;
  long result = syscall(SYS_getrandom, buffer, sizeof(buffer), 0);
  printf("decided result=%ld errno=%d bytes=", result, errno);
  for (size_t i = 0; i < sizeof(buffer); ++i)
    printf("%02x", buffer[i]);
  printf("\n");
  errno = 0;
  result = syscall(SYS_getrandom, buffer, 0, GRND_NONBLOCK);
  printf("decided_zero result=%ld errno=%d\n", result, errno);
  return 0;
}

int main(int argc, char** argv) {
  if (argc == 2 && strcmp(argv[1], "decided") == 0)
    return decided();
  long page = sysconf(_SC_PAGESIZE);
  unsigned char buffer[4096 + 64];
  fill("plain", buffer, 4096, 64, 0);
  fill("nonblock", buffer, 16, 64, GRND_NONBLOCK);
  fill("random", buffer, 16, 64, GRND_RANDOM | GRND_NONBLOCK);
  fill("insecure", buffer, 16, 64, GRND_INSECURE);
  fill("zero", buffer, 0, 64, 0);
  fill("zero_nonblock", buffer, 0, 64, GRND_NONBLOCK);
  call("zero_null", NULL, 0, 0);
  /* Linux validates the flags before it looks at the buffer. */
  fill("unknown_flag", buffer, 16, 64, 0x80);
  fill("random_and_insecure", buffer, 16, 64, GRND_RANDOM | GRND_INSECURE);
  call("unknown_flag_bad_buffer", (void*)8, 16, 0x80);

  /* A readable page that is not writable, and a writable page whose end
   * runs into it: Linux stores the writable prefix and returns its length,
   * or fails with EFAULT when no byte could be stored. */
  unsigned char* pages = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (pages == MAP_FAILED)
    return 90;
  memset(pages, SENTINEL, 2 * page);
  if (mprotect(pages + page, page, PROT_READ) != 0)
    return 91;
  call("read_only", pages + page, 16, 0);
  call("read_only_nonblock", pages + page, 16, GRND_NONBLOCK);
  call("straddle_small", pages + page - 8, 32, 0);
  call("straddle_large", pages + page - 100, 4096, 0);
  for (long i = 0; i < page; ++i)
    if (pages[page + i] != SENTINEL)
      return 92;
  int straddle_written = 0;
  for (long i = page - 100; i < page; ++i)
    straddle_written += pages[i] != SENTINEL;
  printf("read_only_page_kept=1 straddle_prefix_changed=%d\n", straddle_written > 0);
  call("null", NULL, 16, 0);
  call("kernel_address", (void*)0xffff800000000000ul, 16, 0);
  call("kernel_address_zero", (void*)0xffff800000000000ul, 0, 0);
  return 0;
}
