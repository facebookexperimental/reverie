#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(expression)                                                      \
  do {                                                                         \
    if (!(expression)) {                                                       \
      fprintf(stderr, "failure line=%d errno=%d\n", __LINE__, errno);            \
      exit(93);                                                                \
    }                                                                          \
  } while (0)

static const uint64_t upper_words[] = {
    0, UINT64_C(1) << 32, UINT64_C(1) << 63, UINT64_C(0xffffffff00000000)};
static const char base_marker[] = "BASE\n";
static const char target_marker[] = "TARGET\n";
static const char decoy_marker[] = "DECOY\n";

struct observation {
  long result;
  int error;
};

static void child_path(char *output, const char *parent, const char *child) {
  int length = snprintf(output, PATH_MAX, "%s/%s", parent, child);
  CHECK(length > 0 && length < PATH_MAX);
}

static void write_marker(const char *path, const char *bytes, size_t length) {
  int file = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
  CHECK(file >= 0);
  CHECK(write(file, bytes, length) == (ssize_t)length);
  CHECK(close(file) == 0);
}

static size_t read_file_at(int directory, const char *path, unsigned char *output,
                           size_t capacity) {
  int file = openat(directory, path, O_RDONLY);
  CHECK(file >= 0);
  size_t length = 0;
  for (;;) {
    CHECK(length < capacity);
    ssize_t count = read(file, output + length, capacity - length);
    CHECK(count >= 0);
    if (count == 0)
      break;
    length += (size_t)count;
  }
  CHECK(close(file) == 0);
  return length;
}

static void check_cwd(const char *expected) {
  char actual[PATH_MAX];
  CHECK(getcwd(actual, sizeof(actual)) != NULL);
  CHECK(strcmp(actual, expected) == 0);
}

static void check_state(const char *cwd, const char *marker, size_t length) {
  check_cwd(cwd);
  unsigned char contents[32];
  CHECK(read_file_at(AT_FDCWD, "marker", contents, sizeof(contents)) == length);
  CHECK(memcmp(contents, marker, length) == 0);
}

static struct observation observe(uint32_t low, uint64_t upper, int unused,
                                  int expected_error) {
  // fchdir has exactly one argument. These intentionally invalid pointer-like
  // values in the other five syscall registers must never be dereferenced.
  const uint64_t poison[] = {UINT64_MAX, UINT64_C(1) << 63,
                             UINT64_C(0xffff800000000000),
                             UINT64_C(0x0000800000000000),
                             UINT64_C(0xdeadbeefdeadbeef)};
  errno = 0;
  long result = syscall(SYS_fchdir, upper | low, unused ? poison[0] : 0,
                        unused ? poison[1] : 0, unused ? poison[2] : 0,
                        unused ? poison[3] : 0, unused ? poison[4] : 0);
  int error = errno;
  if (result != (expected_error == 0 ? 0 : -1) || error != expected_error) {
    fprintf(stderr, "fd=%016lx unused=%d result=%ld errno=%d expected_errno=%d\n",
            (unsigned long)(upper | low), unused, result, error, expected_error);
    exit(93);
  }
  return (struct observation){result, error};
}

static void record(const char *object, uint64_t upper, int unused,
                   struct observation observed, const char *state) {
  printf("fchdir object=%s upper=%016lx unused=%d result=%ld errno=%d state=%s\n",
         object, (unsigned long)upper, unused, observed.result, observed.error,
         state);
}

static void restore_base(int saved, const char *base) {
  CHECK(fchdir(saved) == 0);
  check_state(base, base_marker, sizeof(base_marker) - 1);
}

static void positive(const char *object, unsigned variant, uint64_t upper,
                     int unused, int saved, const char *base) {
  check_state(base, base_marker, sizeof(base_marker) - 1);
  CHECK(mkdir("original", 0700) == 0);
  write_marker("original/marker", target_marker, sizeof(target_marker) - 1);
  int directory = open("original", O_RDONLY | O_DIRECTORY);
  CHECK(directory >= 0);
  int alias = dup(directory);
  CHECK(alias >= 0 && dup2(directory, 257) == 257);

  // Use ordinary descriptor arguments for the supporting syscalls: this test
  // varies only fchdir's argument width. All aliases share a nonzero cursor.
  unsigned char entries[4096];
  CHECK(syscall(SYS_getdents64, directory, entries, sizeof(entries)) > 0);
  off_t cursor = lseek(directory, 0, SEEK_CUR);
  CHECK(cursor > 0);
  CHECK(lseek(alias, 0, SEEK_CUR) == cursor);
  CHECK(lseek(257, 0, SEEK_CUR) == cursor);

  CHECK(rename("original", "moved") == 0);
  CHECK(mkdir("original", 0700) == 0);
  write_marker("original/marker", decoy_marker, sizeof(decoy_marker) - 1);
  char moved[PATH_MAX];
  child_path(moved, base, "moved");
  const int descriptors[] = {directory, alias, 257};
  struct observation observed =
      observe((uint32_t)descriptors[variant], upper, unused, 0);
  check_state(moved, target_marker, sizeof(target_marker) - 1);
  CHECK(lseek(directory, 0, SEEK_CUR) == cursor);
  CHECK(lseek(alias, 0, SEEK_CUR) == cursor);
  CHECK(lseek(257, 0, SEEK_CUR) == cursor);

  CHECK(close(directory) == 0 && close(alias) == 0 && close(257) == 0);
  // The cwd must own its directory independently of every source descriptor.
  check_state(moved, target_marker, sizeof(target_marker) - 1);
  record(object, upper, unused, observed, "target");
  restore_base(saved, base);
  CHECK(unlink("moved/marker") == 0 && rmdir("moved") == 0);
  CHECK(unlink("original/marker") == 0 && rmdir("original") == 0);
}

static void negative(const char *object, unsigned variant, uint64_t upper,
                     int unused, int saved, const char *base) {
  check_state(base, base_marker, sizeof(base_marker) - 1);
  int file = -1;
  uint32_t low;
  switch (variant) {
  case 0: {
    // Allocate/close only after baseline inspection, so no intermediate open
    // can accidentally reuse the stale descriptor before the tested syscall.
    int closed = dup(saved);
    CHECK(closed >= 0 && close(closed) == 0);
    low = (uint32_t)closed;
    break;
  }
  case 1:
    file = open("marker", O_RDONLY);
    CHECK(file >= 0);
    low = (uint32_t)file;
    break;
  case 2:
    low = INT32_MAX;
    break;
  case 3:
    low = UINT32_C(0x80000000);
    break;
  case 4:
    low = UINT32_MAX;
    break;
  default:
    low = (uint32_t)AT_FDCWD;
    break;
  }
  struct observation observed =
      observe(low, upper, unused, variant == 1 ? ENOTDIR : EBADF);
  check_state(base, base_marker, sizeof(base_marker) - 1);
  if (file >= 0)
    CHECK(close(file) == 0);
  record(object, upper, unused, observed, "base");
}

static void policy(const char *object, int proc, uint64_t upper, int unused,
                   int guest, int saved, const char *base) {
  check_state(base, base_marker, sizeof(base_marker) - 1);
  int directory = open(proc ? "/proc" : "policy-target",
                       O_DIRECTORY | (proc ? O_RDONLY : O_PATH));
  CHECK(directory >= 0);
  unsigned char expected_version[4096];
  size_t version_size = 0;
  if (proc && !guest)
    version_size = read_file_at(directory, "version", expected_version,
                                sizeof(expected_version));
  struct observation observed = observe((uint32_t)directory, upper, unused,
                                        guest ? (proc ? EACCES : EBADF) : 0);
  CHECK(close(directory) == 0);
  const char *state;
  if (guest) {
    check_state(base, base_marker, sizeof(base_marker) - 1);
    state = "base";
  } else if (proc) {
    check_cwd("/proc");
    unsigned char actual_version[4096];
    CHECK(version_size > 0);
    CHECK(read_file_at(AT_FDCWD, "version", actual_version,
                       sizeof(actual_version)) == version_size);
    CHECK(memcmp(actual_version, expected_version, version_size) == 0);
    state = "proc";
  } else {
    char target[PATH_MAX];
    child_path(target, base, "policy-target");
    check_state(target, target_marker, sizeof(target_marker) - 1);
    state = "target";
  }
  record(object, upper, unused, observed, state);
  restore_base(saved, base);
}

int main(int argc, char **argv) {
  CHECK(argc == 2);
  CHECK(strcmp(argv[1], "native") == 0 || strcmp(argv[1], "guest") == 0);
  int guest = strcmp(argv[1], "guest") == 0;
  char base[PATH_MAX];
  int saved = open(".", O_RDONLY | O_DIRECTORY);
  CHECK(saved > 0);
  // Establish the canonical cwd before capturing expectations: the initial
  // guest context may spell TMPDIR through a symlink, whereas fchdir resolves
  // the directory handle. Keep every later cwd and content comparison exact.
  CHECK(fchdir(saved) == 0);
  CHECK(getcwd(base, sizeof(base)) != NULL);
  write_marker("marker", base_marker, sizeof(base_marker) - 1);
  // Clearing bit 31 of INT_MIN would resolve to this live directory and must
  // be detected as incorrect success, rather than another EBADF by accident.
  CHECK(dup2(saved, STDIN_FILENO) == STDIN_FILENO);

  const char *positive_names[] = {"directory", "dup", "fd257"};
  for (unsigned object = 0; object < 3; ++object)
    for (size_t upper = 0; upper < 4; ++upper)
      for (int unused = 0; unused < 2; ++unused)
        positive(positive_names[object], object, upper_words[upper], unused,
                  saved, base);

  const char *negative_names[] = {"closed", "regular-file", "int-max",
                                  "int-min", "minus-one", "at-fdcwd"};
  for (unsigned object = 0; object < 6; ++object)
    for (size_t upper = 0; upper < 4; ++upper)
      for (int unused = 0; unused < 2; ++unused)
        negative(negative_names[object], object, upper_words[upper], unused,
                  saved, base);

  CHECK(mkdir("policy-target", 0700) == 0);
  write_marker("policy-target/marker", target_marker, sizeof(target_marker) - 1);
  puts("policy");
  const char *policy_names[] = {"opath-directory", "proc-root"};
  for (int object = 0; object < 2; ++object)
    for (size_t upper = 0; upper < 4; ++upper)
      for (int unused = 0; unused < 2; ++unused)
        policy(policy_names[object], object, upper_words[upper], unused, guest,
                saved, base);
  CHECK(unlink("policy-target/marker") == 0 && rmdir("policy-target") == 0);
  CHECK(unlink("marker") == 0);
  CHECK(close(STDIN_FILENO) == 0 && close(saved) == 0);
  return 0;
}
