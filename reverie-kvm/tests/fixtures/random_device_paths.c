#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <unistd.h>

enum open_call { USE_OPEN, USE_OPENAT };

static const char* call_name(enum open_call call) {
  return call == USE_OPEN ? "open" : "openat";
}

/* Cast every variadic argument, including pointers, to the x86-64 syscall ABI.
 */
static long
open_path(enum open_call call, long dirfd, const char* path, long flags) {
  if (call == USE_OPEN)
    return syscall(SYS_open, (long)path, flags, 0600L);
  return syscall(SYS_openat, dirfd, (long)path, flags, 0600L);
}

static int failure(const char* expression, int line) {
  fprintf(stderr, "line=%d check=%s errno=%d\n", line, expression, errno);
  return 1;
}

#define CHECK(expression)                    \
  do {                                       \
    if (!(expression))                       \
      return failure(#expression, __LINE__); \
  } while (0)

static int
expect_error(enum open_call call, const char* path, long flags, int expected) {
  errno = 0;
  long result = open_path(call, (long)AT_FDCWD, path, flags);
  int error = errno;
  if (result >= 0)
    syscall(SYS_close, result);
  if (result != -1 || error != expected) {
    fprintf(
        stderr,
        "%s path=%s flags=%lx result=%ld errno=%d expected=%d\n",
        call_name(call),
        path,
        (unsigned long)flags,
        result,
        error,
        expected);
    return 1;
  }
  return 0;
}

static int check_reopens(long fd, int native) {
  const char* directories[] = {"/proc/self/fd", "/dev/fd"};
  for (size_t index = 0; index < sizeof(directories) / sizeof(directories[0]);
       ++index) {
    char path[80];
    int length = snprintf(path, sizeof(path), "%s/%ld", directories[index], fd);
    CHECK(length > 0 && (size_t)length < sizeof(path));
    if (native) {
      /* Native Linux supports these read-only random-device reopens. */
      long reopened = open_path(
          USE_OPENAT, (long)AT_FDCWD, path, (long)(O_RDONLY | O_CLOEXEC));
      CHECK(reopened >= 0);
      CHECK(syscall(SYS_close, reopened) == 0);
    } else {
      /* A guest reopen must not lose the private stream's identity. */
      CHECK(
          expect_error(
              USE_OPENAT, path, (long)(O_RDONLY | O_CLOEXEC), ENOSYS) == 0);
    }
  }
  return 0;
}

static int run_case(
    const char* device,
    const char* variant,
    enum open_call call,
    long dirfd,
    const char* path,
    int native) {
  unsigned char bytes[106];
  long fd = open_path(call, dirfd, path, (long)(O_RDONLY | O_CLOEXEC));
  CHECK(fd >= 0);
  long alias = syscall(SYS_dup, fd);
  CHECK(alias >= 0);
  CHECK(syscall(SYS_read, fd, (long)bytes, 23L) == 23);
  struct iovec parts[] = {{bytes + 23, 7}, {bytes + 30, 19}, {bytes + 49, 33}};
  CHECK(syscall(SYS_readv, alias, (long)parts, 3L) == 59);
  CHECK(syscall(SYS_read, fd, (long)(bytes + 82), 11L) == 11);
  CHECK(syscall(SYS_close, fd) == 0);
  CHECK(check_reopens(alias, native) == 0);
  CHECK(syscall(SYS_read, alias, (long)(bytes + 93), 13L) == 13);
  CHECK(syscall(SYS_close, alias) == 0);

  char header[128];
  int length = snprintf(
      header,
      sizeof(header),
      "%s %s %s bytes=106\n",
      device,
      variant,
      call_name(call));
  CHECK(length > 0 && (size_t)length < sizeof(header));
  CHECK(
      syscall(SYS_write, (long)STDOUT_FILENO, (long)header, (long)length) ==
      length);
  CHECK(
      syscall(
          SYS_write, (long)STDOUT_FILENO, (long)bytes, (long)sizeof(bytes)) ==
      (long)sizeof(bytes));
  CHECK(syscall(SYS_write, (long)STDOUT_FILENO, (long)"\n", 1L) == 1);
  return 0;
}

static int check_controls(int native) {
  const char* null_paths[] = {"/dev/null", "null-link"};
  for (size_t index = 0; index < sizeof(null_paths) / sizeof(null_paths[0]);
       ++index) {
    long fd = open_path(
        USE_OPENAT,
        (long)AT_FDCWD,
        null_paths[index],
        (long)(O_RDONLY | O_CLOEXEC));
    CHECK(fd >= 0);
    struct stat status;
    CHECK(syscall(SYS_fstat, fd, (long)&status) == 0);
    CHECK(S_ISCHR(status.st_mode));
    CHECK(major(status.st_rdev) == 1 && minor(status.st_rdev) == 3);
    char bytes[7];
    CHECK(syscall(SYS_read, fd, (long)bytes, (long)sizeof(bytes)) == 0);
    CHECK(syscall(SYS_close, fd) == 0);
  }

  /* The same basename outside /dev must retain ordinary-file contents. */
  const char expected[] = "ordinary-file-control\n";
  char bytes[sizeof(expected) - 1];
  long fd = open_path(USE_OPEN, (long)AT_FDCWD, "urandom", (long)O_RDONLY);
  CHECK(fd >= 0);
  struct stat status;
  CHECK(syscall(SYS_fstat, fd, (long)&status) == 0);
  CHECK(S_ISREG(status.st_mode));
  CHECK(
      syscall(SYS_read, fd, (long)bytes, (long)sizeof(bytes)) ==
      (long)sizeof(bytes));
  CHECK(memcmp(bytes, expected, sizeof(bytes)) == 0);
  CHECK(syscall(SYS_read, fd, (long)bytes, 1L) == 0);
  CHECK(syscall(SYS_close, fd) == 0);

  const char* devices[] = {"random", "urandom"};
  for (size_t index = 0; index < sizeof(devices) / sizeof(devices[0]);
       ++index) {
    char link[32], nonliteral[64];
    int length = snprintf(link, sizeof(link), "%s-link", devices[index]);
    CHECK(length > 0 && (size_t)length < sizeof(link));
    length =
        snprintf(nonliteral, sizeof(nonliteral), "/dev/./%s", devices[index]);
    CHECK(length > 0 && (size_t)length < sizeof(nonliteral));
    for (enum open_call call = USE_OPEN; call <= USE_OPENAT; ++call) {
      CHECK(
          expect_error(call, link, (long)(O_RDONLY | O_NOFOLLOW), ELOOP) == 0);
      CHECK(
          expect_error(call, nonliteral, (long)(O_RDONLY | O_DIRECT), EINVAL) ==
          0);
      /* O_EXCL refuses the existing node before any host write occurs. */
      CHECK(
          expect_error(
              call, nonliteral, (long)(O_RDONLY | O_CREAT | O_EXCL), EEXIST) ==
          0);
      fd = open_path(call, (long)AT_FDCWD, link, (long)(O_PATH | O_NOFOLLOW));
      CHECK(fd >= 0);
      CHECK(syscall(SYS_fstat, fd, (long)&status) == 0);
      CHECK(S_ISLNK(status.st_mode));
      CHECK(syscall(SYS_close, fd) == 0);
    }
  }

  /* Ordinary symlinks are followed above; a procfs magic link stays refused. */
  if (native) {
    fd = open_path(USE_OPENAT, (long)AT_FDCWD, "magic-link", (long)O_RDONLY);
    CHECK(fd >= 0);
    CHECK(syscall(SYS_read, fd, (long)bytes, 1L) == 1);
    CHECK(syscall(SYS_close, fd) == 0);
  } else {
    CHECK(expect_error(USE_OPENAT, "magic-link", (long)O_RDONLY, ELOOP) == 0);
  }
  const char done[] = "controls ok\n";
  CHECK(
      syscall(
          SYS_write,
          (long)STDOUT_FILENO,
          (long)done,
          (long)(sizeof(done) - 1)) == (long)(sizeof(done) - 1));
  return 0;
}

int main(int argc, char** argv) {
  CHECK(argc == 2);
  int native = strcmp(argv[1], "native") == 0;
  CHECK(native || strcmp(argv[1], "kvm") == 0);
  long devfd = open_path(
      USE_OPENAT,
      (long)AT_FDCWD,
      "/dev",
      (long)(O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  CHECK(devfd >= 0);
  const char* devices[] = {"random", "urandom"};
  const struct {
    const char* name;
    const char* format;
  } variants[] = {
      {"literal", "/dev/%s"},
      {"double-slash", "//dev/%s"},
      {"component-slash", "/dev//%s"},
      {"dot", "/dev/./%s"},
      {"dotdot", "/dev/../dev/%s"},
      {"symlink", "%s-link"},
  };
  for (size_t device = 0; device < sizeof(devices) / sizeof(devices[0]);
       ++device) {
    for (size_t variant = 0; variant < sizeof(variants) / sizeof(variants[0]);
         ++variant) {
      char path[64];
      int length = snprintf(
          path, sizeof(path), variants[variant].format, devices[device]);
      CHECK(length > 0 && (size_t)length < sizeof(path));
      for (enum open_call call = USE_OPEN; call <= USE_OPENAT; ++call) {
        if (run_case(
                devices[device],
                variants[variant].name,
                call,
                (long)AT_FDCWD,
                path,
                native) != 0) {
          fprintf(
              stderr,
              "device=%s variant=%s call=%s\n",
              devices[device],
              variants[variant].name,
              call_name(call));
          return 1;
        }
      }
    }
    CHECK(
        run_case(
            devices[device],
            "dirfd",
            USE_OPENAT,
            devfd,
            devices[device],
            native) == 0);
  }
  CHECK(syscall(SYS_close, devfd) == 0);
  return check_controls(native);
}
