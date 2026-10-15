#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
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
static const long operations[] = {SYS_fstat, SYS_fstatfs};
static const char *operation_names[] = {"fstat", "fstatfs"};

union metadata {
  struct stat stat;
  struct statfs statfs;
};

struct observation {
  long result;
  int error;
  union metadata output;
};

static void assert_fill(const void *memory, size_t size) {
  const unsigned char *bytes = memory;
  for (size_t index = 0; index < size; ++index)
    CHECK(bytes[index] == 0xa5);
}

static struct observation observe(unsigned operation, const char *object,
                                  uint32_t low, uint64_t upper,
                                  int bad_pointer, int expected_error) {
  struct {
    unsigned char before[16];
    union metadata output;
    unsigned char after[16];
  } buffer;
  memset(&buffer, 0xa5, sizeof(buffer));
  const size_t size = operation == 0 ? sizeof(struct stat) : sizeof(struct statfs);
  errno = 0;
  long result = syscall(operations[operation], upper | low,
                        bad_pointer ? (void *)(uintptr_t)UINT64_MAX
                                    : (void *)&buffer.output);
  int error = errno;
  printf("%s object=%s upper=%016lx badptr=%d result=%ld errno=%d\n",
         operation_names[operation], object, (unsigned long)upper, bad_pointer,
         result, error);
  CHECK(result == (expected_error == 0 ? 0 : -1));
  CHECK(error == expected_error);
  assert_fill(buffer.before, sizeof(buffer.before));
  assert_fill(buffer.after, sizeof(buffer.after));
  if (result == -1) {
    assert_fill(&buffer.output, sizeof(buffer.output));
  } else {
    assert_fill((const unsigned char *)&buffer.output + size,
                sizeof(buffer.output) - size);
  }
  struct observation observed = {.result = result, .error = error};
  memcpy(&observed.output, &buffer.output, sizeof(observed.output));
  return observed;
}

static void check_free_counts(const struct statfs *value) {
  CHECK(value->f_bfree <= value->f_blocks);
  CHECK(value->f_bavail <= value->f_bfree);
  CHECK(value->f_ffree <= value->f_files);
}

static int same_fstat(int guest, int proc_root,
                      const struct observation *plain,
                      const struct observation *wide) {
  if (plain->result != wide->result || plain->error != wide->error)
    return 0;
  if (guest || !proc_root || plain->result != 0 || plain->error != 0)
    return memcmp(&plain->output, &wide->output, sizeof(plain->output)) == 0;

  // Linux fs/proc/root.c::proc_root_getattr sets
  // nlink = proc_root.nlink + nr_processes(); host process starts/exits change it.
  // Its u32 kstat.nlink is zero-extended into the x86-64 stat field. Only this
  // native live field can differ across calls; guest proc metadata stays exact.
  if (plain->output.stat.st_nlink > UINT32_MAX ||
      wide->output.stat.st_nlink > UINT32_MAX)
    return 0;
  const size_t offset = offsetof(struct stat, st_nlink);
  const size_t end = offset + sizeof(plain->output.stat.st_nlink);
  const unsigned char *left = (const unsigned char *)&plain->output;
  const unsigned char *right = (const unsigned char *)&wide->output;
  return memcmp(left, right, offset) == 0 &&
         memcmp(left + end, right + end, sizeof(plain->output) - end) == 0;
}

static void check_fstat_comparison_controls(void) {
  struct observation plain = {0}, wide;
  memset(&plain.output, 0, sizeof(plain.output));
  plain.output.stat.st_nlink = 2;
  memcpy(&wide, &plain, sizeof(wide));
  CHECK(same_fstat(0, 1, &plain, &wide));
  CHECK(same_fstat(1, 1, &plain, &wide));
  CHECK(same_fstat(0, 0, &plain, &wide));

  wide.output.stat.st_nlink = 3;
  CHECK(same_fstat(0, 1, &plain, &wide));
  CHECK(same_fstat(0, 1, &wide, &plain));
  CHECK(!same_fstat(1, 1, &plain, &wide));
  CHECK(!same_fstat(0, 0, &plain, &wide));
  for (size_t index = 0; index < 2; ++index) {
    wide.output.stat.st_nlink = index == 0 ? 0 : UINT32_MAX;
    CHECK(same_fstat(0, 1, &plain, &wide));
    CHECK(same_fstat(0, 1, &wide, &plain));
  }
  const uint64_t invalid[] = {UINT64_C(1) << 32, UINT64_C(1) << 63, UINT64_MAX};
  for (size_t index = 0; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
    wide.output.stat.st_nlink = invalid[index];
    CHECK(!same_fstat(0, 1, &plain, &wide));
    CHECK(!same_fstat(0, 1, &wide, &plain));
    CHECK(!same_fstat(0, 1, &wide, &wide));
  }

  memcpy(&wide, &plain, sizeof(wide));
  wide.result = -1;
  CHECK(!same_fstat(0, 1, &plain, &wide));
  CHECK(!same_fstat(0, 1, &wide, &plain));
  wide.result = 0;
  wide.error = EIO;
  CHECK(!same_fstat(0, 1, &plain, &wide));
  CHECK(!same_fstat(0, 1, &wide, &plain));
  plain.error = EIO;
  wide.output.stat.st_nlink = 3;
  CHECK(!same_fstat(0, 1, &plain, &wide));
  plain.error = 0;
  plain.result = -1;
  plain.error = EBADF;
  CHECK(same_fstat(0, 1, &plain, &plain));
  plain.result = plain.error = 0;

  const size_t offset = offsetof(struct stat, st_nlink);
  const size_t end = offset + sizeof(plain.output.stat.st_nlink);
  for (size_t index = 0; index < sizeof(plain.output); ++index) {
    memcpy(&wide, &plain, sizeof(wide));
    ((unsigned char *)&wide.output)[index] ^= 1;
    CHECK(!same_fstat(1, 1, &plain, &wide));
    CHECK(!same_fstat(0, 0, &plain, &wide));
    plain.result = wide.result = -1;
    plain.error = wide.error = EBADF;
    CHECK(!same_fstat(0, 1, &plain, &wide));
    plain.result = plain.error = 0;
    wide.result = wide.error = 0;
    if (index < offset || index >= end) {
      wide.output.stat.st_nlink = 3;
      CHECK(!same_fstat(0, 1, &plain, &wide));
    }
  }
}

static void assert_same(unsigned operation, int guest, int proc_root,
                        const struct observation *plain,
                        const struct observation *wide) {
  CHECK(plain->result == wide->result && plain->error == wide->error);
  if (operation == 0) {
    CHECK(same_fstat(guest, proc_root, plain, wide));
    return;
  }
  if (guest || plain->result != 0) {
    CHECK(memcmp(&plain->output, &wide->output, sizeof(plain->output)) == 0);
    return;
  }

  // Native free-space counters can change between adjacent host syscalls.
  // Compare every stable statfs field and bound each live count independently.
  // Guest statfs has canonical counters and must pass the full-byte comparison
  // above, including those counters, fsid, reserved bytes and output canaries.
  const struct statfs *left = &plain->output.statfs;
  const struct statfs *right = &wide->output.statfs;
  CHECK(left->f_type == right->f_type && left->f_bsize == right->f_bsize);
  CHECK(left->f_blocks == right->f_blocks && left->f_files == right->f_files);
  CHECK(memcmp(&left->f_fsid, &right->f_fsid, sizeof(left->f_fsid)) == 0);
  CHECK(left->f_namelen == right->f_namelen);
  CHECK(left->f_frsize == right->f_frsize && left->f_flags == right->f_flags);
  CHECK(memcmp(left->f_spare, right->f_spare, sizeof(left->f_spare)) == 0);
  check_free_counts(left);
  check_free_counts(right);
}

static void check_timestamps(const struct stat *value, time_t seconds) {
  CHECK(value->st_atim.tv_sec == seconds && value->st_atim.tv_nsec == 0);
  CHECK(value->st_mtim.tv_sec == seconds && value->st_mtim.tv_nsec == 0);
  CHECK(value->st_ctim.tv_sec == seconds && value->st_ctim.tv_nsec == 0);
}

static void check_guest_stat(const struct stat *value, int captured, int proc,
                             int directory) {
  if (proc) {
    CHECK(value->st_dev == makedev(0, 0xff01));
    CHECK(value->st_ino != 0);
    CHECK(value->st_mode == (mode_t)((directory ? S_IFDIR : S_IFREG) |
                                     (directory ? 0555 : 0444)));
    CHECK(value->st_nlink == (nlink_t)(directory ? 2 : 1));
    CHECK(value->st_uid == 0 && value->st_gid == 0 && value->st_rdev == 0);
    CHECK(value->st_blksize == 4096);
    CHECK(value->st_blocks == (value->st_size + 511) / 512);
    if (directory)
      CHECK(value->st_size == 0);
    check_timestamps(value, 0);
  } else {
    check_timestamps(value, 1640995199);
    if (captured) {
      CHECK(value->st_dev != 0 && value->st_ino != 0);
      CHECK(value->st_mode == (S_IFIFO | 0600));
      CHECK(value->st_nlink == 1 && value->st_uid == 0 && value->st_gid == 0);
      CHECK(value->st_rdev == 0 && value->st_size == 0);
      CHECK(value->st_blocks == 0 && value->st_blksize == 4096);
    }
  }
}

static void check_guest_statfs(const struct statfs *value) {
  CHECK(value->f_type != 0 && value->f_bsize > 0 && value->f_frsize > 0);
  CHECK(value->f_namelen > 0);
  const fsblkcnt_t blocks = value->f_blocks < 1000000 ? value->f_blocks : 1000000;
  const fsfilcnt_t files = value->f_files < 500000 ? value->f_files : 500000;
  CHECK(value->f_bfree == blocks && value->f_bavail == blocks);
  CHECK(value->f_ffree == files);
  const unsigned char *fsid = (const unsigned char *)&value->f_fsid;
  for (size_t index = 0; index < sizeof(value->f_fsid); ++index)
    CHECK(fsid[index] == 0);
}

int main(int argc, char **argv) {
  CHECK(argc == 3);
  CHECK(strcmp(argv[1], "guest") == 0 || strcmp(argv[1], "native") == 0);
  check_fstat_comparison_controls();
  const int guest = strcmp(argv[1], "guest") == 0;
  const char contents[] = "low-word-metadata";
  int file = open(argv[2], O_CREAT | O_TRUNC | O_RDWR, 0600);
  CHECK(file >= 0);
  CHECK(write(file, contents, sizeof(contents) - 1) == sizeof(contents) - 1);
  int directory = open(".", O_RDONLY | O_DIRECTORY);
  int proc_root = open("/proc", O_RDONLY | O_DIRECTORY);
  int proc_stat = open("/proc/stat", O_RDONLY);
  char path[64];
  CHECK(snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", file) > 0);
  int fdinfo = open(path, O_RDONLY);
  int stdout_alias = dup(STDOUT_FILENO);
  CHECK(directory >= 0 && proc_root >= 0 && proc_stat >= 0 && fdinfo >= 0);
  CHECK(stdout_alias >= 0);
  int closed = dup(file);
  CHECK(closed >= 0 && close(closed) == 0);

  const struct {
    const char *name;
    int fd;
    int captured;
    int proc;
    int directory;
  } objects[] = {{"stdout", STDOUT_FILENO, 1, 0, 0},
                 {"stdout-alias", stdout_alias, 1, 0, 0},
                 {"stderr", STDERR_FILENO, 1, 0, 0},
                 {"file", file, 0, 0, 0},
                 {"directory", directory, 0, 0, 1},
                 {"proc-root", proc_root, 0, 1, 1},
                 {"proc-stat", proc_stat, 0, 1, 0},
                 {"fdinfo", fdinfo, 0, 1, 0}};
  struct observation stdout_stat = {0};
  for (size_t object = 0; object < sizeof(objects) / sizeof(objects[0]); ++object) {
    struct observation plain = {0};
    for (size_t upper = 0; upper < 4; ++upper) {
      struct observation observed = observe(0, objects[object].name,
          (uint32_t)objects[object].fd, upper_words[upper], 0, 0);
      if (upper == 0)
        plain = observed;
      else
        assert_same(0, guest, objects[object].fd == proc_root, &plain, &observed);
      if (guest)
        check_guest_stat(&observed.output.stat, objects[object].captured,
                         objects[object].proc, objects[object].directory);
      observe(0, objects[object].name, (uint32_t)objects[object].fd,
              upper_words[upper], 1, EFAULT);
    }
    if (object == 0) {
      stdout_stat = plain;
      CHECK(S_ISFIFO(plain.output.stat.st_mode));
    } else if (object == 1) {
      assert_same(0, guest, 0, &stdout_stat, &plain);
    } else if (object == 2) {
      CHECK(S_ISFIFO(plain.output.stat.st_mode));
      CHECK(plain.output.stat.st_dev == stdout_stat.output.stat.st_dev);
      CHECK(plain.output.stat.st_ino != stdout_stat.output.stat.st_ino);
    } else if (object == 3) {
      CHECK(S_ISREG(plain.output.stat.st_mode));
      CHECK(plain.output.stat.st_size == sizeof(contents) - 1);
    } else if (object == 4) {
      CHECK(S_ISDIR(plain.output.stat.st_mode));
    }
  }

  for (size_t object = 3; object <= 4; ++object) {
    struct observation plain = {0};
    for (size_t upper = 0; upper < 4; ++upper) {
      struct observation observed = observe(1, objects[object].name,
          (uint32_t)objects[object].fd, upper_words[upper], 0, 0);
      if (upper == 0)
        plain = observed;
      else
        assert_same(1, guest, 0, &plain, &observed);
      if (guest)
        check_guest_statfs(&observed.output.statfs);
      observe(1, objects[object].name, (uint32_t)objects[object].fd,
              upper_words[upper], 1, EFAULT);
    }
  }

  const uint32_t invalid[] = {INT32_MAX, UINT32_C(0x80000000), UINT32_MAX,
                              (uint32_t)closed};
  const char *invalid_names[] = {"int-max", "int-min", "minus-one", "closed"};
  for (unsigned operation = 0; operation < 2; ++operation)
    for (size_t low = 0; low < 4; ++low)
      for (size_t upper = 0; upper < 4; ++upper)
        for (int bad_pointer = 0; bad_pointer < 2; ++bad_pointer)
          observe(operation, invalid_names[low], invalid[low],
                  upper_words[upper], bad_pointer, EBADF);

  // These are explicit backend policy controls, separate from native parity.
  // Neither a wide fd nor a bad output pointer may bypass a guest refusal.
  puts("proc-policy");
  for (size_t object = 0; object < 2; ++object)
    for (size_t upper = 0; upper < 4; ++upper)
      for (int bad_pointer = 0; bad_pointer < 2; ++bad_pointer) {
        int expected = guest ? (object == 0 ? EACCES : ENOSYS)
                             : (bad_pointer ? EFAULT : 0);
        observe(1, object == 0 ? "proc-root" : "fdinfo",
                (uint32_t)(object == 0 ? proc_root : fdinfo),
                upper_words[upper], bad_pointer, expected);
      }
  CHECK(close(stdout_alias) == 0 && close(fdinfo) == 0);
  CHECK(close(proc_stat) == 0 && close(proc_root) == 0);
  CHECK(close(directory) == 0 && close(file) == 0);
  return 0;
}
