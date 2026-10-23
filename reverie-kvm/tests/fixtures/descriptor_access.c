#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

/* Each case runs against /dev/random, /dev/urandom and an ordinary file. The
 * checks hold natively for all three, and the test compares the backend's
 * standard output with the native run's, so every printed result is Linux's
 * answer for that object. */

static const char *current_path = "";

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "descriptor-access path=%s line=%d check=%s errno=%d\n", current_path, __LINE__, #expr, errno); return 1; } } while (0)
#define ERR(expr, expected) do { errno = 0; long r_ = (expr); int e_ = errno; if (r_ != -1 || e_ != (expected)) { fprintf(stderr, "descriptor-access path=%s line=%d result=%ld errno=%d expected=%d\n", current_path, __LINE__, r_, e_, (expected)); return 1; } } while (0)

static int is_device(const char *path) {
    return strncmp(path, "/dev/", 5) == 0;
}

static int prepare_regular(void) {
    int fd = open("regular", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    unsigned char bytes[8192];
    for (size_t i = 0; i < sizeof(bytes); ++i) bytes[i] = (unsigned char)(i * 7 + 3);
    CHECK(write(fd, bytes, sizeof(bytes)) == (ssize_t)sizeof(bytes));
    CHECK(close(fd) == 0);
    return 0;
}

static void print_bytes(const unsigned char *bytes, size_t length) {
    for (size_t i = 0; i < length; ++i) printf("%02x", bytes[i]);
    printf("\n");
}

static int downstream_mmap(const char *path) {
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    errno = 0;
    void *address = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    int saved = errno;
    if (address != MAP_FAILED) {
        CHECK(!is_device(path));
        printf("downstream-mmap %s mapped first=%02x\n", path, ((unsigned char *)address)[0]);
        CHECK(munmap(address, 4096) == 0);
    } else {
        if (is_device(path)) CHECK(saved == ENODEV);
        printf("downstream-mmap %s errno=%d\n", path, saved);
    }
    CHECK(close(fd) == 0);
    return 0;
}

static int resolver_stream(const char *path) {
    char alternate[80];
    if (is_device(path)) CHECK(snprintf(alternate, sizeof(alternate), "/dev//%s", path + 5) > 0);
    else CHECK(snprintf(alternate, sizeof(alternate), ".//%s", path) > 0);
    int fd = open(alternate, O_RDONLY | O_NONBLOCK);
    CHECK(fd >= 0);
    unsigned char bytes[82];
    CHECK(read(fd, bytes, 23) == 23);
    struct iovec segments[] = {{bytes + 23, 7}, {bytes + 30, 19}, {bytes + 49, 33}};
    CHECK(readv(fd, segments, 3) == 59);
    CHECK(close(fd) == 0);
    printf("downstream-resolver %s read=82\n", path);
    /* Host entropy differs from run to run; an ordinary file's bytes do not. */
    if (!is_device(path)) print_bytes(bytes, sizeof(bytes));
    return 0;
}

static int access_case(const char *path, int flags) {
    int fd = open(path, flags);
    CHECK(fd >= 0);
    int got = fcntl(fd, F_GETFL);
    CHECK(got >= 0);
    CHECK((got & (O_PATH | O_ACCMODE)) == (flags & (O_PATH | O_ACCMODE)));
    int readable = !(flags & O_PATH) && ((flags & O_ACCMODE) == O_RDONLY || (flags & O_ACCMODE) == O_RDWR);
    int writable = !(flags & O_PATH) && ((flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR);
    unsigned char bytes[17];
    memset(bytes, 0x39, sizeof(bytes));
    const void *bad = (const void *)UINTPTR_MAX;
    struct iovec iov[] = {{bytes, 7}, {bytes + 7, 10}};
    if (readable) {
        CHECK(syscall((long)(SYS_read), (long)(fd), (long)(bytes), (long)(17)) == 17);
        CHECK(syscall((long)(SYS_readv), (long)(fd), (long)(NULL), (long)(0)) == 0);
        ERR(syscall((long)(SYS_readv), (long)(fd), (long)(bad), (long)(1025)), EINVAL);
    } else {
        ERR(syscall((long)(SYS_read), (long)(fd), (long)(bad), (long)(0)), EBADF);
        ERR(syscall((long)(SYS_read), (long)(fd), (long)(bytes), (long)(17)), EBADF);
        ERR(syscall((long)(SYS_readv), (long)(fd), (long)(NULL), (long)(0)), EBADF);
        ERR(syscall((long)(SYS_readv), (long)(fd), (long)(bad), (long)(1025)), EBADF);
    }
    if (writable) {
        CHECK(syscall((long)(SYS_write), (long)(fd), (long)(bytes), (long)(17)) == 17);
        CHECK(syscall((long)(SYS_writev), (long)(fd), (long)(iov), (long)(2)) == 17);
        CHECK(syscall((long)(SYS_writev), (long)(fd), (long)(NULL), (long)(0)) == 0);
        ERR(syscall((long)(SYS_write), (long)(fd), (long)(bad), (long)(0)), EFAULT);
        ERR(syscall((long)(SYS_writev), (long)(fd), (long)(bad), (long)(1025)), EINVAL);
    } else {
        ERR(syscall((long)(SYS_write), (long)(fd), (long)(bad), (long)(0)), EBADF);
        ERR(syscall((long)(SYS_write), (long)(fd), (long)(bytes), (long)(17)), EBADF);
        ERR(syscall((long)(SYS_writev), (long)(fd), (long)(NULL), (long)(0)), EBADF);
        ERR(syscall((long)(SYS_writev), (long)(fd), (long)(bad), (long)(1025)), EBADF);
    }
    /* An O_PATH descriptor refuses every ioctl at its descriptor lookup,
     * before FIOCLEX or FIONCLEX could change its close-on-exec flag. */
    if (flags & O_PATH) {
        int before = fcntl(fd, F_GETFD);
        CHECK(before >= 0);
        ERR(ioctl(fd, FIOCLEX), EBADF);
        CHECK(fcntl(fd, F_GETFD) == before);
        ERR(ioctl(fd, FIONCLEX), EBADF);
        CHECK(fcntl(fd, F_GETFD) == before);
        ERR(ioctl(fd, TCGETS, bytes), EBADF);
        ERR(ioctl(fd, 0x7fffU), EBADF);
    }
    int alias = dup(fd);
    CHECK(alias >= 0);
    if (flags & O_PATH) {
        ERR(fcntl(alias, F_SETFL, O_NONBLOCK | O_RDWR), EBADF);
    } else {
        CHECK(fcntl(alias, F_SETFL, O_NONBLOCK | O_RDWR) == 0);
        got = fcntl(fd, F_GETFL);
        CHECK(got >= 0);
        CHECK((got & O_ACCMODE) == (flags & O_ACCMODE));
        CHECK((got & O_NONBLOCK) != 0);
        if (readable) CHECK(syscall((long)(SYS_readv), (long)(alias), (long)(NULL), (long)(0)) == 0);
        else ERR(syscall((long)(SYS_readv), (long)(alias), (long)(NULL), (long)(0)), EBADF);
        if (writable) CHECK(syscall((long)(SYS_writev), (long)(alias), (long)(NULL), (long)(0)) == 0);
        else ERR(syscall((long)(SYS_writev), (long)(alias), (long)(NULL), (long)(0)), EBADF);
    }
    CHECK(close(alias) == 0);
    CHECK(close(fd) == 0);
    printf("access %s flags=%#x ok\n", path, flags);
    return 0;
}

/* A call's result, or the negative errno of its failure. */
static long outcome(long result) {
    return result == -1 ? -(long)errno : result;
}

static int write_faults(const char *path) {
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    long page = sysconf(_SC_PAGESIZE);
    CHECK(page > 0);
    unsigned char *mapping = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED);
    memset(mapping, 0x61, (size_t)page);
    CHECK(mprotect(mapping + page, (size_t)page, PROT_NONE) == 0);
    unsigned char *prefix = mapping + page - 13;
    const void *bad = (const void *)UINTPTR_MAX;
    struct iovec parts[] = {{mapping, 17}, {prefix, 31}, {mapping + 17, 19}};
    struct iovec malformed[] = {{mapping, 17}, {mapping, SIZE_MAX}};
    struct iovec two[] = {{mapping, 7}, {mapping + 7, 11}};
    long r[17];
    /* A 31-byte buffer whose last 18 bytes are unreadable: a random device
     * writes the readable 13-byte prefix; a file's answer is its
     * filesystem's (a short count, or EFAULT). */
    r[0] = outcome(syscall((long)(SYS_write), (long)(fd), (long)(prefix), (long)(31)));
    r[1] = outcome(syscall((long)(SYS_writev), (long)(fd), (long)(parts), (long)(3)));
    r[2] = outcome(syscall((long)(SYS_pwrite64), (long)(fd), (long)(prefix), (long)(31), (long)((long)5)));
    r[3] = outcome(syscall((long)(SYS_pwritev), (long)(fd), (long)(parts), (long)(3), (long)((long)5), (long)(0UL)));
    r[4] = outcome(syscall((long)(SYS_pwritev2), (long)(fd), (long)(parts), (long)(3), (long)((long)-1), (long)(0UL), (long)(0U)));
    r[5] = outcome(syscall((long)(SYS_write), (long)(fd), (long)(prefix + 13), (long)(1)));
    r[6] = outcome(syscall((long)(SYS_writev), (long)(fd), (long)(malformed), (long)(2)));
    r[7] = outcome(syscall((long)(SYS_writev), (long)(fd), (long)(bad), (long)(1)));
    r[8] = outcome(syscall((long)(SYS_pwrite64), (long)(fd), (long)(bad), (long)(0), (long)((long)-1)));
    r[9] = outcome(syscall((long)(SYS_pwritev), (long)(fd), (long)(bad), (long)(1025), (long)((long)-1), (long)(0UL)));
    r[10] = outcome(syscall((long)(SYS_pwritev2), (long)(fd), (long)(bad), (long)(1025), (long)((long)-2), (long)(0UL), (long)(0U)));
    r[11] = outcome(syscall((long)(SYS_pwritev2), (long)(fd), (long)(NULL), (long)(0), (long)((long)-1), (long)(0UL), (long)(0x80000000U)));
    r[12] = outcome(syscall((long)(SYS_pwritev2), (long)(fd), (long)(parts), (long)(3), (long)((long)-1), (long)(0UL), (long)(0x80000000U)));
    /* Linux's import_iovec takes an unsigned-int count: the register's upper
     * 32 bits are ignored. */
    r[13] = outcome(syscall((long)(SYS_writev), (long)(fd), (long)(two), (long)((1L << 32) + 2)));
    r[14] = outcome(syscall((long)(SYS_pwritev), (long)(fd), (long)(two), (long)((1L << 32) + 2), (long)((long)5), (long)(0UL)));
    r[15] = outcome(syscall((long)(SYS_pwritev2), (long)(fd), (long)(two), (long)((1L << 32) + 2), (long)((long)-1), (long)(0UL), (long)(0U)));
    r[16] = outcome(syscall((long)(SYS_writev), (long)(fd), (long)(bad), (long)(1L << 32)));
    CHECK(close(fd) == 0);
    if (is_device(path)) {
        const long expected[] = {13, 30, 13, 30, 30, -EFAULT, -EINVAL, -EFAULT, -EINVAL, -EINVAL, -EINVAL, 0, -EOPNOTSUPP, 18, 18, 18, 0};
        for (int i = 0; i < 17; ++i) CHECK(r[i] == expected[i]);
    }
    /* Access mode 3 grants neither read nor write: a zero-length write is
     * still refused. */
    fd = open(path, O_ACCMODE);
    CHECK(fd >= 0);
    ERR(syscall((long)(SYS_write), (long)(fd), (long)(mapping), (long)(0)), EBADF);
    ERR(syscall((long)(SYS_pwrite64), (long)(fd), (long)(mapping), (long)(0), (long)(0)), EBADF);
    CHECK(close(fd) == 0);
    CHECK(munmap(mapping, (size_t)page * 2) == 0);
    printf("write-faults %s", path);
    for (int i = 0; i < 17; ++i) printf(" %ld", r[i]);
    printf("\n");
    return 0;
}

static int write_stream(const char *path) {
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    int alias = dup(fd);
    CHECK(alias >= 0);
    unsigned char result[82], input[79];
    memset(result, 0, sizeof(result));
    memset(input, 0x35, sizeof(input));
    struct iovec written[] = {{input, 17}, {input + 17, 19}, {input + 36, 43}};
    long r[10];
    r[0] = read(fd, result, 23);
    off_t before = lseek(fd, 0, SEEK_CUR);
    r[1] = write(alias, input, 17);
    r[2] = syscall((long)(SYS_pwrite64), (long)(fd), (long)(input), (long)(79), (long)((long)5));
    r[3] = writev(alias, written, 3);
    r[4] = syscall((long)(SYS_pwritev), (long)(fd), (long)(written), (long)(3), (long)((long)9), (long)(0UL));
    r[5] = syscall((long)(SYS_pwritev2), (long)(alias), (long)(written), (long)(3), (long)((long)-1), (long)(0UL), (long)(0U));
    /* A random device's writes leave its read position; an ordinary file's
     * writes move the shared offset. */
    off_t after = lseek(fd, 0, SEEK_CUR);
    r[6] = fcntl(alias, F_SETFL, O_APPEND);
    r[7] = write(fd, input, 19);
    struct iovec read_parts[] = {{result + 23, 7}, {result + 30, 12}, {result + 42, 23}};
    r[8] = readv(alias, read_parts, 3);
    r[9] = read(fd, result + 65, 17);
    CHECK(close(alias) == 0);
    CHECK(close(fd) == 0);
    if (is_device(path)) {
        const long expected[] = {23, 17, 79, 79, 79, 79, 0, 19, 42, 17};
        for (int i = 0; i < 10; ++i) CHECK(r[i] == expected[i]);
        CHECK(before == after);
    }
    printf("write-stream %s", path);
    for (int i = 0; i < 10; ++i) printf(" %ld", r[i]);
    printf(" position-unmoved=%d\n", before == after);
    if (!is_device(path)) print_bytes(result, sizeof(result));
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 90;
    if (prepare_regular() != 0) return 89;
    const char *paths[] = {"/dev/random", "/dev/urandom", "regular"};
    for (size_t i = 0; i < 3; ++i) {
        current_path = paths[i];
        int result;
        if (!strcmp(argv[1], "readonly")) result = access_case(paths[i], O_RDONLY);
        else if (!strcmp(argv[1], "writeonly")) result = access_case(paths[i], O_WRONLY);
        else if (!strcmp(argv[1], "readwrite")) result = access_case(paths[i], O_RDWR);
        else if (!strcmp(argv[1], "access3")) result = access_case(paths[i], O_ACCMODE);
        else if (!strcmp(argv[1], "path")) result = access_case(paths[i], O_PATH);
        else if (!strcmp(argv[1], "write-faults")) result = write_faults(paths[i]);
        else if (!strcmp(argv[1], "write-stream")) result = write_stream(paths[i]);
        else if (!strcmp(argv[1], "downstream-mmap")) result = downstream_mmap(paths[i]);
        else if (!strcmp(argv[1], "downstream-resolver")) result = resolver_stream(paths[i]);
        else return 91;
        if (result != 0) return result;
    }
    return 0;
}
