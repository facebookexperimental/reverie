#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "random-access line=%d check=%s errno=%d\n", __LINE__, #expr, errno); return 1; } } while (0)
#define ERR(expr, expected) do { errno = 0; long r_ = (expr); int e_ = errno; if (r_ != -1 || e_ != (expected)) { fprintf(stderr, "random-access line=%d result=%ld errno=%d expected=%d\n", __LINE__, r_, e_, (expected)); return 1; } } while (0)

static int mmap_readonly(const char *path) {
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    errno = 0;
    void *address = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    int saved = errno;
    if (address != MAP_FAILED) {
        CHECK(munmap(address, 4096) == 0);
        fprintf(stderr, "random-access downstream mmap unexpectedly succeeded after open\n");
        CHECK(close(fd) == 0);
        return 1;
    }
    CHECK(saved == ENODEV);
    CHECK(close(fd) == 0);
    return 0;
}

static int resolver_stream(const char *path) {
    char alternate[80];
    CHECK(snprintf(alternate, sizeof(alternate), "/dev//%s", path + 5) > 0);
    int fd = open(alternate, O_RDONLY | O_NONBLOCK);
    CHECK(fd >= 0);
    unsigned char bytes[82];
    CHECK(read(fd, bytes, 23) == 23);
    struct iovec segments[] = {{bytes + 23, 7}, {bytes + 30, 19}, {bytes + 49, 33}};
    CHECK(readv(fd, segments, 3) == 59);
    CHECK(close(fd) == 0);
    CHECK(fwrite(bytes, 1, sizeof(bytes), stdout) == sizeof(bytes));
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
    return 0;
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
    CHECK(syscall((long)(SYS_write), (long)(fd), (long)(prefix), (long)(31)) == 13);
    CHECK(syscall((long)(SYS_writev), (long)(fd), (long)(parts), (long)(3)) == 30);
    CHECK(syscall((long)(SYS_pwrite64), (long)(fd), (long)(prefix), (long)(31), (long)((long)5)) == 13);
    CHECK(syscall((long)(SYS_pwritev), (long)(fd), (long)(parts), (long)(3), (long)((long)5), (long)(0UL)) == 30);
    CHECK(syscall((long)(SYS_pwritev2), (long)(fd), (long)(parts), (long)(3), (long)((long)-1), (long)(0UL), (long)(0U)) == 30);
    ERR(syscall((long)(SYS_write), (long)(fd), (long)(prefix + 13), (long)(1)), EFAULT);
    ERR(syscall((long)(SYS_writev), (long)(fd), (long)(malformed), (long)(2)), EINVAL);
    ERR(syscall((long)(SYS_writev), (long)(fd), (long)(bad), (long)(1)), EFAULT);
    ERR(syscall((long)(SYS_pwrite64), (long)(fd), (long)(bad), (long)(0), (long)((long)-1)), EINVAL);
    ERR(syscall((long)(SYS_pwritev), (long)(fd), (long)(bad), (long)(1025), (long)((long)-1), (long)(0UL)), EINVAL);
    ERR(syscall((long)(SYS_pwritev2), (long)(fd), (long)(bad), (long)(1025), (long)((long)-2), (long)(0UL), (long)(0U)), EINVAL);
    CHECK(syscall((long)(SYS_pwritev2), (long)(fd), (long)(NULL), (long)(0), (long)((long)-1), (long)(0UL), (long)(0x80000000U)) == 0);
    ERR(syscall((long)(SYS_pwritev2), (long)(fd), (long)(parts), (long)(3), (long)((long)-1), (long)(0UL), (long)(0x80000000U)), EOPNOTSUPP);
    CHECK(munmap(mapping, (size_t)page * 2) == 0);
    CHECK(close(fd) == 0);
    return 0;
}

static int write_stream(const char *path) {
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    int alias = dup(fd);
    CHECK(alias >= 0);
    unsigned char result[82], input[79];
    memset(input, 0x35, sizeof(input));
    struct iovec written[] = {{input, 17}, {input + 17, 19}, {input + 36, 43}};
    CHECK(read(fd, result, 23) == 23);
    CHECK(write(alias, input, 17) == 17);
    CHECK(syscall((long)(SYS_pwrite64), (long)(fd), (long)(input), (long)(79), (long)((long)5)) == 79);
    CHECK(writev(alias, written, 3) == 79);
    CHECK(syscall((long)(SYS_pwritev), (long)(fd), (long)(written), (long)(3), (long)((long)9), (long)(0UL)) == 79);
    CHECK(syscall((long)(SYS_pwritev2), (long)(alias), (long)(written), (long)(3), (long)((long)-1), (long)(0UL), (long)(0U)) == 79);
    CHECK(fcntl(alias, F_SETFL, O_APPEND) == 0);
    CHECK(write(fd, input, 19) == 19);
    struct iovec read_parts[] = {{result + 23, 7}, {result + 30, 12}, {result + 42, 23}};
    CHECK(readv(alias, read_parts, 3) == 42);
    CHECK(read(fd, result + 65, 17) == 17);
    CHECK(close(alias) == 0);
    CHECK(close(fd) == 0);
    CHECK(fwrite(result, 1, sizeof(result), stdout) == sizeof(result));
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 90;
    const char *paths[] = {"/dev/random", "/dev/urandom"};
    for (size_t i = 0; i < 2; ++i) {
        int result;
        if (!strcmp(argv[1], "readonly")) result = access_case(paths[i], O_RDONLY);
        else if (!strcmp(argv[1], "writeonly")) result = access_case(paths[i], O_WRONLY);
        else if (!strcmp(argv[1], "readwrite")) result = access_case(paths[i], O_RDWR);
        else if (!strcmp(argv[1], "access3")) result = access_case(paths[i], O_ACCMODE);
        else if (!strcmp(argv[1], "path")) result = access_case(paths[i], O_PATH);
        else if (!strcmp(argv[1], "write-faults")) result = write_faults(paths[i]);
        else if (!strcmp(argv[1], "write-stream")) result = write_stream(paths[i]);
        else if (!strcmp(argv[1], "downstream-mmap")) result = mmap_readonly(paths[i]);
        else if (!strcmp(argv[1], "downstream-resolver")) result = resolver_stream(paths[i]);
        else return 91;
        if (result != 0) return result;
    }
    if (strcmp(argv[1], "write-stream") && strcmp(argv[1], "downstream-resolver")) printf("random-access %s ok\n", argv[1]);
    return 0;
}
