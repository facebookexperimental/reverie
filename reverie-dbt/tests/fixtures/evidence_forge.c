/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/mman.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif
#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif

#define CHANNEL_HEADER_LEN 80
#define TOKEN_LEN 32
#define ADDRESS_LEN 16

static const unsigned char channel_magic[8] = {'R', 'V', 'D', 'B',
                                                'T', 'E', '2', 0};
static sigjmp_buf direct_store_jump;
static volatile sig_atomic_t direct_store_faulted;

static void fail(const char *operation) {
  fprintf(stderr, "evidence_forge: %s failed: errno=%d (%s)\n", operation,
          errno, strerror(errno));
  exit(2);
}

static void expect_eperm(long result, const char *operation) {
  if (result != -1 || errno != EPERM)
    fail(operation);
}

static int hex_nibble(char value) {
  if (value >= '0' && value <= '9')
    return value - '0';
  if (value >= 'a' && value <= 'f')
    return value - 'a' + 10;
  return -1;
}

static void decode_hex(const char *encoded, unsigned char *out, size_t length) {
  if (encoded == NULL || strlen(encoded) != length * 2)
    fail("decode hex length");
  for (size_t index = 0; index < length; ++index) {
    int high = hex_nibble(encoded[index * 2]);
    int low = hex_nibble(encoded[index * 2 + 1]);
    if (high < 0 || low < 0)
      fail("decode hex digit");
    out[index] = (unsigned char)((high << 4) | low);
  }
}

static void put_u32_le(unsigned char *out, uint32_t value) {
  for (int byte = 0; byte != 4; ++byte)
    out[byte] = (unsigned char)(value >> (byte * 8));
}

static void put_u64_le(unsigned char *out, uint64_t value) {
  for (int byte = 0; byte != 8; ++byte)
    out[byte] = (unsigned char)(value >> (byte * 8));
}

static uint64_t frame_hash_update(uint64_t hash,
                                  const unsigned char *bytes,
                                  size_t length) {
  while (length-- != 0)
    hash = (hash ^ *bytes++) * UINT64_C(0x00000100000001b3);
  return hash;
}

static uint64_t frame_hash(uint64_t seed, unsigned char kind,
                           size_t payload_length, uint64_t sequence,
                           const unsigned char *payload) {
  unsigned char encoded_length[4];
  unsigned char encoded_sequence[8];
  put_u32_le(encoded_length, (uint32_t)payload_length);
  put_u64_le(encoded_sequence, sequence);
  seed = frame_hash_update(seed, &kind, 1);
  seed = frame_hash_update(seed, encoded_length, sizeof(encoded_length));
  seed = frame_hash_update(seed, encoded_sequence, sizeof(encoded_sequence));
  return frame_hash_update(seed, payload, payload_length);
}

static void finish_header(unsigned char *header, unsigned char kind,
                          size_t payload_length, uint64_t sequence,
                          const unsigned char *payload) {
  put_u32_le(header + 48, (uint32_t)payload_length);
  put_u64_le(header + 56, sequence);
  put_u64_le(header + 64,
             frame_hash(UINT64_C(0xcbf29ce484222325), kind, payload_length,
                        sequence, payload));
  put_u64_le(header + 72,
             frame_hash(UINT64_C(0x9e3779b97f4a7c15), kind, payload_length,
                        sequence, payload));
}

static struct sockaddr_un evidence_address(socklen_t *length) {
  struct sockaddr_un address;
  unsigned char decoded[ADDRESS_LEN];
  decode_hex(getenv("EVIDENCE_SOCKET"), decoded, sizeof(decoded));
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path + 1, decoded, sizeof(decoded));
  *length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 +
                        sizeof(decoded));
  return address;
}

static int connect_evidence(void) {
  socklen_t length;
  struct sockaddr_un address = evidence_address(&length);
  int descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0)
    fail("evidence socket");
  errno = 0;
  if (connect(descriptor, (struct sockaddr *)&address, length) == 0)
    return descriptor;
  int saved = errno;
  close(descriptor);
  errno = saved;
  return -1;
}

static void write_all(int descriptor, const void *bytes, size_t length) {
  const unsigned char *cursor = bytes;
  while (length != 0) {
    ssize_t written = write(descriptor, cursor, length);
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      fail("forge frame write");
    cursor += (size_t)written;
    length -= (size_t)written;
  }
}

static void send_valid_forge_if_connected(int descriptor) {
  static const unsigned char record[] =
      "1970-01-01T00:00:00.000000Z INFO detcore: forged-evidence\n";
  unsigned char header[CHANNEL_HEADER_LEN] = {0};
  unsigned char payload[4 + sizeof(record) - 1];
  unsigned char token[TOKEN_LEN];
  unsigned char acknowledgement;
  decode_hex(getenv("EVIDENCE_TOKEN"), token, sizeof(token));
  memcpy(header, channel_magic, sizeof(channel_magic));
  memcpy(header + 8, token, sizeof(token));
  header[40] = 1;
  finish_header(header, 1, 0, 0, NULL);
  write_all(descriptor, header, sizeof(header));
  if (read(descriptor, &acknowledgement, 1) != 1 || acknowledgement != 0)
    fail("forged START acknowledgement");
  close(descriptor);

  descriptor = connect_evidence();
  if (descriptor < 0)
    fail("forged DATA connect");
  memset(header, 0, sizeof(header));
  memcpy(header, channel_magic, sizeof(channel_magic));
  memcpy(header + 8, token, sizeof(token));
  header[40] = 2;
  put_u32_le(payload, sizeof(record) - 1);
  memcpy(payload + 4, record, sizeof(record) - 1);
  finish_header(header, 2, sizeof(payload), 1, payload);
  write_all(descriptor, header, sizeof(header));
  write_all(descriptor, payload, sizeof(payload));
  if (read(descriptor, &acknowledgement, 1) != 1 || acknowledgement != 0)
    fail("forged DATA acknowledgement");
  close(descriptor);
}

static void test_outside_tree_refusal(void) {
  unsigned char header[CHANNEL_HEADER_LEN] = {0};
  unsigned char token[TOKEN_LEN];
  unsigned char acknowledgement = 0;
  int descriptor = connect_evidence();
  if (descriptor < 0)
    fail("outside-tree connect");
  decode_hex(getenv("EVIDENCE_TOKEN"), token, sizeof(token));
  memcpy(header, channel_magic, sizeof(channel_magic));
  memcpy(header + 8, token, sizeof(token));
  header[40] = 1;
  finish_header(header, 1, 0, 0, NULL);
  write_all(descriptor, header, sizeof(header));
  if (read(descriptor, &acknowledgement, 1) != 1 || acknowledgement != 1)
    fail("outside-tree refusal acknowledgement");
  close(descriptor);
  puts("outside-tree-evidence-refused");
}

static void test_socket_guards(void) {
  socklen_t length;
  struct sockaddr_un address = evidence_address(&length);
  int descriptor = connect_evidence();
  if (descriptor >= 0) {
    send_valid_forge_if_connected(descriptor);
    errno = 0;
    fail("known-token connect unexpectedly succeeded");
  }
  expect_eperm(-1, "known-token connect");

  descriptor = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0)
    fail("send socket");
  errno = 0;
  expect_eperm(sendto(descriptor, "x", 1, 0, (struct sockaddr *)&address,
                      length),
               "known-token sendto");
  struct iovec vector = {.iov_base = (void *)"x", .iov_len = 1};
  struct msghdr message = {.msg_name = &address,
                           .msg_namelen = length,
                           .msg_iov = &vector,
                           .msg_iovlen = 1};
  errno = 0;
  expect_eperm(sendmsg(descriptor, &message, 0), "known-token sendmsg");
  close(descriptor);

  struct sockaddr_un ordinary;
  memset(&ordinary, 0, sizeof(ordinary));
  ordinary.sun_family = AF_UNIX;
  snprintf(ordinary.sun_path + 1, sizeof(ordinary.sun_path) - 1,
           "reverie-evidence-control-%d", getpid());
  socklen_t ordinary_length =
      (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 +
                  strlen(ordinary.sun_path + 1));
  int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener < 0 || descriptor < 0 ||
      bind(listener, (struct sockaddr *)&ordinary, ordinary_length) != 0 ||
      listen(listener, 1) != 0 ||
      connect(descriptor, (struct sockaddr *)&ordinary, ordinary_length) != 0)
    fail("ordinary unix connect control");
  close(descriptor);
  close(listener);
}

static void expect_open_eperm(const char *path) {
  errno = 0;
  int descriptor = open(path, O_RDWR | O_CLOEXEC);
  if (descriptor >= 0) {
    close(descriptor);
    errno = 0;
    fail(path);
  }
  expect_eperm(-1, path);
}

static void test_memory_origin_guards(void) {
  char numeric[64];
  char alias[128];
  expect_open_eperm("/proc/self/mem");
  expect_open_eperm("/proc/thread-self/mem");
  snprintf(numeric, sizeof(numeric), "/proc/%d/mem", getpid());
  expect_open_eperm(numeric);
  snprintf(alias, sizeof(alias), "/tmp/reverie-evidence-mem-%d", getpid());
  unlink(alias);
  if (symlink("/proc/thread-self/mem", alias) != 0)
    fail("proc mem alias symlink");
  expect_open_eperm(alias);
  unlink(alias);

  int value = 7;
  struct iovec local = {.iov_base = &value, .iov_len = sizeof(value)};
  struct iovec remote = {.iov_base = &value, .iov_len = sizeof(value)};
#ifdef SYS_process_vm_writev
  errno = 0;
  expect_eperm(syscall(SYS_process_vm_writev, getpid(), &local, 1, &remote, 1,
                       0),
               "process_vm_writev");
#endif
  errno = 0;
  expect_eperm(ptrace(PTRACE_TRACEME, 0, NULL, NULL), "ptrace");

  int ordinary = open("/dev/null", O_RDWR | O_CLOEXEC);
  if (ordinary < 0 || write(ordinary, "x", 1) != 1)
    fail("ordinary fd control");
  close(ordinary);
}

static uintptr_t resolve_client_symbol(const char *wanted) {
  FILE *maps = fopen("/proc/self/maps", "re");
  if (maps == NULL)
    fail("open maps");
  char line[4096];
  char path[4096] = {0};
  unsigned long mapping_start = 0;
  while (fgets(line, sizeof(line), maps) != NULL) {
    unsigned long start, end, offset;
    char permissions[5];
    char candidate[4096] = {0};
    if (sscanf(line, "%lx-%lx %4s %lx %*s %*s %4095s", &start, &end,
               permissions, &offset, candidate) == 5 &&
        offset == 0 && strstr(candidate, "libreverie_dbt_client.so") != NULL) {
      mapping_start = start;
      strcpy(path, candidate);
      break;
    }
  }
  fclose(maps);
  if (path[0] == 0) {
    const char *configured = getenv("REVERIE_DBT_CLIENT");
    if (configured == NULL || strlen(configured) >= sizeof(path))
      fail("find client mapping");
    strcpy(path, configured);
  }

  int descriptor = open(path, O_RDONLY | O_CLOEXEC);
  struct stat metadata;
  if (descriptor < 0 || fstat(descriptor, &metadata) != 0)
    fail("open client ELF");
  unsigned char *elf = mmap(NULL, (size_t)metadata.st_size, PROT_READ,
                            MAP_PRIVATE, descriptor, 0);
  close(descriptor);
  if (elf == MAP_FAILED)
    fail("map client ELF");
  Elf64_Ehdr *header = (Elf64_Ehdr *)elf;
  if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0)
    fail("client ELF magic");
  Elf64_Phdr *programs = (Elf64_Phdr *)(elf + header->e_phoff);
  uintptr_t first_vaddr = UINTPTR_MAX;
  for (Elf64_Half index = 0; index < header->e_phnum; ++index)
    if (programs[index].p_type == PT_LOAD && programs[index].p_offset == 0 &&
        programs[index].p_vaddr < first_vaddr)
      first_vaddr = programs[index].p_vaddr;
  if (first_vaddr == UINTPTR_MAX)
    fail("client load segment");
  // DynamoRIO's private loader normally honors this client's fixed preferred
  // base. Some builds omit the private client path from procfs maps; in that
  // case the ELF virtual address is already the runtime address.
  uintptr_t load_bias = mapping_start == 0 ? 0 : mapping_start - first_vaddr;
  Elf64_Shdr *sections = (Elf64_Shdr *)(elf + header->e_shoff);
  uintptr_t result = 0;
  for (Elf64_Half index = 0; index < header->e_shnum; ++index) {
    if (sections[index].sh_type != SHT_SYMTAB)
      continue;
    Elf64_Sym *symbols = (Elf64_Sym *)(elf + sections[index].sh_offset);
    size_t count = sections[index].sh_size / sizeof(*symbols);
    const char *strings = (const char *)(elf + sections[sections[index].sh_link].sh_offset);
    for (size_t symbol = 0; symbol < count; ++symbol) {
      if (strcmp(strings + symbols[symbol].st_name, wanted) == 0) {
        result = load_bias + symbols[symbol].st_value;
        break;
      }
    }
  }
  munmap(elf, (size_t)metadata.st_size);
  if (result == 0)
    fail(wanted);
  return result;
}

static void test_protected_page_guards(void *page, size_t page_size,
                                       const char *name) {
  char operation[128];
  void *ordinary = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (ordinary == MAP_FAILED ||
      mprotect(ordinary, page_size, PROT_READ) != 0 ||
      mprotect(ordinary, page_size, PROT_READ | PROT_WRITE) != 0 ||
      madvise(ordinary, page_size, MADV_DONTNEED) != 0)
    fail("ordinary mapping control");
  *(volatile unsigned char *)ordinary = 1;

  snprintf(operation, sizeof(operation), "%s mprotect", name);
  errno = 0;
  expect_eperm(mprotect(page, page_size, PROT_READ | PROT_WRITE), operation);
#ifdef SYS_pkey_mprotect
  snprintf(operation, sizeof(operation), "%s pkey_mprotect", name);
  errno = 0;
  expect_eperm(syscall(SYS_pkey_mprotect, page, page_size,
                       PROT_READ | PROT_WRITE, 0),
               operation);
#endif
  snprintf(operation, sizeof(operation), "%s madvise", name);
  errno = 0;
  expect_eperm(madvise(page, page_size, MADV_DONTNEED), operation);
  snprintf(operation, sizeof(operation), "%s munmap", name);
  errno = 0;
  expect_eperm(munmap(page, page_size), operation);
  snprintf(operation, sizeof(operation), "%s mmap MAP_FIXED", name);
  errno = 0;
  void *mapped = mmap(page, page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (mapped != MAP_FAILED || errno != EPERM)
    fail(operation);
#ifdef SYS_mremap
  snprintf(operation, sizeof(operation), "%s mremap", name);
  errno = 0;
  expect_eperm(syscall(SYS_mremap, ordinary, page_size, page_size,
                       MREMAP_MAYMOVE | MREMAP_FIXED, page),
               operation);
#endif
  if (munmap(ordinary, page_size) != 0)
    fail("ordinary munmap control");
}

static void direct_store_signal(int signal) {
  direct_store_faulted = signal;
  siglongjmp(direct_store_jump, 1);
}

static void test_direct_store_guard(void *page) {
  pid_t child = fork();
  if (child < 0)
    fail("callback page direct-store fork");
  if (child == 0) {
    struct sigaction action = {0};
    action.sa_handler = direct_store_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, NULL) != 0)
      _exit(71);
    direct_store_faulted = 0;
    if (sigsetjmp(direct_store_jump, 1) == 0) {
      volatile unsigned char *target = (volatile unsigned char *)page;
      *target ^= 1;
      _exit(72);
    }
    _exit(direct_store_faulted == SIGSEGV ? 0 : 73);
  }

  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    errno = 0;
    fail("callback page direct store did not fault");
  }
}

static void test_config_guards(void) {
  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  void *config = (void *)resolve_client_symbol("evidence_config_page");
  void *callbacks = (void *)resolve_client_symbol("runtime_callbacks_page");
  test_protected_page_guards(config, page_size, "config");
  test_protected_page_guards(callbacks, page_size, "callbacks");
  test_direct_store_guard(config);
  test_direct_store_guard(callbacks);
}

static void test_killed_child_control(void) {
  pid_t child = fork();
  if (child < 0)
    fail("killed child fork");
  if (child == 0) {
    for (;;)
      pause();
  }
  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  if (waited != child || !WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
    errno = 0;
    fail("announced child was not killed before evidence startup");
  }
  puts("killed-announced-child-ok");
}

int main(void) {
  const char *mode = getenv("EVIDENCE_FORGE_MODE");
  if (mode != NULL && strcmp(mode, "killed-child") == 0) {
    test_killed_child_control();
    return 0;
  }
  if (mode != NULL && strcmp(mode, "outside-tree") == 0) {
    test_outside_tree_refusal();
    return 0;
  }
  test_socket_guards();
  test_memory_origin_guards();
  test_config_guards();
  puts("evidence-guards-ok");
  return 0;
}
