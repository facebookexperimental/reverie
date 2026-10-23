/* Source preparation only: native reference for the two-image fixture.
 * No production counter API, SETREGS, injected application syscall, retry,
 * scaling, count subtraction, or fake conditional count.
 */
#define _GNU_SOURCE
#include <cpuid.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FIXED_ENTRY UINT64_C(0x401000)
#define EXPECTED_FLAGS UINT64_C(0x247)
#define TAG_FIRST UINT64_C(0x43425201)
#define TAG_EXIT UINT64_C(0x434252ff)
#define IMAGE_LIMIT (1024u * 1024u)
#define MAX_MAPS 128

static pid_t child = -1;
static int pmu = -1, guest_out = -1, guest_err = -1;
static bool counting;
static long long deadline_ms;
static volatile sig_atomic_t interrupted;
static uint64_t event_id, initial_rsp, initial_cs, initial_ss;

struct reading { uint64_t value, enabled, running, id; };
_Static_assert(sizeof(struct reading) == 32, "perf read ABI");
_Static_assert(sizeof(struct user_regs_struct) == 216, "x86-64 complete regset");
struct image {
  const char *path;
  unsigned char *bytes;
  size_t size;
  struct stat st;
  Elf64_Ehdr eh;
  uint64_t zero_load_vaddr, bias, anchor;
  unsigned bias_matches;
};
struct mapping {
  uint64_t start, end, offset, inode;
  dev_t file_device;
  ino_t file_inode;
  unsigned dev_major, dev_minor;
  char perms[5];
};
static struct image app, interpreter;
static struct mapping mappings[MAX_MAPS];
static size_t mapping_count;

static long long now_ms(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t)) _exit(124);
  return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void cleanup(void) {
  if (pmu >= 0) {
    if (counting) (void)ioctl(pmu, PERF_EVENT_IOC_DISABLE, 0);
    close(pmu); pmu = -1; counting = false;
  }
  if (child > 0) {
    (void)kill(child, SIGKILL);
    long long end = now_ms() + 2000;
    for (;;) {
      int status;
      pid_t found = waitpid(child, &status, WNOHANG);
      if (found == child && (WIFEXITED(status) || WIFSIGNALED(status))) {
        child = -1; break;
      }
      if (found < 0 && errno == ECHILD) { child = -1; break; }
      if (found == child && WIFSTOPPED(status))
        (void)ptrace(PTRACE_CONT, child, NULL, (void *)(uintptr_t)SIGKILL);
      if (now_ms() >= end) {
        fputs("APP_NATIVE cleanup=kill_requested_not_reaped\n", stderr);
        break; /* PTRACE_O_EXITKILL and the outer cgroup are final backstops. */
      }
      struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL);
    }
  }
  if (guest_out >= 0) close(guest_out);
  if (guest_err >= 0) close(guest_err);
  free(app.bytes); free(interpreter.bytes);
}

static void fail(const char *reason) {
  fprintf(stderr, "APP_NATIVE refusal=%s errno=%d\n", reason, errno);
  exit(125);
}

static void semantic_fail(const char *reason) {
  fprintf(stderr, "APP_NATIVE mismatch=%s\n", reason);
  exit(1);
}

static void on_signal(int signal_number) { interrupted = signal_number; }

static int wait_owned(void) {
  for (;;) {
    int status;
    pid_t found = waitpid(child, &status, WNOHANG);
    if (found == child) {
      /* Never signal a reaped numeric PID from cleanup. */
      if (WIFEXITED(status) || WIFSIGNALED(status)) child = -1;
      printf("{\"record\":\"wait\",\"status\":%d}\n", status);
      return status;
    }
    if (found < 0 && errno == ECHILD) child = -1;
    if (found < 0 && errno != EINTR) fail("waitpid");
    if (interrupted || now_ms() >= deadline_ms) {
      errno = ETIMEDOUT; fail(interrupted ? "controller-interrupted" : "deadline");
    }
    struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL);
  }
}

static void resume(bool syscall_stops) {
  if (ptrace(syscall_stops ? PTRACE_SYSCALL : PTRACE_CONT, child, NULL, NULL))
    fail("resume");
}

static void range(const struct image *im, uint64_t off, uint64_t size) {
  if (off > im->size || size > im->size - off) fail("ELF-range");
}

static Elf64_Shdr section(const struct image *im, unsigned index) {
  if (index >= im->eh.e_shnum) fail("ELF-section-index");
  Elf64_Shdr s;
  uint64_t off = im->eh.e_shoff + (uint64_t)index * sizeof(s);
  range(im, off, sizeof(s)); memcpy(&s, im->bytes + off, sizeof(s));
  return s;
}

static const char *string_at(const struct image *im, const Elf64_Shdr *s,
                             uint64_t off) {
  range(im, s->sh_offset, s->sh_size);
  if (off >= s->sh_size ||
      !memchr(im->bytes + s->sh_offset + off, 0, s->sh_size - off))
    fail("ELF-string");
  return (const char *)im->bytes + s->sh_offset + off;
}

static uint64_t symbol(const struct image *im, const char *name) {
  unsigned matches = 0; uint64_t address = 0;
  for (unsigned n = 0; n < im->eh.e_shnum; ++n) {
    Elf64_Shdr s = section(im, n);
    if (s.sh_type != SHT_SYMTAB) continue;
    if (s.sh_entsize != sizeof(Elf64_Sym) || s.sh_size % s.sh_entsize)
      fail("ELF-symbol-table");
    range(im, s.sh_offset, s.sh_size);
    Elf64_Shdr strings = section(im, s.sh_link);
    if (strings.sh_type != SHT_STRTAB) fail("ELF-symbol-strings");
    for (uint64_t at = 0; at < s.sh_size; at += sizeof(Elf64_Sym)) {
      Elf64_Sym sym; memcpy(&sym, im->bytes + s.sh_offset + at, sizeof(sym));
      if (!strcmp(string_at(im, &strings, sym.st_name), name)) {
        if (sym.st_shndx == SHN_UNDEF || sym.st_shndx >= im->eh.e_shnum)
          fail("ELF-undefined-symbol");
        address = sym.st_value; ++matches;
      }
    }
  }
  if (matches != 1 || !address) fail("ELF-symbol-missing-or-duplicate");
  return address;
}

static void load_image(struct image *im, const char *path, bool main_image) {
  if (path[0] != '/' || strpbrk(path, "\n\r\"\\")) fail("absolute-unambiguous-path");
  im->path = path;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0 || fstat(fd, &im->st)) fail("ELF-open");
  if (!S_ISREG(im->st.st_mode) || im->st.st_size < (off_t)sizeof(Elf64_Ehdr) ||
      im->st.st_size > IMAGE_LIMIT) fail("ELF-file-size");
  im->size = (size_t)im->st.st_size;
  im->bytes = malloc(im->size);
  if (!im->bytes) fail("ELF-buffer");
  size_t done = 0;
  while (done < im->size) {
    ssize_t n = pread(fd, im->bytes + done, im->size - done, (off_t)done);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) fail("ELF-read");
    done += (size_t)n;
  }
  if (close(fd)) fail("ELF-close");
  memcpy(&im->eh, im->bytes, sizeof(im->eh));
  const Elf64_Ehdr *e = &im->eh;
  if (memcmp(e->e_ident, ELFMAG, SELFMAG) || e->e_ident[EI_CLASS] != ELFCLASS64 ||
      e->e_ident[EI_DATA] != ELFDATA2LSB || e->e_ident[EI_VERSION] != EV_CURRENT ||
      e->e_machine != EM_X86_64 || e->e_type != (main_image ? ET_EXEC : ET_DYN) ||
      e->e_ehsize != sizeof(*e) || e->e_phentsize != sizeof(Elf64_Phdr) ||
      e->e_shentsize != sizeof(Elf64_Shdr) || !e->e_phnum || e->e_phnum > 64 ||
      !e->e_shnum || e->e_shnum > 256) fail("ELF-header-contract");
  range(im, e->e_phoff, (uint64_t)e->e_phnum * sizeof(Elf64_Phdr));
  range(im, e->e_shoff, (uint64_t)e->e_shnum * sizeof(Elf64_Shdr));
  unsigned zero_loads = 0, interps = 0, entries = 0;
  for (unsigned n = 0; n < e->e_phnum; ++n) {
    Elf64_Phdr p;
    memcpy(&p, im->bytes + e->e_phoff + n * sizeof(p), sizeof(p));
    if (p.p_type == PT_TLS || (p.p_type == PT_GNU_STACK && (p.p_flags & PF_X)))
      fail("ELF-TLS-or-executable-stack");
    if (p.p_type == PT_LOAD) {
      range(im, p.p_offset, p.p_filesz);
      if (p.p_filesz > p.p_memsz || (p.p_flags & (PF_W | PF_X)) == (PF_W | PF_X))
        fail("ELF-load-contract");
      if (!p.p_offset) { im->zero_load_vaddr = p.p_vaddr & ~UINT64_C(4095); ++zero_loads; }
      if ((p.p_flags & PF_X) && e->e_entry >= p.p_vaddr &&
          e->e_entry - p.p_vaddr < p.p_filesz) ++entries;
    }
    if (p.p_type == PT_INTERP) {
      range(im, p.p_offset, p.p_filesz); ++interps;
      size_t wanted = strlen(interpreter.path) + 1;
      if (!main_image || p.p_filesz != wanted ||
          memcmp(im->bytes + p.p_offset, interpreter.path, wanted))
        fail("ELF-interpreter-path");
    }
  }
  if (zero_loads != 1 || entries != 1 || interps != (unsigned)main_image)
    fail("ELF-load-entry-interpreter");
  Elf64_Shdr names = section(im, e->e_shstrndx);
  unsigned anchors = 0;
  for (unsigned n = 0; n < e->e_shnum; ++n) {
    Elf64_Shdr s = section(im, n);
    if (!strcmp(string_at(im, &names, s.sh_name), ".rodata")) {
      range(im, s.sh_offset, s.sh_size);
      if (s.sh_type != SHT_PROGBITS || s.sh_size != 1 || im->bytes[s.sh_offset])
        fail("ELF-empty-anchor");
      im->anchor = s.sh_addr; ++anchors;
    }
  }
  if (anchors != 1) fail("ELF-anchor-count");
  if (e->e_entry != symbol(im, main_image ? "app_entry" : "interp_start") ||
      (main_image && e->e_entry != FIXED_ENTRY)) fail("ELF-entry-symbol");
  printf("{\"record\":\"image\",\"role\":\"%s\",\"path\":\"%s\","
         "\"device\":%ju,\"inode\":%ju,\"bytes\":%zu,\"entry\":\"0x%" PRIx64 "\"}\n",
         main_image ? "main" : "interpreter", path, (uintmax_t)im->st.st_dev,
         (uintmax_t)im->st.st_ino, im->size, (uint64_t)e->e_entry);
}

static bool same_file(const struct mapping *m, const struct image *im) {
  return m->file_inode == im->st.st_ino && m->file_device == im->st.st_dev;
}

static bool raw_same_file(const struct mapping *m, const struct image *im) {
  return m->inode == (uint64_t)im->st.st_ino &&
      m->dev_major == major(im->st.st_dev) && m->dev_minor == minor(im->st.st_dev);
}

static void capture_mappings(void) {
  char path[64]; snprintf(path, sizeof(path), "/proc/%d/exe", child);
  int fd = open(path, O_PATH | O_CLOEXEC); struct stat st;
  if (fd < 0 || fstat(fd, &st)) fail("owned-exe");
  if (st.st_dev != app.st.st_dev || st.st_ino != app.st.st_ino) fail("owned-exe-identity");
  close(fd);
  snprintf(path, sizeof(path), "/proc/%d/maps", child);
  FILE *f = fopen(path, "re"); if (!f) fail("owned-maps-open");
  char line[4096];
  while (fgets(line, sizeof(line), f)) {
    /* Retain unmatched mappings too: identity refusal must be diagnosable. */
    fputs("APP_NATIVE_MAP ", stdout); fputs(line, stdout);
    struct mapping m = {0};
    if (!strchr(line, '\n') ||
        sscanf(line, "%" SCNx64 "-%" SCNx64 " %4s %" SCNx64 " %x:%x %" SCNu64,
               &m.start, &m.end, m.perms, &m.offset, &m.dev_major, &m.dev_minor,
               &m.inode) != 7 || m.start >= m.end) fail("owned-maps-incomplete");
    if (!m.inode) continue;
    if (raw_same_file(&m, &app) || raw_same_file(&m, &interpreter)) {
      m.file_device = makedev(m.dev_major, m.dev_minor); m.file_inode = m.inode;
    } else {
    /* /proc/maps uses the filesystem device; btrfs stat uses a subvolume
     * device. Authenticate the actual mapped referent, never inode/path alone. */
    char referent[128];
    int length = snprintf(referent, sizeof(referent),
        "/proc/%d/map_files/%" PRIx64 "-%" PRIx64, child, m.start, m.end);
    if (length < 0 || (size_t)length >= sizeof(referent)) fail("map-file-path");
    int mapped_fd = open(referent, O_PATH | O_CLOEXEC);
    struct stat mapped_stat;
    if (mapped_fd < 0 || fstat(mapped_fd, &mapped_stat)) fail("map-file-identity");
    m.file_device = mapped_stat.st_dev; m.file_inode = mapped_stat.st_ino;
    if (close(mapped_fd)) fail("map-file-close");
    }
    printf("{\"record\":\"map-file-identity\",\"start\":\"0x%" PRIx64
           "\",\"end\":\"0x%" PRIx64 "\",\"device\":%ju,\"inode\":%ju}\n",
           m.start, m.end, (uintmax_t)m.file_device, (uintmax_t)m.file_inode);
    if (!same_file(&m, &app) && !same_file(&m, &interpreter)) continue;
    if (mapping_count == MAX_MAPS) fail("mapping-overflow");
    mappings[mapping_count++] = m;
    struct image *im = same_file(&m, &app) ? &app : &interpreter;
    if (!m.offset) {
      if (m.start < im->zero_load_vaddr) fail("mapping-bias-underflow");
      im->bias = m.start - im->zero_load_vaddr; ++im->bias_matches;
    }
    printf("{\"record\":\"mapping\",\"role\":\"%s\",\"start\":\"0x%" PRIx64
           "\",\"end\":\"0x%" PRIx64 "\",\"offset\":\"0x%" PRIx64
           "\",\"perms\":\"%.4s\",\"major\":%u,\"minor\":%u,\"inode\":%" PRIu64 "}\n",
           im == &app ? "main" : "interpreter", m.start, m.end, m.offset,
           m.perms, m.dev_major, m.dev_minor, m.inode);
  }
  if (ferror(f) || fclose(f)) fail("owned-maps-read");
  if (app.bias_matches != 1 || interpreter.bias_matches != 1 || app.bias != 0)
    fail("mapping-bias-ambiguity");
}

static void mapped(const struct image *im, uint64_t address, size_t size, bool execute) {
  unsigned matches = 0;
  for (size_t n = 0; n < mapping_count; ++n) {
    const struct mapping *m = &mappings[n];
    if (same_file(m, im) && m->start <= address && address < m->end &&
        size <= m->end - address && m->perms[0] == 'r' &&
        (!execute || m->perms[2] == 'x')) ++matches;
  }
  if (matches != 1) fail("image-address-mapping");
}

static uint64_t peek(uint64_t address) {
  errno = 0;
  long v = ptrace(PTRACE_PEEKTEXT, child, (void *)(uintptr_t)address, NULL);
  if (errno) fail("fixture-peek");
  return (uint64_t)(unsigned long)v;
}

static void log_bytes(const void *v, size_t n) {
  const unsigned char *p = v;
  for (size_t k = 0; k < n; ++k) printf("%02x", p[k]);
}

static struct user_regs_struct get_regs(const char *phase) {
  struct user_regs_struct r;
  if (ptrace(PTRACE_GETREGS, child, NULL, &r)) fail("getregs");
  printf("{\"record\":\"registers\",\"phase\":\"%s\",\"tid\":%d,"
         "\"rip\":\"0x%llx\",\"rsp\":\"0x%llx\",\"rflags\":\"0x%llx\","
         "\"orig_rax\":%llu,\"bytes\":%zu,\"hex\":\"",
         phase, child, r.rip, r.rsp, r.eflags, r.orig_rax, sizeof(r));
  log_bytes(&r, sizeof(r)); puts("\"}"); return r;
}

static struct ptrace_syscall_info syscall_info(void) {
  struct ptrace_syscall_info s = {0};
  long n = ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(s), &s);
  if (n < 0 || (size_t)n > sizeof(s)) fail("get-syscall-info");
  printf("{\"record\":\"syscall_info\",\"returned_bytes\":%ld,\"op\":%u,"
         "\"arch\":%u,\"ip\":\"0x%" PRIx64 "\",\"sp\":\"0x%" PRIx64 "\",\"hex\":\"",
         n, s.op, s.arch, (uint64_t)s.instruction_pointer, (uint64_t)s.stack_pointer);
  log_bytes(&s, sizeof(s)); puts("\"}");
  size_t needed = s.op == PTRACE_SYSCALL_INFO_ENTRY ?
      __builtin_offsetof(struct ptrace_syscall_info, entry) + sizeof(s.entry) :
      s.op == PTRACE_SYSCALL_INFO_EXIT ?
      __builtin_offsetof(struct ptrace_syscall_info, exit) + sizeof(s.exit.rval) + sizeof(s.exit.is_error) : 0;
  if (!needed || (size_t)n < needed || s.arch != AUDIT_ARCH_X86_64)
    fail("syscall-info-mode-or-short-record");
  return s;
}

static struct reading read_event(const char *phase) {
  struct reading r = {0}; ssize_t n;
  do { n = read(pmu, &r, sizeof(r)); } while (n < 0 && errno == EINTR);
  printf("{\"record\":\"pmu\",\"phase\":\"%s\",\"read_bytes\":%zd,"
         "\"value\":%" PRIu64 ",\"enabled\":%" PRIu64 ",\"running\":%" PRIu64
         ",\"id\":%" PRIu64 "}\n", phase, n, r.value, r.enabled, r.running, r.id);
  if (n != (ssize_t)sizeof(r) || r.id != event_id) fail("perf-read-or-id");
  return r;
}

static struct reading stop_counting(const char *phase) {
  if (!counting || ioctl(pmu, PERF_EVENT_IOC_DISABLE, 0)) fail("perf-disable");
  counting = false; return read_event(phase);
}

static void start_counting(void) {
  if (counting || ioctl(pmu, PERF_EVENT_IOC_ENABLE, 0)) fail("perf-enable");
  counting = true;
}

static void interval(const struct reading *before, const struct reading *after,
                     unsigned expected, const char *phase) {
  if (after->enabled < before->enabled || after->running < before->running)
    fail("perf-time-regressed");
  uint64_t dt = after->enabled - before->enabled, dr = after->running - before->running;
  printf("{\"record\":\"interval\",\"phase\":\"%s\",\"absolute_count\":%" PRIu64
         ",\"expected\":%u,\"enabled_delta\":%" PRIu64 ",\"running_delta\":%" PRIu64 "}\n",
         phase, after->value, expected, dt, dr);
  if (!dt || dt != dr || after->enabled != after->running)
    fail("perf-unscheduled-or-multiplexed");
  if (after->value != expected) semantic_fail("absolute-conditional-count");
}

static void host_profile(void) {
  unsigned a, b, c, d; char vendor[13] = {0}, brand[49] = {0};
  if (!__get_cpuid(0, &a, &b, &c, &d)) fail("cpuid-vendor");
  memcpy(vendor, &b, 4); memcpy(vendor + 4, &d, 4); memcpy(vendor + 8, &c, 4);
  if (!__get_cpuid(1, &a, &b, &c, &d)) fail("cpuid-family");
  unsigned family = (a >> 8) & 15, model = (a >> 4) & 15, stepping = a & 15;
  if (family == 6 || family == 15) model |= ((a >> 16) & 15) << 4;
  if (family == 15) family += (a >> 20) & 255;
  for (unsigned i = 0; i < 3; ++i) {
    if (!__get_cpuid(0x80000002 + i, &a, &b, &c, &d)) fail("cpuid-brand");
    memcpy(brand + i * 16, &a, 4); memcpy(brand + i * 16 + 4, &b, 4);
    memcpy(brand + i * 16 + 8, &c, 4); memcpy(brand + i * 16 + 12, &d, 4);
  }
  if (strcmp(vendor, "AuthenticAMD") || family != 0x1a || model != 0x11 ||
      !strstr(brand, "AMD EPYC 9D85")) fail("unsupported-PMU-profile");
  cpu_set_t cpus; if (sched_getaffinity(0, sizeof(cpus), &cpus)) fail("affinity");
  printf("{\"record\":\"host\",\"vendor\":\"AuthenticAMD\",\"family\":%u,"
         "\"model\":%u,\"stepping\":%u,\"allowed_cpus\":[", family, model, stepping);
  bool first = true;
  for (unsigned i = 0; i < CPU_SETSIZE; ++i) if (CPU_ISSET(i, &cpus)) {
    printf("%s%u", first ? "" : ",", i); first = false;
  }
  puts("]}");
}

static void check_state(const struct user_regs_struct *r, unsigned phase,
                        uint64_t after_pc) {
  const uint64_t iterations[] = {3, 2, 5, 0}, flow[] = {0x11, 0x22, 0x35, 0x40};
  uint64_t helper = interpreter.bias + symbol(&interpreter, "interp_helper");
  if (r->rbx != UINT64_C(0x1122334455667701) ||
      r->rbp != UINT64_C(0x1122334455667705) ||
      r->r12 != UINT64_C(0x112233445566770a) ||
      r->r14 != UINT64_C(0x112233445566770c) ||
      r->r13 != (phase == 0 ? UINT64_C(0x112233445566770b) : helper) ||
      r->rsp != initial_rsp || r->r15 != initial_rsp ||
      r->cs != initial_cs || r->ss != initial_ss ||
      r->eflags != EXPECTED_FLAGS || r->r11 != EXPECTED_FLAGS ||
      r->rip != after_pc || r->rcx != after_pc ||
      r->r8 != iterations[phase] || r->r9 != flow[phase])
    semantic_fail("sample-nonclobbered-state");
}

static void validate_entry(const struct user_regs_struct *r,
                           const struct ptrace_syscall_info *s, unsigned phase) {
  const char *names[] = {"sample_prefix", "sample_main", "sample_helper", "sample_zero"};
  const char *afters[] = {"sample_prefix_after", "sample_main_after", "sample_helper_after", "sample_zero_after"};
  const struct image *im = phase == 0 ? &interpreter : &app;
  uint64_t pc = im->bias + symbol(im, names[phase]);
  uint64_t after = im->bias + symbol(im, afters[phase]);
  if (after != pc + 2) fail("ELF-syscall-width");
  mapped(im, pc, 2, true); mapped(im, im->bias + im->anchor, 1, false);
  if ((peek(pc) & 0xffff) != 0x050f || (peek(im->bias + im->anchor) & 255))
    fail("mapped-fixture-opcode-or-anchor");
  if (s->op != PTRACE_SYSCALL_INFO_ENTRY || s->entry.nr != SYS_write ||
      r->orig_rax != SYS_write || s->instruction_pointer != after ||
      s->stack_pointer != initial_rsp || r->rdi != 1 || r->rdx != 0 ||
      r->rsi != im->bias + im->anchor || r->r10 != TAG_FIRST + phase)
    semantic_fail("unexpected-application-syscall");
  const uint64_t args[] = {r->rdi, r->rsi, r->rdx, r->r10, r->r8, r->r9};
  for (unsigned n = 0; n < 6; ++n)
    if (args[n] != s->entry.args[n]) fail("syscall-info-register-join");
  check_state(r, phase, after);
  printf("{\"record\":\"sample\",\"ordinal\":%u,\"tag\":%" PRIu64
         ",\"image\":\"%s\",\"pc\":\"0x%" PRIx64 "\",\"image_offset\":\"0x%" PRIx64 "\"}\n",
         phase + 1, (uint64_t)r->r10, phase == 0 ? "interpreter" : "main", pc, pc - im->bias);
}

static void syscall_stop(int status) {
  if (!WIFSTOPPED(status) || WSTOPSIG(status) != (SIGTRAP | 0x80) ||
      ((unsigned)status >> 16)) {
    if (child > 0 && WIFSTOPPED(status)) {
      siginfo_t s = {0}; (void)get_regs("unexpected-stop");
      if (!ptrace(PTRACE_GETSIGINFO, child, NULL, &s)) {
        printf("{\"record\":\"unexpected-siginfo\",\"bytes\":%zu,\"hex\":\"", sizeof(s));
        log_bytes(&s, sizeof(s)); puts("\"}");
      }
    }
    fail("unexpected-signal-event-or-terminal");
  }
}

int main(int argc, char **argv) {
  if (argc != 5) {
    fputs("usage: native-observer APP_ABS INTERPRETER_ABS FRESH_STDOUT FRESH_STDERR\n", stderr);
    return 125;
  }
  if (atexit(cleanup)) return 125;
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (sysconf(_SC_PAGESIZE) != 4096) fail("page-size");
  for (int n = 0; n < 3; ++n) if (fcntl(n, F_GETFD) < 0) fail("controller-stdio-closed");
  struct sigaction action = {0}; action.sa_handler = on_signal; sigemptyset(&action.sa_mask);
  if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)) fail("signal-setup");
  action.sa_handler = SIG_DFL;
  if (sigaction(SIGCHLD, &action, NULL)) fail("SIGCHLD-setup");
  host_profile();
  /* Load interpreter first so the main's literal PT_INTERP is authenticated. */
  load_image(&interpreter, argv[2], false); load_image(&app, argv[1], true);
  if (app.st.st_dev == interpreter.st.st_dev && app.st.st_ino == interpreter.st.st_ino)
    fail("images-not-distinct");
  guest_out = open(argv[3], O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  guest_err = open(argv[4], O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (guest_out < 0 || guest_err < 0) fail("guest-output-open");
  deadline_ms = now_ms() + 15000; fflush(NULL);
  child = fork(); if (child < 0) fail("fork");
  if (!child) {
    struct sigaction reset = {0}; reset.sa_handler = SIG_DFL; sigemptyset(&reset.sa_mask);
    if (sigaction(SIGINT, &reset, NULL) || sigaction(SIGTERM, &reset, NULL)) _exit(125);
    sigset_t empty; sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, NULL) || dup2(guest_out, 1) < 0 ||
        dup2(guest_err, 2) < 0 || ptrace(PTRACE_TRACEME, 0, NULL, NULL)) _exit(125);
    close(guest_out); close(guest_err);
    if (raise(SIGSTOP)) _exit(125);
    char *args[] = {argv[1], NULL};
    char *env[] = {"LC_ALL=C", "TZ=UTC", NULL};
    execve(argv[1], args, env); _exit(125);
  }
  int status = wait_owned();
  if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) fail("initial-stop");
  unsigned long options = PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL;
  if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)options)) fail("ptrace-options");
  resume(false); status = wait_owned();
  if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP ||
      ((unsigned)status >> 16) != PTRACE_EVENT_EXEC) fail("exec-stop");
  struct user_regs_struct r = get_regs("exec-before-interpreter");
  capture_mappings();
  uint64_t entry = interpreter.bias + interpreter.eh.e_entry;
  mapped(&interpreter, entry, 1, true); mapped(&app, FIXED_ENTRY, 1, true);
  mapped(&interpreter, interpreter.bias + symbol(&interpreter, "interp_helper"), 1, true);
  if (r.rip != entry || !r.rsp || r.orig_rax != SYS_execve) fail("exec-entry-context");
  initial_rsp = r.rsp; initial_cs = r.cs; initial_ss = r.ss;
  struct perf_event_attr attr = {0};
  attr.size = sizeof(attr); attr.type = PERF_TYPE_RAW; attr.config = UINT64_C(0x5100d1);
  attr.disabled = 1; attr.pinned = 1; attr.exclude_kernel = 1;
  attr.exclude_hv = 1; attr.exclude_guest = 1;
  attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING | PERF_FORMAT_ID;
  pmu = (int)syscall(SYS_perf_event_open, &attr, child, -1, -1, PERF_FLAG_FD_CLOEXEC);
  if (pmu < 0 || ioctl(pmu, PERF_EVENT_IOC_ID, &event_id)) fail("perf-open-id");
  printf("{\"record\":\"pmu-attributes\",\"tid\":%d,\"cpu\":-1,\"id\":%" PRIu64
         ",\"bytes\":%zu,\"hex\":\"", child, event_id, sizeof(attr));
  log_bytes(&attr, sizeof(attr)); puts("\"}");
  if (ioctl(pmu, PERF_EVENT_IOC_RESET, 0)) fail("perf-reset-once-at-exec");
  struct reading baseline = read_event("exec-reset");
  if (baseline.value || baseline.enabled || baseline.running) fail("perf-reset-not-fresh");
  start_counting(); resume(true); status = wait_owned();
  struct reading sample = stop_counting("first-stop"); syscall_stop(status);
  r = get_regs("first-syscall-stop"); struct ptrace_syscall_info si = syscall_info();
  /* Some kernels expose the original execve exit before any app instruction.
   * This exact setup stop is not an application sample or a prefix reset. */
  if (si.op == PTRACE_SYSCALL_INFO_EXIT) {
    if (r.orig_rax != SYS_execve || r.rax != 0 || si.exit.rval != 0 || si.exit.is_error ||
        r.rip != entry || r.rsp != initial_rsp || si.instruction_pointer != entry ||
        si.stack_pointer != initial_rsp || sample.value != 0 || sample.enabled != sample.running)
      fail("inherited-execve-exit");
    puts("{\"record\":\"setup-execve-exit\",\"count\":0,\"prefix_reset\":false}");
    baseline = sample;
    start_counting(); resume(true); status = wait_owned();
    sample = stop_counting("first-app-entry"); syscall_stop(status);
    r = get_regs("first-app-entry"); si = syscall_info();
  }
  const unsigned expected[] = {3, 5, 10, 10};
  for (unsigned phase = 0; phase < 4; ++phase) {
    validate_entry(&r, &si, phase); interval(&baseline, &sample, expected[phase], "write-entry");
    resume(true); status = wait_owned(); syscall_stop(status);
    struct user_regs_struct after = get_regs("write-exit");
    struct ptrace_syscall_info end = syscall_info();
    if (end.op != PTRACE_SYSCALL_INFO_EXIT || end.exit.rval || end.exit.is_error ||
        after.rax || after.orig_rax != SYS_write || end.instruction_pointer != r.rip ||
        end.stack_pointer != initial_rsp || after.rdi != r.rdi || after.rsi != r.rsi ||
        after.rdx != r.rdx || after.r10 != r.r10) semantic_fail("zero-write-return");
    check_state(&after, phase, r.rip);
    struct reading disabled = read_event("write-exit-disabled");
    if (memcmp(&sample, &disabled, sizeof(sample))) fail("perf-counted-through-syscall");
    baseline = sample;
    start_counting(); resume(true); status = wait_owned();
    sample = stop_counting(phase == 3 ? "terminal-entry" : "next-write-entry");
    syscall_stop(status); r = get_regs(phase == 3 ? "terminal-entry" : "next-write-entry");
    si = syscall_info();
  }
  uint64_t exit_pc = app.bias + symbol(&app, "terminal_exit");
  mapped(&app, exit_pc, 2, true);
  if ((peek(exit_pc) & 0xffff) != 0x050f || si.op != PTRACE_SYSCALL_INFO_ENTRY ||
      si.entry.nr != SYS_exit || r.orig_rax != SYS_exit || r.rdi != 0 ||
      r.r10 != TAG_EXIT || r.rip != exit_pc + 2 || si.instruction_pointer != r.rip ||
      si.stack_pointer != initial_rsp) semantic_fail("terminal-syscall");
  check_state(&r, 3, exit_pc + 2); interval(&baseline, &sample, 10, "before-terminal-exit");
  /* PMU remains disabled across SYS_exit; no application signal is forwarded. */
  resume(false); status = wait_owned();
  if (!WIFEXITED(status) || WEXITSTATUS(status)) semantic_fail("terminal-status");
  struct stat out, err;
  if (fstat(guest_out, &out) || fstat(guest_err, &err)) fail("guest-output-stat");
  printf("{\"record\":\"terminal\",\"status\":%d,\"stdout_bytes\":%jd,"
         "\"stderr_bytes\":%jd,\"final_count\":%" PRIu64 "}\n",
         status, (intmax_t)out.st_size, (intmax_t)err.st_size, sample.value);
  if (out.st_size || err.st_size) semantic_fail("guest-output-not-empty");
  puts("{\"record\":\"complete\",\"native_reference\":true,\"samples\":[3,5,10,10],"
       "\"intervals\":[3,2,5,0],\"final\":10,\"exit\":0}");
  return 0;
}
