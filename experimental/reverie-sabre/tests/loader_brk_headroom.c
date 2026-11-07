/* Load a client ELF with the actual loader's elfld_load_elf into this process
 * (nothing is executed) and measure the free space left above a PIE image,
 * where the client's program break starts. */
#define _GNU_SOURCE 1
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include "../vendor/sabre/loader/elf_loading.c"

/* The headroom the loader first tries (64 GiB). */
#define FIRST_HEADROOM ((size_t)1 << 36)

static uintptr_t image_end_of(const ElfW(Ehdr) * ehdr, int fd, uintptr_t bias,
                              size_t pagesize) {
  ElfW(Phdr) phdr[MAX_PHNUM];
  ssize_t got = pread(fd, phdr, sizeof(phdr[0]) * ehdr->e_phnum, ehdr->e_phoff);
  assert(got == (ssize_t)(sizeof(phdr[0]) * ehdr->e_phnum));
  uintptr_t end = 0;
  for (int i = 0; i < ehdr->e_phnum; i++)
    if (phdr[i].p_type == PT_LOAD && phdr[i].p_vaddr + phdr[i].p_memsz > end)
      end = phdr[i].p_vaddr + phdr[i].p_memsz;
  return round_up(bias + end, pagesize);
}

/* The free bytes from `address` (the image's page-rounded end) to the next
 * mapping above it. Fails if a mapping contains `address`, or if no mapping
 * ends exactly there (the image's last page). */
static uintptr_t gap_above(uintptr_t address) {
  FILE *maps = fopen("/proc/self/maps", "r");
  assert(maps != NULL);
  uintptr_t next = UINTPTR_MAX;
  int image_ends_here = 0;
  char line[512];
  while (fgets(line, sizeof(line), maps)) {
    unsigned long start, end;
    if (sscanf(line, "%lx-%lx", &start, &end) != 2)
      continue;
    assert(!(start <= address && address < end));
    if (start >= address && start < next)
      next = start;
    if (end == address)
      image_ends_here = 1;
  }
  fclose(maps);
  assert(image_ends_here);
  return next - address;
}

/* Free address space at `address` for `length` bytes. */
static int range_is_free(uintptr_t address, size_t length) {
  FILE *maps = fopen("/proc/self/maps", "r");
  assert(maps != NULL);
  int free_range = 1;
  char line[512];
  while (fgets(line, sizeof(line), maps)) {
    unsigned long start, end;
    if (sscanf(line, "%lx-%lx", &start, &end) == 2 && start < address + length &&
        address < end)
      free_range = 0;
  }
  fclose(maps);
  return free_range;
}

static size_t vm_size_bytes(void) {
  FILE *status = fopen("/proc/self/status", "r");
  assert(status != NULL);
  char line[256];
  size_t kib = 0;
  while (fgets(line, sizeof(line), status))
    if (sscanf(line, "VmSize: %zu kB", &kib) == 1)
      break;
  fclose(status);
  assert(kib != 0);
  return kib * 1024;
}

int main(int argc, char **argv) {
  assert(argc == 3);
  const char *mode = argv[1];
  size_t pagesize = (size_t)sysconf(_SC_PAGESIZE);
  struct rlimit inherited;
  assert(getrlimit(RLIMIT_AS, &inherited) == 0);
  int unlimited = inherited.rlim_cur == RLIM_INFINITY;
  if (strcmp(mode, "pie-limited") == 0) {
    /* Room for the image but not for 64 GiB of headroom; never raise the
     * inherited limit. */
    rlim_t want = vm_size_bytes() + ((size_t)3 << 30);
    struct rlimit limit = inherited;
    if (unlimited || want < limit.rlim_cur)
      limit.rlim_cur = want;
    assert(setrlimit(RLIMIT_AS, &limit) == 0);
  }
  if (strcmp(mode, "exec") == 0)
    assert(range_is_free(0x20000000, (size_t)1 << 24) &&
           "the fixed-address fixture's range is already mapped");
  int fd = open(argv[2], O_RDONLY);
  assert(fd >= 0);
  ElfW(Ehdr) ehdr;
  assert(elfld_getehdr(fd, &ehdr) == 0);
  ElfW(Addr) phdr = 0, phnum = 0;
  const char *interp = NULL;
  ElfW(Addr) entry = elfld_load_elf(fd, &ehdr, pagesize, &phdr, &phnum, &interp);
  uintptr_t bias = entry - ehdr.e_entry;
  uintptr_t image_end = image_end_of(&ehdr, fd, bias, pagesize);
  uintptr_t gap = gap_above(image_end);
  if (ehdr.e_type == ET_DYN) {
    /* A later top-down mapping lands at the top of the free space, not just
     * above the image. */
    void *later = mmap(NULL, pagesize, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS,
                       -1, 0);
    assert(later != MAP_FAILED);
    assert((uintptr_t)later > image_end);
    assert(gap_above(image_end) >= gap - pagesize);
  }
  if (strcmp(mode, "exec") == 0) {
    /* A fixed-address client keeps its link-time addresses. */
    assert(ehdr.e_type == ET_EXEC && bias == 0);
    printf("PASS exec bias=0\n");
  } else if (strcmp(mode, "pie") == 0) {
    assert(ehdr.e_type == ET_DYN);
    if (unlimited) {
      assert(gap >= FIRST_HEADROOM);
      printf("PASS pie gap>=64GiB\n");
    } else {
      /* An inherited RLIMIT_AS already makes the loader halve. */
      assert(gap >= pagesize);
      printf("PASS pie gap=%zuMiB (inherited RLIMIT_AS)\n", (size_t)(gap >> 20));
    }
  } else {
    assert(ehdr.e_type == ET_DYN);
    assert(gap >= pagesize && gap < FIRST_HEADROOM);
    printf("PASS pie-limited gap=%zuMiB\n", (size_t)(gap >> 20));
  }
  return 0;
}
