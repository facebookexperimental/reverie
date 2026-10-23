/* Exercise the actual selected-map finalizer guard and ELF callback order.
 * No Hermit guest or syscall comparator is replaced by this fixture. */
#define _GNU_SOURCE 1
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../vendor/sabre/loader/premain.c"

static bool domain;
static char sequence[8];
static size_t used;
static bool get_domain(void) {
  return domain;
}
static void enter_domain(void) {
  domain = true;
}
static void exit_domain(void) {
  domain = false;
}
calling_from_plugin_fn calling_from_plugin = get_domain;
enter_plugin_fn enter_plugin = enter_domain;
exit_plugin_fn exit_plugin = exit_domain;
static void record(char value) {
  assert(domain);
  assert(used < sizeof(sequence) - 1);
  sequence[used++] = value;
}
static void first(void) {
  record('1');
}
static void second(void) {
  record('2');
}
static void last(void) {
  record('F');
}
static void guest(void) {
  assert(!domain);
}

int main(int argc, char** argv) {
  assert(argc == 2);
  const char* mode = argv[1];
  bool prior = strcmp(mode, "prior-plugin") == 0;
  bool array = strcmp(mode, "fini-only") != 0 && strcmp(mode, "empty") != 0;
  bool fini = strcmp(mode, "array-only") != 0 && strcmp(mode, "empty") != 0;
  bool zero = strcmp(mode, "zero-array") == 0;
  plugin_fini_fn originals[] = {first, second};
  ElfW(Dyn) array_entry = {.d_tag = DT_FINI_ARRAY};
  ElfW(Dyn) size_entry = {.d_tag = DT_FINI_ARRAYSZ};
  ElfW(Dyn) fini_entry = {.d_tag = DT_FINI};
  struct ld_link_map before = {.l_addr = 0x1000};
  struct ld_link_map selected = {.l_addr = 0x2000};
  struct ld_link_map after = {.l_addr = 0x3000};
  before.l_next = (struct link_map*)&selected;
  selected.l_prev = (struct link_map*)&before;
  selected.l_next = (struct link_map*)&after;
  after.l_prev = (struct link_map*)&selected;
  array_entry.d_un.d_ptr = (ElfW(Addr))originals - selected.l_addr;
  size_entry.d_un.d_val = zero ? 0 : sizeof(originals);
  fini_entry.d_un.d_ptr = (ElfW(Addr))last - selected.l_addr;
  if (array) {
    selected.l_info[DT_FINI_ARRAY] = &array_entry;
    selected.l_info[DT_FINI_ARRAYSZ] = &size_entry;
  }
  if (fini)
    selected.l_info[DT_FINI] = &fini_entry;
  struct ld_link_map before_copy = before, after_copy = after;
  if (strcmp(mode, "bad-size") == 0)
    size_entry.d_un.d_val = sizeof(originals) - 1;
  if (strcmp(mode, "missing-size") == 0)
    selected.l_info[DT_FINI_ARRAYSZ] = NULL;
  if (strcmp(mode, "duplicate-map") == 0)
    before.l_addr = selected.l_addr;
  uintptr_t base = strcmp(mode, "missing-map") == 0 ? 0x4000 : selected.l_addr;

  guest();
  domain = prior;
  guard_plugin_finalizers(&after, base);
  assert(memcmp(&before, &before_copy, sizeof(before)) == 0);
  assert(memcmp(&after, &after_copy, sizeof(after)) == 0);
  assert(domain == prior);
  struct ld_link_map installed = selected;
  guard_plugin_finalizers(&selected, base);
  assert(memcmp(&selected, &installed, sizeof(selected)) == 0);
  if (array || fini) {
    assert(selected.l_info[DT_FINI_ARRAY] == NULL);
    assert(selected.l_info[DT_FINI_ARRAYSZ] == NULL);
    ((plugin_fini_fn)(selected.l_addr +
                      selected.l_info[DT_FINI]->d_un.d_ptr))();
  } else {
    assert(selected.l_info[DT_FINI] == NULL);
  }
  assert(domain == prior);
  assert(
      strcmp(
          sequence,
          !array || zero ? (fini ? "F" : "") : (fini ? "21F" : "21")) == 0);
  domain = false;
  guest();
  printf("PASS %s\n", mode);
  return 0;
}
