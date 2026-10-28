#include "dr_api.h"
extern int parent_value(void);
#ifndef INDIRECT_ONLY
extern int leaf_value(void);
#endif

/* Also callable through native dlopen: the identical ELF dependency graph. */
DR_EXPORT int fixture_value(void) {
#ifdef INDIRECT_ONLY
  return parent_value();
#else
  return parent_value() * 1000 + leaf_value();
#endif
}

static void emit_value(int value) {
  char out[] = "LOADER_VALUE=000000\n";
  for (int pos = 18; pos >= 13; --pos) {
    out[pos] = '0' + value % 10;
    value /= 10;
  }
  /* A syscall avoids adding a libc dependency to this tiny client. */
  __asm__ volatile("syscall"
                   :
                   : "a"(1L), "D"(2L), "S"(out), "d"((long)(sizeof(out) - 1))
                   : "rcx", "r11", "memory");
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[]) {
  (void)id;
  (void)argc;
  (void)argv;
  emit_value(fixture_value());
}
