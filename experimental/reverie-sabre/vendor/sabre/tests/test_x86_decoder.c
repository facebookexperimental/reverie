/* Copyright © 2026 Software Reliability Group, Imperial College London
 *
 * This file is part of SaBRe.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} -I%S/../includes -I%S/../arch/x86_64 %S/../arch/x86_64/x86_decoder.c %s -o %t
 * RUN: %t
 */

#if defined(__x86_64__) || defined(__i386__)

#include "rewriter_safe_insn.h"
#include "x86_decoder.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>

static void check_instruction_mode(const unsigned char *bytes, size_t len,
                                   unsigned short expected, bool is64bit) {
  const char *next = (const char *)bytes;
  unsigned short decoded =
      next_inst(&next, is64bit, NULL, NULL, NULL, NULL, NULL);

  assert(decoded == expected);
  assert(next == (const char *)bytes + len);
}

static void check_instruction(const unsigned char *bytes, size_t len,
                              unsigned short expected) {
  check_instruction_mode(bytes, len, expected, true);
}

static void check_vector_instruction(const unsigned char *bytes, size_t len,
                                     unsigned short expected,
                                     size_t mod_rm_offset) {
  const char *next = (const char *)bytes;
  bool has_prefix = false;
  char *rex = (char *)bytes;
  char *mod_rm = NULL;
  unsigned short decoded =
      next_inst(&next, true, &has_prefix, &rex, &mod_rm, NULL, NULL);

  assert(decoded == expected);
  assert(next == (const char *)bytes + len);
  assert(has_prefix);
  assert(rex == NULL);
  assert(mod_rm == (char *)bytes + mod_rm_offset);
  assert(!is_safe_insn(decoded));
}

static void check_stream_has_no_syscall(const unsigned char *bytes,
                                        size_t len) {
  const char *next = (const char *)bytes;
  const char *end = next + len;
  while (next < end) {
    unsigned short decoded =
        next_inst(&next, true, NULL, NULL, NULL, NULL, NULL);
    assert(decoded != 0x0f05);
  }
  assert(next == end);
}

static void check_32bit_opcode_does_not_read_ahead(void) {
  long page_size = sysconf(_SC_PAGESIZE);
  assert(page_size > 0);
  unsigned char *pages =
      mmap(NULL, (size_t)page_size * 2, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(pages != MAP_FAILED);
  assert(mprotect(pages + page_size, (size_t)page_size, PROT_NONE) == 0);

  pages[page_size - 1] = 0x90; // NOP at the last readable byte.
  check_instruction_mode(pages + page_size - 1, 1, 0x90, false);

  assert(munmap(pages, (size_t)page_size * 2) == 0);
}

int main(void) {
  static const unsigned char movq_to_xmm[] = {0x66, 0x48, 0x0f, 0x6e, 0xc7};
  static const unsigned char unpack_qwords[] = {0x66, 0x0f, 0x6c, 0xc0};
  static const unsigned char store_unaligned[] = {0x0f, 0x11, 0x83, 0xd8,
                                                  0x02, 0x00, 0x00};
  static const unsigned char vex_load_unaligned[] = {0xc5, 0xfe, 0x6f,
                                                     0x4c, 0x16, 0x45};
  static const unsigned char vex_store_unaligned[] = {0xc5, 0xfe, 0x7f, 0x57,
                                                      0x41};
  static const unsigned char vex_zero_upper[] = {0xc5, 0xf8, 0x77};
  static const unsigned char vex_shuffle_imm[] = {0xc5, 0xfd, 0x70, 0xc0, 0x0f};
  static const unsigned char vex_shift_imm[] = {0xc5, 0xfd, 0x71, 0xd0, 0x0f};
  static const unsigned char vex_compare_imm[] = {0xc5, 0xfc, 0xc2, 0xc0, 0x0f};
  static const unsigned char vex3_map0f_imm[] = {0xc4, 0xe1, 0x7d,
                                                 0x70, 0xc0, 0x0f};
  static const unsigned char vex3_map38[] = {0xc4, 0xe2, 0x75, 0x3b, 0xe0};
  static const unsigned char vex3_map3a_imm[] = {0xc4, 0xe3, 0x79,
                                                 0x0f, 0xc0, 0x08};
  static const unsigned char evex_map0f[] = {0x62, 0xf1, 0x7d,
                                             0x48, 0x6f, 0x00};
  static const unsigned char evex_map38_sib_disp[] = {0x62, 0xf2, 0x7d, 0x48,
                                                      0x7c, 0x44, 0x24, 0x20};
  static const unsigned char evex_map3a_imm[] = {0x62, 0xf3, 0x7d, 0x48,
                                                 0x0f, 0xc0, 0x08};
  static const unsigned char legacy_lds[] = {0xc5, 0x00};
  static const unsigned char legacy_les[] = {0xc4, 0x00};
  static const unsigned char legacy_bound[] = {0x62, 0x00};
  static const unsigned char glibc_avx_syscall_lookalike[] = {
      0x0f, 0xbc, 0xc9, 0xc5, 0xfe, 0x6f, 0x4c, 0x0e, 0x05, 0xc5,
      0xfe, 0x7f, 0x4c, 0x0f, 0x05, 0xc5, 0xf8, 0x77, 0xc3};
  static const unsigned char vector_immediate_syscall_lookalike[] = {
      0xc5, 0xfd, 0x70, 0xc0, 0x0f, 0x05, 0x00, 0x00, 0x00, 0x00, 0xc5,
      0xfc, 0xc2, 0xc0, 0x0f, 0x05, 0x00, 0x00, 0x00, 0x00, 0xc4, 0xe1,
      0x7d, 0x70, 0xc0, 0x0f, 0x05, 0x00, 0x00, 0x00, 0x00, 0xc3};

  check_instruction(movq_to_xmm, sizeof(movq_to_xmm), 0x0f6e);
  check_instruction(unpack_qwords, sizeof(unpack_qwords), 0x0f6c);
  check_instruction(store_unaligned, sizeof(store_unaligned), 0x0f11);
  check_vector_instruction(vex_load_unaligned, sizeof(vex_load_unaligned),
                           0xc56f, 3);
  check_vector_instruction(vex_store_unaligned, sizeof(vex_store_unaligned),
                           0xc57f, 3);
  check_instruction(vex_zero_upper, sizeof(vex_zero_upper), 0xc577);
  check_vector_instruction(vex_shuffle_imm, sizeof(vex_shuffle_imm), 0xc570, 3);
  check_vector_instruction(vex_shift_imm, sizeof(vex_shift_imm), 0xc571, 3);
  check_vector_instruction(vex_compare_imm, sizeof(vex_compare_imm), 0xc5c2, 3);
  check_vector_instruction(vex3_map0f_imm, sizeof(vex3_map0f_imm), 0xc470, 4);
  check_vector_instruction(vex3_map38, sizeof(vex3_map38), 0xc43b, 4);
  check_vector_instruction(vex3_map3a_imm, sizeof(vex3_map3a_imm), 0xc40f, 4);
  check_vector_instruction(evex_map0f, sizeof(evex_map0f), 0x626f, 5);
  check_vector_instruction(evex_map38_sib_disp, sizeof(evex_map38_sib_disp),
                           0x627c, 5);
  check_vector_instruction(evex_map3a_imm, sizeof(evex_map3a_imm), 0x620f, 5);
  check_instruction_mode(vex_load_unaligned, sizeof(vex_load_unaligned), 0xc56f,
                         false);
  check_instruction_mode(vex3_map38, sizeof(vex3_map38), 0xc43b, false);
  check_instruction_mode(evex_map0f, sizeof(evex_map0f), 0x626f, false);
  check_instruction_mode(legacy_lds, sizeof(legacy_lds), 0xc5, false);
  check_instruction_mode(legacy_les, sizeof(legacy_les), 0xc4, false);
  check_instruction_mode(legacy_bound, sizeof(legacy_bound), 0x62, false);
  check_stream_has_no_syscall(glibc_avx_syscall_lookalike,
                              sizeof(glibc_avx_syscall_lookalike));
  check_stream_has_no_syscall(vector_immediate_syscall_lookalike,
                              sizeof(vector_immediate_syscall_lookalike));
  check_32bit_opcode_does_not_read_ahead();
  assert(is_safe_insn(0x01));
  assert(is_safe_insn(0x0f1f));
  assert(!is_safe_insn(0xc43b));
  return 0;
}

#else

int main(void) { return 0; }

#endif
