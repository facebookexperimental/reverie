/* Exercise the actual x86_64 detour postamble relocation on synthetic
 * function prologues. The prologues are decoded with the real SaBRe decoder
 * exactly as api_detour_func does, then copied by the real copy_postamble into
 * a different buffer. Nothing is executed and no Hermit guest is involved. */
#define _GNU_SOURCE 1
#include "../vendor/sabre/arch/x86_64/rewriter.c"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>

/* One arena keeps the original and relocated copies within rel32 range. */
static char arena[8192];
#define ORIGINAL (arena + 64)
#define RELOCATED (arena + 4096 + 64)

struct prologue {
  const char *name;
  const unsigned char *bytes;
  size_t len;
  /* The instruction whose RIP-relative operand must be relocated. */
  size_t rip_insn;
  unsigned short opcode;
  size_t disp_offset;
};

/* glibc 2.39 (Ubuntu 24.04) __GI___getrandom:
 *   endbr64
 *   cmpb $0x0,0x1c37e5(%rip)   # __libc_single_threaded_internal
 *   je   ... */
static const unsigned char getrandom_239[] = {
    0xf3, 0x0f, 0x1e, 0xfa, 0x80, 0x3d, 0xe5, 0x37, 0x1c, 0x00, 0x00};
/* cmpb $0x7f,-0x1234(%rip); a negative displacement and a nonzero imm8. */
static const unsigned char cmpb_negative[] = {0x80, 0x3d, 0xcc, 0xed,
                                              0xff, 0xff, 0x7f, 0x90};
/* cmpb $0x0,0x800(%rip): the 4 KiB move turns this displacement into
 * -0x800, which changes its upper 16 bits, so a relocation that kept only the
 * low 16 bits fails here. */
static const unsigned char cmpb_borrow[] = {0x80, 0x3d, 0x00, 0x08,
                                            0x00, 0x00, 0x00, 0x90};
/* cmpl $0x5,0x2000(%rip) */
static const unsigned char cmpl_imm8[] = {0x83, 0x3d, 0x00, 0x20,
                                          0x00, 0x00, 0x05, 0x90};
/* cmpl $0x11223344,0x3000(%rip) */
static const unsigned char cmpl_imm32[] = {0x81, 0x3d, 0x00, 0x30, 0x00,
                                           0x00, 0x44, 0x33, 0x22, 0x11};
/* cmpq $0x0,0x40(%rip): REX.W moves the displacement to offset 3. */
static const unsigned char cmpq_rex[] = {0x48, 0x83, 0x3d, 0x40,
                                         0x00, 0x00, 0x00, 0x00};
/* cmpw $0x1234,0x40(%rip): 0x66 moves the displacement and shrinks imm. */
static const unsigned char cmpw_opsize[] = {0x66, 0x81, 0x3d, 0x40, 0x00,
                                            0x00, 0x00, 0x34, 0x12};
/* cmpb $0x1,%fs:0x40(%rip): a segment prefix on the byte form. */
static const unsigned char cmpb_segment[] = {0x64, 0x80, 0x3d, 0x40,
                                             0x00, 0x00, 0x00, 0x01};

static const struct prologue prologues[] = {
    {"getrandom-2.39", getrandom_239, sizeof(getrandom_239), 1, 0x80, 2},
    {"cmpb-negative", cmpb_negative, sizeof(cmpb_negative), 0, 0x80, 2},
    {"cmpb-borrow", cmpb_borrow, sizeof(cmpb_borrow), 0, 0x80, 2},
    {"cmpl-imm8", cmpl_imm8, sizeof(cmpl_imm8), 0, 0x83, 2},
    {"cmpl-imm32", cmpl_imm32, sizeof(cmpl_imm32), 0, 0x81, 2},
    {"cmpq-rex", cmpq_rex, sizeof(cmpq_rex), 0, 0x83, 3},
    {"cmpw-opsize", cmpw_opsize, sizeof(cmpw_opsize), 0, 0x81, 3},
    {"cmpb-segment", cmpb_segment, sizeof(cmpb_segment), 0, 0x80, 3},
};

static int32_t read_disp(const char *at) {
  int32_t value;
  memcpy(&value, at, sizeof(value));
  return value;
}

int main(int argc, char **argv) {
  assert(argc == 2);
  /* The refusal cases may reach an assertion on an unfixed rewriter. */
  struct rlimit no_core = {0, 0};
  assert(setrlimit(RLIMIT_CORE, &no_core) == 0);
  const struct prologue *p = NULL;
  for (size_t i = 0; i < sizeof(prologues) / sizeof(prologues[0]); i++)
    if (strcmp(argv[1], prologues[i].name) == 0)
      p = &prologues[i];
  assert(p != NULL);

  memset(arena, 0xcc, sizeof(arena));
  memcpy(ORIGINAL, p->bytes, p->len);

  /* Decode the way api_detour_func and detour_func do. */
  struct s_code code[JUMP_SIZE] = {{0}};
  char *next = ORIGINAL;
  size_t count = 0;
  while (next < ORIGINAL + p->len) {
    assert(count < JUMP_SIZE);
    char *mod_rm = NULL;
    code[count].addr = next;
    code[count].insn =
        next_inst((const char **)&next, true, 0, 0, &mod_rm, 0, 0);
    code[count].len = next - code[count].addr;
    code[count].is_ip_relative = mod_rm && (*mod_rm & 0xC7) == 0x5;
    count++;
  }
  assert(next == ORIGINAL + p->len);
  assert(p->rip_insn < count);
  const struct s_code *target = &code[p->rip_insn];
  assert(target->insn == p->opcode);
  assert(target->is_ip_relative);
  int second = (int)p->rip_insn;

  copy_postamble(RELOCATED, code, second);

  /* Every earlier instruction is copied verbatim. */
  size_t prefix = target->addr - ORIGINAL;
  assert(memcmp(RELOCATED, ORIGINAL, prefix) == 0);

  /* The relocated instruction keeps its length, opcode, ModRM and
   * immediate, and still addresses the same absolute location. */
  const char *orig = target->addr;
  const char *moved = RELOCATED + prefix;
  size_t len = target->len;
  assert(memcmp(moved, orig, p->disp_offset) == 0);
  size_t after = p->disp_offset + sizeof(int32_t);
  assert(memcmp(moved + after, orig + after, len - after) == 0);
  intptr_t original_target =
      (intptr_t)(orig + len) + read_disp(orig + p->disp_offset);
  intptr_t relocated_target =
      (intptr_t)(moved + len) + read_disp(moved + p->disp_offset);
  assert(relocated_target == original_target);

  /* The relocated bytes still decode as the same instruction. */
  const char *redecode = moved;
  char *mod_rm = NULL;
  assert(next_inst(&redecode, true, 0, 0, &mod_rm, 0, 0) == p->opcode);
  assert(redecode == moved + len);
  assert(mod_rm && (*mod_rm & 0xC7) == 0x5);

  /* Nothing past the copied instructions was written. */
  assert((unsigned char)RELOCATED[prefix + len] == 0xcc);

  printf("PASS %s\n", p->name);
  return 0;
}
