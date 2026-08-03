/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "riscv_utils.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

static bool has_C_extension = true;
static bool is_riscv64 = true;

uint32_t get_patch_jal(int32_t offset, int d) {
  struct inst_param p;
  p.rd = d;
  p.imm = offset;
  return encode_jal32(&p);
}

uint32_t encode_jal32(struct inst_param *p) {
  uint32_t inst = 0;
  uint32_t opcode = 0b1101111;
  uint32_t rd = p->rd;
  inst |= opcode;
  inst |= rd << 7;
  inst |= (p->imm & 0x80000) << 12; // imm[20]
  inst |= (p->imm & 0x3ff) << 21;   // imm[10:1]
  inst |= (p->imm & 0x400) << 10;   // imm[11]
  inst |= (p->imm & 0x7f800) << 1;  // imm[19:12]
  return inst;
}

uint32_t encode_addi32(struct inst_param *p) {
  uint32_t inst = 0;
  inst |= 0b0010011;
  inst |= p->imm << 20;
  inst |= p->rs1 << 15;
  inst |= p->rd << 7;
  return inst;
}

uint32_t encode_auipc32(struct inst_param *p) {
  uint32_t inst = 0;
  inst |= AUIPC;
  inst |= (p->imm << 12);
  inst |= (p->rd << 7);
  return inst;
}

uint32_t encode_jalr32(struct inst_param *p) {
  uint32_t inst = 0;
  inst |= JALR;
  inst |= p->imm << 20;
  inst |= p->rs1 << 15;
  inst |= p->rd << 7;
  return inst;
}

uint32_t encode_ld32(struct inst_param *p) {
  uint32_t inst = 0;
  inst |= LOAD;
  inst |= (p->imm & 0xfff) << 20;
  inst |= 0b011 << 12;
  inst |= p->rs1 << 15;
  inst |= p->rd << 7;
  return inst;
}

inline uint32_t get_patch_store() {
  // there is no need to make a real assembling function now
  return 0xfe113c23;
}

int64_t decode_jal32_offset(uint32_t inst) {
  int64_t offset = 0;
  int64_t imm = inst >> 12;
  offset |= (imm & 0x80000);       // imm[20]
  offset |= (imm & 0x7fe00) >> 9;  // imm[10:1]
  offset |= (imm & 0x00100) << 2;  // imm[11]
  offset |= (imm & 0x000ff) << 11; // imm[19:12]
  offset <<= 44;                   // sign extend it
  offset >>= 44;
  offset *= 2;
  return offset;
}

int64_t decode_branch32_offset(uint32_t inst) {
  int64_t offset = 0;
  offset |= (inst & 0x80) << 3;        // imm[11]
  offset |= (inst & 0xf00) >> 8;       // imm[4:1]
  offset |= (inst & 0x7e000000) >> 21; // imm[10:5]
  offset |= (inst & 0x80000000) >> 20; // imm[12]
  offset <<= 52;                       // sign extend it
  offset >>= 52;
  offset *= 2;
  return offset;
}

uint64_t decode_jal16_offset(uint16_t inst) {
  int64_t offset = 0;
  int64_t imm = (inst << 3) >> 5;
  offset |= (imm & 0x400);      // imm[11]
  offset |= (imm & 0x200) >> 6; // imm[10]
  offset |= (imm & 0x180);      // imm[9:8]
  offset |= (imm & 0x040) << 3; // imm[10]
  offset |= (imm & 0x020);      // imm[6]
  offset |= (imm & 0x010) << 2; // imm[7]
  offset |= (imm & 0x00e) >> 1; // imm[3:1]
  offset |= (imm & 0x001) << 4; // imm[5]
  offset <<= 53;                // sign extend it
  offset >>= 53;
  offset *= 2;
  return offset;
}

uint64_t decode_j16_offset(uint16_t inst) { return decode_jal16_offset(inst); }

uint64_t decode_branch16_offset(uint16_t inst) {
  int64_t offset = 0;
  offset |= (inst & 0x4) << 2;    // imm[5]
  offset |= (inst & 0x18) >> 3;   // imm[2:1]
  offset |= (inst & 0x60);        // imm[7:6]
  offset |= (inst & 0xc00) >> 8;  // imm[4:3]
  offset |= (inst & 0x1000) >> 5; // imm[8]
  offset <<= 56;                  // sign extend it
  offset >>= 56;
  offset *= 2;
  return offset;
}

// Note: detection for control flow instruction
//       use big endian for detection

inline bool is_jal32(uint32_t inst) { // 32 bit inst, JAL
  return (inst & RISCV_INST32_OP) == 0b1101111;
}

inline bool is_branch32(uint32_t inst) { // 32 bit inst, branch inst
  return (inst & RISCV_INST32_OP) == 0b1100011;
}

inline bool is_jal16(uint16_t inst) { // 16 bit inst, c.JAL, riscv32 only
  return !is_riscv64 && has_C_extension && ((inst & 0x3) == 0x1) &&
         (((inst & 0xe000) >> 13) == 1);
}

inline bool is_j16(uint16_t inst) { // 16 bit inst, c.J
  return has_C_extension && ((inst & 0x3) == 1) &&
         (((inst & 0xe000) >> 13) == 0b101);
}

inline bool is_jr16(uint16_t inst) { // 16 bit inst. c.jr
  return has_C_extension && ((inst & 0x3) == 0b10) && ((inst & 0x7f) == 0b10) &&
         (((inst & 0xf000) >> 12) == 0b1000) && ((inst & 0xf80) != 0);
}

inline bool is_jalr16(uint16_t inst) { // 16 bit inst, c.jalr
  return has_C_extension && ((inst & 0x3) == 0b10) && ((inst & 0x7f) == 0b10) &&
         (((inst & 0xf000) >> 12) == 0b1001) && ((inst & 0xf80) != 0);
}

inline bool is_beqz16(uint16_t inst) { // 16 bit inst, c.beqz
  return has_C_extension && ((inst & 0x3) == 0x1) &&
         (((inst & 0xe000) >> 13) == 0b110);
}

inline bool is_bnez16(uint16_t inst) { // 16 bit inst, c.bnez
  return has_C_extension && ((inst & 0x3) == 0x1) &&
         (((inst & 0xe000) >> 13) == 0b111);
}

inline bool is_control_flow_inst(uint32_t inst) {
  return is_jal32(inst) || is_branch32(inst) || is_jal16(inst) ||
         is_j16(inst) || is_beqz16(inst) || is_bnez16(inst) || is_jr16(inst) ||
         is_jalr16(inst);
}

inline bool is_store32(uint32_t inst) {
  return (inst & RISCV_INST32_OP) == 0b0100011;
}

inline bool is_store16(uint16_t inst) {
  return has_C_extension && ((inst & 0x3) == 0) &&
         (((inst & 0xe000) >> 13) > 0x100);
}

/*  Pre : is_control_flow_inst(inst) is true
 *  Note: riscv encode relative offset in all control flow instruction
 */
uint64_t inst_offset64(uint32_t inst) {
  uint64_t offset;
  if (is_jal32(inst)) {
    offset = decode_jal32_offset(inst);
  } else if (is_branch32(inst)) {
    offset = decode_branch32_offset(inst);
  } else if (is_jal16(inst)) {
    offset = decode_jal16_offset(inst);
  } else if (is_j16(inst)) {
    offset = decode_j16_offset(inst);
  } else if (is_beqz16(inst) || is_bnez16(inst)) {
    offset = decode_branch16_offset(inst);
  } else if (is_jalr16(inst) || is_jr16(inst)) {
    return 0;
  } else {
    fprintf(stderr, "inst_offset64 fails: attempt to extract offset from not "
                    "control flow instruction\n");
    assert(false);
  }
  return offset;
}

inline uint32_t mask(int i) {
  uint32_t m = 1;
  return m <<= i;
}

/* Extract the register with the smallest number in the mask */
int demask(uint32_t m) {
  if (m == 0) {
    return 0;
  }
  m >>= 1; // remove x0
  int i = 1;
  for (int j = 0; j < 31 && !(m & 0x1); j++, i++) {
    m >>= 1;
  }
  return i;
}

/* Ignore a register with the given number */
int demask_ignore(uint32_t m, int a) {
  if (m == 0) {
    return 0;
  }
  m >>= 1; // remove x0
  for (int j = 0, i = 1; j < 31; j++, i++) {
    if ((m & 0x1) == 1 && i != a) {
      return i;
    }
    m >>= 1;
  }
  return 0;
}

/* Return mask of register which values are used in the instruction */
inline uint32_t dependency_reg(uint32_t inst) {
  if ((inst & 0x3) == 0x3) { // 32-bit instruction
    switch (inst & RISCV_INST32_OP) {
    case JALR:
    case LOAD:
    case COMPUTE1_32:
    case COMPUTE1_64:
      return mask(rs1_32(inst));
    case BRANCH:
    case STORE:
    case COMPUTE2_32:
    case COMPUTE2_64:
      return mask(rs1_32(inst)) | mask(rs2_32(inst));
    }
  } else { // 16-bit instruction
    uint8_t op = (inst & 0xe000) >> 13, op2;
    uint8_t rs1, rs2;

    switch (inst & RISCV_INST16_OP) {

    case 0b00:
      rs1 = (inst & 0x380) >> 7;
      if (op != 0) {
        return mask(rs1);
      }
      break;

    case 0b01:

      switch (op) {

      case 0b000:
        rs1 = (inst & 0xf80) >> 7;
        return mask(rs1);

      case 0b001:
        rs1 = (inst & 0xf80) >> 7;
        if (is_riscv64) {
          return mask(rs1);
        }
        break;

      case 0b100:
        op2 = (inst & 0xc00) >> 10;
        rs1 = (inst & 0x380) >> 7;
        rs2 = (inst & 0x1c) >> 2;
        switch (op2) {
        case 0b00:
        case 0b01:
        case 0b10:
          return mask(rs1);
        case 0b11:
          return mask(rs1) | mask(rs2);
        }
        break;

      case 0b110:
        rs1 = (inst & 0x38) >> 7;
        return mask(rs1);
      }
      break;

    case 0b10:
      switch (op) {

      case 0b000:
        rs1 = (inst & 0xf80) >> 7;
        return mask(rs1);

      case 0b001:
        rs1 = (inst & 0xf80) >> 7;
        if (is_riscv64) {
          return mask(rs1);
        }
        break;

      case 0b100:
        rs1 = (inst & 0xf80) >> 7;
        rs2 = (inst & 0x7c) >> 2;
        if (((inst & 0xf000) >> 12) == 0b1000) {
          if (rs2 == 0) {
            return mask(rs1);
          }
        }
        return mask(rs1) | mask(rs2);

      case 0b101:
      case 0b110:
      case 0b111:
        rs2 = (inst & 0x7c) >> 2;
        return mask(rs2);
      }
    }
  }
  return 0;
}

inline uint32_t deprecated_reg(uint32_t inst) {
  if ((inst & 0x3) == 0x3) {
    switch (inst & RISCV_INST32_OP) {
    case LUI:
    case AUIPC:
    case JAL:
      return mask(rd_32(inst));
    case COMPUTE1_32:
    case COMPUTE1_64:
    case JALR:
    case LOAD:
    case COMPUTE2_32:
    case COMPUTE2_64:
      return mask(rd_32(inst)) & ~dependency_reg(inst);
    }
  } else {
    uint8_t op = (inst & 0xe000) >> 13;
    uint8_t rd, rs2;
    switch (inst & RISCV_INST16_OP) {

    case 0b00:
      rd = (inst & 0x1c) >> 2;
      switch (op) {
      case 0:
        return mask(rd);
      default:
        return mask(rd) & ~dependency_reg(inst);
      }
      break;

    case 0b01:
      rd = (inst & 0xf80) >> 7;
      switch (op) {
      case 0b010: /* c.li */
      case 0b011: /* c.addi16sp c.lui */
        if (rd != 2) {
          return mask(rd);
        }
      }
      break;

    case 0b10:
      rd = (inst & 0xf80) >> 7;
      rs2 = (inst & 0x7c) >> 2;

      switch (op) {

      case 0b001: /* c.fldsp c.lqsp */
      case 0b010: /* c.lwsp */
      case 0b011: /* c.flwsp c.ldsp */
        return mask(rd);

      case 0b100:
        if (rd != 0 && rs2 != 0) {
          return mask(rd) & ~mask(rs2);
        }
        break;
      }
      break;
    }
  }
  return 0;
}

inline bool is_safe_insn(uint32_t insn) {
  return insn &&
         (((insn & 0x3f) == 0b0110111)    // lui
          || ((insn & 0x3f) == 0b0010011) // addi, slti, sltiu, xori,ori
          // andi, slli, srli, srai
          || ((insn & 0x3f) == 0b0110011) // add, sub, sll, slt
          // sltu, xor, srl, sra, or, and
          // 32M extension
          || ((insn & 0x3f) == 0b0011011) // addiw, slliw, srliw, sraiw
          || ((insn & 0x3f) == 0b0111011) // addw, subw, sllw, srlw, sraw
          // 64M extension
          || (has_C_extension &&
              (((insn & 0x3) == 0x1 && (insn & 0xe000) == 0)    // c.nop, c.addi
               || ((insn & 0x3) == 0x0 && (insn & 0xe000) == 0) // c.addi4spn
               || ((insn & 0x3) == 0x1 && (insn & 0xe000) == 0x2000 &&
                   is_riscv64)                                       // c.addiw
               || ((insn & 0x3) == 0x1 && (insn & 0xe000) == 0x4000) // c.li
               || ((insn & 0x3) == 0x1 &&
                   (insn & 0xe000) == 0x6000) // c.addiw, c.li
               || ((insn & 0x3) == 0x1 && (insn & 0xe000) == 0x8000)
               // c.srli, c.srli64, c.srai, c.srai64,c.andi, c.sub, c.xor, c.or
               // c.and, c,subw
               || ((insn & 0x3) == 0x2 && (insn & 0xe000) == 0)
               // c.slli, c.slli64
               || ((insn & 0x3) == 0x2 && (insn & 0x7c) != 0 &&
                   (insn & 0xf80) != 0 && (insn & 0xf000) == 0x8000)
               // c.mv
               || ((insn & 0x3) == 0x2 && (insn & 0x7c) != 0 &&
                   (insn & 0xf80) != 0 && (insn & 0xf000) == 0x9000)
               // c.add

               )));
}
