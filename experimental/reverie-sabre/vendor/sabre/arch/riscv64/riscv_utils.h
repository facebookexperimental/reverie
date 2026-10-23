/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef RISCV_UTILS_H_
#define RISCV_UTILS_H_
#include <stdbool.h>
#include <stdint.h>

#define RISCV_INST32_OP 0x7f
#define RISCV_INST16_OP 0x03
#define RD_32 0x0000f80
#define RS1_32 0x00f8000
#define RS2_32 0x1f00000

#define LUI 0b0110111
#define AUIPC 0b0010111
#define JAL 0b1101111
#define JALR 0b1100111
#define BRANCH 0b1100011
#define LOAD 0b0000011
#define STORE 0b0100011
#define COMPUTE1_32 0b0010011
#define COMPUTE2_32 0b0110011
#define COMPUTE1_64 0b0011011
#define COMPUTE2_64 0b0111011

#define rd_32(i) ((i & RD_32) >> 7)
#define rs1_32(i) ((i & RS1_32) >> 15)
#define rs2_32(i) ((i & RS2_32) >> 20)

#define len(inst) ((inst & 0x3) == 0x3 ? 4 : 2)

struct inst_param {
  uint8_t opcode;
  uint8_t func;
  uint8_t rd;
  uint8_t rs1;
  uint8_t rs2;
  int32_t imm;
};

uint32_t get_patch_jal(int32_t, int);
uint32_t get_patch_store();

uint32_t encode_jal32(struct inst_param *);
uint32_t encode_addi32(struct inst_param *);
uint32_t encode_auipc32(struct inst_param *);
uint32_t encode_jalr32(struct inst_param *);
uint32_t encode_ld32(struct inst_param *);
int64_t decode_jal32_offset(uint32_t);
int64_t decode_branch32_offset(uint32_t);
uint64_t decode_jal16_offset(uint16_t);
uint64_t decode_j16_offset(uint16_t);
uint64_t decode_branch16_offset(uint16_t);

bool is_jal32(uint32_t);
bool is_branch32(uint32_t);
bool is_jal16(uint16_t);
bool is_j16(uint16_t);
bool is_jr16(uint16_t);
bool is_jalr16(uint16_t);
bool is_beqz16(uint16_t);
bool is_bnez16(uint16_t);
bool is_store32(uint32_t);
bool is_store16(uint16_t);
bool is_control_flow_inst(uint32_t);
uint64_t inst_offset64(uint32_t);

uint32_t mask(int);
int demask(uint32_t);
int demask_ignore(uint32_t, int);
uint32_t dependency_reg(uint32_t);
uint32_t deprecated_reg(uint32_t);

bool is_safe_insn(uint32_t);

#endif
