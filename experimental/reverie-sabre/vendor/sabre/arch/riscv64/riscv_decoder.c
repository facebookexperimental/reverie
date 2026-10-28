/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "riscv_decoder.h"

#include <byteswap.h>
#include <stdbool.h>
#include <stdint.h>

// move the ip to the start of the next inst
// return current inst's opcode
inline uint32_t next_inst_riscv(char **ip) {
  uint16_t first_half = *((uint16_t *)*ip);
  if ((__bswap_16(first_half) & 0x0300) == 0x0300) {
    uint32_t insn = *((uint32_t *)*ip);
    *ip += 4;
    return insn;
  } else {
    *ip += 2;
    return first_half;
  }
}
