/* Copyright © 2010 The Chromium Authors. All rights reserved.
 * Copyright © 2019 Software Reliability Group, Imperial College London
 *
 * This file is part of SaBRe.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later AND BSD-3-Clause
 */

#ifndef SABRE_ARCH_X86_64_REWRITER_SAFE_INSN_H_
#define SABRE_ARCH_X86_64_REWRITER_SAFE_INSN_H_

#include <stdbool.h>

static inline bool is_safe_insn(unsigned short insn) {
  /* Check if the instruction has no unexpected side-effects. If so, it can
     be safely relocated from the function that we are patching into the
     out-of-line scratch space that we are setting up. This is often necessary
     to make room for the JMP into the scratch space. */
  return (insn <= 0xFF && (insn & 0x7) < 0x6 &&
          (insn & 0xF0) < 0x40
              /* ADD, OR, ADC, SBB, AND, SUB, XOR, CMP */) ||
         insn == 0x63 /* MOVSXD */ ||
         (insn >= 0x80 && insn <= 0x8E /* ADD, OR, ADC,
         SBB, AND, SUB, XOR, CMP, TEST, XCHG, MOV, LEA */) ||
         (insn == 0x90) || /* NOP */
         (insn >= 0xA0 && insn <= 0xA9) /* MOV, TEST */ ||
         (insn >= 0xB0 && insn <= 0xBF /* MOV */) ||
         (insn >= 0xC0 && insn <= 0xC1) || /* Bit Shift */
         (insn >= 0xD0 && insn <= 0xD3) || /* Bit Shift */
         (insn >= 0xC6 && insn <= 0xC7 /* MOV */) ||
         (insn == 0xF7) /* TEST, NOT, NEG, MUL, IMUL, DIV, IDIV */ ||
         (insn >= 0xF19 && insn <= 0xF1F) /* long NOP */;
}

#endif /* SABRE_ARCH_X86_64_REWRITER_SAFE_INSN_H_ */
