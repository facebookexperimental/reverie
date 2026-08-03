/* Copyright © 2010 The Chromium Authors. All rights reserved.
 * Copyright © 2019 Software Reliability Group, Imperial College London
 *
 * This file is part of SaBRe.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later AND BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "loader/rewriter.h"
#include "loader/backend_stats.h"
#include "loader/global_vars.h"

#include "handle_rdtsc.h"
#include "handle_syscall.h"
#include "handle_syscall_loader.h"
#include "handle_vdso.h"
#include "rewriter_safe_insn.h"
#include "rewriter_tools.h"
#include "x86_decoder.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define TRAMPOLINE_MAX_DISTANCE (1536 << 20)

#ifdef __NX_INTERCEPT_RDTSC
static bool rdtscp_prefixes_supported(const char *start, const char *mod_rm) {
  if (mod_rm < start + 2 || (unsigned char)mod_rm[-2] != 0x0F ||
      (unsigned char)mod_rm[-1] != 0x01)
    return false;

  // Operand-size and REX prefixes are architecturally ignored by RDTSCP but
  // accepted by x86 CPUs. Reject every other prefix explicitly rather than
  // turning an invalid native encoding (notably LOCK) into an intercepted one.
  for (const unsigned char *prefix = (const unsigned char *)start;
       prefix < (const unsigned char *)mod_rm - 2; ++prefix) {
    if (*prefix != 0x66 && (*prefix < 0x40 || *prefix > 0x4F))
      return false;
  }
  return true;
}
#endif

static void patch_syscalls_in_func(struct library *lib, char *start, char *end,
                                   char **extra_space, int *extra_len,
                                   bool loader) {
  struct rb_root branch_targets = RB_ROOT;

  _nx_debug_printf("patch_syscalls_in_func: function %p-%p\n", start, end);

  {
    // Count how many targets we'll need
    unsigned long total = 0;
    for (char *ptr = start; ptr < end;) {
      unsigned short insn = next_inst((const char **)&ptr, __WORDSIZE == 64,
                                      NULL, NULL, NULL, NULL, NULL);
      if ((insn >= 0x70 && insn <= 0x7F) /* Jcc */ || insn == 0xEB /* JMP */ ||
          insn == 0xE8 /* CALL */ || insn == 0xE9 /* JMP */ ||
          (insn >= 0x0F80 && insn <= 0x0F8F) /* Jcc */) {
        total += 1;
      }
    }

    // Allocate all the memory we'll need in one go
    struct branch_target *target = malloc(total * sizeof(*target));

    // Lookup branch targets dynamically.
    for (char *ptr = start; ptr < end;) {
      unsigned short insn = next_inst((const char **)&ptr, __WORDSIZE == 64,
                                      NULL, NULL, NULL, NULL, NULL);
      char *addr;
      if ((insn >= 0x70 && insn <= 0x7F) /* Jcc */ || insn == 0xEB /* JMP */) {
        addr = ptr + ((signed char *)(ptr))[-1];
      } else if (insn == 0xE8 /* CALL */ || insn == 0xE9 /* JMP */ ||
                 (insn >= 0x0F80 && insn <= 0x0F8F) /* Jcc */) {
        addr = ptr + ((int *)(ptr))[-1];
      } else
        continue;

      target->addr = addr;
      rb_insert_target(&branch_targets, addr, &target->rb_target);
      target += 1;
    }
  }

  struct code {
    char *addr;
    int len;
    unsigned short insn;
    bool is_ip_relative;
  } code[5] = {{0}};

  int i = 0;
  for (char *ptr = start; ptr < end;) {
    // Keep a ring-buffer of the last few instruction in order to find the
    // correct place to patch the code.
    char *mod_rm;
    code[i].addr = ptr;
    code[i].insn =
        next_inst((const char **)&ptr, __WORDSIZE == 64, 0, 0, &mod_rm, 0, 0);
    code[i].len = ptr - code[i].addr;
    code[i].is_ip_relative = mod_rm && (*mod_rm & 0xC7) == 0x5;

    // Whenever we find a system call, we patch it with a jump to out-of-line
    // code that redirects to our system call entrypoint.
#if defined(__NX_INTERCEPT_RDTSC) || defined(SBR_DEBUG)
    bool is_rdtsc = false;
    bool is_rdtscp = false;
#endif
    if (code[i].insn == 0x0F05 /* SYSCALL */
#ifdef __NX_INTERCEPT_RDTSC
        || ((is_rdtsc = (code[i].insn == 0x0F31)) /* RDTSC */ && !loader)
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-2): Review RDTSCP decoding and rewrite semantics.
        || ((is_rdtscp = code[i].insn == 0x0F01 && mod_rm != NULL &&
                         (unsigned char)*mod_rm == 0xF9 &&
                         rdtscp_prefixes_supported(code[i].addr, mod_rm)) &&
            !loader)
#endif
    ) {

      // Found a system call. Search backwards to figure out how to redirect
      // the code. We will need to overwrite a couple of instructions and,
      // of course, move these instructions somewhere else.
      int start_idx = i;
      int length = code[i].len;
      for (int j = i; (j = (j + (sizeof(code) / sizeof(struct code)) - 1) %
                           (sizeof(code) / sizeof(struct code))) != i;) {
        struct branch_target *target =
            rb_upper_bound_target(&branch_targets, code[j].addr);
        if (target && target->addr < ptr) {
          // Found a branch pointing to somewhere past our instruction. This
          // instruction cannot be moved safely. Leave it in place.
          break;
        }
        if (code[j].addr && !code[j].is_ip_relative &&
            is_safe_insn(code[j].insn)) {
          // These are all benign instructions with no side-effects and no
          // dependency on the program counter. We should be able to safely
          // relocate them.
          start_idx = j;
          length = ptr - code[start_idx].addr;
        } else {
          break;
        }
      }
      // Search forward past the system call, too. Sometimes, we can only find
      // relocatable instructions following the system call.
      char *next = ptr;
      for (int j = i;
           next < end &&
           (j = (j + 1) % (sizeof(code) / sizeof(struct code))) != start_idx;) {
        struct branch_target *target =
            rb_lower_bound_target(&branch_targets, next);
        if (target && target->addr == next) {
          // Found branch target pointing to our instruction
          break;
        }
        char *tmp_rm;
        code[j].addr = next;
        code[j].insn = next_inst((const char **)&next, __WORDSIZE == 64, 0, 0,
                                 &tmp_rm, 0, 0);
        code[j].len = next - code[j].addr;
        code[j].is_ip_relative = tmp_rm && (*tmp_rm & 0xC7) == 0x5;
        if (!code[j].is_ip_relative && is_safe_insn(code[j].insn)) {
          length = next - code[start_idx].addr;
        } else {
          break;
        }
      }
      // We now know, how many instructions neighboring the system call we can
      // safely overwrite. On x86-32 we need six bytes, and on x86-64 We need
      // five bytes to insert a JMPQ and a 32bit address. We then jump to a
      // code fragment that safely forwards to our system call entrypoint.
      //
      // On x86-64, this is complicated by the fact that the API allows up to
      // 128 bytes of red-zones below the current stack pointer. So, we cannot
      // write to the stack until we have adjusted the stack pointer.
      //
      // On both x86-32 and x86-64 we take care to leave the stack unchanged
      // while we are executing the preamble and postamble. This allows us to
      // treat instructions that reference %esp/%rsp as safe for relocation.
      //
      // In particular, this means that on x86-32 we cannot use CALL, but have
      // to use a PUSH/RET combination to change the instruction pointer. On
      // x86-64, we can instead use a 32bit JMPQ.
      //
      // .. .. .. .. ; any leading instructions copied from original code
      // 48 8D 64 24 80              LEA  -0x80(%rsp), %rsp
      // 90 90                       NOP; NOP
      // 9C                          PUSHFQ              ; SYSCALL only
      // 41 5B                       POP %r11            ; SYSCALL only
      // 48 8D 0D .. .. .. ..        LEA return(%rip), %rcx ; SYSCALL only
      // 50                          PUSH %rax
      // 48 8D 05 .. .. .. ..        LEA  ...(%rip), %rax
      // 50                          PUSH %rax
      // 48 B8 .. .. .. ..           MOV  $syscall_enter_with_frame, %rax
      // .. .. .. ..
      // 50                          PUSH %rax
      // 48 8D 05 06 00 00 00        LEA  6(%rip), %rax
      // 48 87 44 24 10              XCHG %rax, 16(%rsp)
      // C3                          RETQ
      // 48 8D A4 24 80 00 00 00     LEA  0x80(%rsp), %rsp
      // .. .. .. .. ; any trailing instructions copied from original code
      // E9 .. .. .. ..              JMPQ ...
      //
      // Total: 63 bytes for SYSCALL (53 for RDTSC/RDTSCP) + copied bytes
      //
      // On x86-32, the stack is available and we can do:
      //
      // TODO(markus): Try to maintain frame pointers on x86-32
      //
      // .. .. .. .. ; any leading instructions copied from original code
      // 68 .. .. .. ..              PUSH . + 11
      // 68 .. .. .. ..              PUSH return_addr
      // 68 .. .. .. ..              PUSH $syscall_enter_with_frame
      // C3                          RET
      // .. .. .. .. ; any trailing instructions copied from original code
      // 68 .. .. .. ..              PUSH return_addr
      // C3                          RET
      //
      // Total: 22 bytes + any bytes that were copied
      //
      // For indirect jumps from the VDSO to the VSyscall page, we instead
      // replace the following code (this is only necessary on x86-64). This
      // time, we don't have to worry about red zones:
      //
      // .. .. .. .. ; any leading instructions copied from original code
      // E8 00 00 00 00              CALL .
      // 48 83 04 24 ..              ADDQ $.., (%rsp)
      // FF .. .. .. .. ..           PUSH ..  ; from original CALL instruction
      // 48 81 3C 24 00 00 00 FF     CMPQ $0xFFFFFFFFFF000000, 0(%rsp)
      // 72 10                       JB   . + 16
      // 81 2C 24 .. .. .. ..        SUBL ..., 0(%rsp)
      // C7 44 24 04 00 00 00 00     MOVL $0, 4(%rsp)
      // C3                          RETQ
      // 48 87 04 24                 XCHG %rax,(%rsp)
      // 48 89 44 24 08              MOV  %rax, 8(%rsp)
      // 58                          POP  %rax
      // C3                          RETQ
      // .. .. .. .. ; any trailing instructions copied from original code
      // E9 .. .. .. ..              JMPQ ...
      //
      // Total: 52 bytes + any bytes that were copied

      if (length < (__WORDSIZE == 32 ? 6 : 5)) {
        // If we cannot figure out any other way to intercept this syscall/RDTSC,
        // we replace it with an illegal instruction. This causes a SIGILL which we then
        // handle in the signal handler. That's a lot slower than rewriting the
        // instruction with a jump, but it should only happen very rarely.
#ifdef __NX_INTERCEPT_RDTSC
        if (is_rdtscp) {
          memcpy(code[i].addr, "\x0F\x0C\x90" /* Reserved UD + NOP */, 3);
          // A supported prefix makes the decoded instruction longer than the
          // three-byte marker. Resume only through NOPs, never a stale opcode.
          memset(code[i].addr + 3, 0x90, code[i].len - 3);
          goto replaced;
        } else if (is_rdtsc) {
          memcpy(code[i].addr, "\x0F\x0B" /* UD2 */, 2);
          goto replaced;
        } else
#endif
        {
          memcpy(code[i].addr, "\x0F\xFF" /* UD0 */, 2);
          if (code[i].insn == 0x0F05)
            sbr_backend_stats_record_patch(code[i].addr, code[i].len,
                                           SBR_PATCH_REWRITE_SIGILL_MARKER);
          goto replaced;
        }
      }
      int needed = (__WORDSIZE == 32 ? 6 : 5) - code[i].len;
      int first = i;
      while (needed > 0 && first != start_idx) {
        first = (first + (sizeof(code) / sizeof(struct code)) - 1) %
                (sizeof(code) / sizeof(struct code));
        needed -= code[first].len;
      }
      int second = i;
      while (needed > 0) {
        second = (second + 1) % (sizeof(code) / sizeof(struct code));
        needed -= code[second].len;
      }
      int preamble = code[i].addr - code[first].addr;
      int postamble =
          code[second].addr + code[second].len - code[i].addr - code[i].len;

      // The following is all the code that construct the various bits of
      // assembly code.
      int syscall_clobber_prefix = code[i].insn == 0x0F05 ? 10 : 0;
      needed = 53 + syscall_clobber_prefix + preamble + postamble;

      // Allocate scratch space and copy the preamble of code that was moved
      // from the function that we are patching.
      char *dest = alloc_scratch_space(lib->maps->fd, code[first].addr, needed,
                                       extra_space, extra_len, true,
                                       TRAMPOLINE_MAX_DISTANCE);
      memcpy(dest, code[first].addr, preamble);

      // For jumps from the VDSO to the VSyscalls we sometimes allow exactly
      // one IP relative instruction in the preamble.
      if (code[first].is_ip_relative) {
        *(int *)(dest + (code[i].addr - code[first].addr) - 4) -=
            dest - code[first].addr;
      }

      // Copy the static body of the assembly code.
      char *body = dest + preamble;
      memcpy(body,
             "\x48\x8D\x64\x24\x80\x90\x90", // LEA -0x80(%rsp),%rsp; NOPs
             7);
      body += 7;
      if (syscall_clobber_prefix) {
        memcpy(body,
               "\x9C"                          // PUSHFQ
               "\x41\x5B"                      // POP %r11
               "\x48\x8D\x0D\x00\x00\x00\x00", // LEA ...(%rip), %rcx
               syscall_clobber_prefix);
        *(int *)(body + 6) =
            (code[i].addr + code[i].len) - (body + syscall_clobber_prefix);
        body += syscall_clobber_prefix;
      }
      char *trampoline = body;
      memcpy(trampoline,
             "\x50"                              // PUSH %rax
             "\x48\x8D\x05\x00\x00\x00\x00"      // LEA  ...(%rip), %rax
             "\x50"                              // PUSH %rax
             "\x48\xB8\x00\x00\x00\x00\x00"      // MOV $entrypoint,
             "\x00\x00\x00"                      //     %rax
             "\x50"                              // PUSH %rax
             "\x48\x8D\x05\x06\x00\x00\x00"      // LEA  6(%rip), %rax
             "\x48\x87\x44\x24\x10"              // XCHG %rax, 16(%rsp)
             "\xC3"                              // RETQ
             "\x48\x8D\xA4\x24\x80\x00\x00\x00", // LEA 0x80(%rsp), %rsp
             41);

      // Copy the postamble that was moved from the function that we are
      // patching.
      memcpy(trampoline + 41, code[i].addr + code[i].len, postamble);

      // Patch up the various computed values
      int post = trampoline - dest + 41 + postamble;
      dest[post] = '\xE9'; // JMPQ
      *(int *)(dest + post + 1) =
          (code[second].addr + code[second].len) - (dest + post + 5);
      // Preserve the architectural SYSCALL return RIP separately from the
      // scratch continuation that executes the relocated postamble.
      *(int *)(trampoline + 4) =
          (code[i].addr + code[i].len) - (trampoline + 8);
      void *entrypoint;

      if (loader)
        entrypoint = handle_syscall_loader;
#ifdef __NX_INTERCEPT_RDTSC
      else if (is_rdtsc || is_rdtscp) {
        entrypoint = is_rdtscp ? rdtscp_entrypoint : rdtsc_entrypoint;
      }
#endif
      else
        entrypoint = handle_syscall;
      *(void **)(trampoline + 11) = entrypoint;
      // Pad unused space in the original function with NOPs
      memset(code[first].addr, 0x90 /* NOP */,
             code[second].addr + code[second].len - code[first].addr);

      // Replace the system call with an unconditional jump to our new code.
      *code[first].addr = '\xE9'; // JMPQ
      *(int *)(code[first].addr + 1) = dest - (code[first].addr + 5);
      if (code[i].insn == 0x0F05)
        sbr_backend_stats_record_patch(code[i].addr, code[i].len,
                                       SBR_PATCH_JUMP_TRAMPOLINE);
      _nx_debug_printf("patched %s at %p (scratch space at %p)\n",
                       (is_rdtscp ? "rdtscp"
                                  : (is_rdtsc ? "rdtsc" : "syscall")),
                       code[i].addr, dest);
    }
  replaced:
    i = (i + 1) % (sizeof(code) / sizeof(struct code));
  }
}

static inline struct rb_root *lookup_branch_targets(char *start, char *end) {
  struct rb_root *branch_targets;

  branch_targets = (struct rb_root *)malloc(sizeof(*branch_targets));
  assert(branch_targets != NULL);
  *branch_targets = RB_ROOT;

  // Lookup branch targets dynamically.
  for (char *ptr = start; ptr < end;) {
    unsigned short insn = next_inst((const char **)&ptr, __WORDSIZE == 64, NULL,
                                    NULL, NULL, NULL, NULL);
    char *addr;
    if ((insn >= 0x70 && insn <= 0x7F) /* Jcc */ || insn == 0xEB /* JMP */) {
      addr = ptr + ((signed char *)(ptr))[-1];
    } else if (insn == 0xE8 /* CALL */ || insn == 0xE9 /* JMP */ ||
               (insn >= 0x0F80 && insn <= 0x0F8F) /* Jcc */) {
      addr = ptr + ((int *)(ptr))[-1];
    } else {
      continue;
    }

    struct branch_target *target = malloc(sizeof(*target));
    target->addr = addr;
    rb_insert_target(branch_targets, addr, &target->rb_target);
  }

  return branch_targets;
}

#if defined(USE_ABS_JMP_DETOUR)
#define JUMP_SIZE                                                              \
  12 // 10 bytes to load target address into register + 2 bytes to jump
#else
#define JUMP_SIZE                                                              \
  5 // 1 byte for the opcode + 4 bytes for the 32-bit displacement
#endif

static const char DETOUR_ASM[] =
    // after rewriting, the detoured function jumps to here
    "\x48\x83\xEC\x08"             // SUB  $0x8, %rsp          # stack alignment
    "\x49\xBB\x00\x00\x00\x00\x00" // MOVABS $handler, %r11    # load handler address
    "\x00\x00\x00"
    "\x41\xFF\xD3"     // CALLQ *%r11              # call handler
    "\x48\x83\xC4\x08" // ADD  $0x8, %rsp          # stack alignment
    "\xC3"; // RETQ                     # return to detoured function (except for __libc_start_main)
// the postamble (i.e. first instructions of detoured function relocated to accommodate the jump) comes here
// then comes the jump back to detoured function after relocated instructions

static const size_t DETOUR_ASM_SIZE = sizeof(DETOUR_ASM) - 1;
static const size_t HANDLER_OFFSET = 6;

static inline void copy_postamble(void *dest, struct s_code code[],
                                  int second) {
  // Copy each instruction, one by one,
  // fixing eventual instructions that use the RIP register
  void *curr = dest;
  for (int insn = 0; insn <= second; insn++) {
    if (code[insn].is_ip_relative || code[insn].insn == 0x0f84 /* JE */ ||
        code[insn].insn == 0xE8 /* CALL */ ||
        code[insn].insn == 0xE9 /* JMP */) {
      bool has_prefix;
      char *rex_ptr;
      char *mod_rm_ptr;
      char *sib_ptr;
      switch (code[insn].insn) {
      case 0x81: // CMP with imm16/32 operand
      case 0x83: // CMP with imm8 operand
      {
        // Instruction format:
        //         83 3D XX XX XX XX XX
        //         -- -- ----------- --
        // addr +  0  1  2           6
        //         |  |  |            -> 8 bit immediate
        //         |  |   -> 32 bit RIP displacement
        //         |   -> Mod R/M byte
        //          -> Opcode

        // Instruction format:
        //         81 3D XX XX XX XX XX XX [ XX XX ]
        //         -- -- ----------- ---------------
        // addr +  0  1  2           6
        //         |  |  |            -> 16 or 32 bit immediate
        //         |  |   -> 32 bit RIP displacement
        //         |   -> Mod R/M byte
        //          -> Opcode

        // Compute value the RIP would hold at runtime
        char *rip = code[insn].addr;
        // Get the RIP-relative displacement in the instruction
        int disp = *(int *)(rip + 2);
        // Compute displacement from the new code to the original instruction
        long ldisp = ((long)rip - (long)curr);
        // Displacement larger than 32 bits?  Not supported yet
        if (ldisp > (long)UINT32_MAX || (ldisp * -1) > (long)UINT32_MAX)
          _nx_fatal_printf(
              "vDSO RIP MOV requires unsupported 64 bit displacement");

        // Emit instruction
        memcpy(curr, code[insn].addr,
               code[insn].len); // CMP [rip+0xXXXX]      , 0xXX
        *(int *)(((char *)curr) + 2) =
            (int)ldisp + disp; // CMP [rip+0xXXXX+disp] , 0xXX
        curr += code[insn].len;
        break;
      }
      case 0x8B: // REX.W MOV
      {
        // Instruction format:
        //         48 8B X5 XX XX XX XX
        //         -- -- -- -----------
        // addr +  0  1  2  3
        //         |  |  |   -> 32 bit RIP displacement
        //         |  |   -> Mod R/M byte ending in 0x5
        //         |   -> Opcode
        //          -> Preffix REX.W

        //         8B X5 XX XX XX XX
        //         -- -- ------------
        // addr +  0  1  2
        //         |  |  |
        //         |  |   -> 32 bit RIP displacement
        //         |   -> Mod R/M byte ending in 0x5
        //          -> Opcode

        // Decode instruction
        const char *code_ptr = code[insn].addr;
        next_inst(&code_ptr, __WORDSIZE == 64, &has_prefix, &rex_ptr,
                  &mod_rm_ptr, &sib_ptr, NULL);
        if (has_prefix && *rex_ptr == (char)0x48) {
          // Compute value the RIP would hold at runtime
          char *rip = code[insn].addr;
          // Get the RIP-relative displacement in the instruction
          int disp = *(int *)(rip + 3);
          // Compute displacement from the new code to the original instruction
          long ldisp = ((long)rip - (long)curr);
          // Displacement larger than 32 bits?  Not supported yet
          if (ldisp > (long)UINT32_MAX || (ldisp * -1) > (long)UINT32_MAX)
            _nx_fatal_printf(
                "vDSO RIP MOV requires unsupported 64 bit displacement");

          // Emit instruction
          memcpy(curr,
                 "\x48\x8B\x00\x00\x00\x00\x00", // REX.W MOV ... , [...]
                 7);
          *(((char *)curr) + 2) = *mod_rm_ptr; // REX.W MOV reg , [rip+...]
          *(int *)(((char *)curr) + 3) =
              (int)ldisp + disp; // REX.W MOV reg , [rip+disp]
          curr += 7;
        } else {
          // Compute value the RIP would hold at runtime
          char *rip = code[insn].addr;
          // Get the RIP-relative displacement in the instruction
          int disp = *(int *)(rip + 2);
          // Compute displacement from the new code to the original instruction
          long ldisp = ((long)rip - (long)curr);
          // Displacement larger than 32 bits?  Not supported yet
          if (ldisp > (long)UINT32_MAX || (ldisp * -1) > (long)UINT32_MAX)
            _nx_fatal_printf(
                "vDSO RIP MOV requires unsupported 64 bit displacement");

          // Emit instruction
          memcpy(curr,
                 "\x8B\x00\x00\x00\x00\x00", // MOV ... , [...]
                 6);
          *(((char *)curr) + 1) = *mod_rm_ptr; // REX.W MOV reg , [rip+...]
          *(int *)(((char *)curr) + 2) =
              (int)ldisp + disp; // REX.W MOV reg , [rip+disp]
          curr += 6;
        }

        /* ******************************************************************
          // The following is commented out to provide some guidance for future
          // implementations of instructions not currently supported:
          // Get register from Mod R/M byte
          char reg_w = (char) (*mod_rm_ptr & 0b00111000);
          // Compute new Mod R/M byte
          char mod_rm = (char) 0b00000100 | reg_w;
          ****************************************************************** */

        break;
      }
      case 0x8D: // LEA
      {
        //         8B X5 XX XX XX XX XX
        //         -- -- -- ------------
        // addr +  0  1  2  3
        //         |  |     |
        //         |  |      -> 32 bit RIP displacement
        //         |   -> Mod R/M byte ending in 0x5
        //          -> Opcode

        // Decode instruction
        const char *code_ptr = code[insn].addr;
        next_inst(&code_ptr, __WORDSIZE == 64, &has_prefix, &rex_ptr,
                  &mod_rm_ptr, &sib_ptr, NULL);

        // Compute value the RIP would hold at runtime
        char *rip = code[insn].addr;
        // Get the RIP-relative displacement in the instruction
        int disp = *(int *)(rip + 3);
        // Compute displacement from the new code to the original instruction
        long ldisp = ((long)rip - (long)curr);
        ldisp += disp;
        // Displacement larger than 32 bits?  Not supported yet
        if (ldisp > (long)UINT32_MAX || (ldisp * -1) > (long)UINT32_MAX)
          _nx_fatal_printf(
              "vDSO RIP MOV requires unsupported 64 bit displacement");

        // Emit instruction
        memcpy(curr,
               rip, // LEA ... , [...]
               7);
        *(int *)(((char *)curr) + 3) = (int)ldisp; // LEA reg , [rip+disp]
        curr += 7;

        /* ******************************************************************
          // The following is commented out to provide some guidance for future
          // implementations of instructions not currently supported:
          // Get register from Mod R/M byte
          char reg_w = (char) (*mod_rm_ptr & 0b00111000);
          // Compute new Mod R/M byte
          char mod_rm = (char) 0b00000100 | reg_w;
          ****************************************************************** */

        break;
      }
      case 0x0F84: // JE
      {
        //         0F 84 XX XX XX XX
        //         ----- -----------
        // addr +  0  1  2  3  4  5
        //         |     |
        //         |      -> 32 bit displacement
        //          -> Opcode

        // Decode instruction
        const char *code_ptr = code[insn].addr;
        next_inst(&code_ptr, __WORDSIZE == 64, &has_prefix, &rex_ptr,
                  &mod_rm_ptr, &sib_ptr, NULL);

        // Compute value the RIP would hold at runtime
        char *rip = code[insn].addr;
        // Get the RIP-relative displacement in the instruction
        int disp = *(int *)(rip + 2);
        // Compute displacement from the new code to the original instruction
        long ldisp = ((long)rip - (long)curr);
        ldisp += disp;
        // Displacement larger than 32 bits?  Not supported yet
        if (ldisp > (long)UINT32_MAX || (ldisp * -1) > (long)UINT32_MAX)
          _nx_fatal_printf(
              "vDSO RIP MOV requires unsupported 64 bit displacement");

        // Emit instruction
        memcpy(curr,
               rip, // JE ...
               6);
        *(int *)(((char *)curr) + 2) = (int)ldisp; // JE rel32
        curr += 6;

        break;
      }
      case 0xE8: // CALL rel32
      case 0xE9: // JMP rel32
        copy_rel32(curr, &code[insn]);
        curr += code[insn].len;
        break;
      default:
        _nx_fatal_printf("vDSO RIP relative instruction not supported: 0x%x\n",
                         code[insn].insn);
      }
    } else {
      memcpy(curr, code[insn].addr, code[insn].len);
      curr += code[insn].len;
    }
  }
}

void detour_func(struct library *lib, char *start, char *end, int syscall_no,
                 char **extra_space, int *extra_len) {
  void *trampoline_addr = NULL;
  struct rb_root *branch_targets;
  struct s_code code[JUMP_SIZE] = {{0}};

  branch_targets = lookup_branch_targets(start, end);

  // Keep a ring-buffer of the last few instruction in order to find the correct
  // place to patch the code.
  char *mod_rm;
  char *ptr = start;
  code[0].addr = ptr;
  code[0].insn =
      next_inst((const char **)&ptr, __WORDSIZE == 64, 0, 0, &mod_rm, 0, 0);
  code[0].len = ptr - code[0].addr;
  code[0].is_ip_relative = mod_rm && (*mod_rm & 0xC7) == 0x5;
  int length = code[0].len;
  char *next = ptr;
  for (size_t i = 1; next < end && i < JUMP_SIZE; i++) {
    struct branch_target *target = rb_lower_bound_target(branch_targets, next);
    if (target && target->addr == next) {
      // Found branch target pointing to our instruction.
      break;
    }
    char *tmp_rm;
    code[i].addr = next;
    code[i].insn =
        next_inst((const char **)&next, __WORDSIZE == 64, 0, 0, &tmp_rm, 0, 0);
    code[i].len = next - code[i].addr;
    code[i].is_ip_relative = tmp_rm && (*tmp_rm & 0xC7) == 0x5;
    if (is_safe_insn(code[i].insn) ||
        (code[i].insn >= 0x50 && code[i].insn <= 0x57) /* PUSH */ ||
        (code[i].insn == 0x6A) /* PUSH */ ||
        (code[i].insn == 0x68) /* PUSH */) {
      length = next - code[0].addr;
    } else {
      break;
    }
  }

  if (length < (__WORDSIZE == 32 ? 6 : JUMP_SIZE)) {
    _nx_fatal_printf("Cannot intercept system call");
  }

  int needed, postamble, second;
  needed_space(code, &needed, &postamble, &second,
#if defined(USE_ABS_JMP_DETOUR)
               70,
#else
               67,
#endif
               JUMP_SIZE);

  // Allocate scratch space and copy the preamble of code that was moved
  // from the function that we are patching.
  char *dest = alloc_scratch_space(lib->maps->fd, code[0].addr, needed,
                                   extra_space, extra_len,
#if defined(USE_ABS_JMP_DETOUR)
                                   false);
#else
                                   true, TRAMPOLINE_MAX_DISTANCE);
#endif
#if defined(USE_ABS_JMP_DETOUR)
  trampoline_addr = dest + 70;
#else
  trampoline_addr = dest + 67;
#endif

  void *plugin_handler;

  if (vdso_callback)
    plugin_handler = vdso_callback(syscall_no, trampoline_addr);
  else
    plugin_handler = NULL;

  // Copy the static body of the assembly code.
  memcpy(dest,
         "\xb8\x00\x00\x00\x00"         // MOV $syscall_no, %eax
         "\x48\x81\xEC\x80\x00\x00\x00" // SUB  $0x80, %rsp
         "\x41\x57"                     // PUSH %r15
         "\x49\xBF\x00\x00\x00\x00\x00" // MOV $plugin_handler
         "\x00\x00\x00"                 //     %r15
         "\x50"                         // PUSH %rax
#if defined(USE_ABS_JMP_DETOUR)
         "\x48\xB8\x00\x00\x00\x00\x00" // MOV ...,
         "\x00\x00\x00"                 //     %rax
#else
         "\x48\x8D\x05\x00\x00\x00\x00" // LEA $fake_ret_addr(%rip), %rax
#endif
         "\x50"                         // PUSH %rax
         "\x48\xB8\x00\x00\x00\x00\x00" // MOV $handle_vdso,
         "\x00\x00\x00"                 //     %rax
         "\x50"                         // PUSH %rax
         "\x48\x8D\x05\x06\x00\x00\x00" // LEA  6(%rip), %rax
         "\x48\x87\x44\x24\x10"         // XCHG %rax, 16(%rsp)
         "\xC3"                         // RETQ
         "\x41\x5f"                     // POP %r15
         "\x48\x81\xC4\x80\x00\x00\x00" // ADD  $0x80, %rsp
         "\xC3",                        // RETQ
#if defined(USE_ABS_JMP_DETOUR)
         70
#else
         67
#endif
  );

  // Copy the postamble that was moved from the function that we are
  // patching.
  copy_postamble(dest +
#if defined(USE_ABS_JMP_DETOUR)
                     70,
#else
                     67,
#endif
                 code, second);

  // Patch up the various computed values
#if defined(USE_ABS_JMP_DETOUR)
  int post = 70 + postamble;
  memcpy(dest + post,
         "\x48\xB8\x00\x00\x00\x00\x00" // MOV ...,
         "\x00\x00\x00"                 //     %rax
         "\xFF\xE0",                    // JMP *%rax
         CODE_LENGTH);
  *(void **)(dest + post + 2) = (void *)(code[second].addr + code[second].len);
#else
  int post = 67 + postamble;
  dest[post] = '\xE9'; // JMPQ
  *(int *)(dest + post + 1) =
      (code[second].addr + code[second].len) - (dest + post + JUMP_SIZE);
#endif
  *(int *)(dest + 1) = syscall_no;
  *(void **)(dest + 16) = plugin_handler;
#if defined(USE_ABS_JMP_DETOUR)
  *(void **)(dest + 27) = (void *)code[second].addr;
  *(void **)(dest + 38) = handle_vdso;
#else
  ptrdiff_t fake_ret_addr =
      (code[second].addr + code[second].len) - (dest + 32);
  *(int *)(dest + 28) = fake_ret_addr;
  *(void **)(dest + 35) = handle_vdso;
#endif

  // Pad unused space in the original function with NOPs
  memset(code[0].addr, 0x90 /* NOP */,
         (code[second].addr + code[second].len) - code[0].addr);

  // Replace the system call with an unconditional jump to our new code.
#if defined(USE_ABS_JMP_DETOUR)
  memcpy(code[0].addr,
         //"\x48\xA1\x00\x00\x00\x00\x00" // MOV ...,
         "\x48\xB8\x00\x00\x00\x00\x00" // MOV ...,
         "\x00\x00\x00"                 //     %rax
         "\xFF\xE0",                    // JMP *%rax
         JUMP_SIZE);
  *(void **)(code[0].addr + 2) = (void *)(dest);
#else
  *code[0].addr = '\xE9'; // JMPQ
  *(int *)(code[0].addr + 1) = dest - (code[0].addr + JUMP_SIZE);
#endif
}

void api_detour_func(struct library *lib, char *start, char *end,
                     sbr_icept_callback_fn callback, bool copy_first_stack_arg,
                     char **extra_space, int *extra_len) {
  void *trampoline_addr = NULL;
  struct rb_root *branch_targets;
  struct s_code code[JUMP_SIZE] = {{0}};

  branch_targets = lookup_branch_targets(start, end);

  // Keep a ring-buffer of the last few instruction in order to find the correct
  // place to patch the code.
  char *mod_rm;
  char *ptr = start;
  code[0].addr = ptr;
  code[0].insn =
      next_inst((const char **)&ptr, __WORDSIZE == 64, 0, 0, &mod_rm, 0, 0);
  code[0].len = ptr - code[0].addr;
  code[0].is_ip_relative = mod_rm && (*mod_rm & 0xC7) == 0x5;
  int length = code[0].len;
  char *next = ptr;
  for (size_t i = 1; next < end && i < JUMP_SIZE; i++) {
    struct branch_target *target = rb_lower_bound_target(branch_targets, next);
    if (target && target->addr == next) {
      // Found branch target pointing to our instruction.
      break;
    }
    char *tmp_rm;
    code[i].addr = next;
    code[i].insn =
        next_inst((const char **)&next, __WORDSIZE == 64, 0, 0, &tmp_rm, 0, 0);
    code[i].len = next - code[i].addr;
    code[i].is_ip_relative = tmp_rm && (*tmp_rm & 0xC7) == 0x5;
    if (is_safe_insn(code[i].insn) || (code[i].insn == 0x0F84) /* JE rel32 */ ||
        (code[i].insn >= 0x50 && code[i].insn <= 0x57) /* PUSH */ ||
        (code[i].insn == 0x6A) /* PUSH */ ||
        (code[i].insn == 0x68) /* PUSH */) {
      length = next - code[0].addr;
    } else {
      break;
    }
  }

  if (length < (__WORDSIZE == 32 ? 6 : JUMP_SIZE)) {
    _nx_fatal_printf("Cannot intercept system call");
  }

  int needed, postamble, second;
  needed_space(code, &needed, &postamble, &second, DETOUR_ASM_SIZE, JUMP_SIZE);

  // Allocate scratch space and copy the preamble of code that was moved
  // from the function that we are patching.
  char *dest = alloc_scratch_space(lib->maps->fd, code[0].addr, needed,
                                   extra_space, extra_len,
#if defined(USE_ABS_JMP_DETOUR)
                                   false);
#else
                                   true, TRAMPOLINE_MAX_DISTANCE);
#endif

  memcpy(dest, DETOUR_ASM, DETOUR_ASM_SIZE);
  if (copy_first_stack_arg) {
    // At function entry, arg7 is at 8(%rsp). Copy it while aligning so CALL
    // places that value at 8(%rsp) in the handler's SysV frame. The four-byte
    // replacement preserves every downstream template offset.
    memcpy(dest, "\xFF\x74\x24\x08", 4); // PUSHQ 8(%rsp)
  }

  // Copy the postamble that was moved from the function that we are
  // patching.
  copy_postamble(dest + DETOUR_ASM_SIZE, code, second);

  // Patch up the various computed values
  trampoline_addr = dest + DETOUR_ASM_SIZE;
  void *handler = callback(trampoline_addr);
  assert(handler);

  int post = DETOUR_ASM_SIZE + postamble;
  dest[post] = '\xE9'; // JMPQ
  *(int *)(dest + post + 1) =
      (code[second].addr + code[second].len) - (dest + post + JUMP_SIZE);
  *(void **)(dest + HANDLER_OFFSET) = handler;
  // Pad unused space in the original function with NOPs
  memset(code[0].addr, 0x90 /* NOP */,
         (code[second].addr + code[second].len) - code[0].addr);

// Replace the system call with an unconditional jump to our new code.
#if defined(USE_ABS_JMP_DETOUR)
  memcpy(code[0].addr,
         //"\x48\xA1\x00\x00\x00\x00\x00" // MOV ...,
         "\x48\xB8\x00\x00\x00\x00\x00" // MOV ...,
         "\x00\x00\x00"                 //     %rax
         "\xFF\xE0",                    // JMP *%rax
         JUMP_SIZE);
  *(void **)(code[0].addr + 2) = (void *)(dest);
#else
  *code[0].addr = '\xE9'; // JMPQ
  *(int *)(code[0].addr + 1) = dest - (code[0].addr + JUMP_SIZE);
#endif
}

void patch_syscalls_in_range(struct library *lib, char *start, char *stop,
                             char **extra_space, int *extra_len, bool loader) {
  _nx_debug_printf("patch syscalls in range %p-%p\n", start, stop);
  char *func = start;
  int nopcount = 0;
  bool has_syscall = false;
  for (char *ptr = start; ptr < stop; ptr++) {
    bool is_rdtscp =
        ptr + 2 < stop && *ptr == '\x0F' && ptr[1] == '\x01' &&
        ptr[2] == '\xF9';
    if ((ptr + 1 < stop && *ptr == '\x0F' &&
         ptr[1] == '\x05' /* SYSCALL */) ||
        (lib->vdso && *ptr == '\xFF')
#ifdef __NX_INTERCEPT_RDTSC
        || (ptr + 1 < stop && *ptr == '\x0F' &&
            ptr[1] == '\x31' /* RDTSC */)
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-2): Review RDTSCP quick-scan classification.
        || is_rdtscp
#endif
    ) {
      ptr += is_rdtscp ? 2 : 1;
      has_syscall = true;
      nopcount = 0;
    } else if (*ptr == '\x90' /* NOP */) {
      nopcount++;
    } else if (!((long)ptr & 0xF)) {
      if (nopcount > 2) {
        // This is very likely the beginning of a new function. Functions are
        // aligned on 16 byte boundaries and the preceding function is padded
        // out with NOPs.
        //
        // For performance reasons, we quickly scan the entire text segment
        // for potential SYSCALLs, and then patch the code in increments of
        // individual functions.
        if (has_syscall) {
          has_syscall = false;
          // Quick scan of the function found a potential syscall, do thorough
          // scan
          _nx_debug_printf("patch syscalls in func after quick scan\n");
          patch_syscalls_in_func(lib, func, stop, extra_space, extra_len,
                                 loader);
        }
        func = ptr;
      }
      nopcount = 0;
    } else {
      nopcount = 0;
    }
  }
  _nx_debug_printf("has syscall? %u\n", has_syscall);
  if (has_syscall) {
    // Patch any remaining system calls that were in the last function before
    // the loop terminated.
    patch_syscalls_in_func(lib, func, stop, extra_space, extra_len, loader);
  }
  _nx_debug_printf("patched syscalls in range\n");
}
