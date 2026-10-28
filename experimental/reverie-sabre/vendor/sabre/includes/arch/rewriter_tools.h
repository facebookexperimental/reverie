/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef SABRE_INCLUDES_ARCH_REWRITER_TOOLS_H_
#define SABRE_INCLUDES_ARCH_REWRITER_TOOLS_H_

#include "macros.h"
#include "rbtree.h"
#include "rewriter_api.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

struct branch_target {
  char *addr;
  struct rb_node rb_target;
};

#define rb_entry_target(node) rb_entry((node), struct branch_target, rb_target)

static inline void copy_rel32(void *dest, const struct s_code *code) {
  if (code->len < 1 + (int)sizeof(int32_t))
    _nx_fatal_printf("invalid rel32 instruction length");
  size_t displacement_offset = code->len - sizeof(int32_t);
  int32_t original_displacement;
  memcpy(&original_displacement, code->addr + displacement_offset,
         sizeof(original_displacement));
  intptr_t original_target =
      (intptr_t)(code->addr + code->len) + (intptr_t)original_displacement;
  intptr_t relocated_displacement =
      original_target - (intptr_t)((char *)dest + code->len);
  if (relocated_displacement < INT32_MIN || relocated_displacement > INT32_MAX)
    _nx_fatal_printf("relative branch target exceeds rel32 range");

  int32_t encoded_displacement = (int32_t)relocated_displacement;
  memcpy(dest, code->addr, code->len);
  memcpy((char *)dest + displacement_offset, &encoded_displacement,
         sizeof(encoded_displacement));
}

/**
 * Returns a pointer pointing to the first target whose address does not compare
 * less than @p addr
 */
static inline struct branch_target *rb_lower_bound_target(struct rb_root *root,
                                                          char *addr) {
  struct rb_node *n = root->rb_node;
  struct rb_node *parent = NULL;
  struct branch_target *target;

  while (n) {
    target = rb_entry_target(n);

    if (!(target->addr < addr)) {
      parent = n;
      n = n->rb_left;
    } else
      n = n->rb_right;
  }
  return parent ? rb_entry_target(parent) : NULL;
}

/**
 * Returns an iterator pointing to the first target whose address compares
 * greater than @p addr
 */
static inline struct branch_target *rb_upper_bound_target(struct rb_root *root,
                                                          char *addr) {
  struct rb_node *n = root->rb_node;
  struct rb_node *parent = NULL;
  struct branch_target *target;

  while (n) {
    target = rb_entry_target(n);

    if (target->addr > addr) {
      parent = n;
      n = n->rb_left;
    } else
      n = n->rb_right;
  }
  return parent ? rb_entry_target(parent) : NULL;
}

static inline struct branch_target *
__rb_insert_target(struct rb_root *root, char *addr, struct rb_node *node) {
  struct rb_node **p = &root->rb_node;
  struct rb_node *parent = NULL;
  struct branch_target *target;

  while (*p) {
    parent = *p;
    target = rb_entry(parent, struct branch_target, rb_target);

    if (addr < target->addr)
      p = &(*p)->rb_left;
    else if (addr > target->addr)
      p = &(*p)->rb_right;
    else
      return target;
  }

  rb_link_node(node, parent, p);

  return NULL;
}

static inline struct branch_target *
rb_insert_target(struct rb_root *root, char *addr, struct rb_node *node) {
  struct branch_target *ret;
  if ((ret = __rb_insert_target(root, addr, node)))
    goto out;
  rb_insert_color(node, root);
out:
  return ret;
}

static inline char *alloc_scratch_space(int fd, char *addr, int needed,
                                        char **extra_space, int *extra_len,
                                        bool near, uint64_t max_distance) {
  if (needed > *extra_len ||
      (near && labs(*extra_space - (char *)(addr)) > (long)max_distance)) {
    // Start a new scratch page and mark any previous page as write-protected
    if (*extra_space)
      mprotect(*extra_space, 4096, PROT_READ | PROT_EXEC);
    // Our new scratch space is initially executable and writable.
    *extra_len = 4096;
    *extra_space =
        maps_alloc_near(fd, addr, *extra_len,
                        PROT_READ | PROT_WRITE | PROT_EXEC, near, max_distance);
    _nx_debug_printf("alloc_scratch_space: mapped %x at %p (near %p)\n",
                     *extra_len, *extra_space, addr);
  }
  if (*extra_space) {
    *extra_len -= needed;
    return *extra_space + *extra_len;
  }
  _nx_fatal_printf("No space left to allocate scratch space");
}

/**
 * Compute the amount of space needed to accommodate relocated instructions
 *
 * @param[in]  code              relocatable instructions
 * @param[out] needed            total amount of bytes to write
 * @param[out] postamble         amount of bytes to relocate
 * @param[out] second            first instruction not to be relocated
 * @param[in]  detour_asm_size   size of static ASM body
 * @param[in]  jump_size         size of the jump snippet
 */
static inline void needed_space(const struct s_code *code, int *needed,
                                int *postamble, int *second,
                                size_t detour_asm_size, size_t jump_size) {
  int additional_bytes_to_relocate =
      (__WORDSIZE == 32 ? 6 : jump_size) - code[0].len;
  *second = 0;
  while (additional_bytes_to_relocate > 0) {
    *second = (*second + 1) % jump_size;
    additional_bytes_to_relocate -= code[*second].len;
  }
  *postamble = (code[*second].addr + code[*second].len) - code[0].addr;

  // The following is all the code that construct the various bits of
  // assembly code.
  *needed = detour_asm_size + *postamble + jump_size;
}

#endif /* SABRE_INCLUDES_ARCH_REWRITER_TOOLS_H_ */
