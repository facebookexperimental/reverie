/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef ELF_LOADING_H
#define ELF_LOADING_H

#include <gelf.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>

int elfld_getehdr(int, ElfW(Ehdr) *);
GElf_Sym find_elf_symbol(const char *, const char *, bool *);
bool read_elf_note(const char *path, Elf64_Word note_type, const char *owner,
                   void *notebuf, size_t *notesz);
bool read_elf_section(const char *path, const char *section_name, void *scbuf,
                      size_t *scsz);
ElfW(Addr) addr_of_elf_symbol(const char *, const char *, bool *);
ElfW(Addr) elfld_load_elf(int fd, ElfW(Ehdr) const *ehdr, size_t pagesize,
                          ElfW(Addr) * out_phdr, ElfW(Addr) * out_phnum,
                          const char **out_interp);

#endif /* !ELF_LOADING_H */
