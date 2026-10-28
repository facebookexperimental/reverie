/*
 * e9elf.h
 * Copyright (C) 2020 National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __E9ELF_H
#define __E9ELF_H

#include <cstdint>

#include "e9alloc.h"
#include "e9mapping.h"
#include "e9patch.h"

#ifndef PT_GNU_PROPERTY
#define PT_GNU_PROPERTY                     0x6474e553
#define NT_GNU_PROPERTY_TYPE_0              5
#define GNU_PROPERTY_X86_FEATURE_1_AND      0xc0000002
#define GNU_PROPERTY_X86_FEATURE_1_IBT      0x1
#define GNU_PROPERTY_X86_FEATURE_1_SHSTK    0x2
#endif

bool parseElf(Binary *B);
size_t emitElf(Binary *B, const MappingSet &mappings, size_t mapping_size);

size_t emitLoaderMap(uint8_t *data, intptr_t addr, size_t len, off_t offset,
    bool r, bool w, bool x, uint32_t type, intptr_t *ub);

#endif
