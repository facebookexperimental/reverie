/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * Licensed under the BSD-style license in the root LICENSE file.
 */

#ifndef BOOTSTRAP_PRIVATE_SEGMENTS_H
#define BOOTSTRAP_PRIVATE_SEGMENTS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* The includer supplies DynamoRIO's bool type (including its C ABI).
 * Pure owner-local calculations shared with the native ownership self-test.
 * Authentication and safe reads are the loader's responsibility. No pointer in
 * these value records is dereferenced as an application address. */
enum { BOOTSTRAP_PRIVATE_MAX_PHDRS = 128, BOOTSTRAP_PRIVATE_MAX_RANGES = 8 };

typedef struct {
    uintptr_t vaddr, memsz, filesz, offset;
    bool readable;
} bootstrap_private_load_t;

typedef struct {
    uintptr_t start, end;
} bootstrap_private_segment_t;

typedef struct {
    uintptr_t base;
    size_t size, page_size, table_end;
    const bootstrap_private_load_t *loads;
    size_t load_count;
    const bootstrap_private_segment_t *recorded;
    size_t recorded_count;
} bootstrap_private_image_t;

static inline bool
bootstrap_private_table_size(size_t image_size, uintptr_t phoff, size_t phnum,
                             size_t phentsize, size_t header_size, size_t entry_size,
                             size_t *table_size)
{
    *table_size = 0;
    if (phnum == 0 || phnum > BOOTSTRAP_PRIVATE_MAX_PHDRS || entry_size == 0 ||
        phentsize != entry_size || phoff < header_size || phoff > image_size ||
        phnum > SIZE_MAX / entry_size)
        return false;
    size_t bytes = phnum * entry_size;
    if (bytes > image_size - phoff)
        return false;
    *table_size = bytes;
    return true;
}

static inline size_t
bootstrap_private_segments(const bootstrap_private_image_t *image,
                           bootstrap_private_segment_t out[BOOTSTRAP_PRIVATE_MAX_RANGES])
{
    memset(out, 0, BOOTSTRAP_PRIVATE_MAX_RANGES * sizeof(*out));
    size_t page = image->page_size;
    if (page == 0 || (page & (page - 1)) != 0 ||
        (image->base & (page - 1)) != 0 || image->size == 0 ||
        image->base > UINTPTR_MAX - image->size ||
        image->table_end == 0 || image->table_end > image->size ||
        image->loads == NULL || image->load_count == 0 ||
        image->load_count > BOOTSTRAP_PRIVATE_MAX_PHDRS || image->recorded == NULL ||
        (image->recorded_count != image->load_count &&
         image->recorded_count != image->load_count + 1))
        return 0;
    uintptr_t preferred = UINTPTR_MAX;
    for (size_t i = 0; i < image->load_count; ++i) {
        uintptr_t start = image->loads[i].vaddr & ~(uintptr_t)(page - 1);
        if (start < preferred)
            preferred = start;
    }
    if (preferred == UINTPTR_MAX)
        return 0;
    bootstrap_private_segment_t loads[BOOTSTRAP_PRIVATE_MAX_PHDRS];
    bool headers_owned = false;
    for (size_t i = 0; i < image->load_count; ++i) {
        const bootstrap_private_load_t *load = &image->loads[i];
        if (load->vaddr < preferred || load->memsz == 0 ||
            load->filesz > load->memsz ||
            (load->vaddr % page) != (load->offset % page))
            return 0;
        uintptr_t relative = load->vaddr - preferred;
        if (relative > image->size || load->memsz > image->size - relative)
            return 0;
        uintptr_t end = image->base + relative + load->memsz;
        if (end > UINTPTR_MAX - (page - 1))
            return 0;
        bootstrap_private_segment_t segment = {
            (image->base + relative) & ~(uintptr_t)(page - 1),
            (end + page - 1) & ~(uintptr_t)(page - 1)
        };
        if (segment.start < image->base ||
            segment.end > image->base + image->size || segment.start >= segment.end)
            return 0;
        if (load->offset == 0 && relative == 0 && load->readable &&
            load->filesz >= image->table_end)
            headers_owned = true;
        size_t j = i;
        while (j > 0 && loads[j - 1].start > segment.start) {
            loads[j] = loads[j - 1];
            --j;
        }
        loads[j] = segment;
    }
    if (!headers_owned)
        return 0;

    uintptr_t load_end = 0;
    for (size_t i = 0; i < image->load_count; ++i) {
        if (image->recorded[i].start != loads[i].start ||
            image->recorded[i].end != loads[i].end)
            return 0;
        if (loads[i].end > load_end)
            load_end = loads[i].end;
    }
    /* module_walk_program_headers can add exactly this synthetic tail. It
     * reconciles metadata only: it never creates an ownership interval. */
    if (image->recorded_count == image->load_count + 1) {
        const bootstrap_private_segment_t *tail = &image->recorded[image->load_count];
        if (tail->start != load_end || tail->end != image->base + image->size ||
            tail->start >= tail->end)
            return 0;
    }
    size_t count = 0;
    for (size_t i = 0; i < image->load_count; ++i) {
        if (count > 0 && loads[count - 1].end >= loads[i].start) {
            if (loads[i].end > loads[count - 1].end)
                loads[count - 1].end = loads[i].end;
        } else {
            loads[count++] = loads[i];
        }
    }
    if (count > BOOTSTRAP_PRIVATE_MAX_RANGES)
        return 0;
    memcpy(out, loads, count * sizeof(*out));
    return count;
}

#endif
