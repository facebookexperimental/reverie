/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * Licensed under the BSD-style license in the root LICENSE file.
 */

/* Included only by the existing initialization self-test. The live oracle
 * derives expected LOAD pages from OS mappings and loaded ELF bytes, never
 * from the ownership cache or its derivation helper. */
#include "../vendor/dynamorio/core/unix/bootstrap_private_segments.h"

enum { BOOTSTRAP_TEST_MAX_PHDRS = 128, BOOTSTRAP_TEST_MAX_MAPS = 32 };
typedef struct {
  uint64_t start, end;
} bootstrap_test_interval_t;
typedef struct {
  uint64_t header, symbol;
  size_t count, bss_count;
  bootstrap_test_interval_t loads[BOOTSTRAP_TEST_MAX_PHDRS];
} bootstrap_test_image_t;

static bool bootstrap_test_read(uint64_t address, void* out, size_t size) {
  size_t read = 0;
  return address <= UINT64_MAX - size &&
      dr_safe_read((const void*)(uintptr_t)address, size, out, &read) &&
      read == size;
}

/* Relocate relative to the offset-zero LOAD instead of assuming positive bias. */
static bool bootstrap_test_relocate(
    uint64_t header, uint64_t header_vaddr, uint64_t vaddr, uint64_t* result) {
  if (vaddr >= header_vaddr) {
    uint64_t delta = vaddr - header_vaddr;
    if (header > UINT64_MAX - delta)
      return false;
    *result = header + delta;
  } else {
    uint64_t delta = header_vaddr - vaddr;
    if (header < delta)
      return false;
    *result = header - delta;
  }
  return true;
}

static bool bootstrap_test_image_at(uint64_t header, uint64_t symbol,
    uint64_t page, bootstrap_test_image_t* image) {
  Elf64_Ehdr eh;
  Elf64_Phdr ph[BOOTSTRAP_TEST_MAX_PHDRS];
  if (!bootstrap_test_read(header, &eh, sizeof(eh)) ||
      memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
      eh.e_ident[EI_CLASS] != ELFCLASS64 ||
      eh.e_ident[EI_DATA] != ELFDATA2LSB || eh.e_machine != EM_X86_64 ||
      eh.e_type != ET_DYN || eh.e_version != EV_CURRENT ||
      eh.e_ehsize != sizeof(eh) || eh.e_phoff < sizeof(eh) ||
      eh.e_phentsize != sizeof(ph[0]) ||
      eh.e_phnum == 0 || eh.e_phnum > BOOTSTRAP_TEST_MAX_PHDRS ||
      eh.e_phoff > UINT64_MAX - eh.e_phnum * sizeof(ph[0]))
    return false;
  uint64_t table_end = eh.e_phoff + eh.e_phnum * sizeof(ph[0]);
  if (header > UINT64_MAX - eh.e_phoff ||
      !bootstrap_test_read(header + eh.e_phoff, ph, eh.e_phnum * sizeof(ph[0])))
    return false;
  size_t header_loads = 0;
  uint64_t header_vaddr = 0;
  for (size_t i = 0; i < eh.e_phnum; ++i)
    if (ph[i].p_type == PT_LOAD && ph[i].p_offset == 0 &&
        ph[i].p_filesz >= sizeof(eh) && ph[i].p_filesz >= table_end) {
      ++header_loads;
      header_vaddr = ph[i].p_vaddr;
    }
  if (header_loads != 1)
    return false;
  memset(image, 0, sizeof(*image));
  image->header = header;
  image->symbol = symbol;
  bool executable_symbol = false;
  for (size_t i = 0; i < eh.e_phnum; ++i) {
    if (ph[i].p_type != PT_LOAD)
      continue;
    if (ph[i].p_filesz > ph[i].p_memsz)
      return false;
    if (ph[i].p_memsz == 0)
      continue;
    uint64_t lo;
    if (!bootstrap_test_relocate(header, header_vaddr, ph[i].p_vaddr, &lo) ||
        lo > UINT64_MAX - ph[i].p_memsz)
      return false;
    uint64_t hi = lo + ph[i].p_memsz;
    if (hi > UINT64_MAX - (page - 1))
      return false;
    executable_symbol |= (ph[i].p_flags & PF_X) != 0 && lo <= symbol && symbol < hi;
    image->bss_count += ph[i].p_memsz > ph[i].p_filesz;
    image->loads[image->count++] = (bootstrap_test_interval_t){
        lo & ~(page - 1), (hi + page - 1) & ~(page - 1)};
  }
  if (!executable_symbol || image->count == 0)
    return false;
  /* Independent sorting; do not assume PHDR order or cache coalescing. */
  for (size_t i = 1; i < image->count; ++i) {
    bootstrap_test_interval_t value = image->loads[i];
    size_t j = i;
    while (j > 0 && image->loads[j - 1].start > value.start) {
      image->loads[j] = image->loads[j - 1];
      --j;
    }
    image->loads[j] = value;
  }
  return true;
}

static bool bootstrap_test_find_image(bootstrap_test_image_t* image) {
  uint64_t page = dr_page_size();
  uint64_t symbol = (uint64_t)(uintptr_t)dr_get_private_reservations;
  if (page == 0 || (page & (page - 1)) != 0)
    return false;
  uint64_t probe = symbol;
  for (size_t i = 0; i < BOOTSTRAP_TEST_MAX_MAPS; ++i) {
    dr_mem_info_t info;
    if (!dr_query_memory_ex((const byte*)(uintptr_t)probe, &info))
      return false;
    uint64_t base = (uint64_t)(uintptr_t)info.base_pc;
    if (base > probe)
      return false;
    if ((info.prot & DR_MEMPROT_READ) != 0 &&
        bootstrap_test_image_at(base, symbol, page, image))
      return true;
    if (base == 0)
      return false;
    probe = base - 1;
  }
  return false; /* Bound reached is a test failure, never a skipped oracle. */
}

static bool bootstrap_test_fully_covered(
    const private_memory_snapshot_t* current, uint64_t lo, uint64_t hi) {
  uint64_t cursor = lo;
  for (uint32_t i = 0; i < current->count && cursor < hi; ++i) {
    if (current->ranges[i].end <= cursor)
      continue;
    if (current->ranges[i].start > cursor)
      return false;
    cursor = current->ranges[i].end < hi ? current->ranges[i].end : hi;
  }
  return cursor == hi;
}

static bool bootstrap_test_owned_image(const private_memory_snapshot_t* current,
    bootstrap_test_image_t* image) {
  if (!private_memory_test_check(
          bootstrap_test_find_image(image), "bootstrap-loaded-elf-phdrs") ||
      !private_memory_test_check(image->bss_count != 0, "bootstrap-actual-bss"))
    return false;
  for (size_t i = 0; i < image->count; ++i)
    if (!private_memory_test_check(
            bootstrap_test_fully_covered(current,
                image->loads[i].start, image->loads[i].end),
            "bootstrap-full-load-and-bss-covered"))
      return false;
  return true;
}

static bool derivation_control(const char* name,
    const bootstrap_private_image_t* image, size_t expected_count,
    const bootstrap_private_segment_t* expected) {
  bootstrap_private_segment_t out[BOOTSTRAP_PRIVATE_MAX_RANGES];
  bootstrap_private_segment_t all_expected[BOOTSTRAP_PRIVATE_MAX_RANGES] = {0};
  memset(out, 0xa5, sizeof(out));
  if (expected_count != 0)
    memcpy(all_expected, expected, expected_count * sizeof(*expected));
  size_t count = bootstrap_private_segments(image, out);
  return private_memory_test_check(count == expected_count &&
      memcmp(out, all_expected, sizeof(out)) == 0, name);
}

static bool run_private_memory_derivation_controls(void) {
  const uintptr_t base = UINT64_C(0x10000000);
  const uintptr_t preferred = UINT64_C(0x71000000);
  const size_t page = 4096;
  const bootstrap_private_load_t original_loads[2] = {
      {preferred, 0x1000, 0x1000, 0, true},
      {preferred + 0x3000, 0x1234, 0x234, 0x3000, false},
  };
  const bootstrap_private_segment_t original_recorded[2] = {
      {base, base + 0x1000}, {base + 0x3000, base + 0x5000},
  };
  const bootstrap_private_image_t original = {
      base, 0x8000, page, 0x400, original_loads, 2, original_recorded, 2,
  };
  if (!derivation_control("derive-bss-and-real-interval-gap", &original,
          2, original_recorded))
    return false;

  /* The exact output proves BSS rounding and excludes the two-page gap. */
  bootstrap_private_load_t loads[9];
  bootstrap_private_segment_t recorded[10];
  memcpy(loads, original_loads, sizeof(original_loads));
  memcpy(recorded, original_recorded, sizeof(original_recorded));
  bootstrap_private_image_t image = original;
  image.loads = loads;
  image.recorded = recorded;
  loads[1].vaddr = preferred + page;
  loads[1].offset = page;
  recorded[1] = (bootstrap_private_segment_t){base + page, base + 3 * page};
  const bootstrap_private_segment_t touching = {base, base + 3 * page};
  if (!derivation_control("derive-touching-coalesces", &image, 1, &touching))
    return false;

  loads[0] = original_loads[1];
  loads[1] = original_loads[0];
  memcpy(recorded, original_recorded, sizeof(original_recorded));
  if (!derivation_control("derive-phdr-order-independent", &image,
          2, original_recorded))
    return false;

  memcpy(loads, original_loads, sizeof(original_loads));
  recorded[2] = (bootstrap_private_segment_t){base + 0x5000, base + 0x8000};
  image.recorded_count = 3;
  if (!derivation_control("derive-exact-synthetic-tail-excluded", &image,
          2, original_recorded))
    return false;
  recorded[2].start += page;
  if (!derivation_control("derive-tail-wrong-start-zero", &image, 0, NULL))
    return false;
  recorded[2].start = base + 0x5000;
  recorded[2].end -= page;
  if (!derivation_control("derive-tail-wrong-end-zero", &image, 0, NULL))
    return false;
  recorded[2] = (bootstrap_private_segment_t){base + 0x8000, base + 0x8000};
  if (!derivation_control("derive-tail-empty-zero", &image, 0, NULL))
    return false;
  image.recorded_count = 4;
  if (!derivation_control("derive-two-extra-segments-zero", &image, 0, NULL))
    return false;

  static const char* const malformed[] = {
      "derive-recorded-start-zero", "derive-recorded-end-zero",
      "derive-recorded-order-zero", "derive-recorded-missing-zero",
      "derive-zero-load-count-zero", "derive-excessive-load-count-zero",
      "derive-filesz-over-memsz-zero", "derive-zero-memsz-zero",
      "derive-incongruent-offset-zero", "derive-unreadable-headers-zero",
      "derive-table-not-in-header-load-zero", "derive-zero-table-end-zero",
      "derive-table-end-outside-zero", "derive-load-outside-envelope-zero",
      "derive-memsz-outside-envelope-zero", "derive-rounded-end-outside-zero",
      "derive-base-envelope-overflow-zero", "derive-unaligned-base-zero",
      "derive-zero-page-zero", "derive-non-power-page-zero",
  };
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
    memcpy(loads, original_loads, sizeof(original_loads));
    memcpy(recorded, original_recorded, sizeof(original_recorded));
    image = original;
    image.loads = loads;
    image.recorded = recorded;
    switch (i) {
      case 0: ++recorded[1].start; break;
      case 1: --recorded[1].end; break;
      case 2:
        recorded[0] = original_recorded[1];
        recorded[1] = original_recorded[0];
        break;
      case 3: image.recorded_count = 1; break;
      case 4: image.load_count = 0; break;
      case 5: image.load_count = BOOTSTRAP_PRIVATE_MAX_PHDRS + 1; break;
      case 6: loads[1].filesz = loads[1].memsz + 1; break;
      case 7: loads[1].memsz = 0; break;
      case 8: ++loads[1].offset; break;
      case 9: loads[0].readable = false; break;
      case 10: image.table_end = 0x1001; break;
      case 11: image.table_end = 0; break;
      case 12: image.table_end = image.size + 1; break;
      case 13: loads[1].vaddr = preferred + 0x9000; break;
      case 14: image.size = 0x4123; break;
      case 15: image.size = 0x4800; break;
      case 16: image.base = UINTPTR_MAX & ~(uintptr_t)(page - 1); break;
      case 17: ++image.base; break;
      case 18: image.page_size = 0; break;
      case 19: image.page_size = 0x1800; break;
    }
    if (!derivation_control(malformed[i], &image, 0, NULL))
      return false;
  }

  /* base+size is representable; only final page rounding overflows. */
  image = original;
  image.base = UINTPTR_MAX - (2 * page - 1);
  image.size = 2 * page - 1;
  loads[0] = (bootstrap_private_load_t){preferred, 2 * page - 1, page, 0, true};
  image.loads = loads;
  image.load_count = 1;
  recorded[0] = (bootstrap_private_segment_t){image.base, UINTPTR_MAX};
  image.recorded = recorded;
  image.recorded_count = 1;
  if (!derivation_control("derive-page-rounding-overflow-zero", &image, 0, NULL))
    return false;

  if (!private_memory_test_check(BOOTSTRAP_PRIVATE_MAX_RANGES == 8,
          "derive-current-capacity-is-eight"))
    return false;
  image = original;
  image.size = 0x20000;
  image.loads = loads;
  image.recorded = recorded;
  for (size_t i = 0; i < 9; ++i) {
    uintptr_t offset = 2 * i * page;
    loads[i] = (bootstrap_private_load_t){preferred + offset, page, page, offset, true};
    recorded[i] = (bootstrap_private_segment_t){base + offset, base + offset + page};
  }
  image.load_count = image.recorded_count = 8;
  if (!derivation_control("derive-eight-disjoint-exact", &image, 8, recorded))
    return false;
  image.load_count = image.recorded_count = 9;
  if (!derivation_control("derive-nine-disjoint-whole-refusal-zero", &image, 0, NULL))
    return false;
  for (size_t i = 0; i < 9; ++i) {
    uintptr_t offset = i * page;
    loads[i].vaddr = preferred + offset;
    loads[i].offset = offset;
    recorded[i] = (bootstrap_private_segment_t){base + offset, base + offset + page};
  }
  const bootstrap_private_segment_t nine_touching = {base, base + 9 * page};
  if (!derivation_control("derive-nine-loads-fit-after-coalescing", &image,
          1, &nine_touching))
    return false;

  const struct {
    const char* name;
    size_t image_size;
    uintptr_t phoff;
    size_t phnum, phentsize, header_size, entry_size, expected_bytes;
    bool accepted;
  } tables[] = {
      {"derive-table-valid", 0x8000, 64, 2, 56, 64, 56, 112, true},
      {"derive-table-max-count", 0x8000, 64, 128, 56, 64, 56, 7168, true},
      {"derive-table-count-zero", 0x8000, 64, 0, 56, 64, 56, 0, false},
      {"derive-table-count-excess", 0x8000, 64, 129, 56, 64, 56, 0, false},
      {"derive-table-entry-mismatch", 0x8000, 64, 2, 55, 64, 56, 0, false},
      {"derive-table-entry-zero", 0x8000, 64, 2, 0, 64, 0, 0, false},
      {"derive-table-before-header", 0x8000, 63, 2, 56, 64, 56, 0, false},
      {"derive-table-offset-outside", 0x8000, 0x8001, 1, 56, 64, 56, 0, false},
      {"derive-table-truncated", 0x8000, 0x8000 - 55, 1, 56, 64, 56, 0, false},
      {"derive-table-multiply-overflow", SIZE_MAX, 64, 2,
          SIZE_MAX / 2 + 1, 64, SIZE_MAX / 2 + 1, 0, false},
      {"derive-table-end-overflow", SIZE_MAX, UINTPTR_MAX, 1, 56, 64, 56, 0, false},
  };
  for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); ++i) {
    size_t bytes = SIZE_MAX;
    bool accepted = bootstrap_private_table_size(tables[i].image_size,
        tables[i].phoff, tables[i].phnum, tables[i].phentsize,
        tables[i].header_size, tables[i].entry_size, &bytes);
    if (!private_memory_test_check(accepted == tables[i].accepted &&
            bytes == tables[i].expected_bytes, tables[i].name))
      return false;
  }
  dr_fprintf(diagnostic_file, "PRIVATE_MEMORY_BOOTSTRAP derivation_controls=1\n");
  return true;
}
