/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The `vm_flags` the list of mappings reports (`vm_flags`,
//! `mapping_list`), driven through the executor's syscalls as a guest makes
//! them, against the `VmFlags` Linux 7.1.3 printed for the same calls (the
//! host probes of dh-9j8ue: `probe/vmflags.py`, `tmp/probe2.py` and
//! `tmp/probe3.py`, quoted at each case), and the guard flag's upkeep
//! across every call that edits the layout.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::vm_flags::HostVmFacts;
use super::vm_flags::inject_host_vm_facts;
use super::vm_flags::mnemonics;
use super::*;

const PAGE: u64 = PAGE_SIZE;
const R: u64 = libc::PROT_READ as u64;
const RW: u64 = (libc::PROT_READ | libc::PROT_WRITE) as u64;
const PRIVATE: u64 = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
const FIXED: u64 = libc::MAP_FIXED as u64;
/// The host this backend's own host matches (Linux 7.1.3, which prints
/// `gu`, with `vm.overcommit_memory` 0).
const HOST: HostVmFacts = HostVmFacts {
    guard_flag_printed: Some(true),
    overcommit_memory: Some(0),
};

struct Directory(std::path::PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "reverie-linuxemu-vm-flags-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

/// The address space of a minimal image, loaded as the backend loads a
/// program, and an executor of its first thread.
fn loaded(directory: &Directory) -> (ElfExecutor, GuestMemory) {
    let mut memory = GuestMemory::new(0, 32 * 1024 * 1024).unwrap();
    let mut state = crate::elf::load_static_elf(
        &mut memory,
        &crate::elf::minimal_test_elf(&[0xf4]),
        &["vm-flags"],
        &[],
        &directory.0,
    )
    .unwrap();
    state.children = ChildWaitContext::test_root();
    (ElfExecutor::new(state, false), memory)
}

fn call(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    number: libc::c_long,
    args: [u64; 6],
) -> i64 {
    executor.execute(&SyscallRequest::new(number as u64, args), memory)
}

/// A new anonymous mapping of `pages` pages; `address` with `MAP_FIXED` in
/// `flags`.
fn mmap(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    address: u64,
    pages: u64,
    prot: u64,
    flags: u64,
) -> u64 {
    let mapped = call(
        executor,
        memory,
        libc::SYS_mmap,
        [address, pages * PAGE, prot, flags, u64::MAX, 0],
    );
    assert!(mapped > 0, "mmap {flags:#x}: {mapped}");
    mapped as u64
}

fn ok(result: i64) {
    assert_eq!(result, 0);
}

/// The line that holds `address` in the executor's list of mappings.
fn line(executor: &ElfExecutor, memory: &GuestMemory, address: u64) -> reverie::MappingFact {
    let map = executor.memory_map(memory, executor.state.tid).unwrap();
    map.mappings
        .iter()
        .find(|mapping| mapping.start <= address && address < mapping.end)
        .cloned()
        .unwrap_or_else(|| panic!("no line holds {address:#x}: {map:?}"))
}

/// The line's range and its `VmFlags` text, `None` where they are not
/// established.
fn flags_at(
    executor: &ElfExecutor,
    memory: &GuestMemory,
    address: u64,
) -> (u64, u64, Option<String>) {
    let line = line(executor, memory, address);
    (line.start, line.end, mnemonics(line.vm_flags))
}

fn text(flags: &str) -> Option<String> {
    Some(flags.to_owned())
}

/// R1, R2: the flags an mmap sets are Linux's, through `MAP_STACK`
/// (`calc_vm_flag_bits`: `VM_NOHUGEPAGE`), `MAP_GROWSDOWN`, `MAP_LOCKED`
/// and `MAP_SYNC`, and `MAP_NORESERVE` (honoured with overcommit mode 0);
/// a `MAP_HUGETLB` line has none.
#[test]
fn mmap_flags_become_the_lines_flags_as_linux_sets_them() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let stack = libc::MAP_STACK as u64;
    // A gap page between cases keeps every line apart.
    fn map(executor: &mut ElfExecutor, memory: &GuestMemory, prot: u64, flags: u64) -> u64 {
        let address = mmap(executor, memory, 0, 2, prot, flags);
        ok(call(
            executor,
            memory,
            libc::SYS_munmap,
            [address + PAGE, PAGE, 0, 0, 0, 0],
        ));
        address
    }
    let cases = [
        // probe2 "anon rw MAP_STACK": `rd wr mr mw me ac nh`.
        (
            "MAP_STACK",
            map(&mut executor, &memory, RW, PRIVATE | stack),
            "rd wr mr mw me ac nh",
        ),
        // probe/vmflags.py: MAP_GROWSDOWN and MAP_LOCKED add `gd` and `lo`.
        (
            "MAP_GROWSDOWN",
            map(
                &mut executor,
                &memory,
                RW,
                PRIVATE | libc::MAP_GROWSDOWN as u64,
            ),
            "rd wr mr mw me gd ac",
        ),
        (
            "MAP_LOCKED",
            map(
                &mut executor,
                &memory,
                RW,
                PRIVATE | libc::MAP_LOCKED as u64,
            ),
            "rd wr mr mw me lo ac",
        ),
        // probe2 "anon rw MAP_SYNC": adds `sf`.
        (
            "MAP_SYNC",
            map(&mut executor, &memory, RW, PRIVATE | libc::MAP_SYNC as u64),
            "rd wr mr mw me ac sf",
        ),
        // probe2 "anon MAP_NORESERVE rw": `rd wr mr mw me nr`.
        (
            "MAP_NORESERVE",
            map(
                &mut executor,
                &memory,
                RW,
                PRIVATE | libc::MAP_NORESERVE as u64,
            ),
            "rd wr mr mw me nr",
        ),
        // probe/vmflags.py "shared anon": `rd wr sh mr mw me ms`.
        (
            "shared anonymous",
            map(
                &mut executor,
                &memory,
                RW,
                (libc::MAP_SHARED | libc::MAP_ANONYMOUS) as u64,
            ),
            "rd wr sh mr mw me ms",
        ),
        (
            "anonymous read-only",
            map(&mut executor, &memory, R, PRIVATE),
            "rd mr mw me",
        ),
    ];
    // glibc's thread stack: PROT_NONE with MAP_STACK, then made writable
    // (probe2: `rd wr mr mw me ac nh`).
    let glibc = map(&mut executor, &memory, 0, PRIVATE | stack);
    ok(call(
        &mut executor,
        &memory,
        libc::SYS_mprotect,
        [glibc, PAGE, RW, 0, 0, 0],
    ));
    // probe2 "anon MAP_HUGETLB|MAP_NORESERVE": `ht` with 2 MiB pages, which
    // these pages are not: no flags.
    let huge = map(
        &mut executor,
        &memory,
        RW,
        PRIVATE | (libc::MAP_HUGETLB | libc::MAP_NORESERVE) as u64,
    );
    for (what, address, linux) in cases {
        assert_eq!(
            flags_at(&executor, &memory, address),
            (address, address + PAGE, text(linux)),
            "{what}"
        );
    }
    assert_eq!(
        flags_at(&executor, &memory, glibc).2,
        text("rd wr mr mw me ac nh")
    );
    assert_eq!(flags_at(&executor, &memory, huge).2, None);
}

/// R2: a line that differs from its neighbours only in `gd` or `lo` stays
/// a line of its own, as Linux merges no mappings whose flags differ.
#[test]
fn a_locked_or_grows_down_mapping_does_not_merge_with_its_neighbours() {
    let _host = inject_host_vm_facts(HOST);
    for (flag, name) in [(libc::MAP_LOCKED, "lo"), (libc::MAP_GROWSDOWN, "gd")] {
        let directory = Directory::new();
        let (mut executor, memory) = loaded(&directory);
        let base = mmap(&mut executor, &memory, 0, 3, RW, PRIVATE);
        mmap(
            &mut executor,
            &memory,
            base + PAGE,
            1,
            RW,
            PRIVATE | FIXED | flag as u64,
        );
        let plain = text("rd wr mr mw me ac");
        let flagged = if name == "lo" {
            text("rd wr mr mw me lo ac")
        } else {
            text("rd wr mr mw me gd ac")
        };
        assert_eq!(
            [base, base + PAGE, base + 2 * PAGE].map(|at| flags_at(&executor, &memory, at)),
            [
                (base, base + PAGE, plain.clone()),
                (base + PAGE, base + 2 * PAGE, flagged),
                (base + 2 * PAGE, base + 3 * PAGE, plain),
            ],
            "{name}"
        );
    }
}

/// `MAP_NORESERVE` under overcommit mode 2, which ignores it: the mapping is
/// charged (`ac`, no `nr`); with the mode not known, the line has no flags,
/// while a line without `MAP_NORESERVE` keeps its own.
#[test]
fn map_noreserve_follows_the_hosts_overcommit_mode() {
    let directory = Directory::new();
    let noreserve = PRIVATE | libc::MAP_NORESERVE as u64;
    {
        let _host = inject_host_vm_facts(HostVmFacts {
            overcommit_memory: Some(2),
            ..HOST
        });
        let (mut executor, memory) = loaded(&directory);
        let address = mmap(&mut executor, &memory, 0, 1, RW, noreserve);
        assert_eq!(
            flags_at(&executor, &memory, address).2,
            text("rd wr mr mw me ac")
        );
    }
    let _host = inject_host_vm_facts(HostVmFacts {
        overcommit_memory: None,
        ..HOST
    });
    let (mut executor, memory) = loaded(&directory);
    let address = mmap(&mut executor, &memory, 0, 1, RW, noreserve);
    let plain = mmap(&mut executor, &memory, 0, 1, R, PRIVATE);
    assert_eq!(flags_at(&executor, &memory, address).2, None);
    assert_eq!(flags_at(&executor, &memory, plain).2, text("rd mr mw me"));
}

/// R3: `mprotect` that removes write from private anonymous memory leaves
/// its charge unknown (probe2: `rd mr mw me` unwritten, `rd mr mw me ac`
/// written), so the line has no flags; made writable again it is charged,
/// and known. A private file mapping keeps its charge (probe2: `rd mr mw
/// me ac`), and so does guarded anonymous memory (probe2: `rd mr mw me gu
/// ac`). A merged line one of whose runs is unknown is unknown, whichever
/// run comes first.
#[test]
fn removing_write_from_private_anonymous_memory_leaves_its_charge_unknown() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let protect = |executor: &mut ElfExecutor, address: u64, pages: u64, prot: u64| {
        ok(call(
            executor,
            &memory,
            libc::SYS_mprotect,
            [address, pages * PAGE, prot, 0, 0, 0],
        ));
    };
    let anonymous = mmap(&mut executor, &memory, 0, 3, RW, PRIVATE);
    protect(&mut executor, anonymous + PAGE, 1, R);
    assert_eq!(
        [anonymous, anonymous + PAGE, anonymous + 2 * PAGE]
            .map(|at| flags_at(&executor, &memory, at).2),
        [text("rd wr mr mw me ac"), None, text("rd wr mr mw me ac")]
    );
    protect(&mut executor, anonymous + PAGE, 1, RW);
    assert_eq!(
        flags_at(&executor, &memory, anonymous),
        (anonymous, anonymous + 3 * PAGE, text("rd wr mr mw me ac"))
    );

    // A private file mapping, read-write and then read-only.
    let path = directory.0.join("rwfile");
    std::fs::write(&path, vec![0u8; 2 * PAGE as usize]).unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let file_facts = super::vm_flags::FileVmFacts::of(&file);
    let fd = 77;
    executor.state.files.insert(fd, file);
    let mut owner = memory.clone();
    let mapped = match execute_basic_syscall(
        &mut owner,
        &mut executor.state,
        &SyscallRequest::new(
            libc::SYS_mmap as u64,
            [0, 2 * PAGE, RW, libc::MAP_PRIVATE as u64, fd as u64, 0],
        ),
    ) {
        SyscallAction::Continue { result, .. } => result,
        _ => panic!("mmap of a file"),
    };
    assert!(mapped > 0, "{mapped}");
    let mapped = mapped as u64;
    match execute_basic_syscall(
        &mut owner,
        &mut executor.state,
        &SyscallRequest::new(libc::SYS_mprotect as u64, [mapped, 2 * PAGE, R, 0, 0, 0]),
    ) {
        SyscallAction::Continue { result: 0, .. } => {}
        _ => panic!("mprotect of a file mapping"),
    }
    let file_line = line(&executor, &memory, mapped);
    if file_facts.is_some() {
        assert_eq!(mnemonics(file_line.vm_flags), text("rd mr mw me ac"));
    } else {
        // The test directory's filesystem is not one whose flags are
        // known; the line says so.
        assert_eq!(file_line.vm_flags, None);
    }

    // Guarded anonymous memory, never written, made read-only.
    let guarded = mmap(&mut executor, &memory, 0, 3, RW, PRIVATE);
    ok(call(
        &mut executor,
        &memory,
        libc::SYS_madvise,
        [guarded, PAGE, mm::MADV_GUARD_INSTALL as u64, 0, 0, 0],
    ));
    protect(&mut executor, guarded, 3, R);
    assert_eq!(
        flags_at(&executor, &memory, guarded),
        (guarded, guarded + 3 * PAGE, text("rd mr mw me gu ac"))
    );

    // A guarded read-only page, and above it a page made read-only while
    // apart from it: they merge, the first run known and the second not,
    // and the line is unknown. In an address space of its own, so that no
    // other mapping joins the line.
    let (mut executor, memory) = loaded(&directory);
    let protect = |executor: &mut ElfExecutor, address: u64, pages: u64, prot: u64| {
        ok(call(
            executor,
            &memory,
            libc::SYS_mprotect,
            [address, pages * PAGE, prot, 0, 0, 0],
        ));
    };
    let known = mmap(&mut executor, &memory, 0, 2, RW, PRIVATE);
    let above = known + PAGE;
    protect(&mut executor, above, 1, 0);
    ok(call(
        &mut executor,
        &memory,
        libc::SYS_madvise,
        [known, PAGE, mm::MADV_GUARD_INSTALL as u64, 0, 0, 0],
    ));
    protect(&mut executor, known, 1, R);
    protect(&mut executor, above, 1, RW);
    protect(&mut executor, above, 1, R);
    let declared = |address: u64| {
        memory
            .declared_mapping(memory.user_range_to_guest(address, PAGE).unwrap())
            .unwrap()
            .flags
    };
    assert_eq!(
        declared(known) & (FLAG_ACCOUNT_UNKNOWN | FLAG_MAYBE_GUARD),
        FLAG_MAYBE_GUARD
    );
    assert_eq!(
        declared(above) & (FLAG_ACCOUNT_UNKNOWN | FLAG_MAYBE_GUARD),
        FLAG_ACCOUNT_UNKNOWN
    );
    assert_eq!(
        flags_at(&executor, &memory, known),
        (known, known + 2 * PAGE, None)
    );
}

/// The guard flag `gu` (R2): an install marks every page of the line it
/// touches, not only the guarded one; a split keeps it on both parts
/// (probe2 "guard on page 0, mprotect page 3 r"); a plain mapping that
/// merges with a guarded one gets it, and keeps it once the guarded part is
/// unmapped (probe3: `rd wr mr mw me gu ac` for the merged 4 pages, then for
/// the plain 2); a remove leaves it.
#[test]
fn the_guard_flag_marks_the_whole_line_and_sticks_through_splits_and_merges() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let guard = |executor: &mut ElfExecutor, address: u64, advice: libc::c_int| {
        ok(call(
            executor,
            &memory,
            libc::SYS_madvise,
            [address, PAGE, advice as u64, 0, 0, 0],
        ));
    };
    let four = mmap(&mut executor, &memory, 0, 4, RW, PRIVATE);
    guard(&mut executor, four, mm::MADV_GUARD_INSTALL);
    assert_eq!(
        flags_at(&executor, &memory, four + 3 * PAGE),
        (four, four + 4 * PAGE, text("rd wr mr mw me gu ac"))
    );
    // The install marks every page of the line, not only the advised one, as
    // `madvise_guard_install` sets VM_MAYBE_GUARD on the whole mapping; so no
    // later edit has to spread it first.
    assert_eq!(
        memory
            .declared_mapping(memory.user_range_to_guest(four + 3 * PAGE, PAGE).unwrap())
            .map(|declared| declared.flags & FLAG_MAYBE_GUARD),
        Some(FLAG_MAYBE_GUARD)
    );
    ok(call(
        &mut executor,
        &memory,
        libc::SYS_mprotect,
        [four + 3 * PAGE, PAGE, R, 0, 0, 0],
    ));
    assert_eq!(
        [four, four + 3 * PAGE].map(|at| flags_at(&executor, &memory, at)),
        [
            (four, four + 3 * PAGE, text("rd wr mr mw me gu ac")),
            (four + 3 * PAGE, four + 4 * PAGE, text("rd mr mw me gu ac")),
        ]
    );
    guard(&mut executor, four, mm::MADV_GUARD_REMOVE);
    assert_eq!(
        flags_at(&executor, &memory, four).2,
        text("rd wr mr mw me gu ac")
    );

    // probe3's sticky merge, in an address space of its own: a guarded
    // 2-page mapping, a plain 2-page one placed right below it, then the
    // guarded one unmapped.
    let (mut executor, memory) = loaded(&directory);
    let guard = |executor: &mut ElfExecutor, address: u64, advice: libc::c_int| {
        ok(call(
            executor,
            &memory,
            libc::SYS_madvise,
            [address, PAGE, advice as u64, 0, 0, 0],
        ));
    };
    let base = mmap(&mut executor, &memory, 0, 4, 0, PRIVATE);
    ok(call(
        &mut executor,
        &memory,
        libc::SYS_munmap,
        [base, 4 * PAGE, 0, 0, 0, 0],
    ));
    let top = mmap(
        &mut executor,
        &memory,
        base + 2 * PAGE,
        2,
        RW,
        PRIVATE | FIXED,
    );
    guard(&mut executor, top, mm::MADV_GUARD_INSTALL);
    let low = mmap(&mut executor, &memory, base, 2, RW, PRIVATE | FIXED);
    assert_eq!(
        flags_at(&executor, &memory, low),
        (base, base + 4 * PAGE, text("rd wr mr mw me gu ac"))
    );
    // The plain pages do not have the flag yet; the line does.
    assert_eq!(
        memory
            .declared_mapping(memory.user_range_to_guest(low, PAGE).unwrap())
            .map(|declared| declared.flags & FLAG_MAYBE_GUARD),
        Some(0)
    );
    ok(call(
        &mut executor,
        &memory,
        libc::SYS_munmap,
        [top, 2 * PAGE, 0, 0, 0, 0],
    ));
    assert_eq!(
        flags_at(&executor, &memory, low),
        (base, base + 2 * PAGE, text("rd wr mr mw me gu ac"))
    );
}

/// The guard flag sticks to a line of the stack window that a neighbour
/// merges with, as it does outside the window. Probe
/// (`stack_guard_merge.c`, Linux 7.1.3): a read-only page of the main stack,
/// guarded, prints `rd mr mw me gd gu ac`; made read-only, the page below it
/// joins its mapping, and the two pages print `rd mr mw me gd gu ac`.
#[test]
fn the_guard_flag_sticks_to_a_merged_stack_window_line() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let page = (executor.state.stack_pointer & !(PAGE - 1)) - 8 * PAGE;
    let below = page - PAGE;
    let read_only = |executor: &mut ElfExecutor, address: u64| {
        ok(call(
            executor,
            &memory,
            libc::SYS_mprotect,
            [address, PAGE, R, 0, 0, 0],
        ));
    };
    read_only(&mut executor, page);
    ok(call(
        &mut executor,
        &memory,
        libc::SYS_madvise,
        [page, PAGE, mm::MADV_GUARD_INSTALL as u64, 0, 0, 0],
    ));
    assert_eq!(
        flags_at(&executor, &memory, page),
        (page, page + PAGE, text("rd mr mw me gd gu ac"))
    );
    read_only(&mut executor, below);
    assert_eq!(
        [below, page].map(|at| flags_at(&executor, &memory, at)),
        [0; 2].map(|_| (below, page + PAGE, text("rd mr mw me gd gu ac")))
    );
}

/// The guard flag stays on each part of a line that every kind of layout
/// call splits: `mmap(MAP_FIXED)`, `munmap`, `mremap`, `mprotect`,
/// `pkey_mprotect`, `brk` and madvise advice that changes a flag. Each case
/// leaves a line half of whose pages had the flag before it (a plain
/// mapping merged with a guarded one), then splits it inside the plain
/// half; the plain part left must keep `gu`.
#[test]
fn every_layout_call_keeps_the_guard_flag_on_the_parts_it_splits() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let guarded_line = |executor: &mut ElfExecutor, memory: &GuestMemory| {
        let base = mmap(executor, memory, 0, 8, 0, PRIVATE);
        ok(call(
            executor,
            memory,
            libc::SYS_munmap,
            [base, 8 * PAGE, 0, 0, 0, 0],
        ));
        let top = mmap(executor, memory, base + 4 * PAGE, 4, RW, PRIVATE | FIXED);
        ok(call(
            executor,
            memory,
            libc::SYS_madvise,
            [top, PAGE, mm::MADV_GUARD_INSTALL as u64, 0, 0, 0],
        ));
        mmap(executor, memory, base, 4, RW, PRIVATE | FIXED);
        assert_eq!(
            flags_at(executor, memory, base),
            (base, base + 8 * PAGE, text("rd wr mr mw me gu ac"))
        );
        base
    };
    type Split = fn(&mut ElfExecutor, &GuestMemory, u64) -> i64;
    let cases: [(&str, Split); 7] = [
        ("mmap MAP_FIXED", |executor, memory, base| {
            let mapped = call(
                executor,
                memory,
                libc::SYS_mmap,
                [base + PAGE, PAGE, R, PRIVATE | FIXED, u64::MAX, 0],
            );
            if mapped == (base + PAGE) as i64 {
                0
            } else {
                mapped
            }
        }),
        ("munmap", |executor, memory, base| {
            call(
                executor,
                memory,
                libc::SYS_munmap,
                [base + PAGE, PAGE, 0, 0, 0, 0],
            )
        }),
        ("mremap", |executor, memory, base| {
            // Moves the second page away, which splits the line there.
            let moved = call(
                executor,
                memory,
                libc::SYS_mremap,
                [
                    base + PAGE,
                    PAGE,
                    PAGE,
                    (libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED) as u64,
                    base - 64 * PAGE,
                    0,
                ],
            );
            if moved == (base - 64 * PAGE) as i64 {
                0
            } else {
                moved
            }
        }),
        ("mprotect", |executor, memory, base| {
            call(
                executor,
                memory,
                libc::SYS_mprotect,
                [base + PAGE, PAGE, R, 0, 0, 0],
            )
        }),
        ("pkey_mprotect", |executor, memory, base| {
            call(
                executor,
                memory,
                libc::SYS_pkey_mprotect,
                [base + PAGE, PAGE, R, u64::MAX, 0, 0],
            )
        }),
        ("madvise", |executor, memory, base| {
            call(
                executor,
                memory,
                libc::SYS_madvise,
                [base + PAGE, PAGE, libc::MADV_RANDOM as u64, 0, 0, 0],
            )
        }),
        ("brk", |executor, memory, _| {
            // The guarded heap grown by two plain pages, which merge with it,
            // then shrunk by one: the line left keeps the flag.
            let heap = executor.state.mm.heap_base;
            let grown = call(
                executor,
                memory,
                libc::SYS_brk,
                [heap + 4 * PAGE, 0, 0, 0, 0, 0],
            );
            assert_eq!(grown, (heap + 4 * PAGE) as i64);
            let shrunk = call(
                executor,
                memory,
                libc::SYS_brk,
                [heap + 3 * PAGE, 0, 0, 0, 0, 0],
            );
            if shrunk == (heap + 3 * PAGE) as i64 {
                0
            } else {
                shrunk
            }
        }),
    ];
    for (what, split) in cases {
        let (mut executor, memory) = loaded(&directory);
        if what == "brk" {
            // The heap grows upward, so its guarded part is its bottom: two
            // pages, guarded, before the case grows and shrinks it.
            let heap = executor.state.mm.heap_base;
            assert_eq!(
                call(
                    &mut executor,
                    &memory,
                    libc::SYS_brk,
                    [heap + 2 * PAGE, 0, 0, 0, 0, 0]
                ),
                (heap + 2 * PAGE) as i64
            );
            ok(call(
                &mut executor,
                &memory,
                libc::SYS_madvise,
                [heap, PAGE, mm::MADV_GUARD_INSTALL as u64, 0, 0, 0],
            ));
            ok(split(&mut executor, &memory, 0));
            assert_eq!(
                flags_at(&executor, &memory, heap + 2 * PAGE),
                (heap, heap + 3 * PAGE, text("rd wr mr mw me gu ac")),
                "{what}"
            );
            continue;
        }
        let base = guarded_line(&mut executor, &memory);
        ok(split(&mut executor, &memory, base));
        // The first page, split from the rest, keeps the flag.
        let (start, end, flags) = flags_at(&executor, &memory, base);
        assert_eq!((start, end), (base, base + PAGE), "{what}");
        assert_eq!(
            flags.as_deref().map(|flags| flags.contains(" gu ")),
            Some(true),
            "{what}: {flags:?}"
        );
    }
}

/// Residual 1: a fork clears `lo` in the child's copy alone (probe3: the
/// child prints `rd wr mr mw me ac`, the parent `rd wr mr mw me lo ac`) and
/// keeps `gu` (probe3); a child that shares the address space (a vfork
/// child's copy) clears nothing, in its copy or its parent's.
#[test]
fn a_fork_clears_locked_in_the_childs_copy_alone_and_a_vfork_child_clears_nothing() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let locked = mmap(
        &mut executor,
        &memory,
        0,
        1,
        RW,
        PRIVATE | libc::MAP_LOCKED as u64,
    );
    let guarded = mmap(&mut executor, &memory, 0, 2, RW, PRIVATE);
    assert_eq!(guarded + 2 * PAGE, locked, "placed right below it");
    ok(call(
        &mut executor,
        &memory,
        libc::SYS_madvise,
        [guarded, PAGE, mm::MADV_GUARD_INSTALL as u64, 0, 0, 0],
    ));
    let flags = |memory: &GuestMemory, address: u64| {
        memory
            .declared_mapping(memory.user_range_to_guest(address, PAGE).unwrap())
            .unwrap()
            .flags
    };
    assert_ne!(flags(&memory, locked) & FLAG_LOCKED, 0);

    let child = memory.snapshot().unwrap();
    ElfExecutor::inherit_mappings_in_forked_child(&child);
    assert_eq!(flags(&child, locked) & FLAG_LOCKED, 0, "the child's copy");
    assert_ne!(flags(&memory, locked) & FLAG_LOCKED, 0, "the parent's");
    assert_ne!(flags(&child, guarded + PAGE) & FLAG_MAYBE_GUARD, 0);
    assert_eq!(child.flagged_pages(FLAG_LOCKED), 0);
    assert_eq!(memory.flagged_pages(FLAG_LOCKED), 1);
    let child_executor = executor
        .fork_child(executor.state.pid + 40, false, false)
        .unwrap();
    // The child's unlocked page stays a mapping of its own, as `dup_mmap`
    // copies it, though its neighbour now has the same flags but the
    // sticky guard flag.
    assert_eq!(
        flags_at(&child_executor, &child, locked),
        (locked, locked + PAGE, text("rd wr mr mw me ac"))
    );
    assert_eq!(
        flags_at(&child_executor, &child, guarded),
        (guarded, guarded + 2 * PAGE, text("rd wr mr mw me gu ac"))
    );
    assert_eq!(
        flags_at(&executor, &memory, locked),
        (locked, locked + PAGE, text("rd wr mr mw me lo ac"))
    );

    // vfork: the child's copy shares its parent's address space on Linux.
    let shared = memory.snapshot_sharing_address_space().unwrap();
    assert!(shared.shares_parent_address_space());
    ElfExecutor::inherit_mappings_in_forked_child(&shared);
    assert_ne!(flags(&shared, locked) & FLAG_LOCKED, 0, "the vfork copy");
    assert_ne!(flags(&memory, locked) & FLAG_LOCKED, 0, "its parent's");
    assert_eq!(shared.flagged_pages(FLAG_LOCKED), 1);
}

// ---------------------------------------------------------------------------
// Residual 2: the guard flag's spread covers every syscall dispatch routes
// to code that edits the layout, derived from the source.

/// One function of a source file, with comments and literals blanked.
struct Function {
    name: String,
    body: String,
    /// Whether it is defined in an `impl` or `trait` block, so that it is
    /// called as `receiver.name(...)` or `Type::name(...)`.
    method: bool,
}

/// `source` with comments, string and character literals blanked to
/// spaces (keeping line structure), so that braces and names inside them
/// are not read as code.
fn blank_comments_and_literals(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for byte in &mut out[from..to] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    };
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                let end = source[i..].find('\n').map_or(bytes.len(), |at| i + at);
                blank(&mut out, i, end);
                i = end;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let mut depth = 0;
                let mut j = i;
                while j < bytes.len() {
                    if bytes[j..].starts_with(b"/*") {
                        depth += 1;
                        j += 2;
                    } else if bytes[j..].starts_with(b"*/") {
                        depth -= 1;
                        j += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        j += 1;
                    }
                }
                blank(&mut out, i, j);
                i = j;
            }
            b'r' if (bytes.get(i + 1) == Some(&b'"') || bytes.get(i + 1) == Some(&b'#'))
                && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_')) =>
            {
                let hashes = bytes[i + 1..].iter().take_while(|b| **b == b'#').count();
                if bytes.get(i + 1 + hashes) != Some(&b'"') {
                    i += 1;
                    continue;
                }
                let close = format!("\"{}", "#".repeat(hashes));
                let start = i + 2 + hashes;
                let end = source[start..]
                    .find(&close)
                    .map_or(bytes.len(), |at| start + at + close.len());
                blank(&mut out, i, end);
                i = end;
            }
            b'"' => {
                let mut j = i + 1;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += if bytes[j] == b'\\' { 2 } else { 1 };
                }
                blank(&mut out, i, (j + 1).min(bytes.len()));
                i = j + 1;
            }
            b'\'' => {
                // A character literal ('x', '\n', '\u{..}'), not a lifetime.
                let end = if bytes.get(i + 1) == Some(&b'\\') {
                    source[i + 2..].find('\'').map(|at| i + 2 + at + 1)
                } else if bytes.get(i + 2) == Some(&b'\'') {
                    Some(i + 3)
                } else {
                    None
                };
                match end {
                    Some(end) => {
                        blank(&mut out, i, end);
                        i = end;
                    }
                    None => i += 1,
                }
            }
            _ => i += 1,
        }
    }
    String::from_utf8(out).unwrap()
}

/// The end (exclusive) of the braced block that opens at `open`.
fn block_end(text: &str, open: usize) -> usize {
    let mut depth = 0;
    for (at, byte) in text.bytes().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return at + 1;
                }
            }
            _ => {}
        }
    }
    text.len()
}

/// `text` without its `#[cfg(test)]` items.
fn without_test_items(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..at]);
        let item = &rest[at..];
        let brace = item.find('{');
        let semicolon = item.find(';');
        let end = match (brace, semicolon) {
            (Some(brace), Some(semicolon)) if semicolon < brace => semicolon + 1,
            (Some(brace), _) => block_end(item, brace),
            (None, Some(semicolon)) => semicolon + 1,
            (None, None) => item.len(),
        };
        rest = &item[end..];
    }
    out.push_str(rest);
    out
}

/// Where the braced body of the item that starts `text` opens: the first
/// `{` outside its brackets; `None` when a `;` there ends it first.
fn body_open(text: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (offset, byte) in text.bytes().enumerate() {
        match byte {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b'{' if depth == 0 => return Some(offset),
            b';' if depth == 0 => return None,
            _ => {}
        }
    }
    None
}

/// The starts of each whole word `word` in `text`.
fn word_starts<'a>(text: &'a str, word: &'a str) -> impl Iterator<Item = usize> + 'a {
    text.match_indices(word)
        .map(|(at, _)| at)
        .filter(move |&at| {
            let bytes = text.as_bytes();
            let ident = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
            (at == 0 || !ident(bytes[at - 1]))
                && bytes.get(at + word.len()).is_none_or(|byte| !ident(*byte))
        })
}

/// Every function with a body in the non-test code of the `.rs` files under
/// `directory`, but `*_tests.rs` files.
fn functions(directory: &Path) -> Vec<Function> {
    let mut files = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(&path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs")
                && !path.to_string_lossy().ends_with("_tests.rs")
            {
                files.push(path);
            }
        }
    }
    let mut functions = Vec::new();
    for file in files {
        let source = std::fs::read_to_string(&file).unwrap();
        let text = without_test_items(&blank_comments_and_literals(&source));
        let blocks: Vec<(usize, usize)> = ["impl", "trait"]
            .iter()
            .flat_map(|word| word_starts(&text, word))
            .filter_map(|at| {
                let open = at + body_open(&text[at..])?;
                Some((open, block_end(&text, open)))
            })
            .collect();
        for at in word_starts(&text, "fn") {
            let name: String = text[at + 2..]
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let Some(open) = body_open(&text[at..]) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let open = at + open;
            functions.push(Function {
                name,
                body: text[open..block_end(&text, open)].to_owned(),
                method: blocks.iter().any(|&(start, end)| start < at && at < end),
            });
        }
    }
    functions
}

/// Whether `body` calls the function `name`: as a method
/// (`receiver.name(` or `Type::name(`) when `method`, otherwise as a free
/// function (`name(` alone or after a module path, `module::name(`), never
/// `libc::name(`.
fn calls(body: &str, name: &str, method: bool) -> bool {
    let call = format!("{name}(");
    word_starts(body, name)
        .filter(|&at| body[at..].starts_with(&call))
        .any(|at| {
            let before = &body[..at];
            if before.ends_with("libc::") {
                return false;
            }
            let as_method = before.ends_with('.')
                || before.ends_with("::")
                    && before[..before.len() - 2]
                        .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                        .next()
                        .is_some_and(|segment| {
                            segment.starts_with(|c: char| c.is_ascii_uppercase())
                        });
            let as_free = !before.ends_with('.') && !as_method;
            if method { as_method } else { as_free }
        })
}

/// The functions of `functions` that `seeds` holds (each with whether it is
/// a method) or that call one of them, transitively, as [`calls`] reads a
/// call. A method whose name `ambiguous` holds (more than one method of the
/// two crates has it) cannot be told from the others by its name, and
/// is not followed.
fn callers_closure(
    functions: &[Function],
    seeds: BTreeMap<String, bool>,
    ambiguous: &BTreeSet<String>,
) -> BTreeMap<String, bool> {
    let mut found = seeds;
    loop {
        let more: Vec<(String, bool)> = functions
            .iter()
            .filter(|function| !found.contains_key(&function.name))
            .filter(|function| {
                found.iter().any(|(name, method)| {
                    !(*method && ambiguous.contains(name)) && calls(&function.body, name, *method)
                })
            })
            .map(|function| (function.name.clone(), function.method))
            .collect();
        if more.is_empty() {
            return found;
        }
        found.extend(more);
    }
}

/// The syscall names (`SYS_*`) in `text`.
fn syscall_names(text: &str) -> BTreeSet<String> {
    text.match_indices("libc::SYS_")
        .map(|(at, _)| {
            text[at + 6..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect()
        })
        .collect()
}

/// Residual 2: the guard flag's spread (`mapping_list::spread_guard_marks`)
/// runs before every syscall that dispatch routes to code that edits the
/// address space's pages, and every such syscall names where it may split
/// (`layout_edit_boundaries`). Nothing here is a list kept by hand:
/// - the memory's page-editing functions are those of `reverie-kvm-core`
///   whose body writes a page's state (`pages.insert`, `pages.remove` or
///   `pages.clear` on the address space's state) or calls such a function,
///   transitively;
/// - the executor's page-editing functions are those that call one,
///   transitively;
/// - the syscalls are the guards of each arm of `execute_basic_syscall_inner`
///   whose body calls one.
///
/// Those syscalls must be exactly [`LAYOUT_SYSCALLS`], for which dispatch
/// calls the spread, once, before any path that edits. Calls are read by
/// name, so a method whose name another method of the two crates shares is
/// not followed; the one such page-editing method is
/// `GuestMemory::snapshot`, which copies the address space into a new one
/// and edits none of the caller's pages. A new one fails here, to be looked
/// at, as does a dispatch arm in another form than `_ if <guard> =>` or a
/// page edit in the dispatch before its match.
///
/// What this reading cannot see, and so does not check: a call made through
/// a function pointer, a closure kept in a variable, a trait object or a
/// macro; a function renamed on import (`use ... as ...`); and a method
/// called by the fully qualified form `<Type as Trait>::name(`. No such
/// call reaches a page edit from dispatch today; one added later is caught
/// only by the tests of the call it makes.
#[test]
fn the_guard_spread_runs_for_every_syscall_whose_dispatch_edits_the_layout() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core = functions(&root.join("../reverie-kvm-core/src"));
    let emu = functions(&root.join("src"));
    let mut method_names: BTreeMap<&str, usize> = BTreeMap::new();
    for function in core.iter().chain(&emu).filter(|function| function.method) {
        *method_names.entry(&function.name).or_default() += 1;
    }
    let ambiguous: BTreeSet<String> = method_names
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(name, _)| name.to_string())
        .collect();
    let writes: Vec<String> = ["access", "state", "prepared"]
        .iter()
        .flat_map(|receiver| {
            ["insert(", "remove(", "clear("]
                .iter()
                .map(move |call| format!("{receiver}.pages.{call}"))
        })
        .collect();
    let seeds: BTreeMap<String, bool> = core
        .iter()
        .filter(|function| writes.iter().any(|write| function.body.contains(write)))
        .map(|function| (function.name.clone(), function.method))
        .collect();
    assert!(seeds.contains_key("set_user_pages"), "{seeds:?}");
    let editing_methods = callers_closure(&core, seeds, &ambiguous);
    for method in [
        "map_user_protection",
        "protect_user_range",
        "unmap_user_range",
        "remap_user_range",
        "describe_mapping",
        "set_user_guards",
        "protect",
        "unmap",
        "guard_install",
    ] {
        assert!(
            editing_methods.contains_key(method),
            "{method}: {editing_methods:?}"
        );
    }
    let unfollowed: Vec<&String> = editing_methods
        .iter()
        .filter(|(name, method)| **method && ambiguous.contains(*name))
        .map(|(name, _)| name)
        .collect();
    assert_eq!(
        unfollowed,
        ["snapshot"],
        "page-editing methods not told apart by name"
    );
    let editing = callers_closure(&emu, editing_methods, &ambiguous);

    let dispatch = without_test_items(&blank_comments_and_literals(include_str!("dispatch.rs")));
    let inner_at = dispatch.find("fn execute_basic_syscall_inner(").unwrap();
    let inner_open = inner_at + dispatch[inner_at..].find('{').unwrap();
    let inner = &dispatch[inner_open..block_end(&dispatch, inner_open)];
    // The arms are read in the one form dispatch writes them in,
    // `_ if <guard> => <body>`, at the match's indentation; another form, or
    // a page edit before the match, which no arm would show, fails here, to
    // be looked at.
    let match_at = inner
        .find("let result = match number {")
        .expect("the inner dispatch's match");
    let prelude_edits: Vec<&String> = editing
        .iter()
        .filter(|(name, method)| {
            !(**method && ambiguous.contains(*name)) && calls(&inner[..match_at], name, **method)
        })
        .map(|(name, _)| name)
        .collect();
    assert!(prelude_edits.is_empty(), "{prelude_edits:?}");
    for arm_line in inner[match_at..].lines().filter(|line| {
        line.starts_with("        ") && !line.starts_with("         ") && line.contains("=>")
    }) {
        let arm = arm_line.trim_start();
        assert!(
            arm.starts_with("_ if ") || arm.starts_with("_ =>"),
            "{arm_line}"
        );
    }
    // Each dispatched syscall, and the page-editing functions its arm calls.
    let mut by_syscall: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for arm in inner.split("\n        _ if ").skip(1) {
        let Some(arrow) = arm.find("=>") else {
            continue;
        };
        let (guard, body) = arm.split_at(arrow);
        let called: BTreeSet<String> = editing
            .iter()
            .filter(|(name, method)| {
                !(**method && ambiguous.contains(*name)) && calls(body, name, **method)
            })
            .map(|(name, _)| name.clone())
            .collect();
        for name in syscall_names(guard) {
            by_syscall.entry(name).or_default().extend(called.clone());
        }
    }
    assert!(by_syscall.len() > 100, "{by_syscall:?}");
    let edits_layout: BTreeSet<String> = by_syscall
        .iter()
        .filter(|(_, called)| !called.is_empty())
        .map(|(name, _)| name.clone())
        .collect();

    let layout_at = dispatch.find("const LAYOUT_SYSCALLS").unwrap();
    let layout_end = layout_at + dispatch[layout_at..].find("];").unwrap();
    let layout = syscall_names(&dispatch[layout_at..layout_end]);
    assert_eq!(
        edits_layout,
        layout,
        "the syscalls whose dispatch edits the layout are the ones the spread runs for; \
         the page-editing calls of each arm: {:?}",
        by_syscall
            .iter()
            .filter(|(_, called)| !called.is_empty())
            .collect::<Vec<_>>()
    );

    // Each names where it may split.
    let directory = Directory::new();
    let (executor, _) = loaded(&directory);
    for number in LAYOUT_SYSCALLS {
        assert!(mutates_layout(number as u64));
        assert!(
            layout_edit_boundaries(number as u64, &[0; 6], &executor.state).is_some(),
            "{number}"
        );
    }
    assert!(layout_edit_boundaries(libc::SYS_read as u64, &[0; 6], &executor.state).is_none());

    // The spread's one caller is dispatch, which runs it once the call is
    // known to edit the layout and before every path that does: the last
    // call of the inner dispatch (the first serves the calls that do not
    // edit the layout, which return before the spread), and the shared-file
    // paths.
    let callers: Vec<&str> = emu
        .iter()
        .filter(|function| calls(&function.body, "spread_guard_marks", false))
        .map(|function| function.name.as_str())
        .collect();
    assert_eq!(callers, ["execute_basic_syscall_dispatch"]);
    let outer_at = dispatch.find("fn execute_basic_syscall_dispatch(").unwrap();
    let outer_open = outer_at + dispatch[outer_at..].find('{').unwrap();
    let outer = &dispatch[outer_open..block_end(&dispatch, outer_open)];
    let position = |needle: &str| {
        outer
            .rfind(needle)
            .unwrap_or_else(|| panic!("{needle} in execute_basic_syscall_dispatch"))
    };
    let spread = position("spread_guard_marks(");
    assert_eq!(outer.matches("spread_guard_marks(").count(), 1);
    assert!(outer.find("mutates_layout(").unwrap() < spread);
    for path in [
        "mmap_with_shared_files(",
        "munmap_shared_file(",
        "execute_basic_syscall_inner(",
    ] {
        assert!(spread < position(path), "{path}");
    }
}

// ---------------------------------------------------------------------------
// The adversarial review of reverie#1342 at 39622d18: its four witnesses,
// kept as they failed there, and the cases each fix adds. Every expected
// `VmFlags` is native Linux 7.1.3's, from the reviewer's probes
// (`rv1342-flags-probe.c`, `rv1342-flags-mergeable-probe.c`,
// `rv1342-flags-unlock-probe.c`) or from `fix1_probe.c` (dh-9j8ue scratch,
// `impl/fix1/probe/`), quoted at each case by its line name.

/// Maps `pages` pages of descriptor `fd` (of the executor's state) at
/// `at`, fixed, with `prot` and `flags`, from file offset `offset`.
#[allow(clippy::too_many_arguments)]
fn map_fd(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    at: u64,
    pages: u64,
    prot: u64,
    flags: u64,
    fd: i64,
    offset: u64,
) {
    let mut owner = memory.clone();
    let result = execute_basic_syscall(
        &mut owner,
        &mut executor.state,
        &SyscallRequest::new(
            libc::SYS_mmap as u64,
            [
                at,
                pages * PAGE,
                prot,
                flags | libc::MAP_FIXED as u64,
                fd as u64,
                offset,
            ],
        ),
    );
    match result {
        SyscallAction::Continue { result, .. } => assert_eq!(result, at as i64),
        _ => panic!("mmap did not return Continue"),
    }
}

/// A new memfd of `pages` pages that may be sealed.
fn sealable_memfd(pages: u64) -> std::fs::File {
    use std::os::fd::FromRawFd;
    // SAFETY: a new memfd this test owns.
    let raw = unsafe { libc::memfd_create(c"vm-flags-review".as_ptr(), libc::MFD_ALLOW_SEALING) };
    assert!(raw >= 0);
    // SAFETY: memfd_create returned a new descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(raw) };
    file.set_len(pages * PAGE).unwrap();
    file
}

/// Adds `F_SEAL_FUTURE_WRITE` to `file`, as another owner of it may.
fn seal_future_writes(file: &std::fs::File) {
    use std::os::fd::AsRawFd;
    // SAFETY: fcntl on a descriptor this test owns.
    let sealed = unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            libc::F_ADD_SEALS,
            libc::F_SEAL_FUTURE_WRITE,
        )
    };
    assert_eq!(sealed, 0);
}

/// `pages` free pages, unmapped, with a free page on each side.
fn room(executor: &mut ElfExecutor, memory: &GuestMemory, pages: u64) -> u64 {
    let base = mmap(executor, memory, 0, pages + 2, 0, PRIVATE);
    ok(call(
        executor,
        memory,
        libc::SYS_munmap,
        [base, (pages + 2) * PAGE, 0, 0, 0, 0],
    ));
    base + PAGE
}

/// Finding 3 witness (`rv1342-flags-probe.log`: child-A/B, grandchild-A/B).
#[test]
fn review_nested_fork_keeps_newly_unlocked_neighbor_apart() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let base = mmap(&mut executor, &memory, 0, 2, 0, PRIVATE);
    mmap(
        &mut executor,
        &memory,
        base,
        1,
        RW,
        PRIVATE | FIXED | libc::MAP_LOCKED as u64,
    );
    let child_memory = memory.snapshot().unwrap();
    ElfExecutor::inherit_mappings_in_forked_child(&child_memory);
    let mut child = executor
        .fork_child(executor.state.pid + 40, false, false)
        .unwrap();
    ok(call(
        &mut child,
        &child_memory,
        libc::SYS_madvise,
        [base, PAGE, mm::MADV_GUARD_INSTALL as u64, 0, 0, 0],
    ));
    mmap(
        &mut child,
        &child_memory,
        base + PAGE,
        1,
        RW,
        PRIVATE | FIXED | libc::MAP_LOCKED as u64,
    );
    assert_eq!(
        flags_at(&child, &child_memory, base),
        (base, base + PAGE, text("rd wr mr mw me gu ac"))
    );
    assert_eq!(
        flags_at(&child, &child_memory, base + PAGE),
        (base + PAGE, base + 2 * PAGE, text("rd wr mr mw me lo ac"))
    );
    let grand_memory = child_memory.snapshot().unwrap();
    ElfExecutor::inherit_mappings_in_forked_child(&grand_memory);
    let grand = child
        .fork_child(child.state.pid + 40, false, false)
        .unwrap();
    // Native Linux 7.1.3: dup_mmap preserves both one-page VMAs;
    // only B's lo disappears, and B does not acquire A's gu.
    assert_eq!(
        flags_at(&grand, &grand_memory, base),
        (base, base + PAGE, text("rd wr mr mw me gu ac"))
    );
    assert_eq!(
        flags_at(&grand, &grand_memory, base + PAGE),
        (base + PAGE, base + 2 * PAGE, text("rd wr mr mw me ac"))
    );
}

/// Round 2, finding 3 witness (`rv1342-delta-api-lineage-probe.log`:
/// child-moved-A, child-moved-C): two locked mappings inherited by a fork
/// child stay two after a move makes them neighbours, and only A has `gu`.
#[test]
fn reviewer_remapped_inherited_locked_mappings_keep_distinct_lineages() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let base = room(&mut executor, &memory, 4);
    for at in [base, base + 3 * PAGE] {
        mmap(
            &mut executor,
            &memory,
            at,
            1,
            RW,
            PRIVATE | FIXED | libc::MAP_LOCKED as u64,
        );
        let physical = memory.user_range_to_guest(at, 1).unwrap();
        memory.write_raw(physical, &[1]).unwrap();
    }
    let child_memory = memory.snapshot().unwrap();
    ElfExecutor::inherit_mappings_in_forked_child(&child_memory);
    let mut child = executor
        .fork_child(executor.state.pid + 40, false, false)
        .unwrap();
    ok(call(
        &mut child,
        &child_memory,
        libc::SYS_madvise,
        [base, PAGE, mm::MADV_GUARD_INSTALL as u64, 0, 0, 0],
    ));
    assert_eq!(
        call(
            &mut child,
            &child_memory,
            libc::SYS_mremap,
            [
                base + 3 * PAGE,
                PAGE,
                PAGE,
                (libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED) as u64,
                base + PAGE,
                0
            ]
        ),
        (base + PAGE) as i64
    );
    let observed = [
        flags_at(&child, &child_memory, base),
        flags_at(&child, &child_memory, base + PAGE),
    ];
    assert_eq!(
        observed,
        [
            (base, base + PAGE, text("rd wr mr mw me gu ac")),
            (base + PAGE, base + 2 * PAGE, text("rd wr mr mw me ac"))
        ]
    );
}

/// Round 2, finding 3: each mapping a fork child inherits locked gets a
/// lineage no other page has, and its own parts, split and joined again,
/// are one mapping again (`fix2_probe.log`: child-inherited,
/// child-split-first/second, child-rejoined).
#[test]
fn an_inherited_locked_mapping_has_a_lineage_of_its_own_and_rejoins_its_parts() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let locked = PRIVATE | FIXED | libc::MAP_LOCKED as u64;
    let base = room(&mut executor, &memory, 5);
    mmap(&mut executor, &memory, base, 2, RW, locked);
    mmap(&mut executor, &memory, base + 3 * PAGE, 2, RW, locked);
    let child_memory = memory.snapshot().unwrap();
    ElfExecutor::inherit_mappings_in_forked_child(&child_memory);
    let lineage = |at: u64| {
        child_memory
            .declared_mapping(child_memory.user_range_to_guest(at, PAGE).unwrap())
            .unwrap()
            .lineage
    };
    assert_eq!(
        lineage(base),
        lineage(base + PAGE),
        "one mapping, one lineage"
    );
    assert_ne!(lineage(base), lineage(base + 3 * PAGE), "two mappings, two");
    let others: BTreeSet<u16> = child_memory
        .user_mapping_runs()
        .runs
        .iter()
        .filter(|run| run.end <= base || base + 5 * PAGE <= run.start)
        .filter_map(|run| run.declared)
        .map(|declared| declared.lineage)
        .collect();
    for at in [base, base + 3 * PAGE] {
        assert!(
            lineage(at) != 0 && !others.contains(&lineage(at)),
            "{others:?}"
        );
    }
    let mut child = executor
        .fork_child(executor.state.pid + 40, false, false)
        .unwrap();
    assert_eq!(
        flags_at(&child, &child_memory, base),
        (base, base + 2 * PAGE, text("rd wr mr mw me ac")),
        "child-inherited"
    );
    ok(call(
        &mut child,
        &child_memory,
        libc::SYS_mprotect,
        [base + PAGE, PAGE, R, 0, 0, 0],
    ));
    assert_eq!(
        [base, base + PAGE].map(|at| flags_at(&child, &child_memory, at)),
        [
            (base, base + PAGE, text("rd wr mr mw me ac")),
            // `rd mr mw me ac` natively once written; whether it was is
            // not known here (`FLAG_ACCOUNT_UNKNOWN`).
            (base + PAGE, base + 2 * PAGE, None),
        ],
        "child-split-first, child-split-second"
    );
    ok(call(
        &mut child,
        &child_memory,
        libc::SYS_mprotect,
        [base + PAGE, PAGE, RW, 0, 0, 0],
    ));
    assert_eq!(
        flags_at(&child, &child_memory, base),
        (base, base + 2 * PAGE, text("rd wr mr mw me ac")),
        "child-rejoined"
    );
}

/// Round 2, finding 3: when a line of descent of forks has used lineages
/// up to `u16::MAX`, the lineages are renumbered in order before new ones
/// are given, keeping every two pages' lineages equal or different as they
/// were, and the new ones are again those of no other page.
#[test]
fn fresh_lineages_renumber_before_they_run_out() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let base = room(&mut executor, &memory, 7);
    let lineage_of = |memory: &GuestMemory, at: u64| {
        memory
            .declared_mapping(memory.user_range_to_guest(at, PAGE).unwrap())
            .unwrap()
            .lineage
    };
    // Three mappings with lineages left by earlier forks, the last two
    // alike, and a locked one.
    for (at, lineage) in [
        (base, u16::MAX),
        (base + 2 * PAGE, 65000),
        (base + 4 * PAGE, 65000),
    ] {
        mmap(&mut executor, &memory, at, 1, RW, PRIVATE | FIXED);
        memory.edit_user_declared(at, PAGE, |declared, _| crate::memory::DeclaredMapping {
            lineage,
            ..declared
        });
    }
    let locked = base + 6 * PAGE;
    mmap(
        &mut executor,
        &memory,
        locked,
        1,
        RW,
        PRIVATE | FIXED | libc::MAP_LOCKED as u64,
    );
    let child = memory.snapshot().unwrap();
    ElfExecutor::inherit_mappings_in_forked_child(&child);
    let [high, low, alike, unlocked] =
        [base, base + 2 * PAGE, base + 4 * PAGE, locked].map(|at| lineage_of(&child, at));
    assert!(low < high, "renumbered in order: {low} {high}");
    assert_eq!(low, alike, "equal lineages stay equal");
    assert!(high < 1000, "renumbered down: {high}");
    let all: Vec<u16> = child
        .user_mapping_runs()
        .runs
        .iter()
        .filter(|run| !(locked..locked + PAGE).contains(&run.start))
        .filter_map(|run| run.declared)
        .map(|declared| declared.lineage)
        .collect();
    assert!(
        unlocked != 0 && !all.contains(&unlocked),
        "{unlocked} {all:?}"
    );
    assert_eq!(lineage_of(&memory, base), u16::MAX, "the parent's stay");
}

/// Finding 4 witness (`rv1342-flags-mergeable-probe.log`: shared).
#[test]
fn review_shared_anonymous_mergeable_advice_does_not_report_mg() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let base = mmap(
        &mut executor,
        &memory,
        0,
        1,
        RW,
        (libc::MAP_SHARED | libc::MAP_ANONYMOUS) as u64,
    );
    ok(call(
        &mut executor,
        &memory,
        libc::SYS_madvise,
        [base, PAGE, libc::MADV_MERGEABLE as u64, 0, 0, 0],
    ));
    assert_eq!(
        flags_at(&executor, &memory, base).2,
        text("rd wr sh mr mw me ms")
    );
}

/// Finding 4: `MADV_MERGEABLE` sets `mg` on private mappings, anonymous and
/// of a file, and on no shared mapping of a file, writable or not
/// (`fix1_probe.log`: mg-private-anon, mg-shared-file-rdwr,
/// mg-shared-file-rdonly, mg-private-file).
#[test]
fn mergeable_advice_marks_private_mappings_and_no_shared_one() {
    use std::os::fd::AsRawFd;
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let file = sealable_memfd(1);
    let shared = libc::MAP_SHARED as u64;
    let private = libc::MAP_PRIVATE as u64;
    let cases = [
        (
            "mg-shared-file-rdwr",
            RW,
            shared,
            true,
            "rd wr sh mr mw me ms",
        ),
        ("mg-shared-file-rdonly", R, shared, false, "rd mr me ms"),
        ("mg-private-file", R, private, false, "rd mr mw me mg"),
    ];
    for (name, prot, flags, writable, linux) in cases {
        let at = room(&mut executor, &memory, 1);
        // The executor's own calls replace its state's descriptors with its
        // table's, so the descriptor goes in just before the mmap.
        let description = if writable {
            file.try_clone().unwrap()
        } else {
            std::fs::File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap()
        };
        let fd = insert_file_with_flags(&mut executor.state, description, false, None);
        assert!(fd >= 0);
        map_fd(&mut executor, &memory, at, 1, prot, flags, fd, 0);
        ok(call(
            &mut executor,
            &memory,
            libc::SYS_madvise,
            [at, PAGE, libc::MADV_MERGEABLE as u64, 0, 0, 0],
        ));
        assert_eq!(
            flags_at(&executor, &memory, at),
            (at, at + PAGE, text(linux)),
            "{name}"
        );
    }
    let at = mmap(&mut executor, &memory, 0, 1, RW, PRIVATE);
    ok(call(
        &mut executor,
        &memory,
        libc::SYS_madvise,
        [at, PAGE, libc::MADV_MERGEABLE as u64, 0, 0, 0],
    ));
    assert_eq!(
        flags_at(&executor, &memory, at).2,
        text("rd wr mr mw me ac mg"),
        "mg-private-anon"
    );
}

/// Finding 5 witness (`rv1342-flags-unlock-probe.log`).
#[test]
fn review_unlock_calls_clear_published_lo() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    for unlock in [libc::SYS_munlock, libc::SYS_munlockall] {
        let (mut executor, memory) = loaded(&directory);
        let base = mmap(
            &mut executor,
            &memory,
            0,
            2,
            RW,
            PRIVATE | libc::MAP_LOCKED as u64,
        );
        ok(call(
            &mut executor,
            &memory,
            unlock,
            [base, 2 * PAGE, 0, 0, 0, 0],
        ));
        assert_eq!(
            flags_at(&executor, &memory, base).2,
            text("rd wr mr mw me ac"),
            "unlock syscall {unlock}"
        );
    }
}

/// Finding 5: munlock unlocks exactly the pages of its range up to the
/// first hole, splitting and merging lines as Linux does, and munlockall
/// unlocks every mapping (`fix1_probe.log`: unlock-full,
/// unlock-partial-first/second/merged, unlock-hole-before/after,
/// unlockall-rw/r).
#[test]
fn unlocking_takes_locked_from_exactly_the_mappings_unlocked() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let locked = PRIVATE | FIXED | libc::MAP_LOCKED as u64;
    let unlock = |executor: &mut ElfExecutor, at: u64, length: u64| {
        call(
            executor,
            &memory,
            libc::SYS_munlock,
            [at, length, 0, 0, 0, 0],
        )
    };

    let full = room(&mut executor, &memory, 2);
    mmap(&mut executor, &memory, full, 2, RW, locked);
    ok(unlock(&mut executor, full, 2 * PAGE));
    assert_eq!(
        flags_at(&executor, &memory, full),
        (full, full + 2 * PAGE, text("rd wr mr mw me ac")),
        "unlock-full"
    );

    let partial = room(&mut executor, &memory, 2);
    mmap(&mut executor, &memory, partial, 2, RW, locked);
    ok(unlock(&mut executor, partial, PAGE));
    assert_eq!(
        [partial, partial + PAGE].map(|at| flags_at(&executor, &memory, at)),
        [
            (partial, partial + PAGE, text("rd wr mr mw me ac")),
            (
                partial + PAGE,
                partial + 2 * PAGE,
                text("rd wr mr mw me lo ac")
            ),
        ],
        "unlock-partial-first, unlock-partial-second"
    );
    // A length of one byte covers its whole page.
    ok(unlock(&mut executor, partial + PAGE, 1));
    assert_eq!(
        flags_at(&executor, &memory, partial),
        (partial, partial + 2 * PAGE, text("rd wr mr mw me ac")),
        "unlock-partial-merged"
    );

    // Linux unlocks the mapping before the hole, fails with ENOMEM there and
    // leaves the one after it locked. This backend's validation does not
    // report the hole (`munlock_guest_range`, a known difference of its
    // own), but unlocks what Linux unlocks.
    let holed = room(&mut executor, &memory, 3);
    mmap(&mut executor, &memory, holed, 1, RW, locked);
    mmap(&mut executor, &memory, holed + 2 * PAGE, 1, RW, locked);
    assert_eq!(unlock(&mut executor, holed, 3 * PAGE), 0);
    assert_eq!(
        [holed, holed + 2 * PAGE].map(|at| flags_at(&executor, &memory, at).2),
        [text("rd wr mr mw me ac"), text("rd wr mr mw me lo ac")],
        "unlock-hole-before, unlock-hole-after"
    );
    // A munlock that starts in a hole unlocks nothing.
    let after = holed + 2 * PAGE;
    assert_eq!(unlock(&mut executor, holed + PAGE, 2 * PAGE), 0);
    assert_eq!(
        flags_at(&executor, &memory, after).2,
        text("rd wr mr mw me lo ac")
    );

    let all = room(&mut executor, &memory, 3);
    mmap(&mut executor, &memory, all, 1, RW, locked);
    mmap(&mut executor, &memory, all + 2 * PAGE, 1, R, locked);
    ok(call(
        &mut executor,
        &memory,
        libc::SYS_munlockall,
        [0, 0, 0, 0, 0, 0],
    ));
    assert_eq!(
        [all, all + 2 * PAGE, after].map(|at| flags_at(&executor, &memory, at).2),
        [
            text("rd wr mr mw me ac"),
            text("rd mr mw me"),
            text("rd wr mr mw me ac")
        ],
        "unlockall-rw, unlockall-r, and every other locked mapping"
    );
    assert_eq!(memory.flagged_pages(FLAG_LOCKED), 0);
}

/// Round 2, finding 5 witness (`rv1342-delta-flags-unlock-prefix-probe.log`):
/// a munlock that fails with ENOMEM still unlocks the mapped prefix.
#[test]
fn review_unlock_error_still_clears_mapped_prefix() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let base = room(&mut executor, &memory, 1);
    mmap(
        &mut executor,
        &memory,
        base,
        1,
        RW,
        PRIVATE | FIXED | libc::MAP_LOCKED as u64,
    );
    let length = crate::memory::USER_ADDRESS_END - base;
    assert!(
        memory.user_range_to_guest(base, length).is_none(),
        "range crosses the provider's address-window boundary"
    );
    assert_eq!(
        call(
            &mut executor,
            &memory,
            libc::SYS_munlock,
            [base, length, 0, 0, 0, 0]
        ),
        negative_errno(libc::ENOMEM)
    );
    // Native apply_vma_lock_flags unlocks the first VMA, then reports
    // ENOMEM at the following hole. Failure does not undo that prefix.
    assert_eq!(
        flags_at(&executor, &memory, base).2,
        text("rd wr mr mw me ac")
    );
}

/// Round 2, finding 5: a munlock Linux refuses for its arguments (EINVAL,
/// a range that wraps) changes nothing, and one that starts in a hole and
/// fails (ENOMEM) unlocks nothing.
#[test]
fn a_munlock_refused_before_any_mapping_unlocks_nothing() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let base = room(&mut executor, &memory, 2);
    mmap(
        &mut executor,
        &memory,
        base + PAGE,
        1,
        RW,
        PRIVATE | FIXED | libc::MAP_LOCKED as u64,
    );
    assert_eq!(
        call(
            &mut executor,
            &memory,
            libc::SYS_munlock,
            [base + PAGE, u64::MAX - base, 0, 0, 0, 0]
        ),
        negative_errno(libc::EINVAL)
    );
    let length = crate::memory::USER_ADDRESS_END - base;
    assert_eq!(
        call(
            &mut executor,
            &memory,
            libc::SYS_munlock,
            [base, length, 0, 0, 0, 0]
        ),
        negative_errno(libc::ENOMEM)
    );
    assert_eq!(
        flags_at(&executor, &memory, base + PAGE).2,
        text("rd wr mr mw me lo ac")
    );
}

/// Finding 2 witness (`rv1342-flags-probe.log`: seal-first, seal-second).
#[test]
fn reviewer_file_mapping_seal_snapshots_must_not_merge() {
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;

    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let base = mmap(&mut executor, &memory, 0, 4, R, PRIVATE);
    ok(call(
        &mut executor,
        &memory,
        libc::SYS_munmap,
        [base, 4 * PAGE, 0, 0, 0, 0],
    ));
    // The external owner may add a FUTURE_WRITE seal while the guest's
    // original read-only shared mapping remains alive.
    // SAFETY: a new memfd this test owns.
    let raw = unsafe { libc::memfd_create(c"review-file-flags".as_ptr(), libc::MFD_ALLOW_SEALING) };
    assert!(raw >= 0);
    // SAFETY: memfd_create returned a new descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(raw) };
    file.set_len(2 * PAGE).unwrap();
    let fd = insert_file_with_flags(&mut executor.state, file.try_clone().unwrap(), false, None);
    assert!(fd >= 0);
    let map_file = |executor: &mut ElfExecutor, at: u64, offset: u64| {
        let mut owner = memory.clone();
        let result = execute_basic_syscall(
            &mut owner,
            &mut executor.state,
            &SyscallRequest::new(
                libc::SYS_mmap as u64,
                [
                    at,
                    PAGE,
                    R,
                    (libc::MAP_SHARED | libc::MAP_FIXED) as u64,
                    fd as u64,
                    offset,
                ],
            ),
        );
        match result {
            SyscallAction::Continue { result, .. } => assert_eq!(result, at as i64),
            _ => panic!("mmap did not return Continue"),
        }
    };
    map_file(&mut executor, base + PAGE, 0);
    assert_eq!(
        flags_at(&executor, &memory, base + PAGE),
        (base + PAGE, base + 2 * PAGE, text("rd sh mr mw me ms")),
    );
    // SAFETY: fcntl on a descriptor this test owns.
    assert_eq!(
        unsafe {
            libc::fcntl(
                file.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_FUTURE_WRITE,
            )
        },
        0
    );
    map_file(&mut executor, base + 2 * PAGE, PAGE);
    // Linux has two mappings: their VM_MAYWRITE bits differ, so they may
    // not merge even though descriptor, protection and offsets agree.
    assert_eq!(
        [base + PAGE, base + 2 * PAGE].map(|at| flags_at(&executor, &memory, at)),
        [
            (base + PAGE, base + 2 * PAGE, text("rd sh mr mw me ms")),
            (base + 2 * PAGE, base + 3 * PAGE, text("rd sh mr me ms")),
        ],
    );
}

/// Finding 2: the seal transition with the sealed mapping at the lower
/// address keeps the two apart too (`fix1_probe.log`: seal-low-sealed,
/// seal-low-unsealed); and a part whose facts are not known, beside a part
/// whose are, in either order, leaves the line it joins with no flags,
/// rather than the known part's.
#[test]
fn file_mappings_whose_captured_flags_differ_or_are_not_known_report_no_merged_flags() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    let (mut executor, memory) = loaded(&directory);
    let shared = libc::MAP_SHARED as u64;

    let low = room(&mut executor, &memory, 2);
    let file = sealable_memfd(2);
    let fd = insert_file_with_flags(&mut executor.state, file.try_clone().unwrap(), false, None);
    map_fd(&mut executor, &memory, low + PAGE, 1, R, shared, fd, PAGE);
    seal_future_writes(&file);
    map_fd(&mut executor, &memory, low, 1, R, shared, fd, 0);
    assert_eq!(
        [low, low + PAGE].map(|at| flags_at(&executor, &memory, at)),
        [
            (low, low + PAGE, text("rd sh mr me ms")),
            (low + PAGE, low + 2 * PAGE, text("rd sh mr mw me ms")),
        ],
        "seal-low-sealed, seal-low-unsealed"
    );

    // Two pages mapped alike are one line; then one of them has its facts
    // made not known, as a capture that failed leaves them.
    for unknown_page in [0, 1] {
        let at = room(&mut executor, &memory, 2);
        let file = sealable_memfd(2);
        let fd =
            insert_file_with_flags(&mut executor.state, file.try_clone().unwrap(), false, None);
        map_fd(&mut executor, &memory, at, 1, R, shared, fd, 0);
        map_fd(&mut executor, &memory, at + PAGE, 1, R, shared, fd, PAGE);
        assert_eq!(
            flags_at(&executor, &memory, at),
            (at, at + 2 * PAGE, text("rd sh mr mw me ms")),
            "one mapping, as on Linux (fix1_probe.log: no-seal-merged)"
        );
        let page = at + unknown_page * PAGE;
        let guest = memory.user_range_to_guest(page, PAGE).unwrap();
        let identity = memory.mapping_identities_in(guest, PAGE).remove(0);
        let Some(super::mapping_list::MappedObject::File {
            file,
            raw_device,
            raw_inode,
            ..
        }) = identity.downcast_ref::<super::mapping_list::MappedObject>()
        else {
            panic!("a file mapping's identity");
        };
        let unknown =
            crate::memory::MappingIdentity::new(super::mapping_list::MappedObject::File {
                file: file.clone(),
                raw_device: *raw_device,
                raw_inode: *raw_inode,
                vm_facts: None,
            });
        memory.describe_mapping(guest, PAGE, None, 0, Some(unknown));
        assert_eq!(
            flags_at(&executor, &memory, at),
            (at, at + 2 * PAGE, None),
            "page {unknown_page} not known"
        );
    }
}

// ---------------------------------------------------------------------------
// Finding 1: the host's facts are captured as the run starts.

/// A subscriber that counts the INFO events that log the host's mapping
/// facts.
struct HostFactsEvents(std::sync::Arc<AtomicU64>);

impl tracing::Subscriber for HostFactsEvents {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        if *event.metadata().level() == tracing::Level::INFO
            && message.0.starts_with("LinuxEmu host mapping facts")
        {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// A run's life as these tests drive it: a mapping with `MAP_NORESERVE`, a
/// guard, lists, a fork, the child's list, and the child's exec.
fn drive_a_run(executor: &mut ElfExecutor, memory: &GuestMemory, directory: &Directory) {
    let noreserve = mmap(
        executor,
        memory,
        0,
        1,
        RW,
        PRIVATE | libc::MAP_NORESERVE as u64,
    );
    let guarded = mmap(executor, memory, 0, 1, RW, PRIVATE);
    ok(call(
        executor,
        memory,
        libc::SYS_madvise,
        [guarded, PAGE, mm::MADV_GUARD_INSTALL as u64, 0, 0, 0],
    ));
    line(executor, memory, noreserve);
    let child_memory = memory.snapshot().unwrap();
    ElfExecutor::inherit_mappings_in_forked_child(&child_memory);
    let mut child = executor
        .fork_child(executor.state.pid + 40, false, false)
        .unwrap();
    line(&child, &child_memory, guarded);
    child.replace_after_exec(test_state(&directory.0)).unwrap();
}

/// The host's facts are read once, as the executor of the run's first task
/// is made, before any syscall of the guest: loading reads none, and a
/// change after that point reaches no mapping made or listed later, in the
/// process, a fork child, or the image it executes.
#[test]
fn the_host_facts_are_captured_as_the_run_starts_and_kept_through_fork_and_exec() {
    let directory = Directory::new();
    // Linux 7.1.3 source: overcommit mode 2 ignores MAP_NORESERVE, and the
    // mapping is charged (`do_mmap`, `mm/mmap.c`; as
    // `map_noreserve_follows_the_hosts_overcommit_mode`); a host that
    // prints no `gu` prints none for a guarded mapping.
    let captured = HostVmFacts {
        guard_flag_printed: Some(false),
        overcommit_memory: Some(super::vm_flags::OVERCOMMIT_NEVER),
    };
    let mut memory = GuestMemory::new(0, 32 * 1024 * 1024).unwrap();
    let mut state = crate::elf::load_static_elf(
        &mut memory,
        &crate::elf::minimal_test_elf(&[0xf4]),
        &["vm-flags"],
        &[],
        &directory.0,
    )
    .unwrap();
    state.children = ChildWaitContext::test_root();
    assert_eq!(
        state.host_vm_facts,
        HostVmFacts::UNCAPTURED,
        "loading reads none"
    );
    let mut executor = {
        let _host = inject_host_vm_facts(captured);
        ElfExecutor::new(state, false)
    };
    assert_eq!(executor.state.host_vm_facts, captured);
    let _later = inject_host_vm_facts(HOST);
    let noreserve = mmap(
        &mut executor,
        &memory,
        0,
        1,
        RW,
        PRIVATE | libc::MAP_NORESERVE as u64,
    );
    let guarded = mmap(&mut executor, &memory, 0, 1, RW, PRIVATE);
    ok(call(
        &mut executor,
        &memory,
        libc::SYS_madvise,
        [guarded, PAGE, mm::MADV_GUARD_INSTALL as u64, 0, 0, 0],
    ));
    for at in [noreserve, guarded] {
        assert_eq!(
            flags_at(&executor, &memory, at).2,
            text("rd wr mr mw me ac"),
            "{at:#x}"
        );
    }
    let child_memory = memory.snapshot().unwrap();
    ElfExecutor::inherit_mappings_in_forked_child(&child_memory);
    let mut child = executor
        .fork_child(executor.state.pid + 40, false, false)
        .unwrap();
    assert_eq!(child.state.host_vm_facts, captured, "a fork keeps them");
    assert_eq!(
        flags_at(&child, &child_memory, guarded).2,
        text("rd wr mr mw me ac")
    );
    child.replace_after_exec(test_state(&directory.0)).unwrap();
    assert_eq!(child.state.host_vm_facts, captured, "an exec keeps them");
}

/// No list, mapping, fork or exec reads a host fact: the run read them all
/// as its executor was made.
#[test]
fn no_list_or_mapping_reads_the_host_after_the_run_starts() {
    let directory = Directory::new();
    let before = super::vm_flags::host_fact_reads();
    let (mut executor, memory) = loaded(&directory);
    let read = super::vm_flags::host_fact_reads() - before;
    assert_eq!(read, 2, "the guard probe and the overcommit mode");
    drive_a_run(&mut executor, &memory, &directory);
    assert_eq!(super::vm_flags::host_fact_reads() - before, read);
}

/// Each run logs its host facts at INFO once, under the subscriber current
/// as the run starts, whatever else the run does, and a second run in the
/// same process logs its own.
#[test]
fn each_run_logs_its_host_facts_once_under_its_own_subscriber() {
    let _host = inject_host_vm_facts(HOST);
    let directory = Directory::new();
    for run in 0..2 {
        let events = std::sync::Arc::new(AtomicU64::new(0));
        tracing::subscriber::with_default(HostFactsEvents(events.clone()), || {
            let (mut executor, memory) = loaded(&directory);
            drive_a_run(&mut executor, &memory, &directory);
        });
        assert_eq!(events.load(Ordering::SeqCst), 1, "run {run}");
    }
}
