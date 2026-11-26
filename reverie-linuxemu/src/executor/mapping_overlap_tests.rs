/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `ElfExecutor::memory_map_overlaps`, the executor's answer to
//! `Guest::memory_map_overlaps`, against the list of mappings it stands for
//! (`ElfExecutor::memory_map`): equal wherever that list is given, over
//! address spaces a seeded sequence of the executor's own syscalls makes,
//! and read from the lines around the range rather than from the whole
//! address space, which the count of pages read shows without timing
//! anything.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::*;

const PAGE: u64 = PAGE_SIZE;
const R: u64 = libc::PROT_READ as u64;
const RW: u64 = (libc::PROT_READ | libc::PROT_WRITE) as u64;
const RX: u64 = (libc::PROT_READ | libc::PROT_EXEC) as u64;
const PRIVATE: u64 = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
const SHARED: u64 = (libc::MAP_SHARED | libc::MAP_ANONYMOUS) as u64;
const FIXED: u64 = libc::MAP_FIXED as u64;
/// The data file's length, in pages.
const DATA_PAGES: u64 = 16;
/// The stack window's user range.
const WINDOW: (u64, u64) = (
    crate::memory::USER_ADDRESS_END - STACK_LIMIT,
    crate::memory::USER_STACK_TOP,
);

struct Directory(std::path::PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "reverie-linuxemu-mapping-overlap-{}-{}",
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
/// program, and an executor of its first thread. An image loaded from a
/// file has every page's mapping known; one loaded from bytes has image
/// pages whose file is not known, so the list leaves out every line that
/// touches them and says it is incomplete.
fn space(directory: &Directory, from_file: bool) -> (ElfExecutor, GuestMemory) {
    let mut memory = GuestMemory::new(0, 128 * 1024 * 1024).unwrap();
    let image = crate::elf::minimal_test_elf(&[0xf4]);
    let mut state = if from_file {
        let path = directory.0.join("overlap-image");
        std::fs::write(&path, &image).unwrap();
        crate::elf::load_static_elf_file(
            &mut memory,
            std::fs::File::open(&path).unwrap(),
            &["overlap"],
            &[],
            &directory.0,
        )
        .unwrap()
    } else {
        crate::elf::load_static_elf(&mut memory, &image, &["overlap"], &[], &directory.0).unwrap()
    };
    state.children = ChildWaitContext::test_root();
    (ElfExecutor::new(state, false), memory)
}

/// [`space`] with a data file of `DATA_PAGES` pages, named `name`, that the
/// guest itself opened (`openat`, read and write) as its descriptor, which
/// is returned. The guest opens it, rather than a test putting a host file
/// in the executor's state, because each call the executor runs puts its own
/// table's descriptors in that state.
fn space_with_data(
    directory: &Directory,
    from_file: bool,
    name: &str,
) -> (ElfExecutor, GuestMemory, i32) {
    space_with_data_pages(directory, from_file, name, DATA_PAGES)
}

/// [`space_with_data`] with a data file of `pages` pages.
fn space_with_data_pages(
    directory: &Directory,
    from_file: bool,
    name: &str,
    pages: u64,
) -> (ElfExecutor, GuestMemory, i32) {
    use std::os::unix::ffi::OsStrExt;

    let path = directory.0.join(name);
    std::fs::write(&path, vec![0x5a; (pages * PAGE) as usize]).unwrap();
    let (mut executor, memory) = space(directory, from_file);
    let page = call(
        &mut executor,
        &memory,
        libc::SYS_mmap,
        [0, PAGE, RW, PRIVATE, u64::MAX, 0],
    );
    assert!(page > 0, "mmap: {page}");
    let page = page as u64;
    let mut name_bytes = path.as_os_str().as_bytes().to_vec();
    name_bytes.push(0);
    memory.clone().write(page, &name_bytes).unwrap();
    let fd = call(
        &mut executor,
        &memory,
        libc::SYS_openat,
        [libc::AT_FDCWD as u64, page, libc::O_RDWR as u64, 0, 0, 0],
    );
    assert!(fd >= 0, "openat {path:?}: {fd}");
    assert_eq!(
        call(
            &mut executor,
            &memory,
            libc::SYS_munmap,
            [page, PAGE, 0, 0, 0, 0]
        ),
        0
    );
    (executor, memory, fd as i32)
}

fn call(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    number: libc::c_long,
    args: [u64; 6],
) -> i64 {
    executor.execute(&SyscallRequest::new(number as u64, args), memory)
}

/// A private mapping of the data file, the guest's descriptor `fd`, at `at`,
/// `pages` pages from page `offset` of the file, replacing what was there;
/// its result.
fn map_data(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    fd: i32,
    at: u64,
    pages: u64,
    prot: u64,
    offset: u64,
) -> i64 {
    call(
        executor,
        memory,
        libc::SYS_mmap,
        [
            at,
            pages * PAGE,
            prot,
            libc::MAP_PRIVATE as u64 | FIXED,
            fd as u64,
            offset * PAGE,
        ],
    )
}

/// Execs a minimal image file from the guest, `execve(path, [path], [])`,
/// with the path and arrays on a page the guest maps first; its result.
fn exec_image(directory: &Directory, executor: &mut ElfExecutor, memory: &GuestMemory) -> i64 {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    let path = directory.0.join("overlap-exec");
    std::fs::write(&path, crate::elf::minimal_test_elf(&[0xf4])).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let page = call(
        executor,
        memory,
        libc::SYS_mmap,
        [0, PAGE, RW, PRIVATE, u64::MAX, 0],
    );
    assert!(page > 0, "mmap: {page}");
    let page = page as u64;
    let (argv, envp) = (page + PAGE / 2, page + PAGE / 2 + 16);
    let mut path_bytes = path.as_os_str().as_bytes().to_vec();
    path_bytes.push(0);
    let mut writer = memory.clone();
    writer.write(page, &path_bytes).unwrap();
    writer.write(argv, &page.to_le_bytes()).unwrap();
    writer.write(argv + 8, &0_u64.to_le_bytes()).unwrap();
    writer.write(envp, &0_u64.to_le_bytes()).unwrap();
    call(
        executor,
        memory,
        libc::SYS_execve,
        [page, argv, envp, 0, 0, 0],
    )
}

/// `pages` free pages, unmapped, with a free page on each side.
fn room(executor: &mut ElfExecutor, memory: &GuestMemory, pages: u64) -> u64 {
    let base = call(
        executor,
        memory,
        libc::SYS_mmap,
        [0, (pages + 2) * PAGE, 0, PRIVATE, u64::MAX, 0],
    );
    assert!(base > 0, "mmap: {base}");
    let base = base as u64;
    assert_eq!(
        call(
            executor,
            memory,
            libc::SYS_munmap,
            [base, (pages + 2) * PAGE, 0, 0, 0, 0],
        ),
        0
    );
    base + PAGE
}

/// A seeded xorshift64* sequence: the same address spaces on every run.
struct Sequence(u64);

impl Sequence {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn pick<T: Copy>(&mut self, choices: &[T]) -> T {
        choices[self.below(choices.len() as u64) as usize]
    }
}

/// Where the seeded calls act: an arena in the mmap area, and the pages just
/// below the image, whose lines meet the image's.
struct Arenas {
    mmap: (u64, u64),
    below_image: (u64, u64),
    /// The guest's descriptor of the data file.
    data_fd: i32,
}

impl Arenas {
    fn pick(&self, sequence: &mut Sequence) -> (u64, u64) {
        if sequence.below(3) == 0 {
            self.below_image
        } else {
            self.mmap
        }
    }
}

/// One seeded call on the address space, of any kind the list follows; it
/// may fail, which leaves an address space as valid as any other.
fn seeded_call(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    arenas: &Arenas,
    sequence: &mut Sequence,
) -> String {
    let (low, high) = arenas.pick(sequence);
    let arena_pages = (high - low) / PAGE;
    let first = sequence.below(arena_pages);
    let pages = 1 + sequence.below((arena_pages - first).min(8));
    let at = low + first * PAGE;
    let prot = sequence.pick(&[0, R, RW, RW, RX]);
    let advice = [
        libc::MADV_RANDOM,
        libc::MADV_SEQUENTIAL,
        libc::MADV_NORMAL,
        libc::MADV_DONTNEED,
        libc::MADV_DONTFORK,
        libc::MADV_DOFORK,
        libc::MADV_HUGEPAGE,
        libc::MADV_NOHUGEPAGE,
    ];
    match sequence.below(12) {
        0 => {
            let flags = PRIVATE | FIXED | sequence.pick(&[0, libc::MAP_NORESERVE as u64]);
            let result = call(
                executor,
                memory,
                libc::SYS_mmap,
                [at, pages * PAGE, prot, flags, u64::MAX, 0],
            );
            format!("mmap private {at:#x}+{pages} prot {prot} flags {flags:#x} = {result}")
        }
        1 => {
            let prot = sequence.pick(&[R, RW]);
            let result = call(
                executor,
                memory,
                libc::SYS_mmap,
                [at, pages * PAGE, prot, SHARED | FIXED, u64::MAX, 0],
            );
            format!("mmap shared anonymous {at:#x}+{pages} prot {prot} = {result}")
        }
        2 => {
            let offset = sequence.below(DATA_PAGES - pages + 1);
            let prot = sequence.pick(&[R, RW, RX]);
            let result = map_data(executor, memory, arenas.data_fd, at, pages, prot, offset);
            format!("mmap data {at:#x}+{pages} prot {prot} offset {offset} = {result}")
        }
        3 => {
            let result = call(
                executor,
                memory,
                libc::SYS_mprotect,
                [at, pages * PAGE, prot, 0, 0, 0],
            );
            format!("mprotect {at:#x}+{pages} prot {prot} = {result}")
        }
        4 => {
            let result = call(
                executor,
                memory,
                libc::SYS_munmap,
                [at, pages * PAGE, 0, 0, 0, 0],
            );
            format!("munmap {at:#x}+{pages} = {result}")
        }
        5 => {
            let advice = sequence.pick(&advice);
            let result = call(
                executor,
                memory,
                libc::SYS_madvise,
                [at, pages * PAGE, advice as u64, 0, 0, 0],
            );
            format!("madvise {at:#x}+{pages} advice {advice} = {result}")
        }
        6 => {
            let to = executor.state.mm.heap_base + sequence.below(8) * PAGE;
            let result = call(executor, memory, libc::SYS_brk, [to, 0, 0, 0, 0, 0]);
            format!("brk {to:#x} = {result:#x}")
        }
        7 => {
            let (to_low, to_high) = arenas.pick(sequence);
            let to_pages = (to_high - to_low) / PAGE;
            let new_pages = 1 + sequence.below(8).min(to_pages - 1);
            let to = to_low + sequence.below(to_pages - new_pages + 1) * PAGE;
            let result = call(
                executor,
                memory,
                libc::SYS_mremap,
                [
                    at,
                    pages * PAGE,
                    new_pages * PAGE,
                    (libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED) as u64,
                    to,
                    0,
                ],
            );
            format!("mremap {at:#x}+{pages} to {to:#x}+{new_pages} = {result}")
        }
        8 => {
            // `mlock(2)` and `munlock(2)`, whose answers a consumer reads the
            // list around.
            let number = sequence.pick(&[libc::SYS_mlock, libc::SYS_munlock]);
            let result = call(executor, memory, number, [at, pages * PAGE, 0, 0, 0, 0]);
            format!(
                "{} {at:#x}+{pages} = {result}",
                if number == libc::SYS_mlock {
                    "mlock"
                } else {
                    "munlock"
                }
            )
        }
        9 => {
            // A shared mapping of the data file.
            let offset = sequence.below(DATA_PAGES - pages + 1);
            let prot = sequence.pick(&[R, RW]);
            let result = call(
                executor,
                memory,
                libc::SYS_mmap,
                [
                    at,
                    pages * PAGE,
                    prot,
                    libc::MAP_SHARED as u64 | FIXED,
                    arenas.data_fd as u64,
                    offset * PAGE,
                ],
            );
            format!("mmap shared data {at:#x}+{pages} prot {prot} offset {offset} = {result}")
        }
        10 => {
            // `MADV_GUARD_INSTALL` and `MADV_GUARD_REMOVE`.
            let advice =
                sequence.pick(&[super::mm::MADV_GUARD_INSTALL, super::mm::MADV_GUARD_REMOVE]);
            let result = call(
                executor,
                memory,
                libc::SYS_madvise,
                [at, pages * PAGE, advice as u64, 0, 0, 0],
            );
            format!("madvise guard {at:#x}+{pages} advice {advice} = {result}")
        }
        _ => {
            // A split of the stack window, whose mappings the list holds
            // beside every other line.
            let page = WINDOW.0 + (16 + sequence.below(8)) * PAGE;
            let prot = sequence.pick(&[R, RW]);
            let result = call(
                executor,
                memory,
                libc::SYS_mprotect,
                [page, PAGE, prot, 0, 0, 0],
            );
            format!("mprotect window {page:#x} prot {prot} = {result}")
        }
    }
}

/// The ranges each check asks about: every page and short run of pages
/// over and around the arenas, unaligned ends, empty and reversed ranges,
/// the image, the heap, and the stack window's edge.
fn ranges(executor: &ElfExecutor, arenas: &Arenas) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    for (low, high) in [arenas.mmap, arenas.below_image] {
        let mut page = low - 2 * PAGE;
        while page < high + 2 * PAGE {
            for pages in [1, 2, 5] {
                ranges.push((page, page + pages * PAGE));
            }
            ranges.push((page + 123, page + PAGE + 7));
            ranges.push((page, page));
            ranges.push((page + PAGE, page));
            page += PAGE;
        }
        ranges.push((low, high));
    }
    let heap = executor.state.mm.heap_base;
    ranges.push((0x20_0000, 0x20_0000 + PAGE));
    ranges.push((0x20_0000 - PAGE, 0x20_0000));
    ranges.push((heap - PAGE, heap + 8 * PAGE));
    ranges.push((WINDOW.0 - PAGE, WINDOW.0 + PAGE));
    ranges.push((WINDOW.0 + 16 * PAGE, WINDOW.0 + 17 * PAGE));
    ranges.push((0, u64::MAX));
    ranges
}

/// What the checks saw, so that a run that compared nothing fails.
#[derive(Default)]
struct Seen {
    compared: usize,
    overlapping: usize,
    incomplete_lists: usize,
    /// Listed lines of the data file, over every check: proof that the file
    /// mappings the seeded calls make took place.
    data_lines: usize,
    /// Execs checked.
    execs: usize,
    /// The seeded calls made, by kind.
    attempted: std::collections::BTreeMap<String, usize>,
    /// The seeded calls of each kind that succeeded, by kind: proof that
    /// each kind changed some address space.
    succeeded: std::collections::BTreeMap<String, usize>,
}

impl Seen {
    /// Counts the seeded call `what` ([`seeded_call`]'s description) by its
    /// kind, the words before its address, and by its result.
    fn count_call(&mut self, what: &str) {
        let kind = what.split(" 0x").next().unwrap_or(what).to_string();
        let succeeded = !what.rsplit("= ").next().unwrap_or("-").starts_with('-');
        *self.attempted.entry(kind.clone()).or_default() += 1;
        if succeeded {
            *self.succeeded.entry(kind).or_default() += 1;
        }
    }
}

/// The runs and lines of an address space rebuilt from every page
/// (`GuestMemory::user_mapping_runs_by_pages`), independently of the index
/// the queries read.
struct Oracle {
    runs: Vec<(u64, u64)>,
    lines: Vec<(u64, u64)>,
}

impl Oracle {
    fn of(executor: &ElfExecutor, memory: &GuestMemory) -> Self {
        let runs = memory.user_mapping_runs_by_pages().runs;
        let image = super::mapping_list::ImageMapFacts::of(&executor.state);
        let window = memory
            .user_layout()
            .0
            .into_iter()
            .find(|window| window.user_end == crate::memory::USER_STACK_TOP)
            .map(|window| (window.user_start, window.user_end));
        Self {
            lines: super::mapping_list::line_extents(runs.clone(), &image, window),
            runs: runs.iter().map(|run| (run.start, run.end)).collect(),
        }
    }

    /// The runs a query of `[start, end)` may read: each run that meets the
    /// span of the range and of every line that overlaps it (listed or not),
    /// plus the one run just before that span and the one just after it, as
    /// the lead ruled k (a line's far ends decide whether the list leaves it
    /// out); and the stack window's runs, which every query reads, since one
    /// page of the window whose mapping is not known empties the list.
    fn allowed_runs(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let (mut low, mut high) = (start, end);
        for &(line_start, line_end) in &self.lines {
            if line_start < end && start < line_end {
                low = low.min(line_start);
                high = high.max(line_end);
            }
        }
        let mut allowed: Vec<(u64, u64)> = self
            .runs
            .iter()
            .copied()
            .filter(|&(run_start, run_end)| run_start < high && low < run_end)
            .collect();
        allowed.extend(self.runs.iter().rev().find(|&&(_, run_end)| run_end <= low));
        allowed.extend(self.runs.iter().find(|&&(run_start, _)| run_start >= high));
        allowed.extend(self.window_runs());
        allowed
    }

    /// The runs that meet the stack window.
    fn window_runs(&self) -> Vec<(u64, u64)> {
        self.runs
            .iter()
            .copied()
            .filter(|&(run_start, run_end)| run_start < WINDOW.1 && WINDOW.0 < run_end)
            .collect()
    }
}

/// Checks the executor's answer for every range against the list of
/// mappings it stands for, which must be given, and the runs the memory
/// lists against the runs rebuilt from every page. With `work`, also that
/// each answer read only runs its range needs ([`check_query_work`]).
fn check(
    executor: &ElfExecutor,
    memory: &GuestMemory,
    arenas: &Arenas,
    seen: &mut Seen,
    work: bool,
    context: &str,
) {
    let tid = executor.state.tid;
    let map = executor
        .memory_map(memory, tid)
        .unwrap_or_else(|error| panic!("the list fails after {context}: {error:?}"));
    if !map.complete {
        seen.incomplete_lists += 1;
    }
    seen.data_lines += map
        .mappings
        .iter()
        .filter(|mapping| {
            matches!(&mapping.backing, reverie::MappingBacking::File { path, .. }
                if path.ends_with(b"overlap-data"))
        })
        .count();
    assert_eq!(
        format!("{:?}", memory.user_mapping_runs().runs),
        format!("{:?}", memory.user_mapping_runs_by_pages().runs),
        "the listed runs after {context}"
    );
    // The window's lines from the index equal those from every window page.
    let (by_index, by_pages) = super::facts::stack_window_lines_both_ways(
        memory,
        &super::mapping_list::ImageMapFacts::of(&executor.state),
    );
    assert_eq!(by_index, by_pages, "the window's lines after {context}");
    let oracle = Oracle::of(executor, memory);
    for (start, end) in ranges(executor, arenas) {
        let expected = map.overlaps(start, end);
        memory.take_query_log();
        assert_eq!(
            executor.memory_map_overlaps(memory, tid, start, end),
            Ok(expected),
            "[{start:#x}, {end:#x}) after {context}\nlist: {map:?}"
        );
        let log = memory.take_query_log();
        if work && start < end {
            let allowed = oracle.allowed_runs(start, end);
            check_query_work(
                &log,
                &allowed,
                &format!("[{start:#x}, {end:#x}) after {context}"),
            );
        }
        seen.compared += 1;
        seen.overlapping += usize::from(expected);
    }
}

/// Runs the seeded sequences, over an image from a file and one from bytes,
/// checking after each call and in a forked child's copy of each address
/// space ([`check`], with `work` as given).
fn seeded_spaces(work: bool) -> Seen {
    let mut seen = Seen::default();
    for from_file in [true, false] {
        for seed in [
            0x9e37_79b9_7f4a_7c15,
            0x1234_5678_9abc_def1,
            0xdead_beef_cafe_f00d,
        ] {
            let directory = Directory::new();
            let (mut executor, memory, data_fd) =
                space_with_data(&directory, from_file, "overlap-data");
            let mmap = room(&mut executor, &memory, 40);
            let arenas = Arenas {
                mmap: (mmap, mmap + 40 * PAGE),
                below_image: (0x20_0000 - 12 * PAGE, 0x20_0000),
                data_fd,
            };
            let mut sequence = Sequence(seed);
            check(&executor, &memory, &arenas, &mut seen, work, "loading");
            // A guard on a page of a private mapping, so that every sequence
            // starts from an address space that holds a guard.
            let guarded = mmap + 32 * PAGE;
            assert_eq!(
                call(
                    &mut executor,
                    &memory,
                    libc::SYS_mmap,
                    [guarded, 4 * PAGE, RW, PRIVATE | FIXED, u64::MAX, 0],
                ),
                guarded as i64
            );
            assert_eq!(
                call(
                    &mut executor,
                    &memory,
                    libc::SYS_madvise,
                    [
                        guarded + PAGE,
                        PAGE,
                        super::mm::MADV_GUARD_INSTALL as u64,
                        0,
                        0,
                        0
                    ],
                ),
                0,
                "MADV_GUARD_INSTALL"
            );
            check(
                &executor,
                &memory,
                &arenas,
                &mut seen,
                work,
                "a guard install",
            );
            // The same guard removed, then installed again, each asserted to
            // succeed, so that the removal's state is checked too.
            for (advice, what) in [
                (super::mm::MADV_GUARD_REMOVE, "a guard removal"),
                (super::mm::MADV_GUARD_INSTALL, "a guard installed again"),
            ] {
                assert_eq!(
                    call(
                        &mut executor,
                        &memory,
                        libc::SYS_madvise,
                        [guarded + PAGE, PAGE, advice as u64, 0, 0, 0],
                    ),
                    0,
                    "{what}"
                );
                check(&executor, &memory, &arenas, &mut seen, work, what);
            }
            // An `mlock(2)`, which this backend refuses whole (ENOSYS: it
            // does not lock pages), and a `munlock(2)`, which it applies, on
            // a mapping of their own, each answered as stated in every
            // sequence and checked after.
            let locked = mmap + 37 * PAGE;
            assert_eq!(
                call(
                    &mut executor,
                    &memory,
                    libc::SYS_mmap,
                    [locked, 2 * PAGE, RW, PRIVATE | FIXED, u64::MAX, 0],
                ),
                locked as i64
            );
            for (number, answer, what) in [
                (
                    libc::SYS_mlock,
                    -i64::from(libc::ENOSYS),
                    "an mlock, refused",
                ),
                (libc::SYS_munlock, 0, "a munlock"),
            ] {
                assert_eq!(
                    call(
                        &mut executor,
                        &memory,
                        number,
                        [locked, 2 * PAGE, 0, 0, 0, 0]
                    ),
                    answer,
                    "{what}"
                );
                check(&executor, &memory, &arenas, &mut seen, work, what);
            }
            for step in 0..48 {
                let what = seeded_call(&mut executor, &memory, &arenas, &mut sequence);
                seen.count_call(&what);
                let context = format!("seed {seed:#x} file {from_file} step {step}: {what}");
                check(&executor, &memory, &arenas, &mut seen, work, &context);
            }
            let child_memory = memory.snapshot().unwrap();
            ElfExecutor::inherit_mappings_in_forked_child(&child_memory).unwrap();
            let child = executor
                .fork_child(executor.state.pid + 40, false, false)
                .unwrap();
            check(&child, &child_memory, &arenas, &mut seen, work, "a fork");
            // A vfork child's copy, which shares the window's record with the
            // parent: a call in the child, then both copies.
            let vfork_memory = memory.snapshot_sharing_address_space().unwrap();
            let what = seeded_call(&mut executor, &vfork_memory, &arenas, &mut sequence);
            let context = format!("seed {seed:#x} file {from_file}: a vfork child's {what}");
            check(&executor, &vfork_memory, &arenas, &mut seen, work, &context);
            check(
                &executor,
                &memory,
                &arenas,
                &mut seen,
                work,
                "its vfork parent",
            );
            // A new image over the address space.
            assert_eq!(exec_image(&directory, &mut executor, &memory), 0, "execve");
            check(&executor, &memory, &arenas, &mut seen, work, "an exec");
            seen.execs += 1;
        }
    }
    assert!(seen.compared > 10_000, "compared {}", seen.compared);
    assert_eq!(seen.execs, 6, "an exec in every sequence");
    seen
}

/// Holds one overlap query's work ([`crate::memory::QueryLog`], counted in
/// the memory's only reads of its index and of page facts) to the runs its
/// range needs: every read is a run of `allowed`, none is a page read on its
/// own, the reads counted with repeats are at most the allowed runs and one
/// re-read, every index entry looked at is a run read but for one probe at
/// the start of each of the query's two searches (the window's and the
/// range's), the page facts read are one per run read, and the query's own
/// settle read no page.
fn check_query_work(log: &crate::memory::QueryLog, allowed: &[(u64, u64)], what: &str) {
    assert_eq!(log.reads_dropped, 0, "{what}: the log dropped reads");
    // The query found the index settled: the settle it begins with read no
    // page (a settle that rebuilt the index would read every page).
    assert_eq!(
        log.settle_pages, 0,
        "{what}: the query's settle read {} pages",
        log.settle_pages
    );
    for read in &log.reads {
        assert!(
            matches!(read, crate::memory::MappingRead::Run(run_start, run_end)
                if allowed.contains(&(*run_start, *run_end))),
            "{what} read {read:?}, outside {allowed:x?}"
        );
    }
    // Counted with repeats: each allowed run read once (a window run the
    // range also meets, or the boundary run past a line that is a window
    // run, is allowed twice, once as each), and one run beside the range's
    // first line that its back-walk reads again.
    assert!(
        log.reads.len() <= allowed.len() + 1,
        "{what} read {} runs for {} allowed",
        log.reads.len(),
        allowed.len()
    );
    assert!(
        log.index_visits <= log.reads.len() as u64 + 2,
        "{what} looked at {} index entries for {} runs read",
        log.index_visits,
        log.reads.len()
    );
    assert!(
        log.page_facts <= log.reads.len() as u64,
        "{what} read {} page facts for {} runs",
        log.page_facts,
        log.reads.len()
    );
}

/// The answer is the list's, and the listed runs are those rebuilt from
/// every page, for every range, after each call of seeded sequences over an
/// image from a file and one from bytes, and in a forked child's copy of
/// each address space.
#[test]
fn the_overlap_answer_is_the_lists_after_every_call() {
    let seen = seeded_spaces(false);
    assert!(
        seen.overlapping > 0 && seen.overlapping < seen.compared,
        "overlapping {} of {}",
        seen.overlapping,
        seen.compared
    );
    assert!(seen.incomplete_lists > 0, "no incomplete list was checked");
    assert!(
        seen.data_lines > 0,
        "no mapping of the data file was checked"
    );
    // Every kind of call the list follows was made, and the ones this
    // backend applies changed some address space.
    for kind in ["mlock", "munlock", "mmap shared data", "madvise guard"] {
        assert!(
            seen.attempted.get(kind).is_some_and(|&count| count > 0),
            "no {kind} was made: {:?}",
            seen.attempted
        );
    }
    // (Every sequence also installs, removes and reinstalls a guard and
    // unlocks a mapping before its seeded calls, each asserted to succeed,
    // and makes an mlock, asserted refused: this backend locks no page.)
    for kind in ["mmap shared data", "mprotect window", "munlock"] {
        assert!(
            seen.succeeded.get(kind).is_some_and(|&count| count > 0),
            "no {kind} succeeded: {:?}",
            seen.succeeded
        );
    }
}

/// Asking whether a range reaches a listed mapping reads only the runs its
/// answer needs, from the index of runs, and no page on its own; listing
/// every mapping reads each run once and no page on its own. Thousands of
/// runs lie far from the queried ranges (2,000 one-page mappings whose
/// protections alternate, each a run and a line of its own), with a large
/// and a larger mapping, so a query that scanned the index or walked pages
/// would read far more than its allowed runs (`Oracle::allowed_runs`).
/// Counted in runs, index entries and page facts read, which no host load
/// changes. A write costs the pages it changes, and a fork's copy derives no
/// page, counted the same way (`QueryLog::settle_pages`).
#[test]
fn the_overlap_answer_reads_the_lines_around_the_range_not_the_address_space() {
    // Every range of the seeded address spaces.
    seeded_spaces(true);
    // Thousands of runs far from the queried ranges.
    let directory = Directory::new();
    let (mut executor, memory) = space(&directory, true);
    let tid = executor.state.tid;
    let mmap = |executor: &mut ElfExecutor, pages: u64, prot: u64| {
        let address = call(
            executor,
            &memory,
            libc::SYS_mmap,
            [0, pages * PAGE, prot, PRIVATE, u64::MAX, 0],
        );
        assert!(address > 0, "mmap: {address}");
        address as u64
    };
    let large = mmap(&mut executor, 2048, RW);
    let gap = room(&mut executor, &memory, 256);
    let small = gap + 126 * PAGE;
    assert_eq!(
        call(
            &mut executor,
            &memory,
            libc::SYS_mmap,
            [small, 4 * PAGE, RW, PRIVATE | FIXED, u64::MAX, 0],
        ),
        small as i64
    );
    let larger = mmap(&mut executor, 16384, RW);
    let many = 2000;
    let first_many = mmap(&mut executor, many, RW);
    for index in (1..many).step_by(2) {
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_mprotect,
                [first_many + index * PAGE, PAGE, R, 0, 0, 0],
            ),
            0
        );
    }
    let oracle = Oracle::of(&executor, &memory);
    let runs = oracle.runs.len();
    assert!(runs > many as usize, "{runs} runs");

    let query = |start: u64, end: u64, expected: bool| {
        memory.take_query_log();
        assert_eq!(
            executor.memory_map_overlaps(&memory, tid, start, end),
            Ok(expected),
            "[{start:#x}, {end:#x})"
        );
        let log = memory.take_query_log();
        // The whole list gives the same answer (read after the query's
        // counts are taken, so they stay the query's alone).
        assert_eq!(
            executor
                .memory_map(&memory, tid)
                .map(|map| map.overlaps(start, end)),
            Ok(expected),
            "[{start:#x}, {end:#x}): the list's answer"
        );
        let allowed = oracle.allowed_runs(start, end);
        check_query_work(&log, &allowed, &format!("[{start:#x}, {end:#x})"));
        assert!(
            !log.reads.is_empty() || !expected,
            "[{start:#x}, {end:#x}) read nothing"
        );
        log
    };
    // Every query also reads the stack window's runs.
    let window = oracle.window_runs().len();
    assert!(window > 0, "the stack window has runs");
    // A page of the small mapping: its run, and one run on each side.
    let small_log = query(small + PAGE, small + 2 * PAGE, true);
    assert!(small_log.reads.len() <= 3 + window, "{small_log:?}");
    // An unmapped page in the gap: at most the runs on each side.
    let empty_log = query(gap + 64 * PAGE, gap + 65 * PAGE, false);
    assert!(empty_log.reads.len() <= 2 + window, "{empty_log:?}");
    // A page in the middle of the large mapping: one run however large, and
    // its neighbours.
    let large_log = query(large + 1024 * PAGE, large + 1025 * PAGE, true);
    assert!(large_log.reads.len() <= 3 + window, "{large_log:?}");
    // A page among the many: its run and its neighbours, not the others.
    let among = first_many + 1000 * PAGE;
    let among_log = query(among, among + PAGE, true);
    assert!(among_log.reads.len() <= 3 + window, "{among_log:?}");

    // The whole list reads each run once, and no page on its own.
    memory.take_query_log();
    let listed = memory.user_mapping_runs().runs.len();
    let log = memory.take_query_log();
    assert_eq!(listed, runs);
    assert_eq!(
        log.reads.len(),
        runs,
        "the whole list read {:?}",
        log.reads.len()
    );
    assert_eq!(
        log.page_facts, runs as u64,
        "the whole list read {} page facts for {runs} runs",
        log.page_facts
    );
    assert!(
        log.reads
            .iter()
            .all(|read| matches!(read, crate::memory::MappingRead::Run(..))),
        "a page read on its own"
    );

    // A one-page protection change in the middle of the 16,384-page mapping
    // settles the index from the pages around it, not from the mapping's.
    memory.take_query_log();
    let middle = larger + 8192 * PAGE;
    assert_eq!(
        call(
            &mut executor,
            &memory,
            libc::SYS_mprotect,
            [middle, PAGE, R, 0, 0, 0],
        ),
        0
    );
    let log = memory.take_query_log();
    assert!(
        log.settle_pages > 0 && log.settle_pages <= 64,
        "a one-page mprotect derived {} pages",
        log.settle_pages
    );
    // A fork's copy takes the index as it is, deriving no page.
    memory.take_query_log();
    let child = memory.snapshot().unwrap();
    let log = child.take_query_log();
    assert_eq!(
        log.settle_pages, 0,
        "the fork's copy derived pages: {log:?}"
    );
}

/// A line made of many runs (the data file mapped one page at a time at
/// contiguous offsets of one open file: each mapping a run of its own, all
/// one line, as Linux merges them), beside a stack window of many runs: a
/// query of one page of the line reads each of the line's runs once, the run
/// on each side of the line, and each of the window's runs once, and looks at
/// two more index entries than it reads (the probe at the start of each of
/// its two searches), however long the line and however split the window.
/// A copy whose query scans the index looks at more entries, and one that
/// walks pages reads more page facts, so both fail.
#[test]
fn a_query_reads_each_run_of_a_line_of_many_runs_once() {
    const LINE_RUNS: u64 = 256;
    const WINDOW_SPLITS: u64 = 128;
    let directory = Directory::new();
    let (mut executor, memory, fd) =
        space_with_data_pages(&directory, true, "overlap-data", LINE_RUNS);
    let tid = executor.state.tid;
    let base = room(&mut executor, &memory, LINE_RUNS);
    for index in 0..LINE_RUNS {
        let at = base + index * PAGE;
        assert_eq!(
            map_data(&mut executor, &memory, fd, at, 1, R, index),
            at as i64
        );
    }
    let line_end = base + LINE_RUNS * PAGE;
    // A stack window of many runs too: every other page of 128 read-only,
    // which every query reads, since one window page whose mapping is not
    // known empties the whole list.
    for index in 0..WINDOW_SPLITS {
        let page = WINDOW.0 + (16 + 2 * index) * PAGE;
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_mprotect,
                [page, PAGE, R, 0, 0, 0],
            ),
            0,
            "mprotect window {page:#x}"
        );
    }
    let oracle = Oracle::of(&executor, &memory);
    let line_runs = oracle
        .runs
        .iter()
        .filter(|&&(run_start, run_end)| base <= run_start && run_end <= line_end)
        .count();
    assert_eq!(
        line_runs, LINE_RUNS as usize,
        "each mapping is a run of its own"
    );
    assert!(
        oracle.lines.contains(&(base, line_end)),
        "the runs are one line: {:x?}",
        oracle.lines
    );
    let below = usize::from(oracle.runs.iter().any(|&(_, run_end)| run_end <= base));
    let above = usize::from(
        oracle
            .runs
            .iter()
            .any(|&(run_start, _)| run_start >= line_end),
    );
    let window = oracle.window_runs().len();
    assert!(
        window > 2 * WINDOW_SPLITS as usize,
        "the stack window has {window} runs"
    );
    let expected_reads = line_runs + below + above + window;
    for at in [base, base + 100 * PAGE, line_end - PAGE] {
        memory.take_query_log();
        assert_eq!(
            executor.memory_map_overlaps(&memory, tid, at, at + PAGE),
            Ok(true),
            "{at:#x}"
        );
        let log = memory.take_query_log();
        // The whole list gives the same answer (read after the query's
        // counts are taken).
        assert_eq!(
            executor
                .memory_map(&memory, tid)
                .map(|map| map.overlaps(at, at + PAGE)),
            Ok(true),
            "{at:#x}: the list's answer"
        );
        check_query_work(
            &log,
            &oracle.allowed_runs(at, at + PAGE),
            &format!("{at:#x}"),
        );
        assert_eq!(
            log.reads.len(),
            expected_reads,
            "{at:#x}: the line's {line_runs} runs, {below} + {above} beside it and the window's {window}"
        );
        assert_eq!(
            log.index_visits,
            expected_reads as u64 + 2,
            "{at:#x}: index entries looked at"
        );
        assert_eq!(log.page_facts, expected_reads as u64, "{at:#x}: page facts");
    }
}

/// A list that fails only because one line cannot be stated fails as a
/// whole, and so does the answer read from it (the trait's default): here a
/// private mapping of a file whose name cannot be read (a readlink of its
/// `/proc/self/fd` entry fails, `FILE_NAME_FAILS_TEST_HOOK`). The executor's
/// answer states no line, so it still answers by range, counting that line
/// as listed, as it would be if its name could be read.
#[test]
fn a_line_that_cannot_be_stated_fails_the_list_but_not_the_answer() {
    struct NameFails;
    impl Drop for NameFails {
        fn drop(&mut self) {
            super::mapping_list::FILE_NAME_FAILS_TEST_HOOK.with(|hook| hook.set(false));
        }
    }
    let directory = Directory::new();
    let (mut executor, memory, fd) = space_with_data(&directory, true, "overlap-data");
    let tid = executor.state.tid;
    let base = room(&mut executor, &memory, 16);
    assert_eq!(
        map_data(&mut executor, &memory, fd, base, 2, R, 0),
        base as i64
    );
    let anonymous = base + 4 * PAGE;
    assert_eq!(
        call(
            &mut executor,
            &memory,
            libc::SYS_mmap,
            [anonymous, 2 * PAGE, RW, PRIVATE | FIXED, u64::MAX, 0],
        ),
        anonymous as i64
    );
    // With every name readable, the list is given and lists the file line.
    let readable = executor.memory_map(&memory, tid).unwrap();
    assert!(readable.overlaps(base, base + PAGE), "{readable:?}");
    let _restore = NameFails;
    super::mapping_list::FILE_NAME_FAILS_TEST_HOOK.with(|hook| hook.set(true));
    let list = executor.memory_map(&memory, tid);
    let unstated = reverie::FactError::NotProvided;
    assert_eq!(list, Err(unstated));
    for (start, end, expected) in [
        (base, base + PAGE, true),
        (anonymous + PAGE, anonymous + 2 * PAGE, true),
        (base + 2 * PAGE, base + 4 * PAGE, false),
        (base - PAGE, base, false),
    ] {
        let from_list = list.clone().map(|map| map.overlaps(start, end));
        assert_eq!(from_list, Err(unstated), "[{start:#x}, {end:#x})");
        assert_eq!(
            executor.memory_map_overlaps(&memory, tid, start, end),
            Ok(expected),
            "[{start:#x}, {end:#x})"
        );
    }
}
