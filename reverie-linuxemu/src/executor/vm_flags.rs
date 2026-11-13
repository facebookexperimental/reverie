/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The flags Linux keeps on each mapping (`vm_flags`, which `smaps` prints
//! as `VmFlags`), as this provider reports them
//! (`reverie::MappingFact::vm_flags`): from the provider flags each page
//! keeps (`DeclaredMapping::flags`, the `FLAG_*` constants of `mm`), the
//! facts about a mapped file captured when the mapping was made
//! ([`FileVmFacts`]), and two facts about the host kernel read once per run,
//! before the guest's first instruction ([`HostVmFacts`]). No host setting is
//! read when a list is, or a mapping made. For a file on overlayfs, which
//! runs the mmap hook of a layer it does not show, the host kernel is asked
//! instead, when the mapping is made, how it maps the same open file
//! description the same way ([`super::host_probe`]).
//!
//! The answer is `None`, rather than a guess, wherever one of those does not
//! establish every bit: see [`line_vm_flags`].

use std::io::BufRead;
use std::os::fd::AsRawFd;

use reverie::VM_ACCOUNT;
use reverie::VM_EXEC;
use reverie::VM_GROWSDOWN;
use reverie::VM_HUGEPAGE;
use reverie::VM_LOCKED;
use reverie::VM_MAYBE_GUARD;
use reverie::VM_MAYEXEC;
use reverie::VM_MAYREAD;
use reverie::VM_MAYSHARE;
use reverie::VM_MAYWRITE;
use reverie::VM_MERGEABLE;
use reverie::VM_NOHUGEPAGE;
use reverie::VM_NORESERVE;
use reverie::VM_RAND_READ;
use reverie::VM_READ;
use reverie::VM_SEQ_READ;
use reverie::VM_SHARED;
use reverie::VM_SYNC;
use reverie::VM_WRITE;

use super::mm::FLAG_ACCOUNT;
use super::mm::FLAG_ACCOUNT_UNKNOWN;
use super::mm::FLAG_GROWSDOWN;
use super::mm::FLAG_HUGEPAGE;
use super::mm::FLAG_HUGETLB;
use super::mm::FLAG_LOCKED;
use super::mm::FLAG_MAYBE_GUARD;
use super::mm::FLAG_MERGEABLE;
use super::mm::FLAG_NOHUGEPAGE;
use super::mm::FLAG_NORESERVE;
use super::mm::FLAG_RANDOM;
use super::mm::FLAG_SEQUENTIAL;
use super::mm::FLAG_SYNC;

/// Facts about the host kernel that decide flags Linux gives mappings, read
/// once per run before the guest runs ([`HostVmFacts::capture_for_run`]) and
/// fixed for the run, so that no list or mapping reads the host. Each is `None` where it could not be
/// established, and a mapping whose flags depend on it then has none
/// reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostVmFacts {
    /// Whether the host kernel prints `VM_MAYBE_GUARD` (`gu`), which a
    /// guard installed with `MADV_GUARD_INSTALL` sets on its mapping in
    /// kernels after 6.17. The guest is told the host's kernel release
    /// (`uname(2)`), so the guest's kernel prints it exactly when the host's
    /// does. Read by installing a guard on a page of the backend's own and
    /// reading that page's `VmFlags` from its own `smaps`; a kernel that
    /// refuses the advice (EINVAL) has no guards, and prints no `gu`.
    pub(crate) guard_flag_printed: Option<bool>,
    /// `/proc/sys/vm/overcommit_memory`: Linux honours `MAP_NORESERVE`
    /// (`VM_NORESERVE`) only when it is not 2 (`OVERCOMMIT_NEVER`,
    /// `do_mmap` in `mm/mmap.c`).
    pub(crate) overcommit_memory: Option<u32>,
}

/// `OVERCOMMIT_NEVER` (`include/uapi/linux/mman.h`).
pub(crate) const OVERCOMMIT_NEVER: u32 = 2;

#[cfg(test)]
std::thread_local! {
    /// A test's host facts for this thread, in place of the host's.
    static TEST_HOST_VM_FACTS: std::cell::Cell<Option<HostVmFacts>> =
        const { std::cell::Cell::new(None) };
    /// How many times this thread read a host fact ([`overcommit_memory`],
    /// [`guard_flag_printed`]), so a test can tell when they are read.
    static HOST_FACT_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl HostVmFacts {
    /// No fact established: what a process's state holds until its run
    /// captures them ([`HostVmFacts::capture_for_run`]). A line whose flags
    /// depend on one then has none reported; nothing is read lazily.
    pub(crate) const UNCAPTURED: Self = Self {
        guard_flag_printed: None,
        overcommit_memory: None,
    };

    /// Reads the host's facts for a new run, and logs them at INFO, under
    /// the caller's subscriber. The executor calls this once per run, as it
    /// makes the run's first task (`ElfExecutor::with_output`), before the
    /// guest's first instruction; forks and execs keep what it read
    /// (`LoadedStaticElf::host_vm_facts`), and no list or mapping reads the
    /// host.
    pub(crate) fn capture_for_run() -> Self {
        let facts = Self::read();
        tracing::info!(
            "LinuxEmu host mapping facts, fixed for the run: the kernel prints the guard \
             flag (gu): {:?}; vm.overcommit_memory: {:?}",
            facts.guard_flag_printed,
            facts.overcommit_memory,
        );
        facts
    }

    fn read() -> Self {
        #[cfg(test)]
        if let Some(facts) = TEST_HOST_VM_FACTS.with(std::cell::Cell::get) {
            return facts;
        }
        Self {
            guard_flag_printed: guard_flag_printed(),
            overcommit_memory: overcommit_memory(),
        }
    }
}

/// Makes [`HostVmFacts::capture_for_run`] read `facts` on this thread, in
/// place of the host's, until the returned guard is dropped.
#[cfg(test)]
pub(crate) fn inject_host_vm_facts(facts: HostVmFacts) -> impl Drop {
    struct Reset(Option<HostVmFacts>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_HOST_VM_FACTS.with(|cell| cell.set(self.0));
        }
    }
    Reset(TEST_HOST_VM_FACTS.with(|cell| cell.replace(Some(facts))))
}

/// How many host facts this thread has read so far.
#[cfg(test)]
pub(crate) fn host_fact_reads() -> usize {
    HOST_FACT_READS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn count_host_fact_read() {
    HOST_FACT_READS.with(|reads| reads.set(reads.get() + 1));
}

#[cfg(not(test))]
fn count_host_fact_read() {}

/// `vm.overcommit_memory`, if it reads as one of Linux's three modes.
fn overcommit_memory() -> Option<u32> {
    count_host_fact_read();
    std::fs::read_to_string("/proc/sys/vm/overcommit_memory")
        .ok()?
        .trim()
        .parse()
        .ok()
        .filter(|mode| *mode <= OVERCOMMIT_NEVER)
}

/// Whether this host's kernel prints `gu` for a mapping with a guard: see
/// [`HostVmFacts::guard_flag_printed`]. The guarded page is the middle one
/// of three, between two inaccessible pages of the same mapping, so that its
/// mapping merges with no other and the flag lands on nothing else. The
/// mapping is made and removed by the system calls themselves, not libc's
/// `mmap` and `munmap`: the probe runs inside a run (as its first task is
/// made), where an allocator the backend's process interposes on those (a
/// test's fault injector, a preloaded library) must not take the probe's
/// mapping for one of the run's own.
fn guard_flag_printed() -> Option<bool> {
    count_host_fact_read();
    const PAGE: usize = 4096;
    struct Mapping(*mut libc::c_void);
    impl Drop for Mapping {
        fn drop(&mut self) {
            // SAFETY: the mapping is this function's own, three pages long.
            unsafe { libc::syscall(libc::SYS_munmap, self.0, 3 * PAGE) };
        }
    }
    // SAFETY: a new anonymous mapping at an address the kernel chooses.
    let address = unsafe {
        libc::syscall(
            libc::SYS_mmap,
            std::ptr::null_mut::<libc::c_void>(),
            3 * PAGE,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    } as *mut libc::c_void;
    if address == libc::MAP_FAILED {
        return None;
    }
    let mapping = Mapping(address);
    // SAFETY: the middle page is part of the mapping above.
    let middle = unsafe { mapping.0.cast::<u8>().add(PAGE) }.cast::<libc::c_void>();
    // SAFETY: changes only the mapping above.
    if unsafe { libc::mprotect(middle, PAGE, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
        return None;
    }
    // SAFETY: changes only the mapping above.
    if unsafe { libc::madvise(middle, PAGE, super::mm::MADV_GUARD_INSTALL) } != 0 {
        let error = std::io::Error::last_os_error();
        return (error.raw_os_error() == Some(libc::EINVAL)).then_some(false);
    }
    let smaps = std::fs::File::open("/proc/self/smaps").ok()?;
    let flags = vm_flags_line(std::io::BufReader::new(smaps), middle as u64)?;
    drop(mapping);
    Some(flags.split_ascii_whitespace().any(|flag| flag == "gu"))
}

/// The `VmFlags` field of the mapping that starts at `start` in the `smaps`
/// text `smaps`, read only as far as that field.
fn vm_flags_line(smaps: impl BufRead, start: u64) -> Option<String> {
    let header = format!("{start:x}-");
    let mut inside = false;
    for line in smaps.lines() {
        let line = line.ok()?;
        if line.starts_with(&header) {
            inside = true;
        } else if inside && let Some(flags) = line.strip_prefix("VmFlags:") {
            return Some(flags.to_owned());
        }
    }
    None
}

/// What decides the flags of a mapping of a file, captured when the mapping
/// is made (`MappedObject::file`): Linux fixes them in `do_mmap`, from the
/// open file description and its mount as they are then, so they are read
/// then rather than when a list is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileVmFacts {
    /// The open file description may be written (`FMODE_WRITE`): a shared
    /// mapping of one that may not has neither `VM_SHARED` nor
    /// `VM_MAYWRITE` (`do_mmap`).
    pub(crate) writable: bool,
    /// The file had a write seal (`F_SEAL_WRITE` or `F_SEAL_FUTURE_WRITE`):
    /// a shared mapping of it has no `VM_MAYWRITE` (`memfd_check_seals_mmap`
    /// in `mm/memfd.c`).
    pub(crate) write_sealed: bool,
    /// The file's mount is `noexec` (`ST_NOEXEC`, which reflects
    /// `MNT_NOEXEC`; no filesystem below sets the other half of
    /// `path_noexec`, `SB_I_NOEXEC`): its mappings have no `VM_MAYEXEC`.
    pub(crate) noexec: bool,
    /// Linux makes no mapping of the file with `VM_SYNC`: the file is on
    /// ext2/3/4 or XFS, whose mmap hooks refuse it for a file that is not
    /// DAX (`ext4_file_mmap_prepare`, `xfs_file_mmap`), or on overlayfs,
    /// whose files do not offer it (`ovl_file_operations` has no
    /// `FOP_MMAP_SYNC`, without which `do_mmap` refuses `MAP_SYNC`).
    pub(crate) refuses_sync: bool,
}

/// `BTRFS_SUPER_MAGIC` (`include/uapi/linux/magic.h`).
const BTRFS_SUPER_MAGIC: i64 = 0x9123_683e;
/// `EXT2_SUPER_MAGIC`, which ext3 and ext4 share.
const EXT4_SUPER_MAGIC: i64 = 0xef53;
/// `XFS_SUPER_MAGIC`.
const XFS_SUPER_MAGIC: i64 = 0x5846_5342;
/// `TMPFS_MAGIC`, which memfds share.
const TMPFS_MAGIC: i64 = 0x0102_1994;
/// `OVERLAYFS_SUPER_MAGIC`.
const OVERLAYFS_SUPER_MAGIC: i64 = 0x794c_7630;

/// `statfs` magic numbers of the filesystems whose mmap hooks leave a
/// regular file's `vm_flags` to the generic code when the file is not DAX:
/// btrfs (`btrfs_file_mmap_prepare`), ext2/3/4 (`ext4_file_mmap_prepare`),
/// XFS (`xfs_file_mmap`) and tmpfs (`shmem_mmap_prepare`). Overlayfs runs
/// the hook of the real file of one of its layers (`ovl_mmap`), which it
/// does not show, so its files are probed instead ([`FileVmFacts::of`]).
/// Any other filesystem (hugetlbfs, whose files are regular too; FUSE and
/// the rest) is not known to.
const FLAG_NEUTRAL_FILESYSTEMS: [i64; 4] = [
    BTRFS_SUPER_MAGIC,
    EXT4_SUPER_MAGIC,
    XFS_SUPER_MAGIC,
    TMPFS_MAGIC,
];

/// One mapping of a file as the guest asked for it, as far as the file's
/// mmap hook could decide flags by it: its protection (`PROT_*` bits),
/// whether it is shared, and its page-aligned file offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MapShape {
    pub(crate) prot: u8,
    pub(crate) shared: bool,
    pub(crate) offset: u64,
}

/// The `statfs` magic number of host descriptor `fd`'s filesystem.
fn filesystem_magic(fd: libc::c_int) -> Option<i64> {
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: fstatfs writes at most one statfs, read only on success.
    if unsafe { libc::fstatfs(fd, filesystem.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: fstatfs succeeded.
    Some(unsafe { filesystem.assume_init() }.f_type)
}

/// Whether the `THPeligible` of a mapping of `file` is asked of the host
/// kernel when a list is taken (`super::host_probe::thp_eligible`): a file
/// on overlayfs, whose real layer decides it, or on tmpfs, whose mount's
/// `huge=` option and the file's size do (`shmem_allowable_huge_orders`).
pub(crate) fn thp_eligibility_is_probed(file: &std::fs::File) -> bool {
    matches!(
        filesystem_magic(file.as_raw_fd()),
        Some(OVERLAYFS_SUPER_MAGIC | TMPFS_MAGIC)
    )
}

impl FileVmFacts {
    /// The facts of mappings of `file` made now with each of `shapes`, or
    /// `None` where they are not known: a file that is not regular, one on a
    /// filesystem outside [`FLAG_NEUTRAL_FILESYSTEMS`] but overlayfs, a DAX
    /// file (on which ext4 and XFS add `VM_HUGEPAGE`), or any query that
    /// fails, but `F_GET_SEALS`'s EINVAL, which says the file takes no seals.
    ///
    /// For a file on overlayfs, the facts are those of a file whose hook
    /// adds no flag (an overlayfs file takes no seals, and its mount's
    /// `noexec` is the overlay's, which `do_mmap` checks before any hook),
    /// and each shape is probed: the host kernel maps one page of the same
    /// open file description with that shape ([`super::host_probe::probe`]),
    /// and the flags it prints must be exactly those these facts give such a
    /// mapping ([`FileVmFacts::hook_adds_no_flag`]). A hook that added a
    /// flag (a DAX layer's `VM_HUGEPAGE`), a flag this provider does not
    /// know, or a probe that fails gives `None`, as does a file on overlayfs
    /// with no shape to probe. What the hook adds is fixed when the mapping
    /// is made, so later protection changes keep the answer.
    pub(crate) fn of(file: &std::fs::File, shapes: &[MapShape]) -> Option<Self> {
        let fd = file.as_raw_fd();
        let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
        // SAFETY: fstat writes at most one stat, read only on success.
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: fstat succeeded.
        if unsafe { stat.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFREG {
            return None;
        }
        let magic = filesystem_magic(fd)?;
        let probed = magic == OVERLAYFS_SUPER_MAGIC;
        if !FLAG_NEUTRAL_FILESYSTEMS.contains(&magic) && !probed {
            return None;
        }
        let mut extended = std::mem::MaybeUninit::<libc::statx>::zeroed();
        // SAFETY: statx of the descriptor itself writes at most one statx,
        // read only on success; the path is NUL-terminated.
        if unsafe {
            libc::statx(
                fd,
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                0,
                extended.as_mut_ptr(),
            )
        } != 0
        {
            return None;
        }
        // SAFETY: statx succeeded.
        if unsafe { extended.assume_init() }.stx_attributes & libc::STATX_ATTR_DAX as u64 != 0 {
            return None;
        }
        // SAFETY: F_GETFL takes no argument.
        let status = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if status < 0 {
            return None;
        }
        // SAFETY: F_GET_SEALS takes no argument.
        let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
        let seals = if seals >= 0 {
            seals
        } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            0
        } else {
            return None;
        };
        let mut mount = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
        // SAFETY: fstatvfs writes at most one statvfs, read only on success.
        if unsafe { libc::fstatvfs(fd, mount.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: fstatvfs succeeded.
        let mount = unsafe { mount.assume_init() };
        let facts = Self {
            writable: matches!(status & libc::O_ACCMODE, libc::O_WRONLY | libc::O_RDWR),
            write_sealed: seals & (libc::F_SEAL_WRITE | libc::F_SEAL_FUTURE_WRITE) != 0,
            noexec: mount.f_flag & libc::ST_NOEXEC != 0,
            refuses_sync: matches!(
                magic,
                EXT4_SUPER_MAGIC | XFS_SUPER_MAGIC | OVERLAYFS_SUPER_MAGIC
            ),
        };
        let neutral = !probed
            || !shapes.is_empty()
                && shapes
                    .iter()
                    .all(|shape| facts.hook_adds_no_flag(file, *shape));
        neutral.then_some(facts)
    }

    /// Whether the host kernel gives a one-page mapping of `file` with
    /// `shape`, made now, exactly the flags these facts give it, as for a
    /// file whose mmap hook adds none: those of a plain mapping
    /// (`MAP_PRIVATE` or `MAP_SHARED` alone) with that protection, which
    /// `line_vm_flags` gives for its provider flags (`mm::new_mapping_flags`).
    /// The flags of the probe's mapping are its own address space's too, so
    /// any flag that space would add to every mapping (`mlockall`'s
    /// `VM_LOCKED`, `PR_SET_MEMORY_MERGE`'s `VM_MERGEABLE`) makes them
    /// differ, and the answer is no.
    fn hook_adds_no_flag(&self, file: &std::fs::File, shape: MapShape) -> bool {
        let kind = if shape.shared {
            libc::MAP_SHARED
        } else {
            libc::MAP_PRIVATE
        };
        let provider = super::mm::new_mapping_flags(
            kind as u64,
            u64::from(shape.prot),
            &HostVmFacts::UNCAPTURED,
        );
        let expected = line_vm_flags(
            shape.prot,
            provider,
            shape.shared,
            FlagBacking::File(Some(self)),
            false,
            HostVmFacts::UNCAPTURED,
        );
        expected.is_some()
            && super::host_probe::probe(
                file,
                shape.prot,
                shape.shared,
                shape.offset,
                4096,
                super::host_probe::Placement::Anywhere,
            )
            .and_then(|block| block.vm_flags)
                == expected
    }
}

impl FileVmFacts {
    /// The `vm_flags` these facts take from a mapping of the file whose
    /// provider flags are `flags` and that is shared or not: `VM_SHARED`
    /// and `VM_MAYWRITE` from a shared mapping of a description that may not
    /// be written, `VM_MAYWRITE` from a shared mapping of a write-sealed
    /// file, and `VM_MAYEXEC` on a `noexec` mount (`do_mmap`). `None` for a
    /// `MAP_SYNC` mapping of a file whose filesystem refuses it, which Linux
    /// never makes.
    pub(crate) fn cleared_flags(&self, flags: u16, shared: bool) -> Option<u64> {
        if flags & FLAG_SYNC != 0 && self.refuses_sync {
            return None;
        }
        let mut cleared = 0;
        if shared && !self.writable {
            cleared |= VM_SHARED | VM_MAYWRITE;
        }
        if shared && self.write_sealed {
            cleared |= VM_MAYWRITE;
        }
        if self.noexec {
            cleared |= VM_MAYEXEC;
        }
        Some(cleared)
    }
}

/// Whether two adjacent mappings of a file, otherwise one mapping (the same
/// description at contiguous offsets, with the same protection, provider
/// flags `flags`, and sharing `shared`), whose facts were captured as
/// `first` and `second` when each was made, have flags known to differ:
/// Linux merges no two mappings whose flags differ but for the sticky ones
/// (`is_mergeable_vma` in `mm/vma.c`), and the facts of a file can change
/// between two mmaps of it (an owner of the file may seal it). Facts that
/// are not known do not keep the mappings apart; the merged line's facts
/// are then not known either (`mapping_list`).
pub(crate) fn file_flags_differ(
    first: Option<&FileVmFacts>,
    second: Option<&FileVmFacts>,
    flags: u16,
    shared: bool,
) -> bool {
    match (first, second) {
        (Some(first), Some(second)) => {
            first.cleared_flags(flags, shared) != second.cleared_flags(flags, shared)
        }
        _ => false,
    }
}

/// What backs a line, as far as its flags go.
#[derive(Clone, Copy, Debug)]
pub(crate) enum FlagBacking<'a> {
    /// Private anonymous memory outside the stack window (`vma_is_anonymous`).
    Anonymous,
    /// A mapping of the stack window: the stack Linux made at exec
    /// (`VM_STACK_FLAGS`: `VM_GROWSDOWN` and `VM_ACCOUNT`), or a part split
    /// from it.
    StackWindow,
    /// `MAP_SHARED | MAP_ANONYMOUS` memory, which Linux backs with a shmem
    /// file of its own.
    SharedAnonymous,
    /// A file, with the facts captured when it was mapped (`None`: not
    /// known).
    File(Option<&'a FileVmFacts>),
}

/// Linux's `vm_flags` for a line whose pages have protection `prot`, carry
/// the provider flags `flags` (`DeclaredMapping::flags`, with the bits that
/// stick to a merged mapping gathered over all its pages), are shared or
/// not, and are backed by `backing`, in an address space with the
/// `READ_IMPLIES_EXEC` personality or not; for a host whose facts are
/// `host`.
///
/// `None` where a bit is not known: a `MAP_HUGETLB` mapping (Linux's has huge
/// pages and `VM_HUGETLB`, which this provider's 4 KiB pages are not); a
/// private anonymous line that may have lost `VM_ACCOUNT` (`mprotect_fixup`
/// takes it back from one with no `anon_vma`, which no page records); a line
/// with a guard when the host's `gu` is not known, or with
/// `MAP_NORESERVE` when the overcommit mode is not; a line that is both
/// locked and guarded, which Linux never makes (it refuses a guard over a
/// locked mapping, `is_valid_guard_vma`, where this provider installs it);
/// a file whose facts are not known, and a `MAP_SYNC` mapping of a file on
/// ext4 or XFS, which those refuse; and anything under `READ_IMPLIES_EXEC`.
pub(crate) fn line_vm_flags(
    prot: u8,
    flags: u16,
    shared: bool,
    backing: FlagBacking<'_>,
    read_implies_exec: bool,
    host: HostVmFacts,
) -> Option<u64> {
    let unknown = read_implies_exec
        || flags & FLAG_HUGETLB != 0
        || flags & FLAG_ACCOUNT_UNKNOWN != 0
            && matches!(backing, FlagBacking::Anonymous | FlagBacking::StackWindow)
        || flags & FLAG_MAYBE_GUARD != 0 && host.guard_flag_printed.is_none()
        || flags & FLAG_NORESERVE != 0 && host.overcommit_memory.is_none()
        || flags & FLAG_LOCKED != 0 && flags & FLAG_MAYBE_GUARD != 0;
    if unknown {
        return None;
    }
    let prot = libc::c_int::from(prot);
    let mut vm = VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;
    for (bit, flag) in [
        (libc::PROT_READ, VM_READ),
        (libc::PROT_WRITE, VM_WRITE),
        (libc::PROT_EXEC, VM_EXEC),
    ] {
        if prot & bit != 0 {
            vm |= flag;
        }
    }
    for (bit, flag) in [
        (FLAG_RANDOM, VM_RAND_READ),
        (FLAG_SEQUENTIAL, VM_SEQ_READ),
        (FLAG_HUGEPAGE, VM_HUGEPAGE),
        (FLAG_NOHUGEPAGE, VM_NOHUGEPAGE),
        (FLAG_MERGEABLE, VM_MERGEABLE),
        (FLAG_ACCOUNT, VM_ACCOUNT),
        (FLAG_NORESERVE, VM_NORESERVE),
        (FLAG_GROWSDOWN, VM_GROWSDOWN),
        (FLAG_LOCKED, VM_LOCKED),
        (FLAG_SYNC, VM_SYNC),
    ] {
        if flags & bit != 0 {
            vm |= flag;
        }
    }
    if flags & FLAG_MAYBE_GUARD != 0 && host.guard_flag_printed == Some(true) {
        vm |= VM_MAYBE_GUARD;
    }
    if shared {
        vm |= VM_SHARED | VM_MAYSHARE;
    }
    match backing {
        FlagBacking::Anonymous | FlagBacking::SharedAnonymous => {}
        FlagBacking::StackWindow => vm |= VM_GROWSDOWN | VM_ACCOUNT,
        FlagBacking::File(facts) => vm &= !facts?.cleared_flags(flags, shared)?,
    }
    Some(vm)
}

/// The name `show_smap_vma_flags` prints in `VmFlags` for each flag this
/// provider reports (`reverie::VM_KNOWN_FLAGS`), in the order of its bit.
pub(crate) const VM_FLAG_NAMES: [(u64, &str); 19] = [
    (VM_READ, "rd"),
    (VM_WRITE, "wr"),
    (VM_EXEC, "ex"),
    (VM_SHARED, "sh"),
    (VM_MAYREAD, "mr"),
    (VM_MAYWRITE, "mw"),
    (VM_MAYEXEC, "me"),
    (VM_MAYSHARE, "ms"),
    (VM_GROWSDOWN, "gd"),
    (VM_MAYBE_GUARD, "gu"),
    (VM_LOCKED, "lo"),
    (VM_SEQ_READ, "sr"),
    (VM_RAND_READ, "rr"),
    (VM_ACCOUNT, "ac"),
    (VM_NORESERVE, "nr"),
    (VM_SYNC, "sf"),
    (VM_HUGEPAGE, "hg"),
    (VM_NOHUGEPAGE, "nh"),
    (VM_MERGEABLE, "mg"),
];

/// The flags the names of a `VmFlags` field, `names`, stand for, or `None`
/// where one is not in [`VM_FLAG_NAMES`] (such as `sd`, `VM_SOFTDIRTY`,
/// which this provider does not report).
pub(crate) fn parse_vm_flags(names: &[u8]) -> Option<u64> {
    names
        .split(u8::is_ascii_whitespace)
        .filter(|name| !name.is_empty())
        .try_fold(0, |flags, name| {
            VM_FLAG_NAMES
                .iter()
                .find(|(_, known)| known.as_bytes() == name)
                .map(|(bit, _)| flags | bit)
        })
}

/// `VmFlags` text, as `show_smap_vma_flags` prints it, for `vm`.
#[cfg(test)]
pub(crate) fn mnemonics(vm: Option<u64>) -> Option<String> {
    let vm = vm?;
    assert_eq!(vm & !reverie::VM_KNOWN_FLAGS, 0);
    Some(
        VM_FLAG_NAMES
            .iter()
            .filter(|(bit, _)| vm & bit != 0)
            .map(|(_, name)| *name)
            .collect::<Vec<_>>()
            .join(" "),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: u8 = libc::PROT_READ as u8;
    const RW: u8 = (libc::PROT_READ | libc::PROT_WRITE) as u8;
    const RX: u8 = (libc::PROT_READ | libc::PROT_EXEC) as u8;
    const KNOWN: HostVmFacts = HostVmFacts {
        guard_flag_printed: Some(true),
        overcommit_memory: Some(0),
    };
    const PLAIN_FILE: FileVmFacts = FileVmFacts {
        writable: true,
        write_sealed: false,
        noexec: false,
        refuses_sync: false,
    };

    fn flags(prot: u8, flags: u16, shared: bool, backing: FlagBacking<'_>) -> Option<String> {
        mnemonics(line_vm_flags(prot, flags, shared, backing, false, KNOWN))
    }

    /// Each line's flags are the `VmFlags` Linux 7.1.3 printed for the same
    /// mapping (the design's host probes of dh-9j8ue: `probe/vmflags.py`,
    /// `tmp/probe2.py`, `tmp/probe3.py`; and `impl/probe/sealed.py` for the
    /// sealed memfd), from the provider flags the mapping's calls leave on
    /// its pages.
    #[test]
    fn line_flags_are_linuxs_for_each_probed_mapping() {
        use FlagBacking::*;
        let read_only = FileVmFacts {
            writable: false,
            ..PLAIN_FILE
        };
        let sealed = FileVmFacts {
            write_sealed: true,
            ..PLAIN_FILE
        };
        let noexec = FileVmFacts {
            noexec: true,
            ..PLAIN_FILE
        };
        let cases: [(&str, Option<String>, &str); 20] = [
            (
                "anon rw",
                flags(RW, FLAG_ACCOUNT, false, Anonymous),
                "rd wr mr mw me ac",
            ),
            (
                "MAP_GROWSDOWN",
                flags(RW, FLAG_ACCOUNT | FLAG_GROWSDOWN, false, Anonymous),
                "rd wr mr mw me gd ac",
            ),
            (
                "MAP_LOCKED",
                flags(RW, FLAG_ACCOUNT | FLAG_LOCKED, false, Anonymous),
                "rd wr mr mw me lo ac",
            ),
            (
                "MAP_STACK",
                flags(RW, FLAG_ACCOUNT | FLAG_NOHUGEPAGE, false, Anonymous),
                "rd wr mr mw me ac nh",
            ),
            (
                "MAP_SYNC anonymous",
                flags(RW, FLAG_ACCOUNT | FLAG_SYNC, false, Anonymous),
                "rd wr mr mw me ac sf",
            ),
            (
                "MAP_SYNC btrfs private",
                flags(RW, FLAG_ACCOUNT | FLAG_SYNC, false, File(Some(&PLAIN_FILE))),
                "rd wr mr mw me ac sf",
            ),
            (
                "MAP_SYNC tmpfs shared",
                flags(RW, FLAG_SYNC, true, File(Some(&PLAIN_FILE))),
                "rd wr sh mr mw me ms sf",
            ),
            (
                "MAP_NORESERVE anon rw",
                flags(RW, FLAG_NORESERVE, false, Anonymous),
                "rd wr mr mw me nr",
            ),
            (
                "private file rw, unwritten, then r",
                flags(
                    R,
                    FLAG_ACCOUNT | FLAG_ACCOUNT_UNKNOWN,
                    false,
                    File(Some(&PLAIN_FILE)),
                ),
                "rd mr mw me ac",
            ),
            (
                "guarded anon rw, unwritten, then r",
                flags(R, FLAG_ACCOUNT | FLAG_MAYBE_GUARD, false, Anonymous),
                "rd mr mw me gu ac",
            ),
            (
                "MAP_LOCKED page in a fork child",
                flags(RW, FLAG_ACCOUNT, false, Anonymous),
                "rd wr mr mw me ac",
            ),
            (
                "shared file O_RDONLY",
                flags(R, 0, true, File(Some(&read_only))),
                "rd mr me ms",
            ),
            (
                "shared file O_RDWR",
                flags(RW, 0, true, File(Some(&PLAIN_FILE))),
                "rd wr sh mr mw me ms",
            ),
            (
                "shared anon",
                flags(RW, 0, true, SharedAnonymous),
                "rd wr sh mr mw me ms",
            ),
            (
                "private file r",
                flags(R, 0, false, File(Some(&read_only))),
                "rd mr mw me",
            ),
            // `impl/probe/sealed.py`: a memfd opened O_RDWR, sealed with
            // F_SEAL_WRITE or F_SEAL_FUTURE_WRITE, then mapped shared.
            (
                "write-sealed memfd, shared, read-only",
                flags(R, 0, true, File(Some(&sealed))),
                "rd sh mr me ms",
            ),
            (
                "noexec tmpfs private r",
                flags(R, 0, false, File(Some(&noexec))),
                "rd mr mw",
            ),
            (
                "noexec tmpfs shared rw",
                flags(RW, 0, true, File(Some(&noexec))),
                "rd wr sh mr mw ms",
            ),
            (
                "the exec stack",
                flags(RW, 0, false, StackWindow),
                "rd wr mr mw me gd ac",
            ),
            (
                "an ELF text segment",
                flags(RX, 0, false, File(Some(&read_only))),
                "rd ex mr mw me",
            ),
        ];
        for (what, ours, linux) in cases {
            assert_eq!(ours.as_deref(), Some(linux), "{what}");
        }
    }

    /// The lines whose flags are not established have none, by name.
    #[test]
    fn lines_with_a_bit_not_known_have_no_flags() {
        use FlagBacking::*;
        let none = |what: &str, vm: Option<u64>| assert_eq!(vm, None, "{what}");
        let line = |prot, flags, shared, backing| {
            line_vm_flags(prot, flags, shared, backing, false, KNOWN)
        };
        none(
            "MAP_HUGETLB",
            line(RW, FLAG_HUGETLB | FLAG_NORESERVE, false, Anonymous),
        );
        // `rd mr mw me` natively, or `rd mr mw me ac` once a page was
        // written: the pages do not say which.
        none(
            "anon rw, then r",
            line(R, FLAG_ACCOUNT | FLAG_ACCOUNT_UNKNOWN, false, Anonymous),
        );
        none("a file not known", line(R, 0, false, File(None)));
        let ext4 = FileVmFacts {
            refuses_sync: true,
            ..PLAIN_FILE
        };
        none(
            "MAP_SYNC on ext4",
            line(RW, FLAG_SYNC | FLAG_ACCOUNT, false, File(Some(&ext4))),
        );
        assert!(line(RW, FLAG_ACCOUNT, false, File(Some(&ext4))).is_some());
        none(
            "locked and guarded",
            line(
                RW,
                FLAG_LOCKED | FLAG_MAYBE_GUARD | FLAG_ACCOUNT,
                false,
                Anonymous,
            ),
        );
        none(
            "READ_IMPLIES_EXEC",
            line_vm_flags(RW, FLAG_ACCOUNT, false, Anonymous, true, KNOWN),
        );
        let unknown_host = HostVmFacts {
            guard_flag_printed: None,
            overcommit_memory: None,
        };
        none(
            "a guard on a host whose gu is not known",
            line_vm_flags(
                RW,
                FLAG_MAYBE_GUARD | FLAG_ACCOUNT,
                false,
                Anonymous,
                false,
                unknown_host,
            ),
        );
        none(
            "MAP_NORESERVE with the overcommit mode not known",
            line_vm_flags(RW, FLAG_NORESERVE, false, Anonymous, false, unknown_host),
        );
        assert!(
            line_vm_flags(RW, FLAG_ACCOUNT, false, Anonymous, false, unknown_host).is_some(),
            "neither fact matters to a plain line"
        );
        // A host that prints no `gu` (before 6.18): the guard leaves no flag.
        let older = HostVmFacts {
            guard_flag_printed: Some(false),
            ..KNOWN
        };
        assert_eq!(
            mnemonics(line_vm_flags(
                R,
                FLAG_MAYBE_GUARD | FLAG_ACCOUNT,
                false,
                Anonymous,
                false,
                older
            ))
            .as_deref(),
            Some("rd mr mw me ac")
        );
    }

    /// The host's facts read from this host: a mode Linux has, and a guard
    /// answer; the `smaps` reader finds the named mapping's field.
    #[test]
    fn the_host_facts_read_from_this_host() {
        assert!(overcommit_memory().is_some_and(|mode| mode <= OVERCOMMIT_NEVER));
        assert!(guard_flag_printed().is_some());
        let text = "1000-2000 rw-p 00000000 00:00 0\nVmFlags: rd wr\n\
                    2000-3000 rw-p 00000000 00:00 0\nSize: 4 kB\nVmFlags: rd wr gu\n";
        assert_eq!(
            vm_flags_line(text.as_bytes(), 0x2000).as_deref(),
            Some(" rd wr gu")
        );
        assert_eq!(vm_flags_line(text.as_bytes(), 0x3000), None);
    }

    /// A file's facts are captured from the file: a regular file on this
    /// host's filesystem opened read-only, and a sealed memfd; a pipe is not
    /// known.
    #[test]
    fn file_facts_come_from_the_file() {
        let directory =
            std::env::temp_dir().join(format!("reverie-linuxemu-vm-flags-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("file");
        std::fs::write(&path, [0u8; 4096]).unwrap();
        let read_only = std::fs::File::open(&path).unwrap();
        let memfd = {
            // SAFETY: a new memfd this test owns.
            let fd = unsafe { libc::memfd_create(c"vm-flags".as_ptr(), libc::MFD_ALLOW_SEALING) };
            assert!(fd >= 0);
            // SAFETY: memfd_create returned a new descriptor.
            unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) }
        };
        // SAFETY: fcntl on a descriptor this test owns.
        assert_eq!(
            unsafe { libc::fcntl(memfd.as_raw_fd(), libc::F_ADD_SEALS, libc::F_SEAL_WRITE) },
            0
        );
        let mut pipe = [0; 2];
        // SAFETY: pipe writes two descriptors.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        // SAFETY: the pipe's descriptors are this test's.
        let (pipe_read, _pipe_write) = unsafe {
            use std::os::fd::FromRawFd;
            (
                std::fs::File::from_raw_fd(pipe[0]),
                std::fs::File::from_raw_fd(pipe[1]),
            )
        };
        let memfd_facts = FileVmFacts::of(&memfd, &[]).unwrap();
        assert_eq!(
            memfd_facts,
            FileVmFacts {
                writable: true,
                write_sealed: true,
                noexec: false,
                refuses_sync: false,
            }
        );
        assert_eq!(FileVmFacts::of(&pipe_read, &[]), None);
        // A regular file of a filesystem outside the list (procfs, whose
        // files are regular in fstat) has no facts.
        let proc_file = std::fs::File::open("/proc/self/status").unwrap();
        assert_eq!(FileVmFacts::of(&proc_file, &[]), None);
        // The temporary directory's filesystem may be outside the list.
        if let Some(facts) = FileVmFacts::of(&read_only, &[]) {
            assert!(!facts.writable && !facts.write_sealed);
        }
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
