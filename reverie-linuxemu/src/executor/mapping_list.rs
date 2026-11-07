/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A process's mappings as Linux lists them in `/proc/<pid>/maps`
//! (`reverie::Guest::memory_map`): what each mapping maps
//! ([`MappedObject`]), given to the guest memory when the mapping is placed,
//! and the list built from the memory's pages ([`list_mappings`]).
//!
//! The guest memory keeps pages, not mappings
//! (`GuestMemory::user_mapping_runs`): each page's declared protection and
//! flags, its file offset, whether it is shared, and the identity of what
//! the mapping that placed it maps, which follows the page through a move,
//! a fork's copy and a protection change. This module decides, from those
//! pages, the lines Linux prints. Linux keeps one `vm_area_struct` per
//! mapping and merges two adjacent ones when their flags, file, file offsets
//! and name agree, and, for anonymous memory, their `anon_vma`
//! (`is_mergeable_vma` and `is_mergeable_anon_vma` in `mm/vma.c`). Adjacent
//! pages here make one line when their protection and provider flags agree,
//! both or neither are shared, and they map nothing, or the same open file
//! (one `struct file`: the same description, `kcmp(2)`'s `KCMP_FILE`) at
//! contiguous offsets, or the same shared anonymous object at contiguous
//! offsets.
//!
//! Two flags stick to a merged mapping rather than keep it apart
//! ([`STICKY_FLAGS`]): a line has one if any of its pages has it.
//!
//! Each line reports Linux's `vm_flags` where they are established
//! (`super::vm_flags::line_vm_flags`).
//!
//! Where that differs from Linux, the difference is Linux's history of
//! `anon_vma`s, which no page holds: two private anonymous mappings that
//! each took an `anon_vma` of its own, by a write fault, before a call made
//! them adjacent with equal protection stay two lines on Linux and are one
//! here. In the stack window the lineage the executor keeps for a fork's
//! inherited mappings (`ElfExecutor::keep_inherited_stack_mappings_apart`)
//! keeps those apart as Linux does.
//!
//! The list is complete, or it says it is not: a page whose mapping is not
//! known (no declared protection, or a file page with no identity) is left
//! out with every line that touches it, which may be part of the same
//! mapping, and the list is marked incomplete, so that each line it gives is
//! exact and no reader sees part of the address space as all of it. In the
//! stack window one such page still empties the whole list
//! (`ElfExecutor::memory_map`). The backend's own pages (bootstrap, program
//! headers, Tool scratch, and the inaccessible range kept where the host's
//! vDSO lies, [`MappedObject::Hidden`]) are not the guest's mappings and are
//! not listed. The kernel's own mappings are not listed either, because this
//! backend gives the guest none: no `[vdso]`, `[vvar]` or `[vsyscall]`, as
//! Linux lists none for a kernel booted with `vdso=0` and `vsyscall=none`.

use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use super::mm::FLAG_ACCOUNT_UNKNOWN;
use super::mm::FLAG_MAYBE_GUARD;
use super::vm_flags::FileVmFacts;
use super::vm_flags::FlagBacking;
use crate::GuestMemory;
use crate::memory::DeclaredMapping;
use crate::memory::MappingIdentity;
use crate::memory::USER_STACK_TOP;
use crate::memory::UserMappingRun;

/// The provider flags that stick to a merged mapping instead of keeping it
/// apart (`DeclaredMapping::flags`): two lines that differ only in these
/// merge, and the line has each if any of its pages has it. Linux's
/// `VM_MAYBE_GUARD` is sticky (`VMA_STICKY_FLAGS`); `FLAG_ACCOUNT_UNKNOWN`
/// is no flag of Linux's, only a doubt about `VM_ACCOUNT`, which the pages
/// keep, so the lines stay as they were without it.
pub(crate) const STICKY_FLAGS: u16 = FLAG_ACCOUNT_UNKNOWN | FLAG_MAYBE_GUARD;

/// What a mapping maps, as Linux names it in `maps`
/// ([`crate::memory::MappingIdentity`] holds one).
pub(crate) enum MappedObject {
    /// A file, mapped through one open file description: the host file the
    /// guest's descriptor stands for, kept open as Linux's mapping keeps its
    /// `struct file`. Its name is read when the list is, so that it is the
    /// file's name then (`d_path`, ` (deleted)` included).
    File {
        file: Arc<std::fs::File>,
        /// The superblock's device (`i_sb->s_dev`), as Linux prints it.
        raw_device: u64,
        raw_inode: u64,
        /// What decides the mapping's flags, as it was when the mapping was
        /// made (`None`: not known).
        vm_facts: Option<FileVmFacts>,
    },
    /// `MAP_SHARED | MAP_ANONYMOUS` memory, which Linux backs with a shmem
    /// file of its own named `/dev/zero (deleted)` (`shmem_zero_setup`). The
    /// device and inode are those of a host shmem file made for the mapping
    /// and kept open while it is, so they name one object, as the kernel's
    /// do, for the mapping and every copy a fork makes.
    SharedAnonymous {
        _object: std::fs::File,
        raw_device: u64,
        raw_inode: u64,
        /// The user address the mapping was made at, from which each page's
        /// offset in the object is its distance.
        origin: u64,
        /// Set once part of the mapping moved (`mremap(2)`), after which a
        /// page's distance from `origin` is no longer its offset.
        moved: AtomicBool,
    },
    /// Pages this backend keeps for itself that Linux does not map.
    Hidden,
}

impl MappedObject {
    /// The identity of a mapping of `file` made now, or `None` where the
    /// host cannot describe the file. It holds the facts that decide the
    /// mapping's flags, read now, as Linux fixes them when it maps the file
    /// ([`FileVmFacts::of`]).
    pub(crate) fn file(file: &Arc<std::fs::File>) -> Option<MappingIdentity> {
        let (st_dev, raw_inode) = fstat_identity(file.as_raw_fd())?;
        let raw_device = superblock_device(file.as_raw_fd()).unwrap_or(st_dev);
        Some(MappingIdentity::new(MappedObject::File {
            file: file.clone(),
            raw_device,
            raw_inode,
            vm_facts: FileVmFacts::of(file),
        }))
    }

    /// The identity of a mapping of the host file `file` holds, through a
    /// descriptor of its own for the same open file description.
    pub(crate) fn file_from(file: &std::fs::File) -> Option<MappingIdentity> {
        Self::file(&Arc::new(file.try_clone().ok()?))
    }

    /// The identity of a new `MAP_SHARED | MAP_ANONYMOUS` mapping made at
    /// user address `origin`, or `None` where the host cannot make its
    /// object.
    pub(crate) fn shared_anonymous(origin: u64) -> Option<MappingIdentity> {
        // SAFETY: the name is NUL-terminated; the result is checked.
        let fd = unsafe { libc::memfd_create(c"dev/zero".as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return None;
        }
        // SAFETY: memfd_create returned a new descriptor this owns.
        let object = unsafe { std::fs::File::from_raw_fd(fd) };
        let (raw_device, raw_inode) = fstat_identity(object.as_raw_fd())?;
        Some(MappingIdentity::new(MappedObject::SharedAnonymous {
            _object: object,
            raw_device,
            raw_inode,
            origin,
            moved: AtomicBool::new(false),
        }))
    }

    /// The identity of pages this backend keeps for itself.
    pub(crate) fn hidden() -> MappingIdentity {
        MappingIdentity::new(MappedObject::Hidden)
    }

    /// Notes that part of a shared anonymous mapping moved, so that its
    /// pages' offsets are no longer known.
    pub(crate) fn note_moved(identity: &MappingIdentity) {
        if let Some(MappedObject::SharedAnonymous { moved, .. }) = identity.downcast_ref() {
            moved.store(true, Ordering::Relaxed);
        }
    }
}

/// The device and inode `fstat(2)` gives host descriptor `fd`.
fn fstat_identity(fd: libc::c_int) -> Option<(u64, u64)> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: fstat writes at most one stat, read only on success.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: fstat succeeded.
    let stat = unsafe { stat.assume_init() };
    Some((stat.st_dev, stat.st_ino))
}

/// The device number of the superblock of host descriptor `fd`'s file, which
/// Linux prints in `maps` (`i_sb->s_dev`) and which need not be the file's
/// `st_dev` (btrfs gives each subvolume one of its own): the `major:minor`
/// field of the supervisor's `mountinfo` line for the descriptor's mount.
/// `None` where the mount is not in the supervisor's namespace (an internal
/// one, such as a memfd's), whose files' `st_dev` is the superblock's.
fn superblock_device(fd: libc::c_int) -> Option<u64> {
    let fdinfo = read_small(&format!("/proc/self/fdinfo/{fd}"))?;
    let mount = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))?
        .trim()
        .to_owned();
    let mountinfo = read_small("/proc/self/mountinfo")?;
    let device = mountinfo.lines().find_map(|line| {
        let mut fields = line.split(' ');
        (fields.next()? == mount).then(|| fields.nth(1))?
    })?;
    let (major, minor) = device.split_once(':')?;
    Some(libc::makedev(major.parse().ok()?, minor.parse().ok()?))
}

/// The text of a small procfs file of the supervisor's own.
fn read_small(path: &str) -> Option<String> {
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(16 * 1024 * 1024)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

/// The name `maps` prints for the file host descriptor `fd` holds: the
/// supervisor's `readlink` of its own `/proc/self/fd/<fd>` (`d_path`'s text,
/// ` (deleted)` included), with each newline written as `\012`, as
/// `seq_path` writes it.
fn file_name(fd: libc::c_int) -> Option<Vec<u8>> {
    let path = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
    let mut name = Vec::new();
    for byte in path.as_os_str().as_bytes() {
        if *byte == b'\n' {
            name.extend_from_slice(b"\\012");
        } else {
            name.push(*byte);
        }
    }
    (!name.is_empty()).then_some(name)
}

/// Whether host descriptors `a` and `b` are one open file description.
fn same_description(a: &std::fs::File, b: &std::fs::File) -> bool {
    const KCMP_FILE: libc::c_int = 0;
    // SAFETY: getpid has no preconditions.
    let pid = unsafe { libc::getpid() };
    // SAFETY: kcmp reads no memory of this process.
    unsafe {
        libc::syscall(
            libc::SYS_kcmp,
            pid,
            pid,
            KCMP_FILE,
            a.as_raw_fd() as libc::c_ulong,
            b.as_raw_fd() as libc::c_ulong,
        ) == 0
    }
}

/// What a process's image fixed that its list reads: where its first
/// thread's stack started (`mm->start_stack`), where its program break
/// started (`mm->start_brk`), and whether it runs with the
/// `READ_IMPLIES_EXEC` personality.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ImageMapFacts {
    pub(crate) start_stack: u64,
    pub(crate) start_brk: u64,
    pub(crate) read_implies_exec: bool,
    /// The host's facts the run captured (`LoadedStaticElf::host_vm_facts`).
    pub(crate) host: super::vm_flags::HostVmFacts,
}

impl ImageMapFacts {
    pub(crate) fn of(state: &crate::elf::LoadedStaticElf) -> Self {
        Self {
            start_stack: state.stack_pointer,
            start_brk: state.mm.heap_base,
            read_implies_exec: state.linux_personality & super::facts::READ_IMPLIES_EXEC != 0,
            host: state.host_vm_facts,
        }
    }
}

/// What one line maps.
enum LineBacking {
    Anonymous,
    File {
        file: Arc<std::fs::File>,
        raw_device: u64,
        raw_inode: u64,
        offset: u64,
        vm_facts: Option<FileVmFacts>,
    },
    SharedAnonymous {
        identity: MappingIdentity,
        raw_device: u64,
        raw_inode: u64,
        offset: u64,
    },
}

/// One line being built from runs of pages.
struct Line {
    start: u64,
    end: u64,
    /// The first run's declared mapping; every run of the line has the same
    /// but for [`STICKY_FLAGS`].
    declared: DeclaredMapping,
    /// The [`STICKY_FLAGS`] any run of the line has.
    sticky: u16,
    /// The [`STICKY_FLAGS`] every run of the line has.
    sticky_everywhere: u16,
    shared: bool,
    backing: LineBacking,
}

impl Line {
    /// The line of `run`: `Ok(None)` for the backend's own pages, `Err(())`
    /// for pages whose mapping is not known.
    fn of(run: &UserMappingRun) -> Result<Option<Self>, ()> {
        let object = run
            .identity
            .as_ref()
            .and_then(MappingIdentity::downcast_ref::<MappedObject>);
        if matches!(object, Some(MappedObject::Hidden)) {
            return Ok(None);
        }
        let declared = run.declared.ok_or(())?;
        let backing = match (object, run.file_offset, run.shared_anonymous) {
            (
                Some(MappedObject::File {
                    file,
                    raw_device,
                    raw_inode,
                    vm_facts,
                }),
                Some(offset),
                false,
            ) => LineBacking::File {
                file: file.clone(),
                raw_device: *raw_device,
                raw_inode: *raw_inode,
                offset,
                vm_facts: *vm_facts,
            },
            (
                Some(MappedObject::SharedAnonymous {
                    raw_device,
                    raw_inode,
                    origin,
                    moved,
                    ..
                }),
                None,
                true,
            ) if !moved.load(Ordering::Relaxed) && run.start >= *origin => {
                LineBacking::SharedAnonymous {
                    identity: run.identity.clone().ok_or(())?,
                    raw_device: *raw_device,
                    raw_inode: *raw_inode,
                    offset: run.start - origin,
                }
            }
            (None, None, false) if !run.shared_file => LineBacking::Anonymous,
            _ => return Err(()),
        };
        let shared = run.shared_file || run.shared_anonymous;
        Ok(Some(Self {
            start: run.start,
            end: run.end,
            declared,
            sticky: declared.flags & STICKY_FLAGS,
            sticky_everywhere: declared.flags & STICKY_FLAGS,
            shared,
            backing,
        }))
    }

    /// Adds `next`, which [`Line::merges_with`] this line, to it. A file
    /// line's facts stay known only while every part's are: those of the
    /// parts with known facts agree on the flags (`merges_with`), and a part
    /// whose facts are not known makes the whole line's not known, so that
    /// no part's flags are reported from another's facts.
    fn absorb(&mut self, next: &Line) {
        self.end = next.end;
        self.sticky |= next.sticky;
        self.sticky_everywhere &= next.sticky_everywhere;
        if let (
            LineBacking::File { vm_facts, .. },
            LineBacking::File {
                vm_facts: next_facts,
                ..
            },
        ) = (&mut self.backing, &next.backing)
            && next_facts.is_none()
        {
            *vm_facts = None;
        }
    }

    /// Whether `next`, which starts where this line ends, is part of the same
    /// mapping on Linux (see the module documentation).
    fn merges_with(&self, next: &Line) -> bool {
        let length = self.end - self.start;
        let unsticky = |declared: DeclaredMapping| DeclaredMapping {
            flags: declared.flags & !STICKY_FLAGS,
            ..declared
        };
        self.end == next.start
            && unsticky(self.declared) == unsticky(next.declared)
            && self.shared == next.shared
            && match (&self.backing, &next.backing) {
                (LineBacking::Anonymous, LineBacking::Anonymous) => true,
                (
                    LineBacking::File {
                        file,
                        offset,
                        vm_facts,
                        ..
                    },
                    LineBacking::File {
                        file: next_file,
                        offset: next_offset,
                        vm_facts: next_facts,
                        ..
                    },
                ) => {
                    offset.checked_add(length) == Some(*next_offset)
                        && (Arc::ptr_eq(file, next_file) || same_description(file, next_file))
                        && !super::vm_flags::file_flags_differ(
                            vm_facts.as_ref(),
                            next_facts.as_ref(),
                            self.declared.flags & !STICKY_FLAGS,
                            self.shared,
                        )
                }
                (
                    LineBacking::SharedAnonymous {
                        identity, offset, ..
                    },
                    LineBacking::SharedAnonymous {
                        identity: next_identity,
                        offset: next_offset,
                        ..
                    },
                ) => {
                    identity.same(next_identity) && offset.checked_add(length) == Some(*next_offset)
                }
                _ => false,
            }
    }

    /// The line as Linux prints it, for an address space whose program break
    /// is `brk` and whose image fixed `image`, with Linux's `vm_flags` where
    /// they are established.
    fn fact(
        self,
        image: &ImageMapFacts,
        brk: u64,
    ) -> Result<reverie::MappingFact, reverie::FactError> {
        let flag_backing = match &self.backing {
            LineBacking::Anonymous => FlagBacking::Anonymous,
            LineBacking::File { vm_facts, .. } => FlagBacking::File(vm_facts.as_ref()),
            LineBacking::SharedAnonymous { .. } => FlagBacking::SharedAnonymous,
        };
        let vm_flags = super::vm_flags::line_vm_flags(
            self.declared.prot,
            self.declared.flags | self.sticky,
            self.shared,
            flag_backing,
            image.read_implies_exec,
            image.host,
        );
        let (offset, backing) = match self.backing {
            LineBacking::Anonymous => {
                // `vma_is_initial_heap`, which Linux tests before the stack.
                let backing = if self.start < brk && self.end > image.start_brk {
                    reverie::MappingBacking::Heap
                } else if self.start <= image.start_stack && self.end >= image.start_stack {
                    reverie::MappingBacking::Stack
                } else {
                    reverie::MappingBacking::Anonymous
                };
                (0, backing)
            }
            LineBacking::File {
                file,
                raw_device,
                raw_inode,
                offset,
                ..
            } => (
                offset,
                reverie::MappingBacking::File {
                    raw_device,
                    raw_inode,
                    path: file_name(file.as_raw_fd()).ok_or(reverie::FactError::NotProvided)?,
                },
            ),
            LineBacking::SharedAnonymous {
                raw_device,
                raw_inode,
                offset,
                ..
            } => (
                offset,
                reverie::MappingBacking::File {
                    raw_device,
                    raw_inode,
                    path: b"/dev/zero (deleted)".to_vec(),
                },
            ),
        };
        let fact = reverie::MappingFact::new(
            self.start,
            self.end,
            u32::from(self.declared.prot),
            self.shared,
            offset,
            backing,
        )?;
        Ok(with_vm_flags(fact, vm_flags))
    }
}

/// `fact` with `vm_flags`, where they are given and are a set Linux can
/// print for it; otherwise `fact` as it is, with none. A set Linux cannot
/// print (such as `VM_EXEC` without `VM_MAYEXEC`, which a protection change
/// this backend allows and Linux refuses can leave) is not established.
pub(super) fn with_vm_flags(
    fact: reverie::MappingFact,
    vm_flags: Option<u64>,
) -> reverie::MappingFact {
    match vm_flags {
        Some(vm_flags) => fact.clone().with_vm_flags(vm_flags).unwrap_or(fact),
        None => fact,
    }
}

/// The mappings of the address space `memory`, whose image fixed `image`, as
/// Linux lists them: complete, or incomplete where some page's mapping is not
/// known (see the module documentation). An incomplete list leaves out the
/// pages whose mapping is not known and every line that touches them, which
/// may be part of the same mapping, so each line it lists is exact. The stack window's
/// mappings are the executor's (`ElfExecutor::memory_map`); every other run
/// of pages is read from the memory under one acquisition of its lock.
pub(crate) fn list_mappings(
    memory: &GuestMemory,
    image: &ImageMapFacts,
) -> Result<reverie::MemoryMap, reverie::FactError> {
    let unknown = || reverie::MemoryMap::new(Vec::new(), false);
    let Some(mut mappings) = super::facts::stack_window_mappings(memory, image)? else {
        return unknown();
    };
    let window = memory
        .user_layout()
        .0
        .into_iter()
        .find(|window| window.user_end == USER_STACK_TOP);
    let brk = memory
        .allocation_cursors()
        .map_or(image.start_brk, |cursors| cursors.program_break);
    let window = window.map(|window| (window.user_start, window.user_end));
    let (lines, unknown_runs) = build_lines(memory.user_mapping_runs().runs, image, window);
    for line in lines {
        let touches_unknown = unknown_runs
            .iter()
            .any(|&(start, end)| line.start <= end && start <= line.end);
        if !touches_unknown {
            mappings.push(line.fact(image, brk)?);
        }
    }
    mappings.sort_by_key(|mapping| mapping.start);
    reverie::MemoryMap::new(mappings, unknown_runs.is_empty())
}

/// The lines of `runs` (in address order) outside the stack window
/// `window` (`[start, end)`), for an image that fixed `image`, and the
/// ranges of the runs whose mapping is not known, which no line crosses.
fn build_lines(
    runs: Vec<UserMappingRun>,
    image: &ImageMapFacts,
    window: Option<(u64, u64)>,
) -> (Vec<Line>, Vec<(u64, u64)>) {
    let mut lines: Vec<Line> = Vec::new();
    // The ranges of pages whose mapping is not known.
    let mut unknown_runs: Vec<(u64, u64)> = Vec::new();
    for run in runs {
        if window.is_some_and(|(start, end)| (start..end).contains(&run.start)) {
            continue;
        }
        let Ok(line) = Line::of(&run) else {
            unknown_runs.push((run.start, run.end));
            continue;
        };
        let Some(line) = line else { continue };
        // The program break's first mapping, which `brk(2)` makes at
        // `start_brk`, never joins the mapping before it (the image's bss,
        // which ends there when the break is not randomized): Linux's `brk`
        // offers `do_brk_flags` only a previous mapping at or above
        // `start_brk` to grow (`vma_prev_limit(&vmi, mm->start_brk)` in
        // `mm/mmap.c`), so `[heap]` starts a line of its own, as Linux 7.1.3
        // lists it.
        match lines.last_mut() {
            Some(last) if line.start != image.start_brk && last.merges_with(&line) => {
                last.absorb(&line);
            }
            _ => lines.push(line),
        }
    }
    (lines, unknown_runs)
}

/// The extent of a line and its sticky flags ([`STICKY_FLAGS`]): those any
/// of its pages has, and those all of them have.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LineExtent {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) sticky: u16,
    pub(crate) sticky_everywhere: u16,
}

/// The stack window's user range of `memory`, if it has one.
fn stack_window(memory: &GuestMemory) -> Option<(u64, u64)> {
    memory
        .user_layout()
        .0
        .into_iter()
        .find(|window| window.user_end == USER_STACK_TOP)
        .map(|window| (window.user_start, window.user_end))
}

/// The line of `memory` (whose image fixed `image`) that holds the page at
/// user address `address`, as the list of mappings would give it: `None`
/// for a page outside every line (unmapped, the backend's own, or a page
/// whose mapping is not known). In the stack window, the window's mapping
/// that holds it (`facts::stack_window_runs`), if the window's record is
/// certain. Outside it, the runs around the page are read, over a range
/// that grows until the line ends inside it on both sides, so the work is
/// proportional to the line, not to the address space.
pub(crate) fn line_holding(
    memory: &GuestMemory,
    image: &ImageMapFacts,
    address: u64,
) -> Option<LineExtent> {
    let page = reverie_kvm_core::layout::PAGE_SIZE;
    let address = address & !(page - 1);
    let window = stack_window(memory);
    if let Some((start, end)) = window
        && (start..end).contains(&address)
    {
        return super::facts::stack_window_line_holding(memory, address);
    }
    let mut radius = 16 * page;
    loop {
        let low = address.saturating_sub(radius);
        let high = address.saturating_add(radius).min(!(page - 1));
        let runs = memory.user_mapping_runs_in(low, high - low).runs;
        let (lines, _) = build_lines(runs, image, window);
        let line = lines
            .into_iter()
            .find(|line| line.start <= address && address < line.end)?;
        // A line that reaches an end of the range may go on past it.
        let open = line.start == low && low != 0 || line.end == high && high < USER_STACK_TOP;
        if !open || radius >= USER_STACK_TOP {
            return Some(LineExtent {
                start: line.start,
                end: line.end,
                sticky: line.sticky,
                sticky_everywhere: line.sticky_everywhere,
            });
        }
        radius = radius.saturating_mul(8);
    }
}

/// Sets the provider flags `set` on every declared page of the user range
/// `[start, end)`, outside the stack window and in it.
fn set_flags(memory: &GuestMemory, start: u64, end: u64, set: u16) {
    if end <= start {
        return;
    }
    memory.edit_user_declared(start, end - start, |declared, _| DeclaredMapping {
        flags: declared.flags | set,
        ..declared
    });
    memory.flag_user_range(start, end - start, set, 0);
}

/// Before a call that may split lines at the user addresses `boundaries`
/// (the ends of the ranges it changes): each line that holds a boundary's
/// page and has the guard flag (`FLAG_MAYBE_GUARD`) on some of its pages
/// but not all gets it on all, so that every part a split leaves keeps it,
/// as a split copies `VM_MAYBE_GUARD` on Linux. This changes no line's
/// flags: the line has the flag already ([`STICKY_FLAGS`]). Nothing is read
/// when no page of the address space has the flag.
pub(crate) fn spread_guard_marks(memory: &GuestMemory, image: &ImageMapFacts, boundaries: &[u64]) {
    if memory.flagged_pages(FLAG_MAYBE_GUARD) == 0 {
        return;
    }
    for &boundary in boundaries {
        if let Some(line) = line_holding(memory, image, boundary)
            && line.sticky & FLAG_MAYBE_GUARD != 0
            && line.sticky_everywhere & FLAG_MAYBE_GUARD == 0
        {
            set_flags(memory, line.start, line.end, FLAG_MAYBE_GUARD);
        }
    }
}

/// After `MADV_GUARD_INSTALL` over the user range `[start, start + length)`
/// applied (with or without holes): sets the guard flag
/// (`FLAG_MAYBE_GUARD`) on every page of each line the range touches, as
/// Linux sets `VM_MAYBE_GUARD` on each whole mapping the advice covers part
/// of (`madvise_guard_install`).
pub(crate) fn mark_guarded_lines(
    memory: &GuestMemory,
    image: &ImageMapFacts,
    start: u64,
    length: u64,
) {
    let page = reverie_kvm_core::layout::PAGE_SIZE;
    let Some(end) = start.checked_add(length) else {
        return;
    };
    if end <= start {
        return;
    }
    let low = line_holding(memory, image, start).map_or(start, |line| line.start);
    let high = line_holding(memory, image, end - page).map_or(end, |line| line.end);
    set_flags(memory, low, high, FLAG_MAYBE_GUARD);
}
