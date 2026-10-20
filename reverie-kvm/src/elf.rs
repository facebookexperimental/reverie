/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ffi::CStr;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;

use goblin::elf::Elf;
use goblin::elf::header::EI_CLASS;
use goblin::elf::header::EI_DATA;
use goblin::elf::header::ELFCLASS64;
use goblin::elf::header::ELFDATA2LSB;
use goblin::elf::header::EM_X86_64;
use goblin::elf::header::ET_DYN;
use goblin::elf::header::ET_EXEC;
use goblin::elf::program_header::PF_W;
use goblin::elf::program_header::PF_X;
use goblin::elf::program_header::PT_INTERP;
use goblin::elf::program_header::PT_LOAD;
use reverie::ExitStatus;

use crate::Error;
use crate::GuestMemory;
use crate::Result;
use crate::bootstrap::BOOT_RESERVED_END;
use crate::bootstrap::PROGRAM_HEADERS_ADDRESS;
use crate::bootstrap::VDSO_ADDRESS;
use crate::memory::AllocationCursors;
use crate::memory::MMAP_BASE;
use crate::memory::RegionKind;
use crate::memory::USER_ADDRESS_END;
use crate::memory::USER_STACK_TOP;
use crate::memory::UserWindow;
use crate::signal::ProcessSignalState;
use crate::signal::SharedThreadSignalState;

#[path = "parent_death.rs"]
pub(crate) mod parent_death;

const PAGE_SIZE: u64 = 4096;
pub(crate) const TASK_COMM_LEN: usize = 16;
/// The fixed ELF64 layout also used by the ptrace tracee initializer.
pub(crate) const LINUX_FIXED_PERSONALITY: u32 = 0x0004_0000;
pub(crate) const STACK_LIMIT: u64 = 8 * 1024 * 1024;
const MAX_PROGRAM_HEADERS_SIZE: usize = PAGE_SIZE as usize;
const MAX_INTERPRETER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SCRIPT_INTERPRETERS: usize = 4;
const MAIN_LOAD_BIAS: u64 = 2 * 1024 * 1024;
const _: () = assert!(BOOT_RESERVED_END <= MAIN_LOAD_BIAS);
/// The host kernel's own vDSO pages that Linux 7.x maps top-down below the
/// interpreter at exec ([vvar] 0x4000, [vvar_vclock] 0x2000, [vdso] 0x2000).
/// Hermit's ptrace backend maps its canonical vDSO elsewhere but leaves these
/// in place, as do the other backends that run on the host kernel, so they
/// occupy the address space. KVM reserves the same range, inaccessible, so its
/// mappings land at the same addresses.
const VDSO_GAP: u64 = 0x8000;
const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
/// The least program-break growth the layout leaves above a main image: 1 MiB
/// for a static program and 4 MiB for one with an interpreter, as before the
/// mmap window existed.
const STATIC_BRK_HEADROOM: u64 = 1024 * 1024;
/// Where Linux loads an interpreted PIE main image with address randomization
/// off (x86-64 ELF_ET_DYN_BASE), before rounding to the image's alignment.
const PIE_BASE: u64 = 0x5555_5555_4000;
const INTERPRETED_BRK_HEADROOM: u64 = 4 * 1024 * 1024;
pub(crate) const GUEST_CAPABILITY_MASK: u64 = (1_u64 << 41) - 1;
const PROC_SUPER_MAGIC: libc::c_long = 0x9fa0;
const POLICY_OPEN_EINTR_ATTEMPTS: usize = 16;

/// Host behavior around Linux commit 43b450632676fb60e9faeddff285d9fac94a4f58,
/// which moved invalid O_CREAT|O_DIRECTORY admission ahead of path lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegularCreateDirectoryPolicy {
    EarlyEinval,
    LegacyLookup,
}

static REGULAR_CREATE_DIRECTORY_POLICY: OnceLock<
    std::result::Result<RegularCreateDirectoryPolicy, String>,
> = OnceLock::new();

fn raw_openat_with_bounded_eintr(
    path: &CStr,
    flags: libc::c_int,
) -> std::result::Result<RawFd, libc::c_int> {
    for _ in 0..POLICY_OPEN_EINTR_ATTEMPTS {
        // SAFETY: path is NUL-terminated and live for the call. A zero mode is
        // valid, and the verified existing path cannot be created by the probe.
        let result =
            unsafe { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, path.as_ptr(), flags, 0) };
        if result >= 0 {
            return Ok(result as RawFd);
        }
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if errno != libc::EINTR {
            return Err(errno);
        }
    }
    Err(libc::EINTR)
}

fn probe_regular_create_directory_policy()
-> std::result::Result<RegularCreateDirectoryPolicy, String> {
    let path = c"/proc/self/status";
    let verification_fd = raw_openat_with_bounded_eintr(path, libc::O_PATH | libc::O_CLOEXEC)
        .map_err(|errno| format!("cannot verify /proc/self/status: errno {errno}"))?;
    // SAFETY: the raw open returned a new owned descriptor.
    let verification = unsafe { File::from_raw_fd(verification_fd) };
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: metadata is writable and verification remains live.
    if unsafe { libc::fstat(verification.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        return Err(format!(
            "cannot stat /proc/self/status: errno {}",
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
        ));
    }
    // SAFETY: fstat initialized metadata on success.
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(format!(
            "/proc/self/status is not regular: mode {:#o}",
            metadata.st_mode
        ));
    }
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: filesystem is writable and verification remains live.
    if unsafe { libc::fstatfs(verification.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(format!(
            "cannot statfs /proc/self/status: errno {}",
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
        ));
    }
    // SAFETY: fstatfs initialized filesystem on success.
    let filesystem = unsafe { filesystem.assume_init() };
    if filesystem.f_type as libc::c_long != PROC_SUPER_MAGIC {
        return Err(format!(
            "/proc/self/status is not on procfs: f_type {:#x}",
            filesystem.f_type
        ));
    }
    drop(verification);

    let flags = libc::O_RDONLY | libc::O_CREAT | libc::O_DIRECTORY | libc::O_CLOEXEC;
    match raw_openat_with_bounded_eintr(path, flags) {
        Err(libc::EINVAL) => Ok(RegularCreateDirectoryPolicy::EarlyEinval),
        Err(libc::ENOTDIR) => Ok(RegularCreateDirectoryPolicy::LegacyLookup),
        Err(errno) => Err(format!(
            "unsupported O_CREAT|O_DIRECTORY result for /proc/self/status: errno {errno}"
        )),
        Ok(fd) => {
            // SAFETY: the policy probe unexpectedly returned a new descriptor;
            // close it before failing initialization.
            let close_result = unsafe { libc::close(fd) };
            Err(format!(
                "O_CREAT|O_DIRECTORY unexpectedly opened /proc/self/status (close={close_result})"
            ))
        }
    }
}

pub(crate) fn initialize_regular_create_directory_policy() -> Result<RegularCreateDirectoryPolicy> {
    match REGULAR_CREATE_DIRECTORY_POLICY.get_or_init(probe_regular_create_directory_policy) {
        Ok(policy) => Ok(*policy),
        Err(error) => Err(Error::HostIo(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("cannot establish O_CREAT|O_DIRECTORY host policy: {error}"),
        ))),
    }
}

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;
// Linux x86-64 reports USER_HZ through AT_CLKTCK. This ABI value is
// independent of the kernel's internal CONFIG_HZ scheduler frequency.
const CLOCK_TICKS_PER_SECOND: u64 = 100;
// Points at the base of the in-guest vDSO ELF image. glibc's dynamic linker
// reads the vDSO's kernel-version ELF note through this entry during startup
// (`_dl_discover_osversion`); without it glibc falls back to a `uname(2)`
// syscall, which diverges the guest's startup syscall stream from the native
// (ptrace) path and breaks cross-backend syscall-count parity.
const AT_SYSINFO_EHDR: u64 = 33;
const AT_FLAGS: u64 = 8;
const AT_PLATFORM: u64 = 15;
const AT_HWCAP: u64 = 16;
const AT_HWCAP2: u64 = 26;
/// The string `AT_PLATFORM` names: `ELF_PLATFORM` of every x86_64 kernel.
const GUEST_PLATFORM: &[u8] = b"x86_64";

/// The guest-side values of a guest's auxiliary vector.
struct GuestAuxvValues {
    program_headers: u64,
    program_header_size: u64,
    program_header_count: u64,
    base: u64,
    entry: u64,
    random: u64,
    execfn: u64,
    platform: u64,
}

/// A guest's auxiliary vector: the entries Linux 6.3 and later give a
/// process, in the order Linux writes them (`create_elf_tables` in
/// fs/binfmt_elf.c, with x86_64's `ARCH_DLINFO` first). glibc's loader spends
/// branches on every entry and reads several, so the same vector gives a KVM
/// guest the start-up, and the virtual time, a traced guest has
/// (<https://github.com/rrnewton/reverie/issues/947>).
///
/// The entries that describe the CPU or the kernel carry
/// `reverie::canonical_auxv_value`, which reverie-ptrace also writes into a
/// traced guest's vector, so neither depends on the host. Identity entries
/// are the guest's own: root, not secure. `AT_FLAGS` is 0, as on every Linux
/// kernel.
fn guest_auxv(guest: &GuestAuxvValues) -> Vec<(u64, u64)> {
    let canonical = |key| {
        reverie::canonical_auxv_value(key)
            .unwrap_or_else(|| panic!("auxv entry {key} has no canonical value"))
    };
    vec![
        (AT_SYSINFO_EHDR, VDSO_ADDRESS),
        (reverie::AT_MINSIGSTKSZ, canonical(reverie::AT_MINSIGSTKSZ)),
        (AT_HWCAP, canonical(AT_HWCAP)),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_CLKTCK, CLOCK_TICKS_PER_SECOND),
        (AT_PHDR, guest.program_headers),
        (AT_PHENT, guest.program_header_size),
        (AT_PHNUM, guest.program_header_count),
        (AT_BASE, guest.base),
        (AT_FLAGS, 0),
        (AT_ENTRY, guest.entry),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_SECURE, 0),
        (AT_RANDOM, guest.random),
        (AT_HWCAP2, canonical(AT_HWCAP2)),
        (AT_EXECFN, guest.execfn),
        (AT_PLATFORM, guest.platform),
        (
            reverie::AT_RSEQ_FEATURE_SIZE,
            canonical(reverie::AT_RSEQ_FEATURE_SIZE),
        ),
        (reverie::AT_RSEQ_ALIGN, canonical(reverie::AT_RSEQ_ALIGN)),
    ]
}

// AUTONOMOUS-BOT-IMPLEMENTED: Share deterministic file identities across fork.
// TODO-HUMAN-REVIEW(PR-136): Review linked and anonymous object identity lifetimes.
#[derive(Debug)]
pub(crate) struct GuestFileIdentity {
    pub inode: u64,
    /// Which timestamps `stat`, `fstat`, `newfstatat` and `statx` report for
    /// the object in a run that reports host metadata timestamps. Every alias
    /// shares this identity: a dup, a `/proc/self/fd` reopen, a fork and an
    /// exec. A received SCM_RIGHTS carrier is recognized from the carrier
    /// itself; see `crate::executor::received_carrier_timestamps`.
    pub timestamps: IdentityTimestamps,
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(https://github.com/rrnewton/reverie/issues/933):
// Review the fixed-timestamp classes of backend-made carriers.
/// The timestamps an object reports in a run that reports host metadata
/// timestamps. A run that does not report them does not use these classes:
/// a carrier then reports the kernel's timestamps, like every host object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityTimestamps {
    /// The times the kernel stored for the host object.
    Host,
    /// A synthetic `/proc` snapshot carrier, such as the one for
    /// `/proc/self/maps`. It reports timestamp 0, like every synthetic
    /// `/proc` file.
    ProcSnapshot,
}

// TODO-HUMAN-REVIEW(PR-136): Review the identity entry lifetime API.
#[derive(Debug)]
pub(crate) enum GuestFileIdentityEntry {
    Persistent(std::sync::Arc<GuestFileIdentity>),
    Ephemeral(std::sync::Weak<GuestFileIdentity>),
}

impl GuestFileIdentityEntry {
    // TODO-HUMAN-REVIEW(PR-136): Review identity entry lifetime accessors.
    pub(crate) fn identity(&self) -> Option<std::sync::Arc<GuestFileIdentity>> {
        match self {
            Self::Persistent(identity) => Some(identity.clone()),
            Self::Ephemeral(identity) => identity.upgrade(),
        }
    }

    // TODO-HUMAN-REVIEW(PR-136): Review identity entry liveness checks.
    pub(crate) fn is_live(&self) -> bool {
        self.identity().is_some()
    }
}

// TODO-HUMAN-REVIEW(PR-136): Review the shared identity table API.
#[derive(Debug)]
pub(crate) struct GuestFileIdentityTable {
    pub next_inode: u64,
    pub objects: std::collections::BTreeMap<(libc::dev_t, libc::ino_t), GuestFileIdentityEntry>,
    /// Read-time procfs descriptions sent with SCM_RIGHTS and not yet received,
    /// keyed by their pinned backing memfd.
    pub proc_transfers:
        std::collections::BTreeMap<(libc::dev_t, libc::ino_t), crate::executor::ProcTransfer>,
    /// Run-wide virtual inotify rename cookies; see executor/inotify.rs.
    pub inotify_cookies: crate::executor::InotifyCookieTable,
}

/// Process-tree-wide state whose lifetime follows a guest task rather than an
/// individual [`LoadedStaticElf`] snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TaskLifecycleState {
    pub generation: u64,
    pub process_generation: u64,
    pub tgid: i32,
    pub pgid: i32,
    pub robust_list_head: u64,
    pub dumpable: bool,
    pub real_parent: Option<reverie::SignalTaskIdentity>,
    pub parent_death_signal: i32,
}

#[derive(Debug, Default)]
pub(crate) struct TaskLifecycleTable {
    next_generation: u64,
    tasks: std::collections::BTreeMap<i32, TaskLifecycleState>,
    signal_targets: std::collections::BTreeMap<
        i32,
        std::sync::Weak<std::sync::Mutex<crate::signal::ThreadSignalState>>,
    >,
    process_exits: std::collections::BTreeMap<(i32, u64), ProcessExitState>,
    pub(crate) parent_death: parent_death::ParentDeathState,
    /// Thread-group id of the root guest the table was created for.
    root_tgid: Option<i32>,
}

#[derive(Debug, Default)]
struct ProcessExitState {
    last_thread: Option<ExitStatus>,
    group: Option<ExitStatus>,
    failed: bool,
}

impl TaskLifecycleTable {
    pub(crate) fn with_root(tid: i32, tgid: i32, pgid: i32, dumpable: bool) -> Self {
        let mut table = Self {
            root_tgid: Some(tgid),
            ..Self::default()
        };
        table.register(tid, tgid, pgid, dumpable);
        table
    }

    /// True when the root guest is not PID 1, so the namespace init it is
    /// parented to (`getppid() == 1`) is synthesized rather than a guest task.
    pub(crate) fn synthesizes_namespace_init(&self) -> bool {
        self.root_tgid
            .is_some_and(|root| root != crate::vm::CONTAINER_INIT_PID)
    }

    pub(crate) fn register(&mut self, tid: i32, tgid: i32, pgid: i32, dumpable: bool) -> u64 {
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("KVM task generation exhausted");
        let generation = self.next_generation;
        let process_generation = if tid == tgid {
            generation
        } else {
            self.tasks
                .values()
                .find(|task| task.tgid == tgid)
                .map_or(generation, |task| task.process_generation)
        };
        self.tasks.insert(
            tid,
            TaskLifecycleState {
                generation,
                process_generation,
                tgid,
                pgid,
                robust_list_head: 0,
                dumpable,
                real_parent: None,
                parent_death_signal: 0,
            },
        );
        // A reused numeric TID never inherits the old task's signal endpoint.
        self.signal_targets.remove(&tid);
        generation
    }

    pub(crate) fn register_with_signals(
        &mut self,
        tid: i32,
        tgid: i32,
        pgid: i32,
        dumpable: bool,
        signals: &SharedThreadSignalState,
    ) -> u64 {
        let generation = self.register(tid, tgid, pgid, dumpable);
        self.signal_targets.insert(tid, signals.downgrade());
        generation
    }

    pub(crate) fn ensure_registered_with_signals(
        &mut self,
        tid: i32,
        tgid: i32,
        pgid: i32,
        dumpable: bool,
        signals: &SharedThreadSignalState,
    ) -> u64 {
        let generation = self.ensure_registered(tid, tgid, pgid, dumpable);
        self.signal_targets.insert(tid, signals.downgrade());
        generation
    }

    /// The caller keeps the lifecycle lock through queue publication, so an
    /// accepted send belongs to this incarnation even if the numeric TID is
    /// reused immediately after the lock is released.
    pub(crate) fn signal_target(&self, tid: i32) -> Option<SharedThreadSignalState> {
        self.signal_targets
            .get(&tid)
            .and_then(SharedThreadSignalState::upgrade)
    }

    pub(crate) fn ensure_registered(
        &mut self,
        tid: i32,
        tgid: i32,
        pgid: i32,
        dumpable: bool,
    ) -> u64 {
        self.tasks
            .get(&tid)
            .map(|task| task.generation)
            .unwrap_or_else(|| self.register(tid, tgid, pgid, dumpable))
    }

    pub(crate) fn remove(&mut self, tid: i32, generation: u64) {
        if self
            .tasks
            .get(&tid)
            .is_some_and(|task| task.generation == generation)
        {
            self.tasks.remove(&tid);
            self.signal_targets.remove(&tid);
        }
    }

    /// Commit a guest task's exit while retiring its exact identity. Host
    /// handle completion and failed child preparation do not select a status.
    pub(crate) fn exit(
        &mut self,
        tid: i32,
        generation: u64,
        status: ExitStatus,
        group: bool,
    ) -> (ExitStatus, bool) {
        let Some(task) = self.tasks.get(&tid).copied() else {
            return (status, false);
        };
        if task.generation != generation {
            return (status, false);
        }
        let exit = self
            .process_exits
            .entry((task.tgid, task.process_generation))
            .or_default();
        let group_started = group && exit.group.is_none();
        if group_started {
            exit.group = Some(status);
        }
        exit.last_thread = Some(status);
        let status = exit.group.unwrap_or(status);
        self.remove(tid, generation);
        (status, group_started)
    }

    /// A still-live waiter may observe a peer's committed group exit before
    /// the backend cancellation flag is published. Never grant that control to
    /// a dead/reused task or a process whose cleanup has already failed.
    pub(crate) fn live_task_group_exit_status(
        &self,
        identity: reverie::SignalTaskIdentity,
    ) -> Option<ExitStatus> {
        let task = self.tasks.get(&identity.tid.as_raw())?;
        if task.generation != identity.task_generation
            || task.tgid != identity.process.tgid.as_raw()
            || task.process_generation != identity.process.generation
        {
            return None;
        }
        let exit = self
            .process_exits
            .get(&(task.tgid, task.process_generation))?;
        if exit.failed { None } else { exit.group }
    }

    pub(crate) fn process_exit_status(
        &self,
        tgid: i32,
        process_generation: u64,
    ) -> Option<ExitStatus> {
        if self
            .tasks
            .values()
            .any(|task| task.tgid == tgid && task.process_generation == process_generation)
        {
            return None;
        }
        let exit = self.process_exits.get(&(tgid, process_generation))?;
        if exit.failed {
            None
        } else {
            exit.group.or(exit.last_thread)
        }
    }

    pub(crate) fn forget_process_exit(&mut self, tgid: i32, process_generation: u64) {
        if !self
            .tasks
            .values()
            .any(|task| task.tgid == tgid && task.process_generation == process_generation)
        {
            self.process_exits.remove(&(tgid, process_generation));
        }
    }

    pub(crate) fn fail(&mut self, tid: i32, generation: u64) -> bool {
        let Some(task) = self.tasks.get(&tid).copied() else {
            return false;
        };
        if task.generation != generation {
            return false;
        }
        self.process_exits
            .entry((task.tgid, task.process_generation))
            .or_default()
            .failed = true;
        self.remove(tid, generation);
        true
    }

    pub(crate) fn reset_after_exec(&mut self, tid: i32, tgid: i32, pgid: i32) -> u64 {
        if let Some(task) = self.tasks.get_mut(&tid) {
            self.process_exits
                .remove(&(task.tgid, task.process_generation));
            task.tgid = tgid;
            task.pgid = pgid;
            task.robust_list_head = 0;
            task.dumpable = true;
            task.generation
        } else {
            self.register(tid, tgid, pgid, true)
        }
    }

    pub(crate) fn reset_after_exec_with_signals(
        &mut self,
        tid: i32,
        tgid: i32,
        pgid: i32,
        signals: &SharedThreadSignalState,
    ) -> u64 {
        let generation = self.reset_after_exec(tid, tgid, pgid);
        self.signal_targets.insert(tid, signals.downgrade());
        generation
    }

    pub(crate) fn set_robust_list(&mut self, tid: i32, head: u64) -> bool {
        let Some(task) = self.tasks.get_mut(&tid) else {
            return false;
        };
        task.robust_list_head = head;
        true
    }

    pub(crate) fn get(&self, tid: i32) -> Option<TaskLifecycleState> {
        self.tasks.get(&tid).copied()
    }

    /// Exact live task identities in one process lifetime, in stable TID order.
    pub(crate) fn signal_process_tasks(
        &self,
        process: reverie::SignalProcessId,
    ) -> Vec<reverie::SignalTaskIdentity> {
        self.tasks
            .iter()
            .filter_map(|(&tid, task)| {
                (task.tgid == process.tgid.as_raw()
                    && task.process_generation == process.generation)
                    .then_some(reverie::SignalTaskIdentity {
                        process,
                        tid: reverie::Pid::from_raw(tid),
                        task_generation: task.generation,
                    })
            })
            .collect()
    }

    pub(crate) fn contains_process(&self, tgid: i32, generation: u64) -> bool {
        self.tasks
            .values()
            .any(|task| task.tgid == tgid && task.process_generation == generation)
    }

    pub(crate) fn has_live_sibling(&self, tid: i32, tgid: i32) -> bool {
        self.tasks
            .iter()
            .any(|(&candidate, task)| candidate != tid && task.tgid == tgid)
    }

    /// Returns `(tgid, pgid)` for each live virtual process exactly once,
    /// including a thread group whose leader exited while a member remains.
    pub(crate) fn processes(&self) -> impl Iterator<Item = (i32, i32)> {
        let mut processes = std::collections::BTreeMap::new();
        for task in self.tasks.values() {
            if let Some(previous) = processes.insert(task.tgid, task.pgid) {
                debug_assert_eq!(previous, task.pgid, "one process has inconsistent PGIDs");
            }
        }
        processes.into_iter()
    }

    pub(crate) fn set_dumpable(&mut self, tgid: i32, dumpable: bool) -> bool {
        let mut found = false;
        for task in self.tasks.values_mut().filter(|task| task.tgid == tgid) {
            task.dumpable = dumpable;
            found = true;
        }
        found
    }
}

/// Retired descriptions belong to one executor. A scope declared before its
/// file-table/transaction guards keeps closes outside both guards, including
/// ordinary early returns. The queue mutex is never held during destruction.
#[derive(Clone, Default)]
pub(crate) struct FileRetirement(Arc<std::sync::Mutex<FileRetirementState>>);

#[cfg(test)]
type RetirementProbe = Arc<dyn Fn(&[i32]) + Send + Sync>;

#[derive(Default)]
struct FileRetirementState {
    scopes: usize,
    files: Vec<RetiredFile>,
    #[cfg(test)]
    probe: Option<RetirementProbe>,
    #[cfg(test)]
    clones_before_failure: Option<usize>,
}

enum RetiredFile {
    Owned(File),
    Shared(Arc<File>),
}

impl std::fmt::Debug for FileRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileRetirement").finish_non_exhaustive()
    }
}

pub(crate) struct FileRetirementScope(FileRetirement);

pub(crate) struct StagedFile {
    file: Option<File>,
    retirement: FileRetirement,
}

impl FileRetirement {
    pub(crate) fn hold(&self) -> FileRetirementScope {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).scopes += 1;
        FileRetirementScope(self.clone())
    }

    pub(crate) fn retire(&self, files: impl IntoIterator<Item = File>) {
        self.retire_inner(files.into_iter().map(RetiredFile::Owned));
    }

    pub(crate) fn retire_shared(&self, files: impl IntoIterator<Item = Arc<File>>) {
        self.retire_inner(files.into_iter().map(RetiredFile::Shared));
    }

    fn retire_inner(&self, files: impl IntoIterator<Item = RetiredFile>) {
        let retired = {
            let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
            state.files.extend(files);
            if state.scopes == 0 {
                std::mem::take(&mut state.files)
            } else {
                Vec::new()
            }
        };
        self.destroy(retired);
    }

    /// The caller has released both executor guards and is about to enter an
    /// operation that may block. Do not retain stale descriptions across it.
    pub(crate) fn drain_unlocked(&self) {
        let retired = {
            let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
            std::mem::take(&mut state.files)
        };
        self.destroy(retired);
    }

    fn destroy(&self, files: Vec<RetiredFile>) {
        if files.is_empty() {
            return;
        }
        #[cfg(test)]
        {
            let probe = self
                .0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .probe
                .clone();
            if let Some(probe) = probe {
                let descriptors: Vec<_> = files
                    .iter()
                    .map(|file| match file {
                        RetiredFile::Owned(file) => file.as_raw_fd(),
                        RetiredFile::Shared(file) => file.as_raw_fd(),
                    })
                    .collect();
                // The actual owners remain alive until the probe permits this
                // destructor to continue; no queue or executor guard is held.
                probe(&descriptors);
            }
        }
        for file in files {
            match file {
                RetiredFile::Owned(file) => drop(file),
                RetiredFile::Shared(file) => drop(file),
            }
        }
    }

    pub(crate) fn stage(&self, file: File) -> StagedFile {
        StagedFile {
            file: Some(file),
            retirement: self.clone(),
        }
    }

    pub(crate) fn stage_clone(&self, file: &File) -> std::io::Result<StagedFile> {
        #[cfg(test)]
        {
            let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(remaining) = state.clones_before_failure.as_mut() {
                if *remaining == 0 {
                    return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
                }
                *remaining -= 1;
            }
        }
        file.try_clone().map(|file| self.stage(file))
    }

    #[cfg(test)]
    pub(crate) fn set_probe(&self, probe: Option<RetirementProbe>) {
        let retired = {
            let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
            std::mem::replace(&mut state.probe, probe)
        };
        drop(retired);
    }

    #[cfg(test)]
    pub(crate) fn fail_clone_after(&self, successful: Option<usize>) {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clones_before_failure = successful;
    }
}

impl Drop for FileRetirementScope {
    fn drop(&mut self) {
        let retired = {
            let mut state = self.0.0.lock().unwrap_or_else(|p| p.into_inner());
            state.scopes -= 1;
            if state.scopes == 0 {
                std::mem::take(&mut state.files)
            } else {
                Vec::new()
            }
        };
        self.0.destroy(retired);
    }
}

impl StagedFile {
    pub(crate) fn as_file(&self) -> &File {
        self.file
            .as_ref()
            .expect("staged descriptor was already transferred")
    }

    pub(crate) fn into_file(mut self) -> File {
        self.file
            .take()
            .expect("staged descriptor was already transferred")
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        self.retirement.retire(self.file.take());
    }
}

/// A guest descriptor entry: its identity in the file table (replaced by
/// every insertion, see [`LoadedStaticElf::insert_file`]), and what probing
/// its open file description has shown. Each fact is a property Linux fixes
/// when the description is opened, so it holds for as long as this entry
/// stands: the access mode and `O_PATH` (`F_GETFL`), the file type
/// (`fstat`), and whether the description can be read at all
/// (`FMODE_CAN_READ`, which a zero-iovec `readv` tests). Each is recorded
/// only from a successful probe; a failing probe is repeated, so its error
/// is reported as before.
#[derive(Debug, Default)]
pub(crate) struct FdEntry {
    access: std::sync::OnceLock<libc::c_int>,
    file_type: std::sync::OnceLock<libc::mode_t>,
    read_capable: std::sync::OnceLock<()>,
}

impl FdEntry {
    /// The access mode and `O_PATH` bits of `F_GETFL` (`probe`) for this
    /// entry's host descriptor.
    pub(crate) fn access(
        &self,
        probe: impl FnOnce() -> std::result::Result<libc::c_int, i64>,
    ) -> std::result::Result<libc::c_int, i64> {
        if let Some(access) = self.access.get() {
            return Ok(*access);
        }
        let access = probe()? & (libc::O_ACCMODE | libc::O_PATH);
        Ok(*self.access.get_or_init(|| access))
    }

    /// The file type bits (`S_IFMT`) of `fstat` (`probe`) for this entry's
    /// host descriptor.
    pub(crate) fn file_type(
        &self,
        probe: impl FnOnce() -> std::result::Result<libc::mode_t, i64>,
    ) -> std::result::Result<libc::mode_t, i64> {
        if let Some(file_type) = self.file_type.get() {
            return Ok(*file_type);
        }
        let file_type = probe()? & libc::S_IFMT;
        Ok(*self.file_type.get_or_init(|| file_type))
    }

    /// Runs the read-capability `probe` unless it has already succeeded for
    /// this entry.
    pub(crate) fn read_capable(
        &self,
        probe: impl FnOnce() -> std::result::Result<(), i64>,
    ) -> std::result::Result<(), i64> {
        if self.read_capable.get().is_some() {
            return Ok(());
        }
        probe()?;
        self.read_capable.get_or_init(|| ());
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct LoadedStaticElf {
    pub entry_point: u64,
    pub stack_pointer: u64,
    /// Initial program break set at load time (`align_up(main_end)`); the base
    /// of the brk-managed heap. The live heap spans `[heap_base, program_break)`.
    pub heap_base: u64,
    /// The lowest break brk accepts: Linux's `mm->end_data` (the end of the
    /// main image's file-backed segment contents), its minimum under
    /// CONFIG_COMPAT_BRK without brk randomization. Shrinking below it
    /// would unmap the image's data.
    pub min_break: u64,
    pub program_break: u64,
    pub brk_limit: u64,
    pub mmap_base: u64,
    pub mmap_next: u64,
    pub mmap_limit: u64,
    pub executable_path: PathBuf,
    pub executable_file: Option<std::sync::Arc<std::fs::File>>,
    pub executable_image: std::sync::Arc<[u8]>,
    pub argv0: Vec<u8>,
    pub cwd: PathBuf,
    pub cwd_fd: std::fs::File,
    pub stdin: Option<std::fs::File>,
    /// Identity of the inherited stdin slot, distinct from its inode/OFD.
    /// Loader setup precedes table publication; fork and exec retain this
    /// identity, while closing or replacing the slot creates a new identity.
    pub stdin_entry_id: std::sync::Arc<()>,
    pub auxv: Vec<(libc::c_ulong, libc::c_ulong)>,
    pub fs_base: u64,
    pub gs_base: u64,
    pub pid: i32,
    /// Process incarnation for the bounded pipe-owner configuration domain.
    /// Threads and exec retain it; a forked process receives a fresh token.
    pub(crate) pipe_owner_process: std::sync::Arc<()>,
    /// Virtual process-group identity, inherited across `fork`.
    pub pgid: i32,
    // TODO-HUMAN-REVIEW(PR-132): Review single-vCPU thread identity transitions.
    pub tid: i32,
    /// The value this process reports from `getppid(2)`.
    ///
    /// This is a *guest-visible* identity, not the traced-tree parent: the root
    /// guest synthesizes a container-init parent (see `root_parent_pid`) so that
    /// `getppid()` matches the ptrace backend's PID namespace, even though the
    /// root guest has no traced parent. Use [`Self::is_traced_tree_root`] to
    /// answer the traced-tree question.
    pub ppid: i32,
    /// Guest-visible parent after the fork-time parent exited, or zero.
    ///
    /// Linux reparents an orphan to its namespace reaper, so `getppid(2)` and
    /// procfs change while the traced-tree parent (`Guest::ppid`) keeps its
    /// fork-time value, as under the ptrace backend. The run-scoped process
    /// family ledger stores the reaper here in the same critical section that
    /// transfers wait ownership. Threads share one cell, fork starts a fresh
    /// zero cell, and `execve` keeps the process's cell.
    pub orphan_reaper_pid: std::sync::Arc<AtomicI32>,
    /// True iff this process is the root of the *traced* process tree, i.e. it
    /// was installed by the backend rather than created by a guest `fork`/`clone`.
    ///
    /// Kept separate from [`Self::ppid`] because the two answer different
    /// questions and disagree for any root guest whose synthetic `getppid()` is
    /// non-zero. Reverie's `Guest::ppid` contract is "None if this is the root of
    /// the traced process tree", and `Guest::is_root_process` is derived from it,
    /// so conflating the two makes the root guest invisible to the tool.
    pub is_traced_tree_root: bool,
    pub umask: libc::mode_t,
    /// Per-task ELF64 Linux personality. Only UNAME26 can change within the
    /// fixed ADDR_NO_RANDOMIZE layout. Fork and clone copy it by value; ordinary
    /// supported exec preserves the calling task's value.
    pub(crate) linux_personality: u32,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-228): Review caller-provided deterministic random seed state.
    pub random_seed: u64,
    /// Task IDs each new task spends (`reverie::task_ids`): Linux's 1 unless
    /// the caller asks for another numbering (Hermit asks for its ptrace
    /// reference's). Shared by the whole run: forks and exec keep it.
    pub ids_per_task: i32,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(https://github.com/rrnewton/reverie/issues/924):
    // Review host metadata timestamps for Tool runs.
    /// Whether a Tool rewrites every timestamp that `stat`, `fstat`,
    /// `newfstatat` and `statx` return, so that the carriers the backend makes
    /// for its own data are classified and keep fixed timestamps (see
    /// [`IdentityTimestamps`]). False by default. Real host files and
    /// descriptors report the kernel's timestamps either way, and captured
    /// output, synthetic `/proc` files and virtual random devices keep fixed
    /// timestamps either way. Set through
    /// [`crate::KvmBackend::set_host_metadata_timestamps`]; fork, clone and
    /// exec carry it unchanged.
    pub host_metadata_timestamps: bool,
    /// Linux task name (`comm`), including the terminating NUL byte.
    ///
    /// This is per-thread state: fork and clone inherit the caller's value,
    /// later changes affect only the calling thread, and exec initializes it
    /// from the replacement image name.
    pub thread_name: [u8; TASK_COMM_LEN],
    /// The thread-group leader's name, exposed by process-level procfs files.
    /// Threads share this value while process children receive an independent
    /// copy initialized from the calling thread's name.
    pub thread_group_leader_name: std::sync::Arc<std::sync::Mutex<[u8; TASK_COMM_LEN]>>,
    /// Process-address-space policy controlled by `PR_SET_THP_DISABLE`.
    /// Threads share this flag; fork takes an independent copy and exec keeps
    /// the existing value.
    pub thp_disabled: std::sync::Arc<AtomicU8>,
    // TODO-HUMAN-REVIEW(PR-181): Review virtual capability lifecycle state.
    pub keep_capabilities: bool,
    pub capability_effective: u64,
    pub capability_permitted: u64,
    pub capability_inheritable: u64,
    pub capability_bounding: u64,
    pub capability_ambient: u64,
    // TODO-HUMAN-REVIEW(PR-235): Review virtual dumpability lifecycle semantics.
    pub dumpable: bool,
    /// Dispositions and process-pending signals shared by a thread group.
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-235): Review process-local virtual signalfd state.
    pub process_signals: std::sync::Arc<std::sync::Mutex<ProcessSignalState>>,
    // Serializes pending-state changes with their signalfd readiness update.
    // Threads share this guard; fork creates a new one and exec preserves it.
    // Ordinary partial order: file table, transaction, lifecycle, process, thread.
    // The inactive publisher takes the run failure guard after lifecycle and
    // before process signals, and retains it through readiness I/O. Initial
    // registry/image lookups release their guards before the file table; image
    // validation and child lookup briefly reacquire them below transaction and
    // lifecycle respectively, releasing them before failure/process acquisition.
    pub signal_transaction: std::sync::Arc<std::sync::Mutex<()>>,
    /// Mask, alternate stack, and pending signals private to this thread.
    pub thread_signals: SharedThreadSignalState,
    /// First observation-bookkeeping refusal for this executor lifetime.
    /// This is separate from guest pending state and from raw syscall results.
    pub signal_dequeue_failure: Option<reverie::syscalls::Errno>,
    // One process-tree-wide membership table distinguishes a live task with no
    // robust-list registration from an unknown/dead tid. Entries are created
    // with each executor, reset across exec, and removed when that executor is
    // destroyed.
    pub task_lifecycle: std::sync::Arc<std::sync::Mutex<TaskLifecycleTable>>,
    pub files: std::collections::BTreeMap<i32, std::fs::File>,
    pub file_retirement: FileRetirement,
    pub(crate) pipe_owners:
        std::collections::BTreeMap<i32, std::sync::Arc<crate::executor::pipe_owner::PipeOwner>>,
    /// Identity of each descriptor entry, independent of its filesystem object.
    /// Insertion, including a dup destination, creates a new identity. Table
    /// snapshots and fork copies retain it so unchanged host handles stay stable.
    pub fd_entry_ids: std::collections::BTreeMap<i32, std::sync::Arc<FdEntry>>,
    pub(crate) epoll_domain: std::sync::Arc<std::sync::Mutex<crate::executor::EpollDomain>>,
    pub(crate) poll_table_id: std::sync::Arc<crate::executor::NativePollTable>,
    pub(crate) native_poll_fds:
        std::collections::BTreeMap<i32, std::sync::Arc<crate::executor::NativePollBinding>>,
    // AUTONOMOUS-BOT-IMPLEMENTED: Keep deterministic random descriptors on the Tool path.
    // TODO-HUMAN-REVIEW(PR-235): Review random-device descriptor lifecycle parity.
    pub random_device_fds: std::collections::BTreeSet<i32>,
    pub random_device_descriptions:
        std::collections::BTreeMap<i32, std::sync::Arc<crate::executor::RandomDeviceDescription>>,
    pub stdout_alias_fds: std::collections::BTreeSet<i32>,
    pub stderr_alias_fds: std::collections::BTreeSet<i32>,
    // AUTONOMOUS-BOT-IMPLEMENTED: Model guest close-on-exec state independently.
    // TODO-HUMAN-REVIEW(#86): Review descriptor and signal inheritance across exec.
    pub cloexec_fds: std::collections::BTreeSet<i32>,
    pub closed_standard_fds: std::collections::BTreeSet<i32>,
    pub(crate) children: crate::executor::ChildWaitContext,
    /// Exact generation and consumer receipt for the already committed reap.
    /// The checked syscall boundary acknowledges it after copyout, including
    /// EFAULT; acknowledgement never selects or removes another child.
    pub(crate) consumed_child_wait: Option<crate::executor::ChildWaitReceipt>,
    // AUTONOMOUS-BOT-IMPLEMENTED: Track memfd-backed synthetic /proc descriptors.
    // TODO-HUMAN-REVIEW(reverie-kvm): Review synthetic /proc determinism.
    //
    // Maps a guest fd opened on a synthesized /proc file to the deterministic
    // inode reported for it. The descriptor itself lives in `files` as an
    // ordinary memfd, so read/lseek/close/dup/fork reuse the real-file paths;
    // this side table only marks which fds must report stable, synthesized
    // metadata instead of the memfd's per-run inode.
    pub proc_files: std::collections::BTreeMap<i32, u64>,
    /// Synthetic proc descriptions opened with O_NOFOLLOW. The private carrier
    /// must be opened through a followed supervisor proc-fd link, so retain
    /// this guest-visible status bit independently of the host OFD.
    pub synthetic_proc_nofollow_fds: std::collections::BTreeSet<i32>,
    /// Host-kernel ordering for O_CREAT|O_DIRECTORY on an existing regular
    /// procfs entry, established before this image can execute.
    pub regular_create_directory_policy: RegularCreateDirectoryPolicy,
    pub fdinfo_files:
        std::collections::BTreeMap<i32, std::sync::Arc<crate::executor::FdinfoDescription>>,
    pub fdinfo_table: std::sync::Weak<std::sync::Mutex<crate::executor::FileTableState>>,
    // AUTONOMOUS-BOT-IMPLEMENTED: Preserve deterministic file-object identity.
    // TODO-HUMAN-REVIEW(PR-136): Review descriptor identity and fork inheritance.
    // Every live descriptor strongly holds its identity; the process-shared
    // registry contains only weak references keyed by unexposed host identity.
    pub fd_object_inodes: std::collections::BTreeMap<i32, std::sync::Arc<GuestFileIdentity>>,
    pub file_identity_table: std::sync::Arc<std::sync::Mutex<GuestFileIdentityTable>>,
    /// Why the signal syscall just executed was refused with ENOSYS, if it
    /// was. Set by the signal-sending path and taken by the executor at the
    /// same syscall boundary, which turns it into the typed refusal
    /// `UnsupportedOperation::Signal`. Never carried across fork or exec.
    pub(crate) signal_refusal: Option<&'static str>,
}

impl LoadedStaticElf {
    /// The value reported by `getppid(2)` and procfs for this process.
    pub(crate) fn guest_parent_pid(&self) -> i32 {
        match self.orphan_reaper_pid.load(Ordering::SeqCst) {
            0 => self.ppid,
            reaper => reaper,
        }
    }

    /// Return replaced descriptions, including inherited stdin at fd 0, so
    /// callers retire them after both the authoritative file-table and
    /// signal-transaction guards are released.
    pub(crate) fn insert_file(&mut self, fd: i32, file: std::fs::File) -> Vec<std::fs::File> {
        {
            let domain = self.epoll_domain.clone();
            let _proof = domain.lock().expect("KVM epoll provenance lock poisoned");
            if let Some(binding) = self.native_poll_fds.remove(&fd) {
                binding.retire();
            }
        }
        self.random_device_descriptions.remove(&fd);
        self.pipe_owners.remove(&fd);
        let mut retired: Vec<_> = self.files.insert(fd, file).into_iter().collect();
        if fd == libc::STDIN_FILENO {
            retired.extend(self.take_stdin());
        }
        self.fd_entry_ids
            .insert(fd, std::sync::Arc::new(FdEntry::default()));
        retired
    }

    pub(crate) fn take_stdin(&mut self) -> Option<std::fs::File> {
        let stdin = self.stdin.take();
        if stdin.is_some() {
            self.stdin_entry_id = std::sync::Arc::new(());
        }
        stdin
    }

    pub(crate) fn remove_file(&mut self, fd: i32) -> Option<std::fs::File> {
        {
            let domain = self.epoll_domain.clone();
            let _proof = domain.lock().expect("KVM epoll provenance lock poisoned");
            if let Some(binding) = self.native_poll_fds.remove(&fd) {
                binding.retire();
            }
        }
        self.random_device_descriptions.remove(&fd);
        self.pipe_owners.remove(&fd);
        let file = self.files.remove(&fd);
        self.fd_entry_ids.remove(&fd);
        file
    }

    #[cfg(test)]
    pub(crate) fn try_clone_for_fork(&self, child_pid: i32) -> Result<Self> {
        let _retirement = self.file_retirement.hold();
        let transaction = self.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        self.try_clone_for_fork_locked(child_pid)
    }

    pub(crate) fn try_clone_for_fork_locked(&self, child_pid: i32) -> Result<Self> {
        // TODO-HUMAN-REVIEW(PR-136): Review shared file identity inheritance across fork.
        let files = self
            .files
            .iter()
            .map(|(&fd, file)| Ok((fd, self.file_retirement.stage_clone(file)?)))
            .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
        let cwd_fd = self.file_retirement.stage_clone(&self.cwd_fd)?;
        let stdin = self
            .stdin
            .as_ref()
            .map(|file| self.file_retirement.stage_clone(file))
            .transpose()?;
        let process_signals = self
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .for_fork();
        Ok(Self {
            entry_point: self.entry_point,
            stack_pointer: self.stack_pointer,
            heap_base: self.heap_base,
            min_break: self.min_break,
            program_break: self.program_break,
            brk_limit: self.brk_limit,
            mmap_base: self.mmap_base,
            mmap_next: self.mmap_next,
            mmap_limit: self.mmap_limit,
            executable_path: self.executable_path.clone(),
            executable_file: self.executable_file.clone(),
            executable_image: self.executable_image.clone(),
            argv0: self.argv0.clone(),
            cwd: self.cwd.clone(),
            cwd_fd: cwd_fd.into_file(),
            stdin: stdin.map(StagedFile::into_file),
            stdin_entry_id: self.stdin_entry_id.clone(),
            auxv: self.auxv.clone(),
            fs_base: self.fs_base,
            gs_base: self.gs_base,
            pid: child_pid,
            pipe_owner_process: std::sync::Arc::new(()),
            pgid: self.pgid,
            tid: child_pid,
            ppid: self.pid,
            orphan_reaper_pid: std::sync::Arc::new(AtomicI32::new(0)),
            // A guest-created child always has a traced parent: this process.
            is_traced_tree_root: false,
            umask: self.umask,
            linux_personality: self.linux_personality,
            random_seed: self.random_seed,
            ids_per_task: self.ids_per_task,
            host_metadata_timestamps: self.host_metadata_timestamps,
            thread_name: self.thread_name,
            thread_group_leader_name: std::sync::Arc::new(std::sync::Mutex::new(self.thread_name)),
            thp_disabled: std::sync::Arc::new(AtomicU8::new(
                self.thp_disabled.load(Ordering::SeqCst),
            )),
            keep_capabilities: self.keep_capabilities,
            capability_effective: self.capability_effective,
            capability_permitted: self.capability_permitted,
            capability_inheritable: self.capability_inheritable,
            capability_bounding: self.capability_bounding,
            capability_ambient: self.capability_ambient,
            dumpable: self.dumpable,
            process_signals: std::sync::Arc::new(std::sync::Mutex::new(process_signals)),
            signal_transaction: Default::default(),
            thread_signals: self.thread_signals.for_fork(),
            signal_dequeue_failure: None,
            task_lifecycle: self.task_lifecycle.clone(),
            files: files
                .into_iter()
                .map(|(fd, file)| (fd, file.into_file()))
                .collect(),
            file_retirement: FileRetirement::default(),
            signal_refusal: None,
            pipe_owners: self.pipe_owners.clone(),
            fd_entry_ids: self.fd_entry_ids.clone(),
            epoll_domain: self.epoll_domain.clone(),
            poll_table_id: self.poll_table_id.fork_identity(),
            native_poll_fds: self
                .native_poll_fds
                .iter()
                .map(|(&fd, binding)| (fd, binding.fork_binding()))
                .collect(),
            random_device_fds: self.random_device_fds.clone(),
            random_device_descriptions: self.random_device_descriptions.clone(),
            stdout_alias_fds: self.stdout_alias_fds.clone(),
            stderr_alias_fds: self.stderr_alias_fds.clone(),
            cloexec_fds: self.cloexec_fds.clone(),
            closed_standard_fds: self.closed_standard_fds.clone(),
            children: crate::executor::ChildWaitContext::default(),
            consumed_child_wait: None,
            proc_files: self.proc_files.clone(),
            synthetic_proc_nofollow_fds: self.synthetic_proc_nofollow_fds.clone(),
            regular_create_directory_policy: self.regular_create_directory_policy,
            fdinfo_files: self.fdinfo_files.clone(),
            fdinfo_table: self.fdinfo_table.clone(),
            fd_object_inodes: self.fd_object_inodes.clone(),
            file_identity_table: self.file_identity_table.clone(),
        })
    }

    // TODO-HUMAN-REVIEW(PR-136): Review live identity filtering across exec.
    #[cfg(test)]
    pub(crate) fn inherit_process_state(&mut self, previous: Self) {
        let _retirement = previous.file_retirement.hold();
        let transaction = previous.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        let retired = self.inherit_process_state_locked(previous);
        drop(_transaction);
        self.file_retirement.retire(retired);
    }

    pub(crate) fn inherit_process_state_locked(&mut self, previous: Self) -> Vec<std::fs::File> {
        // Linux reads comm when a /proc/<pid>/stat or status descriptor is read,
        // so one opened before exec renders the new image's name. Siblings are
        // already torn down; only such descriptors still share this cell.
        let thread_group_leader_name = previous.thread_group_leader_name.clone();
        *thread_group_leader_name
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = *self
            .thread_group_leader_name
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.thread_group_leader_name = thread_group_leader_name;
        let thp_disabled =
            std::sync::Arc::new(AtomicU8::new(previous.thp_disabled.load(Ordering::SeqCst)));
        let regular_create_directory_policy = previous.regular_create_directory_policy;
        let cloexec_fds = previous.cloexec_fds;
        let native_poll_fds = {
            let _proof = previous
                .epoll_domain
                .lock()
                .expect("KVM epoll provenance lock poisoned");
            previous
                .native_poll_fds
                .into_iter()
                .filter_map(|(fd, binding)| {
                    if cloexec_fds.contains(&fd) {
                        binding.retire();
                        None
                    } else {
                        Some((fd, binding))
                    }
                })
                .collect()
        };
        let mut retired = Vec::new();
        previous
            .file_retirement
            .retire_shared(previous.executable_file);
        let mut stdin = previous.stdin;
        let mut stdin_entry_id = previous.stdin_entry_id;
        let files: std::collections::BTreeMap<_, _> = previous
            .files
            .into_iter()
            .filter_map(|(fd, file)| {
                if cloexec_fds.contains(&fd) {
                    retired.push(file);
                    None
                } else {
                    Some((fd, file))
                }
            })
            .collect();
        let fd_entry_ids = previous
            .fd_entry_ids
            .into_iter()
            .filter(|(fd, _)| files.contains_key(fd))
            .collect();
        let random_device_fds = previous
            .random_device_fds
            .into_iter()
            .filter(|fd| files.contains_key(fd))
            .collect();
        let random_device_descriptions = previous
            .random_device_descriptions
            .into_iter()
            .filter(|(fd, _)| files.contains_key(fd))
            .collect();
        let pipe_owners = previous
            .pipe_owners
            .into_iter()
            .filter(|(fd, _)| files.contains_key(fd))
            .collect();
        let stdout_alias_fds = previous
            .stdout_alias_fds
            .into_iter()
            .filter(|fd| !cloexec_fds.contains(fd) && files.contains_key(fd))
            .collect();
        let stderr_alias_fds = previous
            .stderr_alias_fds
            .into_iter()
            .filter(|fd| !cloexec_fds.contains(fd) && files.contains_key(fd))
            .collect();
        let proc_files: std::collections::BTreeMap<_, _> = previous
            .proc_files
            .into_iter()
            .filter(|(fd, _)| files.contains_key(fd))
            .collect();
        let synthetic_proc_nofollow_fds = previous
            .synthetic_proc_nofollow_fds
            .into_iter()
            .filter(|fd| files.contains_key(fd))
            .collect();
        let fdinfo_files = previous
            .fdinfo_files
            .into_iter()
            .filter(|(fd, _)| files.contains_key(fd))
            .collect();
        let fd_object_inodes: std::collections::BTreeMap<_, _> = previous
            .fd_object_inodes
            .into_iter()
            .filter(|(fd, _)| files.contains_key(fd))
            .collect();
        let task_lifecycle = previous.task_lifecycle.clone();
        let file_identity_table = previous.file_identity_table.clone();
        {
            let mut table = file_identity_table
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            table.objects.retain(|_, entry| entry.is_live());
        }
        let mut closed_standard_fds = previous.closed_standard_fds;
        if cloexec_fds.contains(&libc::STDIN_FILENO) {
            retired.extend(stdin.take());
            stdin_entry_id = std::sync::Arc::new(());
            closed_standard_fds.insert(libc::STDIN_FILENO);
        }
        for fd in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            if cloexec_fds.contains(&fd) {
                closed_standard_fds.insert(fd);
            }
        }

        // All fallible executable preparation and sibling teardown happen
        // before this transition. Serialize the pending-state snapshot and
        // endpoint replacement with senders: an accepted event cannot land in
        // the old queue after we have copied it. No file operation or callback
        // occurs while these locks are held.
        let (process_signals, thread_signals) = {
            let mut lifecycle = task_lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut process_signals = previous
                .process_signals
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .after_exec();
            let thread_signals = previous.thread_signals.after_exec();
            process_signals
                .signalfd_masks
                .retain(|fd, _| files.contains_key(fd));
            process_signals
                .signalfd_carriers
                .retain(|fd, _| files.contains_key(fd));
            lifecycle.reset_parent_death_after_exec(
                previous.tid,
                previous.capability_bounding & !previous.capability_permitted != 0,
            );
            lifecycle.reset_after_exec_with_signals(
                previous.tid,
                previous.pid,
                previous.pgid,
                &thread_signals,
            );
            (process_signals, thread_signals)
        };

        self.cwd = previous.cwd;
        retired.push(std::mem::replace(&mut self.cwd_fd, previous.cwd_fd));
        retired.extend(std::mem::replace(&mut self.stdin, stdin));
        self.stdin_entry_id = stdin_entry_id;
        self.pid = previous.pid;
        self.pgid = previous.pgid;
        self.tid = previous.tid;
        self.ppid = previous.ppid;
        self.orphan_reaper_pid = previous.orphan_reaper_pid;
        // `execve` replaces the image, never the position in the process tree.
        self.is_traced_tree_root = previous.is_traced_tree_root;
        self.signal_dequeue_failure = previous.signal_dequeue_failure;
        self.umask = previous.umask;
        self.linux_personality = previous.linux_personality;
        self.random_seed = previous.random_seed;
        self.ids_per_task = previous.ids_per_task;
        self.host_metadata_timestamps = previous.host_metadata_timestamps;
        // `thread_name` intentionally remains the replacement image's name.
        self.thp_disabled = thp_disabled;
        self.keep_capabilities = false;
        self.capability_bounding = previous.capability_bounding;
        self.capability_effective = previous.capability_bounding;
        self.capability_permitted = previous.capability_bounding;
        self.capability_inheritable = previous.capability_inheritable;
        self.capability_ambient =
            previous.capability_ambient & self.capability_permitted & self.capability_inheritable;
        self.dumpable = true;
        self.process_signals = std::sync::Arc::new(std::sync::Mutex::new(process_signals));
        self.signal_transaction = previous.signal_transaction;
        self.thread_signals = thread_signals;
        self.task_lifecycle = task_lifecycle;
        retired.extend(std::mem::replace(&mut self.files, files).into_values());
        self.file_retirement = previous.file_retirement;
        self.pipe_owner_process = previous.pipe_owner_process;
        self.pipe_owners = pipe_owners;
        self.fd_entry_ids = fd_entry_ids;
        self.epoll_domain = previous.epoll_domain;
        self.poll_table_id = previous.poll_table_id;
        self.native_poll_fds = native_poll_fds;
        self.random_device_fds = random_device_fds;
        self.random_device_descriptions = random_device_descriptions;
        self.stdout_alias_fds = stdout_alias_fds;
        self.stderr_alias_fds = stderr_alias_fds;
        self.cloexec_fds = std::collections::BTreeSet::new();
        self.closed_standard_fds = closed_standard_fds;
        self.children = previous.children;
        self.proc_files = proc_files;
        self.synthetic_proc_nofollow_fds = synthetic_proc_nofollow_fds;
        self.regular_create_directory_policy = regular_create_directory_policy;
        self.fdinfo_files = fdinfo_files;
        self.fdinfo_table = previous.fdinfo_table;
        self.fd_object_inodes = fd_object_inodes;
        self.file_identity_table = file_identity_table;
        // The caller releases both descriptor and transaction guards before close.
        retired
    }
}

// TODO-HUMAN-REVIEW(PR-92): Review script loading and executable resolution.
/// Loads `image` as exec'd by the filename `argv[0]`; see
/// [`load_static_elf_with_execfn`].
pub(crate) fn load_static_elf(
    memory: &mut GuestMemory,
    image: &[u8],
    argv: &[&str],
    envp: &[&str],
    cwd: &Path,
) -> Result<LoadedStaticElf> {
    load_static_elf_with_execfn(memory, image, None, argv, envp, cwd)
}

/// Loads `image` as `execve(execfn, argv, envp)` would. `execfn` is the
/// filename given to execve, byte for byte, which Linux copies to the top of
/// the new stack and names in `AT_EXECFN`; `None` means `argv[0]`. A `#!`
/// script keeps it: for a script Linux still records the script's filename
/// there, not the interpreter's. Given explicitly, it is also the script's
/// own argument after the interpreter (bprm->interp), whatever `argv[0]` is.
pub(crate) fn load_static_elf_with_execfn(
    memory: &mut GuestMemory,
    image: &[u8],
    execfn: Option<&[u8]>,
    argv: &[&str],
    envp: &[&str],
    cwd: &Path,
) -> Result<LoadedStaticElf> {
    initialize_regular_create_directory_policy()?;
    // TODO-HUMAN-REVIEW(PR-132): Review ELF user-map construction.
    let owner = memory.clone();
    let _transaction = owner.allocation_guard();
    begin_image(memory)?;
    let script_name = execfn.map(|execfn| String::from_utf8_lossy(execfn).into_owned());
    let result = load_executable(
        memory,
        image,
        execfn,
        script_name.as_deref(),
        argv,
        envp,
        cwd,
        0,
        None,
    );
    if result.is_err() {
        memory.clear_user_access();
    }
    result
}

pub(crate) fn load_static_elf_file(
    memory: &mut GuestMemory,
    file: File,
    argv: &[&str],
    envp: &[&str],
    cwd: &Path,
) -> Result<LoadedStaticElf> {
    initialize_regular_create_directory_policy()?;
    let image = read_file_image(&file)?;
    let invoked_path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    let owner = memory.clone();
    let _transaction = owner.allocation_guard();
    begin_image(memory)?;
    let result = load_executable(
        memory,
        &image,
        None,
        None,
        argv,
        envp,
        cwd,
        0,
        Some(Arc::new(file)),
    );
    let mut loaded = match result {
        Ok(loaded) => loaded,
        Err(error) => {
            memory.clear_user_access();
            return Err(error);
        }
    };
    let thread_name = initial_thread_name(&invoked_path);
    loaded.thread_name = thread_name;
    *loaded
        .thread_group_leader_name
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = thread_name;
    Ok(loaded)
}

// Construction is serialized with allocation but does not promise byte
// rollback. Initial-install errors release tentative ownership. Exec invokes
// this only after its existing fatal point of no return.
fn begin_image(memory: &GuestMemory) -> Result<()> {
    memory.clear_user_access();
    // The new image's layout replaces the old one whole: its identity end and
    // windows may differ (a larger image raises the identity end).
    memory.clear_user_layout();
    let end = memory.guest_end().min(BOOT_RESERVED_END);
    if end > memory.guest_base() {
        memory
            .reserve_region(
                memory.guest_base(),
                end - memory.guest_base(),
                RegionKind::Bootstrap,
            )?
            .commit();
    }
    for (start, end) in [
        (
            crate::bootstrap::TOOL_STACK_TOP - crate::bootstrap::TOOL_STACK_SIZE,
            crate::bootstrap::TOOL_STACK_TOP,
        ),
        (
            crate::bootstrap::THREAD_TOOL_STACK_AREA_START,
            BOOT_RESERVED_END,
        ),
    ] {
        let start = start.max(memory.guest_base());
        let end = end.min(memory.guest_end());
        if start < end {
            memory
                .reserve_region(start, end - start, RegionKind::ToolScratch)?
                .commit();
        }
    }
    Ok(())
}

fn read_file_image(file: &File) -> std::io::Result<Vec<u8>> {
    let mut image = Vec::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = match file.read_at(&mut buffer, image.len() as u64) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if count == 0 {
            break;
        }
        image.extend_from_slice(&buffer[..count]);
    }
    Ok(image)
}

// TODO-HUMAN-REVIEW(PR-92): Review recursive script interpreter loading.
#[allow(clippy::too_many_arguments)]
/// `script_name` is the name of the file `image` came from, as the kernel
/// passes it to a `#!` interpreter (bprm->interp): the exec filename, then
/// each interpreter's name as its script's `#!` line gives it. `None` keeps
/// the older rule: the retained file's path, else `argv[0]` resolved.
fn load_executable(
    memory: &mut GuestMemory,
    image: &[u8],
    execfn: Option<&[u8]>,
    script_name: Option<&str>,
    argv: &[&str],
    envp: &[&str],
    cwd: &Path,
    script_depth: usize,
    executable_file: Option<Arc<File>>,
) -> Result<LoadedStaticElf> {
    let argv0 = *argv
        .first()
        .ok_or_else(|| Error::UnsupportedElf("argv must contain at least argv[0]".to_string()))?;
    let execfn = execfn.unwrap_or(argv0.as_bytes());
    if let Some((interpreter, optional_argument)) = parse_shebang(image)? {
        if script_depth >= MAX_SCRIPT_INTERPRETERS {
            return Err(Error::UnsupportedElf(
                "script interpreter recursion limit exceeded".to_string(),
            ));
        }
        let script_path = if let Some(name) = script_name {
            PathBuf::from(name)
        } else if let Some(file) = executable_file.as_ref() {
            std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?
        } else {
            resolve_executable_path(argv0, envp, cwd)?
        };
        let interpreter_path = resolve_executable_path(&interpreter, envp, cwd)?;
        let read_error = |error| {
            Error::UnsupportedElf(format!(
                "cannot read script interpreter {interpreter_path:?}: {error}"
            ))
        };
        let (interpreter_image, interpreter_file) = if executable_file.is_some() {
            let file = File::open(&interpreter_path).map_err(read_error)?;
            let image = read_file_image(&file).map_err(read_error)?;
            (image, Some(Arc::new(file)))
        } else {
            (std::fs::read(&interpreter_path).map_err(read_error)?, None)
        };
        if interpreter_image.len() as u64 > MAX_INTERPRETER_BYTES {
            return Err(Error::UnsupportedElf(format!(
                "script interpreter {interpreter_path:?} exceeds {MAX_INTERPRETER_BYTES} bytes"
            )));
        }

        let mut interpreter_argv = Vec::with_capacity(argv.len() + 2);
        interpreter_argv.push(interpreter_path.to_string_lossy().into_owned());
        if let Some(argument) = optional_argument {
            interpreter_argv.push(argument);
        }
        interpreter_argv.push(script_path.to_string_lossy().into_owned());
        interpreter_argv.extend(argv.iter().skip(1).map(|argument| (*argument).to_owned()));
        let interpreter_argv = interpreter_argv
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        return load_executable(
            memory,
            &interpreter_image,
            Some(execfn),
            script_name.map(|_| interpreter.as_str()),
            &interpreter_argv,
            envp,
            cwd,
            script_depth + 1,
            interpreter_file,
        );
    }

    let elf = Elf::parse(image)?;
    validate_elf(&elf, true)?;

    for entry in argv
        .iter()
        .chain(envp.iter())
        .map(|entry| entry.as_bytes())
        .chain([execfn])
    {
        if entry.contains(&0) {
            return Err(Error::UnsupportedElf(
                "an execfn/argv/envp entry contains an embedded NUL byte".to_string(),
            ));
        }
    }

    let interpreter_image = interpreter_path(image, &elf)?
        .map(|path| read_interpreter_image(&path))
        .transpose()?;
    let interpreter = interpreter_image
        .as_deref()
        .map(|interpreter_image| -> Result<_> {
            let interpreter = Elf::parse(interpreter_image)?;
            validate_elf(&interpreter, false)?;
            if interpreter.header.e_type != ET_DYN {
                return Err(Error::UnsupportedElf(
                    "program interpreter must be ET_DYN".to_string(),
                ));
            }
            let (first, end) = load_span(&interpreter)?;
            Ok((interpreter, first, end - first))
        })
        .transpose()?;
    let brk_headroom = if interpreter.is_some() {
        INTERPRETED_BRK_HEADROOM
    } else {
        STATIC_BRK_HEADROOM
    };
    let interpreter_span = interpreter.as_ref().map(|(_, _, span)| *span);

    // An interpreted PIE main image loads where Linux loads it (ELF_ET_DYN_BASE
    // rounded to its alignment) in its own window carved out of identity
    // memory, with its program break; identity memory then holds no image, so
    // the layout is chosen before the image loads. A non-PIE image, an
    // ET_DYN image without an interpreter (a static PIE, which Linux places
    // through mmap instead; not modelled), or a PIE in memory too small for its
    // window loads in identity memory (an ET_DYN at MAIN_LOAD_BIAS), and the
    // layout follows it.
    let mut pie_window = None;
    let mut layout = None;
    let mut pie_start = 0;
    if elf.header.e_type == ET_DYN
        && interpreter.is_some()
        && let Some(mut pie_layout) =
            establish_linux_layout(memory, BOOT_RESERVED_END, 0, interpreter_span)?
    {
        let (first, end) = load_span(&elf)?;
        pie_start = interpreted_pie_start(&elf)?;
        pie_window = establish_pie_window(
            memory,
            &mut pie_layout,
            pie_start,
            end - first,
            brk_headroom,
        )?;
        if pie_window.is_some() {
            layout = Some(pie_layout);
        } else {
            memory.clear_user_layout();
        }
    }
    // A PIE's image is relocated relative to its first loaded page, which
    // lands at user `pie_start`; an image linked above that moves down, so
    // its user bias may wrap (it is only ever added to linked addresses).
    let (main_first, _) = load_span(&elf)?;
    let (main_bias, main_end) = match &pie_window {
        Some(window) => {
            let physical_start = window.physical_start + (pie_start - window.user_start);
            let physical_end = load_segments_relocated(memory, image, &elf, &|address| {
                address.checked_sub(main_first)?.checked_add(physical_start)
            })?;
            (
                pie_start.wrapping_sub(main_first),
                pie_start + (physical_end - physical_start),
            )
        }
        None => {
            let bias = if elf.header.e_type == ET_DYN {
                MAIN_LOAD_BIAS
            } else {
                0
            };
            (bias, load_segments(memory, image, &elf, bias)?)
        }
    };
    // The user address of a linked address in the main image.
    let user_address = |address: u64| {
        if pie_window.is_some() {
            Some(main_bias.wrapping_add(address))
        } else {
            main_bias.checked_add(address)
        }
    };
    // Linux's end_data: the highest end of a PT_LOAD segment's file contents.
    let min_break = elf
        .program_headers
        .iter()
        .filter(|header| header.p_type == PT_LOAD)
        .map(|header| {
            user_address(header.p_vaddr)
                .and_then(|start| start.checked_add(header.p_filesz))
                .ok_or_else(|| Error::UnsupportedElf("PT_LOAD address overflow".to_string()))
        })
        .try_fold(BOOT_RESERVED_END, |end, segment| {
            Ok::<_, Error>(end.max(segment?))
        })?;
    let main_entry = user_address(elf.entry)
        .ok_or_else(|| Error::UnsupportedElf("main entry point overflow".to_string()))?;
    let layout = match layout {
        Some(layout) => Some(layout),
        None => establish_linux_layout(memory, main_end, brk_headroom, interpreter_span)?,
    };

    let (entry_point, at_base) = match (&interpreter, &layout) {
        (Some((interpreter, first, span)), Some(layout)) => {
            // Linux maps the interpreter (ld.so) first, top-down below
            // mmap_base, so it sits at the top of the mmap window whatever the
            // main image's size. Its first segment may lie at any address the
            // window can be biased down to.
            let bias_error = || {
                Error::UnsupportedElf("interpreter segments lie above the mmap window".to_string())
            };
            let user_bias = (layout.mmap_user_end - span)
                .checked_sub(*first)
                .ok_or_else(bias_error)?;
            let physical_start = layout.mmap_end - span;
            let physical_bias = physical_start.checked_sub(*first).ok_or_else(bias_error)?;
            load_segments(
                memory,
                interpreter_image.as_deref().unwrap_or_default(),
                interpreter,
                physical_bias,
            )?;
            reserve_vdso_gap(memory, physical_start)?;
            let interpreter_entry = user_bias.checked_add(interpreter.entry).ok_or_else(|| {
                Error::UnsupportedElf("interpreter entry point overflow".to_string())
            })?;
            (interpreter_entry, user_bias)
        }
        (None, Some(layout)) => {
            reserve_vdso_gap(memory, layout.mmap_end)?;
            (main_entry, 0)
        }
        (None, None) => (main_entry, 0),
        (Some(_), None) => unreachable!("a dynamic program always gets a window"),
    };

    let program_headers_address = elf
        .program_headers
        .iter()
        .find(|header| header.p_type == goblin::elf::program_header::PT_PHDR)
        .and_then(|header| user_address(header.p_vaddr))
        .unwrap_or(PROGRAM_HEADERS_ADDRESS);
    memory
        .reserve_region(
            PROGRAM_HEADERS_ADDRESS,
            PAGE_SIZE,
            RegionKind::ProgramHeaders,
        )?
        .commit();
    copy_program_headers(memory, image, &elf)?;
    if program_headers_address == PROGRAM_HEADERS_ADDRESS {
        memory.map_user_range(PROGRAM_HEADERS_ADDRESS, PAGE_SIZE, false)?;
    }
    let stack_start = memory
        .guest_end()
        .checked_sub(STACK_LIMIT)
        .ok_or(Error::LongModeMemoryTooSmall)?;
    memory
        .reserve_region(stack_start, STACK_LIMIT, RegionKind::Stack)?
        .commit();
    crate::bootstrap::map_user_stack_window(memory, STACK_LIMIT)?;
    let (stack_pointer, auxv) = build_initial_stack(
        memory,
        &elf,
        execfn,
        argv,
        envp,
        program_headers_address,
        at_base,
        main_entry,
    )?;
    memory.map_user_range(memory.guest_end() - STACK_LIMIT, STACK_LIMIT, false)?;
    let program_break = align_up(main_end, PAGE_SIZE)?;
    // Mappings are placed top-down in the mmap window, [mmap_base, mmap_limit)
    // physically; the program break grows up to the end of the identity
    // addresses, below the window. Without a window (a static program in
    // memory too small for one) mappings are placed bottom-up above the
    // program break's headroom, below the stack, as before the window existed.
    let (mmap_next, mmap_limit) = match &layout {
        Some(layout) => (layout.mmap_start, layout.mmap_end),
        None => (
            align_up(
                main_end.checked_add(STATIC_BRK_HEADROOM).ok_or_else(|| {
                    Error::UnsupportedElf("program break headroom overflow".to_string())
                })?,
                PAGE_SIZE,
            )?,
            stack_start,
        ),
    };
    // The program break grows to the end of the identity addresses, or of the
    // PIE window.
    let brk_limit = match (&pie_window, &layout) {
        (Some(window), _) => window.user_end(),
        (None, Some(layout)) => layout.identity_end,
        (None, None) => mmap_next,
    };

    let cwd_fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open(cwd)?;

    let executable_path = if let Some(file) = executable_file.as_ref() {
        std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?
    } else {
        resolve_executable_path(argv0, envp, cwd).unwrap_or_else(|_| PathBuf::from(argv0))
    };
    let thread_name = initial_thread_name(&executable_path);
    let argv0 = argv0.as_bytes().to_vec();

    memory.set_allocation_cursors(AllocationCursors {
        program_break,
        mmap_base: mmap_next,
        mmap_next,
        mmap_limit,
    });
    Ok(LoadedStaticElf {
        entry_point,
        stack_pointer,
        heap_base: program_break,
        min_break,
        program_break,
        brk_limit,
        mmap_base: mmap_next,
        mmap_next,
        mmap_limit,
        executable_path,
        executable_file,
        executable_image: std::sync::Arc::from(image),
        argv0,
        cwd: cwd.to_owned(),
        cwd_fd,
        stdin: None,
        stdin_entry_id: std::sync::Arc::new(()),
        auxv,
        fs_base: 0,
        gs_base: 0,
        pid: 1,
        pipe_owner_process: std::sync::Arc::new(()),
        pgid: 1,
        tid: 1,
        ppid: 0,
        orphan_reaper_pid: std::sync::Arc::new(AtomicI32::new(0)),
        // The backend-installed image is the root of the traced process tree.
        // `KvmBackend::set_root_pid` may later renumber `pid`/`tid`/`ppid`; it
        // must not change this.
        is_traced_tree_root: true,
        umask: 0o022,
        linux_personality: LINUX_FIXED_PERSONALITY,
        random_seed: 0,
        ids_per_task: reverie::task_ids::LINUX_IDS_PER_TASK,
        host_metadata_timestamps: false,
        thread_name,
        thread_group_leader_name: std::sync::Arc::new(std::sync::Mutex::new(thread_name)),
        thp_disabled: std::sync::Arc::new(AtomicU8::new(0)),
        keep_capabilities: false,
        capability_effective: GUEST_CAPABILITY_MASK,
        capability_permitted: GUEST_CAPABILITY_MASK,
        capability_inheritable: 0,
        capability_bounding: GUEST_CAPABILITY_MASK,
        capability_ambient: 0,
        dumpable: true,
        process_signals: std::sync::Arc::new(std::sync::Mutex::new(ProcessSignalState::default())),
        signal_transaction: Default::default(),
        thread_signals: SharedThreadSignalState::default(),
        signal_dequeue_failure: None,
        task_lifecycle: std::sync::Arc::new(std::sync::Mutex::new(TaskLifecycleTable::with_root(
            1, 1, 1, true,
        ))),
        files: std::collections::BTreeMap::new(),
        file_retirement: FileRetirement::default(),
        signal_refusal: None,
        pipe_owners: Default::default(),
        fd_entry_ids: std::collections::BTreeMap::new(),
        epoll_domain: Default::default(),
        poll_table_id: Default::default(),
        native_poll_fds: Default::default(),
        random_device_fds: std::collections::BTreeSet::new(),
        random_device_descriptions: std::collections::BTreeMap::new(),
        stdout_alias_fds: std::collections::BTreeSet::new(),
        stderr_alias_fds: std::collections::BTreeSet::new(),
        cloexec_fds: std::collections::BTreeSet::new(),
        closed_standard_fds: std::collections::BTreeSet::new(),
        children: crate::executor::ChildWaitContext::default(),
        consumed_child_wait: None,
        proc_files: std::collections::BTreeMap::new(),
        synthetic_proc_nofollow_fds: std::collections::BTreeSet::new(),
        regular_create_directory_policy: initialize_regular_create_directory_policy()?,
        fdinfo_files: std::collections::BTreeMap::new(),
        fdinfo_table: std::sync::Weak::new(),
        fd_object_inodes: std::collections::BTreeMap::new(),
        file_identity_table: std::sync::Arc::new(std::sync::Mutex::new(GuestFileIdentityTable {
            inotify_cookies: crate::executor::InotifyCookieTable::default(),
            next_inode: 0x2100_0000,
            objects: std::collections::BTreeMap::new(),
            proc_transfers: std::collections::BTreeMap::new(),
        })),
    })
}

pub(crate) fn initial_thread_name(executable_path: &Path) -> [u8; TASK_COMM_LEN] {
    let basename = executable_path
        .file_name()
        .unwrap_or(executable_path.as_os_str())
        .as_bytes();
    let mut name = [0; TASK_COMM_LEN];
    let length = basename.len().min(TASK_COMM_LEN - 1);
    name[..length].copy_from_slice(&basename[..length]);
    name
}

// TODO-HUMAN-REVIEW(PR-92): Review Linux shebang parsing limits.
fn parse_shebang(image: &[u8]) -> Result<Option<(String, Option<String>)>> {
    let Some(rest) = image.strip_prefix(b"#!") else {
        return Ok(None);
    };
    let line = rest.split(|byte| *byte == b'\n').next().unwrap_or(rest);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let line = std::str::from_utf8(line)
        .map_err(|_| Error::UnsupportedElf("script shebang is not UTF-8".to_string()))?
        .trim_matches([' ', '\t']);
    let split = line.find([' ', '\t']).unwrap_or(line.len());
    let interpreter = line[..split].to_string();
    if interpreter.is_empty() {
        return Err(Error::UnsupportedElf(
            "script shebang has no interpreter".to_string(),
        ));
    }
    let argument = line[split..].trim_matches([' ', '\t']);
    Ok(Some((
        interpreter,
        (!argument.is_empty()).then(|| argument.to_string()),
    )))
}

// TODO-HUMAN-REVIEW(PR-92): Review PATH and cwd executable resolution.
pub(crate) fn resolve_executable_path(argv0: &str, envp: &[&str], cwd: &Path) -> Result<PathBuf> {
    let path = Path::new(argv0);
    if path.is_absolute() || path.components().count() > 1 {
        let candidate = if path.is_absolute() {
            path.to_owned()
        } else {
            cwd.join(path)
        };
        return candidate.canonicalize().map_err(|error| {
            Error::UnsupportedElf(format!("cannot resolve executable {candidate:?}: {error}"))
        });
    }

    let search_path = envp
        .iter()
        .find_map(|entry| entry.strip_prefix("PATH="))
        .unwrap_or("/usr/local/bin:/usr/bin:/bin");
    for directory in std::env::split_paths(search_path) {
        let directory = if directory.is_absolute() {
            directory
        } else {
            cwd.join(directory)
        };
        let candidate = directory.join(path);
        if candidate.is_file() {
            return candidate.canonicalize().map_err(|error| {
                Error::UnsupportedElf(format!("cannot resolve executable {candidate:?}: {error}"))
            });
        }
    }
    Err(Error::UnsupportedElf(format!(
        "cannot resolve executable {argv0:?} in PATH"
    )))
}

fn validate_elf(elf: &Elf<'_>, allow_interpreter: bool) -> Result<()> {
    if elf.header.e_ident[EI_CLASS] != ELFCLASS64
        || elf.header.e_ident[EI_DATA] != ELFDATA2LSB
        || elf.header.e_machine != EM_X86_64
    {
        return Err(Error::UnsupportedElf(
            "expected a little-endian ELF64 x86-64 image".to_string(),
        ));
    }
    if elf.header.e_type != ET_EXEC && elf.header.e_type != ET_DYN {
        return Err(Error::UnsupportedElf(
            "only ET_EXEC and ET_DYN images are supported".to_string(),
        ));
    }
    if !allow_interpreter
        && elf
            .program_headers
            .iter()
            .any(|header| header.p_type == PT_INTERP)
    {
        return Err(Error::UnsupportedElf(
            "nested PT_INTERP is not supported".to_string(),
        ));
    }
    if !elf
        .program_headers
        .iter()
        .any(|header| header.p_type == PT_LOAD)
    {
        return Err(Error::UnsupportedElf(
            "image contains no PT_LOAD segments".to_string(),
        ));
    }
    Ok(())
}

fn interpreter_path(image: &[u8], elf: &Elf<'_>) -> Result<Option<String>> {
    let Some(header) = elf
        .program_headers
        .iter()
        .find(|header| header.p_type == PT_INTERP)
    else {
        return Ok(None);
    };
    let start = usize::try_from(header.p_offset)
        .map_err(|_| Error::UnsupportedElf("PT_INTERP offset is too large".to_string()))?;
    let size = usize::try_from(header.p_filesz)
        .map_err(|_| Error::UnsupportedElf("PT_INTERP size is too large".to_string()))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| Error::UnsupportedElf("PT_INTERP range overflow".to_string()))?;
    let bytes = image
        .get(start..end)
        .ok_or_else(|| Error::UnsupportedElf("PT_INTERP extends past the image".to_string()))?;
    let Some(bytes) = bytes.strip_suffix(&[0]) else {
        return Err(Error::UnsupportedElf(
            "PT_INTERP path is not NUL-terminated".to_string(),
        ));
    };
    if bytes.contains(&0) {
        return Err(Error::UnsupportedElf(
            "PT_INTERP path contains an embedded NUL".to_string(),
        ));
    }
    let path = std::str::from_utf8(bytes)
        .map_err(|_| Error::UnsupportedElf("PT_INTERP path is not UTF-8".to_string()))?;
    Ok(Some(path.to_string()))
}

fn read_interpreter_image(path: &str) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).map_err(|error| {
        Error::UnsupportedElf(format!("cannot open interpreter {path:?}: {error}"))
    })?;
    let metadata = file.metadata().map_err(|error| {
        Error::UnsupportedElf(format!("cannot stat interpreter {path:?}: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(Error::UnsupportedElf(format!(
            "interpreter {path:?} is not a regular file",
        )));
    }
    if metadata.len() > MAX_INTERPRETER_BYTES {
        return Err(Error::UnsupportedElf(format!(
            "interpreter {path:?} exceeds {MAX_INTERPRETER_BYTES} bytes",
        )));
    }

    let mut image = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_INTERPRETER_BYTES + 1)
        .read_to_end(&mut image)
        .map_err(|error| {
            Error::UnsupportedElf(format!("cannot read interpreter {path:?}: {error}"))
        })?;
    if image.len() as u64 > MAX_INTERPRETER_BYTES {
        return Err(Error::UnsupportedElf(format!(
            "interpreter {path:?} exceeds {MAX_INTERPRETER_BYTES} bytes",
        )));
    }
    Ok(image)
}

/// Loads `elf`'s PT_LOAD segments at physical `physical_bias + p_vaddr` and
/// returns the physical end of the image. The caller decides the user address
/// those pages have (the same for a non-PIE image; a window's for ld.so).
fn load_segments(
    memory: &mut GuestMemory,
    image: &[u8],
    elf: &Elf<'_>,
    physical_bias: u64,
) -> Result<u64> {
    load_segments_relocated(memory, image, elf, &|address| {
        physical_bias.checked_add(address)
    })
}

/// [`load_segments`], placing each linked address where `relocate` puts it
/// (`None` refuses it). A PIE window's image relocates relative to its first
/// segment, so an image linked above where it lands moves down without
/// wrapping arithmetic.
fn load_segments_relocated(
    memory: &mut GuestMemory,
    image: &[u8],
    elf: &Elf<'_>,
    relocate: &dyn Fn(u64) -> Option<u64>,
) -> Result<u64> {
    let entry = relocate(elf.entry)
        .ok_or_else(|| Error::UnsupportedElf("ELF entry point overflow".to_string()))?;
    let mut image_end = 0;
    let mut entry_is_executable = false;
    for header in elf
        .program_headers
        .iter()
        .filter(|header| header.p_type == PT_LOAD)
    {
        if header.p_filesz > header.p_memsz {
            return Err(Error::UnsupportedElf(format!(
                "PT_LOAD filesz {:#x} exceeds memsz {:#x}",
                header.p_filesz, header.p_memsz
            )));
        }

        let segment_start = relocate(header.p_vaddr)
            .ok_or_else(|| Error::UnsupportedElf("PT_LOAD address overflow".to_string()))?;
        let segment_end = segment_start
            .checked_add(header.p_memsz)
            .ok_or_else(|| Error::UnsupportedElf("PT_LOAD address overflow".to_string()))?;
        if segment_start < BOOT_RESERVED_END && segment_end > 0 {
            return Err(Error::UnsupportedElf(format!(
                "PT_LOAD {segment_start:#x}..{segment_end:#x} overlaps bootstrap memory"
            )));
        }

        let file_start = usize::try_from(header.p_offset)
            .map_err(|_| Error::UnsupportedElf("PT_LOAD offset is too large".to_string()))?;
        let file_size = usize::try_from(header.p_filesz)
            .map_err(|_| Error::UnsupportedElf("PT_LOAD filesz is too large".to_string()))?;
        let file_end = file_start
            .checked_add(file_size)
            .ok_or_else(|| Error::UnsupportedElf("PT_LOAD file range overflow".to_string()))?;
        let contents = image.get(file_start..file_end).ok_or_else(|| {
            Error::UnsupportedElf("PT_LOAD extends past the ELF image".to_string())
        })?;

        let reserved_start = segment_start & !(PAGE_SIZE - 1);
        let reserved_end = align_up(segment_end, PAGE_SIZE)?;
        memory
            .reserve_region(
                reserved_start,
                reserved_end - reserved_start,
                RegionKind::Elf,
            )?
            .commit();
        memory.write_raw(segment_start, contents)?;
        let zero_start = segment_start + header.p_filesz;
        let zero_len = usize::try_from(header.p_memsz - header.p_filesz)
            .map_err(|_| Error::UnsupportedElf("PT_LOAD memsz is too large".to_string()))?;
        memory.zero_raw(zero_start, zero_len)?;
        let mapped_start = segment_start & !(PAGE_SIZE - 1);
        let mapped_end = align_up(segment_end, PAGE_SIZE)?;
        let file_end = align_up(zero_start, PAGE_SIZE)?;
        if header.p_filesz != 0 {
            memory.map_user_permissions(
                mapped_start,
                file_end - mapped_start,
                true,
                header.p_flags & PF_W != 0,
            )?;
            // The file-backed pages map the image file from the segment's
            // page-aligned offset, as Linux maps them.
            memory.record_file_pages(
                mapped_start,
                file_end - mapped_start,
                Some(header.p_offset & !(PAGE_SIZE - 1)),
            );
        }
        if header.p_memsz > header.p_filesz {
            let anonymous_start = if header.p_filesz == 0 {
                mapped_start
            } else {
                file_end
            };
            memory.map_user_range(anonymous_start, mapped_end - anonymous_start, false)?;
        }

        entry_is_executable |=
            header.p_flags & PF_X != 0 && (segment_start..segment_end).contains(&entry);
        image_end = image_end.max(segment_end);
    }

    if !entry_is_executable {
        return Err(Error::UnsupportedElf(
            "entry point is not inside an executable PT_LOAD segment".to_string(),
        ));
    }
    Ok(image_end)
}

fn copy_program_headers(memory: &mut GuestMemory, image: &[u8], elf: &Elf<'_>) -> Result<()> {
    let start = usize::try_from(elf.header.e_phoff)
        .map_err(|_| Error::UnsupportedElf("program-header offset is too large".to_string()))?;
    let size = usize::from(elf.header.e_phentsize)
        .checked_mul(usize::from(elf.header.e_phnum))
        .ok_or_else(|| Error::UnsupportedElf("program-header size overflow".to_string()))?;
    if size > MAX_PROGRAM_HEADERS_SIZE {
        return Err(Error::UnsupportedElf(
            "program-header table exceeds one page".to_string(),
        ));
    }
    let end = start
        .checked_add(size)
        .ok_or_else(|| Error::UnsupportedElf("program-header range overflow".to_string()))?;
    let headers = image.get(start..end).ok_or_else(|| {
        Error::UnsupportedElf("program-header table extends past the image".to_string())
    })?;
    memory.write_raw(PROGRAM_HEADERS_ADDRESS, headers)
}

#[allow(clippy::too_many_arguments)]
fn build_initial_stack(
    memory: &mut GuestMemory,
    elf: &Elf<'_>,
    execfn: &[u8],
    argv: &[&str],
    envp: &[&str],
    program_headers_address: u64,
    at_base: u64,
    at_entry: u64,
) -> Result<(u64, Vec<(libc::c_ulong, libc::c_ulong)>)> {
    // Linux's layout (fs/exec.c, then create_elf_tables in fs/binfmt_elf.c)
    // with address randomization off, at its addresses, so pointers the guest
    // sees match a traced guest's: from the top of the user address space down,
    // an 8-byte NULL, the exec filename, the envp strings and the argv strings
    // (so argv[0] is lowest and the strings ascend argv, envp, execfn), then,
    // below argv[0] rounded down to 16 bytes, the platform string, the
    // AT_RANDOM bytes, and the 16-byte-aligned pointer arrays and auxv.
    // Addresses here are user addresses in the stack window.
    let bottom = USER_ADDRESS_END - STACK_LIMIT;
    let mut cursor = USER_STACK_TOP - std::mem::size_of::<u64>() as u64;
    write_user_stack(memory, cursor, &[0; 8])?;

    // AT_EXECFN names the filename given to execve (bprm->filename), which
    // for a `#!` script is the script's, not the interpreter's.
    cursor = push_c_string(memory, cursor, execfn)?;
    let execfn_address = cursor;
    let mut env_addresses = vec![0; envp.len()];
    for (index, entry) in envp.iter().enumerate().rev() {
        cursor = push_c_string(memory, cursor, entry.as_bytes())?;
        env_addresses[index] = cursor;
    }
    let mut arg_addresses = vec![0; argv.len()];
    for (index, arg) in argv.iter().enumerate().rev() {
        cursor = push_c_string(memory, cursor, arg.as_bytes())?;
        arg_addresses[index] = cursor;
    }

    cursor &= !0xf;
    cursor = push_c_string(memory, cursor, GUEST_PLATFORM)?;
    let platform_address = cursor;

    let random = [
        0x52, 0x65, 0x76, 0x65, 0x72, 0x69, 0x65, 0x2d, 0x4b, 0x56, 0x4d, 0x2d, 0x45, 0x4c, 0x46,
        0x21,
    ];
    cursor = cursor
        .checked_sub(random.len() as u64)
        .ok_or(Error::LongModeMemoryTooSmall)?;
    write_user_stack(memory, cursor, &random)?;
    let random_address = cursor;

    // Build the SysV initial stack image, low to high:
    //   argc, argv[0..], NULL, envp[0..], NULL, auxv pairs.., AT_NULL/0
    // The canonical AT_MINSIGSTKSZ must also bound this host, as it must for a
    // traced guest on it.
    reverie::check_host_minsigstksz(unsafe { libc::getauxval(reverie::AT_MINSIGSTKSZ) })
        .map_err(Error::UnsupportedHost)?;
    let auxv = guest_auxv(&GuestAuxvValues {
        program_headers: program_headers_address,
        program_header_size: u64::from(elf.header.e_phentsize),
        program_header_count: u64::from(elf.header.e_phnum),
        base: at_base,
        entry: at_entry,
        random: random_address,
        execfn: execfn_address,
        platform: platform_address,
    });

    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64);
    words.extend_from_slice(&arg_addresses);
    words.push(0);
    words.extend_from_slice(&env_addresses);
    words.push(0);
    for (key, value) in &auxv {
        words.extend_from_slice(&[*key, *value]);
    }
    words.extend_from_slice(&[AT_NULL, 0]);

    let stack_size = (words.len() * std::mem::size_of::<u64>()) as u64;
    // The kernel enters `_start` with `%rsp` 16-byte aligned and argc at [rsp].
    cursor = cursor
        .checked_sub(stack_size)
        .ok_or(Error::LongModeMemoryTooSmall)?
        & !0xf;
    if cursor < bottom {
        return Err(Error::LongModeMemoryTooSmall);
    }

    let mut stack = Vec::with_capacity(stack_size as usize);
    for word in words {
        stack.extend_from_slice(&word.to_le_bytes());
    }
    write_user_stack(memory, cursor, &stack)?;
    Ok((cursor, auxv))
}

/// Writes `bytes` at user address `address` in the stack window.
fn write_user_stack(memory: &mut GuestMemory, address: u64, bytes: &[u8]) -> Result<()> {
    let physical = memory
        .user_range_to_guest(address, bytes.len() as u64)
        .ok_or(Error::LongModeMemoryTooSmall)?;
    memory.write_raw(physical, bytes)
}

/// Writes a NUL-terminated copy of `bytes` ending just below `cursor` and
/// returns the guest address of the first byte (the new, lower cursor).
fn push_c_string(memory: &mut GuestMemory, cursor: u64, bytes: &[u8]) -> Result<u64> {
    let start = cursor
        .checked_sub((bytes.len() + 1) as u64)
        .ok_or(Error::LongModeMemoryTooSmall)?;
    write_user_stack(memory, start, bytes)?;
    write_user_stack(memory, start + bytes.len() as u64, &[0])?;
    Ok(start)
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or_else(|| Error::UnsupportedElf("address alignment overflow".to_string()))
}

/// The physical layout of a loaded guest (see the K2 design note).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LinuxLayout {
    /// The end of the identity user addresses (boot area, a non-PIE image, the
    /// program break).
    pub(crate) identity_end: u64,
    /// The physical start of the mmap window: `identity_end`, or the PIE
    /// window's end when there is one.
    pub(crate) mmap_start: u64,
    /// The physical end of the mmap window.
    pub(crate) mmap_end: u64,
    /// The window's user end: `MMAP_BASE`, unless memory is too tight for that
    /// (see `establish_linux_layout`).
    pub(crate) mmap_user_end: u64,
}

/// Places the mmap window between the identity addresses and the stack window
/// and ends the identity user addresses at its start. The window's user end is
/// `MMAP_BASE`, and its physical end agrees with `MMAP_BASE` modulo a large
/// page, so alignment decisions are the same in both and the window maps with
/// large pages. The window takes a quarter of guest memory, or more if it must
/// hold an interpreter of `interpreter_span` bytes and the vDSO gap; less when
/// the main image and `brk_headroom` of program-break growth above it need
/// more. The identity addresses keep the rest, so MAP_FIXED and the program
/// break reach as much memory as the window leaves.
///
/// When memory is too tight for a window ending at the highest such physical
/// address, the window ends at the stack window's start instead, with its user
/// end moved down below `MMAP_BASE` (by less than a large page) to keep the
/// agreement. When even that cannot hold the interpreter and the vDSO gap, a
/// static program (no `interpreter_span`) keeps the identity layout memory had
/// before the mmap window (`None`); a dynamic one is refused.
pub(crate) fn establish_linux_layout(
    memory: &mut GuestMemory,
    main_end: u64,
    brk_headroom: u64,
    interpreter_span: Option<u64>,
) -> Result<Option<LinuxLayout>> {
    let stack_start = memory
        .guest_end()
        .checked_sub(STACK_LIMIT)
        .ok_or(Error::LongModeMemoryTooSmall)?;
    let heap_end = align_up(
        main_end
            .checked_add(brk_headroom)
            .ok_or_else(|| Error::UnsupportedElf("program break headroom overflow".to_string()))?,
        PAGE_SIZE,
    )?;
    let needed = interpreter_span
        .unwrap_or(0)
        .checked_add(VDSO_GAP + PAGE_SIZE)
        .ok_or_else(|| Error::UnsupportedElf("interpreter span overflow".to_string()))?;
    // The page tables keep the first large page (the boot area) identity mapped.
    let floor = heap_end.max(LARGE_PAGE_SIZE);
    let fits = |end: u64| floor.checked_add(needed).is_some_and(|need| need <= end);
    let candidate = stack_start / LARGE_PAGE_SIZE * LARGE_PAGE_SIZE + MMAP_BASE % LARGE_PAGE_SIZE;
    let preferred = if candidate <= stack_start {
        Some(candidate)
    } else {
        candidate.checked_sub(LARGE_PAGE_SIZE)
    };
    let mmap_end = match preferred {
        Some(end) if fits(end) => end,
        _ if fits(stack_start) => stack_start,
        _ if interpreter_span.is_none() && heap_end < stack_start => return Ok(None),
        _ => return Err(Error::LongModeMemoryTooSmall),
    };
    let mmap_user_end = MMAP_BASE - (MMAP_BASE - mmap_end) % LARGE_PAGE_SIZE;
    let window = (memory.guest_end() / 4).max(needed);
    let identity_end =
        (mmap_end.saturating_sub(window) / LARGE_PAGE_SIZE * LARGE_PAGE_SIZE).max(floor);
    memory.establish_user_window(UserWindow {
        physical_start: identity_end,
        physical_end: mmap_end,
        user_start: mmap_user_end - (mmap_end - identity_end),
        user_end: mmap_user_end,
    })?;
    memory.set_user_identity_end(identity_end);
    Ok(Some(LinuxLayout {
        identity_end,
        mmap_start: identity_end,
        mmap_end,
        mmap_user_end,
    }))
}

/// A PIE main image's window: physical memory just below the mmap window,
/// mapped at `user_start` (the large page holding the image's start), holding
/// the image and its program break.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PieWindow {
    pub(crate) physical_start: u64,
    pub(crate) physical_end: u64,
    pub(crate) user_start: u64,
}

impl PieWindow {
    pub(crate) fn user_end(&self) -> u64 {
        self.user_start + (self.physical_end - self.physical_start)
    }
}

/// The user address of an interpreted PIE's first loaded page, as Linux's
/// load_elf_binary picks it with randomization off: ELF_ET_DYN_BASE rounded
/// down to the largest power-of-two PT_LOAD alignment (maximum_alignment, at
/// least a page), less the first PT_LOAD's address, page-aligned down; plus
/// that segment's page.
fn interpreted_pie_start(elf: &Elf<'_>) -> Result<u64> {
    let loads = || {
        elf.program_headers
            .iter()
            .filter(|header| header.p_type == PT_LOAD)
    };
    let alignment = loads()
        .map(|header| header.p_align)
        .filter(|align| align.is_power_of_two())
        .max()
        .unwrap_or(0)
        .max(PAGE_SIZE);
    let base = PIE_BASE & !(alignment - 1);
    let first = loads()
        .next()
        .ok_or_else(|| Error::UnsupportedElf("ELF has no PT_LOAD segment".to_string()))?
        .p_vaddr;
    // The bias wraps for an image linked above the base; adding the first
    // page back undoes the wrap. establish_pie_window bounds the result.
    let bias = base.wrapping_sub(first) & !(PAGE_SIZE - 1);
    let (first_page, _) = load_span(elf)?;
    Ok(bias.wrapping_add(first_page))
}

/// Carves the PIE window for an image of `span` bytes starting at user
/// `image_start` out of the top of the identity memory `layout` left below
/// the mmap window, and ends the identity addresses at its start. The window
/// starts at the large page holding `image_start` and holds the image and
/// room for the program break: a quarter of guest memory, or as little as
/// `brk_headroom` when memory is tight. Both ends are large-page aligned, so
/// the window maps with large pages. `None` when even that does not fit above
/// the first large page; the image then loads in identity memory, as before
/// the window existed.
pub(crate) fn establish_pie_window(
    memory: &mut GuestMemory,
    layout: &mut LinuxLayout,
    image_start: u64,
    span: u64,
    brk_headroom: u64,
) -> Result<Option<PieWindow>> {
    let user_start = image_start & !(LARGE_PAGE_SIZE - 1);
    let image = (image_start - user_start)
        .checked_add(span)
        .ok_or_else(|| Error::UnsupportedElf("PIE span overflow".to_string()))?;
    let size = |headroom: u64| {
        image
            .checked_add(headroom)
            .ok_or_else(|| Error::UnsupportedElf("PIE span overflow".to_string()))
            .and_then(|size| align_up(size, LARGE_PAGE_SIZE))
    };
    let end = layout.mmap_start / LARGE_PAGE_SIZE * LARGE_PAGE_SIZE;
    let preferred = size((memory.guest_end() / 4).max(brk_headroom))?;
    let least = size(brk_headroom)?;
    let start = end.saturating_sub(preferred).max(LARGE_PAGE_SIZE);
    if end < start
        || end - start < least
        || user_start
            .checked_add(end - start)
            .is_none_or(|end| end > MMAP_BASE)
    {
        return Ok(None);
    }
    memory.establish_user_window(UserWindow {
        physical_start: start,
        physical_end: end,
        user_start,
        user_end: user_start + (end - start),
    })?;
    memory.set_user_identity_end(start);
    layout.identity_end = start;
    Ok(Some(PieWindow {
        physical_start: start,
        physical_end: end,
        user_start,
    }))
}

/// The page-aligned span `[first, end)` of `elf`'s PT_LOAD segments.
fn load_span(elf: &Elf<'_>) -> Result<(u64, u64)> {
    let loads = elf
        .program_headers
        .iter()
        .filter(|header| header.p_type == PT_LOAD);
    let first = loads
        .clone()
        .map(|header| header.p_vaddr & !(PAGE_SIZE - 1))
        .min()
        .ok_or_else(|| Error::UnsupportedElf("ELF has no PT_LOAD segment".to_string()))?;
    let mut end = 0;
    for header in loads {
        end = end.max(align_up(
            header
                .p_vaddr
                .checked_add(header.p_memsz)
                .ok_or_else(|| Error::UnsupportedElf("PT_LOAD address overflow".to_string()))?,
            PAGE_SIZE,
        )?);
    }
    Ok((first, end))
}

/// Reserves the host vDSO pages' range ([`VDSO_GAP`]) just below physical
/// `below`, inaccessible, so mappings are placed around it as on the host.
pub(crate) fn reserve_vdso_gap(memory: &mut GuestMemory, below: u64) -> Result<()> {
    let start = below
        .checked_sub(VDSO_GAP)
        .ok_or(Error::LongModeMemoryTooSmall)?;
    memory
        .reserve_region(start, VDSO_GAP, RegionKind::Mmap)?
        .commit();
    memory.map_user_permissions(start, VDSO_GAP, false, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MEMORY_SIZE: usize = 16 * 1024 * 1024;
    const TEST_LOAD_ADDRESS: u64 = 0x20_0000;
    const TEST_CODE_OFFSET: usize = 0x1000;

    fn test_static_elf(code: &[u8]) -> Vec<u8> {
        let mut image = vec![0; TEST_CODE_OFFSET + code.len()];

        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = ELFCLASS64;
        image[5] = ELFDATA2LSB;
        image[6] = 1;
        image[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        image[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        image[20..24].copy_from_slice(&1_u32.to_le_bytes());
        image[24..32].copy_from_slice(&TEST_LOAD_ADDRESS.to_le_bytes());
        image[32..40].copy_from_slice(&64_u64.to_le_bytes());
        image[52..54].copy_from_slice(&64_u16.to_le_bytes());
        image[54..56].copy_from_slice(&56_u16.to_le_bytes());
        image[56..58].copy_from_slice(&1_u16.to_le_bytes());

        image[64..68].copy_from_slice(&PT_LOAD.to_le_bytes());
        image[68..72].copy_from_slice(&(PF_X | 4).to_le_bytes());
        image[72..80].copy_from_slice(&(TEST_CODE_OFFSET as u64).to_le_bytes());
        image[80..88].copy_from_slice(&TEST_LOAD_ADDRESS.to_le_bytes());
        image[88..96].copy_from_slice(&TEST_LOAD_ADDRESS.to_le_bytes());
        image[96..104].copy_from_slice(&(code.len() as u64).to_le_bytes());
        image[104..112].copy_from_slice(&0x2000_u64.to_le_bytes());
        image[112..120].copy_from_slice(&0x1000_u64.to_le_bytes());
        image[TEST_CODE_OFFSET..].copy_from_slice(code);
        image
    }

    fn clock_tick_entries(auxv: &[(libc::c_ulong, libc::c_ulong)]) -> Vec<(u64, u64)> {
        auxv.iter()
            // Keep the test oracle independent of the production constants: a
            // regression in either the Linux tag or USER_HZ value must fail.
            .filter(|(key, _)| *key == 17)
            .map(|&(key, value)| (key, value))
            .collect()
    }

    #[test]
    fn loader_reserves_identity_image_and_preserves_overlapping_load_pages() {
        let mut memory = GuestMemory::new(0, TEST_MEMORY_SIZE).unwrap();
        let mut image = test_static_elf(&[0x90, 0xc3]);
        // A second admitted PT_LOAD covers the same two pages and overwrites
        // them in the same order. Ownership must count physical pages once.
        let header = image[64..120].to_vec();
        image[120..176].copy_from_slice(&header);
        image[56..58].copy_from_slice(&2_u16.to_le_bytes());
        image[68..72].copy_from_slice(&7_u32.to_le_bytes());
        image[124..128].copy_from_slice(&5_u32.to_le_bytes());
        let loaded = load_static_elf(
            &mut memory,
            &image,
            &["identity", "argument"],
            &["A=B"],
            &std::env::current_dir().unwrap(),
        )
        .unwrap();
        assert_eq!(loaded.entry_point, TEST_LOAD_ADDRESS);
        assert_eq!(loaded.program_break, TEST_LOAD_ADDRESS + 0x2000);
        assert_eq!(loaded.stack_pointer & 15, 0);
        assert_eq!(
            memory.reservation_kind(TEST_LOAD_ADDRESS),
            Some(RegionKind::Elf)
        );
        assert_eq!(
            memory.reservation_kind(TEST_LOAD_ADDRESS + PAGE_SIZE),
            Some(RegionKind::Elf)
        );
        assert_eq!(
            memory.reservation_kind(PROGRAM_HEADERS_ADDRESS),
            Some(RegionKind::ProgramHeaders)
        );
        assert_eq!(
            memory.reservation_kind(memory.guest_end() - PAGE_SIZE),
            Some(RegionKind::Stack)
        );
        assert_eq!(
            memory.reserved_pages() as u64,
            BOOT_RESERVED_END / PAGE_SIZE + 2 + STACK_LIMIT / PAGE_SIZE + VDSO_GAP / PAGE_SIZE
        );
        assert_eq!(
            memory.allocation_cursors().unwrap().mmap_next,
            loaded.mmap_next
        );
        let mut code = [0; 2];
        memory.read_raw(TEST_LOAD_ADDRESS, &mut code).unwrap();
        assert_eq!(code, [0x90, 0xc3]);
        let mut argc = [0; 8];
        let stack = memory.user_range_to_guest(loaded.stack_pointer, 8).unwrap();
        memory.read_raw(stack, &mut argc).unwrap();
        assert_eq!(u64::from_le_bytes(argc), 2);
        memory.enable_user_access();
        // Later overlapping headers replace policy; they do not union it.
        assert_eq!(
            memory
                .user()
                .user_writable_prefix(TEST_LOAD_ADDRESS, 2)
                .unwrap(),
            0
        );
        assert_eq!(
            memory
                .user()
                .user_accessible_prefix(TEST_LOAD_ADDRESS, 2)
                .unwrap(),
            2
        );
        assert!(memory.user().read(BOOT_RESERVED_END, &mut [0]).is_err());
        assert!(
            memory
                .user()
                .read(PROGRAM_HEADERS_ADDRESS, &mut [0])
                .is_ok()
        );
    }

    #[test]
    fn failed_initial_image_releases_reservations_without_claiming_byte_rollback() {
        let mut memory = GuestMemory::new(0, TEST_MEMORY_SIZE).unwrap();
        let mut image = test_static_elf(&[0x90, 0xc3]);
        image[24..32].copy_from_slice(&(TEST_LOAD_ADDRESS + 0x4000).to_le_bytes());
        assert!(
            load_static_elf(
                &mut memory,
                &image,
                &["bad-entry"],
                &[],
                &std::env::current_dir().unwrap()
            )
            .is_err()
        );
        assert_eq!(memory.reserved_pages(), 0);
        assert_eq!(memory.allocation_cursors(), None);
        let mut bytes = [0; 2];
        memory.read_raw(TEST_LOAD_ADDRESS, &mut bytes).unwrap();
        assert_eq!(bytes, [0x90, 0xc3]);
    }

    #[test]
    fn auxiliary_vector_reports_linux_clock_tick_rate_once() {
        let mut memory = GuestMemory::new(0, TEST_MEMORY_SIZE).unwrap();
        let image = test_static_elf(&[0x0f, 0x0b]);
        let loaded = load_static_elf(
            &mut memory,
            &image,
            &["initial"],
            &[],
            &std::env::current_dir().unwrap(),
        )
        .unwrap();

        assert_eq!(clock_tick_entries(&loaded.auxv), vec![(17, 100)]);
    }

    #[test]
    fn auxiliary_vector_reload_preserves_linux_clock_tick_rate() {
        let mut memory = GuestMemory::new(0, TEST_MEMORY_SIZE).unwrap();
        let first_image = test_static_elf(&[0x90, 0x0f, 0x0b]);
        let second_image = test_static_elf(&[0x90, 0x90, 0x0f, 0x0b]);
        let cwd = std::env::current_dir().unwrap();

        let first = load_static_elf(&mut memory, &first_image, &["first"], &[], &cwd).unwrap();
        let second = load_static_elf(&mut memory, &second_image, &["second"], &[], &cwd).unwrap();

        assert_ne!(first.entry_point, 0);
        assert_ne!(second.entry_point, 0);
        let first_execfn = first
            .auxv
            .iter()
            .find(|(key, _)| *key == AT_EXECFN)
            .map(|(_, value)| *value);
        let second_execfn = second
            .auxv
            .iter()
            .find(|(key, _)| *key == AT_EXECFN)
            .map(|(_, value)| *value);
        assert_ne!(first_execfn, second_execfn);
        assert_eq!(clock_tick_entries(&first.auxv), vec![(17, 100)]);
        assert_eq!(clock_tick_entries(&second.auxv), vec![(17, 100)]);
    }

    /// The keys and order of the vector Linux 7.1 gives a process on this
    /// repository's x86_64 hosts (`LD_SHOW_AUXV=1 /bin/true`), and the
    /// canonical CPU and kernel values in place of the host's.
    #[test]
    fn auxiliary_vector_has_linuxs_entries_in_linuxs_order() {
        let auxv = guest_auxv(&GuestAuxvValues {
            program_headers: 0x200040,
            program_header_size: 56,
            program_header_count: 13,
            base: 0x1000000,
            entry: 0x201000,
            random: 0x3fffef00,
            execfn: 0x3fffefe0,
            platform: 0x3fffef10,
        });
        let keys: Vec<u64> = auxv.iter().map(|(key, _)| *key).collect();
        assert_eq!(
            keys,
            [
                33, 51, 16, 6, 17, 3, 4, 5, 7, 8, 9, 11, 12, 13, 14, 23, 25, 26, 31, 15, 27, 28
            ]
        );
        let value = |key| auxv.iter().find(|(k, _)| *k == key).unwrap().1;
        assert_eq!(value(33), VDSO_ADDRESS);
        assert_eq!(value(16), 0x078b_fbfd);
        assert_eq!(value(26), 0);
        assert_eq!(value(51), 16384);
        assert_eq!(value(27), 28);
        assert_eq!(value(28), 32);
        assert_eq!(value(8), 0);
        assert_eq!(value(15), 0x3fffef10);
        assert_eq!(value(11), 0);
    }

    /// The initial stack follows Linux's exec layout at Linux's addresses, so
    /// the pointers a guest sees match a traced guest's: an 8-byte NULL below
    /// TASK_SIZE, the exec filename, the envp strings and the argv strings
    /// (ascending argv, envp, execfn), then, below argv[0] rounded down to 16
    /// bytes, the platform string, the AT_RANDOM bytes, and the 16-byte-aligned
    /// argc, argv, envp and auxv words.
    #[test]
    fn initial_stack_follows_linux_exec_layout() {
        let mut memory = GuestMemory::new(0, TEST_MEMORY_SIZE).unwrap();
        let image = test_static_elf(&[0x0f, 0x0b]);
        let loaded = load_static_elf(
            &mut memory,
            &image,
            &["/prog", "a"],
            &["X=1", "Y=22"],
            &std::env::current_dir().unwrap(),
        )
        .unwrap();
        let execfn = USER_STACK_TOP - 8 - 6;
        let env_y = execfn - 5;
        let env_x = env_y - 4;
        let arg1 = env_x - 2;
        let arg0 = arg1 - 6;
        let platform = (arg0 & !0xf) - 7;
        let random = platform - 16;
        let auxv = |key: libc::c_ulong| {
            loaded
                .auxv
                .iter()
                .find(|(entry, _)| *entry == key)
                .unwrap()
                .1
        };
        assert_eq!(auxv(libc::AT_EXECFN), execfn);
        assert_eq!(auxv(AT_PLATFORM), platform);
        assert_eq!(auxv(libc::AT_RANDOM), random);
        let read = |address: u64, length: usize| {
            let mut bytes = vec![0; length];
            let physical = memory.user_range_to_guest(address, length as u64).unwrap();
            memory.read_raw(physical, &mut bytes).unwrap();
            bytes
        };
        assert_eq!(read(USER_STACK_TOP - 8, 8), [0; 8]);
        assert_eq!(
            read(arg0, (USER_STACK_TOP - 8 - arg0) as usize),
            b"/prog\0a\0X=1\0Y=22\0/prog\0"
        );
        assert_eq!(read(platform, 7), b"x86_64\0");

        assert_eq!(read(random, 16), b"Reverie-KVM-ELF!");

        let words = 1 + 3 + 3 + 2 * loaded.auxv.len() as u64 + 2;
        assert_eq!(loaded.stack_pointer, (random - words * 8) & !0xf);
        let stack: Vec<u64> = read(loaded.stack_pointer, words as usize * 8)
            .chunks(8)
            .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
            .collect();
        assert_eq!(stack[..7], [2, arg0, arg1, 0, env_x, env_y, 0]);
        // The auxv pairs as the guest reads them, then AT_NULL.
        let pairs: Vec<(u64, u64)> = stack[7..]
            .chunks(2)
            .map(|pair| (pair[0], pair[1]))
            .collect();
        let (last, entries) = pairs.split_last().unwrap();
        assert_eq!(*last, (AT_NULL, 0));
        assert_eq!(entries, loaded.auxv.as_slice());
    }

    /// AT_EXECFN names the filename execve was given, which Linux copies to
    /// the top of the stack above the envp and argv strings. For a `#!`
    /// script that filename is the script's even though argv[0] is now the
    /// interpreter's, both when a launcher rewrote argv itself and when this
    /// loader resolves the script. Naming the interpreter instead shortens the
    /// strings and moves every stack address the guest logs.
    #[test]
    fn initial_stack_names_the_execve_filename_not_argv0() {
        use std::os::unix::fs::PermissionsExt;

        let read_c_string = |memory: &GuestMemory, address: u64| {
            let mut bytes = Vec::new();
            loop {
                let mut byte = [0];
                let physical = memory
                    .user_range_to_guest(address + bytes.len() as u64, 1)
                    .unwrap();
                memory.read_raw(physical, &mut byte).unwrap();
                if byte[0] == 0 {
                    return String::from_utf8(bytes).unwrap();
                }
                bytes.push(byte[0]);
            }
        };
        let execfn_of = |loaded: &LoadedStaticElf| {
            loaded
                .auxv
                .iter()
                .find(|(entry, _)| *entry == libc::AT_EXECFN)
                .unwrap()
                .1
        };

        // A launcher that already rewrote a script's argv to its interpreter.
        let mut memory = GuestMemory::new(0, TEST_MEMORY_SIZE).unwrap();
        let loaded = load_static_elf_with_execfn(
            &mut memory,
            &test_static_elf(&[0x0f, 0x0b]),
            Some(b"/s/run.sh"),
            &["/bin/i", "/s/run.sh"],
            &[],
            &std::env::current_dir().unwrap(),
        )
        .unwrap();
        let execfn = USER_STACK_TOP - 8 - 10;
        assert_eq!(execfn_of(&loaded), execfn);
        assert_eq!(read_c_string(&memory, execfn), "/s/run.sh");
        let words = 1 + 3 + 1 + 2 * loaded.auxv.len() as u64 + 2;
        let argv0 = execfn - 10 - 7;
        let random = ((argv0 & !0xf) - 7) - 16;
        assert_eq!(loaded.stack_pointer, (random - words * 8) & !0xf);

        // A script this loader resolves itself keeps the script's filename.
        let dir = std::env::temp_dir().join(format!("reverie-kvm-execfn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let interpreter = dir.join("interpreter");
        std::fs::write(&interpreter, test_static_elf(&[0x0f, 0x0b])).unwrap();
        std::fs::set_permissions(&interpreter, std::fs::Permissions::from_mode(0o755)).unwrap();
        let script = dir.join("script.sh");
        let script_body = format!("#!{}\n", interpreter.display());
        std::fs::write(&script, &script_body).unwrap();
        let script_name = script.to_str().unwrap();
        let mut memory = GuestMemory::new(0, TEST_MEMORY_SIZE).unwrap();
        let loaded = load_static_elf(
            &mut memory,
            script_body.as_bytes(),
            &[script_name, "a"],
            &[],
            &dir,
        )
        .unwrap();
        assert_eq!(read_c_string(&memory, execfn_of(&loaded)), script_name);

        // Given explicitly, the filename is also the script's argument, even
        // under a display-only argv[0] and through a script interpreter that
        // is itself a script, whose name its `#!` line gives.
        let inner = dir.join("inner.sh");
        std::fs::write(&inner, &script_body).unwrap();
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o755)).unwrap();
        let inner_name = inner.to_str().unwrap();
        let mut memory = GuestMemory::new(0, TEST_MEMORY_SIZE).unwrap();
        let loaded = load_static_elf_with_execfn(
            &mut memory,
            format!("#!{inner_name}\n").as_bytes(),
            Some(b"./outer"),
            &["display", "a"],
            &[],
            &dir,
        )
        .unwrap();
        assert_eq!(read_c_string(&memory, execfn_of(&loaded)), "./outer");
        let word = |address: u64| {
            let mut bytes = [0; 8];
            let physical = memory.user_range_to_guest(address, 8).unwrap();
            memory.read_raw(physical, &mut bytes).unwrap();
            u64::from_le_bytes(bytes)
        };
        let argc = word(loaded.stack_pointer);
        let argv = (1..=argc)
            .map(|index| read_c_string(&memory, word(loaded.stack_pointer + 8 * index)))
            .collect::<Vec<_>>();
        assert_eq!(
            argv,
            [
                interpreter.canonicalize().unwrap().to_str().unwrap(),
                inner_name,
                "./outer",
                "a"
            ]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `AT_PLATFORM` points at the platform string on the guest stack.
    #[test]
    fn loaded_auxiliary_vector_names_the_platform() {
        let mut memory = GuestMemory::new(0, TEST_MEMORY_SIZE).unwrap();
        let image = test_static_elf(&[0x0f, 0x0b]);
        let loaded = load_static_elf(
            &mut memory,
            &image,
            &["initial"],
            &[],
            &std::env::current_dir().unwrap(),
        )
        .unwrap();
        let platform = loaded
            .auxv
            .iter()
            .find(|(key, _)| *key == AT_PLATFORM)
            .unwrap()
            .1;
        let mut bytes = [0; 7];
        let platform = memory.user_range_to_guest(platform, 7).unwrap();
        memory.read_raw(platform, &mut bytes).unwrap();
        assert_eq!(&bytes, b"x86_64\0");
    }

    #[test]
    fn initial_thread_name_uses_basename_and_15_byte_limit() {
        let short = initial_thread_name(Path::new("/usr/bin/program"));
        assert_eq!(&short[..8], b"program\0");
        assert!(short[8..].iter().all(|byte| *byte == 0));
        assert_eq!(
            initial_thread_name(Path::new("/tmp/abcdefghijklmnopq")),
            *b"abcdefghijklmno\0",
        );
    }

    /// The mmap window ends at Linux's mmap_base, its physical end agrees with
    /// mmap_base modulo a large page, and the identity user addresses end where
    /// it begins. The window takes a quarter of memory (rounded to a large
    /// page); a large image moves the identity end above the image and its
    /// program-break headroom, shrinking the window from below, so ld.so's
    /// place at the window's top does not move.
    #[test]
    fn linux_layout_places_the_mmap_window_below_mmap_base() {
        const MIB: u64 = 1024 * 1024;
        let mut memory = GuestMemory::new(0, (1024 * MIB) as usize).unwrap();
        let layout = establish_linux_layout(&mut memory, 0x40_5000, STATIC_BRK_HEADROOM, None)
            .unwrap()
            .unwrap();
        assert_eq!(layout.identity_end, 758 * MIB);
        assert_eq!(layout.mmap_end, 1024 * MIB - STACK_LIMIT - PAGE_SIZE);
        assert_eq!(
            layout.mmap_end % LARGE_PAGE_SIZE,
            MMAP_BASE % LARGE_PAGE_SIZE
        );
        assert_eq!(
            memory.physical_to_user(layout.mmap_end - PAGE_SIZE),
            Some(MMAP_BASE - PAGE_SIZE)
        );
        assert_eq!(
            memory.user_range_to_guest(MMAP_BASE - PAGE_SIZE, PAGE_SIZE),
            Some(layout.mmap_end - PAGE_SIZE)
        );
        assert_eq!(memory.user_range_to_guest(MMAP_BASE, 1), None);
        assert_eq!(memory.user_range_to_guest(layout.identity_end, 1), None);
        assert_eq!(
            memory.user_range_to_guest(layout.identity_end - 1, 1),
            Some(layout.identity_end - 1)
        );

        // A 256 MiB guest keeps identity addresses past 128 MiB, where guest
        // programs map MAP_FIXED.
        let mut quarter = GuestMemory::new(0, (256 * MIB) as usize).unwrap();
        let layout = establish_linux_layout(&mut quarter, 0x40_5000, STATIC_BRK_HEADROOM, None)
            .unwrap()
            .unwrap();
        assert_eq!(layout.identity_end, 182 * MIB);
        assert_eq!(
            quarter.user_range_to_guest(0x0800_3000, PAGE_SIZE),
            Some(0x0800_3000)
        );

        let mut large = GuestMemory::new(0, (1024 * MIB) as usize).unwrap();
        let layout = establish_linux_layout(
            &mut large,
            800 * MIB + 1,
            INTERPRETED_BRK_HEADROOM,
            Some(0x3b000),
        )
        .unwrap()
        .unwrap();
        assert_eq!(layout.identity_end, 804 * MIB + PAGE_SIZE);
        assert_eq!(layout.mmap_end, 1024 * MIB - STACK_LIMIT - PAGE_SIZE);
        let mut small = GuestMemory::new(0, (8 * MIB) as usize).unwrap();
        assert!(establish_linux_layout(&mut small, 0x40_5000, STATIC_BRK_HEADROOM, None).is_err());
        let mut overflow = GuestMemory::new(0, (16 * MIB) as usize).unwrap();
        assert!(
            establish_linux_layout(&mut overflow, u64::MAX - 1024, STATIC_BRK_HEADROOM, None)
                .is_err()
        );
    }

    /// The smallest memory the loader accepted before the mmap window existed
    /// still loads: a 12 MiB guest holds the boot area, a two-page static image
    /// at 2 MiB with its 1 MiB of program-break headroom, the window with the
    /// vDSO gap, and the 8 MiB stack.
    #[test]
    fn loader_fits_a_static_image_in_a_twelve_mib_guest() {
        const MIB: u64 = 1024 * 1024;
        let mut memory = GuestMemory::new(0, (12 * MIB) as usize).unwrap();
        let image = test_static_elf(&[0x0f, 0x0b]);
        let loaded = load_static_elf(
            &mut memory,
            &image,
            &["initial"],
            &[],
            &std::env::current_dir().unwrap(),
        )
        .unwrap();
        assert_eq!(loaded.brk_limit, TEST_LOAD_ADDRESS + 0x2000 + MIB);
        assert_eq!(loaded.mmap_limit, 4 * MIB - PAGE_SIZE);
        assert_eq!(
            memory.physical_to_user(loaded.mmap_limit - PAGE_SIZE),
            Some(MMAP_BASE - PAGE_SIZE)
        );
    }

    /// A minimal ELF64 x86-64 image of type `e_type`: one PT_LOAD of `memsz`
    /// bytes at `vaddr` holding `code` (entered at `vaddr`), and a PT_INTERP
    /// naming `interpreter` when given.
    fn test_elf(
        e_type: u16,
        vaddr: u64,
        memsz: u64,
        interpreter: Option<&std::path::Path>,
        code: &[u8],
    ) -> Vec<u8> {
        use std::os::unix::ffi::OsStrExt;
        let mut image = vec![0; TEST_CODE_OFFSET + code.len()];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = ELFCLASS64;
        image[5] = ELFDATA2LSB;
        image[6] = 1;
        image[16..18].copy_from_slice(&e_type.to_le_bytes());
        image[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        image[20..24].copy_from_slice(&1_u32.to_le_bytes());
        image[24..32].copy_from_slice(&vaddr.to_le_bytes());
        image[32..40].copy_from_slice(&64_u64.to_le_bytes());
        image[52..54].copy_from_slice(&64_u16.to_le_bytes());
        image[54..56].copy_from_slice(&56_u16.to_le_bytes());
        let header = |image: &mut Vec<u8>, at: usize, fields: [u64; 6], kind: u32, flags: u32| {
            image[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            image[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            for (index, field) in fields.iter().enumerate() {
                let start = at + 8 + index * 8;
                image[start..start + 8].copy_from_slice(&field.to_le_bytes());
            }
        };
        let mut next = 64;
        if let Some(path) = interpreter {
            let path = path.as_os_str().as_bytes();
            let path_offset = 64 + 2 * 56;
            image[path_offset..path_offset + path.len()].copy_from_slice(path);
            let size = path.len() as u64 + 1;
            header(
                &mut image,
                next,
                [path_offset as u64, 0, 0, size, size, 1],
                PT_INTERP,
                4,
            );
            next += 56;
        }
        header(
            &mut image,
            next,
            [
                TEST_CODE_OFFSET as u64,
                vaddr,
                vaddr,
                code.len() as u64,
                memsz,
                PAGE_SIZE,
            ],
            PT_LOAD,
            PF_X | 4,
        );
        let headers = (next - 64) / 56 + 1;
        image[56..58].copy_from_slice(&(headers as u16).to_le_bytes());
        image[TEST_CODE_OFFSET..].copy_from_slice(code);
        image
    }

    /// Writes a small ET_DYN interpreter whose one segment spans `memsz` bytes
    /// from `vaddr`, and returns a static-address main image that names it.
    fn dynamic_program(name: &str, vaddr: u64, memsz: u64) -> (std::path::PathBuf, Vec<u8>) {
        let dir =
            std::env::temp_dir().join(format!("reverie-kvm-interp-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ld.so");
        std::fs::write(&path, test_elf(ET_DYN, vaddr, memsz, None, &[0x0f, 0x0b])).unwrap();
        let main = test_elf(
            ET_EXEC,
            TEST_LOAD_ADDRESS,
            0x2000,
            Some(&path),
            &[0x0f, 0x0b],
        );
        (dir, main)
    }

    /// The window grows to hold a large interpreter: a 70 MiB interpreter
    /// span in a 256 MiB guest loads at the window's top, as before the window
    /// existed it loaded at 16 MiB.
    #[test]
    fn loader_sizes_the_window_for_a_large_interpreter() {
        const MIB: u64 = 1024 * 1024;
        let (dir, main) = dynamic_program("large", 0, 70 * MIB);
        let mut memory = GuestMemory::new(0, (256 * MIB) as usize).unwrap();
        let loaded = load_static_elf(
            &mut memory,
            &main,
            &["initial"],
            &[],
            &std::env::current_dir().unwrap(),
        )
        .unwrap();
        assert_eq!(loaded.entry_point, MMAP_BASE - 70 * MIB);
        let physical = memory
            .user_range_to_guest(loaded.entry_point, 70 * MIB)
            .unwrap();
        assert!(physical >= loaded.brk_limit);
        assert!(loaded.brk_limit >= TEST_LOAD_ADDRESS + 0x2000 + INTERPRETED_BRK_HEADROOM);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An interpreter whose first segment lies above where the window could
    /// bias it is refused, not loaded at a wrapped address.
    #[test]
    fn loader_refuses_an_interpreter_above_the_window() {
        const MIB: u64 = 1024 * 1024;
        let (dir, main) = dynamic_program("high", 0x4000_0000, 0x2000);
        let mut memory = GuestMemory::new(0, (64 * MIB) as usize).unwrap();
        let error = load_static_elf(
            &mut memory,
            &main,
            &["initial"],
            &[],
            &std::env::current_dir().unwrap(),
        )
        .unwrap_err();
        assert!(
            matches!(&error, Error::UnsupportedElf(reason) if reason.contains("above the mmap window")),
            "{error:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A static program in memory too small for the mmap window keeps the
    /// layout memory had before it: an 11 MiB + 12 KiB guest leaves one page
    /// between the image's program-break headroom and the stack, and mappings
    /// go there bottom-up.
    #[test]
    fn static_program_without_room_for_a_window_keeps_the_identity_layout() {
        const MIB: u64 = 1024 * 1024;
        let mut memory = GuestMemory::new(0, (11 * MIB + 0x3000) as usize).unwrap();
        let image = test_static_elf(&[0x0f, 0x0b]);
        let loaded = load_static_elf(
            &mut memory,
            &image,
            &["initial"],
            &[],
            &std::env::current_dir().unwrap(),
        )
        .unwrap();
        assert_eq!(loaded.brk_limit, 0x30_2000);
        assert_eq!(loaded.mmap_base, 0x30_2000);
        assert_eq!(loaded.mmap_limit, 0x30_3000);
        assert!(!memory.has_mmap_window());
        assert_eq!(memory.user_layout().0.len(), 1, "the stack window only");
    }

    /// When memory is too tight for the window to end at the highest address
    /// congruent with mmap_base, it ends at the stack window instead, with its
    /// user end moved down (by less than a large page) to keep user and
    /// physical addresses congruent; the vDSO gap stays below it.
    #[test]
    fn tight_memory_moves_the_window_user_end_down() {
        const MIB: u64 = 1024 * 1024;
        let mut memory = GuestMemory::new(0, (11 * MIB + 0x10000) as usize).unwrap();
        let image = test_static_elf(&[0x0f, 0x0b]);
        let loaded = load_static_elf(
            &mut memory,
            &image,
            &["initial"],
            &[],
            &std::env::current_dir().unwrap(),
        )
        .unwrap();
        assert_eq!(loaded.mmap_limit, 0x31_0000);
        let user_end = memory
            .physical_to_user(loaded.mmap_limit - PAGE_SIZE)
            .unwrap()
            + PAGE_SIZE;
        assert_eq!(user_end, MMAP_BASE - 0xef000);
        assert_eq!(
            user_end % LARGE_PAGE_SIZE,
            loaded.mmap_limit % LARGE_PAGE_SIZE
        );
        assert_eq!(
            memory.reservation_kind(loaded.mmap_limit - VDSO_GAP),
            Some(RegionKind::Mmap)
        );
        // An interpreter that needs the whole stretch up to the stack fits too.
        let mut tight = GuestMemory::new(0, (11 * MIB + 0x10000) as usize).unwrap();
        let layout = establish_linux_layout(
            &mut tight,
            0x20_2000,
            STATIC_BRK_HEADROOM,
            Some(0x31_0000 - 0x30_2000 - VDSO_GAP - PAGE_SIZE),
        )
        .unwrap()
        .unwrap();
        assert_eq!(layout.mmap_end, 0x31_0000);
        assert_eq!(layout.mmap_user_end, MMAP_BASE - 0xef000);
    }

    /// An interpreted PIE main image (ET_DYN with a small interpreter) whose one
    /// segment is linked at `vaddr` with `align`, `memsz` bytes long; the
    /// interpreter file lives in the returned directory.
    fn interpreted_pie(
        name: &str,
        vaddr: u64,
        memsz: u64,
        align: u64,
    ) -> (std::path::PathBuf, Vec<u8>) {
        let dir =
            std::env::temp_dir().join(format!("reverie-kvm-pie-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ld.so");
        std::fs::write(&path, test_elf(ET_DYN, 0, 0x2000, None, &[0x0f, 0x0b])).unwrap();
        let mut main = test_elf(ET_DYN, vaddr, memsz, Some(&path), &[0x0f, 0x0b]);
        // The PT_LOAD header follows the PT_INTERP one; p_align is its last word.
        let align_at = 64 + 56 + 48;
        main[align_at..align_at + 8].copy_from_slice(&align.to_le_bytes());
        (dir, main)
    }

    fn load(memory: &mut GuestMemory, image: &[u8]) -> Result<LoadedStaticElf> {
        load_static_elf(
            memory,
            image,
            &["initial"],
            &[],
            &std::env::current_dir().unwrap(),
        )
    }

    /// An interpreted PIE main image loads where Linux loads it, ELF_ET_DYN_BASE,
    /// in its own window below the mmap window, and its program break follows
    /// the image there: brk grows and shrinks in the window, the window's
    /// physical pages are not identity addresses, and identity fallbacks stay
    /// below it.
    #[test]
    fn interpreted_pie_loads_at_linux_pie_base() {
        const MIB: u64 = 1024 * 1024;
        let (dir, image) = interpreted_pie("base", 0, 0x3000, PAGE_SIZE);
        let mut memory = GuestMemory::new(0, (64 * MIB) as usize).unwrap();
        let mut loaded = load(&mut memory, &image).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        // The entry is ld.so's; the image's entry and headers are its auxv.
        let auxv = &loaded.auxv;
        let aux = |key: u64| auxv.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
        assert_eq!(aux(libc::AT_ENTRY), Some(PIE_BASE));
        assert_eq!(loaded.program_break, PIE_BASE + 0x3000);
        assert_eq!(loaded.heap_base, PIE_BASE + 0x3000);
        let physical = memory.user_range_to_guest(PIE_BASE, 0x3000).unwrap();
        let (windows, identity_end) = memory.user_layout();
        assert_eq!(windows.len(), 3, "PIE, mmap and stack windows");
        assert!(physical >= identity_end && physical < loaded.mmap_base);
        assert_eq!(physical % LARGE_PAGE_SIZE, PIE_BASE % LARGE_PAGE_SIZE);
        assert_eq!(memory.user_range_to_guest(physical, 1), None);
        assert!(loaded.brk_limit > loaded.program_break);
        assert_eq!(
            memory.user_range_to_guest(loaded.brk_limit - PAGE_SIZE, PAGE_SIZE),
            Some(loaded.mmap_base - PAGE_SIZE)
        );
        memory.enable_user_access();
        let low = crate::executor::place_mapping(
            &memory,
            &loaded,
            PAGE_SIZE,
            0,
            crate::executor::MappingKind::Anonymous,
            true,
        )
        .unwrap();
        assert_eq!(low, identity_end - PAGE_SIZE);
        let grown = PIE_BASE + 0x3000 + 16 * PAGE_SIZE;
        assert_eq!(
            crate::executor::test_brk(&mut memory, &mut loaded, grown),
            grown as i64
        );
        memory.user().write(grown - 1, &[7]).unwrap();
        let shrunk = PIE_BASE + 0x3000 + PAGE_SIZE;
        assert_eq!(
            crate::executor::test_brk(&mut memory, &mut loaded, shrunk),
            shrunk as i64
        );
        assert!(memory.user().read(grown - 1, &mut [0]).is_err());
        let limit = loaded.brk_limit;
        assert_eq!(
            crate::executor::test_brk(&mut memory, &mut loaded, limit),
            shrunk as i64
        );
    }

    /// Linux rounds ELF_ET_DYN_BASE down to the image's largest PT_LOAD
    /// alignment, and biases an image linked anywhere so its first segment
    /// lands there: a 2 MiB-aligned PIE starts at 0x555555400000, and ones
    /// linked at 0x08000000 and at 0x600000000000 (above the base) are moved
    /// down to ELF_ET_DYN_BASE.
    #[test]
    fn interpreted_pie_placement_follows_alignment_and_relocates_down() {
        const MIB: u64 = 1024 * 1024;
        // The segment's file offset is TEST_CODE_OFFSET, so a 2 MiB-aligned
        // segment is linked at that offset to stay congruent.
        for (name, vaddr, align, start) in [
            (
                "aligned",
                TEST_CODE_OFFSET as u64,
                LARGE_PAGE_SIZE,
                0x5555_5540_0000_u64,
            ),
            ("linked-high", 0x0800_0000, PAGE_SIZE, PIE_BASE),
            ("linked-above-base", 0x6000_0000_0000, PAGE_SIZE, PIE_BASE),
        ] {
            let (dir, image) = interpreted_pie(name, vaddr, 0x3000, align);
            let mut memory = GuestMemory::new(0, (256 * MIB) as usize).unwrap();
            let loaded = load(&mut memory, &image).unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
            let entry = loaded
                .auxv
                .iter()
                .find(|(key, _)| *key == libc::AT_ENTRY)
                .map(|(_, value)| *value);
            assert_eq!(entry, Some(start), "{name}");
            assert_eq!(loaded.program_break, start + 0x3000, "{name}");
            assert!(
                memory.user_range_to_guest(start, 0x3000).is_some(),
                "{name}"
            );
        }
    }

    /// An ET_DYN image without an interpreter (a static PIE) is not placed at
    /// ELF_ET_DYN_BASE: Linux maps it through mmap placement, which is not
    /// modelled, so it keeps the identity placement at 2 MiB.
    #[test]
    fn static_pie_keeps_identity_placement() {
        const MIB: u64 = 1024 * 1024;
        let image = test_elf(ET_DYN, 0, 0x3000, None, &[0x0f, 0x0b]);
        let mut memory = GuestMemory::new(0, (64 * MIB) as usize).unwrap();
        let loaded = load(&mut memory, &image).unwrap();
        assert_eq!(loaded.entry_point, MAIN_LOAD_BIAS);
        assert_eq!(memory.user_layout().0.len(), 2, "mmap and stack windows");
    }

    /// An interpreted PIE in memory too small for its window loads in identity
    /// memory, at 2 MiB, as before the window existed.
    #[test]
    fn interpreted_pie_without_room_for_its_window_loads_in_identity_memory() {
        const MIB: u64 = 1024 * 1024;
        let (dir, image) = interpreted_pie("small", 0, 0x3000, PAGE_SIZE);
        let mut memory = GuestMemory::new(0, (16 * MIB) as usize).unwrap();
        let loaded = load(&mut memory, &image).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let entry = loaded
            .auxv
            .iter()
            .find(|(key, _)| *key == libc::AT_ENTRY)
            .map(|(_, value)| *value);
        assert_eq!(entry, Some(MAIN_LOAD_BIAS));
        assert_eq!(
            memory.user_range_to_guest(MAIN_LOAD_BIAS, PAGE_SIZE),
            Some(MAIN_LOAD_BIAS)
        );
        assert_eq!(memory.user_range_to_guest(PIE_BASE, 1), None);
    }

    /// brk does not go below the image's data (Linux's end_data under
    /// CONFIG_COMPAT_BRK): with a fully file-backed segment the data page
    /// survives a request below it; with bss, the break may go down to the end
    /// of the file contents, as on Linux, and no lower.
    #[test]
    fn brk_stays_at_or_above_the_image_data() {
        let mut contents = vec![0; 0x2000];
        contents[..2].copy_from_slice(&[0x0f, 0x0b]);
        contents[0x1800] = 0x5a;
        let full = test_static_elf(&contents);
        let bss = test_static_elf(&[0x0f, 0x0b]);
        for (image, min_break) in [(full, 0x20_2000_u64), (bss, 0x20_0002)] {
            let mut memory = GuestMemory::new(0, TEST_MEMORY_SIZE).unwrap();
            let mut loaded = load_static_elf(
                &mut memory,
                &image,
                &["initial"],
                &[],
                &std::env::current_dir().unwrap(),
            )
            .unwrap();
            memory.enable_user_access();
            assert_eq!(loaded.min_break, min_break);
            assert_eq!(loaded.program_break, 0x20_2000);
            let below = min_break - 1;
            assert_eq!(
                crate::executor::test_brk(&mut memory, &mut loaded, below),
                0x20_2000
            );
            let mut byte = [0];
            memory.user().read(0x20_1800, &mut byte).unwrap();
            assert_eq!(byte, [image_byte(min_break)]);
            assert_eq!(
                crate::executor::test_brk(&mut memory, &mut loaded, min_break),
                min_break as i64
            );
        }
        fn image_byte(min_break: u64) -> u8 {
            if min_break == 0x20_2000 { 0x5a } else { 0 }
        }
    }

    /// An image whose end is a large-page boundary past the window's usual
    /// start still gets program-break headroom: the identity end moves above
    /// it, and the break grows.
    #[test]
    fn large_image_keeps_program_break_headroom() {
        const MIB: u64 = 1024 * 1024;
        let mut memory = GuestMemory::new(0, (64 * MIB) as usize).unwrap();
        let mut image = test_static_elf(&[0x0f, 0x0b]);
        image[104..112].copy_from_slice(&(48 * MIB - TEST_LOAD_ADDRESS).to_le_bytes());
        let loaded = load_static_elf(
            &mut memory,
            &image,
            &["initial"],
            &[],
            &std::env::current_dir().unwrap(),
        )
        .unwrap();
        assert_eq!(loaded.program_break, 48 * MIB);
        assert_eq!(loaded.brk_limit, 49 * MIB);
        assert_eq!(
            memory.user_range_to_guest(49 * MIB - 1, 1),
            Some(49 * MIB - 1)
        );
        assert_eq!(memory.user_range_to_guest(49 * MIB, 1), None);
        memory.enable_user_access();
        let mut state = loaded;
        let grown = 48 * MIB + 16 * PAGE_SIZE;
        assert_eq!(
            crate::executor::test_brk(&mut memory, &mut state, grown),
            grown as i64
        );
        assert!(memory.user().write(grown - 1, &[1]).is_ok());
    }

    /// Exec replaces the whole layout. A program whose image needs a higher
    /// identity end than the one before it, and the reverse, both load into
    /// the memory the other left, with the same windows and identity addresses
    /// as in fresh memory.
    #[test]
    fn exec_replaces_a_layout_with_a_different_identity_end() {
        const MIB: u64 = 1024 * 1024;
        let small = test_static_elf(&[0x0f, 0x0b]);
        let mut large = test_static_elf(&[0x0f, 0x0b]);
        large[104..112].copy_from_slice(&(48 * MIB - TEST_LOAD_ADDRESS).to_le_bytes());
        let load = |memory: &mut GuestMemory, image: &[u8]| {
            load_static_elf(
                memory,
                image,
                &["initial"],
                &[],
                &std::env::current_dir().unwrap(),
            )
            .unwrap()
        };
        let fresh = |image: &[u8]| {
            let mut memory = GuestMemory::new(0, (64 * MIB) as usize).unwrap();
            let loaded = load(&mut memory, image);
            (memory.user_layout(), loaded.brk_limit, loaded.mmap_limit)
        };
        let small_layout = fresh(&small);
        let large_layout = fresh(&large);
        assert_ne!(small_layout.0.1, large_layout.0.1);

        let mut memory = GuestMemory::new(0, (64 * MIB) as usize).unwrap();
        for (image, expected) in [
            (&small, &small_layout),
            (&large, &large_layout),
            (&small, &small_layout),
        ] {
            let loaded = load(&mut memory, image);
            assert_eq!(
                (memory.user_layout(), loaded.brk_limit, loaded.mmap_limit),
                *expected
            );
        }
    }

    /// A loaded program's mappings are bounded by the layout: the program break
    /// grows to the identity end, mappings fill the window below mmap_base, and
    /// the host vDSO pages' range just below mmap_base (no interpreter here) is
    /// reserved and inaccessible.
    #[test]
    fn loader_reserves_the_vdso_gap_and_bounds_mappings_by_the_layout() {
        let mut memory = GuestMemory::new(0, TEST_MEMORY_SIZE).unwrap();
        let image = test_static_elf(&[0x0f, 0x0b]);
        let loaded = load_static_elf(
            &mut memory,
            &image,
            &["initial"],
            &[],
            &std::env::current_dir().unwrap(),
        )
        .unwrap();
        let gap = memory
            .user_range_to_guest(MMAP_BASE - VDSO_GAP, VDSO_GAP)
            .unwrap();
        assert_eq!(gap + VDSO_GAP, loaded.mmap_limit);
        assert_eq!(memory.reservation_kind(gap), Some(RegionKind::Mmap));
        memory.enable_user_access();
        assert!(memory.user().read(MMAP_BASE - VDSO_GAP, &mut [0]).is_err());
        assert_eq!(loaded.brk_limit, loaded.mmap_base);
        assert_eq!(
            memory.physical_to_user(loaded.mmap_base),
            Some(MMAP_BASE - (loaded.mmap_limit - loaded.mmap_base))
        );
    }

    #[test]
    fn parses_script_interpreters_and_optional_arguments() {
        assert_eq!(
            parse_shebang(b"#!/bin/bash\necho ok\n").unwrap(),
            Some(("/bin/bash".to_string(), None))
        );
        assert_eq!(
            parse_shebang(b"#!/usr/bin/grep -E\n").unwrap(),
            Some(("/usr/bin/grep".to_string(), Some("-E".to_string())))
        );
        assert_eq!(parse_shebang(b"\x7fELF").unwrap(), None);
    }

    // TODO-HUMAN-REVIEW(PR-kvm-execve-path): Covers PATH resolution of a
    // slash-less execve program name, the behavior prepare_exec now relies on
    // so `execve("bash", ...)` matches the ptrace initial launcher instead of
    // returning ENOENT.
    #[test]
    fn resolves_bare_program_name_via_path() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir =
            std::env::temp_dir().join(format!("reverie-kvm-execve-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("bash");
        let mut file = std::fs::File::create(&program).unwrap();
        file.write_all(b"\x7fELF").unwrap();
        let mut perms = file.metadata().unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&program, perms).unwrap();

        let path_env = format!("PATH={}", dir.display());
        let cwd = std::env::current_dir().unwrap();

        // A bare name is searched on PATH and resolves to the canonical file.
        let resolved = resolve_executable_path("bash", &[path_env.as_str()], &cwd).unwrap();
        assert_eq!(resolved, program.canonicalize().unwrap());

        // A bare name absent from PATH is unresolved, not silently joined to cwd.
        assert!(
            resolve_executable_path("definitely-not-on-path", &[path_env.as_str()], &cwd).is_err()
        );

        // A name containing a slash keeps execve(2) semantics: resolved against
        // cwd, never PATH-searched.
        let relative = program.strip_prefix(&cwd).ok();
        if let Some(relative) = relative {
            let via_cwd =
                resolve_executable_path(&relative.to_string_lossy(), &["PATH=/nonexistent"], &cwd)
                    .unwrap();
            assert_eq!(via_cwd, program.canonicalize().unwrap());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
