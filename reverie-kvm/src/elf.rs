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
use crate::memory::RegionKind;
use crate::signal::ProcessSignalState;
use crate::signal::SharedThreadSignalState;

const PAGE_SIZE: u64 = 4096;
pub(crate) const TASK_COMM_LEN: usize = 16;
pub(crate) const STACK_LIMIT: u64 = 8 * 1024 * 1024;
const STACK_STRING_HEADROOM: u64 = 4096;
const MMAP_GAP: u64 = 1024 * 1024;
const MAX_PROGRAM_HEADERS_SIZE: usize = PAGE_SIZE as usize;
const MAX_INTERPRETER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SCRIPT_INTERPRETERS: usize = 4;
const MAIN_LOAD_BIAS: u64 = 2 * 1024 * 1024;
const _: () = assert!(BOOT_RESERVED_END <= MAIN_LOAD_BIAS);
const INTERPRETER_LOAD_BIAS: u64 = 16 * 1024 * 1024;
const IOPRIO_CLASS_SHIFT: u32 = 13;
pub(crate) const GUEST_CAPABILITY_MASK: u64 = (1_u64 << 41) - 1;
/// Page-aligned program-break gap reserved between a large main image and a
/// relocated interpreter base. Only applies when the main image would overrun
/// the historical fixed [`INTERPRETER_LOAD_BIAS`]; small PIEs are unaffected.
const INTERPRETER_MIN_BRK_HEADROOM: u64 = 4 * 1024 * 1024;
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

// AUTONOMOUS-BOT-IMPLEMENTED: Share deterministic file identities across fork.
// TODO-HUMAN-REVIEW(PR-136): Review linked and anonymous object identity lifetimes.
#[derive(Debug)]
pub(crate) struct GuestFileIdentity {
    pub inode: u64,
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
}

#[derive(Debug, Default)]
struct ProcessExitState {
    last_thread: Option<ExitStatus>,
    group: Option<ExitStatus>,
    failed: bool,
}

impl TaskLifecycleTable {
    pub(crate) fn with_root(tid: i32, tgid: i32, pgid: i32, dumpable: bool) -> Self {
        let mut table = Self::default();
        table.register(tid, tgid, pgid, dumpable);
        table
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

#[derive(Debug)]
pub(crate) struct LoadedStaticElf {
    pub entry_point: u64,
    pub stack_pointer: u64,
    /// Initial program break set at load time (`align_up(main_end)`); the base
    /// of the brk-managed heap. The live heap spans `[heap_base, program_break)`.
    pub heap_base: u64,
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
    // Direct KVM workers do not participate in Detcore's virtual clock. Keep a
    // private logical clock so repeated observations advance deterministically
    // without making host thread scheduling observable.
    // TODO-HUMAN-REVIEW(PR-221): Review direct-worker logical clock semantics.
    pub logical_clock_ns: u64,
    pub umask: libc::mode_t,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-228): Review caller-provided deterministic random seed state.
    pub random_seed: u64,
    /// Position in this task's deterministic getrandom byte stream. A new
    /// fork/thread starts at zero under its own virtual TID; exec preserves
    /// the caller's position. Only successful copyout advances the stream.
    pub getrandom_offset: u64,
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
    // TODO-HUMAN-REVIEW(PR-92): Review virtual nice process state.
    pub nice: libc::c_int,
    // TODO-HUMAN-REVIEW(PR-119): Review virtual scheduler/ioprio process state.
    pub sched_policy: libc::c_int,
    pub sched_priority: libc::c_int,
    pub sched_reset_on_fork: bool,
    pub ioprio: libc::c_int,
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
    /// Identity of each descriptor entry, independent of its filesystem object.
    /// Insertion, including a dup destination, creates a new identity. Table
    /// snapshots and fork copies retain it so unchanged host handles stay stable.
    pub fd_entry_ids: std::collections::BTreeMap<i32, std::sync::Arc<()>>,
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
    pub proc_mounts: std::sync::Arc<crate::proc_mounts::ProcMountSnapshot>,
    pub fdinfo_files:
        std::collections::BTreeMap<i32, std::sync::Arc<crate::executor::FdinfoDescription>>,
    pub fdinfo_table: std::sync::Weak<std::sync::Mutex<crate::executor::FileTableState>>,
    // AUTONOMOUS-BOT-IMPLEMENTED: Preserve deterministic file-object identity.
    // TODO-HUMAN-REVIEW(PR-136): Review descriptor identity and fork inheritance.
    // Every live descriptor strongly holds its identity; the process-shared
    // registry contains only weak references keyed by unexposed host identity.
    pub fd_object_inodes: std::collections::BTreeMap<i32, std::sync::Arc<GuestFileIdentity>>,
    pub file_identity_table: std::sync::Arc<std::sync::Mutex<GuestFileIdentityTable>>,
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
        self.random_device_descriptions.remove(&fd);
        let mut retired: Vec<_> = self.files.insert(fd, file).into_iter().collect();
        if fd == libc::STDIN_FILENO {
            retired.extend(self.take_stdin());
        }
        self.fd_entry_ids.insert(fd, std::sync::Arc::new(()));
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
        self.random_device_descriptions.remove(&fd);
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
        // TODO-HUMAN-REVIEW(PR-119): Review scheduler reset and ioprio fork inheritance.
        let reset_realtime = self.sched_reset_on_fork
            && matches!(self.sched_policy, libc::SCHED_FIFO | libc::SCHED_RR);
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
            pgid: self.pgid,
            tid: child_pid,
            ppid: self.pid,
            orphan_reaper_pid: std::sync::Arc::new(AtomicI32::new(0)),
            // A guest-created child always has a traced parent: this process.
            is_traced_tree_root: false,
            logical_clock_ns: self.logical_clock_ns,
            umask: self.umask,
            random_seed: self.random_seed,
            getrandom_offset: 0,
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
            nice: self.nice,
            sched_policy: if reset_realtime {
                libc::SCHED_OTHER
            } else {
                self.sched_policy
            },
            sched_priority: if reset_realtime {
                0
            } else {
                self.sched_priority
            },
            sched_reset_on_fork: false,
            ioprio: if self.ioprio >> IOPRIO_CLASS_SHIFT == 0 {
                0
            } else {
                self.ioprio
            },
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
            fd_entry_ids: self.fd_entry_ids.clone(),
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
            proc_mounts: self.proc_mounts.clone(),
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
        self.logical_clock_ns = previous.logical_clock_ns;
        self.signal_dequeue_failure = previous.signal_dequeue_failure;
        self.umask = previous.umask;
        self.random_seed = previous.random_seed;
        self.getrandom_offset = previous.getrandom_offset;
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
        self.nice = previous.nice;
        // TODO-HUMAN-REVIEW(PR-119): Review scheduler and ioprio exec inheritance.
        self.sched_policy = previous.sched_policy;
        self.sched_priority = previous.sched_priority;
        self.sched_reset_on_fork = previous.sched_reset_on_fork;
        self.ioprio = previous.ioprio;
        self.process_signals = std::sync::Arc::new(std::sync::Mutex::new(process_signals));
        self.signal_transaction = previous.signal_transaction;
        self.thread_signals = thread_signals;
        self.task_lifecycle = task_lifecycle;
        retired.extend(std::mem::replace(&mut self.files, files).into_values());
        self.file_retirement = previous.file_retirement;
        self.fd_entry_ids = fd_entry_ids;
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
        self.proc_mounts = previous.proc_mounts;
        self.fdinfo_files = fdinfo_files;
        self.fdinfo_table = previous.fdinfo_table;
        self.fd_object_inodes = fd_object_inodes;
        self.file_identity_table = file_identity_table;
        // The caller releases both descriptor and transaction guards before close.
        retired
    }
}

// TODO-HUMAN-REVIEW(PR-92): Review script loading and executable resolution.
pub(crate) fn load_static_elf(
    memory: &mut GuestMemory,
    image: &[u8],
    argv: &[&str],
    envp: &[&str],
    cwd: &Path,
) -> Result<LoadedStaticElf> {
    initialize_regular_create_directory_policy()?;
    // TODO-HUMAN-REVIEW(PR-132): Review ELF user-map construction.
    let owner = memory.clone();
    let _transaction = owner.allocation_guard();
    begin_image(memory)?;
    let result = load_executable(memory, image, argv, envp, cwd, 0, None);
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
    let result = load_executable(memory, &image, argv, envp, cwd, 0, Some(Arc::new(file)));
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
fn load_executable(
    memory: &mut GuestMemory,
    image: &[u8],
    argv: &[&str],
    envp: &[&str],
    cwd: &Path,
    script_depth: usize,
    executable_file: Option<Arc<File>>,
) -> Result<LoadedStaticElf> {
    let argv0 = *argv
        .first()
        .ok_or_else(|| Error::UnsupportedElf("argv must contain at least argv[0]".to_string()))?;
    if let Some((interpreter, optional_argument)) = parse_shebang(image)? {
        if script_depth >= MAX_SCRIPT_INTERPRETERS {
            return Err(Error::UnsupportedElf(
                "script interpreter recursion limit exceeded".to_string(),
            ));
        }
        let script_path = if let Some(file) = executable_file.as_ref() {
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
            &interpreter_argv,
            envp,
            cwd,
            script_depth + 1,
            interpreter_file,
        );
    }

    let elf = Elf::parse(image)?;
    validate_elf(&elf, true)?;

    for entry in argv.iter().chain(envp.iter()) {
        if entry.as_bytes().contains(&0) {
            return Err(Error::UnsupportedElf(
                "an argv/envp entry contains an embedded NUL byte".to_string(),
            ));
        }
    }

    let main_bias = if elf.header.e_type == ET_DYN {
        MAIN_LOAD_BIAS
    } else {
        0
    };
    let main_end = load_segments(memory, image, &elf, main_bias)?;
    let main_entry = main_bias
        .checked_add(elf.entry)
        .ok_or_else(|| Error::UnsupportedElf("main entry point overflow".to_string()))?;

    let (entry_point, at_base, image_end) = if let Some(path) = interpreter_path(image, &elf)? {
        // TODO-HUMAN-REVIEW(reverie-kvm): relocate the interpreter above large
        // main images instead of failing to load.
        //
        // Place the dynamic interpreter (ld.so) above the main image. Small
        // PIEs keep the historical fixed 16 MiB base, so their memory layout is
        // byte-identical to before. Large PIEs (e.g. rustc, cargo) whose image
        // would overrun that base get the interpreter relocated just above the
        // main image, with a page-aligned program-break gap, instead of the
        // previous hard "overlaps interpreter base" load failure.
        let interpreter_load_bias = interpreter_load_bias(main_end)?;
        let interpreter_image = read_interpreter_image(&path)?;
        let interpreter = Elf::parse(&interpreter_image)?;
        validate_elf(&interpreter, false)?;
        if interpreter.header.e_type != ET_DYN {
            return Err(Error::UnsupportedElf(
                "program interpreter must be ET_DYN".to_string(),
            ));
        }
        let interpreter_end = load_segments(
            memory,
            &interpreter_image,
            &interpreter,
            interpreter_load_bias,
        )?;
        let interpreter_entry = interpreter_load_bias
            .checked_add(interpreter.entry)
            .ok_or_else(|| Error::UnsupportedElf("interpreter entry point overflow".to_string()))?;
        (
            interpreter_entry,
            interpreter_load_bias,
            main_end.max(interpreter_end),
        )
    } else {
        (main_entry, 0, main_end)
    };

    let program_headers_address = elf
        .program_headers
        .iter()
        .find(|header| header.p_type == goblin::elf::program_header::PT_PHDR)
        .and_then(|header| main_bias.checked_add(header.p_vaddr))
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
    let (stack_pointer, auxv) = build_initial_stack(
        memory,
        &elf,
        argv,
        envp,
        program_headers_address,
        at_base,
        main_entry,
    )?;
    memory.map_user_range(memory.guest_end() - STACK_LIMIT, STACK_LIMIT, false)?;
    let program_break = align_up(main_end, PAGE_SIZE)?;
    let mmap_next = align_up(
        image_end
            .checked_add(MMAP_GAP)
            .ok_or_else(|| Error::UnsupportedElf("initial mmap base overflow".to_string()))?,
        PAGE_SIZE,
    )?;
    let mmap_limit = memory
        .guest_end()
        .checked_sub(STACK_LIMIT)
        .ok_or(Error::LongModeMemoryTooSmall)?;
    if mmap_next >= mmap_limit {
        return Err(Error::LongModeMemoryTooSmall);
    }
    let brk_limit = if at_base == 0 {
        mmap_next
    } else {
        // The interpreter is loaded at `at_base`; the program break grows in the
        // gap between the main image and the interpreter, so cap it there. For a
        // relocated (large-PIE) interpreter this equals the dynamic base rather
        // than the fixed `INTERPRETER_LOAD_BIAS`.
        at_base
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
        pgid: 1,
        tid: 1,
        ppid: 0,
        orphan_reaper_pid: std::sync::Arc::new(AtomicI32::new(0)),
        // The backend-installed image is the root of the traced process tree.
        // `KvmBackend::set_root_pid` may later renumber `pid`/`tid`/`ppid`; it
        // must not change this.
        is_traced_tree_root: true,
        logical_clock_ns: 0,
        umask: 0o022,
        random_seed: 0,
        getrandom_offset: 0,
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
        nice: 0,
        // TODO-HUMAN-REVIEW(PR-119): Review default virtual scheduler and ioprio state.
        sched_policy: libc::SCHED_OTHER,
        sched_priority: 0,
        sched_reset_on_fork: false,
        ioprio: 0,
        process_signals: std::sync::Arc::new(std::sync::Mutex::new(ProcessSignalState::default())),
        signal_transaction: Default::default(),
        thread_signals: SharedThreadSignalState::default(),
        signal_dequeue_failure: None,
        task_lifecycle: std::sync::Arc::new(std::sync::Mutex::new(TaskLifecycleTable::with_root(
            1, 1, 1, true,
        ))),
        files: std::collections::BTreeMap::new(),
        file_retirement: FileRetirement::default(),
        fd_entry_ids: std::collections::BTreeMap::new(),
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
        proc_mounts: std::sync::Arc::new(crate::proc_mounts::ProcMountSnapshot::capture()?),
        fdinfo_files: std::collections::BTreeMap::new(),
        fdinfo_table: std::sync::Weak::new(),
        fd_object_inodes: std::collections::BTreeMap::new(),
        file_identity_table: std::sync::Arc::new(std::sync::Mutex::new(GuestFileIdentityTable {
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

fn load_segments(
    memory: &mut GuestMemory,
    image: &[u8],
    elf: &Elf<'_>,
    load_bias: u64,
) -> Result<u64> {
    let entry = load_bias
        .checked_add(elf.entry)
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

        let segment_start = load_bias
            .checked_add(header.p_vaddr)
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

fn build_initial_stack(
    memory: &mut GuestMemory,
    elf: &Elf<'_>,
    argv: &[&str],
    envp: &[&str],
    program_headers_address: u64,
    at_base: u64,
    at_entry: u64,
) -> Result<(u64, Vec<(libc::c_ulong, libc::c_ulong)>)> {
    // Strings (argv[], envp[], the AT_RANDOM bytes) live in a high region that
    // grows downward from the top of guest memory; the pointer arrays and auxv
    // that reference them are written lower, at the final `rsp`.
    let mut cursor = memory.guest_end().saturating_sub(STACK_STRING_HEADROOM);

    // Push argv/envp strings, recording each guest address. argv[0] is first.
    let mut arg_addresses = Vec::with_capacity(argv.len());
    for arg in argv {
        cursor = push_c_string(memory, cursor, arg.as_bytes())?;
        arg_addresses.push(cursor);
    }
    let mut env_addresses = Vec::with_capacity(envp.len());
    for entry in envp {
        cursor = push_c_string(memory, cursor, entry.as_bytes())?;
        env_addresses.push(cursor);
    }
    let argv0_address = arg_addresses[0];

    let random = [
        0x52, 0x65, 0x76, 0x65, 0x72, 0x69, 0x65, 0x2d, 0x4b, 0x56, 0x4d, 0x2d, 0x45, 0x4c, 0x46,
        0x21,
    ];
    cursor = cursor
        .checked_sub(random.len() as u64)
        .ok_or(Error::LongModeMemoryTooSmall)?;
    memory.write_raw(cursor, &random)?;
    let random_address = cursor;

    // Build the SysV initial stack image, low to high:
    //   argc, argv[0..], NULL, envp[0..], NULL, auxv pairs.., AT_NULL/0
    let auxv = vec![
        (AT_SYSINFO_EHDR, VDSO_ADDRESS),
        (AT_PHDR, program_headers_address),
        (AT_PHENT, u64::from(elf.header.e_phentsize)),
        (AT_PHNUM, u64::from(elf.header.e_phnum)),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_BASE, at_base),
        (AT_ENTRY, at_entry),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_CLKTCK, CLOCK_TICKS_PER_SECOND),
        (AT_SECURE, 0),
        (AT_RANDOM, random_address),
        (AT_EXECFN, argv0_address),
    ];

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
    if cursor < memory.guest_end().saturating_sub(STACK_LIMIT) {
        return Err(Error::LongModeMemoryTooSmall);
    }

    let mut stack = Vec::with_capacity(stack_size as usize);
    for word in words {
        stack.extend_from_slice(&word.to_le_bytes());
    }
    memory.write_raw(cursor, &stack)?;
    Ok((cursor, auxv))
}

/// Writes a NUL-terminated copy of `bytes` ending just below `cursor` and
/// returns the guest address of the first byte (the new, lower cursor).
fn push_c_string(memory: &mut GuestMemory, cursor: u64, bytes: &[u8]) -> Result<u64> {
    let start = cursor
        .checked_sub((bytes.len() + 1) as u64)
        .ok_or(Error::LongModeMemoryTooSmall)?;
    memory.write_raw(start, bytes)?;
    memory.write_raw(start + bytes.len() as u64, &[0])?;
    Ok(start)
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or_else(|| Error::UnsupportedElf("address alignment overflow".to_string()))
}

/// Choose the load base for the dynamic interpreter (`ld.so`) given the end of
/// the already-loaded main image.
///
/// Small position-independent executables keep the historical fixed
/// [`INTERPRETER_LOAD_BIAS`], so their layout is unchanged. When the main image
/// would reach into or past that base (large PIEs such as `rustc` or `cargo`),
/// the interpreter is instead placed just above the main image, page-aligned
/// and past a reserved [`INTERPRETER_MIN_BRK_HEADROOM`] program-break gap. This
/// replaces the previous hard "overlaps interpreter base" load failure.
fn interpreter_load_bias(main_end: u64) -> Result<u64> {
    if main_end <= INTERPRETER_LOAD_BIAS {
        Ok(INTERPRETER_LOAD_BIAS)
    } else {
        align_up(
            main_end
                .checked_add(INTERPRETER_MIN_BRK_HEADROOM)
                .ok_or_else(|| Error::UnsupportedElf("interpreter base overflow".to_string()))?,
            PAGE_SIZE,
        )
    }
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
            BOOT_RESERVED_END / PAGE_SIZE + 2 + STACK_LIMIT / PAGE_SIZE
        );
        assert_eq!(
            memory.allocation_cursors().unwrap().mmap_next,
            loaded.mmap_next
        );
        let mut code = [0; 2];
        memory.read_raw(TEST_LOAD_ADDRESS, &mut code).unwrap();
        assert_eq!(code, [0x90, 0xc3]);
        let mut argc = [0; 8];
        memory.read_raw(loaded.stack_pointer, &mut argc).unwrap();
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

    #[test]
    fn small_pie_keeps_fixed_interpreter_base() {
        // A typical small PIE loads well under 16 MiB; layout must be unchanged.
        assert_eq!(
            interpreter_load_bias(MAIN_LOAD_BIAS).unwrap(),
            INTERPRETER_LOAD_BIAS
        );
        assert_eq!(
            interpreter_load_bias(3 * 1024 * 1024).unwrap(),
            INTERPRETER_LOAD_BIAS
        );
        // Exactly at the fixed base still uses it (boundary is inclusive).
        assert_eq!(
            interpreter_load_bias(INTERPRETER_LOAD_BIAS).unwrap(),
            INTERPRETER_LOAD_BIAS
        );
    }

    #[test]
    fn large_pie_relocates_interpreter_above_main_image() {
        // rustc/cargo observed main image end that overran the fixed base.
        let main_end = 0x015b_bb30;
        let base = interpreter_load_bias(main_end).unwrap();
        // Interpreter is placed above the main image (no overlap)...
        assert!(
            base > main_end,
            "interpreter base {base:#x} must clear main end {main_end:#x}"
        );
        // ...page-aligned...
        assert_eq!(
            base % PAGE_SIZE,
            0,
            "interpreter base {base:#x} must be page aligned"
        );
        // ...past the reserved program-break headroom...
        assert!(
            base >= main_end + INTERPRETER_MIN_BRK_HEADROOM,
            "interpreter base {base:#x} must reserve brk headroom above {main_end:#x}"
        );
        // ...and above the historical fixed base since the image overran it.
        assert!(base > INTERPRETER_LOAD_BIAS);
        // Exact expected value: align_up(main_end + headroom, PAGE_SIZE).
        assert_eq!(
            base,
            align_up(main_end + INTERPRETER_MIN_BRK_HEADROOM, PAGE_SIZE).unwrap()
        );
    }

    #[test]
    fn interpreter_base_overflow_is_reported() {
        // A main image ending near u64::MAX cannot reserve headroom; report it
        // rather than wrapping.
        assert!(interpreter_load_bias(u64::MAX - 1024).is_err());
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
