/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;

use goblin::elf::Elf;
use goblin::elf::header::EI_CLASS;
use goblin::elf::header::EI_DATA;
use goblin::elf::header::ELFCLASS64;
use goblin::elf::header::ELFDATA2LSB;
use goblin::elf::header::EM_X86_64;
use goblin::elf::header::ET_DYN;
use goblin::elf::header::ET_EXEC;
use goblin::elf::program_header::PF_X;
use goblin::elf::program_header::PT_INTERP;
use goblin::elf::program_header::PT_LOAD;

use crate::Error;
use crate::GuestMemory;
use crate::Result;
use crate::bootstrap::BOOT_RESERVED_END;
use crate::bootstrap::PROGRAM_HEADERS_ADDRESS;
use crate::bootstrap::VDSO_ADDRESS;

const PAGE_SIZE: u64 = 4096;
pub(crate) const STACK_LIMIT: u64 = 8 * 1024 * 1024;
const STACK_STRING_HEADROOM: u64 = 4096;
const MMAP_GAP: u64 = 1024 * 1024;
const MAX_PROGRAM_HEADERS_SIZE: usize = PAGE_SIZE as usize;
const MAX_INTERPRETER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SCRIPT_INTERPRETERS: usize = 4;
const MAIN_LOAD_BIAS: u64 = 2 * 1024 * 1024;
const INTERPRETER_LOAD_BIAS: u64 = 16 * 1024 * 1024;
const IOPRIO_CLASS_SHIFT: u32 = 13;
pub(crate) const GUEST_CAPABILITY_MASK: u64 = (1_u64 << 41) - 1;
/// Page-aligned program-break gap reserved between a large main image and a
/// relocated interpreter base. Only applies when the main image would overrun
/// the historical fixed [`INTERPRETER_LOAD_BIAS`]; small PIEs are unaffected.
const INTERPRETER_MIN_BRK_HEADROOM: u64 = 4 * 1024 * 1024;

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
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;
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
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-235): Review process-local virtual signalfd state.
#[derive(Clone, Debug, Default)]
pub(crate) struct SignalFdState {
    pub masks: std::collections::BTreeMap<i32, [u8; 8]>,
    pub pending: std::collections::BTreeSet<i32>,
}

/// Process-tree-wide state whose lifetime follows a guest task rather than an
/// individual [`LoadedStaticElf`] snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TaskLifecycleState {
    pub generation: u64,
    pub tgid: i32,
    pub robust_list_head: u64,
    pub dumpable: bool,
}

#[derive(Debug, Default)]
pub(crate) struct TaskLifecycleTable {
    next_generation: u64,
    tasks: std::collections::BTreeMap<i32, TaskLifecycleState>,
}

impl TaskLifecycleTable {
    pub(crate) fn with_root(tid: i32, tgid: i32, dumpable: bool) -> Self {
        let mut table = Self::default();
        table.register(tid, tgid, dumpable);
        table
    }

    pub(crate) fn register(&mut self, tid: i32, tgid: i32, dumpable: bool) -> u64 {
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("KVM task generation exhausted");
        let generation = self.next_generation;
        self.tasks.insert(
            tid,
            TaskLifecycleState {
                generation,
                tgid,
                robust_list_head: 0,
                dumpable,
            },
        );
        generation
    }

    pub(crate) fn ensure_registered(&mut self, tid: i32, tgid: i32, dumpable: bool) -> u64 {
        self.tasks
            .get(&tid)
            .map(|task| task.generation)
            .unwrap_or_else(|| self.register(tid, tgid, dumpable))
    }

    pub(crate) fn remove(&mut self, tid: i32, generation: u64) {
        if self
            .tasks
            .get(&tid)
            .is_some_and(|task| task.generation == generation)
        {
            self.tasks.remove(&tid);
        }
    }

    pub(crate) fn reset_after_exec(&mut self, tid: i32, tgid: i32) -> u64 {
        if let Some(task) = self.tasks.get_mut(&tid) {
            task.tgid = tgid;
            task.robust_list_head = 0;
            task.dumpable = true;
            task.generation
        } else {
            self.register(tid, tgid, true)
        }
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

    pub(crate) fn set_dumpable(&mut self, tgid: i32, dumpable: bool) -> bool {
        let mut found = false;
        for task in self.tasks.values_mut().filter(|task| task.tgid == tgid) {
            task.dumpable = dumpable;
            found = true;
        }
        found
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
    pub argv0: Vec<u8>,
    pub cwd: PathBuf,
    pub cwd_fd: std::fs::File,
    pub stdin: Option<std::fs::File>,
    pub auxv: Vec<(libc::c_ulong, libc::c_ulong)>,
    pub fs_base: u64,
    pub gs_base: u64,
    pub pid: i32,
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
    pub signal_actions: std::collections::BTreeMap<i32, [u8; 32]>,
    pub signal_mask: [u8; 8],
    pub signal_alt_stack: Option<Vec<u8>>,
    pub signalfd_state: std::sync::Arc<std::sync::Mutex<SignalFdState>>,
    // One process-tree-wide membership table distinguishes a live task with no
    // robust-list registration from an unknown/dead tid. Entries are created
    // with each executor, reset across exec, and removed when that executor is
    // destroyed.
    pub task_lifecycle: std::sync::Arc<std::sync::Mutex<TaskLifecycleTable>>,
    pub files: std::collections::BTreeMap<i32, std::fs::File>,
    // AUTONOMOUS-BOT-IMPLEMENTED: Keep deterministic random descriptors on the Tool path.
    // TODO-HUMAN-REVIEW(PR-235): Review random-device descriptor lifecycle parity.
    pub random_device_fds: std::collections::BTreeSet<i32>,
    pub stdout_alias_fds: std::collections::BTreeSet<i32>,
    pub stderr_alias_fds: std::collections::BTreeSet<i32>,
    // AUTONOMOUS-BOT-IMPLEMENTED: Model guest close-on-exec state independently.
    // TODO-HUMAN-REVIEW(#86): Review descriptor and signal inheritance across exec.
    pub cloexec_fds: std::collections::BTreeSet<i32>,
    pub closed_standard_fds: std::collections::BTreeSet<i32>,
    pub children: std::collections::BTreeMap<i32, i32>,
    // AUTONOMOUS-BOT-IMPLEMENTED: Track memfd-backed synthetic /proc descriptors.
    // TODO-HUMAN-REVIEW(reverie-kvm): Review synthetic /proc determinism.
    //
    // Maps a guest fd opened on a synthesized /proc file to the deterministic
    // inode reported for it. The descriptor itself lives in `files` as an
    // ordinary memfd, so read/lseek/close/dup/fork reuse the real-file paths;
    // this side table only marks which fds must report stable, synthesized
    // metadata instead of the memfd's per-run inode.
    pub proc_files: std::collections::BTreeMap<i32, u64>,
    // AUTONOMOUS-BOT-IMPLEMENTED: Preserve deterministic file-object identity.
    // TODO-HUMAN-REVIEW(PR-136): Review descriptor identity and fork inheritance.
    // Every live descriptor strongly holds its identity; the process-shared
    // registry contains only weak references keyed by unexposed host identity.
    pub fd_object_inodes: std::collections::BTreeMap<i32, std::sync::Arc<GuestFileIdentity>>,
    pub file_identity_table: std::sync::Arc<std::sync::Mutex<GuestFileIdentityTable>>,
}

impl LoadedStaticElf {
    pub(crate) fn try_clone_for_fork(&self, child_pid: i32) -> Result<Self> {
        // TODO-HUMAN-REVIEW(PR-136): Review shared file identity inheritance across fork.
        // TODO-HUMAN-REVIEW(PR-119): Review scheduler reset and ioprio fork inheritance.
        let reset_realtime = self.sched_reset_on_fork
            && matches!(self.sched_policy, libc::SCHED_FIFO | libc::SCHED_RR);
        let files = self
            .files
            .iter()
            .map(|(&fd, file)| Ok((fd, file.try_clone()?)))
            .collect::<Result<_>>()?;
        let signalfd_masks = self
            .signalfd_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .masks
            .clone();
        Ok(Self {
            entry_point: self.entry_point,
            stack_pointer: self.stack_pointer,
            heap_base: self.heap_base,
            program_break: self.program_break,
            brk_limit: self.brk_limit,
            mmap_base: self.mmap_base,
            mmap_next: self.mmap_next,
            mmap_limit: self.mmap_limit,
            argv0: self.argv0.clone(),
            cwd: self.cwd.clone(),
            cwd_fd: self.cwd_fd.try_clone()?,
            stdin: self
                .stdin
                .as_ref()
                .map(std::fs::File::try_clone)
                .transpose()?,
            auxv: self.auxv.clone(),
            fs_base: self.fs_base,
            gs_base: self.gs_base,
            pid: child_pid,
            tid: child_pid,
            ppid: self.pid,
            // A guest-created child always has a traced parent: this process.
            is_traced_tree_root: false,
            logical_clock_ns: self.logical_clock_ns,
            umask: self.umask,
            random_seed: self.random_seed,
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
            signal_actions: self.signal_actions.clone(),
            signal_mask: self.signal_mask,
            signal_alt_stack: self.signal_alt_stack.clone(),
            signalfd_state: std::sync::Arc::new(std::sync::Mutex::new(SignalFdState {
                masks: signalfd_masks,
                pending: std::collections::BTreeSet::new(),
            })),
            task_lifecycle: self.task_lifecycle.clone(),
            files,
            random_device_fds: self.random_device_fds.clone(),
            stdout_alias_fds: self.stdout_alias_fds.clone(),
            stderr_alias_fds: self.stderr_alias_fds.clone(),
            cloexec_fds: self.cloexec_fds.clone(),
            closed_standard_fds: self.closed_standard_fds.clone(),
            children: std::collections::BTreeMap::new(),
            proc_files: self.proc_files.clone(),
            fd_object_inodes: self.fd_object_inodes.clone(),
            file_identity_table: self.file_identity_table.clone(),
        })
    }

    // TODO-HUMAN-REVIEW(PR-136): Review live identity filtering across exec.
    pub(crate) fn inherit_process_state(&mut self, previous: Self) {
        let cloexec_fds = previous.cloexec_fds;
        let previous_signalfd_state = previous
            .signalfd_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let mut stdin = previous.stdin;
        let files: std::collections::BTreeMap<_, _> = previous
            .files
            .into_iter()
            .filter(|(fd, _)| !cloexec_fds.contains(fd))
            .collect();
        let random_device_fds = previous
            .random_device_fds
            .into_iter()
            .filter(|fd| files.contains_key(fd))
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
        let fd_object_inodes: std::collections::BTreeMap<_, _> = previous
            .fd_object_inodes
            .into_iter()
            .filter(|(fd, _)| files.contains_key(fd))
            .collect();
        let signalfd_state = SignalFdState {
            masks: previous_signalfd_state
                .masks
                .into_iter()
                .filter(|(fd, _)| files.contains_key(fd))
                .collect(),
            pending: previous_signalfd_state.pending,
        };
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
            stdin = None;
            closed_standard_fds.insert(libc::STDIN_FILENO);
        }
        for fd in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            if cloexec_fds.contains(&fd) {
                closed_standard_fds.insert(fd);
            }
        }
        let signal_actions = previous
            .signal_actions
            .into_iter()
            .filter_map(|(signal, action)| {
                let handler = usize::from_ne_bytes(
                    action[..std::mem::size_of::<usize>()]
                        .try_into()
                        .expect("signal handler field size"),
                );
                (handler == libc::SIG_IGN).then(|| {
                    let mut ignored = [0; 32];
                    ignored[..std::mem::size_of::<usize>()]
                        .copy_from_slice(&libc::SIG_IGN.to_ne_bytes());
                    (signal, ignored)
                })
            })
            .collect();

        self.cwd = previous.cwd;
        self.cwd_fd = previous.cwd_fd;
        self.stdin = stdin;
        self.pid = previous.pid;
        self.tid = previous.tid;
        self.ppid = previous.ppid;
        // `execve` replaces the image, never the position in the process tree.
        self.is_traced_tree_root = previous.is_traced_tree_root;
        self.logical_clock_ns = previous.logical_clock_ns;
        self.umask = previous.umask;
        self.random_seed = previous.random_seed;
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
        self.signal_actions = signal_actions;
        self.signal_mask = previous.signal_mask;
        self.signalfd_state = std::sync::Arc::new(std::sync::Mutex::new(signalfd_state));
        self.task_lifecycle = task_lifecycle;
        self.task_lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .reset_after_exec(self.tid, self.pid);
        self.files = files;
        self.random_device_fds = random_device_fds;
        self.stdout_alias_fds = stdout_alias_fds;
        self.stderr_alias_fds = stderr_alias_fds;
        self.cloexec_fds = std::collections::BTreeSet::new();
        self.closed_standard_fds = closed_standard_fds;
        self.children = previous.children;
        self.proc_files = proc_files;
        self.fd_object_inodes = fd_object_inodes;
        self.file_identity_table = file_identity_table;
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
    // TODO-HUMAN-REVIEW(PR-132): Review ELF user-map construction.
    memory.clear_user_access();
    load_executable(memory, image, argv, envp, cwd, 0)
}

// TODO-HUMAN-REVIEW(PR-92): Review recursive script interpreter loading.
fn load_executable(
    memory: &mut GuestMemory,
    image: &[u8],
    argv: &[&str],
    envp: &[&str],
    cwd: &Path,
    script_depth: usize,
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
        let script_path = resolve_executable_path(argv0, envp, cwd)?;
        let interpreter_path = resolve_executable_path(&interpreter, envp, cwd)?;
        let interpreter_image = std::fs::read(&interpreter_path).map_err(|error| {
            Error::UnsupportedElf(format!(
                "cannot read script interpreter {interpreter_path:?}: {error}"
            ))
        })?;
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
    copy_program_headers(memory, image, &elf)?;
    if program_headers_address == PROGRAM_HEADERS_ADDRESS {
        memory.map_user_range(PROGRAM_HEADERS_ADDRESS, PAGE_SIZE, false)?;
    }
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

    Ok(LoadedStaticElf {
        entry_point,
        stack_pointer,
        heap_base: program_break,
        program_break,
        brk_limit,
        mmap_base: mmap_next,
        mmap_next,
        mmap_limit,
        argv0: resolve_executable_path(argv0, envp, cwd)
            .unwrap_or_else(|_| PathBuf::from(argv0))
            .to_string_lossy()
            .into_owned()
            .into_bytes(),
        cwd: cwd.to_owned(),
        cwd_fd,
        stdin: None,
        auxv,
        fs_base: 0,
        gs_base: 0,
        pid: 1,
        tid: 1,
        ppid: 0,
        // The backend-installed image is the root of the traced process tree.
        // `KvmBackend::set_root_pid` may later renumber `pid`/`tid`/`ppid`; it
        // must not change this.
        is_traced_tree_root: true,
        logical_clock_ns: 0,
        umask: 0o022,
        random_seed: 0,
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
        signal_actions: std::collections::BTreeMap::new(),
        signal_mask: [0; 8],
        signal_alt_stack: None,
        signalfd_state: std::sync::Arc::new(std::sync::Mutex::new(SignalFdState::default())),
        task_lifecycle: std::sync::Arc::new(std::sync::Mutex::new(TaskLifecycleTable::with_root(
            1, 1, true,
        ))),
        files: std::collections::BTreeMap::new(),
        random_device_fds: std::collections::BTreeSet::new(),
        stdout_alias_fds: std::collections::BTreeSet::new(),
        stderr_alias_fds: std::collections::BTreeSet::new(),
        cloexec_fds: std::collections::BTreeSet::new(),
        closed_standard_fds: std::collections::BTreeSet::new(),
        children: std::collections::BTreeMap::new(),
        proc_files: std::collections::BTreeMap::new(),
        fd_object_inodes: std::collections::BTreeMap::new(),
        file_identity_table: std::sync::Arc::new(std::sync::Mutex::new(GuestFileIdentityTable {
            next_inode: 0x2100_0000,
            objects: std::collections::BTreeMap::new(),
        })),
    })
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

        memory.write(segment_start, contents)?;
        let zero_start = segment_start + header.p_filesz;
        let zero_len = usize::try_from(header.p_memsz - header.p_filesz)
            .map_err(|_| Error::UnsupportedElf("PT_LOAD memsz is too large".to_string()))?;
        memory.zero_raw(zero_start, zero_len)?;
        let mapped_start = segment_start & !(PAGE_SIZE - 1);
        let mapped_end = align_up(segment_end, PAGE_SIZE)?;
        memory.map_user_range(mapped_start, mapped_end - mapped_start, false)?;

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
    memory.write(PROGRAM_HEADERS_ADDRESS, headers)
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
    memory.write(cursor, &random)?;
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
    memory.write(cursor, &stack)?;
    Ok((cursor, auxv))
}

/// Writes a NUL-terminated copy of `bytes` ending just below `cursor` and
/// returns the guest address of the first byte (the new, lower cursor).
fn push_c_string(memory: &mut GuestMemory, cursor: u64, bytes: &[u8]) -> Result<u64> {
    let start = cursor
        .checked_sub((bytes.len() + 1) as u64)
        .ok_or(Error::LongModeMemoryTooSmall)?;
    memory.write(start, bytes)?;
    memory.write(start + bytes.len() as u64, &[0])?;
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
