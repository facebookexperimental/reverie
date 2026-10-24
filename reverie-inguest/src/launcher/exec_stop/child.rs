/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The launcher's local-process unsafe boundary. Child setup uses raw
//! syscalls after fork: no allocator, libc locks, destructors, or unwinding.

use std::ffi::CString;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use safeptrace::Pid;

use super::CleanupConfirmation;
use super::CleanupOwner;
use super::CleanupReceipt;
use super::CleanupWaitFailure;

// Descriptor-only observation in this existing audited unsafe boundary.
#[cfg(feature = "loader-private-runtime")]
pub(super) fn live_birth_pidfd(fd: &std::os::fd::OwnedFd) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut descriptor = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live initialized pollfd, no borrowed target memory, timeout0.
    let result = unsafe { libc::poll(&raw mut descriptor, 1, 0) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let error = if descriptor.revents & libc::POLLNVAL != 0 {
        Some(libc::EBADF)
    } else if descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
        Some(libc::ESRCH)
    } else if descriptor.revents != 0 || result != 0 {
        Some(libc::EIO)
    } else {
        None
    };
    match error {
        Some(errno) => Err(std::io::Error::from_raw_os_error(errno)),
        None => Ok(()),
    }
}

/// Atomic clone/pidfd ownership before safeptrace acquires its generation.
/// Once transferred, only safeptrace may wait for this child.
pub(super) struct PendingChild {
    pid: Pid,
    pidfd: OwnedFd,
    owned: bool,
    evidence: CleanupReceipt,
    // Ptrace and child waiting stay on the OS thread that created the child.
    _local: core::marker::PhantomData<std::rc::Rc<()>>,
}

impl PendingChild {
    pub fn pid(&self) -> Pid {
        self.pid
    }

    // Retain the actual atomic CLONE_PIDFD before the generation takes wait
    // ownership. Failure leaves PendingChild responsible for kill/wait.
    #[cfg(feature = "loader-private-runtime")]
    pub(super) fn duplicate_birth_pidfd(&self) -> std::io::Result<OwnedFd> {
        self.pidfd.try_clone()
    }

    pub fn transfer_to_ptracer(&mut self) {
        self.evidence.borrow_mut().owner = CleanupOwner::Ptracer;
        self.owned = false;
    }
}

impl PendingChild {
    pub(super) fn is_owned(&self) -> bool {
        self.owned
    }

    pub(super) fn retire(&mut self) {
        if !self.owned {
            return;
        }
        // SAFETY: this retained descriptor came atomically from clone3. It
        // names the original child even if another waiter has reaped it.
        let result = unsafe {
            syscall6(
                libc::SYS_pidfd_send_signal as u64,
                [
                    self.pidfd.as_raw_fd() as u64,
                    libc::SIGKILL as u64,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        };
        {
            let mut evidence = self.evidence.borrow_mut();
            evidence.kill_requested = true;
            evidence.kill_errno = (result < 0).then_some((-result) as i32);
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            use nix::sys::wait::Id;
            use nix::sys::wait::WaitPidFlag;
            use nix::sys::wait::WaitStatus;
            use nix::sys::wait::waitid;
            match waitid(
                Id::PIDFd(self.pidfd.as_fd()),
                WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG,
            ) {
                Ok(WaitStatus::Exited(_, code)) => {
                    let mut evidence = self.evidence.borrow_mut();
                    self.owned = false;
                    evidence.confirmed = true;
                    evidence.confirmation = Some(CleanupConfirmation::PidfdWaitid);
                    evidence.terminal_status = Some(safeptrace::ExitStatus::Exited(code));
                    break;
                }
                Ok(WaitStatus::Signaled(_, signal, core_dumped)) => {
                    let mut evidence = self.evidence.borrow_mut();
                    self.owned = false;
                    evidence.confirmed = true;
                    evidence.confirmation = Some(CleanupConfirmation::PidfdWaitid);
                    evidence.terminal_status =
                        Some(safeptrace::ExitStatus::Signaled(signal, core_dumped));
                    break;
                }
                Err(nix::errno::Errno::EINTR) if std::time::Instant::now() < deadline => continue,
                Ok(WaitStatus::StillAlive) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                other => {
                    self.evidence.borrow_mut().wait_error = Some(match other {
                        Err(errno) => CleanupWaitFailure::Errno(errno as i32),
                        Ok(WaitStatus::StillAlive) => CleanupWaitFailure::TimedOut,
                        Ok(_) => CleanupWaitFailure::UnexpectedStatus,
                    });

                    break;
                }
            }
        }
    }
}

impl Drop for PendingChild {
    fn drop(&mut self) {
        self.retire();
    }
}

#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// All pointer storage is made before fork and retained until exec or _exit.
pub struct PreparedExec<'fd> {
    program: CString,
    _arguments: Vec<CString>,
    arguments: Vec<*const libc::c_char>,
    _environment: Vec<CString>,
    environment: Vec<*const libc::c_char>,
    inherited: Vec<std::os::fd::BorrowedFd<'fd>>,
    cwd: Option<std::fs::File>,
    ptrace_launch_facts: bool,
}

impl<'fd> PreparedExec<'fd> {
    /// Match the ordinary ptrace child's deterministic address-space and
    /// terminal job-control setup before exec, without changing this parent.
    /// The default constructor preserves its existing inherited behavior.
    pub fn with_ptrace_launch_facts(mut self) -> Self {
        self.ptrace_launch_facts = true;
        self
    }

    #[cfg(feature = "loader-private-runtime")]
    pub(super) fn retains_descriptor(&self, fd: std::os::fd::BorrowedFd<'_>) -> bool {
        self.inherited
            .iter()
            .any(|inherited| inherited.as_raw_fd() == fd.as_raw_fd())
    }

    /// Prepare a direct exec before clone. No PATH or shell fallback is used.
    ///
    /// `arguments` includes argv0, independently of `program`. Environment is
    /// exact; stdio and other caller-owned process setup are inherited. The
    /// optional cwd is opened now and entered by descriptor in the child.
    /// Bootstrap descriptors remain borrowed until the physical child retires.
    pub fn new(
        program: &std::path::Path,
        arguments: &[std::ffi::OsString],
        environment: &[(std::ffi::OsString, std::ffi::OsString)],
        cwd: Option<&std::path::Path>,
        inherited: Vec<std::os::fd::BorrowedFd<'fd>>,
    ) -> Result<Self, String> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        if !program.is_absolute() {
            return Err("exec_stop_program_must_be_absolute".into());
        }
        if arguments.is_empty() {
            return Err("exec_stop_missing_argv0".into());
        }
        if inherited.iter().any(|fd| fd.as_raw_fd() <= 2) {
            return Err("exec_stop_bootstrap_fd_must_not_be_stdio".into());
        }
        let mut fd_numbers = std::collections::BTreeSet::new();
        if inherited
            .iter()
            .any(|fd| !fd_numbers.insert(fd.as_raw_fd()))
        {
            return Err("exec_stop_duplicate_bootstrap_fd".into());
        }
        let program = CString::new(program.as_os_str().as_bytes())
            .map_err(|_| "program contains NUL".to_owned())?;
        let arguments: Vec<CString> = arguments
            .iter()
            .map(|a| CString::new(a.as_bytes()).map_err(|_| "argument contains NUL".to_owned()))
            .collect::<Result<_, _>>()?;
        let mut keys = std::collections::BTreeSet::new();
        let environment: Vec<CString> = environment
            .iter()
            .map(|(key, value)| {
                if key.is_empty() || key.as_bytes().contains(&b'=') || !keys.insert(key.clone()) {
                    return Err("invalid or duplicate environment key".to_owned());
                }
                let mut bytes = key.as_bytes().to_vec();
                bytes.push(b'=');
                bytes.extend_from_slice(value.as_bytes());
                CString::new(bytes).map_err(|_| "environment contains NUL".to_owned())
            })
            .collect::<Result<_, _>>()?;
        let cwd = cwd
            .map(|path| {
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
                    .open(path)
            })
            .transpose()
            .map_err(|error| format!("exec_stop_cwd: {error}"))?;
        let pointers = |strings: &[CString]| {
            strings
                .iter()
                .map(|s| s.as_ptr())
                .chain([std::ptr::null()])
                .collect()
        };
        Ok(Self {
            program,
            arguments: pointers(&arguments),
            environment: pointers(&environment),
            _arguments: arguments,
            _environment: environment,
            inherited,
            cwd,
            ptrace_launch_facts: false,
        })
    }

    pub(super) fn fork(&self, evidence: CleanupReceipt) -> Result<PendingChild, std::io::Error> {
        // SAFETY: the child uses only raw syscalls and immutable preallocated
        // storage, then execve or exit_group. It cannot unwind or run Drop.
        // Parent memory and all retained CString buffers remain live in both
        // copies. No child code acquires inherited userspace locks.
        let parent = unsafe { syscall6(libc::SYS_getpid as u64, [0; 6]) };
        let mut pidfd = -1_i32;
        let arguments = CloneArgs {
            flags: libc::CLONE_PIDFD as u64,
            pidfd: (&raw mut pidfd) as u64,
            exit_signal: libc::SIGCHLD as u64,
            child_tid: 0,
            parent_tid: 0,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: 0,
        };
        // SAFETY: no CLONE_VM and no replacement stack: fork semantics.
        // The kernel writes an owned CLOEXEC pidfd into this live scalar in
        // the parent. Both branches retain the preallocated child setup.
        let child = unsafe {
            syscall6(
                libc::SYS_clone3 as u64,
                [
                    (&raw const arguments) as u64,
                    core::mem::size_of::<CloneArgs>() as u64,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        };
        if child < 0 {
            return Err(std::io::Error::from_raw_os_error(-child as i32));
        }
        if child == 0 {
            // SAFETY: everything dereferenced by child_entry was prepared in
            // this process before fork; the child never returns.
            unsafe { self.child_entry(parent as u64) }
        }
        // SAFETY: successful CLONE_PIDFD transfers this fresh descriptor to
        // this parent. It is owned exactly once; the child cannot close it.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
        {
            let mut record = evidence.borrow_mut();
            record.child_created = true;
            record.owner = CleanupOwner::PendingPidfd;
        }
        Ok(PendingChild {
            pid: Pid::from_raw(child as i32),
            pidfd,
            owned: true,
            evidence,
            _local: core::marker::PhantomData,
        })
    }

    unsafe fn child_entry(&self, parent: u64) -> ! {
        // SAFETY: raw scalar syscall operands; the child has not exec'd guest
        // code. The parent-death check closes the gap before EXITKILL can be
        // installed at the first ptrace stop.
        unsafe {
            if syscall6(
                libc::SYS_prctl as u64,
                [
                    libc::PR_SET_PDEATHSIG as u64,
                    libc::SIGKILL as u64,
                    0,
                    0,
                    0,
                    0,
                ],
            ) < 0
                || syscall6(libc::SYS_getppid as u64, [0; 6]) != parent as i64
                || syscall6(
                    libc::SYS_prctl as u64,
                    [libc::PR_SET_NO_NEW_PRIVS as u64, 1, 0, 0, 0, 0],
                ) < 0
            {
                exit_child();
            }
            if self.ptrace_launch_facts {
                // Same request as reverie-ptrace::tracer::init_tracee. Raw
                // syscalls keep this existing post-clone boundary allocation
                // free; a refusal exits before executing the requested image.
                const PER_LINUX_NO_RANDOMIZE: u64 = 0x0004_0000;
                if syscall6(
                    libc::SYS_personality as u64,
                    [PER_LINUX_NO_RANDOMIZE, 0, 0, 0, 0, 0],
                ) < 0
                    || syscall6(
                        libc::SYS_personality as u64,
                        [u64::from(u32::MAX), 0, 0, 0, 0, 0],
                    ) != PER_LINUX_NO_RANDOMIZE as i64
                {
                    exit_child();
                }
                // x86-64 kernel sigaction layout, matching the ordinary
                // SIG_IGN/SA_RESTART/empty-mask request for both signals.
                // No handler executes: exec retains SIG_IGN, clearing action
                // flags/restorer/mask. No libc restorer address is transplanted.
                let ignored = [libc::SIG_IGN as u64, libc::SA_RESTART as u64, 0_u64, 0_u64];
                for signal in [libc::SIGTTIN, libc::SIGTTOU] {
                    if syscall6(
                        libc::SYS_rt_sigaction as u64,
                        [signal as u64, ignored.as_ptr() as u64, 0, 8, 0, 0],
                    ) < 0
                    {
                        exit_child();
                    }
                }
            }
            if let Some(cwd) = &self.cwd
                && syscall6(
                    libc::SYS_fchdir as u64,
                    [cwd.as_raw_fd() as u64, 0, 0, 0, 0, 0],
                ) < 0
            {
                exit_child();
            }
            for fd in &self.inherited {
                let fd = fd.as_raw_fd();
                if syscall6(
                    libc::SYS_fcntl as u64,
                    [fd as u64, libc::F_SETFD as u64, 0, 0, 0, 0],
                ) < 0
                {
                    exit_child();
                }
            }
            if syscall6(
                libc::SYS_ptrace as u64,
                [libc::PTRACE_TRACEME as u64, 0, 0, 0, 0, 0],
            ) < 0
            {
                exit_child();
            }
            let pid = syscall6(libc::SYS_getpid as u64, [0; 6]);
            if syscall6(
                libc::SYS_tgkill as u64,
                [pid as u64, pid as u64, libc::SIGSTOP as u64, 0, 0, 0],
            ) < 0
            {
                exit_child();
            }
            // The parent's first resume follows SETOPTIONS(EXITKILL|TRACEEXEC).
            // Every pointer names immutable, NUL-terminated pre-fork storage.
            syscall6(
                libc::SYS_execve as u64,
                [
                    self.program.as_ptr() as u64,
                    self.arguments.as_ptr() as u64,
                    self.environment.as_ptr() as u64,
                    0,
                    0,
                    0,
                ],
            );
            exit_child()
        }
    }
}

/// # Safety
/// Pointer-valued arguments must satisfy the selected Linux syscall's ABI.
#[inline(always)]
unsafe fn syscall6(number: u64, args: [u64; 6]) -> i64 {
    let result: i64;
    // SAFETY: the caller owns every pointer operand. All x86-64 syscall
    // clobbers are declared and the stack is untouched by this instruction.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number => result,
            in("rdi") args[0], in("rsi") args[1], in("rdx") args[2],
            in("r10") args[3], in("r8") args[4], in("r9") args[5],
            lateout("rcx") _, lateout("r11") _, options(nostack),
        );
    }
    result
}

unsafe fn exit_child() -> ! {
    // SAFETY: exit_group has no pointer operands and terminates this child.
    unsafe {
        syscall6(libc::SYS_exit_group as u64, [122, 0, 0, 0, 0, 0]);
    }
    // SAFETY: exit_group cannot return without a hostile external supervisor;
    // retain a terminal trap instead of running any inherited Rust teardown.
    unsafe {
        core::arch::asm!("ud2", options(noreturn));
    }
}
