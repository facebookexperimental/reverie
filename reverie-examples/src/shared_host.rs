/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Shared example host results, launch inputs, and native recorder reference.
//! This module does not initialize an example preload or choose an external runtime.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::path::PathBuf;

use reverie::ExitStatus;
use reverie::syscalls::Sysno;
use reverie_util::CommonToolArguments;

use crate::tools::recorder_tool::Outcome;
use crate::tools::recorder_tool::Report;
use crate::tools::recorder_tool::report;

/// A Reverie backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum BackendKind {
    /// reverie-ptrace: the tool runs in the tracer.
    Ptrace,
    /// reverie-kvm: the program runs in a KVM guest, the tool in the host.
    Kvm,
    /// reverie-liteinst: the tool runs in the program, through a preload.
    Liteinst,
    /// reverie-liteinst without site patching: every syscall traps.
    InGuestTrap,
}

/// How a tool's run ended.
pub struct Run<G> {
    /// How the program ended, as `raise_or_exit` passes it on.
    pub status: ExitStatus,
    /// The program's exit code, or 128 plus the signal that ended it.
    pub exit_code: i32,
    /// The tool's global state at the end.
    pub global_state: G,
    /// What the program wrote to stdout and stderr, where the backend
    /// captured it (the in-guest backends); otherwise the program wrote to
    /// this process's own.
    pub captured: Option<(Vec<u8>, Vec<u8>)>,
}

/// Why a tool did not run to completion.
#[derive(Debug)]
pub enum RunError {
    /// The backend cannot host this tool; the text names why.
    Refused(String),
    /// The backend failed.
    Failed(anyhow::Error),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Refused(reason) => write!(f, "REFUSED: {reason}"),
            RunError::Failed(error) => write!(f, "{error:#}"),
        }
    }
}

impl<E: Into<anyhow::Error>> From<E> for RunError {
    fn from(error: E) -> Self {
        RunError::Failed(error.into())
    }
}

/// The exit code of `status`: its code, or 128 plus the signal that ended it.
pub fn exit_code(status: ExitStatus) -> i32 {
    match status {
        ExitStatus::Exited(code) => code,
        ExitStatus::Signaled(signal, _) => 128 + signal as i32,
        ExitStatus::SignaledRaw(signal, _) => 128 + signal,
    }
}

/// The guest environment: the host's, or only a PATH with `--no-host-envs`,
/// plus each `--env`.
pub fn guest_environment(args: &CommonToolArguments) -> anyhow::Result<BTreeMap<String, String>> {
    let mut environment = if args.no_host_envs {
        BTreeMap::from([("PATH".to_string(), "/bin:/usr/bin".to_string())])
    } else {
        let mut environment = BTreeMap::new();
        for (key, value) in std::env::vars_os() {
            let key = key.into_string().map_err(|_| {
                anyhow::anyhow!("the KVM backend cannot pass a non-UTF-8 environment key")
            })?;
            let value = value.into_string().map_err(|_| {
                anyhow::anyhow!(
                    "the KVM backend cannot pass a non-UTF-8 environment value for {key:?}"
                )
            })?;
            environment.insert(key, value);
        }
        environment
    };
    environment.extend(args.envs.iter().cloned());
    Ok(environment)
}

pub fn resolve_program(
    program: &str,
    environment: &BTreeMap<String, String>,
    cwd: &Path,
) -> io::Result<PathBuf> {
    if program.contains('/') {
        let path = Path::new(program);
        let candidate = if path.is_absolute() {
            path.to_path_buf()
        } else {
            cwd.join(path)
        };
        return require_executable(candidate.canonicalize()?);
    }

    let search_path = environment
        .get("PATH")
        .map(String::as_str)
        .unwrap_or("/usr/local/bin:/usr/bin:/bin");
    let mut permission_error = None;
    for directory in std::env::split_paths(OsStr::new(search_path)) {
        let directory = if directory.is_absolute() {
            directory
        } else {
            cwd.join(directory)
        };
        let candidate = directory.join(program);
        if candidate.is_file() {
            match require_executable(candidate.canonicalize()?) {
                Ok(candidate) => return Ok(candidate),
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    permission_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
    }

    if let Some(error) = permission_error {
        Err(error)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("cannot resolve executable {program:?} in PATH"),
        ))
    }
}

fn require_executable(path: PathBuf) -> io::Result<PathBuf> {
    let metadata = path.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("executable path is not a regular file: {}", path.display()),
        ));
    }
    let path_bytes = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("executable path contains a NUL byte: {}", path.display()),
        )
    })?;
    let accessible = unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            path_bytes.as_ptr(),
            libc::X_OK,
            libc::AT_EACCESS,
        )
    };
    if accessible != 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!(
                "executable path is not executable: {}: {error}",
                path.display()
            ),
        ));
    }
    Ok(path)
}

/// Run `program` natively, observing its syscalls with plain ptrace (no
/// Reverie): a syscall-stop at each entry and exit only reads registers, so
/// the program gets the results Linux gives it.
pub fn run_native(program: &Path, args: &[OsString]) -> anyhow::Result<Report> {
    use std::collections::BTreeSet;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::ffi::OsStringExt;

    use nix::sys::ptrace;
    use nix::sys::signal::Signal;
    use nix::sys::wait::WaitPidFlag;
    use nix::sys::wait::WaitStatus;
    use nix::sys::wait::waitpid;
    use nix::unistd::ForkResult;
    use nix::unistd::Pid as NixPid;

    let argv = std::iter::once(program.as_os_str())
        .chain(args.iter().map(OsString::as_os_str))
        .map(|arg| CString::new(arg.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let path = CString::new(program.as_os_str().as_bytes())?;
    // The environment in name order, as reverie-process's `Command` passes
    // it to a ptrace or KVM guest, so that the order, which a program can
    // see, is not a difference between the launchers.
    let mut environment = std::env::vars_os().collect::<Vec<_>>();
    environment.sort();
    let envp = environment
        .into_iter()
        .map(|(key, value)| {
            let mut entry = key.into_vec();
            entry.push(b'=');
            entry.extend(value.into_vec());
            CString::new(entry)
        })
        .collect::<Result<Vec<_>, _>>()?;
    // SAFETY: the child only calls async-signal-safe functions before exec.
    let child = match unsafe { nix::unistd::fork() }? {
        ForkResult::Child => {
            // The Rust runtime ignores SIGPIPE; a program starts with the
            // default, as reverie-ptrace's and the shell's children do.
            // SAFETY: resetting a disposition in the forked child.
            let _ = unsafe {
                nix::sys::signal::signal(Signal::SIGPIPE, nix::sys::signal::SigHandler::SigDfl)
            };
            // Without address-space randomization, as reverie-ptrace starts
            // its guests: a randomized heap start changes how often a
            // program grows its heap (brk), a difference no backend made.
            // SAFETY: personality(2) in the forked child, before exec.
            unsafe {
                let current = libc::personality(0xffff_ffff);
                if current != -1 {
                    libc::personality((current as libc::c_ulong) | 0x0004_0000);
                }
            }
            let _ = ptrace::traceme();
            let _ = nix::sys::signal::raise(Signal::SIGSTOP);
            let _ = nix::unistd::execve(&path, &argv, &envp);
            // SAFETY: exiting the forked child without unwinding.
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child } => child,
    };
    waitpid(child, None)?;
    ptrace::setoptions(
        child,
        ptrace::Options::PTRACE_O_TRACESYSGOOD
            | ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACEVFORK
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEEXEC
            | ptrace::Options::PTRACE_O_EXITKILL,
    )?;
    ptrace::syscall(child, None)?;

    let mut events = Vec::new();
    // The call each thread is in, from its entry stop to its exit stop.
    let mut entered: BTreeMap<i32, i64> = BTreeMap::new();
    // New threads, whose first stop is the SIGSTOP that starts them traced.
    let mut starting: BTreeSet<i32> = BTreeSet::new();
    let mut exit_code = -1;
    loop {
        let status = match waitpid(NixPid::from_raw(-1), Some(WaitPidFlag::__WALL)) {
            Ok(status) => status,
            Err(nix::errno::Errno::ECHILD) => break,
            Err(error) => return Err(error.into()),
        };
        match status {
            WaitStatus::PtraceSyscall(pid) => {
                let tid = pid.as_raw();
                let regs = ptrace::getregs(pid)?;
                match entered.remove(&tid) {
                    None => {
                        let sysno = regs.orig_rax as i64;
                        if sysno == libc::SYS_exit || sysno == libc::SYS_exit_group {
                            events.push((tid, sysno, Outcome::NoReturn));
                        } else {
                            entered.insert(tid, sysno);
                        }
                    }
                    Some(sysno) => {
                        let value = regs.rax as i64;
                        let outcome = if (-4095..0).contains(&value) {
                            Outcome::Errno(-value as i32)
                        } else {
                            Outcome::Value(value)
                        };
                        events.push((tid, sysno, outcome));
                    }
                }
                let _ = ptrace::syscall(pid, None);
            }
            WaitStatus::PtraceEvent(pid, _, event) => {
                if (event == libc::PTRACE_EVENT_FORK
                    || event == libc::PTRACE_EVENT_VFORK
                    || event == libc::PTRACE_EVENT_CLONE)
                    && let Ok(new) = ptrace::getevent(pid)
                {
                    starting.insert(new as i32);
                }
                let _ = ptrace::syscall(pid, None);
            }
            WaitStatus::Stopped(pid, signal) => {
                let tid = pid.as_raw();
                let deliver = if signal == Signal::SIGSTOP && starting.remove(&tid) {
                    None
                } else {
                    Some(signal)
                };
                let _ = ptrace::syscall(pid, deliver);
            }
            WaitStatus::Exited(pid, code) => {
                if let Some(sysno) = entered.remove(&pid.as_raw()) {
                    events.push((pid.as_raw(), sysno, Outcome::NoReturn));
                }
                if pid == child {
                    exit_code = code;
                }
            }
            WaitStatus::Signaled(pid, signal, _) if pid == child => {
                exit_code = 128 + signal as i32;
            }
            _ => {}
        }
    }
    let events = events
        .into_iter()
        .map(|(tid, sysno, outcome)| {
            let name = Sysno::from(sysno as i32).name().to_owned();
            (tid, name, outcome)
        })
        .collect();
    Ok(report(exit_code, events))
}
