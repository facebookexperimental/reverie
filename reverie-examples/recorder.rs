/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Run a program under the pass-through recorder (`recorder_tool.rs`) on a
//! chosen backend, or natively, and write every syscall it made with the
//! result it got, in a form that compares across backends and with native
//! Linux (`reverie-examples/e2e/compare.rs`).
//!
//! `--backend native` records the same with plain ptrace syscall stops, with
//! no Reverie at all. A backend that cannot host the recorder refuses by
//! name: the record is not written and the refusal is the last line of
//! stderr, starting `REFUSED:`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;

use clap::Parser;
use reverie::syscalls::Sysno;

#[path = "backend.rs"]
mod backend;
#[path = "recorder_tool.rs"]
mod recorder_tool;

use backend::BackendKind;
use recorder_tool::Outcome;
use recorder_tool::Recorder;
use recorder_tool::Report;
use recorder_tool::report;
use recorder_tool::reverie_events;

/// Where to run the program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Target {
    /// Natively, observed with plain ptrace syscall stops.
    Native,
    Ptrace,
    Kvm,
    Liteinst,
    InGuestTrap,
    E9patch,
    Dbt,
    Sabre,
}

/// Run PROGRAM under the pass-through recorder on BACKEND and write its
/// syscalls and their results to OUTPUT.
#[derive(Debug, Parser)]
struct Opts {
    #[clap(long, value_enum)]
    backend: Target,
    /// Where to write the record (stdout is the program's).
    #[clap(long)]
    output: PathBuf,
    /// The example preload the in-guest backends host the recorder in;
    /// by default `libreverie_examples.so` beside this binary.
    #[clap(long)]
    preload: Option<PathBuf>,
    #[clap(value_name = "PROGRAM")]
    program: PathBuf,
    #[clap(
        value_name = "ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    args: Vec<OsString>,
}

/// Run `program` natively, observing its syscalls with plain ptrace (no
/// Reverie): a syscall-stop at each entry and exit only reads registers, so
/// the program gets the results Linux gives it.
fn run_native(program: &Path, args: &[OsString]) -> anyhow::Result<Report> {
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

fn utf8(value: &std::ffi::OsStr) -> anyhow::Result<String> {
    value
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 program or argument {value:?}"))
}

fn reverie_backend(target: Target) -> BackendKind {
    match target {
        Target::Native => unreachable!("native runs without Reverie"),
        Target::Ptrace => BackendKind::Ptrace,
        Target::Kvm => BackendKind::Kvm,
        Target::Liteinst => BackendKind::Liteinst,
        Target::InGuestTrap => BackendKind::InGuestTrap,
        Target::E9patch => BackendKind::E9patch,
        Target::Dbt => BackendKind::Dbt,
        Target::Sabre => BackendKind::Sabre,
    }
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    let report = if opts.backend == Target::Native {
        run_native(&opts.program, &opts.args)?
    } else {
        if opts.backend == Target::E9patch {
            // SAFETY: no other thread runs yet; the runtime starts below.
            unsafe { backend::use_bundled_e9patch() };
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let preload_path = opts.preload.clone().or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|executable| backend::default_preload_path(&executable))
        });
        let preload = preload_path.as_deref().map(|path| backend::Preload {
            tool: recorder_tool::NAME,
            path,
        });
        // The host's environment, as for a native run.
        let common = reverie_util::CommonToolArguments {
            log_file: None,
            no_host_envs: false,
            envs: Vec::new(),
            trace_syscalls: false,
            program: utf8(opts.program.as_os_str())?,
            program_args: opts
                .args
                .iter()
                .map(|arg| utf8(arg))
                .collect::<anyhow::Result<_>>()?,
        };
        let run = runtime.block_on(backend::run::<Recorder>(
            reverie_backend(opts.backend),
            &common,
            (),
            preload,
        ));
        match run {
            Ok(run) => {
                // The program's output, where the backend captured it, goes
                // where it would have gone.
                if let Some((stdout, stderr)) = &run.captured {
                    use std::io::Write as _;
                    std::io::stdout().write_all(stdout)?;
                    std::io::stderr().write_all(stderr)?;
                }
                let events = run.global_state.events.into_inner().unwrap();
                report(run.exit_code, reverie_events(events))
            }
            Err(error) => anyhow::bail!("{error}"),
        }
    };
    std::fs::write(&opts.output, report.text())?;
    Ok(())
}
