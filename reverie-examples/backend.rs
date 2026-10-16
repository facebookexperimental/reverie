/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Run one Reverie tool on a backend chosen at run time, through each
//! backend's public entry point, so that the same tool and the same program
//! can be compared across backends (`reverie-examples/e2e/`).
//!
//! A backend either runs the tool or refuses by name ([`RunError::Refused`]):
//! DBT and SaBRe load one runtime or plugin of their own and have no generic
//! tool host yet, and the in-guest backends (LiteInst, in-guest-trap,
//! e9patch) host a tool only through a preload that compiles it in, which this
//! module does not drive yet.

use std::ffi::OsString;
use std::os::fd::FromRawFd;
use std::path::Path;

use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Tool;

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
    /// reverie-e9patch: the program is rewritten ahead of time.
    E9patch,
    /// reverie-dbt: the program runs under DynamoRIO.
    Dbt,
    /// experimental/reverie-sabre: the program is rewritten at load time.
    Sabre,
}

/// How a tool's run ended.
pub struct Run<G> {
    /// The program's exit code, or 128 plus the signal that ended it.
    pub exit_code: i32,
    /// The tool's global state at the end.
    pub global_state: G,
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

/// Run `program` with `args` under the tool `T` on `backend`.
pub async fn run<T>(
    backend: BackendKind,
    program: &Path,
    args: &[OsString],
    config: <T::GlobalState as GlobalTool>::Config,
) -> Result<Run<T::GlobalState>, RunError>
where
    T: Tool + 'static,
    T::ThreadState: 'static,
    T::GlobalState: 'static,
    <T::GlobalState as GlobalTool>::Config: 'static,
{
    match backend {
        BackendKind::Ptrace => run_ptrace::<T>(program, args, config).await,
        BackendKind::Kvm => run_kvm::<T>(program, args, config).await,
        BackendKind::Liteinst | BackendKind::InGuestTrap | BackendKind::E9patch => {
            Err(RunError::Refused(format!(
                "the {backend:?} backend hosts a tool only through a preload that compiles it \
                 in, which this runner does not drive yet"
            )))
        }
        BackendKind::Dbt | BackendKind::Sabre => Err(RunError::Refused(format!(
            "the {backend:?} backend loads one runtime of its own and has no generic tool host"
        ))),
    }
}

async fn run_ptrace<T>(
    program: &Path,
    args: &[OsString],
    config: <T::GlobalState as GlobalTool>::Config,
) -> Result<Run<T::GlobalState>, RunError>
where
    T: Tool + 'static,
{
    let mut command = reverie::process::Command::new(program);
    command.args(args);
    let tracer = reverie_ptrace::TracerBuilder::<T>::new(command)
        .config(config)
        .spawn()
        .await?;
    let (status, global_state) = tracer.wait().await?;
    Ok(Run {
        exit_code: exit_code(status),
        global_state,
    })
}

async fn run_kvm<T>(
    program: &Path,
    args: &[OsString],
    config: <T::GlobalState as GlobalTool>::Config,
) -> Result<Run<T::GlobalState>, RunError>
where
    T: Tool + 'static,
    T::ThreadState: 'static,
    T::GlobalState: 'static,
    <T::GlobalState as GlobalTool>::Config: 'static,
{
    use anyhow::Context as _;
    let image = std::fs::read(program).with_context(|| format!("reading {program:?}"))?;
    let cwd = std::env::current_dir()?;
    let mut argv = vec![program.to_str().context("non-UTF-8 program")?.to_owned()];
    for arg in args {
        argv.push(arg.to_str().context("non-UTF-8 argument")?.to_owned());
    }
    // In name order, as reverie-process's `Command` passes the environment to
    // a ptrace guest, so that the order, which a program can see, is not a
    // difference between the backends.
    let mut envp = std::env::vars()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    envp.sort();
    let argv = argv.iter().map(String::as_str).collect::<Vec<_>>();
    let envp = envp.iter().map(String::as_str).collect::<Vec<_>>();
    // The guest gets this process's standard input as its descriptor 0, as a
    // ptrace guest does.
    // SAFETY: duplicating a descriptor; the result is owned below or -1.
    let stdin = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    // SAFETY: a descriptor fcntl just returned, owned by nothing else.
    let stdin = (stdin >= 0).then(|| unsafe { std::fs::File::from_raw_fd(stdin) });
    let mut backend = reverie_kvm::KvmBackend::new_with_stdin(1 << 30, stdin)
        .map_err(|error| anyhow::anyhow!("reverie-kvm: {error}"))?;
    backend
        .install_static_elf_with_exec_context(&image, program.as_os_str(), &argv, &envp, &cwd)
        .map_err(|error| anyhow::anyhow!("loading {program:?} into KVM: {error}"))?;
    drop(image);
    let (global_state, exit_code, _stdout, _stderr) = backend
        .run_static_elf_with_tool::<T>(config, false)
        .await
        .map_err(|error| anyhow::anyhow!("KVM run: {error}"))?;
    Ok(Run {
        exit_code,
        global_state,
    })
}
