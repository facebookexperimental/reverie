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
//! tool host yet. The in-guest backends (LiteInst, in-guest-trap, e9patch)
//! host a tool through a preload that compiles it in: the example preload,
//! `libreverie_examples.so` (`src/lib.rs`), selects the tool by the name the
//! caller passes, so a tool runs there only once its name is in that
//! selector.

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
    /// What the program wrote to stdout and stderr, where the backend
    /// captured it (the in-guest backends); otherwise the program wrote to
    /// this process's own.
    pub captured: Option<(Vec<u8>, Vec<u8>)>,
}

/// The tool to run, as the example preload names it, and that preload.
pub struct Preload<'a> {
    /// The name the preload's selector knows the tool by.
    pub tool: &'a str,
    /// The example preload, `libreverie_examples.so`.
    pub path: &'a Path,
}

/// Name the e9tool and e9patch binaries reverie-e9patch built from its
/// vendored source, unless the environment already names them, so that the
/// e9patch backend can rewrite the program.
///
/// # Safety
///
/// This sets environment variables, so no other thread may run.
pub unsafe fn use_bundled_e9patch() {
    for (name, path) in [
        (
            reverie_e9patch::E9TOOL_ENV,
            reverie_e9patch::bundled_e9tool_path(),
        ),
        (
            reverie_e9patch::E9PATCH_BACKEND_ENV,
            reverie_e9patch::bundled_e9patch_path(),
        ),
    ] {
        if std::env::var_os(name).is_none() {
            // SAFETY: the caller runs no other thread.
            unsafe { std::env::set_var(name, path) };
        }
    }
}

/// The example preload beside `executable`, as cargo lays out its binaries.
pub fn default_preload_path(executable: &Path) -> Option<std::path::PathBuf> {
    let parent = executable.parent()?;
    [
        parent.join("libreverie_examples.so"),
        parent.join("deps/libreverie_examples.so"),
        parent
            .parent()
            .unwrap_or(parent)
            .join("libreverie_examples.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
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

/// Run `program` with `args` under the tool `T` on `backend`. The in-guest
/// backends need `preload`, which must compile `T` in under `preload.tool`.
pub async fn run<T>(
    backend: BackendKind,
    program: &Path,
    args: &[OsString],
    config: <T::GlobalState as GlobalTool>::Config,
    preload: Option<Preload<'_>>,
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
            let preload = preload.ok_or_else(|| {
                RunError::Refused(format!(
                    "the {backend:?} backend hosts a tool only through a preload that compiles \
                     it in, and none was found (libreverie_examples.so)"
                ))
            })?;
            run_in_guest::<T>(backend, program, args, config, preload).await
        }
        BackendKind::Dbt | BackendKind::Sabre => Err(RunError::Refused(format!(
            "the {backend:?} backend loads one runtime of its own and has no generic tool host"
        ))),
    }
}

async fn run_in_guest<T>(
    backend: BackendKind,
    program: &Path,
    args: &[OsString],
    config: <T::GlobalState as GlobalTool>::Config,
    preload: Preload<'_>,
) -> Result<Run<T::GlobalState>, RunError>
where
    T: Tool + 'static,
{
    let tool = preload.tool.as_bytes().to_vec();
    let (exit_code, stdout, stderr, global_state) = match backend {
        BackendKind::Liteinst | BackendKind::InGuestTrap => {
            let mut command = reverie::process::Command::new(program);
            command.args(args);
            // in-guest-trap is LiteInst with no site patched: every syscall
            // traps (as `reverie_liteinst::set_guest_site_patching` spells it
            // for a std command).
            command.env(
                reverie_liteinst::SITE_PATCHING_ENV,
                if backend == BackendKind::Liteinst {
                    "1"
                } else {
                    "0"
                },
            );
            let (output, global_state) =
                reverie_liteinst::LiteinstBackend::run_with_output_and_preload_data::<T>(
                    command,
                    config,
                    preload.path,
                    tool,
                )
                .await?;
            use std::os::unix::process::ExitStatusExt as _;
            let status = output.status;
            let exit_code = status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
            (exit_code, output.stdout, output.stderr, global_state)
        }
        BackendKind::E9patch => {
            let mut command = reverie::process::Command::new(program);
            command.args(args);
            let (output, global_state) =
                reverie_e9patch::E9patchBackend::run_direct_with_output_and_preload_data::<T>(
                    command,
                    config,
                    preload.path,
                    tool,
                )
                .await?;
            (
                exit_code(output.status),
                output.stdout,
                output.stderr,
                global_state,
            )
        }
        _ => unreachable!("{backend:?} is not an in-guest backend"),
    };
    Ok(Run {
        exit_code,
        global_state,
        captured: Some((stdout, stderr)),
    })
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
        captured: None,
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
        captured: None,
    })
}
