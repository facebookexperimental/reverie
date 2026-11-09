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
//! A backend either runs the tool or refuses by name ([`RunError::Refused`]).
//! LiteInst and in-guest-trap host the core example preload. External runtime
//! example packages reuse the same generic Tools and host result types.

// `#[path]`-included by each example tool's binary; each uses a different
// subset (a launcher calls `run_blocking`, the recorder `run`), so an item
// unused in one binary's build is used in another's.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::os::fd::FromRawFd;
use std::path::Path;
use std::path::PathBuf;

use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Tool;
pub use reverie_examples::host::BackendKind;
pub use reverie_examples::host::Run;
pub use reverie_examples::host::RunError;
pub use reverie_examples::host::exit_code;
use reverie_examples::host::guest_environment;
use reverie_examples::host::resolve_program;
use reverie_util::CommonToolArguments;

/// The tool to run, as the example preload names it, and that preload.
pub struct Preload<'a> {
    /// The name the preload's selector knows the tool by.
    pub tool: &'a str,
    /// The example preload, `libreverie_examples.so`.
    pub path: &'a Path,
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

/// Run the program `args` names, with its arguments and environment, under
/// the tool `T` on `backend`. The in-guest backends need `preload`, which must
/// compile `T` in under `preload.tool`.
pub async fn run<T>(
    backend: BackendKind,
    args: &CommonToolArguments,
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
        BackendKind::Ptrace => run_ptrace::<T>(args, config).await,
        BackendKind::Kvm => run_kvm::<T>(args, config).await,
        BackendKind::Liteinst | BackendKind::InGuestTrap => {
            let preload = preload.ok_or_else(|| {
                RunError::Refused(format!(
                    "the {backend:?} backend hosts a tool only through a preload that compiles \
                     it in, and none was found (libreverie_examples.so)"
                ))
            })?;
            run_in_guest::<T>(backend, args, config, preload).await
        }
    }
}

/// What a tool's launcher does with [`run`]: find the example preload (`preload`, or
/// `libreverie_examples.so` beside this binary), run the program under `T` on
/// `backend` in a new runtime, and pass on the output the backend captured.
/// `tool` is the name the example preload knows `T` by.
pub fn run_blocking<T>(
    backend: BackendKind,
    args: &CommonToolArguments,
    config: <T::GlobalState as GlobalTool>::Config,
    tool: &str,
    preload: Option<PathBuf>,
) -> anyhow::Result<Run<T::GlobalState>>
where
    T: Tool + 'static,
    T::ThreadState: 'static,
    T::GlobalState: 'static,
    <T::GlobalState as GlobalTool>::Config: 'static,
{
    let preload = preload.or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|executable| default_preload_path(&executable))
    });
    let preload = preload.as_deref().map(|path| Preload { tool, path });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let run = runtime
        .block_on(run::<T>(backend, args, config, preload))
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    if let Some((stdout, stderr)) = &run.captured {
        use std::io::Write as _;
        std::io::stdout().write_all(stdout)?;
        std::io::stderr().write_all(stderr)?;
    }
    Ok(run)
}

async fn run_in_guest<T>(
    backend: BackendKind,
    args: &CommonToolArguments,
    config: <T::GlobalState as GlobalTool>::Config,
    preload: Preload<'_>,
) -> Result<Run<T::GlobalState>, RunError>
where
    T: Tool + 'static,
{
    let tool = preload.tool.as_bytes().to_vec();
    let (status, stdout, stderr, global_state) = match backend {
        BackendKind::Liteinst | BackendKind::InGuestTrap => {
            let mut command: reverie::process::Command = args.clone().into();
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
            let status = ExitStatus::from_raw(output.status.into_raw());
            (status, output.stdout, output.stderr, global_state)
        }
        _ => unreachable!("{backend:?} is not an in-guest backend"),
    };
    Ok(Run {
        status,
        exit_code: exit_code(status),
        global_state,
        captured: Some((stdout, stderr)),
    })
}

async fn run_ptrace<T>(
    args: &CommonToolArguments,
    config: <T::GlobalState as GlobalTool>::Config,
) -> Result<Run<T::GlobalState>, RunError>
where
    T: Tool + 'static,
{
    let tracer = reverie_ptrace::TracerBuilder::<T>::new(args.clone().into())
        .config(config)
        .spawn()
        .await?;
    let (status, global_state) = tracer.wait().await?;
    Ok(Run {
        status,
        exit_code: exit_code(status),
        global_state,
        captured: None,
    })
}

async fn run_kvm<T>(
    args: &CommonToolArguments,
    config: <T::GlobalState as GlobalTool>::Config,
) -> Result<Run<T::GlobalState>, RunError>
where
    T: Tool + 'static,
    T::ThreadState: 'static,
    T::GlobalState: 'static,
    <T::GlobalState as GlobalTool>::Config: 'static,
{
    let cwd = std::env::current_dir()?;
    let environment = guest_environment(args)?;
    let program = resolve_program(&args.program, &environment, &cwd)?;
    let image = std::fs::read(&program)?;
    let mut argv = Vec::with_capacity(args.program_args.len() + 1);
    argv.push(args.program.clone());
    argv.extend(args.program_args.iter().cloned());
    let argv = argv.iter().map(String::as_str).collect::<Vec<_>>();
    // In name order, as reverie-process's `Command` passes the environment to
    // a ptrace guest, so that the order, which a program can see, is not a
    // difference between the backends.
    let envp = environment
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    let envp = envp.iter().map(String::as_str).collect::<Vec<_>>();
    // The guest gets this process's standard input as its descriptor 0, as a
    // ptrace guest does.
    // SAFETY: duplicating a descriptor; the result is owned below or -1.
    let stdin = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    // SAFETY: a descriptor fcntl just returned, owned by nothing else.
    let stdin = (stdin >= 0).then(|| unsafe { std::fs::File::from_raw_fd(stdin) });
    let mut backend = reverie_kvm::KvmBackend::new_with_stdin(1 << 30, stdin)
        .map_err(|error| anyhow::anyhow!("reverie-kvm: {error}"))?;
    // The program's name, as the caller spelled it, is its AT_EXECFN.
    backend
        .install_static_elf_with_exec_context(&image, OsStr::new(&args.program), &argv, &envp, &cwd)
        .map_err(|error| anyhow::anyhow!("loading {program:?} into KVM: {error}"))?;
    drop(image);
    let (global_state, exit_code, _stdout, _stderr) = backend
        .run_static_elf_with_tool::<T>(config, false)
        .await
        .map_err(|error| anyhow::anyhow!("KVM run: {error}"))?;
    Ok(Run {
        status: ExitStatus::Exited(exit_code),
        exit_code,
        global_state,
        captured: None,
    })
}
