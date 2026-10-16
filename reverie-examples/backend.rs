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

// `#[path]`-included by each example tool's binary; each uses a different
// subset (a launcher calls `run_blocking`, the recorder `run`), so an item
// unused in one binary's build is used in another's.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::ffi::CString;
use std::ffi::OsStr;
use std::io;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::path::PathBuf;

use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Tool;
use reverie_util::CommonToolArguments;

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
        BackendKind::Liteinst | BackendKind::InGuestTrap | BackendKind::E9patch => {
            let preload = preload.ok_or_else(|| {
                RunError::Refused(format!(
                    "the {backend:?} backend hosts a tool only through a preload that compiles \
                     it in, and none was found (libreverie_examples.so)"
                ))
            })?;
            run_in_guest::<T>(backend, args, config, preload).await
        }
        BackendKind::Dbt | BackendKind::Sabre => Err(RunError::Refused(format!(
            "the {backend:?} backend loads one runtime of its own and has no generic tool host"
        ))),
    }
}

/// What a tool's launcher does with [`run`]: point e9patch at its bundled
/// tools (before any thread starts), find the example preload (`preload`, or
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
    if backend == BackendKind::E9patch {
        // SAFETY: no other thread runs yet; the runtime starts below.
        unsafe { use_bundled_e9patch() };
    }
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
        BackendKind::E9patch => {
            let command: reverie::process::Command = args.clone().into();
            let (output, global_state) =
                reverie_e9patch::E9patchBackend::run_direct_with_output_and_preload_data::<T>(
                    command,
                    config,
                    preload.path,
                    tool,
                )
                .await?;
            (output.status, output.stdout, output.stderr, global_state)
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

/// The guest environment: the host's, or only a PATH with `--no-host-envs`,
/// plus each `--env`.
fn guest_environment(args: &CommonToolArguments) -> anyhow::Result<BTreeMap<String, String>> {
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

fn resolve_program(
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
