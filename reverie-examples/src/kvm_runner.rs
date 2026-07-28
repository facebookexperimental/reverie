/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Shared KVM launch support for production Reverie example tools.

#[cfg(target_arch = "x86_64")]
use std::collections::BTreeMap;
#[cfg(target_arch = "x86_64")]
use std::ffi::CString;
#[cfg(target_arch = "x86_64")]
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;
#[cfg(target_arch = "x86_64")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_arch = "x86_64")]
use std::path::Path;
#[cfg(target_arch = "x86_64")]
use std::path::PathBuf;

use clap::ValueEnum;
use reverie::GlobalTool;
use reverie::Tool;
#[cfg(target_arch = "x86_64")]
use reverie_kvm::KvmBackend;
use reverie_util::CommonToolArguments;

#[cfg(target_arch = "x86_64")]
const GUEST_MEMORY_SIZE: usize = 256 * 1024 * 1024;

// TODO-HUMAN-REVIEW(PR-151): Review the user-facing example runner selector.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub(crate) enum Runner {
    #[default]
    Ptrace,
    Kvm,
}

// TODO-HUMAN-REVIEW(PR-151): Review pre-runtime stdin reservation.
pub(crate) fn reserve_stdin() -> io::Result<Option<File>> {
    let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    if fd >= 0 {
        // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
        return Ok(Some(unsafe { File::from_raw_fd(fd) }));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EBADF) {
        Ok(None)
    } else {
        Err(error)
    }
}

// TODO-HUMAN-REVIEW(PR-151): Review the shared KVM example result boundary.
pub(crate) struct KvmRun<G> {
    pub(crate) global_state: G,
    pub(crate) exit_code: i32,
}

// TODO-HUMAN-REVIEW(PR-151): Review the production example KVM launch path.
// TODO-HUMAN-REVIEW(PR-235): Review static lifetime requirements for KVM Tool workers.
#[cfg(target_arch = "x86_64")]
pub(crate) async fn run<T>(
    args: &CommonToolArguments,
    config: <T::GlobalState as GlobalTool>::Config,
    stdin: Option<File>,
) -> anyhow::Result<KvmRun<T::GlobalState>>
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

    let envp = environment
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    let envp = envp.iter().map(String::as_str).collect::<Vec<_>>();

    let mut backend = KvmBackend::new_with_stdin(GUEST_MEMORY_SIZE, stdin)?;
    backend.install_static_elf_with_context(&image, &argv, &envp, &cwd)?;
    let (global_state, exit_code, stdout, stderr) =
        backend.run_static_elf_with_tool::<T>(config, false).await?;
    debug_assert!(stdout.is_empty());
    debug_assert!(stderr.is_empty());

    Ok(KvmRun {
        global_state,
        exit_code,
    })
}

#[cfg(not(target_arch = "x86_64"))]
// TODO-HUMAN-REVIEW(PR-151): Review the unsupported-architecture runner error.
// TODO-HUMAN-REVIEW(PR-235): Review cross-architecture KVM runner bound parity.
pub(crate) async fn run<T>(
    args: &CommonToolArguments,
    config: <T::GlobalState as GlobalTool>::Config,
    stdin: Option<File>,
) -> anyhow::Result<KvmRun<T::GlobalState>>
where
    T: Tool + 'static,
    T::ThreadState: 'static,
    T::GlobalState: 'static,
    <T::GlobalState as GlobalTool>::Config: 'static,
{
    let _ = (args, config, stdin);
    anyhow::bail!("the KVM example runner requires x86-64")
}

#[cfg(target_arch = "x86_64")]
fn guest_environment(args: &CommonToolArguments) -> anyhow::Result<BTreeMap<String, String>> {
    let mut environment = if args.no_host_envs {
        BTreeMap::from([("PATH".to_string(), "/bin:/usr/bin".to_string())])
    } else {
        let mut environment = BTreeMap::new();
        for (key, value) in std::env::vars_os() {
            let key = key.into_string().map_err(|_| {
                anyhow::anyhow!("KVM runner cannot pass a non-UTF-8 environment key")
            })?;
            let value = value.into_string().map_err(|_| {
                anyhow::anyhow!("KVM runner cannot pass a non-UTF-8 environment value for {key:?}")
            })?;
            environment.insert(key, value);
        }
        environment
    };
    environment.extend(args.envs.iter().cloned());
    Ok(environment)
}

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
// TODO-HUMAN-REVIEW(PR-151): Review effective execute-permission validation.
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
