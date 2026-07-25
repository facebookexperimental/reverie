/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Correctness-first hybrid backend for e9patch syscall events.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;

use reverie::Backend;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Tool;
use reverie::process::Command;
use reverie::process::Output;
use reverie_ptrace::Tracer;
use reverie_ptrace::TracerBuilder;

use crate::E9PATCH_SYSCALL_TRAP_MARKER;
use crate::E9PATCH_SYSCALL_TRAP_RIP;
use crate::E9patchRewriter;

enum ExecutableResource {
    Temporary(tempfile::TempPath),
    Overlay {
        mount: ExecutableOverlay,
        backing_path: tempfile::TempPath,
    },
    Original,
}

impl ExecutableResource {
    fn cleanup(self) -> io::Result<()> {
        match self {
            Self::Temporary(path) => path.close(),
            Self::Overlay {
                mut mount,
                backing_path,
            } => {
                let unmount = mount.unmount();
                let unlink = backing_path.close();
                unmount.and(unlink)
            }
            Self::Original => Ok(()),
        }
    }
}

struct ExecutableOverlay {
    target: CString,
    target_path: PathBuf,
    mounted: bool,
}

impl ExecutableOverlay {
    fn mount(source: &Path, target: &Path) -> io::Result<Self> {
        let source = path_cstring(source)?;
        let target_cstring = path_cstring(target)?;
        let target_path = target.to_owned();

        syscall_result(unsafe {
            libc::mount(
                source.as_ptr(),
                target_cstring.as_ptr(),
                ptr::null(),
                libc::MS_BIND as libc::c_ulong,
                ptr::null(),
            )
        })?;

        let mut overlay = Self {
            target: target_cstring,
            target_path,
            mounted: true,
        };
        if let Err(error) = syscall_result(unsafe {
            libc::mount(
                ptr::null(),
                overlay.target.as_ptr(),
                ptr::null(),
                (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong,
                ptr::null(),
            )
        }) {
            let _ = overlay.unmount();
            return Err(error);
        }
        Ok(overlay)
    }

    fn unmount(&mut self) -> io::Result<()> {
        if self.mounted {
            syscall_result(unsafe { libc::umount2(self.target.as_ptr(), libc::MNT_DETACH) })?;
            self.mounted = false;
        }
        Ok(())
    }
}

impl Drop for ExecutableOverlay {
    fn drop(&mut self) {
        if let Err(error) = self.unmount() {
            eprintln!(
                "warning: failed to remove e9patch executable overlay {}: {error}",
                self.target_path.display()
            );
        }
    }
}

fn path_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path contains an interior NUL: {}", path.display()),
        )
    })
}

fn syscall_result(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn is_elf_file(path: &Path) -> io::Result<bool> {
    let mut file = File::open(path)?;
    let mut magic = [0_u8; 4];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(magic == *b"\x7fELF"),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

async fn spawn_tracer<T>(
    command: Command,
    config: <T::GlobalState as GlobalTool>::Config,
) -> Result<Tracer<T::GlobalState>, Error>
where
    T: Tool + 'static,
{
    TracerBuilder::<T>::new(command)
        .config(config)
        .injected_syscall_trap(E9PATCH_SYSCALL_TRAP_MARKER, E9PATCH_SYSCALL_TRAP_RIP)
        .spawn()
        .await
}

/// Hybrid e9patch backend with ptrace lifecycle and full `Guest` semantics.
///
/// Recovered syscall instructions in the root ELF are replaced by e9patch
/// trampolines and originate events through an injected register frame.
/// Ptrace remains attached for process lifecycle, shared-library syscalls,
/// signals, timers, and arbitrary-tool `Guest` operations. This is a real
/// e9patch event path, but it is not yet the planned ptrace-free fast path.
// TODO-HUMAN-REVIEW(PR-102): Review the public hybrid backend contract.
pub struct E9patchBackend;

impl E9patchBackend {
    async fn spawn<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preserve_executable: bool,
    ) -> Result<(Tracer<T::GlobalState>, ExecutableResource), Error>
    where
        T: Tool + 'static,
    {
        let source = command.find_program()?;
        let arg0 = command.get_arg0().to_owned();
        // TODO-HUMAN-REVIEW(PR-103): Review non-ELF ptrace fallback behavior.
        if !is_elf_file(&source)? {
            eprintln!(
                ":: Backend: e9patch hybrid; recovered_sites=0; patched_sites=0; b0_sites=0; event_source=ptrace; controller=ptrace; main_executable=non-ELF"
            );
            command.program(&source).arg0(arg0);
            let tracer = spawn_tracer::<T>(command, config).await?;
            return Ok((tracer, ExecutableResource::Original));
        }

        let prepared = E9patchRewriter::from_env()?.prepare(&source)?;
        let report = prepared.report();
        // TODO-HUMAN-REVIEW(PR-103): Review the stable backend coverage diagnostic.
        let event_source = if report.patched_sites() == 0 {
            "ptrace"
        } else {
            "injected-trap"
        };
        eprintln!(
            ":: Backend: e9patch hybrid; recovered_sites={}; patched_sites={}; b0_sites={}; event_source={}; controller=ptrace",
            report.recovered_sites(),
            report.patched_sites(),
            report.b0_sites(),
            event_source,
        );

        // TODO-HUMAN-REVIEW(PR-103): Review zero-site original-image execution.
        if report.patched_sites() == 0 {
            command.program(&source).arg0(arg0);
            let tracer = spawn_tracer::<T>(command, config).await?;
            return Ok((tracer, ExecutableResource::Original));
        }

        // E9patch's loader reopens the executable, so an anonymous memfd is not
        // sufficient. Close the writable descriptor before execve to avoid
        // ETXTBSY. Namespace callers may bind the artifact over the original
        // path to retain executable identity.
        let mut executable = tempfile::Builder::new()
            .prefix("reverie-e9patch-guest-")
            .tempfile()?;
        let mut artifact = prepared.artifact()?;
        io::copy(&mut artifact, executable.as_file_mut())?;
        executable.as_file_mut().flush()?;
        let mut permissions = executable.as_file().metadata()?.permissions();
        permissions.set_mode(0o500);
        executable.as_file().set_permissions(permissions)?;
        let executable = executable.into_temp_path();

        let resource = if preserve_executable {
            let overlay = ExecutableOverlay::mount(&executable, &source)?;
            command.program(&source).arg0(arg0);
            ExecutableResource::Overlay {
                mount: overlay,
                backing_path: executable,
            }
        } else {
            command.program(&executable).arg0(arg0);
            ExecutableResource::Temporary(executable)
        };

        let spawn_result = spawn_tracer::<T>(command, config).await;
        match spawn_result {
            Ok(tracer) => Ok((tracer, resource)),
            Err(error) => {
                let _ = resource.cleanup();
                Err(error)
            }
        }
    }

    /// Runs a tool and captures the rewritten guest's stdout and stderr.
    // TODO-HUMAN-REVIEW(PR-102): Review the public captured-output backend API.
    pub async fn run_with_output<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(Output, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        let (tracer, resource) = Self::spawn::<T>(command, config, false).await?;
        let result = tracer.wait_with_output().await;
        let cleanup = resource.cleanup();
        match (result, cleanup) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    /// Runs a tool with the rewritten ELF mounted at its original path.
    ///
    /// The caller must already be in a private mount namespace with permission
    /// to create a read-only bind mount at the resolved executable path.
    ///
    /// # Safety
    ///
    /// The current process must be disposable and isolated in a private mount
    /// namespace. Otherwise this call can overlay a host executable path.
    // TODO-HUMAN-REVIEW(PR-103): Review the namespace executable-identity API.
    pub async unsafe fn run_preserving_executable<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(ExitStatus, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        let (tracer, resource) = Self::spawn::<T>(command, config, true).await?;
        let result = tracer.wait().await;
        let cleanup = resource.cleanup();
        match (result, cleanup) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    /// Runs a tool with original executable identity and captures its output.
    ///
    /// The caller must already be in a private mount namespace with permission
    /// to create a read-only bind mount at the resolved executable path.
    ///
    /// # Safety
    ///
    /// The current process must be disposable and isolated in a private mount
    /// namespace. Otherwise this call can overlay a host executable path.
    // TODO-HUMAN-REVIEW(PR-103): Review the captured namespace identity API.
    pub async unsafe fn run_with_output_preserving_executable<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(Output, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        let (tracer, resource) = Self::spawn::<T>(command, config, true).await?;
        let result = tracer.wait_with_output().await;
        let cleanup = resource.cleanup();
        match (result, cleanup) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }
}

#[reverie::backend(?Send)]
impl Backend for E9patchBackend {
    async fn run<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(ExitStatus, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        let (tracer, resource) = Self::spawn::<T>(command, config, false).await?;
        let result = tracer.wait().await;
        let cleanup = resource.cleanup();
        match (result, cleanup) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }
}
