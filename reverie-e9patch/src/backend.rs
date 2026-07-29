/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Correctness-first hybrid backend for e9patch syscall events.

use std::ffi::CString;
use std::ffi::OsStr;
use std::fs::File;
use std::future::Future;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use reverie::Backend;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Tool;
use reverie::process::Command;
use reverie::process::Output;
use reverie_ptrace::Tracer;
use reverie_ptrace::TracerBuilder;
use reverie_rpc_transport::RpcServer;

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

/// Opt-in env var arming the shared ld-preload fallback runtime on the guest.
///
/// Default (unset/unrecognized) keeps the working ptrace-only path byte-for-byte
/// unchanged. `hybrid` (or `1`) injects the shared runtime under e9patch's
/// production ptrace-hosted controller; `fallback` selects the isolated
/// in-process controller for experiments. This is opt-in until the in-guest
/// runtime is validated against a real GPL-toolchain guest, because it installs
/// an in-process seccomp/`SIGSYS` filter alongside the ptrace lifecycle owner.
// TODO-HUMAN-REVIEW(PR-104): Review activating in-guest seccomp under ptrace.
const LDPRELOAD_FALLBACK_ENV: &str = "REVERIE_E9PATCH_LDPRELOAD_FALLBACK";

/// Parse [`LDPRELOAD_FALLBACK_ENV`] into a [`crate::RuntimeMode`], or `None`
/// (leave the guest command untouched) when unset or unrecognized.
fn ldpreload_fallback_mode() -> Option<crate::RuntimeMode> {
    match std::env::var_os(LDPRELOAD_FALLBACK_ENV)?.to_str() {
        Some("1") | Some("hybrid") => Some(crate::RuntimeMode::HybridPtrace),
        Some("fallback") => Some(crate::RuntimeMode::InProcessFallback),
        _ => None,
    }
}

async fn spawn_tracer<T>(
    command: Command,
    config: <T::GlobalState as GlobalTool>::Config,
    provenance: Option<(PathBuf, u64, Vec<u64>)>,
) -> Result<Tracer<T::GlobalState>, Error>
where
    T: Tool + 'static,
{
    let builder = TracerBuilder::<T>::new(command).config(config);
    let builder = if let Some((image, image_entry_address, patched_site_addresses)) = provenance {
        builder.site_validated_injected_syscall_trap(
            E9PATCH_SYSCALL_TRAP_MARKER,
            E9PATCH_SYSCALL_TRAP_RIP,
            image,
            image_entry_address,
            patched_site_addresses,
        )?
    } else {
        builder
    };
    builder.spawn().await
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
    // TODO-HUMAN-REVIEW(PR-269): Review the first
    // ptrace-free generic Tool launch boundary and inherited preload contract.
    /// Runs a generic Tool through e9patch's direct AOT callback and captures
    /// the guest's output.
    ///
    /// `preload` must be a tool-specific DSO that embeds the same concrete `T`
    /// and calls [`crate::install_tool::<T>`] from its constructor. The
    /// coordinator path is inherited through [`crate::COORDINATOR_ENV`]. This
    /// opt-in harness is intentionally separate from [`Backend::run`], whose
    /// ptrace lifecycle remains the production default while direct-tool
    /// lifecycle coverage is still single-process and single-thread.
    pub async fn run_direct_with_output_and_preload<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
    ) -> Result<(Output, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        command.stdout(reverie::process::Stdio::piped());
        command.stderr(reverie::process::Stdio::piped());
        launch_direct::<T>(command, config, preload.into()).await
    }

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

        // Opt-in: arm the shared ld-preload fallback runtime on the guest
        // command. Default (unset) leaves the command untouched, so the working
        // ptrace-only path is unchanged. The shared runtime covers residual
        // un-rewritten sites; ptrace remains the lifecycle owner and Guest.
        // AUTONOMOUS-BOT-IMPLEMENTED
        let ldpreload = match ldpreload_fallback_mode() {
            Some(mode) => {
                crate::configure_guest_command(&mut command, mode)?;
                mode.controller_name()
            }
            None => "off",
        };

        // TODO-HUMAN-REVIEW(PR-103): Review non-ELF ptrace fallback behavior.
        if !is_elf_file(&source)? {
            eprintln!(
                ":: Backend: e9patch hybrid; recovered_sites=0; patched_sites=0; b0_sites=0; event_source=ptrace; controller=ptrace; ldpreload={ldpreload}; main_executable=non-ELF"
            );
            command.program(&source).arg0(arg0);
            let tracer = spawn_tracer::<T>(command, config, None).await?;
            return Ok((tracer, ExecutableResource::Original));
        }

        let prepared = E9patchRewriter::from_env()?.prepare(&source)?;
        let report = prepared.report();
        let image_entry_address = report.image_entry_address();
        let patched_site_addresses = report.patched_site_addresses().to_vec();
        // TODO-HUMAN-REVIEW(PR-103): Review the stable backend coverage diagnostic.
        let event_source = if report.patched_sites() == 0 {
            "ptrace"
        } else {
            "injected-trap"
        };
        eprintln!(
            ":: Backend: e9patch hybrid; recovered_sites={}; patched_sites={}; b0_sites={}; event_source={}; controller=ptrace; ldpreload={}",
            report.recovered_sites(),
            report.patched_sites(),
            report.b0_sites(),
            event_source,
            ldpreload,
        );

        // TODO-HUMAN-REVIEW(PR-103): Review zero-site original-image execution.
        if report.patched_sites() == 0 {
            command.program(&source).arg0(arg0);
            let tracer = spawn_tracer::<T>(command, config, None).await?;
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

        let (resource, mapped_image) = if preserve_executable {
            let overlay = ExecutableOverlay::mount(&executable, &source)?;
            command.program(&source).arg0(arg0);
            (
                ExecutableResource::Overlay {
                    mount: overlay,
                    backing_path: executable,
                },
                source,
            )
        } else {
            command.program(&executable).arg0(arg0);
            let mapped_image = executable.to_path_buf();
            (ExecutableResource::Temporary(executable), mapped_image)
        };

        let spawn_result = spawn_tracer::<T>(
            command,
            config,
            Some((mapped_image, image_entry_address, patched_site_addresses)),
        )
        .await;
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

async fn launch_direct<T>(
    mut command: Command,
    config: <T::GlobalState as GlobalTool>::Config,
    preload: PathBuf,
) -> Result<(Output, T::GlobalState), Error>
where
    T: Tool + 'static,
{
    if !preload.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("tool preload {} is not a file", preload.display()),
        )
        .into());
    }
    let preload = preload.canonicalize()?;
    let source = command.find_program()?;
    if !is_elf_file(&source)? {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "direct e9patch Tool hosting requires an ELF main executable",
        )
        .into());
    }
    let arg0 = command.get_arg0().to_owned();
    let prepared = E9patchRewriter::from_env()?.prepare(&source)?;
    let report = prepared.report();
    if report.patched_sites() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "direct e9patch Tool hosting requires at least one recovered syscall site",
        )
        .into());
    }
    eprintln!(
        ":: Backend: e9patch direct-tool; recovered_sites={}; patched_sites={}; b0_sites={}; event_source=aot-callback; controller=in-process-seccomp",
        report.recovered_sites(),
        report.patched_sites(),
        report.b0_sites(),
    );

    let mut executable = tempfile::Builder::new()
        .prefix("reverie-e9patch-direct-guest-")
        .tempfile()?;
    let mut artifact = prepared.artifact()?;
    io::copy(&mut artifact, executable.as_file_mut())?;
    executable.as_file_mut().flush()?;
    let mut permissions = executable.as_file().metadata()?.permissions();
    permissions.set_mode(0o500);
    executable.as_file().set_permissions(permissions)?;
    let executable = executable.into_temp_path();
    command.program(&executable).arg0(arg0);

    let directory = tempfile::Builder::new()
        .prefix("reverie-e9patch-coordinator-")
        .tempdir()?;
    let socket = directory.path().join("coordinator.sock");
    let global = Arc::new(T::GlobalState::init_global_state(&config).await);
    let connected = Arc::new(AtomicBool::new(false));
    let server = RpcServer::bind_with_connection_readiness(
        &socket,
        global.clone(),
        config,
        connected.clone(),
    )
    .map_err(|error| io::Error::other(error.to_string()))?;

    let mut child_command = command.into_std_lossy();
    let configured_preload = child_command
        .get_envs()
        .find(|(key, _)| *key == OsStr::new("LD_PRELOAD"))
        .map(|(_, value)| value.map(ToOwned::to_owned));
    let mut ld_preload = preload.into_os_string();
    let inherited_preload = match configured_preload {
        Some(value) => value,
        None => std::env::var_os("LD_PRELOAD"),
    };
    if let Some(existing) = inherited_preload.filter(|value| !value.is_empty()) {
        ld_preload.push(OsStr::new(":"));
        ld_preload.push(existing);
    }
    child_command
        .env("LD_PRELOAD", ld_preload)
        .env(crate::COORDINATOR_ENV, &socket);

    let child = match child_command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = executable.close();
            return Err(error.into());
        }
    };
    let wait = tokio::task::spawn_blocking(move || child.wait_with_output());
    let wait = serve_rpc_until(server, async move {
        wait.await
            .map_err(|error| io::Error::other(error.to_string()))?
    })
    .await?;
    executable.close()?;
    if !connected.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "e9patch guest exited before its Tool preload connected to the coordinator",
        )
        .into());
    }
    let global = unwrap_global_after_connections(global).await?;
    Ok((
        Output {
            status: wait.status.into(),
            stdout: wait.stdout,
            stderr: wait.stderr,
        },
        global,
    ))
}

async fn serve_rpc_until<G, F, T>(server: RpcServer<G>, completion: F) -> io::Result<T>
where
    G: GlobalTool + 'static,
    F: Future<Output = io::Result<T>>,
{
    let mut serving = tokio::task::JoinSet::new();
    serving.spawn(server.serve());
    tokio::pin!(completion);

    let result = tokio::select! {
        biased;
        result = &mut completion => result,
        result = serving.join_next() => {
            let message = match result {
                Some(Ok(Ok(()))) => "e9patch coordinator stopped unexpectedly".to_owned(),
                Some(Ok(Err(error))) => error.to_string(),
                Some(Err(error)) => error.to_string(),
                None => "e9patch coordinator task disappeared".to_owned(),
            };
            return Err(io::Error::other(message));
        }
    };

    serving.abort_all();
    while let Some(server_result) = serving.join_next().await {
        match server_result {
            Err(error) if error.is_cancelled() => {}
            Ok(Ok(())) => {
                return Err(io::Error::other("e9patch coordinator stopped unexpectedly"));
            }
            Ok(Err(error)) => return Err(io::Error::other(error.to_string())),
            Err(error) => return Err(io::Error::other(error.to_string())),
        }
    }
    result
}

async fn unwrap_global_after_connections<G>(mut global: Arc<G>) -> io::Result<G> {
    for _ in 0..1024 {
        match Arc::try_unwrap(global) {
            Ok(global) => return Ok(global),
            Err(still_shared) => global = still_shared,
        }
        tokio::task::yield_now().await;
    }
    Err(io::Error::other(
        "e9patch coordinator state still has owners after connection shutdown",
    ))
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
