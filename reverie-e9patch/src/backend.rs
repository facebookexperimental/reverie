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
use std::ffi::OsString;
use std::fs::File;
use std::future::Future;
use std::io;
use std::io::Read;
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use reverie::Backend;
use reverie::BackendStatsSource;
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
use crate::E9patchBackendStatsSnapshot;
use crate::E9patchBackendStatsSource;
use crate::E9patchRewriter;

const PRELOAD_BOOTSTRAP_MAGIC: &[u8; 16] = b"REVERIE-E9-V1\0\0\0";
const PRELOAD_BOOTSTRAP_HEADER_BYTES: usize = PRELOAD_BOOTSTRAP_MAGIC.len() + 4;
const PRELOAD_BOOTSTRAP_MAX_BYTES: usize = 4096;

/// Environment variable naming a tool-specific DSO for [`E9patchBackend::run_direct`].
///
/// The DSO must embed the same concrete `T` and install it from a constructor,
/// matching LiteInst's `REVERIE_LITEINST_TOOL_PRELOAD` contract.
pub const TOOL_PRELOAD_ENV: &str = "REVERIE_E9PATCH_TOOL_PRELOAD";

/// Coordinator path and opaque tool-specific bytes consumed by an e9patch
/// preload constructor.
pub struct PreloadBootstrap {
    /// Unix-domain socket path for the generic Tool coordinator.
    pub coordinator: PathBuf,
    /// Opaque bytes supplied by the tool-specific coordinator launcher.
    pub tool_data: Vec<u8>,
}

/// Consumes the inherited generic-Tool bootstrap, if one is present.
///
/// # Safety
///
/// Call only from a preload constructor launched by [`E9patchBackend`]. This
/// scans inherited descriptors and consumes only a sealed, protocol-matching
/// memfd.
pub unsafe fn take_preload_bootstrap() -> io::Result<Option<PreloadBootstrap>> {
    let mut matching_fds = Vec::new();
    let mut found = Vec::new();
    let mut protocol_error = None;
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<libc::c_int>().ok())
        else {
            continue;
        };
        if fd <= libc::STDERR_FILENO {
            continue;
        }
        match read_preload_bootstrap(fd) {
            Ok(Some(bootstrap)) => {
                matching_fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
                found.push(bootstrap);
            }
            Ok(None) => {}
            Err(error) => {
                matching_fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
                protocol_error.get_or_insert(error);
            }
        }
    }
    if let Some(error) = protocol_error {
        return Err(error);
    }
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "multiple e9patch preload bootstraps",
        )),
    }
}

fn read_preload_bootstrap(fd: libc::c_int) -> io::Result<Option<PreloadBootstrap>> {
    let required_seals =
        libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if seals == -1 || seals & required_seals != required_seals {
        return Ok(None);
    }

    let mut magic = [0_u8; PRELOAD_BOOTSTRAP_MAGIC.len()];
    let magic_read = unsafe { libc::pread(fd, magic.as_mut_ptr().cast(), magic.len(), 0) };
    if magic_read != magic.len() as isize || magic != *PRELOAD_BOOTSTRAP_MAGIC {
        return Ok(None);
    }

    let mut stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } == -1 {
        return Ok(None);
    }
    let size = match usize::try_from(unsafe { stat.assume_init() }.st_size) {
        Ok(size)
            if (PRELOAD_BOOTSTRAP_HEADER_BYTES..=PRELOAD_BOOTSTRAP_MAX_BYTES).contains(&size) =>
        {
            size
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid e9patch preload bootstrap size",
            ));
        }
    };
    let mut packet = vec![0_u8; size];
    let read = unsafe { libc::pread(fd, packet.as_mut_ptr().cast(), packet.len(), 0) };
    if read != size as isize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated e9patch preload bootstrap",
        ));
    }

    let lengths = &packet[PRELOAD_BOOTSTRAP_MAGIC.len()..PRELOAD_BOOTSTRAP_HEADER_BYTES];
    let path_len = u16::from_le_bytes([lengths[0], lengths[1]]) as usize;
    let data_len = u16::from_le_bytes([lengths[2], lengths[3]]) as usize;
    if packet.len() != PRELOAD_BOOTSTRAP_HEADER_BYTES + path_len + data_len || path_len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid e9patch preload bootstrap lengths",
        ));
    }
    let path_end = PRELOAD_BOOTSTRAP_HEADER_BYTES + path_len;
    Ok(Some(PreloadBootstrap {
        coordinator: PathBuf::from(OsString::from_vec(
            packet[PRELOAD_BOOTSTRAP_HEADER_BYTES..path_end].to_vec(),
        )),
        tool_data: packet[path_end..].to_vec(),
    }))
}

fn create_preload_bootstrap(coordinator: &Path, tool_data: &[u8]) -> io::Result<OwnedFd> {
    let path = coordinator.as_os_str().as_bytes();
    let path_len = u16::try_from(path.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "e9patch coordinator path exceeds the bootstrap limit",
        )
    })?;
    let data_len = u16::try_from(tool_data.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "e9patch tool bootstrap data exceeds the bootstrap limit",
        )
    })?;
    let mut packet =
        Vec::with_capacity(PRELOAD_BOOTSTRAP_HEADER_BYTES + path.len() + tool_data.len());
    packet.extend_from_slice(PRELOAD_BOOTSTRAP_MAGIC);
    packet.extend_from_slice(&path_len.to_le_bytes());
    packet.extend_from_slice(&data_len.to_le_bytes());
    packet.extend_from_slice(path);
    packet.extend_from_slice(tool_data);
    if packet.len() > PRELOAD_BOOTSTRAP_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "e9patch preload bootstrap exceeds its size limit",
        ));
    }

    let fd = unsafe {
        libc::memfd_create(
            c"reverie-e9patch-bootstrap".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    let original = unsafe { OwnedFd::from_raw_fd(fd) };
    let fd = if original.as_raw_fd() <= libc::STDERR_FILENO {
        let promoted = unsafe {
            libc::fcntl(
                original.as_raw_fd(),
                libc::F_DUPFD_CLOEXEC,
                libc::STDERR_FILENO + 1,
            )
        };
        if promoted == -1 {
            return Err(io::Error::last_os_error());
        }
        unsafe { OwnedFd::from_raw_fd(promoted) }
    } else {
        original
    };
    let mut file = File::from(fd);
    file.write_all(&packet)?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(file.into())
}

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
    /// Runs a generic Tool through the direct AOT callback using the preload
    /// named by [`TOOL_PRELOAD_ENV`].
    ///
    /// This is the direct e9patch analog of LiteInst's environment-selected
    /// backend launch. It deliberately does not replace [`Backend::run`],
    /// which remains ptrace-hosted until the direct path covers the full guest
    /// lifecycle.
    pub async fn run_direct<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(ExitStatus, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        let preload = tool_preload_path()?;
        Self::run_direct_with_preload::<T>(command, config, preload).await
    }

    /// Runs a generic Tool through e9patch's direct AOT callback without
    /// capturing the guest's output.
    ///
    /// This matches LiteInst's explicit-preload status launch: the command's
    /// stdio configuration is left unchanged and the result contains only the
    /// guest's exit status plus the coordinator-owned global state. Any piped
    /// stdout or stderr is drained concurrently and discarded so a noisy guest
    /// cannot block on an unread caller pipe.
    pub async fn run_direct_with_preload<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
    ) -> Result<(ExitStatus, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        let (wait, global) =
            launch_direct::<T>(command, config, preload.into(), false, None).await?;
        match wait {
            ChildWait::Status(status) => Ok((status.into(), global)),
            ChildWait::Output(_) => unreachable!("status run returned captured output"),
        }
    }

    // TODO-HUMAN-REVIEW(PR-269): Review the first generic Tool launch boundary
    // with no host Tool syscall decisions and its inherited preload contract.
    /// Runs a generic Tool through e9patch's direct AOT callback and captures
    /// the guest's output.
    ///
    /// `preload` must be a tool-specific DSO that embeds the same concrete `T`
    /// and calls [`crate::install_tool::<T>`] from its constructor. The
    /// coordinator path is inherited through [`crate::COORDINATOR_ENV`]. This
    /// opt-in harness is intentionally separate from [`Backend::run`]. Its
    /// unit-tool tracer follows and reaps lifecycle events without adding a
    /// syscall-trace action; it does not establish full generic-Tool process-tree
    /// or exec-rebootstrap semantics.
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
        let (wait, global) =
            launch_direct::<T>(command, config, preload.into(), true, None).await?;
        match wait {
            ChildWait::Output(output) => Ok((into_reverie_output(output), global)),
            ChildWait::Status(_) => unreachable!("output run returned only a status"),
        }
    }

    /// Runs a generic Tool with captured output and a sealed, inherited
    /// constructor bootstrap.
    ///
    /// The bootstrap carries the coordinator path and opaque `tool_data`
    /// without adding either value to the guest environment. The tool-specific
    /// preload consumes it with [`crate::take_preload_bootstrap`] before guest
    /// `main` and selects the concrete `T` represented by the bytes.
    ///
    /// The preload must reject unknown selectors and install the same concrete
    /// `T` used to instantiate this coordinator. Selecting another Tool is a
    /// protocol violation even when its serialized types happen to be layout-
    /// compatible.
    pub async fn run_direct_with_output_and_preload_data<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
        tool_data: impl Into<Vec<u8>>,
    ) -> Result<(Output, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        command.stdout(reverie::process::Stdio::piped());
        command.stderr(reverie::process::Stdio::piped());
        let (wait, global) = launch_direct::<T>(
            command,
            config,
            preload.into(),
            true,
            Some(tool_data.into()),
        )
        .await?;
        match wait {
            ChildWait::Output(output) => Ok((into_reverie_output(output), global)),
            ChildWait::Status(_) => unreachable!("output run returned only a status"),
        }
    }

    /// Runs a generic Tool with inherited guest stdio and a sealed constructor
    /// bootstrap.
    ///
    /// The returned [`Output`] contains the guest status and empty byte
    /// buffers. This matches LiteInst's inherited-stdio launch contract for
    /// tools that share the launcher's output sink and need ordering between
    /// intercepted and pass-through guest writes.
    pub async fn run_direct_with_inherited_stdio_and_preload_data<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
        tool_data: impl Into<Vec<u8>>,
    ) -> Result<(Output, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        inherit_stdio(&mut command);
        let (wait, global) = launch_direct::<T>(
            command,
            config,
            preload.into(),
            true,
            Some(tool_data.into()),
        )
        .await?;
        match wait {
            ChildWait::Output(output) => {
                let output = into_reverie_output(output);
                debug_assert!(output.stdout.is_empty());
                debug_assert!(output.stderr.is_empty());
                Ok((output, global))
            }
            ChildWait::Status(_) => unreachable!("output run returned only a status"),
        }
    }

    async fn spawn<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preserve_executable: bool,
    ) -> Result<
        (
            Tracer<T::GlobalState>,
            ExecutableResource,
            E9patchBackendStatsSource,
        ),
        Error,
    >
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
            let stats = E9patchBackendStatsSource::unsupported_non_elf();
            eprintln!(
                ":: Backend: e9patch hybrid; {}; controller=ptrace; ldpreload={ldpreload}",
                stats.snapshot(),
            );
            command.program(&source).arg0(arg0);
            let tracer = spawn_tracer::<T>(command, config, None).await?;
            return Ok((tracer, ExecutableResource::Original, stats));
        }

        let prepared = E9patchRewriter::from_env()?.prepare(&source)?;
        let report = prepared.report();
        let image_entry_address = report.image_entry_address();
        let patched_site_addresses = report.patched_site_addresses().to_vec();
        let stats = E9patchBackendStatsSource::from_report(report);
        // TODO-HUMAN-REVIEW(PR-103): Review the stable backend coverage diagnostic.
        eprintln!(
            ":: Backend: e9patch hybrid; {}; controller=ptrace; ldpreload={ldpreload}",
            stats.snapshot(),
        );

        // TODO-HUMAN-REVIEW(PR-103): Review zero-site original-image execution.
        if report.patched_sites() == 0 {
            command.program(&source).arg0(arg0);
            let tracer = spawn_tracer::<T>(command, config, None).await?;
            return Ok((tracer, ExecutableResource::Original, stats));
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
            Ok(tracer) => Ok((tracer, resource, stats)),
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
        let (tracer, resource, _stats) = Self::spawn::<T>(command, config, false).await?;
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
        let (tracer, resource, _stats) = Self::spawn::<T>(command, config, true).await?;
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
        let (tracer, resource, _stats) = Self::spawn::<T>(command, config, true).await?;
        let result = tracer.wait_with_output().await;
        let cleanup = resource.cleanup();
        match (result, cleanup) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }
}

fn inherit_stdio(command: &mut Command) {
    command.stdin(reverie::process::Stdio::inherit());
    command.stdout(reverie::process::Stdio::inherit());
    command.stderr(reverie::process::Stdio::inherit());
}

enum ChildWait {
    Status(std::process::ExitStatus),
    Output(std::process::Output),
}

fn into_reverie_output(output: std::process::Output) -> Output {
    Output {
        status: output.status.into(),
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn drain_pipe<R>(mut pipe: R) -> std::thread::JoinHandle<io::Result<u64>>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || io::copy(&mut pipe, &mut io::sink()))
}

fn wait_without_output(mut child: std::process::Child) -> io::Result<std::process::ExitStatus> {
    let drainers = [
        child.stdout.take().map(drain_pipe),
        child.stderr.take().map(drain_pipe),
    ];
    let status = child.wait();
    if status.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }

    let mut drain_error = None;
    for drainer in drainers.into_iter().flatten() {
        let result = drainer
            .join()
            .map_err(|_| io::Error::other("e9patch stdio drainer panicked"))
            .and_then(|result| result.map(|_| ()));
        if let Err(error) = result {
            drain_error.get_or_insert(error);
        }
    }
    let status = status?;
    if let Some(error) = drain_error {
        return Err(error);
    }
    Ok(status)
}

fn tool_preload_path_from(value: Option<OsString>) -> io::Result<PathBuf> {
    let path = value
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, TOOL_PRELOAD_ENV))?;
    if path.is_file() {
        Ok(path)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{TOOL_PRELOAD_ENV}={} is not a file", path.display()),
        ))
    }
}

fn tool_preload_path() -> io::Result<PathBuf> {
    tool_preload_path_from(std::env::var_os(TOOL_PRELOAD_ENV))
}

/// Prepend the tool DSO to the command's effective `LD_PRELOAD` value.
///
/// `get_captured_envs()` already applies ordinary inheritance, explicit
/// overrides, `env_remove`, and `env_clear`. Absence from that map is therefore
/// authoritative: consulting the launcher's environment again would resurrect
/// a value the caller deliberately removed.
fn configure_tool_preload(command: &mut Command, preload: PathBuf) {
    let mut ld_preload = preload.into_os_string();
    if let Some(existing) = command
        .get_captured_envs()
        .remove(OsStr::new("LD_PRELOAD"))
        .filter(|value| !value.is_empty())
    {
        ld_preload.push(OsStr::new(":"));
        ld_preload.push(existing);
    }
    command.env("LD_PRELOAD", ld_preload);
}

async fn launch_direct<T>(
    mut command: Command,
    config: <T::GlobalState as GlobalTool>::Config,
    preload: PathBuf,
    capture_output: bool,
    tool_data: Option<Vec<u8>>,
) -> Result<(ChildWait, T::GlobalState), Error>
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

    // Merge the tool preload ahead of any LD_PRELOAD already configured on the
    // command (or inherited from this process), on the reverie `Command` so the
    // default (environment-bootstrap) path below can be driven by a
    // lifecycle-only `TracerBuilder<()>` reaper instead of a bare, single-process
    // spawn.
    configure_tool_preload(&mut command, preload);

    let wait = match tool_data {
        // Sealed-memfd bootstrap path. Mirroring reverie-liteinst's memfd branch,
        // this stays a single-process std spawn: the bootstrap fd is handed to the
        // guest via a `pre_exec` `F_SETFD` clear, expressed against
        // `std::process::Command`. This path is not yet tree-reaped.
        Some(tool_data) => {
            let mut child_command = command.try_into_std()?;
            let bootstrap = create_preload_bootstrap(&socket, &tool_data)?;
            let bootstrap_fd = bootstrap.as_raw_fd();
            // SAFETY: fcntl(2) is async-signal-safe and the closure captures only
            // the raw fd, which stays valid until `bootstrap` is dropped after the
            // child has spawned.
            unsafe {
                child_command.pre_exec(move || {
                    if libc::fcntl(bootstrap_fd, libc::F_SETFD, 0) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let child = match child_command.spawn() {
                Ok(child) => child,
                Err(error) => {
                    let _ = executable.close();
                    return Err(error.into());
                }
            };
            drop(bootstrap);
            let wait = tokio::task::spawn_blocking(move || {
                if capture_output {
                    child.wait_with_output().map(ChildWait::Output)
                } else {
                    wait_without_output(child).map(ChildWait::Status)
                }
            });
            serve_rpc_until(server, async move {
                wait.await
                    .map_err(|error| io::Error::other(error.to_string()))?
            })
            .await?
        }
        // Environment-bootstrap path (the default `run_direct` / output flows).
        // Lifecycle-only reaper: the unit tool `()` declares no syscall
        // subscriptions and therefore installs no PTRACE_EVENT_SECCOMP action.
        // Rewritten syscall sites run entirely in-guest; ptrace follows and reaps
        // the process tree (exec/clone/fork) and forwards ordinary signal-delivery
        // stops. In particular, a residual site handled by the guest's SIGSYS
        // filter is still visible to ptrace as signal delivery, but it is never
        // emulated by a host Tool. Dynamic-loader syscalls that occur before the
        // preload constructor installs that guest filter remain outside it.
        None => {
            command.env(crate::COORDINATOR_ENV, &socket);
            let tracer = match TracerBuilder::<()>::new(command).spawn().await {
                Ok(tracer) => tracer,
                Err(error) => {
                    let _ = executable.close();
                    return Err(error);
                }
            };
            serve_rpc_until(server, async move {
                if capture_output {
                    let (output, ()) = tracer
                        .wait_with_output()
                        .await
                        .map_err(|error| io::Error::other(error.to_string()))?;
                    Ok(ChildWait::Output(std::process::Output {
                        status: output.status.into(),
                        stdout: output.stdout,
                        stderr: output.stderr,
                    }))
                } else {
                    // `wait_discarding_output`, not the bare `wait`: this arm is
                    // reached with the caller's stdio possibly piped, and
                    // `run_direct_with_preload` documents that such pipes are
                    // drained concurrently and discarded. A bare `wait` leaves
                    // them unread and a noisy guest deadlocks on a full pipe.
                    let (status, ()) = tracer
                        .wait_discarding_output()
                        .await
                        .map_err(|error| io::Error::other(error.to_string()))?;
                    Ok(ChildWait::Status(status.into()))
                }
            })
            .await?
        }
    };
    executable.close()?;
    if !connected.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "e9patch guest exited before its Tool preload connected to the coordinator",
        )
        .into());
    }
    let global = unwrap_global_after_connections(global).await?;
    Ok((wait, global))
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
    type Stats = E9patchBackendStatsSnapshot;

    async fn run<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(ExitStatus, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        let (tracer, resource, _stats) = Self::spawn::<T>(command, config, false).await?;
        let result = tracer.wait().await;
        let cleanup = resource.cleanup();
        match (result, cleanup) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    async fn run_with_stats<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(ExitStatus, T::GlobalState, Self::Stats), Error>
    where
        T: Tool + 'static,
    {
        let (tracer, resource, stats) = Self::spawn::<T>(command, config, false).await?;
        let result = tracer.wait().await;
        let cleanup = resource.cleanup();
        match (result, cleanup) {
            (Ok((status, global)), Ok(())) => Ok((status, global, stats.backend_stats())),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;

    use super::*;

    fn captured_ld_preload(command: &Command) -> OsString {
        command
            .get_captured_envs()
            .remove(OsStr::new("LD_PRELOAD"))
            .expect("configured command must contain LD_PRELOAD")
    }

    #[test]
    fn direct_preload_respects_captured_environment_boundaries() {
        const CHILD_ENV: &str = "REVERIE_E9PATCH_PRELOAD_ENV_TEST_CHILD";
        const PARENT_PRELOAD: &str = "reverie-e9patch-parent-preload.so";
        const EXPLICIT_PRELOAD: &str = "explicit-preload.so";
        const TOOL_PRELOAD: &str = "/tool-preload.so";

        if std::env::var_os(CHILD_ENV).is_none() {
            // Run in a child whose real inherited environment contains a
            // nonempty LD_PRELOAD. The dynamic loader may warn that the sentinel
            // is not a DSO, but it still starts the test binary; capture that
            // diagnostic so a failed assertion remains readable.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "backend::tests::direct_preload_respects_captured_environment_boundaries",
                    "--nocapture",
                ])
                .env(CHILD_ENV, "1")
                .env("LD_PRELOAD", PARENT_PRELOAD)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child preload-boundary test failed:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        assert_eq!(std::env::var_os("LD_PRELOAD").unwrap(), PARENT_PRELOAD);

        let mut inherited = Command::new("/bin/true");
        configure_tool_preload(&mut inherited, PathBuf::from(TOOL_PRELOAD));
        assert_eq!(
            captured_ld_preload(&inherited),
            OsString::from(format!("{TOOL_PRELOAD}:{PARENT_PRELOAD}"))
        );

        let mut explicit = Command::new("/bin/true");
        explicit.env("LD_PRELOAD", EXPLICIT_PRELOAD);
        configure_tool_preload(&mut explicit, PathBuf::from(TOOL_PRELOAD));
        assert_eq!(
            captured_ld_preload(&explicit),
            OsString::from(format!("{TOOL_PRELOAD}:{EXPLICIT_PRELOAD}"))
        );

        let mut removed = Command::new("/bin/true");
        removed.env_remove("LD_PRELOAD");
        configure_tool_preload(&mut removed, PathBuf::from(TOOL_PRELOAD));
        assert_eq!(captured_ld_preload(&removed), TOOL_PRELOAD);

        let mut cleared = Command::new("/bin/true");
        cleared.env_clear();
        configure_tool_preload(&mut cleared, PathBuf::from(TOOL_PRELOAD));
        assert_eq!(captured_ld_preload(&cleared), TOOL_PRELOAD);
    }

    fn create_sealed_packet(packet: &[u8]) -> OwnedFd {
        let fd = unsafe {
            libc::memfd_create(
                c"reverie-e9patch-malformed-test".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        assert_ne!(fd, -1);
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(packet).unwrap();
        let seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        assert_ne!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) },
            -1
        );
        file.into()
    }

    /// Identifies live bootstrap objects by protocol payload, not descriptor
    /// number. Another parallel test may reuse an integer immediately after
    /// this test closes it, but cannot turn an unrelated descriptor into the
    /// uniquely identified bootstrap object.
    fn open_test_bootstraps() -> io::Result<Vec<(PathBuf, Vec<u8>)>> {
        let mut open = Vec::new();
        for entry in std::fs::read_dir("/proc/self/fd")? {
            let entry = entry?;
            let Some(fd) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<libc::c_int>().ok())
            else {
                continue;
            };
            if fd <= libc::STDERR_FILENO {
                continue;
            }
            if let Some(bootstrap) = read_preload_bootstrap(fd)? {
                open.push((bootstrap.coordinator, bootstrap.tool_data));
            }
        }
        Ok(open)
    }

    fn named_memfd_is_open(name: &str) -> io::Result<bool> {
        for entry in std::fs::read_dir("/proc/self/fd")? {
            let entry = entry?;
            let target = match std::fs::read_link(entry.path()) {
                Ok(target) => target,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if target.to_string_lossy().contains(name) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[test]
    fn inherited_stdio_replaces_caller_pipes() {
        let mut command = Command::new("/bin/true");
        command
            .stdin(reverie::process::Stdio::piped())
            .stdout(reverie::process::Stdio::piped())
            .stderr(reverie::process::Stdio::piped());
        inherit_stdio(&mut command);
        let mut child = command.try_into_std().unwrap().spawn().unwrap();
        assert!(child.stdin.is_none());
        assert!(child.stdout.is_none());
        assert!(child.stderr.is_none());
        let status = child.wait().unwrap();
        assert!(status.success());
    }

    #[test]
    fn status_wait_drains_piped_output_without_deadlock() {
        const CHILD_ENV: &str = "REVERIE_E9PATCH_STATUS_DRAIN_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let chunk = [b'x'; 16 * 1024];
            for _ in 0..128 {
                io::stdout().write_all(&chunk).unwrap();
                io::stderr().write_all(&chunk).unwrap();
            }
            return;
        }

        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::tests::status_wait_drains_piped_output_without_deadlock",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let (sender, receiver) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            sender.send(wait_without_output(child)).unwrap();
        });
        let result = match receiver.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(result) => result,
            Err(error) => {
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                let _ = waiter.join();
                panic!("status wait did not drain piped output before timeout: {error}");
            }
        };
        waiter.join().unwrap();
        assert!(result.unwrap().success());
    }

    #[test]
    fn tool_preload_path_requires_a_file() {
        let error = tool_preload_path_from(None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(error.to_string(), TOOL_PRELOAD_ENV);

        let directory = tempfile::tempdir().unwrap();
        let error =
            tool_preload_path_from(Some(directory.path().as_os_str().to_owned())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("is not a file"), "{error}");

        let file = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(
            tool_preload_path_from(Some(file.path().as_os_str().to_owned())).unwrap(),
            file.path()
        );
    }

    #[test]
    fn bootstrap_is_bounded_consumed_and_duplicate_safe() {
        let oversized = vec![0_u8; PRELOAD_BOOTSTRAP_MAX_BYTES];
        let error =
            create_preload_bootstrap(Path::new("/tmp/coordinator.sock"), &oversized).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let unrelated = tempfile::tempfile().unwrap();
        let first_expected = (PathBuf::from("/tmp/coordinator.sock"), b"noop".to_vec());
        let bootstrap = create_preload_bootstrap(&first_expected.0, &first_expected.1).unwrap();
        std::mem::forget(bootstrap);
        assert!(open_test_bootstraps().unwrap().contains(&first_expected));

        let bootstrap = unsafe { take_preload_bootstrap() }.unwrap().unwrap();
        assert_eq!(bootstrap.coordinator, Path::new("/tmp/coordinator.sock"));
        assert_eq!(bootstrap.tool_data, b"noop");
        assert!(
            !open_test_bootstraps().unwrap().contains(&first_expected),
            "consumed bootstrap descriptor remains open"
        );
        assert_ne!(
            unsafe { libc::fcntl(unrelated.as_raw_fd(), libc::F_GETFD) },
            -1
        );

        let multiple_expected = [
            (
                PathBuf::from("/tmp/e9patch-fd-reuse-test-1.sock"),
                b"one".to_vec(),
            ),
            (
                PathBuf::from("/tmp/e9patch-fd-reuse-test-2.sock"),
                b"two".to_vec(),
            ),
            (
                PathBuf::from("/tmp/e9patch-fd-reuse-test-3.sock"),
                b"three".to_vec(),
            ),
        ];
        for (coordinator, tool_data) in &multiple_expected {
            let bootstrap = create_preload_bootstrap(coordinator, tool_data).unwrap();
            std::mem::forget(bootstrap);
        }
        let open = open_test_bootstraps().unwrap();
        assert!(
            multiple_expected
                .iter()
                .all(|expected| open.contains(expected))
        );

        let error = match unsafe { take_preload_bootstrap() } {
            Err(error) => error,
            Ok(_) => panic!("multiple matching bootstraps must fail"),
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "multiple e9patch preload bootstraps");
        let open = open_test_bootstraps().unwrap();
        assert!(
            multiple_expected
                .iter()
                .all(|expected| !open.contains(expected)),
            "rejected bootstrap descriptors remain open: {open:?}"
        );

        let malformed = create_sealed_packet(PRELOAD_BOOTSTRAP_MAGIC);
        std::mem::forget(malformed);
        let valid_expected = (PathBuf::from("/tmp/valid.sock"), b"valid".to_vec());
        let valid = create_preload_bootstrap(&valid_expected.0, &valid_expected.1).unwrap();
        std::mem::forget(valid);
        assert!(named_memfd_is_open("reverie-e9patch-malformed-test").unwrap());
        assert!(named_memfd_is_open("reverie-e9patch-bootstrap").unwrap());
        let error = match unsafe { take_preload_bootstrap() } {
            Err(error) => error,
            Ok(_) => panic!("malformed bootstrap must fail"),
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "invalid e9patch preload bootstrap size");
        assert!(!named_memfd_is_open("reverie-e9patch-malformed-test").unwrap());
        assert!(!named_memfd_is_open("reverie-e9patch-bootstrap").unwrap());
    }

    #[test]
    fn bootstrap_promotes_closed_standard_descriptors() {
        const CHILD_ENV: &str = "REVERIE_E9PATCH_BOOTSTRAP_CLOSED_STDIO_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let bootstrap =
                create_preload_bootstrap(Path::new("/tmp/stdio.sock"), b"stdio").unwrap();
            assert!(bootstrap.as_raw_fd() > libc::STDERR_FILENO);
            let expected = (PathBuf::from("/tmp/stdio.sock"), b"stdio".to_vec());
            std::mem::forget(bootstrap);
            assert!(open_test_bootstraps().unwrap().contains(&expected));
            let consumed = unsafe { take_preload_bootstrap() }.unwrap().unwrap();
            assert_eq!(consumed.coordinator, Path::new("/tmp/stdio.sock"));
            assert_eq!(consumed.tool_data, b"stdio");
            assert!(!open_test_bootstraps().unwrap().contains(&expected));
            return;
        }

        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .arg("--exact")
            .arg("backend::tests::bootstrap_promotes_closed_standard_descriptors")
            .env(CHILD_ENV, "1");
        unsafe {
            child.pre_exec(|| {
                for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
                    libc::close(fd);
                }
                Ok(())
            });
        }
        assert!(child.status().unwrap().success());
    }
}
