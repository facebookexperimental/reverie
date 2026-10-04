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
use std::os::unix::fs::MetadataExt;
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
    fn cleanup(mut self, completed: bool) -> io::Result<()> {
        match self.cleanup_in_place(completed) {
            Ok(()) => Ok(()),
            Err(error) => {
                // No destructor/unlink fallback after refusal, even if the
                // traced tasks already physically retired or setup failed.
                reverie_ptrace::quarantine_cleanup_resource(self);
                let _ = writeln!(
                    io::stderr().lock(),
                    "e9patch cleanup unconfirmed; original resource retained permanently: {error}"
                );
                Err(error)
            }
        }
    }

    fn cleanup_in_place(&mut self, completed: bool) -> io::Result<()> {
        self.cleanup_in_place_with_post_remove(completed, |_| {})
    }

    // The callback lets tests install a replacement after the real unlink and
    // before replacing the resource (which drops its TempPath).
    fn cleanup_in_place_with_post_remove(
        &mut self,
        completed: bool,
        post_remove: impl FnOnce(&Path),
    ) -> io::Result<()> {
        let remove = |path: &Path| match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
        match self {
            Self::Temporary(path) => {
                remove(path)?;
                // The pathname is gone; Drop must not unlink a new occupant.
                path.disable_cleanup(true);
                post_remove(path);
            }
            Self::Overlay {
                mount,
                backing_path,
            } => {
                mount.namespace.verify()?;
                if mount.mounted && !completed {
                    // Namespace equality is not exclusive mount authority.
                    // Fatal cleanup never selects a mount by pathname, even
                    // after switch-back or removal of a covering mount.
                    return Err(io::Error::other(
                        "fatal e9patch overlay cleanup unconfirmed; mounted overlay and backing retained",
                    ));
                }
                // Only an actual Ok legacy result selects the established
                // pathname cleanup. Its concurrent-topology limitation remains.
                mount.unmount()?;
                remove(backing_path)?;
                backing_path.disable_cleanup(true);
                post_remove(backing_path);
            }
            Self::Original => {}
        }
        *self = Self::Original;
        Ok(())
    }

    fn overlay(backing_path: tempfile::TempPath, target: &Path) -> io::Result<Self> {
        Self::overlay_with_remount(backing_path, target, |target| {
            syscall_result(unsafe {
                libc::mount(
                    ptr::null(),
                    target.as_ptr(),
                    ptr::null(),
                    (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong,
                    ptr::null(),
                )
            })
        })
    }

    fn overlay_with_remount(
        backing_path: tempfile::TempPath,
        target: &Path,
        remount: impl FnOnce(&std::ffi::CStr) -> io::Result<()>,
    ) -> io::Result<Self> {
        // Own the backing before bind. All fallible preparation precedes bind;
        // after it succeeds the full original resource is immediately owned.
        let namespace = MountNamespace::capture()?;
        let source = path_cstring(&backing_path)?;
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
        let resource = Self::Overlay {
            mount: ExecutableOverlay {
                target: target_cstring,
                target_path,
                namespace,
                mounted: true,
            },
            backing_path,
        };
        let Self::Overlay { mount, .. } = &resource else {
            unreachable!()
        };
        if let Err(error) = remount(&mount.target) {
            reverie_ptrace::quarantine_cleanup_resource(resource);
            let _ = writeln!(
                io::stderr().lock(),
                "e9patch readonly remount failed; installed overlay and backing retained permanently: {error}"
            );
            return Err(error);
        }
        Ok(resource)
    }
}

impl reverie_ptrace::PtraceCleanupResource for ExecutableResource {
    fn cleanup(&mut self) -> Result<(), Error> {
        self.cleanup_in_place(false).map_err(Error::from)
    }
}

fn finish_legacy_wait<G: 'static, R: 'static>(
    result: Result<(R, G), Error>,
    resource: ExecutableResource,
) -> Result<(R, G), Error> {
    match result {
        Err(Error::Tool(error))
            if error
                .downcast_ref::<reverie_ptrace::CleanupUnconfirmed>()
                .is_some() =>
        {
            let retained = error
                .downcast_ref::<reverie_ptrace::CleanupUnconfirmed>()
                .unwrap();
            let attachment = retained.retain_cleanup_resource::<G, R, _>(resource);
            match attachment {
                Ok(()) => Err(Error::Tool(error)),
                // The API retains the exact unbound guard and another admission
                // permit on refusal. Keep the original typed failure in context.
                Err(refusal) => Err(Error::Tool(error.context(refusal))),
            }
        }
        Err(error) => {
            let _ = resource.cleanup(false);
            Err(error)
        }
        Ok(result) => {
            resource.cleanup(true)?;
            Ok(result)
        }
    }
}

fn finish_spawn<G>(
    result: Result<Tracer<G>, Error>,
    resource: ExecutableResource,
) -> Result<(Tracer<G>, ExecutableResource), Error> {
    match result {
        Ok(tracer) => Ok((tracer, resource)),
        Err(error) => {
            let _ = resource.cleanup(false);
            Err(error)
        }
    }
}

struct ExecutableOverlay {
    target: CString,
    target_path: PathBuf,
    namespace: MountNamespace,
    mounted: bool,
}

struct MountNamespace {
    file: File,
    device: u64,
    inode: u64,
}

impl MountNamespace {
    fn capture() -> io::Result<Self> {
        let file = File::open("/proc/thread-self/ns/mnt")?;
        let metadata = file.metadata()?;
        Ok(Self {
            file,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn verify(&self) -> io::Result<()> {
        let held = self.file.metadata()?;
        let current = std::fs::metadata("/proc/thread-self/ns/mnt")?;
        if (held.dev(), held.ino()) != (self.device, self.inode)
            || (current.dev(), current.ino()) != (self.device, self.inode)
        {
            return Err(io::Error::other(
                "e9patch cleanup refused outside its original thread mount namespace",
            ));
        }
        Ok(())
    }
}

impl ExecutableOverlay {
    fn unmount(&mut self) -> io::Result<()> {
        self.namespace.verify()?;
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
            let _ = writeln!(
                io::stderr().lock(),
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
            let resource = ExecutableResource::overlay(executable, &source)?;
            command.program(&source).arg0(arg0);
            (resource, source)
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
        let (tracer, resource) = finish_spawn(spawn_result, resource)?;
        Ok((tracer, resource, stats))
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
        let (output, global, _stats) =
            <Self as Backend>::run_with_output::<T>(command, config).await?;
        Ok((output, global))
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
        finish_legacy_wait(tracer.wait().await, resource)
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
        finish_legacy_wait(tracer.wait_with_output().await, resource)
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
        .tempdir_in("/tmp")?;
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
        finish_legacy_wait(tracer.wait().await, resource)
    }

    async fn run_with_stats<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(ExitStatus, T::GlobalState, Self::Stats), Error>
    where
        T: Tool + 'static,
    {
        let (tracer, resource, stats) = Self::spawn::<T>(command, config, false).await?;
        finish_legacy_wait(tracer.wait().await, resource)
            .map(|(status, global)| (status, global, stats.backend_stats()))
    }

    async fn run_with_output<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(Output, T::GlobalState, Self::Stats), Error>
    where
        T: Tool + 'static,
    {
        // Pipe here rather than relying on the caller. The previous inherent
        // `run_with_output` left this to whoever called it, so a caller that
        // forgot returned empty buffers that were indistinguishable from a
        // guest that printed nothing.
        command.stdout(reverie::process::Stdio::piped());
        command.stderr(reverie::process::Stdio::piped());
        let (tracer, resource, stats) = Self::spawn::<T>(command, config, false).await?;
        finish_legacy_wait(tracer.wait_with_output().await, resource)
            .map(|(output, global)| (output, global, stats.backend_stats()))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;

    use super::*;

    struct ReplacementOracle {
        path: PathBuf,
        original: File,
        original_identity: (u64, u64),
        replacement: Option<File>,
    }

    impl ReplacementOracle {
        fn new(directory: &Path) -> (Self, tempfile::TempPath) {
            let mut file = tempfile::NamedTempFile::new_in(directory).unwrap();
            file.write_all(b"original inode bytes").unwrap();
            let original = file.reopen().unwrap();
            let metadata = original.metadata().unwrap();
            assert_eq!(metadata.nlink(), 1);
            let path = file.into_temp_path();
            (
                Self {
                    path: path.to_path_buf(),
                    original,
                    original_identity: (metadata.dev(), metadata.ino()),
                    replacement: None,
                },
                path,
            )
        }

        fn replace(&mut self, path: &Path) {
            assert_eq!(path, self.path);
            assert_eq!(
                fs::symlink_metadata(path).unwrap_err().kind(),
                io::ErrorKind::NotFound,
                "the real first unlink must precede replacement"
            );
            let original = self.original.metadata().unwrap();
            assert_eq!((original.dev(), original.ino()), self.original_identity);
            assert_eq!(original.nlink(), 0);
            let mut replacement = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap();
            replacement
                .write_all(b"distinct replacement bytes")
                .unwrap();
            let metadata = replacement.metadata().unwrap();
            // The open original fd prevents inode reuse from satisfying this.
            assert_ne!((metadata.dev(), metadata.ino()), self.original_identity);
            assert_eq!(metadata.nlink(), 1);
            eprintln!(
                "post-remove path={} original={:?}/nlink={} replacement={:?}/nlink={}",
                path.display(),
                self.original_identity,
                original.nlink(),
                (metadata.dev(), metadata.ino()),
                metadata.nlink()
            );
            self.replacement = Some(replacement);
        }

        fn assert_survives(&self) {
            use std::os::unix::fs::FileExt;

            let held = self.replacement.as_ref().expect("post-remove hook ran");
            let metadata = fs::symlink_metadata(&self.path)
                .expect("cleanup/Drop unlinked the distinct replacement");
            let held_metadata = held.metadata().unwrap();
            assert_eq!(
                (metadata.dev(), metadata.ino()),
                (held_metadata.dev(), held_metadata.ino())
            );
            assert_ne!((metadata.dev(), metadata.ino()), self.original_identity);
            assert_eq!(metadata.nlink(), 1);
            assert_eq!(held_metadata.nlink(), 1);
            assert_eq!(fs::read(&self.path).unwrap(), b"distinct replacement bytes");
            let mut bytes = [0; 26];
            assert_eq!(held.read_at(&mut bytes, 0).unwrap(), bytes.len());
            assert_eq!(&bytes, b"distinct replacement bytes");
            let original = self.original.metadata().unwrap();
            assert_eq!((original.dev(), original.ino()), self.original_identity);
            assert_eq!(original.nlink(), 0);
            let mut bytes = [0; 20];
            assert_eq!(self.original.read_at(&mut bytes, 0).unwrap(), bytes.len());
            assert_eq!(&bytes, b"original inode bytes");
        }
    }

    fn temporary_cleanup_replacement(missing: bool) {
        let directory = tempfile::tempdir().unwrap();
        let (mut oracle, path) = ReplacementOracle::new(directory.path());
        let mut resource = ExecutableResource::Temporary(path);
        if missing {
            fs::remove_file(&oracle.path).unwrap();
        }
        resource
            .cleanup_in_place_with_post_remove(true, |path| oracle.replace(path))
            .unwrap();
        assert!(matches!(resource, ExecutableResource::Original));
        oracle.assert_survives();
        drop(resource);
        oracle.assert_survives();
    }

    #[test]
    fn temporary_cleanup_preserves_replacement() {
        temporary_cleanup_replacement(false);
    }

    #[test]
    fn temporary_not_found_cleanup_preserves_replacement() {
        temporary_cleanup_replacement(true);
    }

    #[test]
    fn temporary_failed_unlink_retains_guard_for_retry() {
        let directory = tempfile::tempdir().unwrap();
        let (mut oracle, path) = ReplacementOracle::new(directory.path());
        let mut resource = ExecutableResource::Temporary(path);
        let parked = directory.path().join("parked-original");
        fs::rename(&oracle.path, &parked).unwrap();
        fs::create_dir(&oracle.path).unwrap();
        let error = resource
            .cleanup_in_place_with_post_remove(true, |_| panic!("failed unlink ran hook"))
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EISDIR));
        let ExecutableResource::Temporary(path) = &resource else {
            panic!("failed unlink lost the original guard")
        };
        assert_eq!(path.to_path_buf(), oracle.path);
        assert_eq!(oracle.original.metadata().unwrap().nlink(), 1);
        fs::remove_dir(&oracle.path).unwrap();
        fs::rename(&parked, &oracle.path).unwrap();
        resource
            .cleanup_in_place_with_post_remove(true, |path| oracle.replace(path))
            .unwrap();
        assert!(matches!(resource, ExecutableResource::Original));
        drop(resource);
        oracle.assert_survives();
    }

    #[test]
    fn temporary_failed_unlink_keeps_drop_armed() {
        let directory = tempfile::tempdir().unwrap();
        let (oracle, path) = ReplacementOracle::new(directory.path());
        let mut resource = ExecutableResource::Temporary(path);
        let parked = directory.path().join("parked-original");
        fs::rename(&oracle.path, &parked).unwrap();
        fs::create_dir(&oracle.path).unwrap();
        let error = resource.cleanup_in_place(true).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EISDIR));
        assert!(matches!(resource, ExecutableResource::Temporary(_)));
        fs::remove_dir(&oracle.path).unwrap();
        fs::rename(&parked, &oracle.path).unwrap();
        // Directly dropping this test-owned guard proves a failed unlink did
        // not disarm it. Production error paths retain/quarantine the guard.
        drop(resource);
        assert_eq!(
            fs::symlink_metadata(&oracle.path).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(oracle.original.metadata().unwrap().nlink(), 0);
    }

    #[test]
    fn retained_executable_cleanup_preserves_backing_on_detach_refusal() {
        let backing = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let path = backing.to_path_buf();
        let target = tempfile::tempdir().unwrap();
        // This unique directory is deliberately not a mount. The real umount2
        // refusal exercises retention, without claiming mounted-overlay coverage.
        let mut resource = ExecutableResource::Overlay {
            mount: ExecutableOverlay {
                target: path_cstring(target.path()).unwrap(),
                target_path: target.path().to_owned(),
                namespace: MountNamespace::capture().unwrap(),
                mounted: true,
            },
            backing_path: backing,
        };
        // The established success path must still exercise the real syscall;
        // unconditional fatal retention is not an umount-refusal test.
        assert!(resource.cleanup_in_place(true).is_err());
        assert!(path.exists(), "detach refusal unlinked original backing");
        let ExecutableResource::Overlay {
            mount,
            backing_path,
        } = &mut resource
        else {
            panic!("refusal dropped original resource variant")
        };
        assert_eq!(backing_path.to_path_buf(), path);
        // Test-only rescue removes the synthetic mounted claim. No real mount
        // was installed or recovered by this unit control.
        mount.mounted = false;
        reverie_ptrace::PtraceCleanupResource::cleanup(&mut resource).unwrap();
        assert!(!path.exists());
        assert!(matches!(resource, ExecutableResource::Original));
    }

    #[test]
    fn confirmed_executable_cleanup_preserves_original_error_precedence() {
        let backing = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let path = backing.to_path_buf();
        let result: Result<(ExitStatus, ()), Error> = finish_legacy_wait(
            Err(reverie::Errno::EBADF.into()),
            ExecutableResource::Temporary(backing),
        );
        assert!(matches!(result, Err(Error::Errno(reverie::Errno::EBADF))));
        assert!(!path.exists());
    }

    static OVERLAY_EXIT_RELEASE: AtomicBool = AtomicBool::new(true);
    static OVERLAY_EFFECTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    #[derive(Debug)]
    struct OverlayToolFailure(Box<u64>);
    impl std::fmt::Display for OverlayToolFailure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "typed overlay failure after effect {}", self.0)
        }
    }
    impl std::error::Error for OverlayToolFailure {}

    #[derive(Default)]
    struct OverlayFailureTool;
    #[reverie::tool]
    impl Tool for OverlayFailureTool {
        type GlobalState = ();
        type ThreadState = ();

        fn subscriptions(_: &()) -> reverie::Subscription {
            reverie::Subscription::none()
        }

        async fn handle_thread_start<G: reverie::Guest<Self>>(
            &self,
            _: &mut G,
        ) -> Result<(), Error> {
            OVERLAY_EFFECTS.fetch_add(1, Ordering::SeqCst);
            Err(anyhow::Error::new(OverlayToolFailure(Box::new(73))).into())
        }

        async fn on_exit_thread<G: reverie::GlobalRPC<()>>(
            &self,
            _: reverie::Tid,
            _: &G,
            _: (),
            _: ExitStatus,
        ) -> Result<(), Error> {
            while !OVERLAY_EXIT_RELEASE.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum OverlayCase {
        Namespace,
        Cover,
        Complete,
        Setup,
        Constructor,
        SuccessRefusal,
        Replacement,
        MissingReplacement,
        RetryReplacement,
    }

    fn overlay_now_ns() -> u64 {
        let mut now: libc::timespec = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) },
            0
        );
        now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
    }

    fn visible_mount_id(path: &Path) -> u64 {
        let path = path_cstring(path).unwrap();
        let mut stat = MaybeUninit::<libc::statx>::zeroed();
        assert_eq!(
            unsafe {
                libc::statx(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    0,
                    libc::STATX_MNT_ID,
                    stat.as_mut_ptr(),
                )
            },
            0
        );
        let stat = unsafe { stat.assume_init() };
        assert_ne!(stat.stx_mask & libc::STATX_MNT_ID, 0);
        stat.stx_mnt_id
    }

    fn assert_mount_present(id: u64) {
        assert!(
            fs::read_to_string("/proc/thread-self/mountinfo")
                .unwrap()
                .lines()
                .any(|line| line.split_once(' ').unwrap().0.parse::<u64>().unwrap() == id)
        );
    }

    async fn assert_overlay_admission_closed() {
        let result = TracerBuilder::<()>::new(Command::new("/bin/true"))
            .spawn()
            .await;
        assert!(
            matches!(result, Err(Error::Tool(error)) if error.downcast_ref::<reverie_ptrace::CleanupAdmissionRefused>().is_some()),
            "retained mounted overlay reopened real ptrace admission"
        );
    }

    fn assert_overlay_primary(error: &Error) -> usize {
        let Error::Tool(error) = error else {
            panic!("original typed Tool failure lost")
        };
        let cause = error
            .downcast_ref::<OverlayToolFailure>()
            .expect("original cause type");
        assert_eq!(*cause.0, 73);
        &*cause.0 as *const u64 as usize
    }

    async fn run_overlay_case(name: &'static str, case: OverlayCase) {
        const ROLE: &str = "REVERIE_REAL_OVERLAY_CHILD";
        const DEADLINE: &str = "REVERIE_REAL_OVERLAY_DEADLINE";
        const PARENT_NAMESPACE: &str = "REVERIE_REAL_OVERLAY_PARENT_NAMESPACE";
        if std::env::var(ROLE).as_deref() != Ok(name) {
            let deadline = overlay_now_ns() + 5_000_000_000;
            let mut child = std::process::Command::new("/usr/bin/unshare")
                .args([
                    "--user",
                    "--map-root-user",
                    "--mount",
                    "--propagation",
                    "private",
                    "--",
                ])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture", "--test-threads=1"])
                .env(ROLE, name)
                .env(
                    PARENT_NAMESPACE,
                    fs::read_link("/proc/thread-self/ns/mnt").unwrap(),
                )
                .env(DEADLINE, deadline.to_string())
                .spawn()
                .unwrap();
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(
                        status.success(),
                        "real overlay fixture/environment failed: {status}"
                    );
                    assert!(
                        overlay_now_ns() < deadline,
                        "original five-second deadline expired"
                    );
                    return;
                }
                if overlay_now_ns() >= deadline {
                    let signal = child.kill();
                    let rescue_deadline = overlay_now_ns() + 2_000_000_000;
                    let rescue = loop {
                        let status = child.try_wait().unwrap();
                        if status.is_some() || overlay_now_ns() >= rescue_deadline {
                            break status;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    };
                    panic!(
                        "original overlay deadline failed; separate rescue only: {signal:?}, {rescue:?}"
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }
        assert!(std::env::args().any(|arg| arg == name));
        assert!(std::env::args().any(|arg| arg == "--exact"));
        assert_ne!(
            fs::read_link("/proc/thread-self/ns/mnt")
                .unwrap()
                .as_os_str(),
            std::env::var_os(PARENT_NAMESPACE).unwrap(),
            "mount fixture must own a private namespace before changing mounts"
        );
        eprintln!(
            "private mount namespace {:?}; parent {:?}",
            fs::read_link("/proc/thread-self/ns/mnt").unwrap(),
            std::env::var_os(PARENT_NAMESPACE).unwrap()
        );
        let remaining = std::env::var(DEADLINE)
            .unwrap()
            .parse::<u64>()
            .unwrap()
            .saturating_sub(overlay_now_ns());
        tokio::time::timeout(
            std::time::Duration::from_nanos(remaining),
            overlay_case_body(case),
        )
        .await
        .expect("real overlay body exceeded original pre-exec deadline");
    }

    async fn overlay_case_body(case: OverlayCase) {
        if matches!(
            case,
            OverlayCase::Replacement
                | OverlayCase::MissingReplacement
                | OverlayCase::RetryReplacement
        ) {
            overlay_cleanup_replacement(case);
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        fs::write(&target, b"original-file").unwrap();
        let mut backing = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        backing.write_all(b"original-overlay").unwrap();
        let backing = backing.into_temp_path();
        let backing_name = backing.to_path_buf();
        let original_namespace = MountNamespace::capture().unwrap();
        let resource = if matches!(case, OverlayCase::Constructor) {
            // A real MS_BIND followed by an injected returned errno at precisely
            // the readonly-remount boundary; this is not a kernel EPERM claim.
            let result = ExecutableResource::overlay_with_remount(backing, &target, |_| {
                Err(io::Error::from_raw_os_error(libc::EIO))
            });
            assert!(matches!(result, Err(ref error) if error.raw_os_error() == Some(libc::EIO)));
            drop(result);
            None
        } else {
            Some(ExecutableResource::overlay(backing, &target).unwrap())
        };
        let original_id = visible_mount_id(&target);
        assert_ne!(original_id, visible_mount_id(directory.path()));
        assert_eq!(fs::read(&target).unwrap(), b"original-overlay");
        assert_mount_present(original_id);

        match case {
            OverlayCase::Namespace | OverlayCase::Cover => {
                OVERLAY_EXIT_RELEASE.store(false, Ordering::SeqCst);
                let tracer = TracerBuilder::<OverlayFailureTool>::new(Command::new("/bin/true"))
                    .spawn()
                    .await
                    .unwrap();
                let root = tracer.guest_pid();
                let error = finish_legacy_wait(tracer.wait().await, resource.unwrap())
                    .expect_err("actual Pending marker");
                let Error::Tool(error) = error else {
                    panic!("typed cleanup marker required")
                };
                let marker = error
                    .downcast_ref::<reverie_ptrace::CleanupUnconfirmed>()
                    .expect("actual Pending owner");
                let primary = assert_overlay_primary(marker.primary());
                let mut pending = marker.take_cleanup::<(), ExitStatus>().unwrap();
                drop(error);
                OVERLAY_EXIT_RELEASE.store(true, Ordering::SeqCst);
                let mut cover = None;
                if matches!(case, OverlayCase::Namespace) {
                    assert_eq!(
                        unsafe { libc::unshare(libc::CLONE_NEWNS) },
                        0,
                        "thread namespace setup refusal is failure"
                    );
                    assert!(original_namespace.verify().is_err());
                    let leader = fs::metadata("/proc/self/ns/mnt").unwrap();
                    assert_eq!(
                        (leader.dev(), leader.ino()),
                        (original_namespace.device, original_namespace.inode)
                    );
                } else {
                    let mut file = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
                    file.write_all(b"cover-overlay").unwrap();
                    cover =
                        Some(ExecutableResource::overlay(file.into_temp_path(), &target).unwrap());
                    assert_ne!(visible_mount_id(&target), original_id);
                    assert_eq!(fs::read(&target).unwrap(), b"cover-overlay");
                    assert_mount_present(original_id);
                }
                let visible_before = visible_mount_id(&target);
                let reverie_ptrace::ToolRunOutcome::CleanupPending(owner) =
                    pending.resume_cleanup().await
                else {
                    panic!("mounted overlay was falsely retired")
                };
                pending = owner;
                assert_eq!(assert_overlay_primary(pending.failure().primary()), primary);
                assert!(
                    !Path::new(&format!("/proc/{root}")).exists(),
                    "resource callback preceded actual task retirement"
                );
                assert_eq!(
                    visible_mount_id(&target),
                    visible_before,
                    "fatal cleanup detached a visible mount"
                );
                assert!(backing_name.exists());
                assert_overlay_admission_closed().await;
                if matches!(case, OverlayCase::Namespace) {
                    assert_eq!(
                        unsafe {
                            libc::setns(original_namespace.file.as_raw_fd(), libc::CLONE_NEWNS)
                        },
                        0
                    );
                    original_namespace.verify().unwrap();
                } else {
                    // Remove only the test-owned cover via the established
                    // successful path. This is not original-overlay recovery.
                    cover.take().unwrap().cleanup(true).unwrap();
                }
                assert_eq!(visible_mount_id(&target), original_id);
                assert_mount_present(original_id);
                let reverie_ptrace::ToolRunOutcome::CleanupPending(pending) =
                    pending.resume_cleanup().await
                else {
                    panic!("switch-back/cover removal falsely certified overlay recovery")
                };
                assert_eq!(assert_overlay_primary(pending.failure().primary()), primary);
                assert!(backing_name.exists());
                assert_eq!(visible_mount_id(&target), original_id);
                assert_overlay_admission_closed().await;
                drop(pending); // Abandonment must not release the original guard.
                assert_eq!(visible_mount_id(&target), original_id);
            }
            OverlayCase::Complete => {
                let tracer = TracerBuilder::<OverlayFailureTool>::new(Command::new("/bin/true"))
                    .spawn()
                    .await
                    .unwrap();
                let root = tracer.guest_pid();
                let result = tracer.wait().await;
                let primary = assert_overlay_primary(result.as_ref().err().unwrap());
                assert!(!Path::new(&format!("/proc/{root}")).exists());
                let error = finish_legacy_wait(result, resource.unwrap()).err().unwrap();
                assert_eq!(assert_overlay_primary(&error), primary);
                drop(error);
            }
            OverlayCase::Setup => {
                let result =
                    TracerBuilder::<()>::new(Command::new(directory.path().join("absent-program")))
                        .spawn()
                        .await;
                let original = result
                    .as_ref()
                    .err()
                    .expect("actual spawn setup error")
                    .to_string();
                let error = finish_spawn(result, resource.unwrap()).err().unwrap();
                assert_eq!(error.to_string(), original);
                drop(error);
            }
            OverlayCase::Replacement
            | OverlayCase::MissingReplacement
            | OverlayCase::RetryReplacement => unreachable!(),
            OverlayCase::Constructor => {}
            OverlayCase::SuccessRefusal => {
                // Real kernel refusal: clear only this thread's effective
                // CAP_SYS_ADMIN around the established successful cleanup.
                let mut header = [0x2008_0522_u32, 0];
                let mut caps = [[0_u32; 3]; 2];
                assert_eq!(
                    unsafe {
                        libc::syscall(libc::SYS_capget, header.as_mut_ptr(), caps.as_mut_ptr())
                    },
                    0
                );
                let saved = caps;
                assert_ne!(caps[0][0] & (1 << 21), 0);
                caps[0][0] &= !(1 << 21);
                assert_eq!(
                    unsafe { libc::syscall(libc::SYS_capset, header.as_ptr(), caps.as_ptr()) },
                    0
                );
                let result =
                    finish_legacy_wait::<(), _>(Ok((ExitStatus::Exited(0), ())), resource.unwrap());
                assert_eq!(
                    unsafe { libc::syscall(libc::SYS_capset, header.as_ptr(), saved.as_ptr()) },
                    0
                );
                assert!(
                    matches!(result, Err(Error::Io(ref error)) if error.raw_os_error() == Some(libc::EPERM))
                );
                drop(result);
            }
        }
        assert_eq!(fs::read(&target).unwrap(), b"original-overlay");
        assert_eq!(visible_mount_id(&target), original_id);
        assert_mount_present(original_id);
        assert!(
            backing_name.exists(),
            "fatal/refused cleanup unlinked original backing"
        );
        assert_overlay_admission_closed().await;
        if matches!(
            case,
            OverlayCase::Namespace | OverlayCase::Cover | OverlayCase::Complete
        ) {
            assert_eq!(
                OVERLAY_EFFECTS.load(Ordering::SeqCst),
                1,
                "original Tool effect count changed"
            );
        }
        // Explicit test teardown only. Product retains its guard/permit even
        // after this independent test-owned rescue; no recovery pass is claimed.
        assert_eq!(
            unsafe { libc::umount2(path_cstring(&target).unwrap().as_ptr(), libc::MNT_DETACH) },
            0
        );
        assert_eq!(fs::read(&target).unwrap(), b"original-file");
        fs::remove_file(&backing_name).unwrap();
        assert_overlay_admission_closed().await;
    }

    fn overlay_cleanup_replacement(case: OverlayCase) {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        fs::write(&target, b"underlying target bytes").unwrap();
        let underlying_mount = visible_mount_id(&target);
        let (mut oracle, backing) = ReplacementOracle::new(directory.path());
        let mut resource = ExecutableResource::overlay(backing, &target).unwrap();
        let overlay_mount = visible_mount_id(&target);
        assert_ne!(overlay_mount, underlying_mount);
        assert_mount_present(overlay_mount);
        assert_eq!(fs::read(&target).unwrap(), b"original inode bytes");
        // The constructor performed a real bind and readonly remount.
        assert_eq!(
            fs::OpenOptions::new()
                .write(true)
                .open(&target)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EROFS)
        );
        if matches!(case, OverlayCase::RetryReplacement) {
            let mut header = [0x2008_0522_u32, 0];
            let mut caps = [[0_u32; 3]; 2];
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_capget, header.as_mut_ptr(), caps.as_mut_ptr()) },
                0
            );
            let saved = caps;
            assert_ne!(caps[0][0] & (1 << 21), 0);
            caps[0][0] &= !(1 << 21);
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_capset, header.as_ptr(), caps.as_ptr()) },
                0
            );
            let refused = resource
                .cleanup_in_place_with_post_remove(true, |_| panic!("unmount refusal ran hook"));
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_capset, header.as_ptr(), saved.as_ptr()) },
                0
            );
            assert_eq!(refused.unwrap_err().raw_os_error(), Some(libc::EPERM));
            let ExecutableResource::Overlay {
                mount,
                backing_path,
            } = &resource
            else {
                panic!("unmount refusal lost original resource")
            };
            assert!(mount.mounted);
            assert_eq!(backing_path.to_path_buf(), oracle.path);
            assert_eq!(oracle.original.metadata().unwrap().nlink(), 1);
            assert_eq!(visible_mount_id(&target), overlay_mount);
            assert_mount_present(overlay_mount);
        }
        if matches!(case, OverlayCase::MissingReplacement) {
            fs::remove_file(&oracle.path).unwrap();
        }
        resource
            .cleanup_in_place_with_post_remove(true, |path| {
                assert_eq!(visible_mount_id(&target), underlying_mount);
                assert_eq!(fs::read(&target).unwrap(), b"underlying target bytes");
                assert!(
                    !fs::read_to_string("/proc/thread-self/mountinfo")
                        .unwrap()
                        .lines()
                        .any(
                            |line| line.split_once(' ').unwrap().0.parse::<u64>().unwrap()
                                == overlay_mount
                        ),
                    "original overlay must be unmounted before replacement"
                );
                eprintln!(
                    "unmounted overlay={overlay_mount} restored_mount={underlying_mount} target={}",
                    target.display()
                );
                oracle.replace(path);
            })
            .unwrap();
        assert!(matches!(resource, ExecutableResource::Original));
        oracle.assert_survives();
        drop(resource);
        oracle.assert_survives();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn overlay_cleanup_preserves_replacement() {
        run_overlay_case(
            "backend::tests::overlay_cleanup_preserves_replacement",
            OverlayCase::Replacement,
        )
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn overlay_not_found_cleanup_preserves_replacement() {
        run_overlay_case(
            "backend::tests::overlay_not_found_cleanup_preserves_replacement",
            OverlayCase::MissingReplacement,
        )
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn overlay_failed_unmount_retains_guard_for_retry() {
        run_overlay_case(
            "backend::tests::overlay_failed_unmount_retains_guard_for_retry",
            OverlayCase::RetryReplacement,
        )
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn overlay_fatal_pending_namespace_retains_original() {
        run_overlay_case(
            "backend::tests::overlay_fatal_pending_namespace_retains_original",
            OverlayCase::Namespace,
        )
        .await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn overlay_fatal_pending_cover_retains_original() {
        run_overlay_case(
            "backend::tests::overlay_fatal_pending_cover_retains_original",
            OverlayCase::Cover,
        )
        .await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn overlay_complete_tool_failure_retains_original() {
        run_overlay_case(
            "backend::tests::overlay_complete_tool_failure_retains_original",
            OverlayCase::Complete,
        )
        .await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn overlay_spawn_setup_failure_retains_original() {
        run_overlay_case(
            "backend::tests::overlay_spawn_setup_failure_retains_original",
            OverlayCase::Setup,
        )
        .await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn overlay_readonly_remount_refusal_retains_original() {
        run_overlay_case(
            "backend::tests::overlay_readonly_remount_refusal_retains_original",
            OverlayCase::Constructor,
        )
        .await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn overlay_success_cleanup_refusal_retains_original() {
        run_overlay_case(
            "backend::tests::overlay_success_cleanup_refusal_retains_original",
            OverlayCase::SuccessRefusal,
        )
        .await;
    }

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

    #[tokio::test(flavor = "current_thread")]
    async fn backend_trait_output_capture_runs_non_elf_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let guest = directory.path().join("guest.sh");
        fs::write(
            &guest,
            "#!/bin/sh\nprintf 'front-door-out'\nprintf 'front-door-err' >&2\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&guest).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&guest, permissions).unwrap();

        let (output, (), stats) =
            <E9patchBackend as Backend>::run_with_output::<()>(Command::new(guest), ())
                .await
                .unwrap();

        assert_eq!(output.status, ExitStatus::Exited(0));
        assert_eq!(output.stdout, b"front-door-out");
        assert_eq!(output.stderr, b"front-door-err");
        assert_eq!(
            stats.rewrite_support(),
            crate::E9patchRewriteSupport::UnsupportedNonElf
        );
        assert_eq!(stats.recovered_sites(), None);
        assert_eq!(stats.patched_sites(), None);
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
