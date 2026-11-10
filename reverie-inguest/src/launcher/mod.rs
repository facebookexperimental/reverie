//! Shared coordinator-side preload launch, RPC lifetime and completion policy.
//!
//! The compatibility Backend implementation retains the existing LiteInst
//! capability report. Engine-specific frontend selection is separate from
//! extracting this shared launch mechanism.

/// Owned initial-image stop observations and cancellation; no production release.
#[cfg(feature = "exec-stop")]
pub mod exec_stop;

// The native frontend drives the x86-64 fixed-gate recipe; on aarch64 it
// is refused at compile time until that recipe exists there.
#[cfg(all(feature = "exec-native-injection", target_arch = "x86_64"))]
pub mod native;
#[cfg(all(feature = "exec-native-injection", target_arch = "x86_64"))]
pub mod native_frontend;

use std::ffi::OsStr;
use std::ffi::OsString;
use std::future::Future;
use std::io;
use std::io::Read as _;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Output;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use reverie::Backend;
use reverie::BackendCapabilities;
use reverie::BackendStatsRequest;
use reverie::BackendStatsSource;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Tool;
use reverie::process::Command;
use reverie::process::Output as ReverieOutput;
use reverie_rpc_transport::ConnectionAdmission;
use reverie_rpc_transport::ConnectionMonitor;
use reverie_rpc_transport::ExitReporter;
use reverie_rpc_transport::RpcError;
#[cfg(feature = "exec-private-init")]
use reverie_rpc_transport::RpcIssueMonitor;
use reverie_rpc_transport::RpcServer;

use crate::bootstrap::COORDINATOR_ENV;
use crate::bootstrap::SITE_PATCHING_ENV;
use crate::bootstrap::STATS_COORDINATOR_ENV;
use crate::bootstrap::TOOL_PRELOAD_ENV;
use crate::bootstrap::create_preload_bootstrap;
#[cfg(test)]
use crate::bootstrap::read_preload_bootstrap;
#[cfg(test)]
use crate::bootstrap::take_preload_bootstrap;

const RPC_CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Typed statistics server for an authenticated private InitialImage launch.
///
/// The launching coordinator must create the run directory exclusively with
/// mode 0700, retain the genuine launch birth, and supply same-birth admission.
/// The relative endpoint requires the verified launch cwd and mount view to
/// remain unchanged through the process's terminal statistics submission.
#[cfg(feature = "exec-private-init")]
pub struct InitialImageStatsServer {
    server: RpcServer<crate::stats::LiteinstStatsGlobal>,
    issues: RpcIssueMonitor,
}

/// Consuming owner of the actual InitialImage statistics collected by the server.
#[cfg(feature = "exec-private-init")]
pub struct InitialImageStatsCollector {
    global: Arc<crate::stats::LiteinstStatsGlobal>,
}

#[cfg(feature = "exec-private-init")]
impl InitialImageStatsServer {
    /// Bind the fixed companion of the genuine Tool RPC endpoint.
    ///
    /// Binding never replaces an existing directory entry. Admission and
    /// retained connection issues are mandatory before any connection serves.
    pub fn bind(
        tool_rpc: &Path,
        owned_run_directory: &Path,
        admission: Arc<dyn ConnectionAdmission>,
    ) -> Result<(Self, InitialImageStatsCollector), RpcError> {
        let endpoint = crate::initial_image_stats::initial_image_stats_endpoint(tool_rpc)?;
        crate::initial_image_stats::check_owned_directory(
            tool_rpc,
            &endpoint,
            owned_run_directory,
        )?;
        let global = Arc::new(crate::stats::LiteinstStatsGlobal::default());
        let mut server = RpcServer::bind_exclusive(&endpoint, global.clone(), ())?;
        server.set_connection_admission(admission)?;
        let issues = server.retain_connection_issues();
        Ok((
            Self { server, issues },
            InitialImageStatsCollector { global },
        ))
    }

    /// Consume the unchanged prebound statistics endpoint and create the one
    /// real typed collector after common namespace setup. The caller retains
    /// the endpoint's owned directory through physical reap and server drain;
    /// neither this adapter nor the RPC factory unlinks or rebinds its inode.
    pub fn from_prebound(
        listener: std::os::unix::net::UnixListener,
        tool_rpc: &Path,
        owned_run_directory: &Path,
        admission: Arc<dyn ConnectionAdmission>,
    ) -> Result<(Self, InitialImageStatsCollector), RpcError> {
        let endpoint = crate::initial_image_stats::initial_image_stats_endpoint(tool_rpc)?;
        crate::initial_image_stats::check_owned_directory(
            tool_rpc,
            &endpoint,
            owned_run_directory,
        )?;
        if listener.local_addr()?.as_pathname() != Some(endpoint.as_path()) {
            return Err(RpcError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "prebound statistics endpoint differs from Tool companion",
            )));
        }
        let global = Arc::new(crate::stats::LiteinstStatsGlobal::default());
        let mut server = RpcServer::from_prebound(listener, global.clone(), ())?;
        server.set_connection_admission(admission)?;
        let issues = server.retain_connection_issues();
        Ok((
            Self { server, issues },
            InitialImageStatsCollector { global },
        ))
    }

    /// Observe actual accepted connection lifetime through teardown.
    pub fn connection_monitor(&self) -> ConnectionMonitor {
        self.server.connection_monitor()
    }

    /// Retained connection failures, including admission and cancellation.
    pub fn issue_monitor(&self) -> RpcIssueMonitor {
        self.issues.clone()
    }

    /// Serve the existing typed statistics protocol until explicitly stopped.
    pub async fn serve(self) -> Result<(), RpcError> {
        self.server.serve().await
    }
}

#[cfg(feature = "exec-private-init")]
impl InitialImageStatsCollector {
    /// Consume the actual source after clean connection/server teardown.
    ///
    /// Callers must reject retained issues and active connections, finish the
    /// physical watcher drain, and abort and join the server before this call.
    /// Live owners are an error under the ordinary bounded unwrap contract.
    pub async fn into_source(self) -> io::Result<crate::stats::LiteinstBackendStatsSource> {
        Ok(unwrap_global_after_connections(self.global)
            .await?
            .into_source())
    }
}

// TODO-HUMAN-REVIEW(PR-127): Review LiteInst Backend lifecycle and preload contract.
/// Shared preload launcher with a coordinator-owned `GlobalTool`.
///
/// Its legacy Backend implementation and protocol names remain compatible with
/// LiteInst while consumers migrate to independent in-guest frontend selection.
pub struct PreloadBackend;

tokio::task_local! {
    /// The admission every run started inside
    /// [`PreloadBackend::with_connection_admission`] installs on its
    /// coordinator.
    static CONNECTION_ADMISSION: Arc<dyn ConnectionAdmission>;
}

#[cfg(feature = "rpc-io-fixture")]
struct RpcLaunchIssueCaptureForTest {
    connections: ConnectionMonitor,
    issues: reverie_rpc_transport::RpcIssueMonitor,
}

#[cfg(feature = "rpc-io-fixture")]
tokio::task_local! {
    static RPC_ISSUES_FOR_TEST: Arc<std::sync::Mutex<Vec<RpcLaunchIssueCaptureForTest>>>;
}

/// Immutable observations from an actual ordinary launcher's Tool RPC server.
#[doc(hidden)]
#[cfg(feature = "rpc-io-fixture")]
#[derive(Debug)]
pub struct RpcLaunchObservationForTest {
    pub active_connections: usize,
    pub issues: Vec<reverie_rpc_transport::ConnectionIssue>,
}

impl PreloadBackend {
    /// Observe actual Tool servers after `future` returns, without exposing
    /// cancellation or planned-shutdown controls. Tests must require a completed
    /// successful launcher result as well as zero active connections and issues;
    /// a cancelled or timed-out future cannot establish a clean joined drain.
    #[doc(hidden)]
    #[cfg(feature = "rpc-io-fixture")]
    pub async fn with_rpc_issues_for_test<F: Future>(
        future: F,
    ) -> (F::Output, Vec<RpcLaunchObservationForTest>) {
        let captures = Arc::new(std::sync::Mutex::new(Vec::new()));
        let result = RPC_ISSUES_FOR_TEST.scope(captures.clone(), future).await;
        let observations = captures
            .lock()
            .unwrap()
            .iter()
            .map(|capture| RpcLaunchObservationForTest {
                active_connections: capture.connections.active_connections(),
                issues: capture.issues.snapshot(),
            })
            .collect();
        (result, observations)
    }

    /// Runs `future` so that every LiteInst run it starts admits each guest
    /// connection to its coordinator through `admission` before serving it:
    /// the admission receives the connecting process's pidfd before the
    /// configuration handshake, and a refusal closes the connection (see
    /// [`ConnectionAdmission`]). The statistics connection is not admitted; it
    /// carries no scheduled request. Runs started outside such a scope admit
    /// every connection unchecked, as before.
    pub async fn with_connection_admission<F: Future>(
        admission: Arc<dyn ConnectionAdmission>,
        future: F,
    ) -> F::Output {
        CONNECTION_ADMISSION.scope(admission, future).await
    }

    /// Runs `future` with the static-executable refusal disabled.
    /// Reserved for activation paths that arm static guests
    /// themselves (exec-stop); ordinary preload launches refuse.
    pub async fn with_static_executables_allowed<F: Future>(future: F) -> F::Output {
        STATIC_OPTOUT.scope(AllowStaticExecutables, future).await
    }

    /// Runs a tool using an explicit tool-specific preload library.
    ///
    /// This path dispatches patchable syscalls in the guest and keeps the
    /// `GlobalTool` in this coordinator. The coordinator drains inherited RPC
    /// connections to follow process-like fork/clone3 descendants without
    /// attaching ptrace. Vfork is translated to a COW child and supports the
    /// child-exit completion boundary. A trapping site that cannot be patched,
    /// or every site when `REVERIE_LITEINST_SITE_PATCHING` is `0`, runs the Tool
    /// through the in-guest `SIGSYS` fallback; that fallback refuses with
    /// `EOPNOTSUPP` on a thread whose fallback state is not ready, or while
    /// another fallback is pending on that thread. Thread clone and exec
    /// rebootstrap remain unsupported and are refused.
    pub async fn run_with_preload<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
    ) -> Result<(ExitStatus, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        let (wait, global, stats) = launch::<T>(
            command,
            config,
            preload.into(),
            false,
            None,
            BackendStatsRequest::DISABLED,
        )
        .await?;
        debug_assert!(stats.is_none());
        match wait {
            ChildWait::Status(status) => Ok((status.into(), global)),
            ChildWait::Output(_) => unreachable!("status run returned captured output"),
        }
    }

    /// Runs an in-guest Tool and aggregates one typed statistics snapshot per process.
    pub async fn run_with_preload_and_stats<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
    ) -> Result<
        (
            ExitStatus,
            T::GlobalState,
            crate::stats::LiteinstBackendStatsSource,
        ),
        Error,
    >
    where
        T: Tool + 'static,
    {
        let (wait, global, stats) = launch::<T>(
            command,
            config,
            preload.into(),
            false,
            None,
            BackendStatsRequest::ENABLED,
        )
        .await?;
        let stats = stats.expect("enabled LiteInst run must return statistics");
        match wait {
            ChildWait::Status(status) => Ok((status.into(), global, stats)),
            ChildWait::Output(_) => unreachable!("status run returned captured output"),
        }
    }

    /// Runs a tool and captures the guest's stdout and stderr.
    pub async fn run_with_output_and_preload<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
    ) -> Result<(Output, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        command.stdout(reverie::process::Stdio::piped());
        command.stderr(reverie::process::Stdio::piped());
        let (wait, global, stats) = launch::<T>(
            command,
            config,
            preload.into(),
            true,
            None,
            BackendStatsRequest::DISABLED,
        )
        .await?;
        debug_assert!(stats.is_none());
        match wait {
            ChildWait::Output(output) => Ok((output, global)),
            ChildWait::Status(_) => unreachable!("output run returned only a status"),
        }
    }

    /// Runs an in-guest Tool with captured output and per-process statistics.
    pub async fn run_with_output_and_preload_and_stats<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
    ) -> Result<
        (
            Output,
            T::GlobalState,
            crate::stats::LiteinstBackendStatsSource,
        ),
        Error,
    >
    where
        T: Tool + 'static,
    {
        command.stdout(reverie::process::Stdio::piped());
        command.stderr(reverie::process::Stdio::piped());
        let (wait, global, stats) = launch::<T>(
            command,
            config,
            preload.into(),
            true,
            None,
            BackendStatsRequest::ENABLED,
        )
        .await?;
        let stats = stats.expect("enabled LiteInst run must return statistics");
        match wait {
            ChildWait::Output(output) => Ok((output, global, stats)),
            ChildWait::Status(_) => unreachable!("output run returned only a status"),
        }
    }

    // TODO-HUMAN-REVIEW(PR-139): Review the public tool-specific bootstrap API.
    /// Runs a tool with captured output and opaque constructor bootstrap bytes.
    pub async fn run_with_output_and_preload_data<T>(
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
        let (wait, global, stats) = launch::<T>(
            command,
            config,
            preload.into(),
            true,
            Some(tool_data.into()),
            BackendStatsRequest::DISABLED,
        )
        .await?;
        debug_assert!(stats.is_none());
        match wait {
            ChildWait::Output(output) => Ok((output, global)),
            ChildWait::Status(_) => unreachable!("output run returned only a status"),
        }
    }

    // TODO-HUMAN-REVIEW(PR-152): Review inherited-stdio tool bootstrap support.
    /// Runs a tool with inherited guest stdio and opaque constructor bootstrap bytes.
    ///
    /// The returned [`Output`] contains the guest status and empty byte buffers.
    /// This is useful for tools that share the launcher's output sink and must
    /// preserve ordering between intercepted and pass-through guest writes.
    pub async fn run_with_inherited_stdio_and_preload_data<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
        tool_data: impl Into<Vec<u8>>,
    ) -> Result<(Output, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        inherit_stdio(&mut command);
        let (wait, global, stats) = launch::<T>(
            command,
            config,
            preload.into(),
            true,
            Some(tool_data.into()),
            BackendStatsRequest::DISABLED,
        )
        .await?;
        debug_assert!(stats.is_none());
        match wait {
            ChildWait::Output(output) => {
                debug_assert!(output.stdout.is_empty());
                debug_assert!(output.stderr.is_empty());
                Ok((output, global))
            }
            ChildWait::Status(_) => unreachable!("output run returned only a status"),
        }
    }

    /// Runs a tool with captured output and opaque constructor bootstrap bytes,
    /// and aggregates one typed statistics snapshot per process.
    ///
    /// Only the Tool coordinator travels in the bootstrap. The statistics
    /// coordinator is still named by [`STATS_COORDINATOR_ENV`]; Tool
    /// installation removes it from the environment, but the kernel's copy in
    /// `/proc/self/environ` keeps it.
    pub async fn run_with_output_and_preload_data_and_stats<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
        tool_data: impl Into<Vec<u8>>,
    ) -> Result<
        (
            Output,
            T::GlobalState,
            crate::stats::LiteinstBackendStatsSource,
        ),
        Error,
    >
    where
        T: Tool + 'static,
    {
        command.stdout(reverie::process::Stdio::piped());
        command.stderr(reverie::process::Stdio::piped());
        let (wait, global, stats) = launch::<T>(
            command,
            config,
            preload.into(),
            true,
            Some(tool_data.into()),
            BackendStatsRequest::ENABLED,
        )
        .await?;
        let stats = stats.expect("enabled LiteInst run must return statistics");
        match wait {
            ChildWait::Output(output) => Ok((output, global, stats)),
            ChildWait::Status(_) => unreachable!("output run returned only a status"),
        }
    }

    /// Runs a tool with inherited guest stdio and opaque constructor bootstrap
    /// bytes, and aggregates one typed statistics snapshot per process.
    ///
    /// As with [`Self::run_with_inherited_stdio_and_preload_data`], the
    /// returned [`Output`] contains the guest status and empty byte buffers.
    pub async fn run_with_inherited_stdio_and_preload_data_and_stats<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
        tool_data: impl Into<Vec<u8>>,
    ) -> Result<
        (
            Output,
            T::GlobalState,
            crate::stats::LiteinstBackendStatsSource,
        ),
        Error,
    >
    where
        T: Tool + 'static,
    {
        inherit_stdio(&mut command);
        let (wait, global, stats) = launch::<T>(
            command,
            config,
            preload.into(),
            true,
            Some(tool_data.into()),
            BackendStatsRequest::ENABLED,
        )
        .await?;
        let stats = stats.expect("enabled LiteInst run must return statistics");
        match wait {
            ChildWait::Output(output) => {
                debug_assert!(output.stdout.is_empty());
                debug_assert!(output.stderr.is_empty());
                Ok((output, global, stats))
            }
            ChildWait::Status(_) => unreachable!("output run returned only a status"),
        }
    }

    /// Runs a tool with opaque constructor bootstrap bytes and returns only the
    /// guest's exit status.
    ///
    /// Unlike [`Self::run_with_inherited_stdio_and_preload_data`], this leaves
    /// the command's stdio configuration exactly as the caller set it.
    pub async fn run_with_preload_data<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
        tool_data: impl Into<Vec<u8>>,
    ) -> Result<(ExitStatus, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        let (wait, global, stats) = launch::<T>(
            command,
            config,
            preload.into(),
            false,
            Some(tool_data.into()),
            BackendStatsRequest::DISABLED,
        )
        .await?;
        debug_assert!(stats.is_none());
        match wait {
            ChildWait::Status(status) => Ok((status.into(), global)),
            ChildWait::Output(_) => unreachable!("status run returned captured output"),
        }
    }

    /// Runs a tool with opaque constructor bootstrap bytes, returns the guest's
    /// exit status, and aggregates one typed statistics snapshot per process.
    ///
    /// The statistics coordinator is named in the environment exactly as for
    /// [`Self::run_with_output_and_preload_data_and_stats`].
    pub async fn run_with_preload_data_and_stats<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
        tool_data: impl Into<Vec<u8>>,
    ) -> Result<
        (
            ExitStatus,
            T::GlobalState,
            crate::stats::LiteinstBackendStatsSource,
        ),
        Error,
    >
    where
        T: Tool + 'static,
    {
        let (wait, global, stats) = launch::<T>(
            command,
            config,
            preload.into(),
            false,
            Some(tool_data.into()),
            BackendStatsRequest::ENABLED,
        )
        .await?;
        let stats = stats.expect("enabled LiteInst run must return statistics");
        match wait {
            ChildWait::Status(status) => Ok((status.into(), global, stats)),
            ChildWait::Output(_) => unreachable!("status run returned captured output"),
        }
    }
}

fn effective_command_env(command: &Command, key: &OsStr) -> Option<OsString> {
    command.get_captured_envs().remove(key)
}

/// The command's [`SITE_PATCHING_ENV`] selection: `1` on, `0` off, unset
/// none. Any other value is refused here, as the runtime would refuse it.
fn command_site_patching(command: &Command) -> io::Result<Option<bool>> {
    match effective_command_env(command, OsStr::new(SITE_PATCHING_ENV)) {
        None => Ok(None),
        Some(value) if value == OsStr::new("1") => Ok(Some(true)),
        Some(value) if value == OsStr::new("0") => Ok(Some(false)),
        Some(value) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported {SITE_PATCHING_ENV} value {value:?}"),
        )),
    }
}

fn configure_in_guest_command_preload(command: &mut Command, preload: PathBuf) {
    let mut ld_preload = preload.into_os_string();
    if let Some(existing) =
        effective_command_env(command, OsStr::new("LD_PRELOAD")).filter(|value| !value.is_empty())
    {
        ld_preload.push(OsStr::new(":"));
        ld_preload.push(existing);
    }
    command.env("LD_PRELOAD", ld_preload);
}

/// Disables address-space randomization for the guest, as Reverie's ptrace and
/// DBT launchers do. Randomized stack, heap and mapping addresses differ from
/// run to run, and a guest observes them, so two runs of the same program would
/// diverge. `personality(2)` is async-signal-safe and survives `execve`.
fn disable_address_space_randomization(command: &mut std::process::Command) {
    // SAFETY: the closure makes only async-signal-safe `personality` calls.
    unsafe {
        command.pre_exec(|| {
            let current = libc::personality(0xffff_ffff);
            if current == -1 {
                return Err(io::Error::last_os_error());
            }
            let deterministic = current as libc::c_ulong | libc::ADDR_NO_RANDOMIZE as libc::c_ulong;
            if libc::personality(deterministic) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn inherit_stdio(command: &mut Command) {
    command.stdin(reverie::process::Stdio::inherit());
    command.stdout(reverie::process::Stdio::inherit());
    command.stderr(reverie::process::Stdio::inherit());
}

#[reverie::backend(?Send)]
impl Backend for PreloadBackend {
    type Stats = crate::stats::LiteinstBackendStatsSnapshot;

    /// The capabilities of the in-guest runtime that [`Backend::run`] starts.
    fn capabilities() -> BackendCapabilities {
        BackendCapabilities::LITEINST_IN_GUEST
    }

    async fn run<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(ExitStatus, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        let preload = tool_preload_path()?;
        Self::run_with_preload::<T>(command, config, preload).await
    }

    async fn run_with_stats<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(ExitStatus, T::GlobalState, Self::Stats), Error>
    where
        T: Tool + 'static,
    {
        let preload = tool_preload_path()?;
        let (status, global, stats) =
            Self::run_with_preload_and_stats::<T>(command, config, preload).await?;
        Ok((status, global, stats.backend_stats()))
    }

    async fn run_with_output<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(ReverieOutput, T::GlobalState, Self::Stats), Error>
    where
        T: Tool + 'static,
    {
        // The preload path is resolved here rather than taken as a parameter:
        // it is a LiteInst mechanism, not part of the backend-agnostic
        // contract. See the `Backend` trait docs, "Why `preload` is
        // deliberately not on this trait".
        let preload = tool_preload_path()?;
        let (output, global, stats) =
            Self::run_with_output_and_preload_and_stats::<T>(command, config, preload).await?;
        // This family of LiteInst entry points predates the trait and reports
        // `std::process::Output`; the trait speaks Reverie's own `Output` so
        // that the captured status is the same `reverie::ExitStatus` that
        // `run` and `run_with_stats` return. Preserve the wait status's core
        // dump bit rather than using the older infallible conversion, which
        // cannot distinguish signal termination with and without a core dump.
        let output = ReverieOutput {
            status: ExitStatus::from_raw(output.status.into_raw()),
            stdout: output.stdout,
            stderr: output.stderr,
        };
        Ok((output, global, stats.backend_stats()))
    }
}

/// Typed opt-out from the static-executable refusal, for the future
/// exec-stop activation path (which arms static guests itself).
/// Builder-scoped like connection admission; never an env var.
#[derive(Clone, Copy)]
pub struct AllowStaticExecutables;

tokio::task_local! {
    static STATIC_OPTOUT: AllowStaticExecutables;
}

/// Open `path` for header inspection, or `None` when it is not a regular
/// file. A FIFO, terminal, or device named on the command line belongs to
/// the guest: opening a FIFO blocks until a writer appears, reading a pipe
/// or terminal consumes the guest's input, and opening a device can have
/// side effects. Such a path is never opened. The open is non-blocking and
/// acquires no controlling terminal, and the opened file is checked again
/// in case the path was replaced after the first check.
fn open_regular(path: &Path) -> io::Result<Option<std::fs::File>> {
    use std::os::unix::fs::OpenOptionsExt;
    if !std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file()) {
        return Ok(None);
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Ok(None);
    }
    Ok(Some(file))
}

/// Read up to `buf.len()` bytes from the start of `file`; returns the count.
fn read_prefix(file: &mut std::fs::File, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match file.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

/// Fixed-width native-endian reads at absolute offsets of an ELF file.
fn read_at<const N: usize>(file: &mut std::fs::File, offset: u64) -> io::Result<[u8; N]> {
    use std::io::Seek;
    use std::io::SeekFrom;
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = [0u8; N];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_u16(file: &mut std::fs::File, offset: u64) -> io::Result<u16> {
    read_at(file, offset).map(u16::from_ne_bytes)
}

fn read_u32(file: &mut std::fs::File, offset: u64) -> io::Result<u32> {
    read_at(file, offset).map(u32::from_ne_bytes)
}

fn read_u64(file: &mut std::fs::File, offset: u64) -> io::Result<u64> {
    read_at(file, offset).map(u64::from_ne_bytes)
}

/// An opened ELF with its class and program-header table location.
struct ElfProgramHeaders {
    file: std::fs::File,
    class: u8,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
}

/// An ELF's class and program-header table location (`e_phoff`,
/// `e_phentsize`, `e_phnum`), or `None` for a file that is not an ELF:
/// missing, not a regular file, shorter than the ident, or without ELF
/// magic (a script). An unknown class is an error, not `None`: the
/// kernel's ELF loader never reads `EI_CLASS` (`load_elf_binary` in
/// fs/binfmt_elf.c checks the magic, `e_type` and `e_machine`), so such a
/// file can run, and one whose headers cannot be read must not run
/// unconfined.
fn elf_program_headers(path: &Path) -> io::Result<Option<ElfProgramHeaders>> {
    let Some(mut file) = open_regular(path)? else {
        return Ok(None);
    };
    let mut ident = [0u8; 20];
    if read_prefix(&mut file, &mut ident)? < ident.len() || &ident[0..4] != b"\x7fELF" {
        return Ok(None);
    }
    let class = ident[4];
    let (phoff, phentsize, phnum) = match class {
        2 => (
            read_u64(&mut file, 32)?,
            read_u16(&mut file, 54)?,
            read_u16(&mut file, 56)?,
        ),
        1 => (
            read_u32(&mut file, 28).map(u64::from)?,
            read_u16(&mut file, 42)?,
            read_u16(&mut file, 44)?,
        ),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown ELF class {class} (EI_CLASS)"),
            ));
        }
    };
    Ok(Some(ElfProgramHeaders {
        file,
        class,
        phoff,
        phentsize,
        phnum,
    }))
}

const PT_INTERP: u32 = 3;

/// Read the target ELF's program headers; true when PT_INTERP is
/// absent (static executable). A file that is not an ELF (see
/// [`elf_program_headers`]) is not a static ELF; a script's interpreter
/// is checked by [`refuse_static_target`]. Read/parse failures AFTER a
/// full ELF ident are errors: an uninspectable ELF must not run
/// unconfined either.
fn target_is_static(program: &Path) -> io::Result<bool> {
    let Some(ElfProgramHeaders {
        mut file,
        phoff,
        phentsize,
        phnum,
        ..
    }) = elf_program_headers(program)?
    else {
        return Ok(false);
    };
    if phoff == 0 || phnum == 0 || phentsize < 4 {
        return Ok(true);
    }
    for index in 0..u64::from(phnum) {
        if read_u32(&mut file, phoff + index * u64::from(phentsize))? == PT_INTERP {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Read an ELF's PT_INTERP string, if any.
fn elf_interp(path: &Path) -> io::Result<Option<String>> {
    let Some(ElfProgramHeaders {
        mut file,
        class,
        phoff,
        phentsize,
        phnum,
    }) = elf_program_headers(path)?
    else {
        return Ok(None);
    };
    for index in 0..u64::from(phnum) {
        let base = phoff + index * u64::from(phentsize);
        if read_u32(&mut file, base)? != PT_INTERP {
            continue;
        }
        let (offset, filesz) = match class {
            2 => (
                read_u64(&mut file, base + 8)?,
                read_u64(&mut file, base + 32)?,
            ),
            _ => (
                read_u32(&mut file, base + 4).map(u64::from)?,
                read_u32(&mut file, base + 16).map(u64::from)?,
            ),
        };
        if filesz == 0 || filesz > 4096 {
            return Ok(None);
        }
        use std::io::Seek;
        use std::io::SeekFrom;
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0u8; filesz as usize];
        file.read_exact(&mut bytes)?;
        if bytes.last() == Some(&0) {
            bytes.pop();
        }
        return Ok(Some(String::from_utf8_lossy(&bytes).into_owned()));
    }
    Ok(None)
}

/// `path`, resolved the way the guest's exec resolves it: a relative
/// path is relative to the command's working directory.
fn resolve_in(current_dir: Option<&Path>, path: &Path) -> PathBuf {
    match current_dir {
        Some(directory) if path.is_relative() => directory.join(path),
        _ => path.to_path_buf(),
    }
}

/// The interpreter a `#!` script names, parsed as the kernel's
/// `load_script` (fs/binfmt_script.c) parses the first `BINPRM_BUF_SIZE`
/// (256) bytes: after `#!`, skip spaces and tabs; the name ends at a
/// space, tab, NUL, or the end of the first line. `None` when the file is
/// not a script, or when the kernel would refuse it (`ENOEXEC`: no name,
/// or a name that may be truncated because the buffer holds no newline
/// and no terminator after it).
fn shebang_interpreter(path: &Path, current_dir: Option<&Path>) -> io::Result<Option<PathBuf>> {
    use std::os::unix::ffi::OsStrExt;
    let Some(mut file) = open_regular(path)? else {
        return Ok(None);
    };
    // Zero-filled: the kernel's buffer is NUL-padded past the end of a
    // short file.
    let mut buf = [0u8; 256];
    let len = read_prefix(&mut file, &mut buf)?;
    if len < 2 || &buf[..2] != b"#!" {
        return Ok(None);
    }
    let spacetab = |byte: u8| byte == b' ' || byte == b'\t';
    let terminator = |byte: u8| spacetab(byte) || byte == 0;
    // The kernel's newline search (`strnchr`) stops at the first NUL;
    // without a newline its terminator search runs through the last
    // byte of the buffer (`next_terminator` up to `buf_end` inclusive).
    let newline = buf
        .iter()
        .take_while(|&&byte| byte != 0)
        .position(|&byte| byte == b'\n');
    let line = match newline {
        Some(newline) => &buf[2..newline],
        None => &buf[2..],
    };
    let Some(start) = line.iter().position(|&byte| !spacetab(byte)) else {
        return Ok(None);
    };
    let name = &line[start..];
    let end = name.iter().position(|&byte| terminator(byte));
    let name = match end {
        Some(end) => &name[..end],
        // Without a newline, a name running to the end of the buffer
        // may be truncated; the kernel refuses rather than guess.
        None if newline.is_none() => return Ok(None),
        None => name,
    };
    if name.is_empty() {
        return Ok(None);
    }
    Ok(Some(resolve_in(
        current_dir,
        Path::new(std::ffi::OsStr::from_bytes(name)),
    )))
}

/// Precise linker recognition (musereview bar): `program` counts as
/// a dynamic linker ONLY when its target argument's own PT_INTERP
/// names it (string-equal or canonical-equal). A bare ET_DYN
/// exemption would admit static-pie guests, so there is none.
/// Returns the target to check instead, when recognized.
fn linker_target(
    program: &Path,
    args: &[std::ffi::OsString],
    current_dir: Option<&Path>,
) -> Option<PathBuf> {
    // The executable glibc's loader runs is the first argument that
    // does not start with `--`, after its options, which it parses
    // exactly as below (`ld.so --help`, glibc 2.34): only these
    // spellings, each value as the next argument, no `--opt=value`
    // form, and `--` is not an end-of-options marker. ld.so rejects
    // any other `--` argument, so an unrecognised one gives no target
    // and `program` itself, which has no PT_INTERP, is refused.
    const VALUE_OPTIONS: &[&str] = &[
        "--argv0",
        "--audit",
        "--glibc-hwcaps-mask",
        "--glibc-hwcaps-prepend",
        "--inhibit-rpath",
        "--library-path",
        "--preload",
    ];
    const FLAG_OPTIONS: &[&str] = &[
        "--help",
        "--inhibit-cache",
        "--list",
        "--list-diagnostics",
        "--list-tunables",
        "--verify",
        "--version",
    ];
    let mut tokens = args.iter();
    let target = loop {
        let token = tokens.next()?;
        let text = token.to_string_lossy();
        if !text.starts_with("--") {
            break token;
        }
        if VALUE_OPTIONS.contains(&text.as_ref()) {
            tokens.next()?;
        } else if !FLAG_OPTIONS.contains(&text.as_ref()) {
            return None;
        }
    };
    // glibc's loader looks a target name without a slash up as a
    // library (cache and library path), never in the working directory,
    // so no file here is the one it runs: no recognised target.
    if !target.as_encoded_bytes().contains(&b'/') {
        return None;
    }
    let target = resolve_in(current_dir, Path::new(target));
    let interp = elf_interp(&target).ok()??;
    let interp_path = Path::new(&interp);
    let names_program = interp_path == program
        || matches!(
            (interp_path.canonicalize(), program.canonicalize()),
            (Ok(a), Ok(b)) if a == b
        );
    names_program.then_some(target)
}

/// Bound on the `#!` chain followed. The kernel itself stops earlier
/// (`exec_binprm` in fs/exec.c fails with `ELOOP` after six binary
/// handler passes), so a longer chain never runs at all.
const MAX_SCRIPT_DEPTH: usize = 8;

/// Refuse static targets before spawn unless the typed opt-out is in
/// scope. A static guest has no interpreter to load the preload
/// runtime, so launching it would run it unconfined.
///
/// Only files the exec itself would load are inspected: `program`, the
/// `#!` interpreters it names, and, when `program` has no PT_INTERP and
/// may be the dynamic linker run as a program, the linker's target
/// argument. Arguments of an ordinary dynamic program are never opened.
fn refuse_static_target(
    program: &Path,
    args: &[std::ffi::OsString],
    current_dir: Option<&Path>,
) -> io::Result<()> {
    if STATIC_OPTOUT.try_with(|_| ()).is_ok() {
        return Ok(());
    }
    let refusal = |path: &Path| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "{}: static executables are not supported by the in-guest backend (no PT_INTERP)",
                path.display()
            ),
        )
    };
    let inspect = |path: &Path| {
        target_is_static(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot inspect {} for PT_INTERP: {error}", path.display()),
            )
        })
    };
    if inspect(program)? {
        // Linker-as-program: when the target argument's PT_INTERP
        // names `program`, `program` is the dynamic linker itself and
        // the target is the guest that will actually run (with the
        // preload loaded by that linker), so check the target instead.
        // A no-PT_INTERP program with no such target -- a static or
        // static-pie guest, or a linker invoked alone -- is refused.
        return match linker_target(program, args, current_dir) {
            Some(target) if !inspect(&target)? => Ok(()),
            Some(target) => Err(refusal(&target)),
            None => Err(refusal(program)),
        };
    }
    // A script runs its `#!` interpreter, which needs the same check.
    // A static interpreter is refused even when it is the dynamic
    // linker: the kernel passes it the script, not an ELF to load.
    let mut script = program.to_path_buf();
    for _ in 0..MAX_SCRIPT_DEPTH {
        let Some(interpreter) = shebang_interpreter(&script, current_dir)? else {
            return Ok(());
        };
        if inspect(&interpreter)? {
            return Err(refusal(&interpreter));
        }
        script = interpreter;
    }
    Ok(())
}

enum ChildWait {
    Status(std::process::ExitStatus),
    Output(Output),
}

/// Bytes of captured guest stderr a pre-connect error carries.
const PRE_CONNECT_STDERR_LIMIT: usize = 2048;

/// The error for a guest that exited before connecting: the exit status
/// always, plus the tail of captured stderr when the launch captured
/// output, so a pre-connect refusal keeps its own diagnostic.
fn pre_connect_error(wait: &ChildWait) -> io::Error {
    let (status, stderr) = match wait {
        ChildWait::Status(status) => (*status, None),
        ChildWait::Output(output) => (output.status, Some(output.stderr.as_slice())),
    };
    let mut message = format!(
        "LiteInst guest exited before connecting to the coordinator; \
         static executables and loader failures are unsupported; guest {status}"
    );
    if let Some(stderr) = stderr
        && !stderr.is_empty()
    {
        let truncated = stderr.len() > PRE_CONNECT_STDERR_LIMIT;
        let tail = if truncated {
            &stderr[stderr.len() - PRE_CONNECT_STDERR_LIMIT..]
        } else {
            stderr
        };
        let excerpt = String::from_utf8_lossy(tail);
        if truncated {
            message.push_str(&format!(
                "; guest stderr (last {PRE_CONNECT_STDERR_LIMIT} of {} bytes): {excerpt}",
                stderr.len()
            ));
        } else {
            message.push_str(&format!("; guest stderr: {excerpt}"));
        }
    }
    io::Error::new(io::ErrorKind::ConnectionAborted, message)
}

async fn serve_rpc_until<G, F, T, B>(
    server: RpcServer<G>,
    stats_server: Option<RpcServer<crate::stats::LiteinstStatsGlobal>>,
    connection_monitors: Vec<ConnectionMonitor>,
    completion: F,
    failure: B,
) -> io::Result<T>
where
    G: GlobalTool + 'static,
    F: Future<Output = io::Result<T>>,
    B: Future<Output = ()>,
{
    serve_rpc_until_with_timeout(
        server,
        stats_server,
        connection_monitors,
        completion,
        failure,
        RPC_CONNECTION_DRAIN_TIMEOUT,
    )
    .await
}

async fn serve_rpc_until_with_timeout<G, F, T, B>(
    server: RpcServer<G>,
    stats_server: Option<RpcServer<crate::stats::LiteinstStatsGlobal>>,
    connection_monitors: Vec<ConnectionMonitor>,
    completion: F,
    failure: B,
    drain_timeout: Duration,
) -> io::Result<T>
where
    G: GlobalTool + 'static,
    F: Future<Output = io::Result<T>>,
    B: Future<Output = ()>,
{
    // JoinSet aborts the server if this future is cancelled. RpcServer::serve
    // owns the per-connection JoinSet, so aborting it also releases every
    // outstanding connection and its GlobalTool Arc.
    let mut serving = tokio::task::JoinSet::new();
    let mut shutdown = Vec::new();
    let (send, receive) = tokio::sync::oneshot::channel();
    shutdown.push(send);
    serving.spawn(server.serve_until(async {
        let _ = receive.await;
    }));
    if let Some(stats_server) = stats_server {
        let (send, receive) = tokio::sync::oneshot::channel();
        shutdown.push(send);
        serving.spawn(stats_server.serve_until(async {
            let _ = receive.await;
        }));
    }

    serve_rpc_tasks_until_with_timeout_and_shutdown(
        serving,
        connection_monitors,
        completion,
        failure,
        drain_timeout,
        shutdown,
    )
    .await
}

/// The error a launch returns when the coordinator's tool reported a backend
/// failure (`GlobalTool::report_backend_failure`).
fn backend_failure_error() -> io::Error {
    io::Error::other(
        "the coordinator's tool reported a backend failure; the run cannot continue faithfully",
    )
}

fn rpc_server_stopped(
    result: Option<Result<Result<(), RpcError>, tokio::task::JoinError>>,
) -> io::Error {
    let message = match result {
        Some(Ok(Ok(()))) => "LiteInst coordinator stopped unexpectedly".to_owned(),
        Some(Ok(Err(error))) => error.to_string(),
        Some(Err(error)) => error.to_string(),
        None => "LiteInst coordinator task disappeared".to_owned(),
    };
    io::Error::other(message)
}

/// Serves the coordinator until `completion` (the root guest's wait) and the
/// drain of every connection, or until `failure` completes: the tool reported
/// a backend failure. A failure ends the run at once with an error, before or
/// during the drain, and wins over a completion that is ready at the same time.
/// Returning drops the servers and so every guest connection; the caller kills
/// any guest that remains.
#[cfg(test)]
async fn serve_rpc_tasks_until_with_timeout<F, T, B>(
    serving: tokio::task::JoinSet<Result<(), RpcError>>,
    connection_monitors: Vec<ConnectionMonitor>,
    completion: F,
    failure: B,
    drain_timeout: Duration,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
    B: Future<Output = ()>,
{
    serve_rpc_tasks_until_with_timeout_and_shutdown(
        serving,
        connection_monitors,
        completion,
        failure,
        drain_timeout,
        Vec::new(),
    )
    .await
}

async fn serve_rpc_tasks_until_with_timeout_and_shutdown<F, T, B>(
    mut serving: tokio::task::JoinSet<Result<(), RpcError>>,
    connection_monitors: Vec<ConnectionMonitor>,
    completion: F,
    failure: B,
    drain_timeout: Duration,
    shutdown: Vec<tokio::sync::oneshot::Sender<()>>,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
    B: Future<Output = ()>,
{
    tokio::pin!(completion);
    tokio::pin!(failure);
    let mut failed = false;
    let mut drain_required = false;
    let mut result = tokio::select! {
        biased;
        () = &mut failure => { failed = true; Err(backend_failure_error()) },
        result = &mut completion => { drain_required = true; result },
        stopped = serving.join_next() => Err(rpc_server_stopped(stopped)),
    };
    if drain_required {
        // Existing last-close rule and finite bound are unchanged. Every arm
        // now reaches the same joined teardown, retaining the original error.
        let drain = async {
            for monitor in &connection_monitors {
                monitor.wait_for_idle().await;
            }
        };
        tokio::pin!(drain);
        let drain_error = tokio::select! {
            biased;
            () = &mut failure => { failed = true; None },
            stopped = serving.join_next() => Some(rpc_server_stopped(stopped)),
            outcome = tokio::time::timeout(drain_timeout, &mut drain) => {
                outcome.err().map(|_| {
                    let active = connection_monitors.iter().map(ConnectionMonitor::active_connections).sum::<usize>();
                    io::Error::new(io::ErrorKind::TimedOut, format!(
                        "LiteInst coordinator retained {active} active RPC connection(s) for {}ms after guest exit", drain_timeout.as_millis()
                    ))
                })
            },
        };
        if !failed {
            failed = std::future::poll_fn(|context| {
                std::task::Poll::Ready(failure.as_mut().poll(context).is_ready())
            })
            .await;
        }
        if result.is_ok() {
            if failed {
                result = Err(backend_failure_error());
            } else if let Some(error) = drain_error {
                result = Err(error);
            }
        } else if failed {
            tracing::warn!("a backend failure was reported; preserving guest completion error");
        } else if let Some(error) = drain_error {
            tracing::warn!("{error}; preserving guest completion error");
        }
    }
    let cooperative = !shutdown.is_empty();
    if cooperative {
        for sender in shutdown {
            let _ = sender.send(());
        }
    } else {
        // Task-only fixtures retain the same cancellation route; actual
        // servers use serve_until, which joins its own connection tasks.
        serving.abort_all();
    }
    while let Some(stopped) = serving.join_next().await {
        let error = match stopped {
            Err(error) if error.is_cancelled() => None,
            Ok(Ok(())) if cooperative => None,
            stopped => Some(rpc_server_stopped(Some(stopped))),
        };
        if result.is_ok()
            && !failed
            && let Some(error) = error
        {
            result = Err(error);
        }
    }
    // Even the task-only cancellation route must wait for nested connection
    // destruction; returning while it still owns a GlobalState Arc is unsafe
    // for force_exit/cancel/cleanup. A missing last-close is a terminal error.
    let joined = tokio::time::timeout(drain_timeout, async {
        for monitor in &connection_monitors {
            monitor.wait_for_idle().await;
        }
    })
    .await;
    if joined.is_err() && result.is_ok() {
        result = Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "RPC cancellation did not release every connection",
        ));
    }
    result
}

/// The launcher-side [`ExitReporter`]: forwards to the coordinator's global
/// tool. Weak, so an admission keeping it never keeps the global alive past the
/// run (launch reclaims it by value); after the run each call does nothing.
struct GlobalExitReporter<G>(std::sync::Weak<G>);

impl<G: GlobalTool> ExitReporter for GlobalExitReporter<G> {
    fn process_exited(&self, pid: i32) {
        if let Some(global) = self.0.upgrade() {
            global.on_backend_process_exited(pid);
        }
    }

    fn pending_process_exits(&self) -> Vec<i32> {
        self.0
            .upgrade()
            .map(|global| global.backend_pending_process_exits())
            .unwrap_or_default()
    }

    fn backend_failed(&self, failure: reverie::BackendFailure) {
        if let Some(global) = self.0.upgrade() {
            global.report_backend_failure(failure);
        }
    }
}

async fn unwrap_global_after_connections<G>(mut global: Arc<G>) -> io::Result<G> {
    // Aborting RpcServer::serve drops its JoinSet, which aborts every connection
    // task. Those tasks release their GlobalTool Arc on their next scheduler
    // turn, so a fast guest can otherwise race Arc::try_unwrap here.
    for _ in 0..1024 {
        match Arc::try_unwrap(global) {
            Ok(global) => return Ok(global),
            Err(still_shared) => global = still_shared,
        }
        tokio::task::yield_now().await;
    }
    Err(io::Error::other(
        "LiteInst coordinator state still has owners after connection shutdown",
    ))
}

async fn launch<T>(
    mut command: Command,
    config: <T::GlobalState as GlobalTool>::Config,
    preload: PathBuf,
    capture_output: bool,
    tool_data: Option<Vec<u8>>,
    stats_request: BackendStatsRequest,
) -> Result<
    (
        ChildWait,
        T::GlobalState,
        Option<crate::stats::LiteinstBackendStatsSource>,
    ),
    Error,
>
where
    T: Tool + 'static,
{
    T::facility_admission(&config)?;
    if !preload.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("tool preload {} is not a file", preload.display()),
        )
        .into());
    }

    let preload = preload.canonicalize()?;
    let arg0 = command.get_arg0().to_owned();
    let program = command.find_program()?;
    let guest_args: Vec<std::ffi::OsString> =
        command.get_args().map(|arg| arg.to_os_string()).collect();
    refuse_static_target(&program, &guest_args, command.get_current_dir())?;
    command.program(program).arg0(arg0);

    let directory = tempfile::Builder::new()
        .prefix("reverie-liteinst-")
        .tempdir_in("/tmp")?;
    let socket = directory.path().join("coordinator.sock");
    let global = Arc::new(T::GlobalState::init_global_state(&config).await);
    let connected = Arc::new(AtomicBool::new(false));
    let mut server = RpcServer::bind_with_connection_readiness(
        &socket,
        global.clone(),
        config,
        connected.clone(),
    )
    .map_err(|error| io::Error::other(error.to_string()))?;
    if let Ok(admission) = CONNECTION_ADMISSION.try_with(Arc::clone) {
        // Weak, so the admission's reporter never keeps the coordinator's
        // global state alive past the run (launch reclaims it by value); a
        // report arriving after the run finds no global and is dropped.
        admission.attach_exit_reporter(Arc::new(GlobalExitReporter(Arc::downgrade(&global))));
        server
            .set_connection_admission(admission)
            .map_err(|error| io::Error::other(error.to_string()))?;
    }
    #[cfg(feature = "rpc-io-fixture")]
    let _ = RPC_ISSUES_FOR_TEST.try_with(|captures| {
        let issues = server.retain_connection_issues();
        captures.lock().unwrap().push(RpcLaunchIssueCaptureForTest {
            connections: server.connection_monitor(),
            issues,
        });
    });
    let mut connection_monitors = vec![server.connection_monitor()];
    let (stats_global, stats_server, stats_socket) = if stats_request.is_enabled() {
        let socket = directory.path().join("stats.sock");
        let global = Arc::new(crate::stats::LiteinstStatsGlobal::default());
        let server = RpcServer::bind(&socket, global.clone(), ())
            .map_err(|error| io::Error::other(error.to_string()))?;
        connection_monitors.push(server.connection_monitor());
        (Some(global), Some(server), Some(socket))
    } else {
        (None, None, None)
    };

    configure_in_guest_command_preload(&mut command, preload);

    let wait = match tool_data {
        Some(tool_data) => {
            // The site-patching selection the caller set on the command goes
            // in the bootstrap: the runtime honors it, and the guest neither
            // sees it in its environment nor can change it there.
            let site_patching = command_site_patching(&command)?;
            let mut child_command = command.try_into_std()?;
            disable_address_space_randomization(&mut child_command);
            // The statistics coordinator travels in the bootstrap with the
            // Tool coordinator, not in the guest's environment.
            child_command.env_remove(STATS_COORDINATOR_ENV);
            child_command.env_remove(SITE_PATCHING_ENV);

            let bootstrap = create_preload_bootstrap(
                &socket,
                stats_socket.as_deref(),
                site_patching,
                &tool_data,
            )?;
            let bootstrap_fd = bootstrap.as_raw_fd();
            unsafe {
                child_command.pre_exec(move || {
                    if libc::fcntl(bootstrap_fd, libc::F_SETFD, 0) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = child_command.spawn()?;
            drop(bootstrap);
            let wait = tokio::task::spawn_blocking(move || {
                if capture_output {
                    child.wait_with_output().map(ChildWait::Output)
                } else {
                    child.wait().map(ChildWait::Status)
                }
            });
            serve_rpc_until(
                server,
                stats_server,
                connection_monitors,
                async move {
                    wait.await
                        .map_err(|error| io::Error::other(error.to_string()))?
                },
                backend_failure(&global),
            )
            .await?
        }
        None => {
            let mut child_command = command.try_into_std()?;
            disable_address_space_randomization(&mut child_command);
            child_command.env(COORDINATOR_ENV, &socket);
            child_command.env_remove(STATS_COORDINATOR_ENV);
            if let Some(stats_socket) = &stats_socket {
                child_command.env(STATS_COORDINATOR_ENV, stats_socket);
            }
            let mut child = child_command.spawn()?;
            let wait = tokio::task::spawn_blocking(move || {
                if capture_output {
                    child.wait_with_output().map(ChildWait::Output)
                } else {
                    child.wait().map(ChildWait::Status)
                }
            });
            serve_rpc_until(
                server,
                stats_server,
                connection_monitors,
                async move {
                    wait.await
                        .map_err(|error| io::Error::other(error.to_string()))?
                },
                backend_failure(&global),
            )
            .await?
        }
    };
    if !connected.load(Ordering::Acquire) {
        return Err(pre_connect_error(&wait).into());
    }
    let global = unwrap_global_after_connections(global).await?;
    let stats = match stats_global {
        Some(stats) => Some(unwrap_global_after_connections(stats).await?.into_source()),
        None => None,
    };
    Ok((wait, global, stats))
}

/// Completes when the coordinator's tool reports a backend failure. It holds
/// the global state only until the serve loop that polls it returns, so the
/// launch can still reclaim the state by value afterwards.
fn backend_failure<G: GlobalTool + 'static>(global: &Arc<G>) -> impl Future<Output = ()> + use<G> {
    let global = Arc::clone(global);
    async move { global.wait_for_backend_failure().await }
}

fn tool_preload_path() -> io::Result<PathBuf> {
    let path = std::env::var_os(TOOL_PRELOAD_ENV)
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

#[cfg(all(test, feature = "exec-private-init"))]
mod initial_stats_tests {
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicUsize;

    use reverie::Tid;
    use reverie_rpc_transport::Admitted;
    use reverie_rpc_transport::RpcClient;

    use super::*;

    #[derive(Default)]
    struct TestAdmission {
        calls: AtomicUsize,
        refuse: bool,
    }

    impl ConnectionAdmission for TestAdmission {
        fn admit(&self, _peer: OwnedFd) -> io::Result<Admitted> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.refuse {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "test refusal",
                ));
            }
            // A transport component fixture, not a same-birth authenticator.
            Ok(Admitted {
                process_id: std::process::id() as i32,
            })
        }
    }

    fn directory() -> tempfile::TempDir {
        let directory = tempfile::Builder::new()
            .prefix("reverie-initial-stats-")
            .tempdir_in("/tmp")
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    async fn stop_server(
        task: tokio::task::JoinHandle<Result<(), RpcError>>,
        issues: &RpcIssueMonitor,
    ) {
        issues.planned_shutdown();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn initial_stats_bind_rejects_wrong_parent_mode_symlink_and_existing_entry() {
        let owned = directory();
        let other = directory();
        let tool_rpc = owned.path().join("rpc.sock");
        let stats_rpc = owned.path().join("stats.sock");
        let admission = Arc::new(TestAdmission::default());
        assert!(InitialImageStatsServer::bind(&tool_rpc, other.path(), admission.clone()).is_err());
        assert!(!stats_rpc.exists());

        std::fs::set_permissions(owned.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(InitialImageStatsServer::bind(&tool_rpc, owned.path(), admission.clone()).is_err());
        std::fs::set_permissions(owned.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let alias = other.path().join("alias");
        std::os::unix::fs::symlink(owned.path(), &alias).unwrap();
        assert!(InitialImageStatsServer::bind(&tool_rpc, &alias, admission.clone()).is_err());
        assert!(!stats_rpc.exists());

        let bytes = b"owned existing entry\0\xff";
        std::fs::write(&stats_rpc, bytes).unwrap();
        let before = std::fs::symlink_metadata(&stats_rpc).unwrap();
        match InitialImageStatsServer::bind(&tool_rpc, owned.path(), admission) {
            Err(RpcError::Io(error)) => assert_eq!(error.raw_os_error(), Some(libc::EADDRINUSE)),
            Err(error) => panic!("unexpected occupied companion error: {error}"),
            Ok(_) => panic!("statistics wrapper replaced an existing entry"),
        }
        let after = std::fs::symlink_metadata(&stats_rpc).unwrap();
        assert_eq!(
            (after.dev(), after.ino(), after.mode()),
            (before.dev(), before.ino(), before.mode())
        );
        assert_eq!(std::fs::read(&stats_rpc).unwrap(), bytes);
    }

    #[tokio::test]
    async fn initial_stats_source_refuses_live_server_owners() {
        let directory = directory();
        let tool_rpc = directory.path().join("rpc.sock");
        let (server, collector) = InitialImageStatsServer::bind(
            &tool_rpc,
            directory.path(),
            Arc::new(TestAdmission::default()),
        )
        .unwrap();
        let error = match collector.into_source().await {
            Err(error) => error,
            Ok(_) => panic!("statistics source escaped a live server owner"),
        };
        assert!(error.to_string().contains("still has owners"));
        drop(server);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn initial_stats_connection_must_finish_before_clean_source_teardown() {
        let directory = directory();
        let tool_rpc = directory.path().join("rpc.sock");
        let endpoint = crate::initial_image_stats::initial_image_stats_endpoint(&tool_rpc).unwrap();
        let admission = Arc::new(TestAdmission::default());
        let (server, collector) =
            InitialImageStatsServer::bind(&tool_rpc, directory.path(), admission.clone()).unwrap();
        let connections = server.connection_monitor();
        let issues = server.issue_monitor();
        let task = tokio::spawn(server.serve());
        let client = RpcClient::<crate::stats::LiteinstStatsGlobal>::connect(
            &endpoint,
            Tid::from_raw(std::process::id() as i32),
        )
        .await
        .unwrap();
        assert_eq!(admission.calls.load(Ordering::Relaxed), 1);
        assert_eq!(connections.active_connections(), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), connections.wait_for_idle())
                .await
                .is_err()
        );
        assert_eq!(connections.active_connections(), 1);
        drop(client);
        tokio::time::timeout(Duration::from_secs(2), connections.wait_for_idle())
            .await
            .unwrap();
        assert!(issues.snapshot().is_empty());
        stop_server(task, &issues).await;
        assert_eq!(connections.active_connections(), 0);
        assert!(issues.snapshot().is_empty());
        assert_eq!(
            collector
                .into_source()
                .await
                .unwrap()
                .snapshot()
                .process_reports(),
            0
        );
    }

    #[tokio::test]
    async fn initial_stats_admission_failure_is_retained_through_teardown() {
        let directory = directory();
        let tool_rpc = directory.path().join("rpc.sock");
        let endpoint = crate::initial_image_stats::initial_image_stats_endpoint(&tool_rpc).unwrap();
        let admission = Arc::new(TestAdmission {
            refuse: true,
            ..Default::default()
        });
        let (server, collector) =
            InitialImageStatsServer::bind(&tool_rpc, directory.path(), admission.clone()).unwrap();
        let connections = server.connection_monitor();
        let issues = server.issue_monitor();
        let task = tokio::spawn(server.serve());
        assert!(
            RpcClient::<crate::stats::LiteinstStatsGlobal>::connect(
                &endpoint,
                Tid::from_raw(std::process::id() as i32),
            )
            .await
            .is_err()
        );
        tokio::time::timeout(Duration::from_secs(2), issues.failed())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), connections.wait_for_idle())
            .await
            .unwrap();
        assert_eq!(admission.calls.load(Ordering::Relaxed), 1);
        assert_eq!(issues.snapshot().len(), 1);
        stop_server(task, &issues).await;
        assert_eq!(connections.active_connections(), 0);
        assert_eq!(
            issues.snapshot().len(),
            1,
            "failure cannot disappear during cancellation"
        );
        assert_eq!(
            collector
                .into_source()
                .await
                .unwrap()
                .snapshot()
                .process_reports(),
            0
        );
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;
    use std::time::Duration;

    use reverie::Tid;

    use super::*;
    use crate::rpc::CoordinatorClient;

    fn short_socket_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("reverie-liteinst-test-")
            .tempdir_in("/tmp")
            .unwrap()
    }

    struct CapturedLogWriter(Arc<Mutex<Vec<u8>>>);

    impl io::Write for CapturedLogWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn coordinator_global_waits_for_cancelled_connection_owners() {
        let global = Arc::new(17_u64);
        let connection_owner = global.clone();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            drop(connection_owner);
        });

        assert_eq!(unwrap_global_after_connections(global).await.unwrap(), 17);
    }

    #[test]
    fn pre_connect_error_preserves_status_and_bounded_stderr() {
        fn exited(code: i32) -> std::process::ExitStatus {
            std::process::ExitStatus::from_raw(code << 8)
        }
        fn output(code: i32, stderr: Vec<u8>) -> ChildWait {
            ChildWait::Output(Output {
                status: exited(code),
                stdout: Vec::new(),
                stderr,
            })
        }

        let error = pre_connect_error(&output(101, b"bad selector\n".to_vec()));
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        let message = error.to_string();
        assert!(message.contains("exited before connecting"), "{message}");
        assert!(message.contains("exit status: 101"), "{message}");
        assert!(message.contains("bad selector"), "{message}");

        let mut large = vec![b'x'; PRE_CONNECT_STDERR_LIMIT + 1000];
        large.extend_from_slice(b"tail-marker");
        let total = large.len();
        let message = pre_connect_error(&output(42, large)).to_string();
        assert!(
            message.contains(&format!("last {PRE_CONNECT_STDERR_LIMIT} of {total} bytes")),
            "{message}"
        );
        assert!(message.contains("tail-marker"), "{message}");
        assert!(
            message.len() < PRE_CONNECT_STDERR_LIMIT + 400,
            "excerpt is bounded: {} bytes",
            message.len()
        );

        let message = pre_connect_error(&output(42, vec![0xff, b'a'])).to_string();
        assert!(message.contains('\u{fffd}'), "{message}");

        let message = pre_connect_error(&output(42, Vec::new())).to_string();
        assert!(!message.contains("guest stderr"), "{message}");

        let message = pre_connect_error(&ChildWait::Status(exited(42))).to_string();
        assert!(message.contains("exit status: 42"), "{message}");
        assert!(!message.contains("guest stderr"), "{message}");

        // The unchanged prefix, a signal exit, and an exactly-at-limit
        // excerpt (no truncation marker).
        let message = pre_connect_error(&ChildWait::Status(std::process::ExitStatus::from_raw(
            libc::SIGKILL,
        )))
        .to_string();
        assert!(
            message.starts_with(
                "LiteInst guest exited before connecting to the coordinator; \
                 static executables and loader failures are unsupported; guest "
            ),
            "{message}"
        );
        assert!(message.contains("signal: 9 (SIGKILL)"), "{message}");
        let at_limit = vec![b'y'; PRE_CONNECT_STDERR_LIMIT];
        let message = pre_connect_error(&output(42, at_limit)).to_string();
        assert!(message.contains("; guest stderr: "), "{message}");
        assert!(!message.contains("last"), "{message}");
    }

    #[derive(Default)]
    struct MultiClientGlobal {
        total: AtomicU64,
        senders: Mutex<Vec<i32>>,
    }

    #[reverie::global_tool]
    impl GlobalTool for MultiClientGlobal {
        type Request = u64;
        type Response = u64;
        type Config = u64;

        async fn receive_rpc(&self, from: Tid, amount: u64) -> u64 {
            self.senders.lock().unwrap().push(from.as_raw());
            self.total.fetch_add(amount, Ordering::Relaxed) + amount
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn production_coordinator_drain_timeout_is_thirty_seconds() {
        assert_eq!(RPC_CONNECTION_DRAIN_TIMEOUT, Duration::from_secs(30));

        let directory = short_socket_tempdir();
        let socket = directory.path().join("coordinator.sock");
        let server = RpcServer::bind(&socket, Arc::new(MultiClientGlobal::default()), 41).unwrap();
        let monitor = server.connection_monitor();
        let (connected_tx, connected_rx) = tokio::sync::oneshot::channel();
        let (complete_tx, complete_rx) = tokio::sync::oneshot::channel();

        let client = tokio::spawn(async move {
            let _client = reverie_rpc_transport::RpcClient::<MultiClientGlobal>::connect(
                &socket,
                Tid::from_raw(707),
            )
            .await
            .unwrap();
            connected_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let completion = async move {
            complete_rx
                .await
                .map_err(|error| io::Error::other(error.to_string()))
        };
        let mut serving = Box::pin(serve_rpc_until(
            server,
            None,
            vec![monitor.clone()],
            completion,
            std::future::pending(),
        ));

        let initial_poll =
            std::future::poll_fn(|context| std::task::Poll::Ready(serving.as_mut().poll(context)))
                .await;
        assert!(initial_poll.is_pending());
        connected_rx.await.unwrap();
        assert_eq!(monitor.active_connections(), 1);

        complete_tx.send(()).unwrap();
        let drain_poll =
            std::future::poll_fn(|context| std::task::Poll::Ready(serving.as_mut().poll(context)))
                .await;
        assert!(drain_poll.is_pending());
        tokio::time::advance(Duration::from_secs(29)).await;
        let before_deadline =
            std::future::poll_fn(|context| std::task::Poll::Ready(serving.as_mut().poll(context)))
                .await;
        assert!(before_deadline.is_pending());

        tokio::time::advance(Duration::from_secs(1)).await;
        let error = tokio::time::timeout(Duration::from_secs(1), serving)
            .await
            .expect("the production coordinator drain did not expire at 30 seconds")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            error.to_string(),
            "LiteInst coordinator retained 1 active RPC connection(s) for 30000ms after guest exit"
        );

        client.abort();
        let _ = client.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn coordinator_serves_multiple_local_rpc_connections() {
        let directory = short_socket_tempdir();
        let socket = directory.path().join("coordinator.sock");
        let global = Arc::new(MultiClientGlobal::default());
        let server = RpcServer::bind(&socket, global.clone(), 41).unwrap();
        let connection_monitors = vec![server.connection_monitor()];

        let clients = tokio::task::spawn_blocking(move || -> io::Result<()> {
            let mut first = CoordinatorClient::connect(&socket)?;
            let mut second = CoordinatorClient::connect(&socket)?;
            assert_eq!(first.config::<u64>()?, 41);
            assert_eq!(second.config::<u64>()?, 41);

            let first_total: u64 = first.send(Tid::from_raw(101), 2_u64)?;
            let second_total: u64 = second.send(Tid::from_raw(202), 3_u64)?;
            assert_eq!(first_total, 2);
            assert_eq!(second_total, 5);
            Ok(())
        });
        let completion = async move {
            clients
                .await
                .map_err(|error| io::Error::other(error.to_string()))?
        };

        tokio::time::timeout(
            Duration::from_secs(5),
            serve_rpc_until(
                server,
                None,
                connection_monitors,
                completion,
                std::future::pending(),
            ),
        )
        .await
        .expect("the second local RPC connection blocked at its config handshake")
        .unwrap();

        assert_eq!(global.total.load(Ordering::Relaxed), 5);
        assert_eq!(*global.senders.lock().unwrap(), [101, 202]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn coordinator_two_monitor_drain_is_level_triggered() {
        let directory = short_socket_tempdir();
        let main_socket = directory.path().join("coordinator.sock");
        let stats_socket = directory.path().join("stats.sock");
        let main_server =
            RpcServer::bind(&main_socket, Arc::new(MultiClientGlobal::default()), 41).unwrap();
        let stats_server = RpcServer::bind(
            &stats_socket,
            Arc::new(crate::stats::LiteinstStatsGlobal::default()),
            (),
        )
        .unwrap();
        let main_monitor = main_server.connection_monitor();
        let stats_monitor = stats_server.connection_monitor();
        let connection_monitors = vec![main_monitor.clone(), stats_monitor.clone()];
        let (main_connected_tx, main_connected_rx) = tokio::sync::oneshot::channel();
        let (stats_connected_tx, stats_connected_rx) = tokio::sync::oneshot::channel();
        let (release_main_tx, release_main_rx) = tokio::sync::oneshot::channel();
        let (complete_tx, complete_rx) = tokio::sync::oneshot::channel();

        let main_client = tokio::spawn(async move {
            let client = reverie_rpc_transport::RpcClient::<MultiClientGlobal>::connect(
                &main_socket,
                Tid::from_raw(404),
            )
            .await
            .unwrap();
            main_connected_tx.send(()).unwrap();
            release_main_rx.await.unwrap();
            drop(client);
        });
        let stats_client = tokio::spawn(async move {
            let client =
                reverie_rpc_transport::RpcClient::<crate::stats::LiteinstStatsGlobal>::connect(
                    &stats_socket,
                    Tid::from_raw(405),
                )
                .await
                .unwrap();
            stats_connected_tx.send(()).unwrap();
            drop(client);
        });
        let completion = async move {
            complete_rx
                .await
                .map_err(|error| io::Error::other(error.to_string()))
        };
        let mut serving = Box::pin(serve_rpc_until_with_timeout(
            main_server,
            Some(stats_server),
            connection_monitors,
            completion,
            std::future::pending(),
            Duration::from_secs(1),
        ));

        let initial_poll =
            std::future::poll_fn(|context| std::task::Poll::Ready(serving.as_mut().poll(context)))
                .await;
        assert!(initial_poll.is_pending());
        main_connected_rx.await.unwrap();
        stats_connected_rx.await.unwrap();
        stats_client.await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while stats_monitor.active_connections() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the stats connection did not close before the drain began");
        assert_eq!(main_monitor.active_connections(), 1);
        assert_eq!(stats_monitor.active_connections(), 0);

        complete_tx.send(()).unwrap();
        let drain_poll =
            std::future::poll_fn(|context| std::task::Poll::Ready(serving.as_mut().poll(context)))
                .await;
        assert!(drain_poll.is_pending());
        assert_eq!(main_monitor.active_connections(), 1);

        release_main_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), serving)
            .await
            .expect("the two-monitor coordinator drain hung")
            .unwrap();
        main_client.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn coordinator_surfaces_server_failure_during_connection_drain() {
        let directory = short_socket_tempdir();
        let socket = directory.path().join("coordinator.sock");
        let server = RpcServer::bind(&socket, Arc::new(MultiClientGlobal::default()), 41).unwrap();
        let monitor = server.connection_monitor();
        let (connected_tx, connected_rx) = tokio::sync::oneshot::channel();
        let (release_client_tx, release_client_rx) = tokio::sync::oneshot::channel();
        let (complete_tx, complete_rx) = tokio::sync::oneshot::channel();
        let (fail_server_tx, fail_server_rx) = tokio::sync::oneshot::channel();

        let client = tokio::spawn(async move {
            let client = reverie_rpc_transport::RpcClient::<MultiClientGlobal>::connect(
                &socket,
                Tid::from_raw(505),
            )
            .await
            .unwrap();
            connected_tx.send(()).unwrap();
            release_client_rx.await.unwrap();
            drop(client);
        });
        let mut server_tasks = tokio::task::JoinSet::new();
        server_tasks.spawn(server.serve());
        server_tasks.spawn(async move {
            fail_server_rx.await.unwrap();
            Err(RpcError::Io(io::Error::other("drain-phase server failure")))
        });
        let completion = async move {
            complete_rx
                .await
                .map_err(|error| io::Error::other(error.to_string()))
        };
        let mut serving = Box::pin(serve_rpc_tasks_until_with_timeout(
            server_tasks,
            vec![monitor.clone()],
            completion,
            std::future::pending(),
            Duration::from_secs(1),
        ));

        connected_rx.await.unwrap();
        assert_eq!(monitor.active_connections(), 1);
        complete_tx.send(()).unwrap();
        let drain_poll =
            std::future::poll_fn(|context| std::task::Poll::Ready(serving.as_mut().poll(context)))
                .await;
        assert!(drain_poll.is_pending());
        assert_eq!(monitor.active_connections(), 1);

        fail_server_tx.send(()).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), serving)
            .await
            .expect("the drain did not observe the injected server failure")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            error.to_string(),
            "rpc i/o error: drain-phase server failure"
        );

        release_client_tx.send(()).unwrap();
        client.await.unwrap();
    }

    /// A connected client that holds its connection until told to drop it,
    /// a serve loop over it, and the senders that complete the guest's wait
    /// and publish a backend failure.
    struct FailureCase {
        serving: std::pin::Pin<Box<dyn Future<Output = io::Result<()>>>>,
        complete: tokio::sync::oneshot::Sender<()>,
        fail: tokio::sync::oneshot::Sender<()>,
        release_client: tokio::sync::oneshot::Sender<()>,
        client: tokio::task::JoinHandle<()>,
        monitor: ConnectionMonitor,
    }

    async fn failure_case() -> FailureCase {
        let directory = short_socket_tempdir();
        let socket = directory.path().join("coordinator.sock");
        let server = RpcServer::bind(&socket, Arc::new(MultiClientGlobal::default()), 41).unwrap();
        let monitor = server.connection_monitor();
        let (connected_tx, connected_rx) = tokio::sync::oneshot::channel();
        let (release_client, release_client_rx) = tokio::sync::oneshot::channel();
        let (complete, complete_rx) = tokio::sync::oneshot::channel::<()>();
        let (fail, fail_rx) = tokio::sync::oneshot::channel::<()>();
        let client = tokio::spawn(async move {
            let client = reverie_rpc_transport::RpcClient::<MultiClientGlobal>::connect(
                &socket,
                Tid::from_raw(606),
            )
            .await
            .unwrap();
            connected_tx.send(()).unwrap();
            let _ = release_client_rx.await;
            drop(client);
            drop(directory);
        });
        let mut server_tasks = tokio::task::JoinSet::new();
        server_tasks.spawn(server.serve());
        let completion = async move {
            complete_rx
                .await
                .map_err(|error| io::Error::other(error.to_string()))
        };
        let failure = async move {
            let _ = fail_rx.await;
        };
        let serving = Box::pin(serve_rpc_tasks_until_with_timeout(
            server_tasks,
            vec![monitor.clone()],
            completion,
            failure,
            Duration::from_secs(30),
        ));
        connected_rx.await.unwrap();
        FailureCase {
            serving,
            complete,
            fail,
            release_client,
            client,
            monitor,
        }
    }

    async fn poll_once(
        serving: &mut std::pin::Pin<Box<dyn Future<Output = io::Result<()>>>>,
    ) -> bool {
        std::future::poll_fn(|context| std::task::Poll::Ready(serving.as_mut().poll(context)))
            .await
            .is_pending()
    }

    fn assert_backend_failure(result: io::Result<()>) {
        let error = result.unwrap_err();
        assert_eq!(error.to_string(), backend_failure_error().to_string());
    }

    /// A backend failure while the root guest still runs ends the serve loop
    /// at once, with the failure, although a connection is still open.
    #[tokio::test(flavor = "current_thread")]
    async fn a_backend_failure_ends_the_run_while_the_guest_runs() {
        let mut case = failure_case().await;
        assert!(poll_once(&mut case.serving).await);
        case.fail.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), case.serving)
            .await
            .expect("a backend failure did not end the serve loop");
        assert_backend_failure(result);
        assert_eq!(case.monitor.active_connections(), 0);
        let _ = case.complete.send(());
        let _ = case.release_client.send(());
        case.client.await.unwrap();
    }

    /// A backend failure during the drain ends it at once, instead of waiting
    /// for the drain's 30-second bound.
    #[tokio::test(flavor = "current_thread")]
    async fn a_backend_failure_ends_the_drain() {
        let mut case = failure_case().await;
        case.complete.send(()).unwrap();
        assert!(poll_once(&mut case.serving).await);
        assert_eq!(case.monitor.active_connections(), 1);
        case.fail.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), case.serving)
            .await
            .expect("a backend failure did not end the drain");
        assert_backend_failure(result);
        let _ = case.release_client.send(());
        case.client.await.unwrap();
    }

    /// A failure published with the guest's completion wins over it, and one
    /// published in the instant the drain ends still fails the run.
    #[tokio::test(flavor = "current_thread")]
    async fn a_backend_failure_wins_over_a_simultaneous_completion() {
        let case = failure_case().await;
        case.fail.send(()).unwrap();
        case.complete.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), case.serving)
            .await
            .expect("the serve loop hung");
        assert_backend_failure(result);
        let _ = case.release_client.send(());
        case.client.await.unwrap();

        let mut case = failure_case().await;
        case.complete.send(()).unwrap();
        assert!(poll_once(&mut case.serving).await);
        // The drain's end and the failure become ready together.
        case.release_client.send(()).unwrap();
        case.fail.send(()).unwrap();
        case.client.await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), case.serving)
            .await
            .expect("the serve loop hung");
        assert_backend_failure(result);
    }

    /// A failure that becomes ready only after the drain has ended (the drain
    /// arm completes in the same poll in which the failure arm was still
    /// pending) is caught by the one extra poll after the drain.
    #[tokio::test(flavor = "current_thread")]
    async fn a_backend_failure_published_as_the_drain_ends_still_fails_the_run() {
        let directory = short_socket_tempdir();
        let socket = directory.path().join("coordinator.sock");
        let server = RpcServer::bind(&socket, Arc::new(MultiClientGlobal::default()), 41).unwrap();
        let monitor = server.connection_monitor();
        let (connected_tx, connected_rx) = tokio::sync::oneshot::channel();
        let (release_client, release_client_rx) = tokio::sync::oneshot::channel::<()>();
        let client = tokio::spawn(async move {
            let client = reverie_rpc_transport::RpcClient::<MultiClientGlobal>::connect(
                &socket,
                Tid::from_raw(607),
            )
            .await
            .unwrap();
            connected_tx.send(()).unwrap();
            let _ = release_client_rx.await;
            drop(client);
        });
        let mut server_tasks = tokio::task::JoinSet::new();
        server_tasks.spawn(server.serve());
        // Pending until it has seen the connections idle once, then ready: so
        // in the poll that ends the drain it is still pending, and ready at
        // the next poll.
        let idle = monitor.clone();
        let mut seen_idle = false;
        let failure = std::future::poll_fn(move |_| {
            if idle.active_connections() == 0 {
                if seen_idle {
                    return std::task::Poll::Ready(());
                }
                seen_idle = true;
            }
            std::task::Poll::Pending
        });
        let serving = serve_rpc_tasks_until_with_timeout(
            server_tasks,
            vec![monitor.clone()],
            async { Ok(()) },
            failure,
            Duration::from_secs(30),
        );
        connected_rx.await.unwrap();
        release_client.send(()).unwrap();
        client.await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), serving)
            .await
            .expect("the serve loop hung");
        assert_backend_failure(result);
        drop(directory);
    }

    /// A backend failure raised by a failed completion must retain both the
    /// original completion error and the existing diagnostic through teardown.
    #[tokio::test(flavor = "current_thread")]
    async fn a_backend_failure_preserves_completion_error_and_diagnostic() {
        let directory = short_socket_tempdir();
        let socket = directory.path().join("coordinator.sock");
        let server = RpcServer::bind(&socket, Arc::new(MultiClientGlobal::default()), 41).unwrap();
        let monitor = server.connection_monitor();
        let (connected_tx, connected_rx) = tokio::sync::oneshot::channel();
        let (fail_tx, fail_rx) = tokio::sync::oneshot::channel();
        let captured_logs = Arc::new(Mutex::new(Vec::new()));
        let writer_logs = captured_logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .with_writer(move || CapturedLogWriter(writer_logs.clone()))
            .finish();
        let _subscriber_guard = tracing::subscriber::set_default(subscriber);

        let client = tokio::spawn(async move {
            let _client = reverie_rpc_transport::RpcClient::<MultiClientGlobal>::connect(
                &socket,
                Tid::from_raw(608),
            )
            .await
            .unwrap();
            connected_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let completion = async move {
            connected_rx
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
            // The failure first becomes ready within the completion's poll,
            // after the initial biased failure arm has already been pending.
            fail_tx.send(()).unwrap();
            Err::<(), _>(io::Error::new(
                io::ErrorKind::InvalidData,
                "guest completion failed before RPC drain",
            ))
        };
        let failure = async move {
            let _ = fail_rx.await;
        };
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            serve_rpc_until_with_timeout(
                server,
                None,
                vec![monitor.clone()],
                completion,
                failure,
                Duration::from_millis(25),
            ),
        )
        .await
        .expect("a backend failure left the coordinator teardown unbounded")
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "guest completion failed before RPC drain"
        );
        assert_eq!(monitor.active_connections(), 0);
        let logs = String::from_utf8(captured_logs.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("a backend failure was reported; preserving guest completion error"));

        client.abort();
        let _ = client.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn coordinator_connection_drain_is_bounded() {
        let directory = short_socket_tempdir();
        let socket = directory.path().join("coordinator.sock");
        let global = Arc::new(MultiClientGlobal::default());
        let server = RpcServer::bind(&socket, global, 41).unwrap();
        let connection_monitors = vec![server.connection_monitor()];
        let (connected_tx, connected_rx) = tokio::sync::oneshot::channel();

        let client = tokio::spawn(async move {
            let _client = reverie_rpc_transport::RpcClient::<MultiClientGlobal>::connect(
                &socket,
                Tid::from_raw(303),
            )
            .await
            .unwrap();
            connected_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let completion = async move {
            connected_rx
                .await
                .map_err(|error| io::Error::other(error.to_string()))
        };

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            serve_rpc_until_with_timeout(
                server,
                None,
                connection_monitors,
                completion,
                std::future::pending(),
                Duration::from_millis(25),
            ),
        )
        .await
        .expect("a held connection left the coordinator drain unbounded")
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            error.to_string(),
            "LiteInst coordinator retained 1 active RPC connection(s) for 25ms after guest exit"
        );

        client.abort();
        let _ = client.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn coordinator_drain_timeout_preserves_completion_error() {
        let directory = short_socket_tempdir();
        let socket = directory.path().join("coordinator.sock");
        let server = RpcServer::bind(&socket, Arc::new(MultiClientGlobal::default()), 41).unwrap();
        let connection_monitors = vec![server.connection_monitor()];
        let (connected_tx, connected_rx) = tokio::sync::oneshot::channel();
        let captured_logs = Arc::new(Mutex::new(Vec::new()));
        let writer_logs = captured_logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .with_writer(move || CapturedLogWriter(writer_logs.clone()))
            .finish();
        let _subscriber_guard = tracing::subscriber::set_default(subscriber);

        let client = tokio::spawn(async move {
            let _client = reverie_rpc_transport::RpcClient::<MultiClientGlobal>::connect(
                &socket,
                Tid::from_raw(606),
            )
            .await
            .unwrap();
            connected_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let completion = async move {
            connected_rx
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
            Err::<(), _>(io::Error::new(
                io::ErrorKind::InvalidData,
                "guest completion failed before RPC drain",
            ))
        };

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            serve_rpc_until_with_timeout(
                server,
                None,
                connection_monitors,
                completion,
                std::future::pending(),
                Duration::from_millis(25),
            ),
        )
        .await
        .expect("a held connection left the coordinator drain unbounded")
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "guest completion failed before RPC drain"
        );
        let logs = String::from_utf8(captured_logs.lock().unwrap().clone()).unwrap();
        assert!(logs.contains(
            "LiteInst coordinator retained 1 active RPC connection(s) for 25ms after guest exit; preserving guest completion error"
        ));

        client.abort();
        let _ = client.await;
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

    #[test]
    fn sealed_bootstrap_preserves_bytes_and_rejection_classification() {
        use std::fs::File;
        use std::io::Write;
        use std::os::fd::FromRawFd;
        use std::os::fd::OwnedFd;
        use std::os::unix::ffi::OsStringExt;

        const CHILD: &str = "REVERIE_COMPONENT_BOOTSTRAP_WIRE_CHILD";
        const TEST: &str =
            "launcher::tests::sealed_bootstrap_preserves_bytes_and_rejection_classification";
        if std::env::var_os(CHILD).is_none() {
            // Descriptor scanning in the duplicate-bootstrap test must not see
            // this test's matching descriptors while tests run concurrently.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--test-threads=1"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                selected_child_test_passed(&output, TEST),
                "bootstrap control did not execute successfully: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        fn fixture(bytes: &[u8], sealed: bool) -> OwnedFd {
            let fd = unsafe {
                libc::memfd_create(
                    c"bootstrap-wire-control".as_ptr(),
                    libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
                )
            };
            assert!(fd >= 0);
            let mut file = unsafe { File::from_raw_fd(fd) };
            file.write_all(bytes).unwrap();
            if sealed {
                let seals = libc::F_SEAL_SEAL
                    | libc::F_SEAL_SHRINK
                    | libc::F_SEAL_GROW
                    | libc::F_SEAL_WRITE;
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) }, 0);
            }
            file.into()
        }

        // Frozen legacy packet, including non-UTF8 path and opaque Tool data.
        // This literal is independent of the moved encoder's constants.
        let expected = b"REVERIE-LI-V1\0\0\0\x0f\0\x03\0/tmp/raw-\xff.sock\0\xff*";
        let coordinator = PathBuf::from(OsString::from_vec(b"/tmp/raw-\xff.sock".to_vec()));
        let data = b"\0\xff*";
        let fd = create_preload_bootstrap(&coordinator, None, None, data).unwrap();
        let mut actual = [0u8; 128];
        let count =
            unsafe { libc::pread(fd.as_raw_fd(), actual.as_mut_ptr().cast(), actual.len(), 0) };
        assert_eq!(count, expected.len() as isize);
        assert_eq!(&actual[..expected.len()], expected);
        let decoded = read_preload_bootstrap(fd.as_raw_fd()).unwrap().unwrap();
        assert_eq!(decoded.coordinator, coordinator);
        assert_eq!(decoded.tool_data, data);
        assert_eq!(decoded.stats_coordinator, None);

        // Version 2 names the statistics coordinator too, after the Tool
        // coordinator; a frozen literal again.
        let expected_v2 =
            b"REVERIE-LI-V2\0\0\0\x0f\0\x0b\0\x03\0/tmp/raw-\xff.sock/tmp/s.sock\0\xff*";
        let stats = PathBuf::from("/tmp/s.sock");
        let fd = create_preload_bootstrap(&coordinator, Some(&stats), None, data).unwrap();
        let count =
            unsafe { libc::pread(fd.as_raw_fd(), actual.as_mut_ptr().cast(), actual.len(), 0) };
        assert_eq!(count, expected_v2.len() as isize);
        assert_eq!(&actual[..expected_v2.len()], expected_v2);
        let decoded = read_preload_bootstrap(fd.as_raw_fd()).unwrap().unwrap();
        assert_eq!(decoded.coordinator, coordinator);
        assert_eq!(decoded.stats_coordinator, Some(stats));
        assert_eq!(decoded.tool_data, data);
        assert_eq!(decoded.site_patching, None);

        // Version 3 adds the site-patching selection (2: off) after the
        // lengths; its statistics path may be empty.
        let expected_v3 = b"REVERIE-LI-V3\0\0\0\x0f\0\0\0\x03\0\x02/tmp/raw-\xff.sock\0\xff*";
        let fd = create_preload_bootstrap(&coordinator, None, Some(false), data).unwrap();
        let count =
            unsafe { libc::pread(fd.as_raw_fd(), actual.as_mut_ptr().cast(), actual.len(), 0) };
        assert_eq!(count, expected_v3.len() as isize);
        assert_eq!(&actual[..expected_v3.len()], expected_v3);
        let decoded = read_preload_bootstrap(fd.as_raw_fd()).unwrap().unwrap();
        assert_eq!(decoded.coordinator, coordinator);
        assert_eq!(decoded.stats_coordinator, None);
        assert_eq!(decoded.site_patching, Some(false));
        assert_eq!(decoded.tool_data, data);
        let fd = create_preload_bootstrap(&coordinator, Some(Path::new("/s")), Some(true), data)
            .unwrap();
        let decoded = read_preload_bootstrap(fd.as_raw_fd()).unwrap().unwrap();
        assert_eq!(decoded.stats_coordinator.as_deref(), Some(Path::new("/s")));
        assert_eq!(decoded.site_patching, Some(true));

        let unsealed = fixture(expected, false);
        assert!(
            read_preload_bootstrap(unsealed.as_raw_fd())
                .unwrap()
                .is_none()
        );
        let mut wrong_magic = expected.to_vec();
        wrong_magic[0] ^= 1;
        let unrelated = fixture(&wrong_magic, true);
        assert!(
            read_preload_bootstrap(unrelated.as_raw_fd())
                .unwrap()
                .is_none()
        );
        let mut wrong_length = expected.to_vec();
        wrong_length[16] += 1;
        let malformed = fixture(&wrong_length, true);
        let error = read_preload_bootstrap(malformed.as_raw_fd()).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "invalid LiteInst preload bootstrap lengths"
        );
        let oversized = create_preload_bootstrap(&coordinator, None, None, &[0; 4096])
            .err()
            .unwrap();
        assert_eq!(oversized.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_and_closes_multiple_matching_bootstraps() {
        let expected = [
            (
                PathBuf::from("/tmp/reverie-liteinst-fd-reuse-test-1.sock"),
                b"one".to_vec(),
            ),
            (
                PathBuf::from("/tmp/reverie-liteinst-fd-reuse-test-2.sock"),
                b"two".to_vec(),
            ),
            (
                PathBuf::from("/tmp/reverie-liteinst-fd-reuse-test-3.sock"),
                b"three".to_vec(),
            ),
        ];
        for (coordinator, tool_data) in &expected {
            let bootstrap = create_preload_bootstrap(coordinator, None, None, tool_data).unwrap();
            std::mem::forget(bootstrap);
        }
        let open = open_test_bootstraps().unwrap();
        assert!(
            expected.iter().all(|expected| open.contains(expected)),
            "created bootstrap descriptors are not all visible: {open:?}"
        );

        let error = match unsafe { take_preload_bootstrap() } {
            Err(error) => error,
            Ok(_) => panic!("multiple matching bootstraps must fail"),
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "multiple LiteInst preload bootstraps");
        let open = open_test_bootstraps().unwrap();
        assert!(
            expected.iter().all(|expected| !open.contains(expected)),
            "rejected bootstrap descriptors remain open: {open:?}"
        );
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
    fn effective_command_environment_honors_override_remove_and_clear() {
        let ambient_path = std::env::var_os("PATH").expect("test process must have PATH");
        assert!(!ambient_path.is_empty());

        let mut command = Command::new("/bin/true");
        command.env("PATH", "/caller/bin");
        assert_eq!(
            effective_command_env(&command, OsStr::new("PATH")),
            Some(OsString::from("/caller/bin"))
        );

        command.env_remove("PATH");
        assert_eq!(effective_command_env(&command, OsStr::new("PATH")), None);

        let mut cleared = Command::new("/bin/true");
        cleared.env_clear();
        assert_eq!(effective_command_env(&cleared, OsStr::new("PATH")), None);
    }

    fn selected_child_test_passed(output: &std::process::Output, test: &str) -> bool {
        output.status.success()
            && String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line == format!("test {test} ... ok"))
    }

    #[test]
    fn a_stale_child_test_selector_is_not_a_successful_control() {
        const MISSING: &str = "launcher::tests::__missing_child_selection_control";
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", MISSING, "--test-threads=1"])
            .output()
            .unwrap();
        // Libtest accepts an empty selection. Our process-isolated control
        // must additionally prove that the intended test actually ran.
        assert!(output.status.success());
        assert!(!selected_child_test_passed(&output, MISSING));
    }

    #[test]
    fn in_guest_preload_override_remove_and_clear_win_over_ambient() {
        const CHILD_ENV: &str = "REVERIE_LITEINST_PRELOAD_ENV_TEST_CHILD";
        const TEST: &str =
            "launcher::tests::in_guest_preload_override_remove_and_clear_win_over_ambient";
        if std::env::var_os(CHILD_ENV).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--test-threads=1"])
                .env(CHILD_ENV, "1")
                .env("LD_PRELOAD", "libc.so.6")
                .output()
                .unwrap();
            assert!(
                selected_child_test_passed(&output, TEST),
                "child test failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        assert_eq!(std::env::var_os("LD_PRELOAD"), Some("libc.so.6".into()));

        let mut command = Command::new("/bin/true");
        command.env("LD_PRELOAD", "/caller/tool.so");
        configure_in_guest_command_preload(&mut command, PathBuf::from("/liteinst/runtime.so"));
        let preload = command
            .get_envs()
            .find(|(key, _)| *key == OsStr::new("LD_PRELOAD"))
            .and_then(|(_, value)| value);
        assert_eq!(
            preload,
            Some(OsStr::new("/liteinst/runtime.so:/caller/tool.so"))
        );

        let mut removed = Command::new("/bin/true");
        removed.env_remove("LD_PRELOAD");
        configure_in_guest_command_preload(&mut removed, PathBuf::from("/liteinst/runtime.so"));
        assert_eq!(
            effective_command_env(&removed, OsStr::new("LD_PRELOAD")),
            Some(OsString::from("/liteinst/runtime.so"))
        );

        let mut cleared = Command::new("/bin/true");
        cleared.env_clear();
        configure_in_guest_command_preload(&mut cleared, PathBuf::from("/liteinst/runtime.so"));
        assert_eq!(
            effective_command_env(&cleared, OsStr::new("LD_PRELOAD")),
            Some(OsString::from("/liteinst/runtime.so"))
        );
    }

    /// Build a marker-writing fixture binary. The static variant is
    /// hermetic: a tiny `-nostdlib` assembly `_start` (openat, write,
    /// close, exit), so the refusal tests never depend on a host
    /// static libc (`libc.a`), which the validation image lacks. The
    /// dynamic variant uses a C main so it carries a real PT_INTERP
    /// naming the host dynamic linker.
    fn build_fixture(dir: &Path, name: &str, marker: &Path, statik: bool) -> std::path::PathBuf {
        let out = dir.join(name);
        if statik {
            build_asm_fixture(dir, &out, marker, &["-static"]);
            return out;
        }
        let c = dir.join("fixture.c");
        std::fs::write(
            &c,
            format!(
                "#include <stdio.h>\nint main(void){{FILE*f=fopen(\"{}\",\"w\");if(f){{fputs(\"ran\",f);fclose(f);}}return 7;}}\n",
                marker.display()
            ),
        )
        .unwrap();
        let output = std::process::Command::new("cc")
            .arg("-o")
            .arg(&out)
            .arg(&c)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cc fixture build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        out
    }

    /// Assemble the hermetic `_start` fixture: create `marker`, write
    /// "ran", exit 7. Linked `-nostdlib`, so no libc in any form.
    fn build_asm_fixture(dir: &Path, out: &Path, marker: &Path, extra_flags: &[&str]) {
        let marker = marker.display().to_string();
        assert!(
            !marker.contains('"') && !marker.contains('\\'),
            "marker path must be asm-string safe: {marker}"
        );
        let asm = dir.join("fixture.S");
        std::fs::write(&asm, fixture_asm_source(&marker)).unwrap();
        let output = std::process::Command::new("cc")
            .arg("-nostdlib")
            .args(extra_flags)
            .arg("-o")
            .arg(out)
            .arg(&asm)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cc asm fixture build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_arch = "x86_64")]
    fn fixture_asm_source(marker: &str) -> String {
        format!(
            r#".text
.globl _start
_start:
    mov $257, %rax
    mov $-100, %rdi
    lea marker_path(%rip), %rsi
    mov $577, %edx
    mov $420, %r10d
    syscall
    test %rax, %rax
    js .Lexit
    mov %rax, %rdi
    mov $1, %rax
    lea ran_text(%rip), %rsi
    mov $3, %edx
    syscall
    mov $3, %rax
    syscall
.Lexit:
    mov $60, %rax
    mov $7, %edi
    syscall
.section .rodata
marker_path: .asciz "{marker}"
ran_text: .ascii "ran"
"#
        )
    }

    #[cfg(target_arch = "aarch64")]
    fn fixture_asm_source(marker: &str) -> String {
        format!(
            r#".text
.globl _start
_start:
    mov x8, #56
    mov x0, #-100
    adr x1, marker_path
    mov x2, #577
    mov x3, #420
    svc #0
    tbnz x0, #63, .Lexit
    mov x9, x0
    mov x8, #64
    mov x0, x9
    adr x1, ran_text
    mov x2, #3
    svc #0
    mov x8, #57
    mov x0, x9
    svc #0
.Lexit:
    mov x8, #93
    mov x0, #7
    svc #0
.section .rodata
marker_path: .asciz "{marker}"
ran_text: .ascii "ran"
"#
        )
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    fn fixture_asm_source(_marker: &str) -> String {
        panic!("no hermetic static fixture for this target_arch");
    }

    #[test]
    fn static_detection_reads_program_headers() {
        let dir = short_socket_tempdir();
        let marker = dir.path().join("marker");
        let statik = build_fixture(dir.path(), "fx-static", &marker, true);
        let dynamic = build_fixture(dir.path(), "fx-dynamic", &marker, false);
        assert!(target_is_static(&statik).unwrap());
        assert!(!target_is_static(&dynamic).unwrap());
        assert!(!target_is_static(Path::new("/bin/true")).unwrap());
    }

    #[test]
    fn short_and_non_elf_targets_are_not_static() {
        // A bare "#!" (proot-suite test-shebang-length-limit) and
        // other sub-ident non-ELF files are scripts, not static
        // ELFs: the check must say not-static so the normal
        // exec/shebang path handles them, not fail the launch
        // with "failed to fill whole buffer".
        // MUTATION ARM: restoring read_exact on the ident in
        // target_is_static makes every case here error instead.
        let dir = short_socket_tempdir();
        for (name, bytes) in [
            ("bare-shebang", b"#!".as_slice()),
            ("empty", b"".as_slice()),
            ("short-script", b"#!/bin/sh".as_slice()),
            ("nineteen-bytes", b"not an elf at all!!".as_slice()),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            assert!(
                !target_is_static(&path).unwrap(),
                "{name} misclassified as static"
            );
            refuse_static_target(&path, &[], None).unwrap();
        }
    }

    #[test]
    fn malformed_elf_after_ident_fails_closed() {
        // The short/non-ELF tolerance ends at a complete ident:
        // a file that claims ELF64/ELF32 and then truncates its
        // header or points its program headers past EOF is an
        // uninspectable ELF, and the launch must refuse rather
        // than classify it as not static.
        // MUTATION ARM: mapping a post-ident read error to
        // Ok(false) makes every case here return not-static
        // instead of Err.
        fn elf64_header(phoff: u64) -> Vec<u8> {
            let mut bytes = vec![0u8; 64];
            bytes[..4].copy_from_slice(b"\x7fELF");
            bytes[4] = 2;
            bytes[32..40].copy_from_slice(&phoff.to_ne_bytes());
            bytes[54..56].copy_from_slice(&56u16.to_ne_bytes());
            bytes[56..58].copy_from_slice(&1u16.to_ne_bytes());
            bytes
        }
        fn elf32_header(phoff: u32) -> Vec<u8> {
            let mut bytes = vec![0u8; 52];
            bytes[..4].copy_from_slice(b"\x7fELF");
            bytes[4] = 1;
            bytes[28..32].copy_from_slice(&phoff.to_ne_bytes());
            bytes[42..44].copy_from_slice(&32u16.to_ne_bytes());
            bytes[44..46].copy_from_slice(&1u16.to_ne_bytes());
            bytes
        }

        let dir = short_socket_tempdir();
        let elf64 = elf64_header(4096);
        let mut cases: Vec<(&str, Vec<u8>)> = [20usize, 32, 63]
            .into_iter()
            .map(|len| {
                (
                    match len {
                        20 => "truncated-elf64-20",
                        32 => "truncated-elf64-32",
                        _ => "truncated-elf64-63",
                    },
                    elf64[..len].to_vec(),
                )
            })
            .collect();
        cases.push(("elf64-phoff-past-eof", elf64));
        cases.push(("elf32-phoff-past-eof", elf32_header(4096)));

        for (name, bytes) in cases {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            let error = target_is_static(&path).unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::UnexpectedEof,
                "{name}: {error}"
            );
            let error = refuse_static_target(&path, &[], None).unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::UnexpectedEof,
                "{name}: {error}"
            );
        }
    }

    #[test]
    fn static_target_refused_before_spawn_marker_absent() {
        let dir = short_socket_tempdir();
        let marker = dir.path().join("marker");
        let statik = build_fixture(dir.path(), "fx-static2", &marker, true);
        let err = refuse_static_target(&statik, &[], None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("no PT_INTERP"), "{err}");
        assert!(!marker.exists());
        let dynamic = build_fixture(dir.path(), "fx-dynamic2", &marker, false);
        refuse_static_target(&dynamic, &[], None).unwrap();
    }

    #[tokio::test]
    async fn static_guest_never_spawns_dynamic_guest_runs() {
        #[derive(Default, Debug)]
        struct EchoGlobal;
        #[reverie::tool]
        impl reverie::GlobalTool for EchoGlobal {
            type Request = u64;
            type Response = u64;
            type Config = u64;
            async fn receive_rpc(&self, _from: reverie::Pid, message: u64) -> u64 {
                message
            }
        }
        #[derive(Default)]
        struct EchoTool;
        #[reverie::tool]
        impl reverie::Tool for EchoTool {
            type GlobalState = EchoGlobal;
            type ThreadState = ();
        }
        let dir = short_socket_tempdir();
        let preload = dir.path().join("preload.so");
        // A placeholder, not a shared object: a refused launch never
        // reads it, and ld.so ignores it ("file too short") in a launch
        // that runs, so the guest runs without the runtime.
        std::fs::write(&preload, b"placeholder").unwrap();
        let marker = dir.path().join("marker-static");
        let statik = build_fixture(dir.path(), "fx-static3", &marker, true);
        let command = reverie::process::Command::new(statik.to_str().unwrap());
        // MUTATION ARM: deleting refuse_static_target from launch()
        // lets this fixture run unconfined (marker appears).
        let err = PreloadBackend::run_with_preload::<EchoTool>(command, 7, preload.clone())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("no PT_INTERP"),
            "static refusal: {err}"
        );
        assert!(!marker.exists(), "static guest ran unconfined");
        let marker2 = dir.path().join("marker-dynamic");
        let dynamic = build_fixture(dir.path(), "fx-dynamic3", &marker2, false);
        let command2 = reverie::process::Command::new(dynamic.to_str().unwrap());
        let _ = PreloadBackend::run_with_preload::<EchoTool>(command2, 7, preload).await;
        assert!(marker2.exists(), "dynamic guest never spawned");
    }

    /// The host dynamic linker the dynamic fixture names.
    fn fixture_ldso(dynamic: &Path) -> std::path::PathBuf {
        let interp = elf_interp(dynamic)
            .unwrap()
            .expect("dynamic fixture carries PT_INTERP");
        std::path::PathBuf::from(interp)
    }

    #[test]
    fn linker_as_program_checks_its_target() {
        // ld.so (ET_DYN, no PT_INTERP by definition) as program --
        // literoot's shebang/interp routes launch exactly this
        // shape: program=ld.so, first argument=the ELF it loads.
        // The TARGET decides, never a bare ET_DYN exemption.
        let dir = short_socket_tempdir();
        let marker = dir.path().join("marker");
        let statik = build_fixture(dir.path(), "fx-static4", &marker, true);
        let dynamic = build_fixture(dir.path(), "fx-dynamic4", &marker, false);
        let ldso = fixture_ldso(&dynamic);
        // Linker + static target: refused (target would run
        // unconfined -- no interpreter loads the preload into it).
        let err =
            refuse_static_target(&ldso, &[statik.as_os_str().to_os_string()], None).unwrap_err();
        assert!(err.to_string().contains("no PT_INTERP"), "{err}");
        // Linker + dynamic target: admitted (the linker loads the
        // preload into its target).
        refuse_static_target(&ldso, &[dynamic.as_os_str().to_os_string()], None).unwrap();
        // Linker alone: refused. No target names it as an
        // interpreter, so it is indistinguishable from a static-pie
        // guest at this layer; admitting it would be the bare
        // ET_DYN exemption the review bar rejects.
        let err = refuse_static_target(&ldso, &[], None).unwrap_err();
        assert!(err.to_string().contains("no PT_INTERP"), "{err}");
        // Linker options are skipped when finding the target, including
        // value-taking ones; the `--opt=value` spelling is not an ld.so
        // option, so ld.so itself is refused (linker_options_match_glibc_rtld).
        let err = refuse_static_target(
            &ldso,
            &[
                "--inhibit-cache".to_owned().into(),
                statik.as_os_str().to_os_string(),
            ],
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no PT_INTERP"), "{err}");
        refuse_static_target(
            &ldso,
            &[
                "--library-path".to_owned().into(),
                "/nonexistent".to_owned().into(),
                dynamic.as_os_str().to_os_string(),
            ],
            None,
        )
        .unwrap();
        let err = refuse_static_target(
            &ldso,
            &[
                "--library-path=/nonexistent".to_owned().into(),
                statik.as_os_str().to_os_string(),
            ],
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no PT_INTERP"), "{err}");
    }

    #[test]
    fn static_pie_guest_still_refused() {
        // musereview bar: an ET_DYN static-pie GUEST must not pass
        // as a "linker". Hermetic static-pie shape: ET_DYN with no
        // PT_INTERP, from the same nostdlib asm fixture (a real
        // `cc -static-pie` would need host libc.a/rcrt1; the ELF
        // facts the refusal reads are identical).
        let dir = short_socket_tempdir();
        let marker = dir.path().join("marker");
        let out = dir.path().join("fx-staticpie");
        build_asm_fixture(
            dir.path(),
            &out,
            &marker,
            &["-pie", "-Wl,--no-dynamic-linker"],
        );
        let header = std::fs::read(&out).unwrap();
        assert_eq!(
            u16::from_ne_bytes([header[16], header[17]]),
            3,
            "fixture must be ET_DYN"
        );
        assert!(elf_interp(&out).unwrap().is_none());
        assert!(target_is_static(&out).unwrap());
        // As program: refused (no target names it as interpreter).
        assert!(refuse_static_target(&out, &[], None).is_err());
        // As a would-be linker in front of a dynamic target: still
        // refused -- the target's PT_INTERP names the real linker,
        // not this guest.
        let dynamic = build_fixture(dir.path(), "fx-dynamic5", &marker, false);
        assert!(refuse_static_target(&out, &[dynamic.as_os_str().to_os_string()], None).is_err());
        // As ld.so's target argument: refused (it has no PT_INTERP
        // naming the linker).
        let ldso = fixture_ldso(&dynamic);
        assert!(refuse_static_target(&ldso, &[out.as_os_str().to_os_string()], None).is_err());
    }

    #[tokio::test]
    async fn linker_as_program_launches_dynamic_target_only() {
        #[derive(Default, Debug)]
        struct EchoGlobal;
        #[reverie::tool]
        impl reverie::GlobalTool for EchoGlobal {
            type Request = u64;
            type Response = u64;
            type Config = u64;
            async fn receive_rpc(&self, _from: reverie::Pid, message: u64) -> u64 {
                message
            }
        }
        #[derive(Default)]
        struct EchoTool;
        #[reverie::tool]
        impl reverie::Tool for EchoTool {
            type GlobalState = EchoGlobal;
            type ThreadState = ();
        }
        let dir = short_socket_tempdir();
        let preload = dir.path().join("preload.so");
        // A placeholder, not a shared object: a refused launch never
        // reads it, and ld.so ignores it ("file too short") in a launch
        // that runs, so the guest runs without the runtime.
        std::fs::write(&preload, b"placeholder").unwrap();
        let dynamic_marker = dir.path().join("marker-linker-dynamic");
        let dynamic = build_fixture(dir.path(), "fx-dynamic6", &dynamic_marker, false);
        let ldso = fixture_ldso(&dynamic);
        // MUTATION ARM: dropping the linker_target redirect (always
        // checking `program`) refuses ld.so itself and the dynamic
        // half below never spawns.
        let mut command = reverie::process::Command::new(ldso.to_str().unwrap());
        command.arg(dynamic.to_str().unwrap());
        let _ = PreloadBackend::run_with_preload::<EchoTool>(command, 7, preload.clone()).await;
        assert!(
            dynamic_marker.exists(),
            "ld.so + dynamic target never spawned"
        );
        let static_marker = dir.path().join("marker-linker-static");
        let statik = build_fixture(dir.path(), "fx-static6", &static_marker, true);
        let mut command = reverie::process::Command::new(ldso.to_str().unwrap());
        command.arg(statik.to_str().unwrap());
        let err = PreloadBackend::run_with_preload::<EchoTool>(command, 7, preload)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("no PT_INTERP"),
            "ld.so + static target refusal: {err}"
        );
        assert!(!static_marker.exists(), "static target ran unconfined");
    }

    /// Runs `check` on another thread and fails the test, rather than
    /// hanging it, when the check does not return within ten seconds.
    fn within_deadline<T: Send + 'static>(
        what: &str,
        check: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(check());
        });
        receiver
            .recv_timeout(Duration::from_secs(10))
            .unwrap_or_else(|_| panic!("{what}: the static check blocked"))
    }

    #[test]
    fn guest_arguments_that_are_pipes_are_never_opened() {
        // A FIFO or pipe named as the first argument belongs to the
        // guest: opening a FIFO with no writer blocks, and reading a
        // pipe consumes the guest's input (`python3 /dev/stdin` lost its
        // first 20 bytes). Neither an ordinary program's arguments nor
        // ld.so's target may be opened unless they are regular files.
        // MUTATION ARM: open_regular checks the path before opening and
        // the opened file after; dropping both loses the pipe's bytes in
        // the ld.so case, and also dropping O_NONBLOCK blocks on the
        // FIFO. Either check alone keeps both cases correct.
        let dir = short_socket_tempdir();
        let marker = dir.path().join("marker");
        let dynamic = build_fixture(dir.path(), "fx-dynamic9", &marker, false);
        let ldso = fixture_ldso(&dynamic);
        let fifo = dir.path().join("fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        let (mut reader, mut writer) = std::io::pipe().unwrap();
        let input = b"AAAAAAAAAAAAAAAAAAAABBBB-rest-of-input\n";
        std::io::Write::write_all(&mut writer, input).unwrap();
        drop(writer);
        // The path /dev/stdin resolves to when the pipe is fd 0.
        let pipe = PathBuf::from(format!("/proc/self/fd/{}", reader.as_raw_fd()));
        for argument in [fifo, pipe] {
            for (program, expected) in [
                (dynamic.clone(), Ok(())),
                (ldso.clone(), Err(io::ErrorKind::Unsupported)),
            ] {
                let args = vec![argument.clone().into_os_string()];
                let result = within_deadline("pipe argument", move || {
                    refuse_static_target(&program, &args, None).map_err(|error| error.kind())
                });
                assert_eq!(result, expected, "{}", argument.display());
            }
        }
        let mut survived = Vec::new();
        reader.read_to_end(&mut survived).unwrap();
        assert_eq!(survived, input, "the guest's input was consumed");
    }

    #[tokio::test]
    async fn pipe_argument_keeps_its_input_through_launch() {
        // The reviewer's reproduction as a launch: `cat /dev/stdin` with
        // piped input must print every byte. /dev/stdin is a procfs link
        // to the launcher's fd 0, which the guest inherits; the same
        // link to the launcher's pipe, `/proc/<launcher>/fd/<n>`, names
        // one pipe for the check and the guest without replacing the
        // test harness's stdin.
        // MUTATION ARM: consulting linker_target for this dynamic
        // program and dropping both regular-file checks in open_regular
        // drops the first 20 bytes.
        #[derive(Default, Debug)]
        struct EchoGlobal;
        #[reverie::tool]
        impl reverie::GlobalTool for EchoGlobal {
            type Request = u64;
            type Response = u64;
            type Config = u64;
            async fn receive_rpc(&self, _from: reverie::Pid, message: u64) -> u64 {
                message
            }
        }
        #[derive(Default)]
        struct EchoTool;
        #[reverie::tool]
        impl reverie::Tool for EchoTool {
            type GlobalState = EchoGlobal;
            type ThreadState = ();
        }
        let dir = short_socket_tempdir();
        let preload = dir.path().join("preload.so");
        // A placeholder, not a shared object: a refused launch never
        // reads it, and ld.so ignores it ("file too short") in a launch
        // that runs, so the guest runs without the runtime.
        std::fs::write(&preload, b"placeholder").unwrap();
        let out = dir.path().join("out");
        let (reader, mut writer) = std::io::pipe().unwrap();
        let input = b"AAAAAAAAAAAAAAAAAAAABBBB-rest-of-input\n";
        std::io::Write::write_all(&mut writer, input).unwrap();
        drop(writer);
        let pipe = format!("/proc/{}/fd/{}", std::process::id(), reader.as_raw_fd());
        let mut command = reverie::process::Command::new("/bin/cat");
        command
            .arg(&pipe)
            .stdout(std::fs::File::create(&out).unwrap());
        let _ = PreloadBackend::run_with_preload::<EchoTool>(command, 7, preload).await;
        drop(reader);
        assert_eq!(std::fs::read(&out).unwrap(), input);
    }

    #[test]
    fn linker_options_match_glibc_rtld() {
        // ld.so's target is the first argument after the options glibc's
        // rtld accepts (`ld.so --help`, glibc 2.34). A value option
        // consumes its value even when the value names a dynamic ELF;
        // anything else that starts with `--` is not an ld.so option,
        // so no target is found and ld.so itself is refused.
        // MUTATION ARM: dropping `--audit` or a `--glibc-hwcaps-*` from
        // VALUE_OPTIONS, or skipping unknown options, admits the static
        // target behind them.
        let dir = short_socket_tempdir();
        let marker = dir.path().join("marker");
        let statik = build_fixture(dir.path(), "fx-static10", &marker, true).into_os_string();
        let dynamic = build_fixture(dir.path(), "fx-dynamic10", &marker, false).into_os_string();
        let ldso = fixture_ldso(Path::new(&dynamic));
        let check = |args: &[&OsStr]| {
            let args: Vec<OsString> = args.iter().map(|arg| arg.to_os_string()).collect();
            refuse_static_target(&ldso, &args, None).map_err(|error| error.kind())
        };
        let refused = Err(io::ErrorKind::Unsupported);
        for option in [
            "--argv0",
            "--audit",
            "--glibc-hwcaps-mask",
            "--glibc-hwcaps-prepend",
            "--inhibit-rpath",
            "--library-path",
            "--preload",
        ] {
            let option = OsStr::new(option);
            assert_eq!(check(&[option, &dynamic, &statik]), refused, "{option:?}");
            assert_eq!(check(&[option, &statik, &dynamic]), Ok(()), "{option:?}");
            assert_eq!(check(&[option]), refused, "{option:?} without a value");
        }
        for flag in [
            "--help",
            "--inhibit-cache",
            "--list",
            "--list-diagnostics",
            "--list-tunables",
            "--verify",
            "--version",
        ] {
            let flag = OsStr::new(flag);
            assert_eq!(check(&[flag, &statik]), refused, "{flag:?}");
            assert_eq!(check(&[flag, &dynamic]), Ok(()), "{flag:?}");
        }
        for unknown in [
            "--",
            "--argv0=name",
            "--bogus",
            "--hwcap",
            "--library-path=/nonexistent",
            "--platform",
        ] {
            let unknown = OsStr::new(unknown);
            assert_eq!(check(&[unknown, &dynamic]), refused, "{unknown:?}");
        }
    }

    #[test]
    fn elf32_phoff_reads_all_four_bytes() {
        // ELF32 e_phoff is four bytes. Here it is 0x10034: the real
        // table, past 64 KiB, holds only PT_LOAD, while a decoy
        // PT_INTERP sits at 0x34, where a two-byte read would look.
        // MUTATION ARM: reading e_phoff with read_u16 finds the decoy
        // and admits this static file.
        let dir = short_socket_tempdir();
        let mut bytes = vec![0u8; 0x10034 + 32];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 1;
        bytes[28..32].copy_from_slice(&0x10034u32.to_ne_bytes());
        bytes[42..44].copy_from_slice(&32u16.to_ne_bytes());
        bytes[44..46].copy_from_slice(&1u16.to_ne_bytes());
        bytes[0x34..0x38].copy_from_slice(&PT_INTERP.to_ne_bytes());
        bytes[0x10034..0x10038].copy_from_slice(&1u32.to_ne_bytes());
        let path = dir.path().join("elf32-phoff-high-half");
        std::fs::write(&path, bytes).unwrap();
        assert!(target_is_static(&path).unwrap());
        let error = refuse_static_target(&path, &[], None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
    }

    #[test]
    fn linker_target_resolves_against_command_directory() {
        // ld.so opens a relative target that contains a slash in the
        // guest's working directory, so the check resolves it there too.
        // A name without a slash it looks up as a library, never in a
        // directory (glibc 2.34: `cd /usr/bin && ld.so true` fails), so
        // it is no recognised target and ld.so itself is refused.
        // MUTATION ARM: resolving against the launcher's directory
        // refuses the dynamic case; resolving slash-less names admits
        // `fx-dynamic11`.
        let dir = short_socket_tempdir();
        let marker = dir.path().join("marker");
        build_fixture(dir.path(), "fx-static11", &marker, true);
        let dynamic = build_fixture(dir.path(), "fx-dynamic11", &marker, false);
        let ldso = fixture_ldso(&dynamic);
        let check = |name: &str, directory: Option<&Path>| {
            refuse_static_target(&ldso, &[OsString::from(name)], directory)
        };
        check("./fx-dynamic11", Some(dir.path())).unwrap();
        let error = check("./fx-static11", Some(dir.path())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        // From the launcher's directory the name finds nothing, so ld.so
        // has no recognised target and is refused itself.
        let error = check("./fx-dynamic11", None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let error = check("fx-dynamic11", Some(dir.path())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn script_interpreter_is_checked() {
        // The kernel runs a script's `#!` interpreter, so a static
        // interpreter would run unconfined just as a static program
        // would. The chain is followed, and parsed as load_script does.
        // MUTATION ARM: admitting a program once it has PT_INTERP or no
        // ELF magic, without following `#!`, admits every refused case.
        let dir = short_socket_tempdir();
        let marker = dir.path().join("marker");
        let statik = build_fixture(dir.path(), "fx-static12", &marker, true);
        let dynamic = build_fixture(dir.path(), "fx-dynamic12", &marker, false);
        let script = |name: &str, text: String| {
            let path = dir.path().join(name);
            std::fs::write(&path, text).unwrap();
            path
        };
        let refused = |path: &Path, directory: Option<&Path>, interpreter: &str| {
            let error = refuse_static_target(path, &[], directory).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
            assert!(error.to_string().contains(interpreter), "{error}");
        };
        let admitted = |path: &Path, directory: Option<&Path>| {
            refuse_static_target(path, &[], directory)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        };
        let s = statik.display();
        let d = dynamic.display();
        refused(&script("static", format!("#!{s}\n")), None, "fx-static12");
        refused(
            &script("static-arg", format!("#! \t{s} -x\necho\n")),
            None,
            "fx-static12",
        );
        refused(
            &script("static-unterminated", format!("#!{s}")),
            None,
            "fx-static12",
        );
        let relative = script("relative", "#!fx-static12\n".to_owned());
        refused(&relative, Some(dir.path()), "fx-static12");
        // Resolved against the launcher's directory, the name finds no
        // interpreter, and that exec fails before anything runs.
        admitted(&relative, None);
        let inner = script("inner", format!("#!{s}\n"));
        refused(
            &script("outer", format!("#!{}\n", inner.display())),
            None,
            "fx-static12",
        );
        admitted(&script("dynamic", format!("#!{d} -x\n")), None);
        let inner = script("inner-dynamic", format!("#!{d}\n"));
        admitted(
            &script("outer-dynamic", format!("#!{}\n", inner.display())),
            None,
        );
        // A name that may be truncated (no newline or terminator in the
        // first 256 bytes) is refused by the kernel (ENOEXEC).
        let long = format!("#!{s}{}", "/".repeat(300));
        admitted(&script("truncated", long), None);
        // A chain that names itself ends (the kernel fails it with ELOOP).
        let looped = dir.path().join("loop");
        std::fs::write(&looped, format!("#!{}\n", looped.display())).unwrap();
        admitted(&looped, None);
    }

    #[test]
    fn shebang_name_may_end_at_the_last_buffer_byte() {
        // Without a newline, the kernel's terminator search includes the
        // buffer's last byte (byte 255): a 255-byte script whose
        // 253-byte interpreter name ends at the NUL padding runs that
        // interpreter, so the check follows it too.
        // MUTATION ARM: excluding byte 255 from the line admits the
        // first two cases unchecked.
        let dir = short_socket_tempdir();
        let marker = dir.path().join("marker");
        let statik = build_fixture(dir.path(), "fx-static14", &marker, true);
        let prefix = dir.path().as_os_str().as_encoded_bytes().to_vec();
        let leaf = b"fx-static14";
        // Pad with repeated slashes so the path names the fixture and is
        // exactly 253 bytes long.
        let pad = 253 - prefix.len() - leaf.len();
        let mut name = prefix;
        name.extend(std::iter::repeat_n(b'/', pad));
        name.extend_from_slice(leaf);
        assert_eq!(name.len(), 253);
        use std::os::unix::ffi::OsStrExt;
        let named = std::fs::canonicalize(std::ffi::OsStr::from_bytes(&name)).unwrap();
        assert_eq!(named, std::fs::canonicalize(&statik).unwrap());
        let script = |file: &str, tail: &[u8]| {
            let path = dir.path().join(file);
            let mut bytes = b"#!".to_vec();
            bytes.extend_from_slice(&name);
            bytes.extend_from_slice(tail);
            std::fs::write(&path, bytes).unwrap();
            path
        };
        for (file, tail) in [
            ("exact-255", b"".as_slice()),
            ("space-at-255", b" -arg".as_slice()),
        ] {
            let error = refuse_static_target(&script(file, tail), &[], None).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{file}: {error}");
        }
        // A name still running at byte 255, with no newline, may be
        // truncated: the kernel refuses it (ENOEXEC), so nothing runs.
        refuse_static_target(&script("name-past-255", b"xyz"), &[], None).unwrap();
    }

    #[test]
    fn unknown_elf_class_is_refused() {
        // The kernel's ELF loader never reads EI_CLASS, so a static
        // executable with an unknown class byte still runs; the check
        // cannot read its headers and must refuse it, by name.
        // MUTATION ARM: treating an unknown class as "not an ELF"
        // admits every case here.
        let dir = short_socket_tempdir();
        let marker = dir.path().join("marker");
        let statik = build_fixture(dir.path(), "fx-static15", &marker, true);
        let original = std::fs::read(&statik).unwrap();
        for class in [0u8, 3, 255] {
            let path = dir.path().join(format!("class-{class}"));
            let mut bytes = original.clone();
            bytes[4] = class;
            std::fs::write(&path, bytes).unwrap();
            let error = refuse_static_target(&path, &[], None).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{class}: {error}");
            assert!(
                error
                    .to_string()
                    .contains(&format!("unknown ELF class {class}")),
                "{error}"
            );
            // The same file as a `#!` interpreter.
            let script = dir.path().join(format!("script-{class}"));
            std::fs::write(&script, format!("#!{}\n", path.display())).unwrap();
            let error = refuse_static_target(&script, &[], None).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{class}: {error}");
        }
    }
}
