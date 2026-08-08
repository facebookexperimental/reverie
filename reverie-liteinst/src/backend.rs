//! Coordinator-side implementation of Reverie's backend contract.

use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;
use std::future::Future;
use std::io;
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Output;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use reverie::Backend;
use reverie::BackendStatsRequest;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Tool;
use reverie::process::Command;
use reverie::process::Output as ReverieOutput;
use reverie::process::Stdio as ReverieStdio;
use reverie_ptrace::TracerBuilder;
use reverie_rpc_transport::ConnectionMonitor;
use reverie_rpc_transport::RpcServer;

/// Environment variable naming the tool-specific preload DSO for a backend run.
pub const TOOL_PRELOAD_ENV: &str = "REVERIE_LITEINST_TOOL_PRELOAD";
/// Environment variable passed to legacy tool preloads with the coordinator path.
///
/// The tool-data launcher uses a sealed inherited bootstrap instead.
pub const COORDINATOR_ENV: &str = "REVERIE_LITEINST_COORDINATOR";
/// Environment variable naming the optional, stats-only coordinator socket.
pub const STATS_COORDINATOR_ENV: &str = "REVERIE_LITEINST_STATS_COORDINATOR";

const PRELOAD_BOOTSTRAP_MAGIC: &[u8; 16] = b"REVERIE-LI-V1\0\0\0";
const PRELOAD_BOOTSTRAP_HEADER_BYTES: usize = PRELOAD_BOOTSTRAP_MAGIC.len() + 4;
const PRELOAD_BOOTSTRAP_MAX_BYTES: usize = 4096;
const RPC_CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

// TODO-HUMAN-REVIEW(PR-139): Review the public inherited preload bootstrap contract.
/// Coordinator path and tool-specific bytes consumed by a preload constructor.
pub struct PreloadBootstrap {
    /// Unix-domain socket path for the generic tool coordinator.
    pub coordinator: PathBuf,
    /// Opaque bytes supplied by the tool-specific coordinator launcher.
    pub tool_data: Vec<u8>,
}

// TODO-HUMAN-REVIEW(PR-139): Review the public inherited preload bootstrap consumer.
/// Consumes the inherited generic-tool bootstrap, if one is present.
///
/// # Safety
///
/// Call only from a preload constructor launched by LiteinstBackend; this scans
/// inherited descriptors and consumes only a sealed, protocol-matching memfd.
pub unsafe fn take_preload_bootstrap() -> io::Result<Option<PreloadBootstrap>> {
    let mut found = Vec::new();
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
                found.push((unsafe { OwnedFd::from_raw_fd(fd) }, bootstrap));
            }
            Ok(None) => {}
            Err(error) => {
                let _matching_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                return Err(error);
            }
        }
    }
    match found.len() {
        0 => Ok(None),
        1 => {
            let (_fd, bootstrap) = found.pop().unwrap();
            Ok(Some(bootstrap))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "multiple LiteInst preload bootstraps",
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
        _ => return Ok(None),
    };
    let mut packet = vec![0_u8; size];
    let read = unsafe { libc::pread(fd, packet.as_mut_ptr().cast(), packet.len(), 0) };
    if read != size as isize
        || packet.get(..PRELOAD_BOOTSTRAP_MAGIC.len()) != Some(PRELOAD_BOOTSTRAP_MAGIC)
    {
        return Ok(None);
    }

    let lengths = &packet[PRELOAD_BOOTSTRAP_MAGIC.len()..PRELOAD_BOOTSTRAP_HEADER_BYTES];
    let path_len = u16::from_le_bytes([lengths[0], lengths[1]]) as usize;
    let data_len = u16::from_le_bytes([lengths[2], lengths[3]]) as usize;
    if packet.len() != PRELOAD_BOOTSTRAP_HEADER_BYTES + path_len + data_len || path_len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid LiteInst preload bootstrap lengths",
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
            "LiteInst coordinator path exceeds the bootstrap limit",
        )
    })?;
    let data_len = u16::try_from(tool_data.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "LiteInst tool bootstrap data exceeds the bootstrap limit",
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
            "LiteInst preload bootstrap exceeds its size limit",
        ));
    }

    let fd = unsafe {
        libc::memfd_create(
            c"reverie-liteinst-bootstrap".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(&packet)?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(file.into())
}

// TODO-HUMAN-REVIEW(PR-127): Review LiteInst Backend lifecycle and preload contract.
/// Online LiteInst backend with a coordinator-owned `GlobalTool`.
pub struct LiteinstBackend;

impl LiteinstBackend {
    /// Runs a Tool under the ptrace-owned LiteInst hybrid runtime.
    ///
    /// Ptrace owns the sole Tool and GlobalTool from exec onward; the preload
    /// contributes only dynamic site installation and injected hot-site traps.
    /// This initial hybrid contract supports one tracee process with one thread;
    /// fork, vfork, and clone fail closed before either side is resumed.
    ///
    /// Trap markers, exact DSO addresses, mapping state, and an inner runtime
    /// call site provide strong accidental-collision resistance. They are not a
    /// security boundary against arbitrary code already executing in the guest.
    // TODO-HUMAN-REVIEW(PR-270): Review public host-hybrid launch API.
    pub async fn run_host_with_preload<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
    ) -> Result<(ExitStatus, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        let preload = configure_host_command(&mut command, preload.into())?;
        TracerBuilder::<T>::new(command)
            .config(config)
            .liteinst_runtime(
                preload,
                crate::runtime::HOST_BEGIN_MARKER,
                crate::runtime::HOST_READY_MARKER,
                crate::runtime::HOST_HELPER_RETURN_MARKER,
                crate::runtime::HOST_SYSCALL_MARKER,
            )
            .spawn()
            .await?
            .wait()
            .await
    }

    /// Runs the ptrace-owned LiteInst hybrid and returns typed backend statistics.
    ///
    /// This source fully accounts for the current hybrid because every installed
    /// hook returns through the ptrace-host SIGTRAP path. The in-guest Tool path
    /// keeps direct-hook counters in each guest process; exposing those after
    /// exit requires RPC aggregation and is deliberately not inferred here.
    pub async fn run_host_with_preload_and_stats<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
    ) -> Result<
        (
            ExitStatus,
            T::GlobalState,
            crate::LiteinstBackendStatsSource,
        ),
        Error,
    >
    where
        T: Tool + 'static,
    {
        let preload = configure_host_command(&mut command, preload.into())?;
        let tracer = TracerBuilder::<T>::new(command)
            .config(config)
            .liteinst_runtime_with_stats(
                preload,
                crate::runtime::HOST_BEGIN_MARKER,
                crate::runtime::HOST_READY_MARKER,
                crate::runtime::HOST_HELPER_RETURN_MARKER,
                crate::runtime::HOST_SYSCALL_MARKER,
                BackendStatsRequest::ENABLED,
            )
            .spawn()
            .await?;
        let stats = tracer
            .liteinst_instrumentation_stats()
            .expect("LiteInst runtime tracer must expose instrumentation statistics");
        let (status, global) = tracer.wait().await?;
        Ok((
            status,
            global,
            crate::LiteinstBackendStatsSource::from_ptrace_host_hybrid(stats.snapshot()),
        ))
    }

    /// Runs a Tool under the ptrace-owned LiteInst hybrid and captures output.
    ///
    /// The same single-process/single-thread and non-security-boundary contract
    /// as [`Self::run_host_with_preload`] applies.
    // TODO-HUMAN-REVIEW(PR-270): Review public host-hybrid output API.
    pub async fn run_host_with_output_and_preload<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
    ) -> Result<(ReverieOutput, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        command
            .stdout(ReverieStdio::piped())
            .stderr(ReverieStdio::piped());
        let preload = configure_host_command(&mut command, preload.into())?;
        TracerBuilder::<T>::new(command)
            .config(config)
            .liteinst_runtime(
                preload,
                crate::runtime::HOST_BEGIN_MARKER,
                crate::runtime::HOST_READY_MARKER,
                crate::runtime::HOST_HELPER_RETURN_MARKER,
                crate::runtime::HOST_SYSCALL_MARKER,
            )
            .spawn()
            .await?
            .wait_with_output()
            .await
    }

    /// Runs the ptrace-owned LiteInst hybrid, captures output, and returns typed statistics.
    pub async fn run_host_with_output_and_preload_and_stats<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
        preload: impl Into<PathBuf>,
    ) -> Result<
        (
            ReverieOutput,
            T::GlobalState,
            crate::LiteinstBackendStatsSource,
        ),
        Error,
    >
    where
        T: Tool + 'static,
    {
        command
            .stdout(ReverieStdio::piped())
            .stderr(ReverieStdio::piped());
        let preload = configure_host_command(&mut command, preload.into())?;
        let tracer = TracerBuilder::<T>::new(command)
            .config(config)
            .liteinst_runtime_with_stats(
                preload,
                crate::runtime::HOST_BEGIN_MARKER,
                crate::runtime::HOST_READY_MARKER,
                crate::runtime::HOST_HELPER_RETURN_MARKER,
                crate::runtime::HOST_SYSCALL_MARKER,
                BackendStatsRequest::ENABLED,
            )
            .spawn()
            .await?;
        let stats = tracer
            .liteinst_instrumentation_stats()
            .expect("LiteInst runtime tracer must expose instrumentation statistics");
        let (output, global) = tracer.wait_with_output().await?;
        Ok((
            output,
            global,
            crate::LiteinstBackendStatsSource::from_ptrace_host_hybrid(stats.snapshot()),
        ))
    }

    /// Runs a tool using an explicit tool-specific preload library.
    ///
    /// This path dispatches patchable syscalls in the guest and keeps the
    /// `GlobalTool` in this coordinator. The coordinator drains inherited RPC
    /// connections to follow process-like fork/clone3 descendants without
    /// attaching ptrace. Vfork is translated to a COW child and supports the
    /// child-exit completion boundary. Thread clone, exec rebootstrap, and
    /// unpatchable-site fallback remain unsupported.
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
            crate::LiteinstBackendStatsSource,
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
    ) -> Result<(Output, T::GlobalState, crate::LiteinstBackendStatsSource), Error>
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
}

fn configure_host_command(command: &mut Command, preload: PathBuf) -> io::Result<PathBuf> {
    if !preload.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("LiteInst host runtime {} is not a file", preload.display()),
        ));
    }
    let preload = preload.canonicalize()?;
    let mut ld_preload = preload.clone().into_os_string();
    if let Some(existing) = command
        .get_env("LD_PRELOAD")
        .or_else(|| std::env::var_os("LD_PRELOAD").map(Into::into))
        .filter(|value| !value.is_empty())
    {
        ld_preload.push(OsStr::new(":"));
        let existing: &OsStr = existing.as_ref();
        ld_preload.push(existing);
    }
    command
        .env("LD_PRELOAD", ld_preload)
        .env(crate::runtime::HOST_RUNTIME_ENV, "1");
    Ok(preload)
}

fn effective_command_env(command: &Command, key: &OsStr) -> Option<OsString> {
    command.get_captured_envs().remove(key)
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

fn inherit_stdio(command: &mut Command) {
    command.stdin(reverie::process::Stdio::inherit());
    command.stdout(reverie::process::Stdio::inherit());
    command.stderr(reverie::process::Stdio::inherit());
}

#[reverie::backend(?Send)]
impl Backend for LiteinstBackend {
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
}

enum ChildWait {
    Status(std::process::ExitStatus),
    Output(Output),
}

async fn serve_rpc_until<G, F, T>(
    server: RpcServer<G>,
    stats_server: Option<RpcServer<crate::stats::LiteinstStatsGlobal>>,
    connection_monitors: Vec<ConnectionMonitor>,
    completion: F,
) -> io::Result<T>
where
    G: GlobalTool + 'static,
    F: Future<Output = io::Result<T>>,
{
    serve_rpc_until_with_timeout(
        server,
        stats_server,
        connection_monitors,
        completion,
        RPC_CONNECTION_DRAIN_TIMEOUT,
    )
    .await
}

async fn serve_rpc_until_with_timeout<G, F, T>(
    server: RpcServer<G>,
    stats_server: Option<RpcServer<crate::stats::LiteinstStatsGlobal>>,
    connection_monitors: Vec<ConnectionMonitor>,
    completion: F,
    drain_timeout: Duration,
) -> io::Result<T>
where
    G: GlobalTool + 'static,
    F: Future<Output = io::Result<T>>,
{
    // JoinSet aborts the server if this future is cancelled. RpcServer::serve
    // owns the per-connection JoinSet, so aborting it also releases every
    // outstanding connection and its GlobalTool Arc.
    let mut serving = tokio::task::JoinSet::new();
    serving.spawn(server.serve());
    if let Some(stats_server) = stats_server {
        serving.spawn(stats_server.serve());
    }
    tokio::pin!(completion);

    let mut result = tokio::select! {
        biased;
        result = &mut completion => result,
        result = serving.join_next() => {
            let message = match result {
                Some(Ok(Ok(()))) => "LiteInst coordinator stopped unexpectedly".to_owned(),
                Some(Ok(Err(error))) => error.to_string(),
                Some(Err(error)) => error.to_string(),
                None => "LiteInst coordinator task disappeared".to_owned(),
            };
            return Err(io::Error::other(message));
        }
    };

    // A fork child inherits the parent's connected socket. If it later needs
    // its own identity, the client opens the replacement before dropping the
    // inherited descriptor. Consequently this count cannot transiently reach
    // zero while a supported descendant still owns coordinator state. Block
    // on last-close notifications instead of keeping this task runnable, but
    // fail closed after a finite interval if a descriptor is leaked.
    let drain = async {
        for monitor in &connection_monitors {
            monitor.wait_for_idle().await;
        }
    };
    tokio::pin!(drain);
    let drain_result = tokio::select! {
        biased;
        result = serving.join_next() => {
            let message = match result {
                Some(Ok(Ok(()))) => "LiteInst coordinator stopped unexpectedly".to_owned(),
                Some(Ok(Err(error))) => error.to_string(),
                Some(Err(error)) => error.to_string(),
                None => "LiteInst coordinator task disappeared".to_owned(),
            };
            return Err(io::Error::other(message));
        }
        result = tokio::time::timeout(drain_timeout, &mut drain) => result,
    };
    if drain_result.is_err() {
        let active_connections = connection_monitors
            .iter()
            .map(ConnectionMonitor::active_connections)
            .sum::<usize>();
        result = Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "LiteInst coordinator retained {active_connections} active RPC connection(s) for {}ms after guest exit",
                drain_timeout.as_millis()
            ),
        ));
    }

    serving.abort_all();
    while let Some(server_result) = serving.join_next().await {
        match server_result {
            Err(error) if error.is_cancelled() => {}
            Ok(Ok(())) => {
                return Err(io::Error::other(
                    "LiteInst coordinator stopped unexpectedly",
                ));
            }
            Ok(Err(error)) => return Err(io::Error::other(error.to_string())),
            Err(error) => return Err(io::Error::other(error.to_string())),
        }
    }
    result
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
        Option<crate::LiteinstBackendStatsSource>,
    ),
    Error,
>
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
    let arg0 = command.get_arg0().to_owned();
    let program = command.find_program()?;
    command.program(program).arg0(arg0);

    let directory = tempfile::Builder::new()
        .prefix("reverie-liteinst-")
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
            let mut child_command = command.try_into_std()?;
            child_command.env_remove(STATS_COORDINATOR_ENV);
            if let Some(stats_socket) = &stats_socket {
                child_command.env(STATS_COORDINATOR_ENV, stats_socket);
            }

            let bootstrap = create_preload_bootstrap(&socket, &tool_data)?;
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
            serve_rpc_until(server, stats_server, connection_monitors, async move {
                wait.await
                    .map_err(|error| io::Error::other(error.to_string()))?
            })
            .await?
        }
        None => {
            let mut child_command = command.try_into_std()?;
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
            serve_rpc_until(server, stats_server, connection_monitors, async move {
                wait.await
                    .map_err(|error| io::Error::other(error.to_string()))?
            })
            .await?
        }
    };
    if !connected.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "LiteInst guest exited before connecting to the coordinator; static executables and loader failures are unsupported",
        )
        .into());
    }
    let global = unwrap_global_after_connections(global).await?;
    let stats = match stats_global {
        Some(stats) => Some(unwrap_global_after_connections(stats).await?.into_source()),
        None => None,
    };
    Ok((wait, global, stats))
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

#[cfg(test)]
mod tests {
    use std::os::fd::IntoRawFd;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;
    use std::time::Duration;

    use reverie::Tid;
    use reverie_preload::rpc::CoordinatorClient;

    use super::*;

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

    #[tokio::test(flavor = "current_thread")]
    async fn coordinator_serves_multiple_local_rpc_connections() {
        let directory = tempfile::tempdir().unwrap();
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
            serve_rpc_until(server, None, connection_monitors, completion),
        )
        .await
        .expect("the second local RPC connection blocked at its config handshake")
        .unwrap();

        assert_eq!(global.total.load(Ordering::Relaxed), 5);
        assert_eq!(*global.senders.lock().unwrap(), [101, 202]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn coordinator_connection_drain_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
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

    #[test]
    fn rejects_and_closes_multiple_matching_bootstraps() {
        let first = create_preload_bootstrap(Path::new("/tmp/first.sock"), b"one")
            .unwrap()
            .into_raw_fd();
        let second = create_preload_bootstrap(Path::new("/tmp/second.sock"), b"two")
            .unwrap()
            .into_raw_fd();
        let third = create_preload_bootstrap(Path::new("/tmp/third.sock"), b"three")
            .unwrap()
            .into_raw_fd();

        let error = match unsafe { take_preload_bootstrap() } {
            Err(error) => error,
            Ok(_) => panic!("multiple matching bootstraps must fail"),
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "multiple LiteInst preload bootstraps");
        assert_eq!(unsafe { libc::fcntl(first, libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        assert_eq!(unsafe { libc::fcntl(second, libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        assert_eq!(unsafe { libc::fcntl(third, libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
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

    #[test]
    fn in_guest_preload_override_remove_and_clear_win_over_ambient() {
        const CHILD_ENV: &str = "REVERIE_LITEINST_PRELOAD_ENV_TEST_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "backend::tests::in_guest_preload_override_remove_and_clear_win_over_ambient",
                    "--test-threads=1",
                ])
                .env(CHILD_ENV, "1")
                .env("LD_PRELOAD", "libc.so.6")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
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
}
