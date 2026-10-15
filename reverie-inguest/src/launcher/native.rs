//! Shared native-target startup over the existing process/namespace owner.
//!
//! This module transfers kernel observations, not native launch authority.
//! The host admission owner must qualify the actual sealed artifacts and root
//! graph and retain the physical watch before acknowledging the child.

use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use reverie::process::Child;
use reverie::process::Command;
use reverie::process::Signal;
use reverie::process::TerminalExecve;
use reverie::syscalls::Errno;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const FRAME_MAGIC: &[u8; 8] = b"HLNROOT1";
const FRAME_BYTES: usize = 64;
const ACK: &[u8; 8] = b"HLNACK01";

/// Actual child/root observations; they never establish namespace authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRootObservation {
    /// Actual namespace-visible child process ID.
    pub pid: i32,
    /// Actual child thread ID; the first domain requires the leader.
    pub tid: i32,
    /// Device number of the transferred root directory.
    pub device: u64,
    /// Inode number of the transferred root directory.
    pub inode: u64,
    /// Actual root mount identity in the common container namespace.
    pub mount_id: u64,
    /// Device number of the retained actual mount namespace object.
    pub namespace_device: u64,
    /// Inode number of the retained actual mount namespace object.
    pub namespace_inode: u64,
}

/// Prebuilt child-side setup in the existing common container namespace.
///
/// # Safety
/// Implementations run after clone: all storage must already exist, and every
/// operation must allocate/free nothing, acquire no userspace lock and use no
/// formatter. The root descriptor/observations must refer to the actual child
/// and sealed common input graph; no extra namespace or placeholder PID is
/// permitted. Returned errors must have a raw OS errno. The frontend step
/// installs exactly one qualified inherited filter and the complete fixed gate
/// page; it must terminate via that gate after publication on any failure.
pub unsafe trait NativeGuestSetup: Send + Sync + 'static {
    /// Bind the actual task proc leaves and enter the prepared immutable root.
    ///
    /// # Safety
    /// The caller must invoke this exactly once in the actual cloned child,
    /// before frontend installation or runtime workers. The qualified root and
    /// prebuilt storage must remain owned through startup transfer. All child
    /// operations must obey the trait's allocation/lock/formatter restrictions
    /// and return only raw OS errno errors.
    unsafe fn bind_and_enter(&mut self) -> io::Result<NativeRootObservation>;
    /// Borrow the genuine entered root until the startup transfer is complete.
    fn root_descriptor(&self) -> BorrowedFd<'_>;
    /// Retire setup/root descriptor leases, then install the qualified frontend.
    /// Successful return precedes only the command's terminal target exec entry.
    ///
    /// # Safety
    /// The caller must have completed `bind_and_enter` in this same child and
    /// received the genuine parent startup ACK for its transferred root. The
    /// startup channel must be retired; no other filter may already be installed.
    /// Invoke this exactly once under the trait's fork-safe restrictions, then
    /// use only the qualified terminal exec entry. Implementations must retire
    /// setup leases and fail through the fixed gate after publication.
    unsafe fn install_frontend(&mut self) -> io::Result<()>;
}

/// Parent-side same-birth startup owner, shared with RPC/provider/watch state.
pub trait NativeStartAdmission: Send + Sync + 'static {
    /// Validate the actual child pidfd and root before ACK; retain its watch.
    ///
    /// The frame is not authority. The implementation compares kernel mount,
    /// root and task observations with independently held artifacts/input graph.
    /// This startup precedes filter installation; the actual Initial admission
    /// must additionally verify installed filter/maps before admitting Tool.
    fn observe_start(
        &self,
        peer: OwnedFd,
        root: OwnedFd,
        observation: NativeRootObservation,
    ) -> io::Result<()>;
    /// Poison the run on every startup/transport/child setup failure.
    fn startup_failed(&self);
}

/// Physical child owner. A cancelled owner kills and reaps its actual child.
/// The caller's existing bounded physical watch remains the deadline owner.
pub struct NativeChild {
    child: Option<Child>,
    admission: Arc<dyn NativeStartAdmission>,
}

#[derive(Clone, Copy)]
enum CancellationProbe {
    Reaped,
    Live,
    Error {
        errno: Option<i32>,
        kind: io::ErrorKind,
    },
}

#[derive(Clone, Copy)]
struct CancelledReap {
    probe: CancellationProbe,
    sigkill_requested: bool,
    signal_error: Option<(Option<i32>, io::ErrorKind)>,
}

fn diagnose_reaped(
    pid: reverie::Pid,
    status: reverie::ExitStatus,
    path: &'static str,
    cancellation: Option<CancelledReap>,
) {
    // Only call after the owned child has been reaped. The existing bounded
    // host diagnostic sink/deadline still governs emission; a blocked sink
    // must never delay killing or reaping a live owned child.
    if cancellation.is_none() && status.success() {
        return;
    }
    let sigkill_requested = cancellation.is_some_and(|reap| reap.sigkill_requested);
    let status_origin = if sigkill_requested {
        // The child may have exited independently after the live/error probe;
        // requesting SIGKILL does not establish what caused the observed exit.
        "observed_after_cleanup_attempt"
    } else {
        "original"
    };
    let (probe, probe_errno, probe_error_kind) = match cancellation.map(|reap| reap.probe) {
        None => ("not_requested", None, None),
        Some(CancellationProbe::Reaped) => ("reaped", None, None),
        Some(CancellationProbe::Live) => ("live", None, None),
        Some(CancellationProbe::Error { errno, kind }) => ("error", errno, Some(kind)),
    };
    let signal_error = cancellation.and_then(|reap| reap.signal_error);
    let core_dumped = match status {
        reverie::ExitStatus::Exited(_) => false,
        reverie::ExitStatus::Signaled(_, core) | reverie::ExitStatus::SignaledRaw(_, core) => core,
    };
    tracing::warn!(
        pid = pid.as_raw(),
        path,
        status_origin,
        raw_status = status.into_raw(),
        exit_code = ?status.code(),
        signal = ?status.signal(),
        core_dumped,
        probe,
        ?probe_errno,
        ?probe_error_kind,
        sigkill_requested,
        ?signal_error,
        "native physical child reaped"
    );
}

impl NativeChild {
    /// Actual physical child ID, unchanged across a successful native exec.
    pub fn id(&self) -> reverie::Pid {
        self.child.as_ref().expect("live native child owner").id()
    }

    /// Wait on the real child without converting RPC EOF into completion.
    pub async fn wait(mut self) -> io::Result<reverie::ExitStatus> {
        let child = self.child.as_mut().expect("live native child");
        let pid = child.id();
        let result = child.wait().await;
        if let Ok(status) = result {
            diagnose_reaped(pid, status, "wait", None);
            self.child.take();
        }
        result
    }

    /// Capture original command output while waiting on the real child.
    pub async fn wait_with_output(mut self) -> io::Result<reverie::process::Output> {
        use tokio::io::AsyncRead;
        use tokio::io::AsyncReadExt;
        async fn read<A: AsyncRead + Unpin>(handle: Option<A>) -> io::Result<Vec<u8>> {
            let mut bytes = Vec::new();
            if let Some(mut handle) = handle {
                handle.read_to_end(&mut bytes).await?;
            }
            Ok(bytes)
        }
        let child = self.child.as_mut().expect("live native child");
        drop(child.stdin.take());
        let stdout = read(child.stdout.take());
        let stderr = read(child.stderr.take());
        let pid = child.id();
        let wait = async {
            let status = child.wait().await?;
            // Pipe EOF may be delayed beyond the real child's death, and this
            // completion may then be cancelled. Diagnose the genuine wait now.
            diagnose_reaped(pid, status, "wait_with_output", None);
            Ok::<_, io::Error>(status)
        };
        let result = tokio::try_join!(wait, stdout, stderr).map(|(status, stdout, stderr)| {
            reverie::process::Output {
                status,
                stdout,
                stderr,
            }
        });
        if result.is_ok() {
            self.child.take();
        }
        result
    }
}

impl Drop for NativeChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let pid = child.id();
            // Capture only scalar state before poisoning/cleanup. try_wait may
            // itself reap, or return the cached result from wait_with_output.
            let probe = match child.try_wait() {
                Ok(Some(status)) => Ok(status),
                Ok(None) => Err(CancellationProbe::Live),
                Err(error) => Err(CancellationProbe::Error {
                    errno: error.raw_os_error(),
                    kind: error.kind(),
                }),
            };
            self.admission.startup_failed();
            match probe {
                Ok(status) => {
                    // Never signal or wait again using an already-reaped PID.
                    diagnose_reaped(
                        pid,
                        status,
                        "cancel",
                        Some(CancelledReap {
                            probe: CancellationProbe::Reaped,
                            sigkill_requested: false,
                            signal_error: None,
                        }),
                    );
                }
                Err(probe) => {
                    let signal_error = child
                        .signal(Signal::SIGKILL)
                        .err()
                        .map(|error| (error.raw_os_error(), error.kind()));
                    if let Ok(status) = child.wait_blocking() {
                        diagnose_reaped(
                            pid,
                            status,
                            "cancel",
                            Some(CancelledReap {
                                probe,
                                sigkill_requested: true,
                                signal_error,
                            }),
                        );
                    }
                    // A failed wait establishes no reap. Preserve the cleanup
                    // attempt without introducing possibly blocking emission.
                }
            }
        }
    }
}

/// Spawn the exact original command, with common-root startup authentication.
///
/// # Safety
/// The caller supplies a genuinely qualified setup and terminal execution
/// entry and retains all artifact/input pins through reap. The common outer
/// container setup has already finished before workers start. No existing
/// command filter may be stacked with this frontend. All original command
/// program/argv/env/cwd/stdio remain owned by `Command`; no helper is executed.
/// `entry` must issue the target exec at the inherited fixed gate and exit
/// there on kernel failure, never return into the ordinary spawn path.
pub unsafe fn spawn(
    mut command: Command,
    mut setup: Box<dyn NativeGuestSetup>,
    entry: TerminalExecve,
    admission: Arc<dyn NativeStartAdmission>,
) -> io::Result<NativeChild> {
    if !std::path::Path::new(command.get_program()).is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native target must be absolute",
        ));
    }
    let (parent, child_socket) = socket_pair()?;
    let parent_fd = parent.as_raw_fd();
    // SAFETY: the setup contract excludes allocation/locks; only fixed stack
    // frames and raw kernel transport run before original target execution.
    unsafe {
        command.pre_exec(move || {
            libc::close(parent_fd);
            let observation = setup.bind_and_enter().map_err(raw_errno)?;
            if observation.pid != libc::getpid()
                || observation.tid != libc::syscall(libc::SYS_gettid) as i32
                || observation.pid != observation.tid
            {
                return Err(Errno::EPERM);
            }
            send_root(
                child_socket.as_raw_fd(),
                setup.root_descriptor(),
                observation,
            )
            .map_err(raw_errno)?;
            receive_ack(child_socket.as_raw_fd()).map_err(raw_errno)?;
            // The startup channel never reaches guest code or the filter.
            libc::close(child_socket.as_raw_fd());
            setup.install_frontend().map_err(raw_errno)?;
            Ok(())
        });
        command.terminal_execve(entry);
    }
    // Any setup error closes the cloned socket at process exit. After filter
    // publication the terminal-entry/setup contract owns the raw fatal exit.
    let child = match command.spawn_with(|_| 126) {
        Ok(child) => child,
        Err(error) => {
            admission.startup_failed();
            return Err(error.into());
        }
    };
    // Drop only the parent's copied callback/FD owners after clone. The child's
    // owners remain alive until kernel exec; no child heap destructor is run.
    drop(command);
    let owner = NativeChild {
        child: Some(child),
        admission,
    };
    let observation_result = (|| {
        let pid = owner.id().as_raw();
        let (root, observation) = receive_root(parent.as_raw_fd(), pid)?;
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let peer = unsafe { OwnedFd::from_raw_fd(fd) };
        owner.admission.observe_start(peer, root, observation)?;
        let sent = unsafe {
            libc::send(
                parent.as_raw_fd(),
                ACK.as_ptr().cast(),
                ACK.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent != ACK.len() as isize {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "native startup ACK failed",
            ));
        }
        Ok(())
    })();
    observation_result?;
    Ok(owner)
}

fn raw_errno(error: io::Error) -> Errno {
    Errno::new(error.raw_os_error().unwrap_or(libc::EIO))
}

fn socket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let pair = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let on: libc::c_int = 1;
    if unsafe {
        libc::setsockopt(
            pair.0.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&on as *const libc::c_int).cast(),
            core::mem::size_of_val(&on) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let timeout = libc::timeval {
        tv_sec: STARTUP_TIMEOUT.as_secs() as _,
        tv_usec: 0,
    };
    if unsafe {
        libc::setsockopt(
            pair.1.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            core::mem::size_of_val(&timeout) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(pair)
}

fn frame(observation: NativeRootObservation) -> [u8; FRAME_BYTES] {
    let mut bytes = [0; FRAME_BYTES];
    bytes[..8].copy_from_slice(FRAME_MAGIC);
    bytes[8..12].copy_from_slice(&observation.pid.to_le_bytes());
    bytes[12..16].copy_from_slice(&observation.tid.to_le_bytes());
    for (part, value) in bytes[16..].as_chunks_mut::<8>().0.iter_mut().zip([
        observation.device,
        observation.inode,
        observation.mount_id,
        observation.namespace_device,
        observation.namespace_inode,
        0,
    ]) {
        *part = value.to_le_bytes();
    }
    bytes
}

fn send_root(fd: i32, root: BorrowedFd<'_>, observation: NativeRootObservation) -> io::Result<()> {
    let mut bytes = frame(observation);
    let mut control = [0_u64; 4];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { core::mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(core::mem::size_of::<i32>() as _) } as usize;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(core::mem::size_of::<i32>() as _) as usize;
        libc::CMSG_DATA(header)
            .cast::<i32>()
            .write_unaligned(root.as_raw_fd());
        if libc::sendmsg(fd, &message, libc::MSG_NOSIGNAL) != FRAME_BYTES as isize {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
    }
    Ok(())
}

fn receive_ack(fd: i32) -> io::Result<()> {
    let mut bytes = [0_u8; 9];
    let n = unsafe { libc::recv(fd, bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if n != ACK.len() as isize || &bytes[..ACK.len()] != ACK {
        return Err(io::Error::from_raw_os_error(libc::EPROTO));
    }
    Ok(())
}

fn receive_root(fd: i32, pid: i32) -> io::Result<(OwnedFd, NativeRootObservation)> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native root transfer timed out",
            ));
        }
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let status = unsafe { libc::poll(&raw mut poll, 1, remaining.as_millis().max(1) as i32) };
        if status < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if status <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native root transfer unavailable",
            ));
        }
        break;
    }
    let mut bytes = [0; FRAME_BYTES];
    let mut control = [0_u64; 16];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { core::mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = core::mem::size_of_val(&control);
    let n = unsafe { libc::recvmsg(fd, &raw mut message, libc::MSG_CMSG_CLOEXEC) };
    let mut roots = Vec::new();
    let mut credentials = None;
    let mut unknown = false;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            let length = (*header).cmsg_len;
            if length < libc::CMSG_LEN(0) as usize {
                unknown = true;
                break;
            }
            let payload = length - libc::CMSG_LEN(0) as usize;
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                if !payload.is_multiple_of(core::mem::size_of::<i32>()) {
                    unknown = true;
                }
                for offset in (0..payload).step_by(core::mem::size_of::<i32>()) {
                    let raw = libc::CMSG_DATA(header)
                        .add(offset)
                        .cast::<i32>()
                        .read_unaligned();
                    if raw < 0 {
                        unknown = true;
                    } else {
                        roots.push(OwnedFd::from_raw_fd(raw));
                    }
                }
            } else if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_CREDENTIALS
                && payload == core::mem::size_of::<libc::ucred>()
                && credentials.is_none()
            {
                credentials = Some(
                    libc::CMSG_DATA(header)
                        .cast::<libc::ucred>()
                        .read_unaligned(),
                );
            } else {
                unknown = true;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if n != FRAME_BYTES as isize
        || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || unknown
        || roots.len() != 1
        || credentials.is_none_or(|credential| credential.pid != pid)
        || &bytes[..8] != FRAME_MAGIC
        || bytes[56..] != [0; 8]
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "native root transfer refused",
        ));
    }
    let word = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let observation = NativeRootObservation {
        pid: i32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        tid: i32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        device: word(16),
        inode: word(24),
        mount_id: word(32),
        namespace_device: word(40),
        namespace_inode: word(48),
    };
    let root = roots.pop().unwrap();
    let mut stat: libc::stat = unsafe { core::mem::zeroed() };
    if observation.pid != pid
        || observation.tid != pid
        || observation.mount_id == 0
        || observation.namespace_inode == 0
        || unsafe { libc::fstat(root.as_raw_fd(), &raw mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_dev != observation.device
        || stat.st_ino != observation.inode
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "native root identity refused",
        ));
    }
    Ok((root, observation))
}

/// Output settings retained by the existing native run future.
pub struct NativeRunIo {
    /// The same optional statistics server and its existing admission owner.
    pub stats: Option<super::InitialImageStatsServer>,
    /// Capture the original command's stdout and stderr while waiting.
    pub capture_output: bool,
}

/// Actual physical child result from the shared native launch.
pub enum NativeRunOutput {
    /// Original command was run without capturing output.
    Status(reverie::ExitStatus),
    /// Original command's unchanged stdout/stderr and physical exit status.
    Output(reverie::process::Output),
}

/// Run one original native command with the same configured GlobalTool server.
///
/// The caller owns the actual prepared host admission, common root, DETLOG,
/// observer, provider and terminal physical watch. Their tasks/receipts remain
/// active through the real child wait and native registry completion; callers
/// must propagate their terminal drain failures before reporting success.
/// No GlobalTool is reconstructed, and no additional RPC client is created.
///
/// # Safety
/// All [`spawn`] contracts apply. Server native admissions, stats admission and
/// the startup owner must be the same actual retained run owner. The common
/// container setup and artifact/root/input qualification precede this call.
pub async unsafe fn run_native<G: reverie::GlobalTool + 'static>(
    mut command: Command,
    setup: Box<dyn NativeGuestSetup>,
    entry: TerminalExecve,
    admission: Arc<dyn NativeStartAdmission>,
    mut server: reverie_rpc_transport::RpcServer<G>,
    output: NativeRunIo,
    global: &Arc<G>,
) -> io::Result<NativeRunOutput> {
    let NativeRunIo {
        stats,
        capture_output,
    } = output;
    if !Arc::ptr_eq(global, &server.global()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native RPC GlobalTool owner differs",
        ));
    }
    let issues = server.retain_connection_issues();
    let mut monitors = vec![server.connection_monitor()];
    let (stats_server, stats_issues) = match stats {
        Some(stats) => {
            monitors.push(stats.connection_monitor());
            (Some(stats.server), Some(stats.issues))
        }
        None => (None, None),
    };
    if capture_output {
        command
            .stdout(reverie::process::Stdio::piped())
            .stderr(reverie::process::Stdio::piped());
    }
    // Startup is synchronous and bounded by the real STARTUP_TIMEOUT receive.
    // The child waits only for the root admission ACK, so RPC serving is not
    // required before this returns. Keep Command's owned CString pointers in
    // their actual thread instead of inventing Send for an unrelated API.
    let child = unsafe { spawn(command, setup, entry, admission) }?;
    let completion = async move {
        if capture_output {
            child.wait_with_output().await.map(NativeRunOutput::Output)
        } else {
            child.wait().await.map(NativeRunOutput::Status)
        }
    };
    let tool_failure = super::backend_failure(global);
    let failure = async {
        tokio::select! {
            biased;
            () = tool_failure => {},
            () = issues.failed() => {},
            () = async {
                match &stats_issues {
                    Some(monitor) => monitor.failed().await,
                    None => std::future::pending::<()>().await,
                }
            } => {},
        }
    };
    let output =
        super::serve_rpc_until(server, stats_server, monitors, completion, failure).await?;
    if !issues.snapshot().is_empty()
        || stats_issues
            .as_ref()
            .is_some_and(|monitor| !monitor.snapshot().is_empty())
    {
        return Err(io::Error::other(
            "native RPC connection retained a terminal issue",
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OutputMechanicsAdmission;
    impl NativeStartAdmission for OutputMechanicsAdmission {
        fn observe_start(
            &self,
            _: OwnedFd,
            _: OwnedFd,
            _: NativeRootObservation,
        ) -> io::Result<()> {
            Err(io::Error::other(
                "ordinary child capture control has no native admission",
            ))
        }
        fn startup_failed(&self) {}
    }

    #[tokio::test(flavor = "current_thread")]
    async fn guarded_ordinary_child_captures_distinct_stdout_and_stderr() {
        // A real ordinary child tests this guard's borrowed wait/read ownership.
        // It does not install a native frontend or exercise native exec proof.
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf output-marker; printf error-marker >&2"]);
        command
            .stdout(reverie::process::Stdio::piped())
            .stderr(reverie::process::Stdio::piped());
        let child = command.spawn().unwrap();
        let pid = child.id().as_raw();
        let guarded = NativeChild {
            child: Some(child),
            admission: Arc::new(OutputMechanicsAdmission),
        };
        let (captured, subscriber) = capture_diagnostics(pid, None);
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let output = tokio::time::timeout(Duration::from_secs(5), guarded.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"output-marker");
        assert_eq!(output.stderr, b"error-marker");
        assert!(
            captured.text().is_empty(),
            "uncancelled exit zero must stay quiet"
        );
    }

    #[derive(Default)]
    struct CountingAdmission(std::sync::atomic::AtomicUsize);

    impl NativeStartAdmission for CountingAdmission {
        fn observe_start(
            &self,
            _: OwnedFd,
            _: OwnedFd,
            _: NativeRootObservation,
        ) -> io::Result<()> {
            Err(io::Error::other("ordinary child has no native admission"))
        }

        fn startup_failed(&self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn assert_reaped(pid: i32) {
        let mut status = 0;
        // SAFETY: this only observes the exact ordinary child owned by a test.
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert_eq!(result, -1, "diagnostic precedes reap of child {pid}");
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    struct DiagnosticCapture {
        pid: i32,
        bytes: std::sync::Mutex<Vec<u8>>,
        before_write: Option<Box<dyn Fn() + Send + Sync>>,
    }

    impl DiagnosticCapture {
        fn text(&self) -> String {
            String::from_utf8(self.bytes.lock().unwrap().clone()).unwrap()
        }
    }

    struct DiagnosticWriter(Arc<DiagnosticCapture>);

    impl io::Write for DiagnosticWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            // Every actual sink write must be after the kernel reap, even
            // when this writer deliberately blocks below.
            assert_reaped(self.0.pid);
            if let Some(before_write) = &self.0.before_write {
                before_write();
            }
            self.0.bytes.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn capture_diagnostics(
        pid: i32,
        before_write: Option<Box<dyn Fn() + Send + Sync>>,
    ) -> (
        Arc<DiagnosticCapture>,
        impl tracing::Subscriber + Send + Sync,
    ) {
        let captured = Arc::new(DiagnosticCapture {
            pid,
            bytes: std::sync::Mutex::new(Vec::new()),
            before_write,
        });
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || DiagnosticWriter(writer.clone()))
            .finish();
        (captured, subscriber)
    }

    fn live_ordinary_child() -> Child {
        let mut command = Command::new("/bin/cat");
        command
            .stdin(reverie::process::Stdio::piped())
            .stdout(reverie::process::Stdio::null())
            .stderr(reverie::process::Stdio::null());
        // The retained stdin writer prevents EOF until cancellation.
        command.spawn().unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn guarded_ordinary_child_preserves_nonzero_exit_and_diagnostic() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf known-exit >&2; exit 73"]);
        command
            .stdout(reverie::process::Stdio::piped())
            .stderr(reverie::process::Stdio::piped());
        let child = command.spawn().unwrap();
        let pid = child.id().as_raw();
        let admission = Arc::new(CountingAdmission::default());
        let guarded = NativeChild {
            child: Some(child),
            admission: admission.clone(),
        };
        let (captured, subscriber) = capture_diagnostics(pid, None);
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let output = tokio::time::timeout(Duration::from_secs(5), guarded.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(output.status, reverie::ExitStatus::Exited(73));
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"known-exit");
        assert_eq!(admission.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        let logs = captured.text();
        assert!(logs.contains("status_origin=\"original\""), "{logs}");
        assert!(logs.contains("raw_status=18688"), "{logs}");
        assert!(logs.contains("exit_code=Some(73)"), "{logs}");
        assert!(logs.contains("signal=None"), "{logs}");
        assert!(logs.contains("core_dumped=false"), "{logs}");
        assert!(logs.contains("sigkill_requested=false"), "{logs}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn guarded_ordinary_child_preserves_known_signal_and_diagnostic() {
        let child = live_ordinary_child();
        let pid = child.id().as_raw();
        let admission = Arc::new(CountingAdmission::default());
        let guarded = NativeChild {
            child: Some(child),
            admission: admission.clone(),
        };
        // An independently requested, unmaskable signal is the original
        // status here, not a cancellation cleanup signal.
        guarded
            .child
            .as_ref()
            .unwrap()
            .signal(Signal::SIGKILL)
            .unwrap();
        let (captured, subscriber) = capture_diagnostics(pid, None);
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let status = tokio::time::timeout(Duration::from_secs(5), guarded.wait())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            status,
            reverie::ExitStatus::Signaled(Signal::SIGKILL, false)
        );
        assert_eq!(admission.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        let logs = captured.text();
        assert!(logs.contains("status_origin=\"original\""), "{logs}");
        assert!(logs.contains("raw_status=9"), "{logs}");
        assert!(logs.contains("exit_code=None"), "{logs}");
        assert!(logs.contains("signal=Some(9)"), "{logs}");
        assert!(logs.contains("core_dumped=false"), "{logs}");
        assert!(logs.contains("sigkill_requested=false"), "{logs}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cached_wait_is_diagnosed_before_pipe_eof_and_cancel_does_not_kill_again() {
        use std::future::Future;
        use std::task::Poll;

        // Retain a real writer for this exact pipe in the parent. EOF stays
        // pending without spawning an orphan or borrowing another child.
        let mut pipe = [-1; 2];
        // SAFETY: pipe points to two writable descriptor slots. Each returned
        // descriptor is transferred exactly once to an OwnedFd below.
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let reader = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        let held_writer = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 29"]);
        command.stdout(reverie::process::Stdio::from(
            held_writer.try_clone().unwrap(),
        ));
        let mut child = command.spawn().unwrap();
        child.stdout = Some(reverie::process::ChildStdout::from(reader));
        drop(command);
        let pid = child.id().as_raw();
        let admission = Arc::new(CountingAdmission::default());
        let mut guarded = NativeChild {
            child: Some(child),
            admission: admission.clone(),
        };
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(5),
                guarded.child.as_mut().unwrap().wait(),
            )
            .await
            .unwrap()
            .unwrap(),
            reverie::ExitStatus::Exited(29)
        );
        let (captured, subscriber) = capture_diagnostics(pid, None);
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let mut completion = Box::pin(guarded.wait_with_output());
        std::future::poll_fn(|cx| {
            assert!(completion.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let before_eof = captured.text();
        assert!(
            before_eof.contains("path=\"wait_with_output\""),
            "{before_eof}"
        );
        assert!(before_eof.contains("exit_code=Some(29)"), "{before_eof}");
        assert_eq!(admission.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        drop(completion);
        assert_eq!(admission.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        let logs = captured.text();
        assert!(logs.contains("path=\"cancel\""), "{logs}");
        assert!(logs.contains("probe=\"reaped\""), "{logs}");
        assert!(logs.contains("sigkill_requested=false"), "{logs}");
        assert!(
            !logs.contains("status_origin=\"observed_after_cleanup_attempt\""),
            "{logs}"
        );
        assert!(!logs.contains("signal_error=Some"), "{logs}");
        assert_reaped(pid);
        drop(held_writer);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn live_cancel_reaps_before_a_blocked_diagnostic_sink() {
        use std::sync::atomic::AtomicBool;
        use std::sync::atomic::Ordering;
        use std::sync::mpsc;

        let child = live_ordinary_child();
        let pid = child.id().as_raw();
        let admission = Arc::new(CountingAdmission::default());
        let mut guarded = NativeChild {
            child: Some(child),
            admission: admission.clone(),
        };
        assert!(
            guarded
                .child
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none()
        );
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = std::sync::Mutex::new(release_rx);
        let blocked = AtomicBool::new(false);
        let poisoned = admission.clone();
        let before_write = Box::new(move || {
            if !blocked.swap(true, Ordering::SeqCst) {
                assert_eq!(poisoned.0.load(Ordering::SeqCst), 1);
                entered_tx.send(()).unwrap();
                release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap();
            }
        });
        let (captured, subscriber) = capture_diagnostics(pid, Some(before_write));
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let poisoned = admission.clone();
        let release = std::thread::spawn(move || {
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            // The sink is now blocked, but poisoning and the actual kernel
            // reap must already be complete, not waiting on log progress.
            assert_eq!(poisoned.0.load(Ordering::SeqCst), 1);
            assert_reaped(pid);
            release_tx.send(()).unwrap();
        });
        drop(guarded);
        release.join().unwrap();
        assert_eq!(admission.0.load(Ordering::SeqCst), 1);
        assert_reaped(pid);
        let logs = captured.text();
        assert!(
            logs.contains("status_origin=\"observed_after_cleanup_attempt\""),
            "{logs}"
        );
        assert!(logs.contains("probe=\"live\""), "{logs}");
        assert!(logs.contains("sigkill_requested=true"), "{logs}");
        assert!(logs.contains("signal=Some(9)"), "{logs}");
        assert!(!logs.contains("status_origin=\"original\""), "{logs}");
    }
}
