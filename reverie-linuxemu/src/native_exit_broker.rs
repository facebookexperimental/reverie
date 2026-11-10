//! Private source candidate for native terminal socket-reference retirement.
//!
//! This module does not install a runtime, start a guest, or publish a guest
//! terminal receipt. The caller supplies exclusive startup authority and owns a
//! continuously running dispatcher. Every job and its original socket-reference
//! vector remain in that dispatcher until completion or explicit retained error;
//! dropping a waiting future must not drop them. See `JobProgress`.
//!
//! Bootstrap and explicit exec-client setup may wait before guest admission.
//! Parent-side job methods use nonblocking
//! internal socket I/O. `advance` retires original socket references only after
//! the worker has acknowledged the complete transferred set. The trusted worker
//! then exits natively, and the broker's actual wait result completes the job.
//! Unexpected external worker destruction between ACK and parent retirement is
//! an adverse-host failure; ACK is not an unkillable kernel reference lease.
//! An explicit `BrokerOwner::abort_failed_invocation` is also a fatal event,
//! never a successful cleanup: it can destroy acknowledged worker references
//! before a surviving client retires its originals. Surviving clients and their
//! resources are unconfirmed; the abort does not revoke all guest execution.
//!
//! Broker control/job channels, identity pidfds and exported client channels
//! can outlive a single call. `reverie_process::launch_window` protects transient
//! opens, not these long-lived owners. CLOEXEC does not isolate a forked tracee
//! that never execs, such as `reverie_ptrace::spawn_fn_with_config`; this module
//! does not arrange their exclusion from that child. Embedders must keep live
//! broker use separate from such in-process no-exec launches unless they provide
//! that exclusion for every broker descriptor throughout the launch. Neither
//! the launch-window guard nor descriptor numbering establishes that isolation.

#[path = "native_exit_broker/bootstrap.rs"]
mod bootstrap;
#[path = "native_exit_broker/exec_client.rs"]
mod exec_client;
#[path = "native_exit_broker/raw.rs"]
mod raw;
use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::sync::Arc;

pub use bootstrap::AmbientClass;
pub use bootstrap::AmbientDescriptor;
pub use bootstrap::BootstrapFailure;
pub use bootstrap::StartupAuthority;
pub use exec_client::ExecBrokerClient;
pub use exec_client::ExecClientFailure;

/// A syscall/protocol error. The job and caller-owned reference vector are not
/// consumed by this value; the dispatcher must retain both on every error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreError {
    pub operation: &'static str,
    pub errno: i32,
}

impl CoreError {
    pub fn is_retryable_resource(&self) -> bool {
        matches!(
            self.errno,
            libc::EINTR
                | libc::EAGAIN
                | libc::EMFILE
                | libc::ENFILE
                | libc::ENOMEM
                | libc::ETOOMANYREFS
        )
    }

    fn last(operation: &'static str) -> Self {
        Self {
            operation,
            errno: io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO),
        }
    }

    fn protocol(operation: &'static str) -> Self {
        Self {
            operation,
            errno: libc::EPROTO,
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "native terminal socket broker {}: {}",
            self.operation,
            io::Error::from_raw_os_error(self.errno)
        )
    }
}

impl std::error::Error for CoreError {}

/// The task's actual reference, including an existing shared Rust owner. The
/// core never claims that another Arc/OFD owner is also retiring.
#[derive(Debug)]
pub enum SocketReference {
    Owned(File),
    Shared(Arc<File>),
}

impl AsRawFd for SocketReference {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Owned(file) => file.as_raw_fd(),
            Self::Shared(file) => file.as_raw_fd(),
        }
    }
}

/// Read-only exact socket-file classification. ENOTSOCK is the ordinary negative
/// result; every other query error is returned with the original owner intact.
pub fn is_socket_file(fd: RawFd) -> Result<bool, CoreError> {
    let mut kind: libc::c_int = 0;
    let mut size = size_of::<libc::c_int>() as libc::socklen_t;
    // SO_TYPE is immutable and does not clear an error or change an option.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut size,
        )
    };
    if rc == 0 {
        if size as usize != size_of::<libc::c_int>() {
            return Err(CoreError::protocol("SO_TYPE output size"));
        }
        return Ok(true);
    }
    let error = CoreError::last("SO_TYPE");
    if error.errno == libc::ENOTSOCK {
        Ok(false)
    } else {
        Err(error)
    }
}

/// One bootstrap-owned native child. The original launcher must retain this
/// handle and repeatedly try_wait after shutdown; clients cannot reap it. This
/// deliberately has no blocking Drop. Normal completion requires actual reap.
/// An unconfirmed owner must remain retained unless its exact creator explicitly
/// elects fatal whole-invocation failure with `abort_failed_invocation`; that
/// exception supplies no successful cleanup or all-descendants-stopped receipt.
#[must_use = "retain through actual broker reap or explicit fatal invocation abort"]
pub struct BrokerOwner {
    pid: libc::pid_t,
    client: BrokerClient,
    reaped: bool,
    pidfd: Option<Arc<OwnedFd>>,
    ambient: Vec<AmbientDescriptor>,
    creator_pid: libc::pid_t,
    creator_tid: libc::pid_t,
    _creator_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl BrokerOwner {
    fn check_owner(&self) -> Result<(), CoreError> {
        if unsafe { libc::getpid() } != self.creator_pid
            || unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t != self.creator_tid
        {
            return Err(CoreError::protocol(
                "native broker owner changed process/thread",
            ));
        }
        Ok(())
    }

    /// Create the clean broker before guest resources and other threads exist.
    /// `authority` asserts the complete startup contract; a task-count sample is
    /// not a substitute. Bootstrap blocks signals temporarily and may wait for
    /// child setup. It is never called from a Tool callback or a lazy constructor.
    /// Ambient inode queries are restricted to kernel-identified local
    /// filesystems (ext2/3/4, btrfs, tmpfs, devtmpfs and devpts). Character
    /// nodes on other filesystems and mounts absent from mountinfo are refused;
    /// internal shmem remains supported through the kernel F_GET_SEALS query.
    /// O_PATH, sockets and pipes retain their separate classification paths.
    pub fn bootstrap(authority: StartupAuthority) -> Result<Self, BootstrapFailure> {
        bootstrap::start(authority)
    }

    pub fn client(&self) -> BrokerClient {
        self.client.clone()
    }

    pub fn ambient_descriptors(&self) -> &[AmbientDescriptor] {
        &self.ambient
    }

    pub fn native_pid(&self) -> libc::pid_t {
        self.pid
    }

    /// Abort this entire failed launcher invocation without ordinary Rust
    /// destruction, broker SHUTDOWN, or an invented native-wait receipt.
    ///
    /// The exact original creator process/thread is checked before any effect.
    /// On a mismatch the error returns this same owner, still unreleased. On
    /// admission the native exit_group(125) syscall does not return. Native
    /// process death may kill broker/workers before live clients retire their
    /// originals; such clients, descendants and cleanup remain unconfirmed.
    /// This operation does not promise bounded kernel exit or an observed 125
    /// status: only an actual external wait can establish the latter.
    ///
    /// # Safety
    /// The caller must have selected terminal failure of the whole current
    /// launcher invocation, preserve its primary error/panic and every pending
    /// owner through this call, and prevent its evidence from claiming success.
    /// It must not use this as normal completion, a retry, or library cleanup.
    /// Abort does not establish that affected clients stopped or were reaped:
    /// the caller explicitly elects failed invocation termination with possible
    /// unconfirmed survivors. Normal completion still requires its actual
    /// stop/reap proofs. This exception accepts destruction of the failed broker
    /// domain, including the post-ACK window documented above. No successful
    /// receipt/publication predicate is relaxed.
    pub unsafe fn abort_failed_invocation(
        self,
    ) -> Result<std::convert::Infallible, (CoreError, Self)> {
        if let Err(error) = self.check_owner() {
            return Err((error, self));
        }
        let _retained = std::mem::ManuallyDrop::new(self);
        // SAFETY: the caller authorizes fatal whole-invocation termination;
        // exact creator identity was checked and no owner is ordinarily dropped.
        unsafe { raw::exit(125) }
    }

    /// Nonblocking shutdown request. The daemon reaps outstanding native jobs
    /// before exiting. Call only after every producer of new jobs is stopped.
    pub fn request_shutdown(&self) -> Result<bool, CoreError> {
        self.check_owner()?;
        let frame = raw::Frame::new(raw::SHUTDOWN, 0, 0, 0);
        send(
            self.client.control.as_raw_fd(),
            &frame,
            &[],
            "broker shutdown",
        )
    }

    pub fn shutdown_poll_interest(&self) -> libc::pollfd {
        libc::pollfd {
            fd: self.client.control.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        }
    }

    pub fn exit_poll_interest(&self) -> Option<libc::pollfd> {
        self.pidfd.as_ref().map(|fd| libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
    }

    /// Actual native child wait, without blocking a current-thread executor.
    pub fn try_wait(&mut self) -> Result<Option<i32>, CoreError> {
        self.check_owner()?;
        if self.reaped {
            return Err(CoreError::protocol("broker already reaped"));
        }
        let mut status = 0;
        let rc = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG | libc::__WCLONE) };
        if rc == 0 {
            return Ok(None);
        }
        if rc == self.pid {
            self.reaped = true;
            return Ok(Some(status));
        }
        let error = CoreError::last("waitpid broker");
        if error.errno == libc::EINTR {
            Ok(None)
        } else {
            Err(error)
        }
    }
}

/// Native broker identity authenticated by bootstrap ownership or the
/// registered exec session. The pid is diagnostic; signaling uses this held
/// pidfd, never a reopened numeric PID. This is not a guest process identity.
#[derive(Debug)]
pub struct BrokerIdentity {
    pid: libc::pid_t,
    pidfd: Arc<OwnedFd>,
}

impl BrokerIdentity {
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }
    pub fn pidfd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_ref().as_fd()
    }
}

#[derive(Clone)]
pub struct BrokerClient {
    control: Arc<OwnedFd>,
    process: libc::pid_t,
    identity: Option<Arc<BrokerIdentity>>,
}

impl BrokerClient {
    /// A partially failed bootstrap owner has no authenticated identity. Do
    /// not substitute an environment PID or the launcher-created channel's
    /// SO_PEERPIDFD, whose recorded peer would be the launcher itself.
    pub fn authenticated_broker_identity(&self) -> Result<&BrokerIdentity, CoreError> {
        if unsafe { libc::getpid() } != self.process {
            return Err(CoreError::protocol("fork-inherited broker identity"));
        }
        self.identity.as_deref().ok_or_else(|| {
            CoreError::protocol("broker identity unavailable before completed setup")
        })
    }

    /// Reserve one empty native worker before guest admission. Only internal
    /// channels are allocated here; no terminal File owners can be dropped on
    /// failure. The task service drives advance_reservation until real READY.
    /// A later contiguous socket group may reserve another worker during owned
    /// cleanup; retryable setup failures remain pending with retained owners.
    pub fn reserve_worker(&self) -> Result<NativeExitJob, CoreError> {
        if unsafe { libc::getpid() } != self.process {
            return Err(CoreError::protocol(
                "fork-inherited client requires authenticated adoption",
            ));
        }
        let _identity = self.authenticated_broker_identity()?;
        Ok(NativeExitJob {
            client: self.clone(),
            channels: Some(Channels::new()?),
            expected_owners: None,
            identity: Vec::new(),
            transfer: Vec::new(),
            sent: 0,
            job: 0,
            worker_pid: None,
            stage: JobStage::Request,
            parent_references_retired: false,
            unexpected_rights: Vec::with_capacity(raw::MAX_RIGHTS),
            failure: None,
            last_native_status: None,
            worker_channel_closed: false,
            retry_deadline: None,
            backoff: std::time::Duration::from_millis(1),
            retry_reason: None,
            attempts: 1,
        })
    }
}

struct Channels {
    data: Option<OwnedFd>,
    completion: OwnedFd,
    request_rights: Option<(OwnedFd, OwnedFd)>,
}

impl Channels {
    fn new() -> Result<Self, CoreError> {
        let (data, worker_data) = socket_pair()?;
        let (completion, broker_completion) = socket_pair()?;
        Ok(Self {
            data: Some(data),
            completion,
            request_rights: Some((worker_data, broker_completion)),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobStage {
    Request,
    AwaitReady,
    Ready,
    Begin,
    Transfer,
    ChunkAcknowledgement,
    FinalAcknowledgement,
    Go,
    NativeWait,
    Abort,
    AbortWait,
    Restart,
    CancelWait,
    Cancelled,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationProgress {
    Pending,
    Ready,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmptyCancellationProgress {
    Pending,
    /// None proves no request was committed / no worker created; Some is an
    /// actual native wait for the empty worker, including its exact status.
    Complete(Option<NativeExitReceipt>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeExitReceipt {
    pub job: u64,
    pub native_pid: libc::pid_t,
    /// Actual wait status, never EOF, pidfd readiness or an about-to-exit marker.
    pub raw_wait_status: i32,
    /// Number of references supplied for this batch, not a claim of retirement.
    pub socket_references: usize,
    /// Distinct descriptor prefix authenticated by complete chunk ACKs in this
    /// attempt. Unacknowledged SCM_RIGHTS prefixes are deliberately not counted.
    pub acknowledged_descriptors: usize,
    /// True only after the complete final ACK allowed the original vector to
    /// be retired. An aborted attempt retains those originals for its retry.
    pub parent_references_retired: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobProgress {
    Pending,
    Complete(NativeExitReceipt),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetryReason {
    Resource(CoreError),
    /// recvmsg hides the underlying cause. Do not call this a measured EMFILE:
    /// security_file_receive or fd-table pressure can both truncate SCM_RIGHTS.
    IncompleteAncillaryTransfer,
    WorkerExitedBeforeRetirement {
        raw_wait_status: i32,
    },
}

/// The prestarted task service owns this object and the complete original Vec
/// independently of its waiting future. Errors never consume them. In a fatal
/// retained state they move to that run's existing reaper, which must not drop
/// them or report a receipt merely because cleanup cannot currently progress.
#[must_use = "the task service/reaper owns cleanup independently of its waiter"]
pub struct NativeExitJob {
    client: BrokerClient,
    channels: Option<Channels>,
    expected_owners: Option<usize>,
    identity: Vec<RawFd>,
    transfer: Vec<RawFd>,
    sent: usize,
    job: u64,
    worker_pid: Option<libc::pid_t>,
    stage: JobStage,
    parent_references_retired: bool,
    unexpected_rights: Vec<OwnedFd>,
    failure: Option<CoreError>,
    last_native_status: Option<NativeExitReceipt>,
    worker_channel_closed: bool,
    retry_deadline: Option<std::time::Instant>,
    backoff: std::time::Duration,
    retry_reason: Option<RetryReason>,
    attempts: u64,
}

impl NativeExitJob {
    pub fn stage(&self) -> JobStage {
        self.stage
    }
    pub fn failure(&self) -> Option<&CoreError> {
        self.failure.as_ref()
    }
    pub fn parent_references_retired(&self) -> bool {
        self.parent_references_retired
    }
    pub fn retained_unexpected_rights(&self) -> &[OwnedFd] {
        &self.unexpected_rights
    }
    pub fn take_retained_unexpected_rights(&mut self) -> Vec<OwnedFd> {
        std::mem::take(&mut self.unexpected_rights)
    }
    pub fn last_native_status(&self) -> Option<NativeExitReceipt> {
        self.last_native_status
    }
    pub fn retry_reason(&self) -> Option<&RetryReason> {
        self.retry_reason.as_ref()
    }
    pub fn attempts(&self) -> u64 {
        self.attempts
    }
    /// Native diagnostics only; this is not a guest task or signal authority.
    pub fn native_worker_pid(&self) -> Option<libc::pid_t> {
        self.worker_pid
    }
    pub fn acknowledged_prefix(&self) -> usize {
        self.sent
    }
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        self.retry_deadline
            .map(|deadline| deadline.saturating_duration_since(std::time::Instant::now()))
    }

    /// Interests are empty while a resource retry is backed off or a fatal
    /// failure is retained. The service combines these with retry_after and
    /// its own submission/waiter wakeup. Host backoff never chooses a guest
    /// event or advances virtual time; it only retries existing cleanup.
    pub fn poll_interests(&self) -> [libc::pollfd; 3] {
        let empty = libc::pollfd {
            fd: -1,
            events: 0,
            revents: 0,
        };
        let mut interests = [empty; 3];
        if (self.failure.is_some() && self.stage != JobStage::CancelWait)
            || self.retry_after().is_some_and(|delay| !delay.is_zero())
        {
            return interests;
        }
        let Some(channels) = &self.channels else {
            return interests;
        };
        interests[2] = libc::pollfd {
            fd: channels.completion.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        match self.stage {
            JobStage::Request => {
                interests[0] = libc::pollfd {
                    fd: self.client.control.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                }
            }
            JobStage::AwaitReady
            | JobStage::ChunkAcknowledgement
            | JobStage::FinalAcknowledgement => {
                interests[1] = libc::pollfd {
                    fd: channels
                        .data
                        .as_ref()
                        .expect("active data channel")
                        .as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
            }
            JobStage::Begin | JobStage::Transfer | JobStage::Go | JobStage::Abort => {
                interests[1] = libc::pollfd {
                    fd: channels
                        .data
                        .as_ref()
                        .expect("active data channel")
                        .as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
            }
            JobStage::NativeWait if !self.worker_channel_closed => {
                interests[1] = libc::pollfd {
                    fd: channels
                        .data
                        .as_ref()
                        .expect("active data channel")
                        .as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
            }
            _ => {}
        }
        interests
    }

    /// Cancel only a reservation that never accepted a File batch. Existing
    /// fatal error information remains available; unknown received rights stay
    /// owned and must be moved to explicit failure cleanup separately.
    pub fn poll_cancel_empty(&mut self) -> Result<EmptyCancellationProgress, CoreError> {
        if unsafe { libc::getpid() } != self.client.process {
            return self.fatal(CoreError::protocol("fork-inherited native job owner"));
        }
        if self.expected_owners.is_some() || self.parent_references_retired {
            return Err(CoreError::protocol("empty cancellation after batch begin"));
        }
        if self.stage == JobStage::Cancelled {
            return Ok(EmptyCancellationProgress::Complete(self.last_native_status));
        }
        self.retry_deadline = None;
        if self.stage == JobStage::Request || self.stage == JobStage::Restart {
            // START was not successfully sent, or the preceding attempt has
            // already been actually reaped. All endpoints are internal-only.
            self.channels = None;
            self.stage = JobStage::Cancelled;
            return Ok(EmptyCancellationProgress::Complete(self.last_native_status));
        }
        if self.stage != JobStage::CancelWait {
            let channels = self
                .channels
                .as_mut()
                .ok_or_else(|| CoreError::protocol("cancel channels absent"))?;
            // This worker has never seen BEGIN or a guest right. EOF makes its
            // raw empty setup exit; no SIGKILL or numeric-PID signal is used.
            drop(channels.data.take());
            self.stage = JobStage::CancelWait;
        }
        if !self.unexpected_rights.is_empty() {
            // Do not receive additional descriptors into a full error owner.
            // The worker may exit, but authentic completion cannot be consumed
            // until the service explicitly moves these owners out.
            return Err(CoreError::protocol("cancel retains unexpected rights"));
        }
        if self.unexpected_rights.capacity() < raw::MAX_RIGHTS {
            self.unexpected_rights
                .try_reserve_exact(raw::MAX_RIGHTS)
                .map_err(|_| CoreError {
                    operation: "cancel reply owner capacity",
                    errno: libc::ENOMEM,
                })?;
        }
        let channels = self
            .channels
            .as_ref()
            .ok_or_else(|| CoreError::protocol("cancel wait channel absent"))?;
        let Some(frame) = receive(
            channels.completion.as_raw_fd(),
            "empty cancellation wait",
            &mut self.unexpected_rights,
            None,
        )?
        else {
            return Ok(EmptyCancellationProgress::Pending);
        };
        if frame.kind == raw::ERROR && frame.job == 0 && frame.sequence == 0 && frame.count == 0 {
            // The live broker reports its failed creation, so no child exists.
            let _cause = remote_error(&frame, "cancelled worker creation", 0, 0)?;
        } else {
            if frame.kind != raw::DONE
                || frame.job == 0
                || frame.count != 0
                || (self.job != 0 && frame.job != self.job)
            {
                return Err(CoreError::protocol("empty cancellation receipt"));
            }
            let pid = i32::try_from(frame.sequence)
                .map_err(|_| CoreError::protocol("cancel pid width"))?;
            let status = i32::try_from(frame.status)
                .map_err(|_| CoreError::protocol("cancel status width"))?;
            if pid <= 0 || self.worker_pid.is_some_and(|expected| expected != pid) {
                return Err(CoreError::protocol("cancel pid identity"));
            }
            self.last_native_status = Some(NativeExitReceipt {
                job: frame.job,
                native_pid: pid,
                raw_wait_status: status,
                socket_references: 0,
                acknowledged_descriptors: 0,
                parent_references_retired: false,
            });
        }
        self.stage = JobStage::Cancelled;
        self.channels = None;
        Ok(EmptyCancellationProgress::Complete(self.last_native_status))
    }

    pub fn advance_reservation(&mut self) -> Result<ReservationProgress, CoreError> {
        if unsafe { libc::getpid() } != self.client.process {
            return self.fatal(CoreError::protocol("fork-inherited native job owner"));
        }
        if self.expected_owners.is_some() {
            return self.fatal(CoreError::protocol("reservation after batch begin"));
        }
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if !self.admit_retry() {
            return Ok(ReservationProgress::Pending);
        }
        let result = self.drive(false);
        self.handle_result(result)?;
        Ok(if self.stage == JobStage::Ready {
            ReservationProgress::Ready
        } else {
            ReservationProgress::Pending
        })
    }

    /// No File owner is passed until the initial READY has been established.
    /// The same owned Vec/order is then retained by the service through every
    /// aborted pre-retirement attempt. Shared Arc aliases transfer one kernel
    /// right per distinct raw fd but retire every supplied Rust reference.
    pub fn advance(
        &mut self,
        sockets: &mut Vec<SocketReference>,
    ) -> Result<JobProgress, CoreError> {
        if unsafe { libc::getpid() } != self.client.process {
            return self.fatal(CoreError::protocol("fork-inherited native job owner"));
        }
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if self.stage == JobStage::Complete {
            return self.fatal(CoreError::protocol("advance after completion"));
        }
        if !self.admit_retry() {
            return Ok(JobProgress::Pending);
        }
        if self.expected_owners.is_none() {
            if self.stage != JobStage::Ready {
                return self.fatal(CoreError::protocol("batch before reserved READY"));
            }
            let mut identity = Vec::new();
            if identity.try_reserve_exact(sockets.len()).is_err() {
                self.delay(RetryReason::Resource(CoreError {
                    operation: "batch identity allocation",
                    errno: libc::ENOMEM,
                }));
                return Ok(JobProgress::Pending);
            }
            for socket in sockets.iter() {
                let fd = socket.as_raw_fd();
                match is_socket_file(fd) {
                    Ok(true) => identity.push(fd),
                    Ok(false) => {
                        return self.fatal(CoreError {
                            operation: "non-socket terminal batch",
                            errno: libc::ENOTSOCK,
                        });
                    }
                    Err(error) => return self.fatal(error),
                }
            }
            let mut transfer = Vec::new();
            if transfer.try_reserve_exact(identity.len()).is_err() {
                self.delay(RetryReason::Resource(CoreError {
                    operation: "batch transfer allocation",
                    errno: libc::ENOMEM,
                }));
                return Ok(JobProgress::Pending);
            }
            transfer.extend_from_slice(&identity);
            transfer.sort_unstable();
            transfer.dedup();
            self.expected_owners = Some(sockets.len());
            self.identity = identity;
            self.transfer = transfer;
            self.stage = JobStage::Begin;
        }
        if self.parent_references_retired {
            if !sockets.is_empty() {
                return self.fatal(CoreError::protocol("retired owner vector repopulated"));
            }
        } else if sockets.len() != self.expected_owners.unwrap_or(0)
            || sockets
                .iter()
                .map(AsRawFd::as_raw_fd)
                .ne(self.identity.iter().copied())
        {
            return self.fatal(CoreError::protocol("original socket owners changed"));
        }
        let result = self.drive(true);
        self.handle_result(result)?;
        if self.stage == JobStage::Go && !self.parent_references_retired {
            // Complete final ACK only. socket_file_ops has no flush, and every
            // distinct file has a held native copy. No callback or allocation
            // lies between retirement and setting the irreversible stage.
            sockets.clear();
            self.parent_references_retired = true;
        }
        if self.stage == JobStage::Complete {
            Ok(JobProgress::Complete(
                self.last_native_status.expect("complete wait receipt"),
            ))
        } else {
            Ok(JobProgress::Pending)
        }
    }

    fn admit_retry(&mut self) -> bool {
        if self.retry_after().is_some_and(|delay| !delay.is_zero()) {
            return false;
        }
        self.retry_deadline = None;
        true
    }

    fn delay(&mut self, reason: RetryReason) {
        self.retry_reason = Some(reason);
        self.retry_deadline = Some(std::time::Instant::now() + self.backoff);
        self.backoff = (self.backoff * 2).min(std::time::Duration::from_secs(1));
    }

    fn fatal<T>(&mut self, error: CoreError) -> Result<T, CoreError> {
        self.failure = Some(error.clone());
        Err(error)
    }

    fn handle_result(&mut self, result: Result<(), CoreError>) -> Result<(), CoreError> {
        // A precise error retained after native wait is final even if its
        // errno is usually retryable; the failed worker is not still pending.
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        match result {
            Ok(()) => Ok(()),
            Err(error) if error.is_retryable_resource() => {
                // No sendmsg effect on a negative result. A live receiving
                // worker is aborted/reaped before any retransmission. GO has
                // no rights and may simply wait for host buffer availability.
                if !self.parent_references_retired {
                    match self.stage {
                        JobStage::Begin
                        | JobStage::Transfer
                        | JobStage::ChunkAcknowledgement
                        | JobStage::FinalAcknowledgement => {
                            self.stage = JobStage::Abort;
                        }
                        _ => {}
                    }
                }
                self.delay(RetryReason::Resource(error));
                Ok(())
            }
            Err(error) => self.fatal(error),
        }
    }

    fn drive(&mut self, has_batch: bool) -> Result<(), CoreError> {
        if self.stage == JobStage::Restart {
            // This point is reachable only after actual wait, or a broker
            // setup error proving no child was created. Original refs stay.
            if self.channels.is_none() {
                self.channels = Some(Channels::new()?);
            }
            self.stage = JobStage::Request;
        }
        let channels = self
            .channels
            .as_ref()
            .ok_or_else(|| CoreError::protocol("job channels absent"))?;
        if let Some(frame) = receive(
            channels.completion.as_raw_fd(),
            "native completion",
            &mut self.unexpected_rights,
            None,
        )? {
            if frame.kind == raw::ERROR
                && frame.job == 0
                && frame.sequence == 0
                && frame.count == 0
                && self.stage == JobStage::AwaitReady
            {
                let error = remote_error(&frame, "native worker creation", 0, 0)?;
                if error.is_retryable_resource() {
                    self.restart(RetryReason::Resource(error))?;
                    return Ok(());
                }
                return Err(error);
            }
            if frame.kind != raw::DONE
                || frame.count != 0
                || (self.job != 0 && frame.job != self.job)
                || frame.job == 0
            {
                return Err(CoreError::protocol("native completion identity"));
            }
            let status = i32::try_from(frame.status)
                .map_err(|_| CoreError::protocol("native wait status width"))?;
            let pid = i32::try_from(frame.sequence)
                .map_err(|_| CoreError::protocol("native pid width"))?;
            if pid <= 0 || self.worker_pid.is_some_and(|expected| expected != pid) {
                return Err(CoreError::protocol("native pid identity"));
            }
            self.last_native_status = Some(NativeExitReceipt {
                job: frame.job,
                native_pid: pid,
                raw_wait_status: status,
                socket_references: self.expected_owners.unwrap_or(0),
                acknowledged_descriptors: self.sent,
                parent_references_retired: self.parent_references_retired,
            });
            if !self.parent_references_retired {
                // Wait may beat the data-channel ERROR. Preserve a setup
                // refusal's exact cause rather than repeatedly replacing an
                // unsupported/dead worker. There is at most one pre-READY
                // report, and actual wait is already retained above.
                if self.stage == JobStage::AwaitReady
                    && let Some(error_frame) = receive(
                        channels
                            .data
                            .as_ref()
                            .expect("setup data channel")
                            .as_raw_fd(),
                        "reaped worker setup report",
                        &mut self.unexpected_rights,
                        Some(&mut self.worker_channel_closed),
                    )?
                    && error_frame.kind == raw::ERROR
                {
                    let cause = remote_error(
                        &error_frame,
                        "native worker supervision/setup",
                        frame.job,
                        0,
                    )?;
                    return self.fatal(cause);
                }
                let aborted_resource = matches!(self.stage, JobStage::Abort | JobStage::AbortWait)
                    && status == 0
                    && matches!(
                        self.retry_reason.as_ref(),
                        Some(RetryReason::Resource(_) | RetryReason::IncompleteAncillaryTransfer)
                    );
                if aborted_resource {
                    self.restart(
                        self.retry_reason
                            .clone()
                            .expect("explicit aborted resource cause"),
                    )?;
                    return Ok(());
                }
                // Unexplained, killed, or non-resource setup exits are fatal
                // with originals retained. Never hide them in an endless
                // worker-respawn loop or count their wait as cleanup success.
                return Err(CoreError {
                    operation: "native worker exited before authenticated resource abort",
                    errno: libc::ECHILD,
                });
            }
            if self.stage != JobStage::NativeWait || status != 0 || frame.job != self.job {
                return Err(CoreError {
                    operation: "native exit failed after reference retirement",
                    errno: libc::ECHILD,
                });
            }
            self.stage = JobStage::Complete;
            return Ok(());
        }
        let data = channels
            .data
            .as_ref()
            .expect("active data channel")
            .as_raw_fd();
        match self.stage {
            JobStage::Request => {
                let channels = self.channels.as_ref().expect("owned channels");
                let rights = channels
                    .request_rights
                    .as_ref()
                    .ok_or_else(|| CoreError::protocol("worker request owners absent"))?;
                let frame = raw::Frame::new(raw::START, 0, 0, 0);
                if send(
                    self.client.control.as_raw_fd(),
                    &frame,
                    &[rights.0.as_raw_fd(), rights.1.as_raw_fd()],
                    "worker reservation",
                )? {
                    self.channels
                        .as_mut()
                        .expect("owned channels")
                        .request_rights = None;
                    self.stage = JobStage::AwaitReady;
                }
            }
            JobStage::AwaitReady => {
                if let Some(frame) = self.worker_frame(data)? {
                    if frame.kind == raw::ERROR && frame.job != 0 && frame.count == 0 {
                        self.job = frame.job;
                        let error =
                            remote_error(&frame, "native worker supervision/setup", self.job, 0)?;
                        if error.is_retryable_resource() {
                            self.retry_reason = Some(RetryReason::Resource(error));
                            self.stage = JobStage::Abort;
                            return Ok(());
                        }
                        return Err(error);
                    }
                    if frame.kind != raw::READY
                        || frame.job == 0
                        || frame.count != 0
                        || frame.status != 0
                    {
                        return Err(CoreError::protocol("reserved worker READY"));
                    }
                    let pid = i32::try_from(frame.sequence)
                        .map_err(|_| CoreError::protocol("READY pid width"))?;
                    if pid <= 0 {
                        return Err(CoreError::protocol("READY pid"));
                    }
                    self.worker_pid = Some(pid);
                    self.job = frame.job;
                    self.stage = if has_batch {
                        JobStage::Begin
                    } else {
                        JobStage::Ready
                    };
                }
            }
            JobStage::Ready => {}
            JobStage::Begin => {
                let frame = raw::Frame::new(raw::BEGIN, self.job, 0, self.transfer.len() as u64);
                if send(data, &frame, &[], "begin socket transfer")? {
                    self.stage = if self.transfer.is_empty() {
                        JobStage::FinalAcknowledgement
                    } else {
                        JobStage::Transfer
                    };
                }
            }
            JobStage::Transfer => {
                let end = self.transfer.len().min(self.sent + raw::MAX_RIGHTS);
                let frame = raw::Frame::new(
                    raw::RIGHTS,
                    self.job,
                    self.sent as u64,
                    (end - self.sent) as u64,
                );
                if send(
                    data,
                    &frame,
                    &self.transfer[self.sent..end],
                    "socket transfer chunk",
                )? {
                    self.stage = JobStage::ChunkAcknowledgement;
                }
            }
            JobStage::ChunkAcknowledgement => {
                if let Some(frame) = self.worker_frame(data)? {
                    if self.precommit_error(&frame)? {
                        return Ok(());
                    }
                    let end = self.transfer.len().min(self.sent + raw::MAX_RIGHTS);
                    if frame.kind != raw::CHUNK_ACK
                        || frame.job != self.job
                        || frame.sequence != end as u64
                        || frame.count != self.transfer.len() as u64
                        || frame.status != 0
                    {
                        return Err(CoreError::protocol("socket chunk ACK"));
                    }
                    self.sent = end;
                    self.stage = if end == self.transfer.len() {
                        JobStage::FinalAcknowledgement
                    } else {
                        JobStage::Transfer
                    };
                }
            }
            JobStage::FinalAcknowledgement => {
                if let Some(frame) = self.worker_frame(data)? {
                    if self.precommit_error(&frame)? {
                        return Ok(());
                    }
                    if frame.kind != raw::ACK
                        || frame.job != self.job
                        || frame.sequence != self.transfer.len() as u64
                        || frame.count != self.transfer.len() as u64
                        || frame.status != 0
                    {
                        return Err(CoreError::protocol("complete socket ACK"));
                    }
                    self.stage = JobStage::Go;
                }
            }
            JobStage::Go => {
                if !self.parent_references_retired {
                    return Err(CoreError::protocol("GO before original retirement"));
                }
                let frame = raw::Frame::new(
                    raw::GO,
                    self.job,
                    self.transfer.len() as u64,
                    self.transfer.len() as u64,
                );
                if send(data, &frame, &[], "native exit GO")? {
                    self.stage = JobStage::NativeWait;
                }
            }
            JobStage::NativeWait if !self.worker_channel_closed => {
                if let Some(frame) = receive(
                    data,
                    "post-ACK worker reply",
                    &mut self.unexpected_rights,
                    Some(&mut self.worker_channel_closed),
                )? {
                    return Err(remote_error(
                        &frame,
                        "post-ACK native worker",
                        self.job,
                        self.transfer.len(),
                    )?);
                }
            }
            JobStage::Abort => {
                let frame = raw::Frame::new(raw::ABORT, self.job, 0, 0);
                match send(data, &frame, &[], "abort incomplete transfer") {
                    Ok(true) => self.stage = JobStage::AbortWait,
                    Ok(false) => {}
                    Err(error) if error.errno == libc::EPIPE || error.errno == libc::ECONNRESET => {
                        self.stage = JobStage::AbortWait
                    }
                    Err(error) => return Err(error),
                }
            }
            JobStage::AbortWait | JobStage::NativeWait | JobStage::Complete => {}
            JobStage::CancelWait | JobStage::Cancelled => {
                return Err(CoreError::protocol("advance cancelled reservation"));
            }
            JobStage::Restart => unreachable!(),
        }
        Ok(())
    }

    fn worker_frame(&mut self, data: RawFd) -> Result<Option<raw::Frame>, CoreError> {
        let result = receive(
            data,
            "pre-ACK worker reply",
            &mut self.unexpected_rights,
            Some(&mut self.worker_channel_closed),
        )?;
        if self.worker_channel_closed {
            self.stage = JobStage::AbortWait;
        }
        Ok(result)
    }

    fn precommit_error(&mut self, frame: &raw::Frame) -> Result<bool, CoreError> {
        if frame.kind == raw::INCOMPLETE
            && frame.job == self.job
            && frame.count == self.transfer.len() as u64
        {
            self.retry_reason = Some(RetryReason::IncompleteAncillaryTransfer);
            self.stage = JobStage::Abort;
            return Ok(true);
        }
        if frame.kind == raw::ERROR {
            let error = remote_error(
                frame,
                "pre-ACK native worker",
                self.job,
                self.transfer.len(),
            )?;
            if error.is_retryable_resource() {
                self.retry_reason = Some(RetryReason::Resource(error));
                self.stage = JobStage::Abort;
                return Ok(true);
            }
            return Err(error);
        }
        Ok(false)
    }

    fn restart(&mut self, reason: RetryReason) -> Result<(), CoreError> {
        if self.parent_references_retired {
            return Err(CoreError::protocol("restart after retirement"));
        }
        self.attempts = self
            .attempts
            .checked_add(1)
            .ok_or_else(|| CoreError::protocol("worker attempt generation exhausted"))?;
        // A reaped worker has released any installed prefix natively. Dropping
        // old internal channels can fput queued prefix copies, but originals
        // are still retained and the only transferred file class is socket.
        self.channels = None;
        self.job = 0;
        self.worker_pid = None;
        self.sent = 0;
        self.worker_channel_closed = false;
        self.stage = JobStage::Restart;
        self.delay(reason);
        Ok(())
    }
}

fn socket_pair() -> Result<(OwnedFd, OwnedFd), CoreError> {
    let mut fds = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(CoreError::last("internal socketpair"));
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn send(
    fd: RawFd,
    frame: &raw::Frame,
    rights: &[RawFd],
    operation: &'static str,
) -> Result<bool, CoreError> {
    let rc = unsafe { raw::send_frame(fd, frame, rights.as_ptr(), rights.len(), true) };
    match rc {
        0 => Ok(true),
        x if x == -libc::EAGAIN || x == -libc::EINTR => Ok(false),
        x => Err(CoreError {
            operation,
            errno: -x,
        }),
    }
}

fn receive(
    fd: RawFd,
    operation: &'static str,
    retained: &mut Vec<OwnedFd>,
    closed: Option<&mut bool>,
) -> Result<Option<raw::Frame>, CoreError> {
    // The caller latches the first error and never calls receive again. This
    // capacity precondition prevents allocating after fd installation, and a
    // failure cannot silently overwrite or ordinarily drop the retained set.
    if !retained.is_empty() || retained.capacity() < raw::MAX_RIGHTS {
        return Err(CoreError::protocol("unexpected-rights retention not ready"));
    }
    let mut frame = raw::Frame::new(0, 0, 0, 0);
    let mut rights = [-1; raw::MAX_RIGHTS];
    let mut received = 0;
    let rc = unsafe {
        raw::receive_frame(
            fd,
            &mut frame,
            rights.as_mut_ptr(),
            rights.len(),
            &mut received,
            true,
        )
    };
    for fd in rights[..received].iter().copied() {
        // recvmsg has installed each fd, including any prefix delivered with
        // MSG_CTRUNC. It remains an explicit job-owned reference on all errors.
        retained.push(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    if received != 0 {
        return Err(CoreError::protocol(
            "unexpected rights in parent reply (owned and retained)",
        ));
    }
    if rc == -libc::ECONNRESET
        && let Some(closed) = closed
    {
        // EOF is only readiness after GO. Native completion still requires
        // the broker's actual wait; neither EOF nor pidfd wake is proof.
        *closed = true;
        return Ok(None);
    }
    match rc {
        x if x == -libc::EAGAIN || x == -libc::EINTR => Ok(None),
        0 => Ok(Some(frame)),
        x if x > 0 => Err(CoreError::protocol(
            "incomplete rights in parent protocol reply",
        )),
        x => Err(CoreError {
            operation,
            errno: -x,
        }),
    }
}

fn remote_error(
    frame: &raw::Frame,
    operation: &'static str,
    job: u64,
    count: usize,
) -> Result<CoreError, CoreError> {
    if frame.kind != raw::ERROR
        || (job != 0 && frame.job != job)
        || frame.count != count as u64
        || frame.status <= 0
        || frame.status > 4095
    {
        return Err(CoreError::protocol("native error frame"));
    }
    Ok(CoreError {
        operation,
        errno: frame.status as i32,
    })
}

impl fmt::Debug for BrokerOwner {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("BrokerOwner")
            .field("pid", &self.pid)
            .field("reaped", &self.reaped)
            .field("ambient_count", &self.ambient.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for BrokerClient {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("BrokerClient")
            .field("channel", &self.control.as_raw_fd())
            .finish()
    }
}

impl fmt::Debug for NativeExitJob {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("NativeExitJob")
            .field("job", &self.job)
            .field("stage", &self.stage)
            .field("attempts", &self.attempts)
            .field("expected_owners", &self.expected_owners)
            .field("transfer_count", &self.transfer.len())
            .field("parent_references_retired", &self.parent_references_retired)
            .field("retained_unexpected_rights", &self.unexpected_rights.len())
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}
