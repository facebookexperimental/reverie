//! Exported-client death control for the ordinary-main broker test launcher.
//! The launcher supplies the broker; this module does not bootstrap one.
//! The caller owns BrokerOwner through shutdown and actual __WCLONE wait.
use std::ffi::CString;
use std::ffi::OsString;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::IntoRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::time::Duration;
use std::time::Instant;

use reverie_kvm::native_exit_broker::BrokerClient;
use reverie_kvm::native_exit_broker::BrokerOwner;
use reverie_kvm::native_exit_broker::JobProgress;
use reverie_kvm::native_exit_broker::JobStage;
use reverie_kvm::native_exit_broker::NativeExitJob;
use reverie_kvm::native_exit_broker::ReservationProgress;
use reverie_kvm::native_exit_broker::SocketReference;

const STEP: Duration = Duration::from_secs(5);
const CHILD_MODE: &str = "--broker-client-death-child";
const CONTROL_MAGIC: u64 = 0x6578697464656174;
const WIRE_MAGIC: u64 = 0x7265766578697431;
const WIRE_VERSION: u32 = 1;
const WIRE_DONE: u32 = 7;
const WIRE_ERROR: u32 = 8;
const MAX_RIGHTS: usize = 253;

// Private protocol observation, bound to native_exit_broker/raw.rs in INPUTS.
// This is not an API that grants task admission or publishes a guest result.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct WaitFrame {
    magic: u64,
    version: u32,
    kind: u32,
    job: u64,
    sequence: u64,
    count: u64,
    status: i64,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Control {
    magic: u64,
    phase: u64,
    client: i64,
    worker: i64,
    job: u64,
    acknowledged: u64,
    retired: u64,
    eof_errno: i64,
}
impl Control {
    fn command(phase: u64) -> Self {
        Self {
            magic: CONTROL_MAGIC,
            phase,
            ..Self::default()
        }
    }
}

#[derive(Debug)]
pub struct DeathReceipt {
    pub launcher_pid: i32,
    pub broker_pid: i32,
    pub client_pid: i32,
    pub client_wait_status: i32,
    pub worker_pid: i32,
    pub worker_job: u64,
    pub worker_wait_status: i32,
    pub complete_acknowledged: usize,
    pub original_references_retired: bool,
    pub worker_error_errno_after_protocol_eof: i32,
    pub broker_live_after_worker_wait: bool,
    pub peer_eof_after_native_wait: bool,
}
#[derive(Default)]
pub struct DeathOwners {
    phase: &'static str,
    child: Option<(i32, Option<OwnedFd>)>,
    control: Option<OwnedFd>,
    retained: Vec<OwnedFd>,
    child_wait_status: Option<i32>,
}
#[must_use = "retain the owned child/channels and broker until actual cleanup"]
pub struct DeathFailure {
    pub message: String,
    pub owners: DeathOwners,
}

/// Call before the launcher's bootstrap branch. A matching internal child must
/// adopt its exported client, never bootstrap another broker inside libtest.
/// Nonmatching ordinary invocations are unchanged.
pub fn dispatch_client_child() {
    let args: Vec<OsString> = std::env::args_os().collect();
    if args.get(1).is_none_or(|arg| arg != CHILD_MODE) {
        return;
    }
    let mut held = ChildOwners::default();
    let result = child_body(&args, &mut held);
    if let Err(ref message) = result {
        eprintln!("BROKER_CLIENT_DEATH_CHILD_FAILURE: {message}");
    }
    // Native exit is intentional in both cases. No Rust destructor can turn
    // this control into ordinary last-close behavior after complete ACK.
    unsafe { exit_raw(if result.is_ok() { 0 } else { 125 }) }
}

#[derive(Default)]
struct ChildOwners {
    control: Option<OwnedFd>,
    client: Option<BrokerClient>,
    job: Option<NativeExitJob>,
    originals: Vec<SocketReference>,
    peer: Option<UnixStream>,
    unknown: Vec<OwnedFd>,
    adoption_failure: Option<reverie_kvm::native_exit_broker::ExecClientFailure>,
}

fn child_body(args: &[OsString], held: &mut ChildOwners) -> Result<(), String> {
    require(args.len() == 5, "exact internal client argument shape")?;
    let session_fd = parse_fd(&args[2])?;
    let control_fd = parse_fd(&args[4])?;
    require(
        session_fd != control_fd && session_fd >= 3 && control_fd >= 3,
        "two distinct inherited control owners",
    )?;
    // The numbers locate inherited descriptors; duplicate creates ownership.
    // Only successful nonce authentication makes the first one a BrokerClient.
    let session = duplicate(session_fd)?;
    held.control = Some(duplicate(control_fd)?);
    let nonce = parse_nonce(&args[3])?;
    match BrokerClient::adopt_exec_channel(session, nonce) {
        Ok(client) => held.client = Some(client),
        Err(failure) => {
            let message = failure.cause.to_string();
            held.adoption_failure = Some(failure);
            return Err(message);
        }
    }
    require(
        unsafe { libc::close(session_fd) } == 0,
        "close original inherited session",
    )?;
    require(
        unsafe { libc::close(control_fd) } == 0,
        "close original inherited test endpoint",
    )?;
    let deadline = Instant::now() + STEP;
    held.job = Some(
        held.client
            .as_ref()
            .unwrap()
            .reserve_worker()
            .map_err(|e| e.to_string())?,
    );
    loop {
        let job = held.job.as_mut().unwrap();
        match job.advance_reservation().map_err(|e| e.to_string())? {
            ReservationProgress::Ready => break,
            ReservationProgress::Pending => poll_job(job, deadline)?,
        }
    }
    let worker = held
        .job
        .as_ref()
        .unwrap()
        .native_worker_pid()
        .ok_or("READY lacks worker PID")?;
    let (source, peer) = UnixStream::pair().map_err(io)?;
    held.originals.push(SocketReference::Owned(unsafe {
        File::from_raw_fd(source.into_raw_fd())
    }));
    held.peer = Some(peer);
    loop {
        let job = held.job.as_mut().unwrap();
        require(
            matches!(
                job.advance(&mut held.originals)
                    .map_err(|e| e.to_string())?,
                JobProgress::Pending
            ),
            "no GO or completion before client death",
        )?;
        if job.stage() == JobStage::Go {
            break;
        }
        poll_job(job, deadline)?;
    }
    let job = held.job.as_ref().unwrap();
    require(
        job.acknowledged_prefix() == 1
            && job.parent_references_retired()
            && held.originals.is_empty(),
        "exact complete ACK and original owner retirement",
    )?;
    let interests = job.poll_interests();
    let data = interests[1].fd;
    let completion = interests[2].fd;
    require(
        data >= 0 && completion >= 0 && data != completion,
        "distinct exact job endpoints",
    )?;

    // Deliberate protocol fault after ACK: no GO. Half-close proves the worker
    // actually consumes EOF, because it must return its exact ERROR first.
    // A mutant that exits on EOF cannot supply this causal observation.
    require(
        unsafe { libc::shutdown(data, libc::SHUT_WR) } == 0,
        "half-close only internal job writer",
    )?;
    let error: WaitFrame = receive(data, &mut held.unknown, Instant::now() + STEP)?;
    require(
        held.unknown.is_empty(),
        "worker error has no unexpected rights",
    )?;
    require(
        error.magic == WIRE_MAGIC
            && error.version == WIRE_VERSION
            && error.kind == WIRE_ERROR
            && error.job > 0
            && error.sequence == 1
            && error.count == 1
            && error.status == libc::ECONNRESET as i64,
        "actual post-ACK worker EOF error",
    )?;
    let report = Control {
        magic: CONTROL_MAGIC,
        phase: 1,
        client: unsafe { libc::getpid() } as i64,
        worker: worker as i64,
        job: error.job,
        acknowledged: 1,
        retired: 1,
        eof_errno: error.status,
    };
    send(
        held.control.as_ref().unwrap().as_raw_fd(),
        &report,
        &[completion, held.peer.as_ref().unwrap().as_raw_fd()],
        Instant::now() + STEP,
    )?;
    let command: Control = receive(
        held.control.as_ref().unwrap().as_raw_fd(),
        &mut held.unknown,
        Instant::now() + STEP,
    )?;
    require(
        held.unknown.is_empty()
            && command.magic == CONTROL_MAGIC
            && command.phase == 2
            && command.client == 0
            && command.worker == 0
            && command.job == 0
            && command.acknowledged == 0
            && command.retired == 0
            && command.eof_errno == 0,
        "exact parent command for native client exit",
    )?;
    Ok(())
}

/// Runs one complete-ACK exported-client death case. The caller keeps the
/// original BrokerOwner alive and settles it only after this receipt succeeds.
/// An error returns the exact child/channel owners; it is never a passing case.
pub fn run_exported_client_death(owner: &BrokerOwner) -> Result<DeathReceipt, DeathFailure> {
    let mut owners = DeathOwners {
        phase: "setup",
        retained: Vec::with_capacity(MAX_RIGHTS),
        ..DeathOwners::default()
    };
    let result: Result<DeathReceipt, String> = (|| {
        let launcher = unsafe { libc::getpid() };
        let broker_client = owner.client();
        let broker = broker_client
            .authenticated_broker_identity()
            .map_err(|e| e.to_string())?;
        require(
            broker.pid() == owner.native_pid(),
            "authenticated broker identity equals owned child",
        )?;
        require_live(
            broker.pidfd().as_raw_fd(),
            "broker live before exported-client setup",
        )?;
        spawn_client(owner, &mut owners)?;
        let (client_pid, client_pidfd) = owners.child.as_ref().ok_or("owned client missing")?;
        let expected_client = *client_pid;
        require_live(
            client_pidfd
                .as_ref()
                .ok_or("client pidfd setup incomplete")?
                .as_raw_fd(),
            "exported client live before ACK",
        )?;
        owners.phase = "await-client-complete-ack-and-causal-eof";
        let report: Control = receive(
            owners.control.as_ref().unwrap().as_raw_fd(),
            &mut owners.retained,
            Instant::now() + STEP,
        )?;
        require(
            report.magic == CONTROL_MAGIC
                && report.phase == 1
                && report.client == expected_client as i64
                && report.worker > 0
                && report.worker <= i32::MAX as i64
                && report.job > 0
                && report.acknowledged == 1
                && report.retired == 1
                && report.eof_errno == libc::ECONNRESET as i64
                && owners.retained.len() == 2,
            "exact complete ACK/EOF report with two observed owners",
        )?;
        owners.phase = "assert-live-client-eof-retention";
        let completion = owners.retained[0].as_raw_fd();
        let peer = owners.retained[1].as_raw_fd();
        // No sleeps: the ERROR proves EOF was consumed. At that causal boundary
        // neither native wait nor object EOF is allowed while the client lives.
        require_live(
            owners
                .child
                .as_ref()
                .unwrap()
                .1
                .as_ref()
                .ok_or("client pidfd absent")?
                .as_raw_fd(),
            "client still alive after actual worker EOF",
        )?;
        require_no_data(completion, "no DONE from channel EOF while client lives")?;
        require_no_data(peer, "transferred source remains owned after protocol EOF")?;
        require_live(
            broker.pidfd().as_raw_fd(),
            "broker still live before client native exit",
        )?;
        send(
            owners.control.as_ref().unwrap().as_raw_fd(),
            &Control::command(2),
            &[],
            Instant::now() + STEP,
        )?;
        owners.phase = "await-actual-client-wait";
        let client_status = wait_client(&mut owners, Instant::now() + STEP)?;
        require(client_status == 0, "exact actual native client exit0")?;
        owners.phase = "await-broker-actual-worker-wait-after-client-exit0";
        let before = owners.retained.len();
        let done: WaitFrame = receive(completion, &mut owners.retained, Instant::now() + STEP)?;
        require(
            owners.retained.len() == before,
            "native completion carries no rights",
        )?;
        require(
            done.magic == WIRE_MAGIC
                && done.version == WIRE_VERSION
                && done.kind == WIRE_DONE
                && done.job == report.job
                && done.sequence == report.worker as u64
                && done.count == 0
                && done.status == 0,
            "broker actual wait for exact worker/job status0",
        )?;
        owners.phase = "assert-object-eof-after-actual-worker-wait0";
        require_eof(peer, Instant::now() + STEP)?;
        require_live(
            broker.pidfd().as_raw_fd(),
            "original broker remains alive after worker actual wait",
        )?;
        Ok(DeathReceipt {
            launcher_pid: launcher,
            broker_pid: broker.pid(),
            client_pid: expected_client,
            client_wait_status: client_status,
            worker_pid: report.worker as i32,
            worker_job: report.job,
            worker_wait_status: done.status as i32,
            complete_acknowledged: 1,
            original_references_retired: true,
            worker_error_errno_after_protocol_eof: report.eof_errno as i32,
            broker_live_after_worker_wait: true,
            peer_eof_after_native_wait: true,
        })
    })();
    result.map_err(|message| DeathFailure {
        message: format!("{}: {message}", owners.phase),
        owners,
    })
}

fn spawn_client(owner: &BrokerOwner, owners: &mut DeathOwners) -> Result<(), String> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } == 0,
        "read unchanged native parent SIGCHLD action",
    )?;
    require(
        action.sa_sigaction != libc::SIG_IGN && action.sa_flags & libc::SA_NOCLDWAIT == 0,
        "exec-client test requires non-autoreaping parent; unexeced broker IGN control is separate",
    )?;
    let exported = match owner.export_client_for_exec() {
        Ok(exported) => exported,
        Err(failure) => {
            // This setup failure may own unexpected SCM references. Retain them
            // before returning; the outer runner must not normally drop failure.
            owners.retained.extend(failure.retained_rights);
            if let Some(channel) = failure.channel {
                owners.retained.push(channel);
            }
            return Err(failure.cause.to_string());
        }
    };
    let (session, nonce) = exported.into_parts();
    let (parent, child) = pair()?;
    let exe = std::env::current_exe().map_err(io)?;
    let argv = [
        CString::new(exe.as_os_str().as_bytes()).map_err(|e| e.to_string())?,
        CString::new(CHILD_MODE).unwrap(),
        CString::new(session.as_raw_fd().to_string()).unwrap(),
        CString::new(nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap(),
        CString::new(child.as_raw_fd().to_string()).unwrap(),
    ];
    let environment: Vec<CString> = std::env::vars_os()
        .map(|(key, value)| {
            let mut bytes = key.as_bytes().to_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_bytes());
            CString::new(bytes).map_err(|e| e.to_string())
        })
        .collect::<Result<_, _>>()?;
    let mut args: Vec<_> = argv.iter().map(|v| v.as_ptr()).collect();
    args.push(std::ptr::null());
    let mut env: Vec<_> = environment.iter().map(|v| v.as_ptr()).collect();
    env.push(std::ptr::null());
    let all = u64::MAX;
    let mut old = 0u64;
    require(
        unsafe {
            raw(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK as usize,
                &all as *const _ as usize,
                &mut old as *mut _ as usize,
                8,
                0,
                0,
            )
        } == 0,
        "block catchable signals for exact clone",
    )?;
    let parent_pid = unsafe { libc::getpid() };
    let pid = unsafe { raw(libc::SYS_clone, 0, 0, 0, 0, 0, 0) };
    if pid == 0 {
        // Raw-only child path until exec, no allocator or inherited Rust Drop.
        if unsafe {
            raw(
                libc::SYS_prctl,
                libc::PR_SET_PDEATHSIG as usize,
                libc::SIGKILL as usize,
                0,
                0,
                0,
                0,
            )
        } != 0
            || unsafe { raw(libc::SYS_getppid, 0, 0, 0, 0, 0, 0) } != parent_pid as i64
        {
            unsafe { exit_raw(125) }
        }
        for fd in [session.as_raw_fd(), child.as_raw_fd()] {
            if unsafe {
                raw(
                    libc::SYS_fcntl,
                    fd as usize,
                    libc::F_SETFD as usize,
                    0,
                    0,
                    0,
                    0,
                )
            } < 0
            {
                unsafe { exit_raw(125) }
            }
        }
        if unsafe {
            raw(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK as usize,
                &old as *const _ as usize,
                0,
                8,
                0,
                0,
            )
        } != 0
        {
            unsafe { exit_raw(125) }
        }
        unsafe {
            raw(
                libc::SYS_execve,
                argv[0].as_ptr() as usize,
                args.as_ptr() as usize,
                env.as_ptr() as usize,
                0,
                0,
                0,
            );
            exit_raw(125)
        }
    }
    // Save the exact child before any fallible parent operation. Native exec
    // changes the clone0 child's exit-signal category; exact-PID __WALL waits
    // cover it without mistaking ECHILD for successful completion.
    let mut pidfd_error = None;
    if pid > 0 {
        owners.child = Some((pid as i32, None));
        let fd = unsafe { raw(libc::SYS_pidfd_open, pid as usize, 0, 0, 0, 0, 0) };
        if fd >= 0 {
            owners.child.as_mut().unwrap().1 = Some(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        } else {
            pidfd_error = Some(format!("owned client pidfd setup errno={}", -fd));
        }
    }
    owners.control = Some(parent);
    let restored = unsafe {
        raw(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK as usize,
            &old as *const _ as usize,
            0,
            8,
            0,
            0,
        )
    };
    require(restored == 0, "exact parent mask restoration")?;
    let mut actual_mask = 0u64;
    require(
        unsafe {
            raw(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK as usize,
                0,
                &mut actual_mask as *mut _ as usize,
                8,
                0,
                0,
            )
        } == 0
            && actual_mask == old,
        "parent mask exact readback",
    )?;
    require(pid > 0, "owned clone0 client creation")?;
    if let Some(error) = pidfd_error {
        return Err(error);
    }
    drop(child);
    drop(session);
    Ok(())
}

fn wait_client(owners: &mut DeathOwners, deadline: Instant) -> Result<i32, String> {
    let (pid, pidfd) = owners.child.as_ref().ok_or("owned child absent")?;
    loop {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(*pid, &mut status, libc::WNOHANG | libc::__WALL) };
        if rc == *pid {
            owners.child_wait_status = Some(status);
            return Ok(status);
        }
        if rc < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(io(std::io::Error::last_os_error()));
        }
        poll_one(
            pidfd
                .as_ref()
                .ok_or("actual client wait lacks pidfd")?
                .as_raw_fd(),
            libc::POLLIN,
            deadline,
        )?;
    }
}
fn require_live(pidfd: RawFd, why: &str) -> Result<(), String> {
    let mut p = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut p, 1, 0) };
    require(rc == 0 && p.revents == 0, why)
}
fn require_no_data(fd: RawFd, why: &str) -> Result<(), String> {
    let mut byte = 0u8;
    let rc = unsafe {
        libc::recv(
            fd,
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    require(
        rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN),
        why,
    )
}
fn require_eof(fd: RawFd, deadline: Instant) -> Result<(), String> {
    loop {
        let mut byte = 0u8;
        let rc = unsafe { libc::recv(fd, (&mut byte as *mut u8).cast(), 1, libc::MSG_DONTWAIT) };
        if rc == 0 {
            return Ok(());
        }
        if rc > 0 {
            return Err("unexpected object payload after actual native wait".into());
        }
        let errno = std::io::Error::last_os_error().raw_os_error();
        if errno == Some(libc::EINTR) {
            continue;
        }
        require(errno == Some(libc::EAGAIN), "peer EOF query")?;
        poll_one(fd, libc::POLLIN, deadline)?;
    }
}
fn poll_job(job: &NativeExitJob, deadline: Instant) -> Result<(), String> {
    let mut fds = job.poll_interests();
    poll_slice(&mut fds, deadline, job.retry_after())
}
fn poll_one(fd: RawFd, events: i16, deadline: Instant) -> Result<(), String> {
    poll_slice(
        &mut [libc::pollfd {
            fd,
            events,
            revents: 0,
        }],
        deadline,
        None,
    )
}
fn poll_slice(
    fds: &mut [libc::pollfd],
    deadline: Instant,
    retry: Option<Duration>,
) -> Result<(), String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    require(
        !remaining.is_zero(),
        "fixed five-second step expired; no completion inferred",
    )?;
    let wait = retry
        .unwrap_or(remaining)
        .min(remaining)
        .as_millis()
        .clamp(1, 1000) as i32;
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, wait) };
    if rc < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
        return Err(io(std::io::Error::last_os_error()));
    }
    require(
        fds.iter()
            .all(|p| p.revents & (libc::POLLNVAL | libc::POLLERR) == 0),
        "owned observation descriptor remains valid",
    )
}
fn pair() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [-1; 2];
    require(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        } == 0,
        "private test seqpacket pair",
    )?;
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}
fn duplicate(fd: RawFd) -> Result<OwnedFd, String> {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        Err(io(std::io::Error::last_os_error()))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }
}
fn parse_fd(value: &OsString) -> Result<RawFd, String> {
    value
        .to_str()
        .ok_or("fd is not UTF-8")?
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())
}
fn parse_nonce(value: &OsString) -> Result<[u8; 32], String> {
    let text = value.to_str().ok_or("nonce is not UTF-8")?;
    require(
        text.len() == 64 && text.is_ascii(),
        "exact private nonce encoding",
    )?;
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}
fn require(ok: bool, why: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(why.to_owned()) }
}
fn io(error: std::io::Error) -> String {
    error.to_string()
}

fn send<T>(fd: RawFd, value: &T, rights: &[RawFd], deadline: Instant) -> Result<(), String> {
    require(rights.len() <= MAX_RIGHTS, "bounded test ancillary payload")?;
    loop {
        let mut storage = [0usize; 130];
        let mut iov = libc::iovec {
            iov_base: (value as *const T).cast_mut().cast(),
            iov_len: std::mem::size_of::<T>(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if !rights.is_empty() {
            let bytes = std::mem::size_of_val(rights);
            require(
                unsafe { libc::CMSG_SPACE(bytes as u32) } as usize
                    <= std::mem::size_of_val(&storage),
                "fixed ancillary capacity",
            )?;
            msg.msg_control = storage.as_mut_ptr().cast();
            msg.msg_controllen = unsafe { libc::CMSG_SPACE(bytes as u32) } as usize;
            let header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
            unsafe {
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(bytes as u32) as usize;
                std::ptr::copy_nonoverlapping(
                    rights.as_ptr(),
                    libc::CMSG_DATA(header).cast(),
                    rights.len(),
                );
            }
        }
        let rc = unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
        if rc == std::mem::size_of::<T>() as isize {
            return Ok(());
        }
        if rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        require(
            rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN),
            "exact test packet send",
        )?;
        poll_one(fd, libc::POLLOUT, deadline)?;
    }
}
fn receive<T: Copy + Default>(
    fd: RawFd,
    retained: &mut Vec<OwnedFd>,
    deadline: Instant,
) -> Result<T, String> {
    loop {
        let mut storage = [0usize; 130];
        let mut value = T::default();
        let mut iov = libc::iovec {
            iov_base: (&mut value as *mut T).cast(),
            iov_len: std::mem::size_of::<T>(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = storage.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&storage);
        retained.reserve(MAX_RIGHTS);
        let rc =
            unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC) };
        if rc < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error();
            if errno == Some(libc::EINTR) {
                continue;
            }
            require(errno == Some(libc::EAGAIN), "test packet receive")?;
            poll_one(fd, libc::POLLIN, deadline)?;
            continue;
        }
        let mut header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        let mut bad = false;
        while !header.is_null() {
            let h = unsafe { &*header };
            let base = unsafe { libc::CMSG_LEN(0) } as usize;
            if h.cmsg_len < base {
                bad = true;
                break;
            }
            if h.cmsg_level == libc::SOL_SOCKET && h.cmsg_type == libc::SCM_RIGHTS {
                let bytes = h.cmsg_len - base;
                if !bytes.is_multiple_of(std::mem::size_of::<RawFd>()) {
                    bad = true;
                } else {
                    let count = bytes / std::mem::size_of::<RawFd>();
                    for i in 0..count {
                        let fd = unsafe { *libc::CMSG_DATA(header).cast::<RawFd>().add(i) };
                        retained.push(unsafe { OwnedFd::from_raw_fd(fd) });
                    }
                }
            } else {
                bad = true;
            }
            header = unsafe { libc::CMSG_NXTHDR(&msg, header) };
        }
        require(
            !bad && msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
                && rc == std::mem::size_of::<T>() as isize,
            "exact untruncated test frame; unexpected owners retained",
        )?;
        return Ok(value);
    }
}
unsafe fn exit_raw(code: usize) -> ! {
    unsafe {
        raw(libc::SYS_exit_group, code, 0, 0, 0, 0, 0);
    }
    loop {
        std::hint::spin_loop();
    }
}
#[cfg(target_arch = "x86_64")]
unsafe fn raw(
    number: libc::c_long,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
) -> i64 {
    let result: i64;
    unsafe {
        std::arch::asm!("syscall", inlateout("rax") number => result,
        in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d, in("r8") e, in("r9") f,
        lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    result
}

/// Separate early-main cases: unlike the exported client above, the native
/// broker never execs and therefore remains an exact __WCLONE child.
#[derive(Clone, Copy, Debug)]
pub enum ParentSigchldMode {
    Ignore,
    NoChildWait,
}
#[derive(Debug)]
pub struct SigchldReceipt {
    pub mode: ParentSigchldMode,
    pub broker_pid: i32,
    pub broker_actual_wait_status: i32,
    pub worker_actual_wait: reverie_kvm::native_exit_broker::NativeExitReceipt,
    pub parent_action_unchanged_during_case: bool,
    pub original_action_restored: bool,
}
#[derive(Default)]
pub struct SigchldOwners {
    owner: Option<BrokerOwner>,
    job: Option<NativeExitJob>,
    bootstrap_failure: Option<reverie_kvm::native_exit_broker::BootstrapFailure>,
}
#[must_use = "retain any unconfirmed broker/job owner despite setup failure"]
pub struct SigchldFailure {
    pub message: String,
    pub owners: SigchldOwners,
    pub action_restore_error: Option<String>,
}

/// Must be selected before ordinary launcher bootstrap and before any threads
/// or guest descriptors. The supplied StartupAuthority remains the real launch
/// contract; this test does not infer exclusivity from a /proc task count.
pub fn run_unexeced_sigchld_case(
    authority: reverie_kvm::native_exit_broker::StartupAuthority,
    mode: ParentSigchldMode,
) -> Result<SigchldReceipt, Box<SigchldFailure>> {
    let mut owners = SigchldOwners::default();
    let old = match current_sigchld() {
        Ok(action) => action,
        Err(message) => {
            return Err(Box::new(SigchldFailure {
                message,
                owners,
                action_restore_error: None,
            }));
        }
    };
    let mut temporary = old;
    match mode {
        ParentSigchldMode::Ignore => {
            temporary.handler = libc::SIG_IGN;
            temporary.flags &= !(libc::SA_NOCLDWAIT as usize);
        }
        ParentSigchldMode::NoChildWait => {
            temporary.handler = libc::SIG_DFL;
            temporary.flags |= libc::SA_NOCLDWAIT as usize;
        }
    }
    let result = (|| {
        set_sigchld(&temporary)?;
        let installed = current_sigchld()?;
        require(
            same_action(&temporary, &installed),
            "exact installed raw SIGCHLD control",
        )?;
        match BrokerOwner::bootstrap(authority) {
            Ok(owner) => owners.owner = Some(owner),
            Err(failure) => {
                let message = failure.cause.to_string();
                owners.bootstrap_failure = Some(failure);
                return Err(message);
            }
        }
        require(
            same_action(&installed, &current_sigchld()?),
            "bootstrap leaves parent SIGCHLD control unchanged",
        )?;
        let owner = owners.owner.as_mut().unwrap();
        owners.job = Some(owner.client().reserve_worker().map_err(|e| e.to_string())?);
        let job = owners.job.as_mut().unwrap();
        let deadline = Instant::now() + STEP;
        while job.advance_reservation().map_err(|e| e.to_string())? != ReservationProgress::Ready {
            poll_job(job, deadline)?;
        }
        let mut no_files = Vec::new();
        let worker_wait = loop {
            match job.advance(&mut no_files).map_err(|e| e.to_string())? {
                JobProgress::Complete(receipt) => break receipt,
                JobProgress::Pending => poll_job(job, deadline)?,
            }
        };
        require(
            worker_wait.raw_wait_status == 0
                && worker_wait.socket_references == 0
                && worker_wait.acknowledged_descriptors == 0
                && worker_wait.parent_references_retired
                && no_files.is_empty(),
            "empty native worker exact wait",
        )?;
        let broker_pid = owner.native_pid();
        let deadline = Instant::now() + STEP;
        while !owner.request_shutdown().map_err(|e| e.to_string())? {
            let p = owner.shutdown_poll_interest();
            poll_one(p.fd, p.events, deadline)?;
        }
        let status = loop {
            if let Some(status) = owner.try_wait().map_err(|e| e.to_string())? {
                break status;
            }
            let p = owner
                .exit_poll_interest()
                .ok_or("native broker lacks pidfd readiness")?;
            poll_one(p.fd, p.events, deadline)?;
        };
        require(
            status == 0,
            "actual unexeced broker __WCLONE wait0 under parent disposition",
        )?;
        require(
            same_action(&installed, &current_sigchld()?),
            "worker/reap leaves parent action unchanged",
        )?;
        Ok(SigchldReceipt {
            mode,
            broker_pid,
            broker_actual_wait_status: status,
            worker_actual_wait: worker_wait,
            parent_action_unchanged_during_case: true,
            original_action_restored: false,
        })
    })();
    // Every returning path restores the exact saved semantic disposition. A
    // failed restoration is explicit failure and never a successful receipt.
    let restored = (|| {
        set_sigchld(&old)?;
        require(
            same_action(&old, &current_sigchld()?),
            "original SIGCHLD semantic action readback",
        )
    })();
    match (result, restored) {
        (Ok(mut receipt), Ok(())) => {
            receipt.original_action_restored = true;
            Ok(receipt)
        }
        (result, restoration) => Err(Box::new(SigchldFailure {
            message: result
                .err()
                .unwrap_or_else(|| "SIGCHLD restoration failed".into()),
            owners,
            action_restore_error: restoration.err(),
        })),
    }
}
// Exact x86-64 kernel rt_sigaction ABI, avoiding libc normalization that can
// add SA_RESTORER while ostensibly restoring a default/ignored disposition.
#[repr(C)]
#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct KernelAction {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: u64,
}
fn current_sigchld() -> Result<KernelAction, String> {
    let mut action = KernelAction::default();
    require(
        unsafe {
            raw(
                libc::SYS_rt_sigaction,
                libc::SIGCHLD as usize,
                0,
                &mut action as *mut _ as usize,
                8,
                0,
                0,
            )
        } == 0,
        "read exact kernel SIGCHLD action",
    )?;
    Ok(action)
}
fn set_sigchld(action: &KernelAction) -> Result<(), String> {
    require(
        unsafe {
            raw(
                libc::SYS_rt_sigaction,
                libc::SIGCHLD as usize,
                action as *const _ as usize,
                0,
                8,
                0,
                0,
            )
        } == 0,
        "set exact kernel SIGCHLD action",
    )
}
fn same_action(a: &KernelAction, b: &KernelAction) -> bool {
    a == b
}

impl DeathFailure {
    pub fn print_retained_owners(&self) {
        eprintln!(
            "CLIENT_DEATH_RETAINED phase={} child={:?} child_pidfd={:?} control={:?} retained_rights={} actual_child_wait={:?}",
            self.owners.phase,
            self.owners.child.as_ref().map(|c| c.0),
            self.owners
                .child
                .as_ref()
                .and_then(|c| c.1.as_ref())
                .map(AsRawFd::as_raw_fd),
            self.owners.control.as_ref().map(AsRawFd::as_raw_fd),
            self.owners.retained.len(),
            self.owners.child_wait_status
        );
    }
}
impl SigchldFailure {
    pub fn print_retained_owners(&self) {
        eprintln!(
            "SIGCHLD_CASE_RETAINED broker={:?} job_stage={:?} bootstrap_failure={} restore_error={:?}",
            self.owners.owner.as_ref().map(BrokerOwner::native_pid),
            self.owners.job.as_ref().map(NativeExitJob::stage),
            self.owners.bootstrap_failure.is_some(),
            self.action_restore_error
        );
    }
}
