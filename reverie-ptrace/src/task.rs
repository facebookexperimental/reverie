/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `TracedTask` and its methods.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

use async_trait::async_trait;
use futures::future;
use futures::future::Either;
use futures::future::Future;
use futures::future::FutureExt;
use futures::future::TryFutureExt;
use nix::sys::mman::ProtFlags;
use nix::sys::signal::Signal;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Mprotect;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie::Backtrace;
use reverie::Errno;
use reverie::ExitStatus;
use reverie::Frame;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Never;
use reverie::Pid;
#[cfg(target_arch = "x86_64")]
use reverie::Rdtsc;
use reverie::Subscription;
use reverie::Tid;
use reverie::TimerSchedule;
use reverie::Tool;
use safeptrace::ChildOp;
use safeptrace::Error as TraceError;
use safeptrace::Event;
use safeptrace::Running;
use safeptrace::Stopped;
use safeptrace::Wait;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::task::JoinError;
use tokio::task::JoinHandle;

use crate::children;
use crate::cp;
use crate::error::Error;
use crate::gdbstub::BreakpointType;
use crate::gdbstub::CoreRegs;
use crate::gdbstub::GdbRequest;
use crate::gdbstub::GdbServer;
use crate::gdbstub::ResumeAction;
use crate::gdbstub::ResumeInferior;
use crate::gdbstub::StopEvent;
use crate::gdbstub::StopReason;
use crate::gdbstub::StoppedInferior;
use crate::regs::Reg;
use crate::regs::RegAccess;
use crate::stack::GuestStack;
use crate::timer::HandleFailure;
use crate::timer::Timer;
use crate::timer::TimerEventRequest;
use crate::vdso;

#[derive(Debug)]
struct Suspended {
    waker: Option<mpsc::Sender<Pid>>,
    suspended: Arc<AtomicBool>,
}

/// Expected resume action sent by gdb client, when the task is in a gdb stop.
#[derive(Debug, Clone, Copy, PartialEq)]
enum ExpectedGdbResume {
    /// Expecting a normal gdb resume, either single step, until or continue
    Resume,
    /// Expecting a gdb step over, this happens the underlying task hit a sw
    /// breakpoint, gdb then needs to restore the original instruction --
    /// which implies deleting the breakpoint, single-step, then restore
    /// the breakpoint. This is a special case because we need to serialize
    /// the whole operation, otherwise when there's a different thread in
    /// the same process group which share the same breakpoint, removing
    /// breakpoint can cause the 2nd thread to miss the breakpoint.
    StepOver,
    /// Force single-step, even if Resume(continue) is requested. This
    /// is a workaround when fork/vfork/clone event is reported to gdb,
    /// gdb could then issue an `vCont;p<pid>:-1` to resume all threads in
    /// the thread group, which could cause the main thread to miss events.
    StepOnly,
}

pub struct Child {
    id: Pid,
    /// Task is suspended, either stopped by gdb (client), or received
    /// SIGSTOP sent by other threads in the same process group.
    suspended: Arc<AtomicBool>,
    /// Notify a task reached SIGSTOP.
    wait_all_stop_tx: Option<mpsc::Sender<(Pid, Suspended)>>,
    /// Channel to receive if a child task is becoming a daemon, when
    /// `daemonize()` is called.
    pub(crate) daemonizer_rx: Option<mpsc::Receiver<broadcast::Receiver<()>>>,
    /// Join handle to let child task exit gracefully.
    pub(crate) handle: JoinHandle<ExitStatus>,
}

impl Child {
    /// Child task identifier.
    pub fn id(&self) -> Pid {
        self.id
    }
}

impl fmt::Debug for Child {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Child").field("id", &self.id).finish()
    }
}

impl Future for Child {
    type Output = Result<ExitStatus, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.handle.poll_unpin(cx)
    }
}

pub type Children = children::Children<Child>;

enum HandleSignalResult {
    /// Signal is suppressed with task resumed.
    SignalSuppressed(Wait),
    /// signal needs to be delivered.
    SignalToDeliver(Stopped, Signal),
}

/// All the info needed to be able to interact with the global state.
struct GlobalState<G: GlobalTool> {
    /// The tool's static configuration data.
    cfg: G::Config,

    /// Reference to the tool's global state. This is used to send it "rpc" messages.
    gs_ref: Arc<G>,

    /// Events the tool is subscripted (like interception)
    subscriptions: Arc<Subscription>,

    /// guests are sequentialized already (by detcore for example), gdbserver
    /// should avoid sequentialize threads.
    sequentialized_guest: Arc<bool>,
}

impl<G: GlobalTool> Clone for GlobalState<G> {
    fn clone(&self) -> Self {
        Self {
            cfg: self.cfg.clone(),
            gs_ref: self.gs_ref.clone(),
            subscriptions: self.subscriptions.clone(),
            sequentialized_guest: self.sequentialized_guest.clone(),
        }
    }
}

/// Our runtime representation of what Reverie knows about a guest thread. Its
/// lifetime matches the lifetime of the thread.
pub struct TracedTask<L: Tool> {
    /// Thread ID.
    tid: Pid,

    /// Process ID.
    pid: Pid,

    /// Parent process ID.
    ppid: Option<Pid>,

    /// State associated with the thread. Unique for each thread.
    thread_state: L::ThreadState,

    /// State associated with the process. This is shared among threads in the
    /// same thread group.
    process_state: Arc<L>,

    /// Global state. This is shared among all threads in a process tree.
    global_state: GlobalState<L::GlobalState>,

    /// True if we can intercept CPUID, false otherwise.
    has_cpuid_interception: bool,

    /// Set to `Some` if the syscall has not been injected yet. `None` if it has.
    pending_syscall: Option<(Sysno, SyscallArgs)>,

    /// pending signal to deliver. This can happen when
    /// syscall got interrupted (by signal)
    pending_signal: Option<Signal>,

    /// A channel to allow short-circuiting the next state to main run loop. This
    /// is useful inside of `inject` or `tail_inject` where we might need to
    /// cancel a future early.
    next_state: mpsc::Sender<Result<Wait, TraceError>>,

    /// The receiving end of the next_state channel.
    next_state_rx: Option<mpsc::Receiver<Result<Wait, TraceError>>>,

    /// The timer tracking this task. Used to trigger RCB-based `timeouts`.
    timer: Timer,

    /// A notifier used to cancel `handle_syscall_event` futures. For example,
    /// `tail_inject` should never return to the handler.
    notifier: Arc<Notify>,

    /// Child processes to wait on. When one of the children exits, it should be
    /// removed from this list.
    child_procs: Arc<Mutex<Children>>,

    /// Child threads to wait on. When one of the child threads exits, it should
    /// be removed from this list.
    child_threads: Arc<Mutex<Children>>,

    /// Channel to send child processes to that are left over by the time this
    /// task exits.
    orphanage: mpsc::Sender<Child>,

    /// broadcast to kill all daemons
    daemon_kill_switch: broadcast::Sender<()>,

    /// Channel to damonize a process
    daemonizer: mpsc::Sender<broadcast::Receiver<()>>,

    /// The rx end of `daemonizer`.
    daemonizer_rx: Option<mpsc::Receiver<broadcast::Receiver<()>>>,

    /// Total number of tasks
    ntasks: Arc<AtomicUsize>,

    /// Total number of daemons
    ndaemons: Arc<AtomicUsize>,

    /// Task is a daemon
    is_a_daemon: bool,

    /// Software breakpoints.
    // NB: For multi-threaded programs, sw breakpoints apply to all threads
    // because they're in the same address space. Hence removing sw
    // breakpoint in one thread also remove it for the rest of the threads
    // in the same process group. *However*, our model is slightly different
    // because we use different tx/rx channels even the threads are in the
    // same process group, hence each threads owns `breakpoints: HashMap`
    // instead of `Arc<Mutex<..>>`.
    breakpoints: HashMap<u64, u64>,

    /// Notify gdbserver start accepting incoming packets.
    gdbserver_start_tx: Option<oneshot::Sender<()>>,

    /// task is suspended (received SIGSTOP)
    suspended: Arc<AtomicBool>,

    /// Notify gdbserver there's a new stop event.
    gdb_stop_tx: Option<mpsc::Sender<StoppedInferior>>,

    /// Task is attached by gdb.
    // NB: gdb doesn't always attach everything, when fork/clone is called.
    // gdb also allows detach from a task, and re-attach again.
    attached_by_gdb: bool,

    /// Task is resumed by gdb.
    // NB: gdb doesn't always attach everything, when fork/clone is called.
    // gdb also allows detach from a task, and re-attach again.
    resumed_by_gdb: Option<ResumeAction>,

    /// GDB resume request, gdbstub is the sender
    gdb_resume_tx: Option<mpsc::Sender<ResumeInferior>>,

    /// GDB resume request, reverie is the receiver
    gdb_resume_rx: Option<mpsc::Receiver<ResumeInferior>>,

    /// Request sent by gdb. the tx channel is used by gdb instead of
    /// `TracedTask`.
    gdb_request_tx: Option<mpsc::Sender<GdbRequest>>,

    /// Receiver to receive gdb request.
    gdb_request_rx: Option<mpsc::Receiver<GdbRequest>>,

    /// Wait to be resumed when in sigstop due to all stop mode.
    exit_suspend_tx: Option<mpsc::Sender<Pid>>,

    /// Wait to be resumed when in sigstop due to all stop mode.
    exit_suspend_rx: Option<mpsc::Receiver<Pid>>,

    /// Suspended task when hitting swbp. This is used to implement gdb's
    /// all stop mode.
    suspended_tasks: BTreeMap<Pid, Suspended>,

    /// Task needs (single) step over the swbp instruciton when a swbp is
    /// hit. unless this is done, if is not safe for other threads running
    /// in parallel to report breakpoint, otherwise there're could be an
    /// interleaved step-over, which might remove the breakpoint, hence
    /// causing others to miss the breakpoint.
    needs_step_over: Arc<Mutex<()>>,

    /// Whether or not the tool is currently holding a handle on the guest Stack (and thus
    /// potentially using actual stack memory within the guest).
    stack_checked_out: Arc<AtomicBool>,
}

impl<L: Tool> fmt::Debug for TracedTask<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TracedTask")
            .field("tid", &self.tid)
            .field("pid", &self.pid)
            .field("ppid", &self.ppid)
            .finish()
    }
}

impl<L: Tool> TracedTask<L> {
    /// Create a new TracedTask.
    pub fn new(
        tid: Pid,
        cfg: <L::GlobalState as GlobalTool>::Config,
        gs_ref: Arc<L::GlobalState>,
        events: &Subscription,
        orphanage: mpsc::Sender<Child>,
        daemon_kill_switch: broadcast::Sender<()>,
        mut gdbserver: Option<GdbServer>,
    ) -> Self {
        let process_state = Arc::new(L::new(tid, &cfg));
        let global_state = GlobalState {
            gs_ref,
            cfg,
            subscriptions: Arc::new(events.clone()),
            sequentialized_guest: Arc::new(
                gdbserver
                    .as_ref()
                    .map(|s| s.sequentialized_guest)
                    .unwrap_or(false),
            ),
        };
        let thread_state = process_state.init_thread_state(tid, None);
        let (next_state, next_state_rx) = mpsc::channel(1);
        let (daemonizer, daemonizer_rx) = mpsc::channel(1);
        let (gdb_resume_tx, gdb_resume_rx) = mpsc::channel(1);
        let (gdb_request_tx, gdb_request_rx) = mpsc::channel(1);
        let (exit_suspend_tx, exit_suspend_rx) = mpsc::channel(16);
        Self {
            tid,
            pid: tid,
            ppid: None,
            thread_state,
            process_state,
            global_state,
            has_cpuid_interception: false,
            pending_syscall: None,
            next_state,
            next_state_rx: Some(next_state_rx),
            timer: Timer::new(tid, tid),
            notifier: Arc::new(Notify::new()),
            pending_signal: None,
            child_procs: Arc::new(Mutex::new(Children::new())),
            child_threads: Arc::new(Mutex::new(Children::new())),
            orphanage,
            daemon_kill_switch,
            daemonizer,
            daemonizer_rx: Some(daemonizer_rx),
            ntasks: Arc::new(AtomicUsize::new(1)),
            ndaemons: Arc::new(AtomicUsize::new(0)),
            is_a_daemon: false,
            gdbserver_start_tx: gdbserver.as_mut().and_then(|s| s.server_tx.take()),
            gdb_stop_tx: gdbserver
                .as_mut()
                .and_then(|s| s.inferior_attached_tx.take()),
            attached_by_gdb: false,
            resumed_by_gdb: None,
            gdb_resume_tx: Some(gdb_resume_tx),
            gdb_resume_rx: Some(gdb_resume_rx),
            breakpoints: HashMap::new(),
            suspended: Arc::new(AtomicBool::new(false)),
            gdb_request_tx: Some(gdb_request_tx),
            gdb_request_rx: Some(gdb_request_rx),
            exit_suspend_tx: Some(exit_suspend_tx),
            exit_suspend_rx: Some(exit_suspend_rx),
            needs_step_over: Arc::new(Mutex::new(())),
            suspended_tasks: BTreeMap::new(),
            stack_checked_out: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a child TracedTask corresponding to a clone()
    fn cloned(&self, child: Pid) -> Self {
        let global_state = self.global_state.clone();
        let process_state = self.process_state.clone();
        let thread_state =
            process_state.init_thread_state(child, Some((self.tid, &self.thread_state)));
        let (next_state, next_state_rx) = mpsc::channel(1);
        let (daemonizer, daemonizer_rx) = mpsc::channel(1);
        let (gdb_resume_tx, gdb_resume_rx) = mpsc::channel(1);
        let (gdb_request_tx, gdb_request_rx) = mpsc::channel(1);
        let (exit_suspend_tx, exit_suspend_rx) = mpsc::channel(16);
        self.ntasks.fetch_add(1, Ordering::SeqCst);
        Self {
            tid: child,
            pid: self.pid,
            ppid: self.ppid,
            thread_state,
            process_state,
            global_state,
            has_cpuid_interception: self.has_cpuid_interception,
            pending_syscall: None,
            next_state,
            next_state_rx: Some(next_state_rx),
            timer: Timer::new(self.pid, child),
            notifier: Arc::new(Notify::new()),
            pending_signal: None,
            child_procs: self.child_procs.clone(),
            child_threads: self.child_threads.clone(),
            orphanage: self.orphanage.clone(),
            daemon_kill_switch: self.daemon_kill_switch.clone(),
            daemonizer,
            daemonizer_rx: Some(daemonizer_rx),
            ntasks: self.ntasks.clone(),
            ndaemons: self.ndaemons.clone(),
            is_a_daemon: self.is_a_daemon,
            gdbserver_start_tx: None,
            gdb_stop_tx: None,
            attached_by_gdb: self.attached_by_gdb,
            resumed_by_gdb: self.resumed_by_gdb,
            gdb_resume_tx: Some(gdb_resume_tx),
            gdb_resume_rx: Some(gdb_resume_rx),
            breakpoints: self.breakpoints.clone(),
            suspended: Arc::new(AtomicBool::new(false)),
            gdb_request_tx: Some(gdb_request_tx),
            gdb_request_rx: Some(gdb_request_rx),
            exit_suspend_tx: Some(exit_suspend_tx),
            exit_suspend_rx: Some(exit_suspend_rx),
            needs_step_over: self.needs_step_over.clone(),
            suspended_tasks: BTreeMap::new(),
            stack_checked_out: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a child TracedTask corresponding to a fork()
    fn forked(&self, child: Pid) -> Self {
        let process_state = Arc::new(L::new(child, &self.global_state.cfg));
        let thread_state =
            process_state.init_thread_state(child, Some((self.tid, &self.thread_state)));
        let (next_state, next_state_rx) = mpsc::channel(1);
        let (daemonizer, daemonizer_rx) = mpsc::channel(1);
        let (gdb_resume_tx, gdb_resume_rx) = mpsc::channel(1);
        let (gdb_request_tx, gdb_request_rx) = mpsc::channel(1);
        let (exit_suspend_tx, exit_suspend_rx) = mpsc::channel(16);
        self.ntasks.fetch_add(1, Ordering::SeqCst);
        Self {
            tid: child,
            pid: child,
            ppid: Some(self.pid),
            thread_state,
            process_state,
            global_state: self.global_state.clone(),
            has_cpuid_interception: self.has_cpuid_interception,
            pending_syscall: None,
            next_state,
            next_state_rx: Some(next_state_rx),
            timer: Timer::new(child, child),
            notifier: Arc::new(Notify::new()),
            pending_signal: None,
            child_procs: Arc::new(Mutex::new(Children::new())),
            child_threads: Arc::new(Mutex::new(Children::new())),
            orphanage: self.orphanage.clone(),
            daemon_kill_switch: self.daemon_kill_switch.clone(),
            daemonizer,
            daemonizer_rx: Some(daemonizer_rx),
            ntasks: self.ntasks.clone(),
            ndaemons: self.ndaemons.clone(),
            // NB: if daemon forks, then its child's parent pid is no longer 1.
            is_a_daemon: false,
            gdbserver_start_tx: None,
            gdb_stop_tx: None,
            attached_by_gdb: self.attached_by_gdb,
            resumed_by_gdb: None,
            gdb_resume_tx: Some(gdb_resume_tx),
            gdb_resume_rx: Some(gdb_resume_rx),
            breakpoints: self.breakpoints.clone(),
            suspended: Arc::new(AtomicBool::new(false)),
            gdb_request_tx: Some(gdb_request_tx),
            gdb_request_rx: Some(gdb_request_rx),
            exit_suspend_tx: Some(exit_suspend_tx),
            exit_suspend_rx: Some(exit_suspend_rx),
            needs_step_over: Arc::new(Mutex::new(())),
            suspended_tasks: BTreeMap::new(),
            stack_checked_out: Arc::new(AtomicBool::new(false)),
        }
    }

    fn get_syscall(&self, task: &Stopped) -> Result<Syscall, TraceError> {
        let regs = task.getregs()?;
        let nr = Sysno::from(regs.orig_syscall() as i32);

        let args = regs.args();

        Ok(Syscall::from_raw(
            nr,
            SyscallArgs::new(
                args.0 as usize,
                args.1 as usize,
                args.2 as usize,
                args.3 as usize,
                args.4 as usize,
                args.5 as usize,
            ),
        ))
    }
}

fn set_ret(task: &Stopped, ret: Reg) -> Result<Reg, TraceError> {
    let mut regs = task.getregs()?;
    let old = regs.ret();
    *regs.ret_mut() = ret;
    task.setregs(regs)?;
    Ok(old)
}

/// Handles a potentially internal error, converting it to an exit status.
async fn handle_internal_error(err: Error) -> Result<ExitStatus, reverie::Error> {
    match err {
        Error::Internal(TraceError::Died(zombie)) => Ok(zombie.reap().await),
        Error::Internal(TraceError::Errno(errno)) => Err(errno.into()),
        Error::External(err) => Err(err),
    }
}

/// Helper for canceling handlers.
async fn cancellable<F>(notifier: Arc<Notify>, f: F) -> Option<F::Output>
where
    F: Future,
{
    futures::select! {
        () = notifier.notified().fuse() => None,
        result = f.fuse() => Some(result),
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum SegfaultTrapInfo {
    Cpuid,
    Rdtscs(Rdtsc),
}

#[cfg(target_arch = "x86_64")]
impl SegfaultTrapInfo {
    /// Check if segfault is called by cpuid/rdtsc trap
    pub fn decode_segfault(insn_at_rip: u64) -> Option<SegfaultTrapInfo> {
        if insn_at_rip & 0xffffu64 == 0xa20fu64 {
            Some(SegfaultTrapInfo::Cpuid)
        } else if insn_at_rip & 0xffffu64 == 0x310fu64 {
            Some(SegfaultTrapInfo::Rdtscs(Rdtsc::Tsc))
        } else if insn_at_rip & 0xffffffu64 == 0xf9010fu64 {
            Some(SegfaultTrapInfo::Rdtscs(Rdtsc::Tscp))
        } else {
            None
        }
    }
}

// restore syscall context when it returns. This is needed because we might
// have injected a different syscall (or arguments) in handle_seccomp.
fn restore_context(
    task: &Stopped,
    context: libc::user_regs_struct,
    retval: Option<Reg>,
) -> Result<(), TraceError> {
    let mut regs = task.getregs()?;

    if let Some(ret) = retval {
        *regs.ret_mut() = ret;
    }

    // Restore instruction pointer.
    *regs.ip_mut() = context.ip();

    // Restore syscall arguments.
    regs.set_args(context.args());

    // This is needed when syscall is interrupted by a signal (ERESTARTSYS)
    // we need restore the original syscall number as well because it is
    // possible syscall is reinjected as a different variant, like vfork ->
    // clone, which accepts different arguments.
    *regs.orig_syscall_mut() = context.orig_syscall();

    // NB: syscall also clobbers %rcx/%r11, but we're not required to restore
    // them, because the syscall is finished and they're supposed to change.
    // TL&DR: do not restore %rcx/%r11 here.

    task.setregs(regs)
}

impl<L: Tool + 'static> TracedTask<L> {
    #[cfg(target_arch = "x86_64")]
    async fn intercept_cpuid(&mut self) -> Result<(), Errno> {
        use reverie::syscalls::ArchPrctl;
        use reverie::syscalls::ArchPrctlCmd;

        self.inject_with_retry(ArchPrctl::new().with_cmd(ArchPrctlCmd::ARCH_SET_CPUID(0)))
            .await
            .map(|_| ())
    }

    /// Perform the very first setup of a fresh tracee process:
    ///
    /// (1) Set up the special reverie/guest shared page in the tracee.
    ///
    /// (2) Also disables vdso within the guest
    ///
    /// Warning: this function MUTATES guest code to accomplish the modifications, even though this
    /// mutation is undone before it returns.  As a result, it  has an extra precondition.
    ///
    /// Precondition: all threads in the guest process are stopped. Otherwise a guest state may be
    /// executing the instructions that are mutated and may crash (due to problems with incoherent
    /// instruction fetch resulting in non-atomic writes to instructions that straddle cache line
    /// boundaries).
    ///
    /// Precondition: the caller is entitled to execute (blocking, destructive) waitpids against the
    /// target tracee.  This must not race with concurrent asynchronous tasks operating on the same
    /// TID.
    ///
    /// Postcondition: the guest registers and code memory are restored to their original state,
    /// including RIP, but the vdso page and special shared page are modified accordingly.
    pub async fn tracee_preinit(&mut self, task: Stopped) -> Result<Stopped, TraceError> {
        type SavedInstructions = [u8; 8];

        /// Helper function for tracee_preinit that does the core work.
        async fn setup_special_mmap_page(
            task: Stopped,
            saved_regs: &libc::user_regs_struct,
        ) -> Result<Stopped, TraceError> {
            // NOTE: This point in the code assumes that a specific instruction
            // sequence "SYSCALL; INT3", has been patched into the guest, and
            // that RIP points to the syscall.
            let mut regs = saved_regs.clone();

            let page_addr = cp::PRIVATE_PAGE_OFFSET;

            *regs.syscall_mut() = Sysno::mmap as Reg;
            *regs.orig_syscall_mut() = regs.syscall();
            regs.set_args((
                page_addr as Reg,
                cp::PRIVATE_PAGE_SIZE as Reg,
                (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as Reg,
                (libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_ANONYMOUS) as Reg,
                -1i64 as Reg,
                0,
            ));

            task.setregs(regs)?;
            // Execute the injected mmap call.
            let mut running = task.step(None)?;

            // loop until second breakpoint hit after injected syscall.
            let task = loop {
                let (task, event) = running.next_state().await?.assume_stopped();
                match event {
                    Event::Signal(Signal::SIGTRAP) => break task,
                    Event::Signal(sig) => {
                        // We can catch spurious signals here, such as SIGWINCH.
                        // All we can do is skip over them.
                        tracing::debug!(
                            "[{}] Skipping {:?} during initialization",
                            task.pid(),
                            event
                        );
                        running = task.resume(sig)?;
                    }
                    Event::Seccomp => {
                        // Injected mmap trapped. We may not necessarily
                        // intercept a seccomp event here if the tool hasn't
                        // subscribed to the mmap syscall.
                        running = task.resume(None)?;
                    }
                    unknown => {
                        panic!("task {} returned unknown event {:?}", task.pid(), unknown);
                    }
                }
            };

            // Make sure we got our desired address.
            assert_eq!(
                Errno::from_ret(task.getregs()?.ret() as usize)?,
                page_addr,
                "Could not mmap address {}",
                page_addr
            );

            cp::populate_mmap_page(task.pid().into(), page_addr).map_err(|err| err)?;

            // Restore our saved registers, including our instruction pointer.
            task.setregs(*saved_regs)?;
            Ok(task)
        }

        /// Put the guest into the weird state where it has an
        /// "INT3;SYSCALL;INT3" patched into the code wherever RIP happens to be
        /// pointing. It leaves RIP pointing at the syscall instruction. This
        /// allows forcible injection of syscalls into the guest.
        async fn establish_injection_state(
            mut task: Stopped,
        ) -> Result<(Stopped, libc::user_regs_struct, SavedInstructions), TraceError> {
            #[cfg(target_arch = "x86_64")]
            const SYSCALL_BP: SavedInstructions = [
                0x0f, 0x05, // syscall
                0xcc, // int3
                0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // padding
            ];

            #[cfg(target_arch = "aarch64")]
            const SYSCALL_BP: SavedInstructions = [
                0x01, 0x00, 0x00, 0xd4, // svc 0
                0x20, 0x00, 0x20, 0xd4, // brk 1
            ];

            // Save the original registers so we can restore them later.
            let regs = task.getregs()?;

            // Saved instruction memory
            let ip = AddrMut::from_raw(regs.ip() as usize).unwrap();
            let saved: SavedInstructions = task.read_value(ip)?;

            // Patch the tracee at the current instruction pointer.
            //
            // NOTE: `process_vm_writev` cannot write to write-protected pages,
            // but `PTRACE_POKEDATA` can! Thus, we need to make sure we only
            // write one word-sized chunk at a time. Luckily, the instructions
            // we want to inject fit inside of just one 64-bit word.
            task.write_value(ip.cast(), &SYSCALL_BP)?;

            Ok((task, regs, saved))
        }

        /// Undo the effects of `establish_injection_state` and put the program
        /// code memory and instruction pointer back to normal.
        fn remove_injection_state(
            task: &mut Stopped,
            regs: libc::user_regs_struct,
            saved: SavedInstructions,
        ) -> Result<(), TraceError> {
            // NOTE: Again, because `process_vm_writev` cannot write to
            // write-protected pages, we must write in word-sized chunks with
            // PTRACE_POKEDATA.
            let ip = AddrMut::from_raw(regs.ip() as usize).unwrap();
            task.write_value(ip, &saved)?;
            task.setregs(regs)?;
            Ok(())
        }

        let (task, regs, prev_state) = establish_injection_state(task).await?;
        let mut task = setup_special_mmap_page(task, &regs).await?;

        // Restore registers after adding our temporary injection state.
        remove_injection_state(&mut task, regs, prev_state)?;

        vdso::vdso_patch(self).await.expect("unable to patch vdso");

        // Protect our trampoline page from being written to. We won't need to
        // change this again for the lifetime of the guest process.
        self.inject_with_retry(
            Mprotect::new()
                .with_addr(AddrMut::from_raw(cp::TRAMPOLINE_BASE))
                .with_len(cp::TRAMPOLINE_SIZE)
                .with_protection(ProtFlags::PROT_READ | ProtFlags::PROT_EXEC),
        )
        .await?;

        // Try to intercept cpuid instructions on x86_64
        #[cfg(target_arch = "x86_64")]
        if self.global_state.subscriptions.has_cpuid() {
            self.has_cpuid_interception = self.intercept_cpuid().await.map_err(|err| {
                match err {
                    Errno::ENODEV => tracing::warn!(
                        "Unable to intercept CPUID: Underlying hardware does not support CPUID faulting"
                    ),
                    err => tracing::warn!("Unable to intercept CPUID: {}", err),
                }

                err
            }).is_ok();
        }

        // Restore registers again after we've injected syscalls so that we
        // don't leave the return value register (%rax) in a dirty state.
        task.setregs(regs)?;

        Ok(task)
    }

    #[cfg(target_arch = "x86_64")]
    async fn handle_cpuid(
        &mut self,
        mut regs: libc::user_regs_struct,
    ) -> Result<libc::user_regs_struct, TraceError> {
        let eax = regs.rax as u32;
        let ecx = regs.rcx as u32;
        let cpuid = self
            .process_state
            .clone()
            .handle_cpuid_event(self, eax, ecx)
            .await?;
        regs.rax = cpuid.eax as u64;
        regs.rbx = cpuid.ebx as u64;
        regs.rcx = cpuid.ecx as u64;
        regs.rdx = cpuid.edx as u64;
        regs.rip += 2;
        self.timer.finalize_requests();
        Ok(regs)
    }

    #[cfg(target_arch = "x86_64")]
    async fn handle_rdtscs(
        &mut self,
        mut regs: libc::user_regs_struct,
        request: Rdtsc,
    ) -> Result<libc::user_regs_struct, TraceError> {
        let retval = self
            .process_state
            .clone()
            .handle_rdtsc_event(self, request)
            .await?;
        regs.rax = retval.tsc & 0xffff_ffffu64;
        regs.rdx = retval.tsc >> 32;
        match request {
            Rdtsc::Tsc => {
                regs.rip += 2;
            }
            Rdtsc::Tscp => {
                regs.rip += 3;
                regs.rcx = retval.aux.unwrap_or(0) as u64;
            }
        }
        self.timer.finalize_requests();
        Ok(regs)
    }

    /// Returns `true` if the signal was actually meant for the timer, and
    /// therefore should not be forwarded to the tool / guest.
    async fn handle_timer(&mut self, task: Stopped) -> Result<(bool, Stopped), TraceError> {
        let task = match self.timer.handle_signal(task).await {
            Err(HandleFailure::ImproperSignal(task)) => return Ok((false, task)),
            Err(HandleFailure::Cancelled(task)) => return Ok((true, task)),
            Err(HandleFailure::TraceError(e)) => return Err(e),
            Err(HandleFailure::Event(wait)) => self.abort(Ok(wait)).await,
            Ok(task) => task,
        };
        self.process_state.clone().handle_timer_event(self).await;
        self.timer.finalize_requests();
        Ok((true, task))
    }

    /// Handle a state change in the guest, and leave it in a stopped state.
    /// Return the signal that the process would be resumed with, if any.
    ///
    /// Preconditions:
    ///  * running on the ptracer pthread
    ///
    /// Postconditions:
    ///  * guest thread may or may not be stopped, depending on value of GuestNext
    ///
    async fn handle_stop_event(&mut self, stopped: Stopped, event: Event) -> Result<Wait, Error> {
        self.timer.observe_event();
        // A task is processed by this loop on any state change, so we must
        // handle all possibilities here:
        Ok(match event {
            Event::Signal(sig) => self.handle_signal(stopped, sig).await?,
            // A state we reach in the middle, between the prehook (before exec
            // syscall) and the exec completing (posthook).
            Event::Exec(_new_pid) => self.handle_exec_event(stopped).await?,
            // A regular old system call.
            Event::Seccomp => self.handle_seccomp(stopped).await?,
            Event::NewChild(op, child) => self.handle_new_task(op, stopped, child, None).await?,
            Event::VforkDone => self.handle_vfork_done_event(stopped).await?,
            task_state => panic!("unknown task state: {:?}", task_state),
        })
    }

    async fn get_stop_tx(&self) -> Option<(Arc<AtomicBool>, mpsc::Sender<(Pid, Suspended)>)> {
        for child in self.child_threads.lock().await.deref_mut().into_iter() {
            if child.id() == self.tid() {
                return Some((child.suspended.clone(), child.wait_all_stop_tx.take()?));
            }
        }
        None
    }

    async fn handle_sigtrap(&mut self, task: Stopped) -> Result<HandleSignalResult, TraceError> {
        let resumed_by_gdb_step = self
            .resumed_by_gdb
            .map_or(false, |action| matches!(action, ResumeAction::Step(_)));
        let mut regs = task.getregs()?;
        let rip_minus_one = regs.ip() - 1;

        Ok(if self.breakpoints.contains_key(&rip_minus_one) {
            *regs.ip_mut() = rip_minus_one;
            let next_state = self.resume_from_swbreak(task, regs).await?;
            HandleSignalResult::SignalSuppressed(next_state)
        } else if resumed_by_gdb_step {
            self.notify_gdb_stop(StopReason::stopped(
                task.pid(),
                self.pid(),
                StopEvent::Signal(Signal::SIGTRAP),
                regs.into(),
            ))
            .await?;
            let running = self
                .await_gdb_resume(task, ExpectedGdbResume::Resume)
                .await?;
            HandleSignalResult::SignalSuppressed(running.next_state().await?)
        } else {
            let running = task.resume(None)?;
            HandleSignalResult::SignalSuppressed(running.next_state().await?)
        })
    }

    async fn handle_sigstop(&mut self, task: Stopped) -> Result<HandleSignalResult, TraceError> {
        let resumed_by_gdb_step = self
            .resumed_by_gdb
            .map_or(false, |action| matches!(action, ResumeAction::Step(_)));
        debug_assert!(!resumed_by_gdb_step);
        if let Some((suspended_flag, stop_tx)) = self.get_stop_tx().await {
            let notify_stop_tx = stop_tx
                .send((
                    task.pid(),
                    Suspended {
                        waker: self.exit_suspend_tx.clone(),
                        suspended: suspended_flag,
                    },
                ))
                .await;
            drop(stop_tx);
            if notify_stop_tx.is_ok() {
                if let Some(rx) = self.exit_suspend_rx.as_mut() {
                    let _resumed_by = rx.recv().await.unwrap();
                }
            }
        }
        Ok(HandleSignalResult::SignalSuppressed(
            task.resume(None)?.next_state().await?,
        ))
    }

    #[cfg(target_arch = "x86_64")]
    async fn handle_sigsegv(&mut self, task: Stopped) -> Result<HandleSignalResult, TraceError> {
        let regs = task.getregs()?;
        let trap_info = Addr::from_raw(regs.rip as usize)
            .and_then(|addr| task.read_value(addr).ok())
            .and_then(SegfaultTrapInfo::decode_segfault);
        Ok(match trap_info {
            Some(SegfaultTrapInfo::Cpuid) => {
                let regs = self.handle_cpuid(regs).await?;
                task.setregs(regs)?;
                HandleSignalResult::SignalSuppressed(task.resume(None)?.next_state().await?)
            }
            Some(SegfaultTrapInfo::Rdtscs(req)) => {
                let regs = self.handle_rdtscs(regs, req).await?;
                task.setregs(regs)?;
                HandleSignalResult::SignalSuppressed(task.resume(None)?.next_state().await?)
            }
            None => HandleSignalResult::SignalToDeliver(task, Signal::SIGSEGV),
        })
    }

    #[cfg(not(target_arch = "x86_64"))]
    async fn handle_sigsegv(&mut self, task: Stopped) -> Result<HandleSignalResult, TraceError> {
        Ok(HandleSignalResult::SignalToDeliver(task, Signal::SIGSEGV))
    }

    // handle ptrace signal delivery stop
    async fn handle_signal(&mut self, task: Stopped, sig: Signal) -> Result<Wait, TraceError> {
        tracing::debug!("[{}] handle_signal: received signal {}", task.pid(), sig);
        let result = match sig {
            Signal::SIGSEGV => self.handle_sigsegv(task).await?,
            Signal::SIGSTOP => self.handle_sigstop(task).await?,
            Signal::SIGTRAP => self.handle_sigtrap(task).await?,
            sig if sig == Timer::signal_type() => {
                let (was_timer, task) = self.handle_timer(task).await?;
                if was_timer {
                    HandleSignalResult::SignalSuppressed(task.resume(None)?.next_state().await?)
                } else {
                    HandleSignalResult::SignalToDeliver(task, sig)
                }
            }
            sig => HandleSignalResult::SignalToDeliver(task, sig),
        };

        match result {
            HandleSignalResult::SignalSuppressed(wait) => Ok(wait),
            HandleSignalResult::SignalToDeliver(task, sig) => {
                let sig = self
                    .process_state
                    .clone()
                    .handle_signal_event(self, sig)
                    .await?;
                self.timer.finalize_requests();
                Ok(task.resume(sig)?.next_state().await?)
            }
        }
    }

    // handle ptrace exec event
    async fn handle_exec_event(&mut self, task: Stopped) -> Result<Wait, TraceError> {
        // execve/execveat are tail injected, however, after exec, the new
        // program start as a clean slate, hence it is actually ok to do either
        // inject or tail inject after execve succeeded.
        self.pending_syscall = None;

        // TODO: Update PID? Need to write a test checking this.

        // Step the tracee to get the SIGTRAP that immediately follows the
        // PTRACE_EVENT_EXEC. We can't call `tracee_preinit` until after this
        // because when it tries to step the tracee, it'll get this SIGTRAP
        // signal instead.
        let (task, event) = task
            .step(None)?
            .wait_for_signal(Signal::SIGTRAP)
            .await?
            .assume_stopped();
        assert_eq!(event, Event::Signal(Signal::SIGTRAP));

        let task = self.tracee_preinit(task).await?;

        self.process_state.clone().handle_post_exec(self).await?;
        self.timer.finalize_requests();

        if self.attached_by_gdb {
            let request_tx = self.gdb_request_tx.clone();
            let resume_tx = self.gdb_resume_tx.clone();

            let proc_exe = format!("/proc/{}/exe", task.pid());
            let exe = std::fs::read_link(&proc_exe[..]).unwrap();

            let stopped = StoppedInferior {
                reason: StopReason::stopped(
                    task.pid(),
                    self.pid(),
                    StopEvent::Exec(exe),
                    task.getregs()?.into(),
                ),
                request_tx: request_tx.unwrap(),
                resume_tx: resume_tx.unwrap(),
            };

            // NB: notify initial gdb stop, this is the first time we can
            // tell gdb tracee is ready, because a new memory map has been
            // loaded (due to execve). Otherwise gdb may try to manipulate
            // old process' address space.
            if let Some(attach_tx) = self.gdb_stop_tx.as_ref() {
                let _ = attach_tx.send(stopped).await.unwrap();
            }
            let running = self
                .await_gdb_resume(task, ExpectedGdbResume::Resume)
                .await?;
            Ok(running.next_state().await?)
        } else {
            Ok(task.step(None)?.next_state().await?)
        }
    }

    async fn handle_seccomp(&mut self, mut task: Stopped) -> Result<Wait, Error> {
        let syscall = self.get_syscall(&task)?;
        let (nr, args) = syscall.into_parts();

        self.pending_syscall = Some((nr, args));

        let retval = cancellable(self.notifier.clone(), async {
            self.process_state
                .clone()
                .handle_syscall_event(self, syscall)
                .await
        })
        .await;

        // If no syscall was injected, then we need to suppress the implicit
        // syscall.
        if self.pending_syscall.is_some() {
            task = self.skip_seccomp_syscall(task).await?;
        }

        // Finalize timer requests after `skip_seccomp_syscall`, which may step
        self.timer.finalize_requests();

        if let Some(retval) = retval {
            let ret = match retval {
                Ok(x) => x as u64,
                Err(err) => (-(err.into_errno()?.into_raw() as i64)) as u64,
            };

            set_ret(&task, ret)?;
        }

        // Finally, resume the guest.
        let sig = self.pending_signal.take();
        Ok(task.resume(sig)?.next_state().await?)
    }

    async fn handle_new_task(
        &mut self,
        op: ChildOp,
        parent: Stopped,
        child: Running,
        context: Option<libc::user_regs_struct>,
    ) -> Result<Wait, TraceError> {
        tracing::debug!(
            "[scheduler] handling fork from parent {} to child {}: {:?}",
            parent.pid(),
            child.pid(),
            op
        );

        let mut child_task = match op {
            ChildOp::Clone => self.cloned(child.pid()),
            ChildOp::Fork => self.forked(child.pid()),
            ChildOp::Vfork => self.forked(child.pid()),
        };

        let (child_stop_tx, child_stop_rx) = mpsc::channel(1);
        child_task.gdb_stop_tx = Some(child_stop_tx);

        let daemonizer_rx = child_task.daemonizer_rx.take();
        let child_resume_tx = child_task.gdb_resume_tx.clone();
        let child_request_tx = child_task.gdb_request_tx.clone();
        let suspended = child_task.suspended.clone();

        if let Some(context) = context {
            restore_context(&parent, context, Some(child.pid().as_raw() as u64))?;
        }

        let id = child.pid();

        let task = tokio::task::spawn_local(async move {
            // The child could potentially exit here. In most cases the first
            // event we get here should be `Event::Signal(Signal::SIGSTOP)`, but
            // we can also receive `Event::Exit` if a thread is created via
            // `clone`, but immediately killed via an `exit_group`. We have to
            // handle that rare case here.
            //
            // NOTE: It is okay to call `wait` instead of the async `next_state`
            // here because the notifier is not yet aware of the new process.
            let (child, event) = child.wait().unwrap().assume_stopped();

            assert!(
                event == Event::Signal(Signal::SIGSTOP) || event == Event::Exit,
                "Got unexpected event {:?}",
                event
            );

            if let Some(context) = context {
                // Restore context, but only if the child hasn't arrived at
                // `Event::Exit`.
                if event == Event::Signal(Signal::SIGSTOP) {
                    restore_context(&child, context, None).unwrap();
                }
            }

            if child_task.is_a_daemon {
                child_task.ndaemons.fetch_add(1, Ordering::SeqCst);
            }

            let tid = child.pid();
            match child_task.run(child).await {
                Err(err) => {
                    tracing::error!("Error in tracee tid {}: {}", tid, err);

                    // We assume the tracee is stopped since this error likely
                    // originated from the tool itself when the tracee is
                    // already stopped. If the tracee is not in a stopped state,
                    // that's fine too and ignore the detach error.
                    let running = match Stopped::new_unchecked(tid).detach(None) {
                        Err(err) => {
                            // If we get an error here, the child process may
                            // not be in a ptrace stop.
                            tracing::error!("Failed to detach from {}: {}", tid, err);
                            return ExitStatus::Exited(1);
                        }
                        Ok(running) => running,
                    };

                    // Reap the process and get its exit status.
                    let (_pid, exit_status) = running.next_state().await.unwrap().assume_exited();
                    exit_status
                }
                Ok(exit_status) => exit_status,
            }
        });

        if op == ChildOp::Clone {
            let mut child_threads = self.child_threads.lock().await;
            child_threads.push(Child {
                id,
                suspended,
                wait_all_stop_tx: None,
                daemonizer_rx,
                handle: task,
            });
        } else {
            let mut child_procs = self.child_procs.lock().await;
            child_procs.push(Child {
                id,
                suspended,
                wait_all_stop_tx: None,
                daemonizer_rx,
                handle: task,
            });
        }

        let parent_regs = parent.getregs()?;
        if self.attached_by_gdb {
            // NB: We report T05;create event (for clone). However gdbserver
            // from binutils-gdb doesn't report it, even after toggling
            // QThreadEvents, as mentioned in https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#QThreadEvents
            // We report `create` event anyway.
            self.notify_gdb_stop(StopReason::new_task(
                self.tid(),
                self.pid(),
                id,
                parent_regs.into(),
                op,
                child_request_tx,
                child_resume_tx,
                Some(child_stop_rx),
            ))
            .await?;
            // We just reported a new event, wait for gdb resume.
            let running = self
                .await_gdb_resume(parent, ExpectedGdbResume::StepOnly)
                .await?;
            // NB: We could potentially hit a breakpoint after above resume,
            // make sure we don't miss the breakpoint and await for gdb
            // resume (once again). This is possible because result of
            // handle_new_task in from_task_state is ignored, while it could
            // be a valid state like SIGTRAP, which could be a breakpoint is
            // hit.
            running
                .next_state()
                .and_then(|wait| self.check_swbreak(wait))
                .await
        } else {
            Ok(parent.step(None)?.next_state().await?)
        }
    }

    async fn handle_vfork_done_event(&mut self, stopped: Stopped) -> Result<Wait, TraceError> {
        Ok(stopped.resume(None)?.next_state().await?)
    }

    async fn handle_exit_event(task: Stopped) -> Result<ExitStatus, TraceError> {
        // Nothing to do but resume and wait for the final exit status.
        let wait = task.resume(None)?.next_state().await?;
        let (_pid, exit_status) = wait.assume_exited();
        Ok(exit_status)
    }

    /// Aborts the current handler. This just sends a result through a channel to
    /// the `run_loop`, which should cause the current future to be dropped and
    /// canceled. Thus, this function will never return so that execution of the
    /// current future doesn't proceed any further.
    async fn abort(&mut self, result: Result<Wait, TraceError>) -> ! {
        self.next_state.send(result).await.unwrap();

        // Wait on a future that will never complete. This pending future will
        // be dropped when the channel receives the event just sent.
        future::pending().await
    }

    /// Marks the current task as exited via a channel. The receiver end of the
    /// channel should cause the current future to be dropped and canceled. Thus,
    /// this function will never return so that execution doesn't proceed any
    /// further.
    async fn exit(&mut self, exit_status: ExitStatus) -> ! {
        self.abort(Ok(Wait::Exited(self.tid(), exit_status))).await
    }

    /// Marks the current task as having successfully called `execve` and so it
    /// should never return.
    async fn execve(&mut self, next_state: Wait) -> ! {
        self.abort(Ok(next_state)).await
    }

    /// Triggers the tool exit callbacks.
    async fn tool_exit(self, exit_status: ExitStatus) -> Result<(), reverie::Error> {
        if self.is_main_thread() {
            // Wait for all child threads to fully exit. This *must* happen before
            // the main thread can exit.
            // TODO: Use FuturesUnordered instead of `join_all` for better
            // performance.
            {
                let children = self.child_threads.lock().await.take_inner();
                future::join_all(children).await;
            }

            // Check if there are any children who's futures are still pending. If
            // this is the case, then they shall be considered "orphans" and are
            // "adopted" by the tracer process who shall then wait for them to exit
            // and get their final exit code. Normally, when not running under
            // ptrace, orphans are adopted by the init process who should
            // automatically reap them by waiting for the final exit status.
            let (orphans, _) = {
                let mut child_procs = self.child_procs.lock().await;
                child_procs.deref_mut().await
            };

            for orphan in orphans.into_inner() {
                // Bon voyage.
                self.orphanage.send(orphan).await.unwrap();
            }

            let _ = self
                .notify_gdb_stop(StopReason::Exited(self.pid(), exit_status))
                .await;

            let wrapped = WrappedFrom(self.tid, &self.global_state);

            // Thread exit
            self.process_state
                .on_exit_thread(self.tid, &wrapped, self.thread_state, exit_status)
                .await?;

            // The try_unwrap and subsequent unwrap are safe to do. ptrace
            // guarantees that all threads in the thread group have exited
            // before the main thread.
            let process_state = Arc::try_unwrap(self.process_state).unwrap_or_else(|_| {
                // If you end up seeing this panic, make sure that all clones of
                // `process_state` are dropped before reaching this point.
                panic!("Reverie internal invariant broken. try_unwrap on process state failed")
            });
            let wrapped = WrappedFrom(self.tid, &self.global_state);
            process_state
                .on_exit_process(self.tid, &wrapped, exit_status)
                .await?;

            let ntasks_remaining = self.ntasks.fetch_sub(1, Ordering::SeqCst);
            let ndaemons = self.ndaemons.load(Ordering::SeqCst);

            if self.is_a_daemon {
                self.ndaemons.fetch_sub(1, Ordering::SeqCst);
            }

            if ntasks_remaining == 1 + ndaemons {
                // daemonize() might not get called, this is not an error.
                let _ = self.daemon_kill_switch.send(());
            }
        } else {
            let _ = self
                .notify_gdb_stop(StopReason::ThreadExited(
                    self.tid(),
                    self.pid(),
                    exit_status,
                ))
                .await;
            let wrapped = WrappedFrom(self.tid, &self.global_state);

            self.child_threads
                .lock()
                .await
                .retain(|child| child.id() != self.tid);

            // Thread exit
            self.process_state
                .on_exit_thread(self.tid, &wrapped, self.thread_state, exit_status)
                .await?;

            self.ntasks.fetch_sub(1, Ordering::SeqCst);
            if self.is_a_daemon {
                self.ndaemons.fetch_sub(1, Ordering::SeqCst);
            }
        }

        Ok(())
    }

    async fn run_loop(&mut self, task: Stopped) -> Result<ExitStatus, reverie::Error> {
        match self.run_loop_internal(task).await {
            Ok(exit_status) => Ok(exit_status),
            Err(err) => {
                // Note: Calling handle_internal_error cannot happen in the
                // `select!()` of the `run` function because then the exit
                // events that get generated in here cannot be caught by the
                // `select!()`.
                handle_internal_error(err).await
            }
        }
    }

    async fn run_loop_internal(&mut self, task: Stopped) -> Result<ExitStatus, Error> {
        // This is the beginning of the life of the guest. Allow the tool to
        // inject syscalls as soon as the thread starts.
        if let Some(Err(err)) = cancellable(self.notifier.clone(), async {
            self.process_state.clone().handle_thread_start(self).await
        })
        .await
        {
            // Propagate user errors. Don't care about the result of syscall injections.
            err.into_errno()?;
        }
        self.timer.finalize_requests();

        // Resume the guest for the first time. Note that the root task and
        // child tasks start out in a stopped state for different reasons: The
        // root task is stopped because of the SIGSTOP raised inside of `fork()`
        // after calling `traceme`. Child tasks start out in a running state,
        // but we wait for them to stop in `Event::NewChild`.
        //
        // NB: await_gdb_resume == resume if not attached_by_gdb.
        let running = self
            .await_gdb_resume(task, ExpectedGdbResume::Resume)
            .await?;

        // Notify gdb server (if any) that tracee is ready.
        if let Some(server_tx) = self.gdbserver_start_tx.take() {
            self.attached_by_gdb = true;
            server_tx.send(()).unwrap();
        }

        let mut task_state = running.next_state().await?;
        let mut next_state_rx = self.next_state_rx.take().unwrap();

        loop {
            match task_state {
                Wait::Stopped(stopped, event) => {
                    // Allow short-circuiting of the event stream. This makes it
                    // easier to send exit and execve events directly to the run
                    // loop from within `inject` or `tail_inject`.
                    let fut1 = next_state_rx.recv().fuse();
                    let fut2 = self.handle_stop_event(stopped, event).fuse();

                    futures::pin_mut!(fut1, fut2);

                    task_state = futures::select_biased! {
                        next_state = fut1 => {
                            if let Some(next_state) = next_state {
                                next_state.map_err(Error::Internal)
                            } else {
                                panic!()
                            }
                        }
                        next_state = fut2 => next_state,
                    }?;
                }
                Wait::Exited(pid, exit_status) => {
                    self.notify_gdb_stop(StopReason::Exited(pid, exit_status))
                        .await?;
                    break Ok(exit_status);
                }
            }
        }
    }

    /// Drive a single guest thread to completion. Returns the final exit code
    /// when that guest thread exits.
    pub async fn run(mut self, child: Stopped) -> Result<ExitStatus, reverie::Error> {
        let exit_status = {
            let exit_event = child.exit_event().fuse();
            let run_loop = self.run_loop(child).fuse();
            futures::pin_mut!(exit_event, run_loop);

            futures::select_biased! {
                task = exit_event => match Self::handle_exit_event(task).await {
                    Ok(exit_status) => exit_status,
                    Err(err) => handle_internal_error(err.into()).await?,
                },
                exit_status = run_loop => exit_status?,
            }
        };

        self.tool_exit(exit_status).await?;

        Ok(exit_status)
    }

    /// Skip the syscall which is about to happen in the tracee, switching the tracee
    /// from Seccomp() state to Stopped(SIGTRAP) state.
    ///
    /// This uses the convention that setting the syscall number to -1 causes the
    /// kernel to skip it. This function takes as argument the current register state
    /// and restores it after stepping over the skipped syscall instruction.
    ///
    /// Preconditions:
    ///  Ptrace tracee is in a (seccomp) stopped state.
    ///  The tracee was stopped with the RIP pointing just after a syscall instruction (+2).
    ///
    /// Postconditions:
    ///  Set tracee state to Stopped/SIGTRP.
    ///  Restore the registers to the state specified by the regs arg.
    async fn skip_seccomp_syscall(&mut self, task: Stopped) -> Result<Stopped, TraceError> {
        // So here we are, at ptrace seccomp stop, if we simply resume, the kernel
        // would do the syscall, without our patch. we change to syscall number to
        // -1, so that kernel would simply skip the syscall, so that we can jump to
        // our patched syscall on the first run. Please note after calling this
        // function, the task state will no longer be in ptrace event seccomp.
        #[cfg(target_arch = "x86_64")]
        let regs = task.getregs()?;

        #[cfg(target_arch = "x86_64")]
        {
            let mut new_regs = regs;
            *new_regs.orig_syscall_mut() = -1i64 as u64;
            task.setregs(new_regs)?;
        }

        #[cfg(target_arch = "aarch64")]
        task.set_syscall(-1)?;

        let mut running = task.step(None)?;

        // After the step, wait for the next transition. Note that this can return
        // an exited state if there is a group exit while some thread is blocked on
        // a syscall.
        loop {
            match running.next_state().await? {
                Wait::Stopped(task, Event::Signal(Signal::SIGTRAP)) => {
                    #[cfg(target_arch = "x86_64")]
                    task.setregs(regs)?;
                    break Ok(task);
                }
                Wait::Stopped(task, Event::Signal(sig)) => {
                    // We can get a spurious signal here, such as SIGWINCH. Skip
                    // past them until the tracee eventually arrives at SIGTRAP.
                    running = task.step(sig)?;
                }
                Wait::Stopped(task, event) => {
                    panic!(
                        "skip_seccomp_syscall: PID {} got unexpected event: {:?}",
                        task.pid(),
                        event
                    );
                }
                Wait::Exited(_pid, exit_status) => {
                    break self.exit(exit_status).await;
                }
            }
        }
    }

    /// inject syscall for given tracee
    ///
    /// NB: limitations:
    /// - tracee must be in stopped state.
    /// - the tracee must have returned from PTRACE_EXEC_EVENT
    /// - must be called on the ptracer thread
    ///
    /// Side effects:
    /// - mutates contexts
    async fn untraced_syscall(
        &mut self,
        task: Stopped,
        nr: Sysno,
        args: SyscallArgs,
    ) -> Result<Result<i64, Errno>, TraceError> {
        tracing::trace!(
            "[scheduler/tool] (pid = {}) untraced syscall: {:?}",
            task.pid(),
            nr
        );
        let mut regs = task.getregs()?;

        let oldregs = regs;

        *regs.syscall_mut() = nr as Reg;
        *regs.orig_syscall_mut() = nr as Reg;
        regs.set_args((
            args.arg0 as Reg,
            args.arg1 as Reg,
            args.arg2 as Reg,
            args.arg3 as Reg,
            args.arg4 as Reg,
            args.arg5 as Reg,
        ));

        // Jump to our private page to run the syscall instruction there. See
        // `populate_mmap_page` for details.
        *regs.ip_mut() = cp::PRIVATE_PAGE_OFFSET as Reg;

        task.setregs(regs)?;

        // Step to run the syscall instruction.
        let wait = task.step(None)?.next_state().await?;

        // Get the result of the syscall to return to the caller.
        self.from_task_state(wait, Some(oldregs)).await
    }

    // Helper function
    async fn private_inject(
        &mut self,
        task: Stopped,
        nr: Sysno,
        args: SyscallArgs,
    ) -> Result<Result<i64, Errno>, TraceError> {
        let task = self.skip_seccomp_syscall(task).await?;

        self.untraced_syscall(task, nr, args).await
    }

    async fn from_task_state(
        &mut self,
        wait_status: Wait,
        context: Option<libc::user_regs_struct>,
    ) -> Result<Result<i64, Errno>, TraceError> {
        match wait_status {
            Wait::Stopped(stopped, event) => match event {
                Event::Signal(_sig) if context.is_none() => {
                    let regs = stopped.getregs()?;
                    Ok(Ok(regs.ret() as i64))
                }
                Event::Signal(sig) => {
                    let mut regs = stopped.getregs()?;
                    // NB: it is possible to get interrupted by signal (such as
                    // SIGCHLD) before single step finishes (in that case rip ==
                    // 0x7000_0000u64).
                    debug_assert!(
                        regs.ip() as usize == cp::PRIVATE_PAGE_OFFSET + cp::SYSCALL_INSTR_SIZE
                            || regs.ip() as usize == cp::PRIVATE_PAGE_OFFSET
                    );
                    // interrupted by signal, return -ERESTARTSYS so that tracee can do a
                    // restart_syscall.
                    if sig != Signal::SIGTRAP {
                        *regs.ret_mut() = (-(Errno::ERESTARTSYS.into_raw()) as i64) as u64;
                        self.pending_signal = Some(sig);
                    }
                    if let Some(context) = context {
                        // Restore syscall args to original values. This is
                        // needed when we convert syscalls like SYS_open ->
                        // SYS_openat, syscall args are modified need to restore
                        // it back.
                        restore_context(&stopped, context, None)?;
                    }
                    Ok(Errno::from_ret(regs.ret() as usize).map(|x| x as i64))
                }
                Event::NewChild(op, child) => {
                    let ret = child.pid().as_raw() as i64;
                    let _ = self.handle_new_task(op, stopped, child, context).await?;
                    Ok(Ok(ret))
                }
                Event::Exec(_new_pid) => {
                    // This should never return.
                    let next_state = self.handle_exec_event(stopped).await?;
                    self.execve(next_state).await
                }
                Event::Syscall => {
                    let regs = stopped.getregs()?;
                    Ok(Errno::from_ret(regs.ret() as usize).map(|x| x as i64))
                }
                st => panic!("untraced_syscall returned unknown state: {:?}", st),
            },
            Wait::Exited(_pid, exit_status) => self.exit(exit_status).await,
        }
    }

    async fn do_inject(&mut self, nr: Sysno, args: SyscallArgs) -> Result<i64, Errno> {
        match self.inner_inject(nr, args).await {
            Ok(ret) => ret,
            Err(err) => self.abort(Err(err)).await,
        }
    }

    async fn inner_inject(
        &mut self,
        nr: Sysno,
        args: SyscallArgs,
    ) -> Result<Result<i64, Errno>, TraceError> {
        let task = self.assume_stopped();

        tracing::debug!(
            "[tool] (tid {}) beginning inject of syscall: {}, args {:?}",
            self.tid(),
            nr,
            args,
        );

        if self.pending_syscall.take() == Some((nr, args)) {
            // If we're reinjecting the same syscall with the same arguments,
            // then we can just let the tracee continue and stop at sysexit.
            let wait = task.syscall(None)?.next_state().await?;
            self.from_task_state(wait, None).await
        } else {
            self.private_inject(task, nr, args).await
        }
    }

    async fn do_tail_inject(&mut self, nr: Sysno, args: SyscallArgs) -> ! {
        match self.inner_tail_inject(nr, args).await {
            Ok(_) => {
                // Drop the handle_syscall_event future.
                self.notifier.notify_one();
                future::pending().await
            }
            Err(err) => self.abort(Err(err)).await,
        }
    }

    async fn inner_tail_inject(
        &mut self,
        nr: Sysno,
        args: SyscallArgs,
    ) -> Result<Result<i64, Errno>, TraceError> {
        let tid = self.tid();

        tracing::info!(
            "[tool] (tid {}) beginning tail_inject of syscall: {}",
            &tid,
            nr,
        );

        let task = self.assume_stopped();

        if self.pending_syscall.take() == Some((nr, args)) {
            // We're reinjecting the same syscall with the same arguments.
            // Nothing to actually do but let the tracee resume.

            // The return value here doesn't matter.
            Ok(Ok(0))
        } else {
            // Syscall has already been injected. Can't do the optimization.
            self.private_inject(task, nr, args).await
        }
    }

    /// Get a ptrace stub which can do ptrace operations
    // Assumption: Task is in stopped state as long as we have a valid
    // reference to `TracedTask`.
    fn assume_stopped(&self) -> Stopped {
        Stopped::new_unchecked(self.tid())
    }

    async fn notify_gdb_stop(&self, reason: StopReason) -> Result<(), TraceError> {
        if !self.attached_by_gdb {
            return Ok(());
        }

        if let Some(stop_tx) = self.gdb_stop_tx.as_ref() {
            let request_tx = self.gdb_request_tx.clone();
            let resume_tx = self.gdb_resume_tx.clone();
            let stop = StoppedInferior {
                reason,
                request_tx: request_tx.unwrap(),
                resume_tx: resume_tx.unwrap(),
            };
            let _ = stop_tx.send(stop).await.unwrap();
        }
        Ok(())
    }

    async fn handle_gdb_request(&mut self, request: Option<GdbRequest>) {
        if let Some(request) = request {
            match request {
                GdbRequest::SetBreakpoint(bkpt, reply_tx) => {
                    if bkpt.ty == BreakpointType::Software {
                        let result = self.add_breakpoint(bkpt.addr).await;
                        reply_tx.send(result).unwrap();
                    }
                }
                GdbRequest::RemoveBreakpoint(bkpt, reply_tx) => {
                    if bkpt.ty == BreakpointType::Software {
                        let result = self.remove_breakpoint(bkpt.addr).await;
                        reply_tx.send(result).unwrap();
                    }
                }
                GdbRequest::ReadInferiorMemory(addr, length, reply_tx) => {
                    let result = self.read_inferior_memory(addr, length);
                    reply_tx.send(result).unwrap();
                }
                GdbRequest::WriteInferiorMemory(addr, length, data, reply_tx) => {
                    let result = self.write_inferior_memory(addr, length, data);
                    reply_tx.send(result).unwrap();
                }
                GdbRequest::ReadRegisters(reply_tx) => {
                    let result = self.read_registers();
                    reply_tx.send(result).unwrap();
                }
                GdbRequest::WriteRegisters(core_regs, reply_tx) => {
                    let result = self.write_registers(core_regs);
                    reply_tx.send(result).unwrap();
                }
            }
        }
    }

    async fn handle_gdb_resume(
        resume: Option<ResumeInferior>,
        task: Stopped,
        resume_action: ExpectedGdbResume,
    ) -> Result<(Running, Option<ResumeInferior>), TraceError> {
        match resume {
            None => Ok((task.resume(None)?, None)),
            Some(resume) => {
                let is_resume = resume_action == ExpectedGdbResume::Resume || resume.detach;
                let is_step_only = resume_action == ExpectedGdbResume::StepOnly;
                let running = match resume.action {
                    ResumeAction::Step(sig) => task.step(sig)?,
                    ResumeAction::Continue(sig) if is_resume => task.resume(sig)?,
                    ResumeAction::Continue(sig) if is_step_only => task.step(sig)?,
                    action => panic!(
                        "[pid = {}] unexpected resume action {:?}, expecting: {:?}",
                        task.pid(),
                        action,
                        resume_action,
                    ),
                };
                Ok((running, Some(resume)))
            }
        }
    }

    async fn await_gdb_resume(
        &mut self,
        task: Stopped,
        resume_action: ExpectedGdbResume,
    ) -> Result<Running, TraceError> {
        if !self.attached_by_gdb {
            return task.resume(None);
        }

        let mut resume_rx = self.gdb_resume_rx.take().unwrap();
        let mut gdb_request_rx = self.gdb_request_rx.take().unwrap();

        let mut resume_future = Box::pin(resume_rx.recv());

        let (running, resumed) = loop {
            let request_future = Box::pin(gdb_request_rx.recv());

            match future::select(request_future, resume_future).await {
                Either::Left((gdb_request, pending_resume_future)) => {
                    self.handle_gdb_request(gdb_request).await;
                    resume_future = pending_resume_future;
                }
                Either::Right((resume_request, _)) => {
                    break Self::handle_gdb_resume(resume_request, task, resume_action).await?;
                }
            }
        };

        self.gdb_request_rx = Some(gdb_request_rx);
        self.gdb_resume_rx = Some(resume_rx);

        if let Some(resumed) = resumed {
            if resumed.detach {
                // no longer report stop event to gdb
                // self.gdb_stop_tx = None;
                self.attached_by_gdb = false;
            }

            self.resumed_by_gdb = Some(resumed.action);
        }

        Ok(running)
    }

    /// Resume from a software breakpoint set by gdb. The resume action is
    /// initiated from gdb (client).
    // NB: caller to %rip accordingly prior to hitting breakpoint.
    async fn resume_from_swbreak(
        &mut self,
        task: Stopped,
        regs: libc::user_regs_struct,
    ) -> Result<Wait, TraceError> {
        task.setregs(regs)?;

        // Task could be hitting a breakpoint, after previously suspended by
        // a different task, need to notify this task is fully stopped.
        self.suspended.store(true, Ordering::SeqCst);
        if let Some((suspended_flag, stop_tx)) = self.get_stop_tx().await {
            let _ = stop_tx
                .send((
                    self.tid(),
                    Suspended {
                        waker: None,
                        suspended: suspended_flag,
                    },
                ))
                .await
                .unwrap();
        }

        // When resuming from breakpoint, gdb (client) needs to remove the
        // breakpoint (implying restore the original instruction), do a
        // single-step (step-over), and re-insert the breakpoint.
        // Because removing (sw) breakpoint modifies the instructions, other
        // thread might miss the breakpoint after the breakpoint is removed
        // and before the breakpoint is (re-)inserted. Hence we must make
        // serialize this sequence.
        let needs_step_over = self.needs_step_over.clone();
        let _guard = needs_step_over.lock().await;

        self.notify_gdb_stop(StopReason::stopped(
            task.pid(),
            self.pid(),
            StopEvent::SwBreak,
            regs.into(),
        ))
        .await?;

        self.freeze_all().await?;

        let running = self
            .await_gdb_resume(task, ExpectedGdbResume::StepOver)
            .await?;
        let wait = running.next_state().await?.assume_stopped();
        let mut task = wait.0;
        let mut event = wait.1;

        // Detached by client.
        if !self.attached_by_gdb {
            self.thaw_all().await?;
            return Ok(Wait::Stopped(task, event));
        }

        task = loop {
            match event {
                Event::Signal(Signal::SIGTRAP) => break task,
                Event::Signal(Signal::SIGSTOP) => {
                    let running = task.step(None)?;
                    let wait = running.next_state().await?.assume_stopped();
                    task = wait.0;
                    event = wait.1;
                }
                // TODO: combine with handle_signal!
                Event::Signal(Signal::SIGCHLD) => {
                    let running = task.step(Signal::SIGCHLD)?;
                    let wait = running.next_state().await?.assume_stopped();
                    task = wait.0;
                    event = wait.1;
                }
                unknown => panic!("[pid = {}] got unexpected event {:?}", self.tid(), unknown),
            }
        };
        self.notify_gdb_stop(StopReason::stopped(
            task.pid(),
            self.pid(),
            StopEvent::Signal(Signal::SIGTRAP),
            task.getregs()?.into(),
        ))
        .await?;

        let running = self
            .await_gdb_resume(task, ExpectedGdbResume::Resume)
            .await?;
        let wait = running.next_state().await?;
        self.thaw_all().await?;
        Ok(wait)
    }

    /// check if the stop is caused by sw breakpoint.
    async fn check_swbreak(&mut self, wait: Wait) -> Result<Wait, TraceError> {
        match wait {
            Wait::Stopped(task, event) if event == Event::Signal(Signal::SIGTRAP) => {
                let mut regs = task.getregs()?;
                let rip_minus_one = regs.ip() - 1;
                if self.breakpoints.contains_key(&rip_minus_one) {
                    *regs.ip_mut() = rip_minus_one;
                    self.resume_from_swbreak(task, regs).await
                } else {
                    Ok(Wait::Stopped(task, event))
                }
            }
            other => Ok(other),
        }
    }

    async fn add_breakpoint(&mut self, addr: u64) -> Result<(), TraceError> {
        if let Some(bkpt_addr) = AddrMut::from_raw(addr as usize) {
            let mut task = self.assume_stopped();
            let saved_insn: u64 = task.read_value(bkpt_addr)?;
            let insn = (saved_insn & !0xffu64) | 0xccu64;
            task.write_value(bkpt_addr, &insn)?;
            self.breakpoints.insert(addr, saved_insn);
        }
        Ok(())
    }

    /// thaw all threads.
    async fn thaw_all(&mut self) -> Result<(), TraceError> {
        for (_pid, suspended_task) in core::mem::take(&mut self.suspended_tasks) {
            if let Some(tx) = suspended_task.waker.as_ref() {
                suspended_task.suspended.store(false, Ordering::SeqCst);
                let _sent = tx.try_send(self.tid());
            }
        }
        Ok(())
    }

    /// freeze all threads, except the caller.
    async fn freeze_all(&mut self) -> Result<(), TraceError> {
        // The tool have chosen to sequentialize thread execution, gdbserver
        // should avoid doing its own thread serialization, otherwise this
        // could lead to deadlock.
        if *self.global_state.sequentialized_guest {
            return Ok(());
        }
        let (stop_tx, mut stop_rx) = mpsc::channel(1);
        for child in self.child_threads.lock().await.deref_mut().into_iter() {
            if child.id() != self.tid() && !child.suspended.load(Ordering::SeqCst) {
                let killed = Errno::result(unsafe {
                    libc::syscall(libc::SYS_tgkill, self.pid(), child.id(), Signal::SIGSTOP)
                });
                if killed.is_ok() {
                    child.suspended.store(true, Ordering::SeqCst);
                    child.wait_all_stop_tx = Some(stop_tx.clone());
                }
            }
        }
        drop(stop_tx);
        while let Some((pid, suspended_task)) = stop_rx.recv().await {
            self.suspended_tasks.insert(pid, suspended_task);
        }
        Ok(())
    }

    async fn remove_breakpoint(&mut self, addr: u64) -> Result<(), TraceError> {
        let insn = self.breakpoints.remove(&addr).ok_or(Errno::ENOENT)?;
        let mut task = self.assume_stopped();
        if let Some(bkpt_addr) = AddrMut::from_raw(addr as usize) {
            task.write_value(bkpt_addr, &insn)?;
        }
        Ok(())
    }

    fn read_inferior_memory(&self, addr: u64, mut size: usize) -> Result<Vec<u8>, TraceError> {
        let task = self.assume_stopped();

        // NB: dont' trust size to be sane blindly.
        if size > 0x8000 {
            size = 0x8000;
        }

        let mut res = vec![0; size];
        if let Some(addr) = Addr::from_raw(addr as usize) {
            let nb = task.read(addr, &mut res)?;
            res.resize(nb, 0);
        }

        // There could be a software breakpoint within the address requested,
        // we should return the orignal contents without the breakpoint insn.
        // This is *not* documented in gdb remote protocol, however, both
        // gdbserver and rr does this. see:
        // rr: https://github.com/rr-debugger/rr/blob/master/src/GdbServer.cc#L561
        // gdbserver: https://github.com/bminor/binutils-gdb/blob/master/gdbserver/mem-break.cc#L1914
        for (bkpt, saved_insn) in self.breakpoints.iter() {
            if (addr..addr + res.len() as u64).contains(bkpt) {
                // This abuses bkpt insn 0xcc is single byte.
                res[*bkpt as usize - addr as usize] = *saved_insn as u8;
            }
        }

        Ok(res)
    }

    fn write_inferior_memory(
        &self,
        addr: u64,
        size: usize,
        data: Vec<u8>,
    ) -> Result<(), TraceError> {
        let mut task = self.assume_stopped();
        let size = std::cmp::min(size, data.len());
        let addr = AddrMut::from_raw(addr as usize).ok_or(Errno::EFAULT)?;
        task.write(addr, &data[..size])?;
        Ok(())
    }

    fn read_registers(&self) -> Result<CoreRegs, TraceError> {
        let task = self.assume_stopped();
        let regs = task.getregs()?;
        let fpregs = task.getfpregs()?;
        let core_regs = CoreRegs::from_parts(regs, fpregs);
        Ok(core_regs)
    }

    fn write_registers(&self, core_regs: CoreRegs) -> Result<(), TraceError> {
        let task = self.assume_stopped();
        let (regs, fpregs) = core_regs.into_parts();
        task.setregs(regs)?;
        task.setfpregs(fpregs)?;
        Ok(())
    }
}

#[async_trait]
impl<L: Tool + 'static> Guest<L> for TracedTask<L> {
    type Memory = Stopped;
    type Stack = GuestStack;

    #[inline]
    fn tid(&self) -> Pid {
        self.tid
    }

    #[inline]
    fn pid(&self) -> Pid {
        self.pid
    }

    #[inline]
    fn ppid(&self) -> Option<Pid> {
        self.ppid
    }

    fn memory(&self) -> Self::Memory {
        self.assume_stopped()
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        let task = self.assume_stopped();

        match task.getregs() {
            Ok(ret) => ret,
            Err(err) => self.abort(Err(err)).await,
        }
    }

    async fn stack(&mut self) -> Self::Stack {
        match GuestStack::new(self.tid, self.stack_checked_out.clone()) {
            Ok(ret) => ret,
            Err(err) => self.abort(Err(err)).await,
        }
    }

    fn thread_state_mut(&mut self) -> &mut L::ThreadState {
        &mut self.thread_state
    }

    fn thread_state(&self) -> &L::ThreadState {
        &self.thread_state
    }

    async fn daemonize(&mut self) {
        let pid = self.pid();
        self.ndaemons.fetch_add(1, Ordering::SeqCst);
        self.is_a_daemon = true;

        tracing::info!("[reverie] daemonizing pid {} ..", pid);
        self.daemonizer
            .send(self.daemon_kill_switch.subscribe())
            .await
            .unwrap();

        if self.ndaemons.load(Ordering::SeqCst) == self.ntasks.load(Ordering::SeqCst) {
            self.daemon_kill_switch.send(()).unwrap();
        }
    }

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        // Call a non-templatized function to reduce code bloat.
        let (nr, args) = syscall.into_parts();
        self.do_inject(nr, args).await
    }

    #[allow(unreachable_code)]
    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never {
        // Call a non-templatized function to reduce code bloat.
        let (nr, args) = syscall.into_parts();
        self.do_tail_inject(nr, args).await
    }

    fn set_timer(&mut self, sched: TimerSchedule) -> Result<(), reverie::Error> {
        let rcbs = match sched {
            TimerSchedule::Rcbs(r) => r,
            TimerSchedule::Time(dur) => Timer::as_ticks(dur),
            //if timer is imprecise there is no really a point in trying to single step any further than r
            TimerSchedule::RcbsAndInstructions(r, _) => r,
        };
        self.timer
            .request_event(TimerEventRequest::Imprecise(rcbs))?;
        Ok(())
    }

    fn set_timer_precise(&mut self, sched: TimerSchedule) -> Result<(), reverie::Error> {
        match sched {
            TimerSchedule::Rcbs(r) => self.timer.request_event(TimerEventRequest::Precise(r))?,
            TimerSchedule::Time(dur) => self
                .timer
                .request_event(TimerEventRequest::Precise(Timer::as_ticks(dur)))?,
            TimerSchedule::RcbsAndInstructions(r, i) => self
                .timer
                .request_event(TimerEventRequest::PreciseInstruction(r, i))?,
        };
        Ok(())
    }

    fn read_clock(&mut self) -> Result<u64, reverie::Error> {
        Ok(self.timer.read_clock())
    }

    fn backtrace(&mut self) -> Option<Backtrace> {
        use unwind::Accessors;
        use unwind::AddressSpace;
        use unwind::Byteorder;
        use unwind::Cursor;
        use unwind::PTraceState;
        use unwind::RegNum;

        let mut frames = Vec::new();

        let space = AddressSpace::new(Accessors::ptrace(), Byteorder::DEFAULT).ok()?;
        let state = PTraceState::new(self.tid.as_raw() as u32).ok()?;
        let mut cursor = Cursor::remote(&space, &state).ok()?;

        loop {
            let ip = cursor.register(RegNum::IP).ok()?;
            let is_signal = cursor.is_signal_frame().ok()?;

            frames.push(Frame { ip, is_signal });

            if !cursor.step().ok()? {
                break;
            }
        }

        // TODO: Take a snapshot of `/proc/self/maps` so the backtrace can be
        // processed offline?

        Some(Backtrace::new(self.tid(), frames))
    }

    fn has_cpuid_interception(&self) -> bool {
        self.has_cpuid_interception
    }
}

#[async_trait]
impl<L: Tool + 'static> GlobalRPC<L::GlobalState> for TracedTask<L> {
    async fn send_rpc<'a>(
        &'a self,
        args: <L::GlobalState as GlobalTool>::Request,
    ) -> <L::GlobalState as GlobalTool>::Response {
        let wrapped = WrappedFrom(self.tid(), &self.global_state);
        wrapped.send_rpc(args).await
    }

    fn config(&self) -> &<L::GlobalState as GlobalTool>::Config {
        &self.global_state.cfg
    }
}

/// Wrap a GlobalState with a Tid from which the messages originate.  This enables the
/// GlobalRPC instance below.
struct WrappedFrom<'a, G: GlobalTool>(Tid, &'a GlobalState<G>);

#[async_trait]
impl<'a, G: GlobalTool> GlobalRPC<G> for WrappedFrom<'a, G> {
    async fn send_rpc(&self, args: G::Request) -> G::Response {
        // In debugging mode we round-trip through a serialized representation
        // to make sure it works.
        let deserial = if cfg!(debug_assertions) {
            let serial = bincode::serialize(&args).unwrap();
            bincode::deserialize(&serial).unwrap()
        } else {
            args
        };
        self.1.gs_ref.receive_rpc(self.0, deserial).await
    }
    fn config(&self) -> &G::Config {
        &self.1.cfg
    }
}
