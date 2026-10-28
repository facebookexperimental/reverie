/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Timer events end to end: `Guest::set_timer` and
//! `Guest::set_timer_precise` through the production CPL3 SYSCALL transport
//! to `Tool::handle_timer_event`, under the Reverie contract. These tests
//! require KVM and the raw PMU event; unavailable hardware is not a pass.
//! A precise event must land exactly at its target, at the instruction
//! boundary right after the target branch, with the same registers in every
//! run.
//!
//! The guests run a loop of 3 RCBs per iteration far past each target, by at
//! least [`TAIL`] RCBs, so a kick has time to land however late its
//! interrupt comes; the guest's next subscribed syscall would otherwise
//! cancel the request. Every delivery is checked against a ceiling as well as
//! the target: it comes less than [`CEILING`] RCBs after the target. A test
//! that expects no event runs the same tail after the event that should
//! cancel the request, and each has a control without that event.

#![cfg(target_arch = "x86_64")]

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use futures::FutureExt;
use reverie::BackendStatsRequest;
use reverie::BackendStatsSource;
use reverie::CpuIdResult;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::ParkedObservationLease;
use reverie::Pid;
use reverie::ProcessAlarmSignalOutcome;
use reverie::Rdtsc;
use reverie::RdtscResult;
use reverie::Signal;
use reverie::SignalEvent;
use reverie::SignalTarget;
use reverie::Subscription;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::Errno;
use reverie::syscalls::Execve;
use reverie::syscalls::ExitGroup;
use reverie::syscalls::Fork;
use reverie::syscalls::Getpid;
use reverie::syscalls::RtSigprocmask;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie::syscalls::Tgkill;
use reverie_kvm::KvmBackend;
use serde::Deserialize;
use serde::Serialize;

const MEMORY: usize = 16 * 1024 * 1024;

/// RCBs each guest runs past its last target: far beyond the longest kick
/// latency measured on a loaded host (about 320,000 RCBs).
const TAIL: u64 = 30_000_000;

/// How far past its target an event may come: three times that latency, and
/// a thirtieth of [`TAIL`].
const CEILING: u64 = 1_000_000;

/// Checks that `clock` lies in the delivery window of a request for `ticks`
/// RCBs made at clock `requested_at`: at or past its target, and less than
/// [`CEILING`] past it.
fn assert_delivered(clock: u64, requested_at: u64, ticks: u64, context: &str) {
    let target = requested_at + ticks;
    assert!(
        (target..target + CEILING).contains(&clock),
        "{context}: delivered at {clock}, target {target}"
    );
}

/// Runs `test` again in a child process with a time limit, as read_clock.rs
/// does, and checks that the child ran exactly that test. Returns false in
/// the child, which then runs the test body.
fn bounded(test: &str) -> bool {
    bounded_with(test, &[])
}

/// [`bounded`], with `env` set for the child.
fn bounded_with(test: &str, env: &[(&str, &str)]) -> bool {
    if std::env::var_os("REVERIE_KVM_TIMER_TEST_CHILD").is_some() {
        return false;
    }
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "120s"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env("REVERIE_KVM_TIMER_TEST_CHILD", "1")
        .envs(env.iter().copied())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed"),
        "{test}: {}\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

/// A static guest assembled from `body`, as in read_clock.rs, or a guest
/// compiled from C, and the guest memory it runs in.
struct Program {
    directory: PathBuf,
    executable: PathBuf,
    memory: usize,
}

impl Program {
    fn new(body: &str) -> Self {
        Self::build(
            "guest.S",
            &format!(".global _start\n.text\n_start:\n{body}\n"),
            &["-nostdlib", "-static", "-Wl,--build-id=none"],
            MEMORY,
        )
    }

    /// A dynamically linked guest compiled from the C `source` with `flags`,
    /// with room for its loader and libraries.
    fn c(source: &str, flags: &[&str]) -> Self {
        Self::build(
            "guest.c",
            source,
            &[&["-O2"], flags].concat(),
            256 * 1024 * 1024,
        )
    }

    fn build(name: &str, text: &str, flags: &[&str], memory: usize) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "reverie-kvm-timer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join(name);
        let executable = directory.join("guest");
        std::fs::write(&source, text).unwrap();
        let output = std::process::Command::new("timeout")
            .args(["--kill-after=2s", "10s", "/usr/bin/gcc"])
            .args(flags)
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            directory,
            executable,
            memory,
        }
    }
}

impl Drop for Program {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

/// A loop of at least `rcbs` RCBs, 3 per iteration (see read_clock.rs).
fn branches(rcbs: u64) -> String {
    let iterations = rcbs.div_ceil(3);
    format!(
        "mov ${iterations}, %rcx\n1: xor %eax,%eax\njz 2f\nud2\n2: jnz 3f\n3: dec %rcx\njnz 1b\n"
    )
}

const GETPPID: &str = "mov $110,%eax\nsyscall\n";
const EXIT: &str = "xor %edi,%edi\nmov $60,%eax\nsyscall\nud2\n";

/// Where a [`TimerTool`] requests its timer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
enum Arm {
    /// In `handle_thread_start`, before the initial exec.
    ThreadStart,
    /// In `handle_post_exec`: at the start of each image.
    #[default]
    PostExec,
    /// In the callback of the guest's `getppid`, the marker.
    Marker,
    /// In the callback of the guest's `execve`, before it runs.
    Execve,
}

/// An injection that a timer event's callback cannot perform on KVM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Refused {
    Fork,
    Exec,
    /// `tgkill` of SIGUSR1 to the thread itself.
    Signal,
    /// A tail injection other than an exit.
    Tail,
}

/// What a timer event's callback does after it polls a refused injection
/// once and drops it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum AfterDropped {
    /// Tail-inject an exit.
    Exit,
    /// Retire the thread.
    Retire,
    /// Poll a getpid injection once, report whether it completed, and return.
    Inject,
}

/// A signal-mask change a timer event's callback injects while SIGUSR1 is
/// blocked and pending. The guest keeps the address of SIGUSR1's mask in
/// r14, with SIGUSR2's mask after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum MaskChange {
    /// Unblock SIGUSR1, which would make it deliverable.
    UnblockPending,
    /// Block SIGUSR2, which makes nothing deliverable.
    BlockAnother,
    /// Unblock SIGUSR1 with a sigset size of 4: `EINVAL`.
    BadSize,
    /// Unblock SIGUSR1 with an invalid `how`: `EINVAL`.
    BadHow,
    /// Unblock the signals of a mask at address 8, which the guest cannot
    /// read: `EFAULT`.
    BadSet,
}

impl MaskChange {
    fn request(self, masks: u64) -> RtSigprocmask {
        let (how, set, size) = match self {
            Self::UnblockPending => (libc::SIG_UNBLOCK, masks, 8),
            Self::BlockAnother => (libc::SIG_BLOCK, masks + 8, 8),
            Self::BadSize => (libc::SIG_UNBLOCK, masks, 4),
            Self::BadHow => (99, masks, 8),
            Self::BadSet => (libc::SIG_UNBLOCK, 8, 8),
        };
        RtSigprocmask::new()
            .with_how(how)
            .with_set(Addr::from_raw(set as usize))
            .with_oldset(None)
            .with_sigsetsize(size)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Plan {
    arm: Arm,
    /// RCB counts requested there, in order: each replaces the one before.
    requests: Vec<u64>,
    /// Requests made again from `handle_timer_event`, for the last count.
    rearm: u32,
    /// Subscribe to RDTSC.
    rdtsc: bool,
    /// Subscribe to CPUID.
    cpuid: bool,
    /// Leave `tgkill` unsubscribed, so that its signal is the only event.
    quiet_tgkill: bool,
    /// Subscribe to no syscall at all.
    no_syscalls: bool,
    /// End the run from the timer event.
    exit_at_event: bool,
    /// Request precise events (`Guest::set_timer_precise`).
    precise: bool,
    /// From the callback of the guest's `getpid`, request this many RCBs.
    rearm_at_getpid: Option<u64>,
    /// From a signal's callback, request this many RCBs.
    rearm_at_signal: Option<u64>,
    /// Ask for a precise event with an instruction offset, and for 0 RCBs
    /// precisely and imprecisely, after the requests.
    refusals: bool,
    /// Inject this from the timer event, ignore the error, and carry on.
    refused_at_event: Option<Refused>,
    /// Poll that injection once instead, drop it, and do this.
    after_dropped: Option<AfterDropped>,
    /// Inject this from the timer event, report its result, and carry on.
    mask_change: Option<MaskChange>,
    /// Report the registers the timer event sees.
    registers: bool,
    /// At the marker, after the request, queue a process SIGALRM and observe
    /// it while the marker's callback stays parked.
    parked_signal: bool,
    /// At the marker, return ERESTARTSYS from the first attempt of the
    /// callback, after the request; the attempt that follows requests again
    /// only if this is `Some(true)`.
    restart: Option<bool>,
    /// Hold the first timer event's callback until another thread's `tgkill`
    /// has run, and hold that `tgkill` until the callback has begun, as a
    /// Tool that runs one thread at a time would (see [`Gate`]).
    rendezvous: bool,
    /// Deliver every signal, and report the clock at its callback.
    deliver: bool,
    /// Subscribe to `tgkill` alone.
    only_tgkill: bool,
    /// From SIGSEGV's callback, send SIGUSR1 to the thread itself.
    self_signal_at_fault: bool,
    /// Report the registers each signal's callback sees.
    signal_registers: bool,
    /// Hold a new thread's start until another thread's `tgkill` has run.
    hold_thread_start: bool,
}

/// The two points a [`Plan::rendezvous`] orders.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Gate {
    /// The first timer event's callback has begun.
    Timer,
    /// The other thread's `tgkill` has run.
    Sent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Event {
    Requested {
        clock: u64,
        ticks: u64,
    },
    Refused(String),
    Timer {
        clock: u64,
    },
    Signal(i32),
    /// A signal's callback under [`Plan::deliver`], and the clock there.
    Signalled {
        signal: i32,
        clock: u64,
    },
    /// Opens a gate (not logged).
    Open(Gate),
    /// Waits until a gate is open (not logged).
    Wait(Gate),
    Rdtsc,
    Cpuid,
    /// An attempt of the marker's callback.
    Attempt(u32),
    /// The registers a timer event saw.
    Registers(Registers),
    /// The result of an injection from a timer event.
    Injected(String),
}

/// The user registers a timer event's callback sees (`Guest::regs`), and the
/// thread's pid as the Tool sees it (`Guest::pid`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Registers {
    pid: u64,
    rip: u64,
    rax: u64,
    orig_rax: u64,
    rcx: u64,
    r11: u64,
    eflags: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    r10: u64,
    r8: u64,
    r9: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    rsp: u64,
    rbx: u64,
    rbp: u64,
    r15: u64,
    cs: u64,
    ss: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
    fs_base: u64,
    gs_base: u64,
}

#[derive(Default)]
struct Log {
    events: Mutex<Vec<Event>>,
    timer: Latch,
    sent: Latch,
}

/// A gate that opens once and stays open.
#[derive(Default)]
struct Latch(Mutex<(bool, Vec<std::task::Waker>)>);

impl Latch {
    fn open(&self) {
        let mut latch = self.0.lock().unwrap();
        latch.0 = true;
        latch.1.drain(..).for_each(std::task::Waker::wake);
    }

    async fn wait(&self) {
        futures::future::poll_fn(|context| {
            let mut latch = self.0.lock().unwrap();
            if latch.0 {
                return std::task::Poll::Ready(());
            }
            latch.1.push(context.waker().clone());
            std::task::Poll::Pending
        })
        .await
    }
}

#[reverie::global_tool]
impl GlobalTool for Log {
    type Config = Plan;
    type Request = Event;
    type Response = ();

    async fn receive_rpc(&self, _from: Pid, event: Event) {
        let latch = |gate| match gate {
            Gate::Timer => &self.timer,
            Gate::Sent => &self.sent,
        };
        match event {
            Event::Open(gate) => latch(gate).open(),
            Event::Wait(gate) => latch(gate).wait().await,
            event => self.events.lock().unwrap().push(event),
        }
    }
}

#[derive(Default)]
struct TimerTool;

/// Each thread's counts of its timer events and of its marker attempts.
#[derive(Default, Serialize, Deserialize)]
struct Counts {
    delivered: u32,
    attempts: u32,
}

/// A process SIGALRM, as the kernel would queue it.
fn alarm(pid: Pid) -> SignalEvent {
    let mut info = [0; reverie::SIGNAL_INFO_SIZE];
    info[..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
    SignalEvent::new(libc::SIGALRM, info, SignalTarget::Process { pid }).unwrap()
}

/// Injects `refused` from a timer event's callback, which cannot perform it.
async fn inject_refused<G: Guest<TimerTool>>(
    guest: &mut G,
    refused: Refused,
) -> Result<i64, Errno> {
    let (pid, tid) = (guest.pid().as_raw(), guest.tid().as_raw());
    match refused {
        Refused::Fork => guest.inject(Fork::new()).await,
        Refused::Exec => guest.inject(Execve::new()).await,
        Refused::Signal => {
            guest
                .inject(
                    Tgkill::new()
                        .with_tgid(pid)
                        .with_tid(tid)
                        .with_sig(libc::SIGUSR1),
                )
                .await
        }
        Refused::Tail => guest.tail_inject(Getpid::new()).await,
    }
}

/// Reports the user registers and the pid a callback sees.
async fn report_registers<G: Guest<TimerTool>>(guest: &mut G) {
    let r = guest.regs().await;
    let registers = Registers {
        pid: guest.pid().as_raw() as u64,
        rip: r.rip,
        rax: r.rax,
        orig_rax: r.orig_rax,
        rcx: r.rcx,
        r11: r.r11,
        eflags: r.eflags,
        rdi: r.rdi,
        rsi: r.rsi,
        rdx: r.rdx,
        r10: r.r10,
        r8: r.r8,
        r9: r.r9,
        r12: r.r12,
        r13: r.r13,
        r14: r.r14,
        rsp: r.rsp,
        rbx: r.rbx,
        rbp: r.rbp,
        r15: r.r15,
        cs: r.cs,
        ss: r.ss,
        ds: r.ds,
        es: r.es,
        fs: r.fs,
        gs: r.gs,
        fs_base: r.fs_base,
        gs_base: r.gs_base,
    };
    guest.send_rpc(Event::Registers(registers)).await;
}

/// Requests a timer event `ticks` RCBs on, precise if the plan says so.
async fn arm<G: Guest<TimerTool>>(guest: &mut G, ticks: u64) {
    let clock = guest.read_clock().unwrap();
    let schedule = TimerSchedule::Rcbs(ticks);
    if guest.config().precise {
        guest.set_timer_precise(schedule).unwrap();
    } else {
        guest.set_timer(schedule).unwrap();
    }
    guest.send_rpc(Event::Requested { clock, ticks }).await;
}

async fn request<G: Guest<TimerTool>>(guest: &mut G) {
    let plan = guest.config().clone();
    for ticks in plan.requests {
        arm(guest, ticks).await;
    }
    if plan.refusals {
        let schedule = TimerSchedule::RcbsAndInstructions(1_000, 3);
        let refused = match guest.set_timer_precise(schedule) {
            Err(reverie::Error::Io(error)) => format!("{:?}: {error}", error.kind()),
            other => format!("{other:?}"),
        };
        guest.send_rpc(Event::Refused(refused)).await;
        let refused = guest.set_timer_precise(TimerSchedule::Rcbs(0));
        guest.send_rpc(Event::Refused(format!("{refused:?}"))).await;
        let refused = guest.set_timer(TimerSchedule::Rcbs(0));
        guest.send_rpc(Event::Refused(format!("{refused:?}"))).await;
    }
}

#[reverie::tool]
impl Tool for TimerTool {
    type GlobalState = Log;
    type ThreadState = Counts;

    fn may_observe_signal_dequeues(plan: &Plan) -> bool {
        plan.parked_signal
    }

    fn subscriptions(plan: &Plan) -> Subscription {
        if plan.no_syscalls {
            return Subscription::none();
        }
        let mut subscription = Subscription::all_syscalls();
        if plan.rdtsc {
            subscription.rdtsc();
        }
        if plan.cpuid {
            subscription.cpuid();
        }
        if plan.quiet_tgkill {
            subscription.disable_syscall(Sysno::tgkill);
        }
        if plan.only_tgkill {
            subscription = Subscription::none();
            subscription.syscall(Sysno::tgkill);
        }
        subscription
    }

    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        if guest.config().arm == Arm::ThreadStart {
            request(guest).await;
        }
        if guest.config().hold_thread_start && guest.tid() != guest.pid() {
            guest.send_rpc(Event::Wait(Gate::Sent)).await;
        }
        Ok(())
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        if guest.config().arm == Arm::PostExec {
            request(guest).await;
        }
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        let plan = guest.config().clone();
        match (plan.arm, syscall.number()) {
            (Arm::Marker, Sysno::getppid) => {
                let attempt = guest.thread_state().attempts;
                guest.thread_state_mut().attempts += 1;
                guest.send_rpc(Event::Attempt(attempt)).await;
                match (plan.restart, attempt) {
                    (Some(_), 0) => {
                        request(guest).await;
                        return Err(Errno::ERESTARTSYS.into());
                    }
                    (Some(false), _) => {}
                    _ => request(guest).await,
                }
                if plan.parked_signal {
                    let site = guest.parked_signal_site().expect("a parked callback site");
                    let pid = guest.pid();
                    let queued = guest.queue_process_alarm_signal(alarm(pid)).await;
                    assert!(
                        matches!(queued, ProcessAlarmSignalOutcome::Accepted(_)),
                        "{queued:?}"
                    );
                    guest
                        .observe_parked_signal(site, ParkedObservationLease { nonce: 1 })
                        .await
                        .unwrap();
                }
            }
            (Arm::Execve, Sysno::execve) => request(guest).await,
            (_, Sysno::tgkill) if plan.rendezvous || plan.hold_thread_start => {
                if plan.rendezvous {
                    guest.send_rpc(Event::Wait(Gate::Timer)).await;
                }
                let sent = guest.inject(syscall).await;
                guest.send_rpc(Event::Open(Gate::Sent)).await;
                return Ok(sent?);
            }
            (_, Sysno::getpid) if plan.rearm_at_getpid.is_some() => {
                arm(guest, plan.rearm_at_getpid.unwrap()).await
            }
            _ => {}
        }
        guest.tail_inject(syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        let plan = guest.config().clone();
        if plan.deliver {
            let clock = guest.read_clock().unwrap();
            let signal = signal as i32;
            guest.send_rpc(Event::Signalled { signal, clock }).await;
        } else {
            guest.send_rpc(Event::Signal(signal as i32)).await;
        }
        if plan.signal_registers {
            report_registers(guest).await;
        }
        if plan.self_signal_at_fault && signal == Signal::SIGSEGV {
            let (pid, tid) = (guest.pid().as_raw(), guest.tid().as_raw());
            let sent = Tgkill::new()
                .with_tgid(pid)
                .with_tid(tid)
                .with_sig(libc::SIGUSR1);
            assert_eq!(guest.inject(sent).await, Ok(0));
        }
        if let Some(ticks) = plan.rearm_at_signal {
            arm(guest, ticks).await;
        }
        let suppressed = signal == Signal::SIGUSR1 || signal == Signal::SIGALRM;
        Ok((plan.deliver || !suppressed).then_some(signal))
    }

    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        request: Rdtsc,
    ) -> Result<RdtscResult, Errno> {
        guest.send_rpc(Event::Rdtsc).await;
        Ok(RdtscResult::new(request))
    }

    async fn handle_cpuid_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        eax: u32,
        ecx: u32,
    ) -> Result<CpuIdResult, Errno> {
        guest.send_rpc(Event::Cpuid).await;
        let host = std::arch::x86_64::__cpuid_count(eax, ecx);
        Ok(CpuIdResult {
            eax: host.eax,
            ebx: host.ebx,
            ecx: host.ecx,
            edx: host.edx,
        })
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
        let clock = guest.read_clock().unwrap();
        guest.send_rpc(Event::Timer { clock }).await;
        let plan = guest.config().clone();
        if plan.registers {
            report_registers(guest).await;
        }
        if plan.rendezvous && guest.thread_state().delivered == 0 {
            guest.send_rpc(Event::Open(Gate::Timer)).await;
            guest.send_rpc(Event::Wait(Gate::Sent)).await;
        }
        if let Some(change) = plan.mask_change {
            let masks = guest.regs().await.r14;
            let result = guest.inject(change.request(masks)).await;
            guest.send_rpc(Event::Injected(format!("{result:?}"))).await;
            return;
        }
        if let Some(refused) = plan.refused_at_event {
            let Some(after) = plan.after_dropped else {
                // Each of these ends the run; a Tool that ignores the error,
                // as this one does, cannot carry on as if the syscall had
                // failed.
                let _ignored = inject_refused(guest, refused).await;
                return;
            };
            // Polled once and dropped, the refused injection still ends the
            // run, and what the callback does next neither replaces that
            // outcome nor reaches the guest.
            let _dropped = inject_refused(guest, refused).now_or_never();
            match after {
                AfterDropped::Exit => guest.tail_inject(ExitGroup::new().with_status(0)).await,
                AfterDropped::Retire => guest.retire_current_thread().await,
                AfterDropped::Inject => {
                    let later = guest.inject(Getpid::new()).now_or_never();
                    guest.send_rpc(Event::Injected(format!("{later:?}"))).await;
                }
            }
            return;
        }
        let counts = guest.thread_state_mut();
        counts.delivered += 1;
        if counts.delivered <= plan.rearm {
            let ticks = *plan.requests.last().unwrap();
            guest.set_timer(TimerSchedule::Rcbs(ticks)).unwrap();
            guest.send_rpc(Event::Requested { clock, ticks }).await;
            // A syscall the Tool injects is not an event: the request stays.
            assert!(guest.inject(Getpid::new()).await.unwrap() > 0);
        } else if plan.exit_at_event {
            guest.tail_inject(ExitGroup::new().with_status(0)).await
        }
    }
}

/// How a run ended: the guest's exit code, stdout and stderr, or the run's
/// failure, as text.
type Ending = Result<(i32, Vec<u8>, Vec<u8>), String>;

/// Runs `program` under a [`TimerTool`] following `plan`, and returns the
/// Tool's events and how the run ended. The image is installed from its file,
/// which `/proc/self/exe` names.
/// The entries set up within a precise request's stepping window in the
/// last [`run_ending`] (`KvmBackendStats::timer_window_entries`): none means
/// that no step, run to a breakpoint or unstepped entry toward a precise
/// target began in that run.
static WINDOW_ENTRIES: AtomicU64 = AtomicU64::new(0);

fn run_ending(program: &Program, plan: Plan) -> (Vec<Event>, Ending) {
    let mut backend = KvmBackend::new(program.memory).unwrap();
    backend.set_backend_stats_request(BackendStatsRequest::ENABLED);
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(&program.executable).unwrap(),
            &[program.executable.to_str().unwrap()],
            &[],
            &program.directory,
        )
        .unwrap();
    let completion = futures::executor::block_on(
        backend.run_static_elf_with_tool_completion::<TimerTool>(plan, true),
    )
    .unwrap();
    let events = completion.global_state.events.into_inner().unwrap();
    WINDOW_ENTRIES.store(
        backend.backend_stats().timer_window_entries(),
        Ordering::Relaxed,
    );
    let ending = completion
        .result
        .map(|(status, out, err)| {
            let code = status
                .code()
                .unwrap_or_else(|| 128 + status.signal().expect("a signaled status"));
            (code, out, err)
        })
        .map_err(|error| error.to_string());
    (events, ending)
}

/// Runs `program` under a [`TimerTool`] following `plan`, checks that it
/// exits with status 0 and no output, and returns the Tool's events.
fn run(program: &Program, plan: Plan) -> Vec<Event> {
    let (events, ending) = run_ending(program, plan);
    assert_eq!(ending, Ok((0, vec![], vec![])), "{events:?}");
    events
}

fn timer_clocks(events: &[Event]) -> Vec<u64> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Timer { clock } => Some(*clock),
            _ => None,
        })
        .collect()
}

/// The clock at which the last request before the first timer event (or
/// the last request at all) was made, and its count.
fn last_request(events: &[Event]) -> (u64, u64) {
    let before_timer = events
        .iter()
        .take_while(|event| !matches!(event, Event::Timer { .. }));
    before_timer
        .filter_map(|event| match event {
            Event::Requested { clock, ticks } => Some((*clock, *ticks)),
            _ => None,
        })
        .last()
        .expect("a request was made")
}

fn skid_margin() -> u64 {
    reverie::pmu_config::try_get_pmu_config()
        .expect("the preemption timer requires this CPU's PMU profile")
        .skid_margin()
}

#[test]
fn a_timer_event_arrives_once_at_or_after_its_target() {
    if bounded("a_timer_event_arrives_once_at_or_after_its_target") {
        return;
    }
    let lead = 1_000;
    for ticks in [1, 2, 5, skid_margin(), 1_000_000, 100_000_000] {
        // Requested where the image starts, and in the callback of a syscall.
        let at_start = Program::new(&(branches(ticks + TAIL) + EXIT));
        let at_marker = Program::new(&(branches(lead) + GETPPID + &branches(ticks + TAIL) + EXIT));
        for (arm, program) in [(Arm::PostExec, &at_start), (Arm::Marker, &at_marker)] {
            let events = run(
                program,
                Plan {
                    arm,
                    requests: vec![ticks],
                    ..Plan::default()
                },
            );
            let (requested_at, _) = last_request(&events);
            let clocks = timer_clocks(&events);
            assert_eq!(clocks.len(), 1, "{arm:?} {ticks}: {events:?}");
            assert_delivered(
                clocks[0],
                requested_at,
                ticks,
                &format!("{arm:?} {ticks}: {events:?}"),
            );
            println!(
                "{arm:?}: requested {ticks} RCBs at {requested_at}, delivered at {}",
                clocks[0]
            );
        }
    }
}

#[test]
fn a_timer_event_reaches_a_guest_that_never_exits() {
    if bounded("a_timer_event_reaches_a_guest_that_never_exits") {
        return;
    }
    // One taken JZ per iteration, forever: no syscall, no fault.
    let program = Program::new("1: xor %eax,%eax\njz 1b\nud2\n");
    let events = run(
        &program,
        Plan {
            requests: vec![1_000_000],
            exit_at_event: true,
            ..Plan::default()
        },
    );
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), 1, "{events:?}");
    assert_delivered(clocks[0], 0, 1_000_000, &format!("{events:?}"));
}

#[test]
fn a_new_request_replaces_the_outstanding_one() {
    if bounded("a_new_request_replaces_the_outstanding_one") {
        return;
    }
    let program = Program::new(&(branches(100_000_000 + TAIL) + EXIT));
    for requests in [
        // A nearer request replaces a farther one, which then never fires.
        vec![100_000_000, 1_000_000],
        // A farther one replaces a nearer one, which then never fires.
        vec![1_000_000, 30_000_000],
    ] {
        let events = run(
            &program,
            Plan {
                requests: requests.clone(),
                ..Plan::default()
            },
        );
        let clocks = timer_clocks(&events);
        assert_eq!(clocks.len(), 1, "{requests:?}: {events:?}");
        let (requested_at, ticks) = last_request(&events);
        assert_eq!(ticks, requests[1]);
        assert_delivered(
            clocks[0],
            requested_at,
            ticks,
            &format!("{requests:?}: {events:?}"),
        );
    }
}

#[test]
fn another_event_cancels_an_outstanding_request() {
    if bounded("another_event_cancels_an_outstanding_request") {
        return;
    }
    let ticks = 1_000_000;
    // getpid and gettid (kept in r12 and r13), then the marker, where the
    // request is made, then the event under test, then the tail.
    let program = |event: &str| {
        Program::new(
            &("mov $39,%eax\nsyscall\nmov %rax,%r12\nmov $186,%eax\nsyscall\nmov %rax,%r13\n"
                .to_owned()
                + &branches(1_000)
                + GETPPID
                + event
                + &branches(ticks + TAIL)
                + EXIT),
        )
    };
    let tgkill = "mov %r12,%rdi\nmov %r13,%rsi\nmov $10,%edx\nmov $234,%eax\nsyscall\n";
    let plan = |rdtsc, cpuid, quiet_tgkill| Plan {
        arm: Arm::Marker,
        requests: vec![ticks],
        rdtsc,
        cpuid,
        quiet_tgkill,
        ..Plan::default()
    };
    for (name, event, plan, witness) in [
        (
            "a subscribed syscall",
            "mov $39,%eax\nsyscall\n",
            plan(false, false, false),
            None,
        ),
        (
            "a signal",
            tgkill,
            plan(false, false, true),
            Some(Event::Signal(libc::SIGUSR1)),
        ),
        (
            "RDTSC",
            "rdtsc\n",
            plan(true, false, false),
            Some(Event::Rdtsc),
        ),
        (
            "CPUID",
            "xor %eax,%eax\nxor %ecx,%ecx\ncpuid\n",
            plan(false, true, false),
            Some(Event::Cpuid),
        ),
    ] {
        let events = run(&program(event), plan.clone());
        assert_eq!(timer_clocks(&events), [0; 0], "{name}: {events:?}");
        if let Some(witness) = witness {
            assert!(events.contains(&witness), "{name}: {events:?}");
        }
        // The control: without the event, the request fires.
        let events = run(&program(""), plan);
        let clocks = timer_clocks(&events);
        assert_eq!(clocks.len(), 1, "{name} control: {events:?}");
        let (requested_at, _) = last_request(&events);
        assert_delivered(
            clocks[0],
            requested_at,
            ticks,
            &format!("{name}: {events:?}"),
        );
    }
}

#[test]
fn an_exec_cancels_an_outstanding_request() {
    if bounded("an_exec_cancels_an_outstanding_request") {
        return;
    }
    let ticks = 1_000_000;
    // The first image executes itself with two arguments; the second, seeing
    // them, runs the tail.
    let program = Program::new(&format!(
        "cmpq $2, (%rsp)\nje after_exec\nlea self_path(%rip), %rdi\nlea arguments(%rip), %rsi\n\
         lea environment(%rip), %rdx\nmov $59, %eax\nsyscall\nneg %eax\nmov %eax, %edi\n\
         mov $231, %eax\nsyscall\nud2\nafter_exec:\n{}{EXIT}\
         .data\nself_path: .asciz \"/proc/self/exe\"\nfirst: .asciz \"timer\"\n\
         second: .asciz \"again\"\n.balign 8\narguments: .quad first, second, 0\n\
         environment: .quad 0\n",
        branches(ticks + TAIL)
    ));
    // Requested in the execve callback: the exec cancels it.
    let events = run(
        &program,
        Plan {
            arm: Arm::Execve,
            requests: vec![ticks],
            ..Plan::default()
        },
    );
    assert_eq!(timer_clocks(&events), [0; 0], "{events:?}");
    assert_eq!(last_request(&events).1, ticks, "{events:?}");
    // Requested at thread start, before the initial exec, which cancels it.
    let tail = Program::new(&(branches(ticks + TAIL) + EXIT));
    let events = run(
        &tail,
        Plan {
            arm: Arm::ThreadStart,
            requests: vec![ticks],
            ..Plan::default()
        },
    );
    assert_eq!(timer_clocks(&events), [0; 0], "{events:?}");
    // The control: requested at the start of each image, it fires in the
    // second (the execve's syscall event cancels the first image's request).
    let events = run(
        &program,
        Plan {
            requests: vec![ticks],
            ..Plan::default()
        },
    );
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), 1, "{events:?}");
    let (requested_at, _) = last_request(&events);
    assert_delivered(clocks[0], requested_at, ticks, &format!("{events:?}"));
}

#[test]
fn a_timer_event_can_request_the_next_one() {
    if bounded("a_timer_event_can_request_the_next_one") {
        return;
    }
    let ticks = 1_000_000;
    let rearm = 4;
    let program = Program::new(&(branches(u64::from(rearm + 1) * (ticks + TAIL)) + EXIT));
    let events = run(
        &program,
        Plan {
            requests: vec![ticks],
            rearm,
            ..Plan::default()
        },
    );
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), rearm as usize + 1, "{events:?}");
    assert_delivered(clocks[0], 0, ticks, &format!("{events:?}"));
    for pair in clocks.windows(2) {
        assert_delivered(pair[1], pair[0], ticks, &format!("{events:?}"));
    }
}

#[test]
fn instruction_offsets_and_zero_counts_are_refused() {
    if bounded("instruction_offsets_and_zero_counts_are_refused") {
        return;
    }
    let ticks = 1_000_000;
    let program = Program::new(&(branches(ticks + TAIL) + EXIT));
    let events = run(
        &program,
        Plan {
            requests: vec![ticks],
            refusals: true,
            ..Plan::default()
        },
    );
    let refusals: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Refused(text) => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(refusals.len(), 3, "{events:?}");
    assert!(
        refusals[0].starts_with("Unsupported: ")
            && refusals[0].contains("TimerSchedule::RcbsAndInstructions"),
        "{events:?}"
    );
    assert_eq!(refusals[1..], ["Err(Errno(EINVAL))"; 2], "{events:?}");
    // Neither refusal disturbed the outstanding request.
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), 1, "{events:?}");
    assert_delivered(clocks[0], 0, ticks, &format!("{events:?}"));
}

#[test]
fn a_timer_event_reaches_a_guest_making_syscalls_the_tool_does_not_see() {
    if bounded("a_timer_event_reaches_a_guest_making_syscalls_the_tool_does_not_see") {
        return;
    }
    // A Tool that subscribes to no syscall, and a guest that makes 50,000
    // getpid calls, 4 RCBs apart, then the tail. The i-th call's exit is at
    // clock 4i + 3, so the first at or past the target of 100,000 is at
    // 100,003. A kick lands about 100 RCBs after its overflow, after that
    // call has left user mode (to land before it, it would have to come
    // within 3 RCBs), so the request comes due at that exit and is delivered
    // at that syscall's return. Left for a kick that finds the guest in user
    // mode instead, it would wait for a rare early kick or for the last call.
    //
    // Before the loop, the guest keeps getpid's result in r13, its stack
    // pointer in r12 and the address after the loop's syscall in r14, and
    // puts known values in the six argument registers, which the calls leave
    // as they are.
    let ticks = 100_000;
    let calls = 50_000;
    let due_exit = ticks + 3;
    let program = Program::new(&format!(
        "mov $39,%eax\nsyscall\nmov %rax,%r13\nmov %rsp,%r12\nlea 7f(%rip),%r14\n\
         mov $0x1111,%edi\nmov $0x2222,%esi\nmov $0x3333,%edx\n\
         mov $0x4444,%r10d\nmov $0x5555,%r8d\nmov $0x6666,%r9d\n\
         mov ${calls}, %r15\n4: mov $3, %rbx\n5: dec %rbx\njnz 5b\n\
         mov $39,%eax\nsyscall\n7: dec %r15\njnz 4b\n{}{EXIT}",
        branches(TAIL)
    ));
    let events = run(
        &program,
        Plan {
            requests: vec![ticks],
            no_syscalls: true,
            registers: true,
            ..Plan::default()
        },
    );
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), 1, "{events:?}");
    assert_eq!(
        clocks[0], due_exit,
        "target {ticks}, due at the exit at {due_exit}: {events:?}"
    );
    // The callback sees the registers the guest resumes with at that
    // syscall's return: rip at the instruction after the syscall, which is
    // where SYSCALL left rcx, r11 holding the flags SYSCALL saved, rax the
    // call's result, and the arguments and the stack pointer as the guest
    // left them. orig_rax reads -1.
    let r = events
        .iter()
        .find_map(|event| match event {
            Event::Registers(registers) => Some(registers),
            _ => None,
        })
        .expect("the timer event reported its registers");
    assert_ne!(r.pid, 0, "{r:#x?}");
    assert_eq!(r.r13, r.pid, "getpid's result before the loop: {r:#x?}");
    assert_eq!((r.rip, r.rcx), (r.r14, r.r14), "rip and rcx: {r:#x?}");
    assert_eq!(r.rax, r.pid, "rax, getpid's result: {r:#x?}");
    assert_eq!(r.r11, r.eflags, "r11, the flags SYSCALL saved: {r:#x?}");
    assert_eq!(
        [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9],
        [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666],
        "argument registers: {r:#x?}"
    );
    assert_eq!(r.rsp, r.r12, "rsp: {r:#x?}");
    assert_eq!(r.orig_rax, u64::MAX, "orig_rax: {r:#x?}");
    println!(
        "requested {ticks} RCBs during {calls} unsubscribed syscalls, delivered at {} with {r:#x?}",
        clocks[0]
    );
}

#[test]
fn a_timer_callback_cannot_inject_a_process_action_a_signal_or_a_tail() {
    if bounded("a_timer_callback_cannot_inject_a_process_action_a_signal_or_a_tail") {
        return;
    }
    let ticks = 1_000_000;
    let program = Program::new(&(branches(ticks + TAIL) + EXIT));
    for (refused, syscall) in [
        (Refused::Fork, libc::SYS_fork),
        (Refused::Exec, libc::SYS_execve),
        (Refused::Signal, libc::SYS_tgkill),
        (Refused::Tail, libc::SYS_getpid),
    ] {
        let (events, ending) = run_ending(
            &program,
            Plan {
                requests: vec![ticks],
                refused_at_event: Some(refused),
                ..Plan::default()
            },
        );
        assert_eq!(timer_clocks(&events).len(), 1, "{refused:?}: {events:?}");
        // The Tool ignored the error and returned; the run fails anyway, and
        // says why.
        let failure = ending.expect_err("the run must fail");
        assert!(
            failure.contains(&format!(
                "KVM timer-event callback injected syscall {syscall}, which a timer event cannot perform"
            )),
            "{refused:?}: {failure}"
        );
    }
}

#[test]
fn a_refused_timer_injection_ends_the_run_even_when_dropped() {
    if bounded("a_refused_timer_injection_ends_the_run_even_when_dropped") {
        return;
    }
    let ticks = 1_000_000;
    let program = Program::new(&(branches(ticks + TAIL) + EXIT));
    // A refusal at each of the three places that make one: an injection the
    // backend refuses (fork), one the provider refuses (tgkill of SIGUSR1 to
    // the thread), and a tail injection (getpid). The Tool polls it once,
    // drops it, and then exits, retires, or injects again.
    for (refused, syscall) in [
        (Refused::Fork, libc::SYS_fork),
        (Refused::Signal, libc::SYS_tgkill),
        (Refused::Tail, libc::SYS_getpid),
    ] {
        for after in [
            AfterDropped::Exit,
            AfterDropped::Retire,
            AfterDropped::Inject,
        ] {
            let (events, ending) = run_ending(
                &program,
                Plan {
                    requests: vec![ticks],
                    refused_at_event: Some(refused),
                    after_dropped: Some(after),
                    ..Plan::default()
                },
            );
            let context = format!("{refused:?}, then {after:?}: {events:?}");
            assert_eq!(timer_clocks(&events).len(), 1, "{context}");
            if after == AfterDropped::Inject {
                // The later injection never ran: polled once, it had not
                // completed.
                assert!(
                    events.contains(&Event::Injected("None".to_owned())),
                    "{context}"
                );
            }
            let failure = ending.expect_err(&format!("the run must fail: {context}"));
            assert!(
                failure.contains(&format!(
                    "KVM timer-event callback injected syscall {syscall}, which a timer event cannot perform"
                )),
                "{context}: {failure}"
            );
        }
    }
}

#[test]
fn a_timer_callback_cannot_make_a_pending_signal_deliverable() {
    if bounded("a_timer_callback_cannot_make_a_pending_signal_deliverable") {
        return;
    }
    let ticks = 1_000_000;
    // The guest blocks SIGUSR1 (r14 keeps the address of its mask, SIGUSR2's
    // follows), sends it to itself with a tgkill the Tool does not see, so
    // that it stays pending, then reaches the marker, where the request is
    // made, and the tail. It exits with its signal mask shifted right by 8
    // bits: 2 with SIGUSR1 blocked, 10 with SIGUSR2 blocked as well.
    let program = Program::new(&format!(
        "lea masks(%rip),%r14\n\
         xor %edi,%edi\nmov %r14,%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $14,%eax\nsyscall\n\
         mov $39,%eax\nsyscall\nmov %rax,%r12\nmov $186,%eax\nsyscall\nmov %rax,%r13\n\
         mov %r12,%rdi\nmov %r13,%rsi\nmov $10,%edx\nmov $234,%eax\nsyscall\n\
         {}{GETPPID}{}\
         xor %edi,%edi\nxor %esi,%esi\nlea 16(%r14),%rdx\nmov $8,%r10d\nmov $14,%eax\nsyscall\n\
         mov 16(%r14),%rdi\nshr $8,%rdi\nmov $60,%eax\nsyscall\nud2\n\
         .data\n.balign 8\nmasks: .quad 0x200, 0x800, 0\n",
        branches(1_000),
        branches(ticks + TAIL)
    ));
    for (change, expected) in [
        // Refused: the run fails, though the Tool ignores the error.
        (MaskChange::UnblockPending, None),
        // The controls run, and return their own results.
        (MaskChange::BlockAnother, Some(("Ok(0)", 10))),
        (MaskChange::BadSize, Some(("Err(EINVAL)", 2))),
        (MaskChange::BadHow, Some(("Err(EINVAL)", 2))),
        (MaskChange::BadSet, Some(("Err(EFAULT)", 2))),
    ] {
        let (events, ending) = run_ending(
            &program,
            Plan {
                arm: Arm::Marker,
                requests: vec![ticks],
                quiet_tgkill: true,
                mask_change: Some(change),
                ..Plan::default()
            },
        );
        let context = format!("{change:?}: {events:?}");
        assert_eq!(timer_clocks(&events).len(), 1, "{context}");
        let injected: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::Injected(result) => Some(result.as_str()),
                _ => None,
            })
            .collect();
        match expected {
            None => {
                assert_eq!(injected, [""; 0], "{context}");
                let failure = ending.expect_err(&format!("the run must fail: {context}"));
                assert!(
                    failure.contains(&format!(
                        "KVM timer-event callback injected syscall {}, which a timer event cannot perform",
                        libc::SYS_rt_sigprocmask
                    )),
                    "{context}: {failure}"
                );
            }
            Some((result, code)) => {
                assert_eq!(injected, [result], "{context}");
                assert_eq!(ending, Ok((code, vec![], vec![])), "{context}");
            }
        }
    }
}

#[test]
fn a_parked_signal_cancels_an_outstanding_request() {
    if bounded("a_parked_signal_cancels_an_outstanding_request") {
        return;
    }
    let ticks = 1_000_000;
    let program = Program::new(&(branches(1_000) + GETPPID + &branches(ticks + TAIL) + EXIT));
    // The marker's callback makes the request, then queues a SIGALRM and
    // observes it while parked: the signal's callback cancels the request.
    let events = run(
        &program,
        Plan {
            arm: Arm::Marker,
            requests: vec![ticks],
            parked_signal: true,
            ..Plan::default()
        },
    );
    assert!(events.contains(&Event::Signal(libc::SIGALRM)), "{events:?}");
    assert_eq!(timer_clocks(&events), [0; 0], "{events:?}");
    // The control: without the signal, the request fires.
    let events = run(
        &program,
        Plan {
            arm: Arm::Marker,
            requests: vec![ticks],
            ..Plan::default()
        },
    );
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), 1, "{events:?}");
    let (requested_at, _) = last_request(&events);
    assert_delivered(clocks[0], requested_at, ticks, &format!("{events:?}"));
}

#[test]
fn a_fault_signal_cancels_an_outstanding_request() {
    if bounded("a_fault_signal_cancels_an_outstanding_request") {
        return;
    }
    let ticks = 1_000_000;
    // A SIGILL handler that steps over the faulting ud2, installed first;
    // then the marker, where the request is made, then the fault, whose
    // signal's callback cancels the request, then the tail.
    let program = |fault: &str| {
        Program::new(&format!(
            "mov ${}, %edi\nlea action(%rip), %rsi\nxor %edx, %edx\nmov $8, %r10d\nmov $13, %eax\nsyscall\n\
             test %rax, %rax\njnz failed\n{}{GETPPID}{fault}{}{EXIT}\
             failed: mov $1, %edi\nmov $60, %eax\nsyscall\nud2\n\
             handler: addq $2, 168(%rdx)\nret\nrestorer: mov $15, %eax\nsyscall\nud2\n\
             .data\n.balign 8\naction: .quad handler, 0x4000004, restorer, 0\n",
            libc::SIGILL,
            branches(1_000),
            branches(ticks + TAIL)
        ))
    };
    let plan = Plan {
        arm: Arm::Marker,
        requests: vec![ticks],
        ..Plan::default()
    };
    let events = run(&program("ud2\n"), plan.clone());
    assert!(events.contains(&Event::Signal(libc::SIGILL)), "{events:?}");
    assert_eq!(timer_clocks(&events), [0; 0], "{events:?}");
    // The control: without the fault, the request fires.
    let events = run(&program(""), plan);
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), 1, "{events:?}");
    let (requested_at, _) = last_request(&events);
    assert_delivered(clocks[0], requested_at, ticks, &format!("{events:?}"));
}

#[test]
fn a_restarted_callback_cancels_the_request_of_the_attempt_before() {
    if bounded("a_restarted_callback_cancels_the_request_of_the_attempt_before") {
        return;
    }
    let ticks = 1_000_000;
    let program = Program::new(&(branches(1_000) + GETPPID + &branches(ticks + TAIL) + EXIT));
    // The marker's first attempt makes the request and returns ERESTARTSYS,
    // with no signal pending, so the callback runs again at once: that
    // attempt is the syscall's event again, and cancels the request.
    let events = run(
        &program,
        Plan {
            arm: Arm::Marker,
            requests: vec![ticks],
            restart: Some(false),
            ..Plan::default()
        },
    );
    assert!(
        events.contains(&Event::Attempt(0)) && events.contains(&Event::Attempt(1)),
        "{events:?}"
    );
    assert_eq!(timer_clocks(&events), [0; 0], "{events:?}");
    // The control: the second attempt requests again, and that request fires.
    let events = run(
        &program,
        Plan {
            arm: Arm::Marker,
            requests: vec![ticks],
            restart: Some(true),
            ..Plan::default()
        },
    );
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), 1, "{events:?}");
    let (requested_at, _) = last_request(&events);
    assert_delivered(clocks[0], requested_at, ticks, &format!("{events:?}"));
}

/// How many times each precise test runs its guest.
const REPEATS: usize = 20;

/// RCBs a precise test's guest runs past its target: an event delivered
/// late, by a kick, still comes before the guest exits.
const PRECISE_TAIL: u64 = 1_000_000;

/// Exits with bit 8 of r15, where a guest collects the trap flag of the
/// flags images it reads, as its status.
const EXIT_WITH_TRAP_FLAG_SEEN: &str = "mov %r15d,%edi\nshr $8,%edi\nmov $60,%eax\nsyscall\nud2\n";

/// Ten RCBs, with a label `branches` does not use.
const TEN_RCBS: &str = "mov $10,%ecx\n7: dec %ecx\njnz 7b\n";

/// A guest that keeps the addresses of `branches`' labels in r12 (label 1,
/// where a loop's third branch leaves RIP), r13 (label 2, after its first)
/// and r14 (label 3, after its second), runs `before`, which must not use
/// those labels, then a loop of `rcbs` RCBs, then `exit`.
fn labelled(before: &str, rcbs: u64, exit: &str) -> Program {
    Program::new(&format!(
        "lea 1f(%rip),%r12\nlea 2f(%rip),%r13\nlea 3f(%rip),%r14\n{before}{}{exit}",
        branches(rcbs)
    ))
}

/// Where the loop's `branch`-th branch, counted from 1, leaves RIP.
fn after_branch(registers: &Registers, branch: u64) -> u64 {
    match branch % 3 {
        1 => registers.r13,
        2 => registers.r14,
        _ => registers.r12,
    }
}

/// The most guests [`lands_exactly`] runs for one target: as many again as
/// the exact runs it needs, for kicks proven late. On this host about one
/// kick in a hundred came past the 2,000 RCB margin, and one in seven at a
/// load average of 43.
const ATTEMPTS: usize = 2 * REPEATS;

/// A plan that requests one precise event of `ticks` RCBs at the start of
/// each image.
fn precise(ticks: u64) -> Plan {
    Plan {
        requests: vec![ticks],
        precise: true,
        ..Plan::default()
    }
}

/// What one guest of [`lands_exactly`] showed: an exact event, or a kick
/// proven late before any entry of its stepping window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Landing {
    Exact,
    ProvenLate,
}

/// Runs guests through `land`, given each one's attempt number, until
/// [`REPEATS`] land exactly, running a proven-late one again, but never more
/// than [`ATTEMPTS`] guests in all. Returns how many came late, or the
/// refusal of a guest past that budget.
fn within_attempts(mut land: impl FnMut(usize) -> Landing) -> Result<usize, String> {
    let (mut exact, mut late) = (0, 0);
    while exact < REPEATS {
        if exact + late == ATTEMPTS {
            return Err(format!(
                "{late} proven-late guests left {ATTEMPTS} too few for {REPEATS} exact ones"
            ));
        }
        match land(exact + late + 1) {
            Landing::Exact => exact += 1,
            Landing::ProvenLate => late += 1,
        }
    }
    Ok(late)
}

#[test]
fn the_guest_budget_of_a_precise_target_is_a_total() {
    // The first `late` guests come late, proven so, and the rest exactly:
    // what `within_attempts` returns, and how many guests it ran.
    let run = |late: usize| {
        let mut guests = 0;
        let result = within_attempts(|_| {
            guests += 1;
            if guests <= late {
                Landing::ProvenLate
            } else {
                Landing::Exact
            }
        });
        (result, guests)
    };
    assert_eq!(run(0), (Ok(0), REPEATS));
    assert_eq!(run(REPEATS), (Ok(REPEATS), ATTEMPTS));
    assert!(matches!(run(REPEATS + 1), (Err(_), ATTEMPTS)));
}

/// Runs `program` under `plan`, with registers reported, until `REPEATS`
/// runs have exited with status 0 and got one timer event exactly at
/// `target`, with RIP where `rip` says, and the same registers every time.
///
/// A request whose last notification is a kick (`kicked`: its target lies
/// more than the skid margin plus the single-step allowance past the clock
/// where it is requested) can come late: the PMU interrupt behind about one
/// kick in a thousand on an idle host, and one in a hundred on a busy one,
/// arrives past the margin. Such a run gets its one event past the target,
/// recorded as late, before any entry of the window began (see
/// [`WINDOW_ENTRIES`]), and is run again, within [`ATTEMPTS`] guests in all
/// (see [`within_attempts`]). Every other run must land exactly and record
/// no skid overshoot (the process-global witness count), so a miss after the
/// window's entries began fails.
fn lands_exactly(
    program: &Program,
    plan: Plan,
    target: u64,
    rip: impl Fn(&Registers) -> u64,
    kicked: bool,
) -> Registers {
    let mut first: Option<Registers> = None;
    let _ = reverie::take_skid_overshoot_count();
    within_attempts(|attempt| {
        let events = run(
            program,
            Plan {
                registers: true,
                ..plan.clone()
            },
        );
        let witnessed = reverie::take_skid_overshoot_count();
        let entries = WINDOW_ENTRIES.load(Ordering::Relaxed);
        let context = format!(
            "target {target}, attempt {attempt}, {witnessed} recorded, {entries} window entries: \
             {events:?}"
        );
        let clocks = timer_clocks(&events);
        if kicked && clocks.len() == 1 && clocks[0] > target && entries == 0 {
            assert!(witnessed > 0, "a late event is recorded: {context}");
            println!(
                "late run: target {target}, attempt {attempt}, delivered at {} before any \
                 window entry",
                clocks[0]
            );
            return Landing::ProvenLate;
        }
        assert_eq!(clocks, [target], "{context}");
        assert_eq!(witnessed, 0, "{context}");
        let registers = registers_of(&events);
        assert_eq!(registers.rip, rip(&registers), "{context}");
        match &first {
            None => first = Some(registers),
            Some(first) => assert_eq!(&registers, first, "{context}"),
        }
        Landing::Exact
    })
    .unwrap_or_else(|refusal| panic!("target {target}: {refusal}"));
    first.unwrap()
}

/// The registers the run's one timer event saw.
fn registers_of(events: &[Event]) -> Registers {
    events
        .iter()
        .find_map(|event| match event {
            Event::Registers(registers) => Some(registers.clone()),
            _ => None,
        })
        .unwrap()
}

/// A precise event `k` RCBs from where the image starts, for each `k`.
fn precise_events_land_exactly(ticks: &[u64]) {
    for &k in ticks {
        let program = labelled("", k + PRECISE_TAIL, EXIT);
        let plan = precise(k);
        let kicked = k > skid_margin() + reverie::pmu_config::SINGLESTEP_TIMEOUT_RCBS;
        let registers = lands_exactly(&program, plan, k, |r| after_branch(r, k), kicked);
        // The loop counts RCX down once per iteration of three branches,
        // before the third: after branch k it has done floor(k / 3) of them.
        assert_eq!(
            registers.rcx,
            (k + PRECISE_TAIL).div_ceil(3) - k / 3,
            "{registers:x?}"
        );
        println!("precise {k} RCBs: {REPEATS} runs at clock {k}, {registers:x?}");
    }
}

#[test]
fn a_precise_event_lands_exactly_one_to_six_rcbs_on() {
    if bounded("a_precise_event_lands_exactly_one_to_six_rcbs_on") {
        return;
    }
    precise_events_land_exactly(&[1, 2, 3, 4, 5, 6]);
}

#[test]
fn a_precise_event_lands_exactly_around_the_skid_margin() {
    if bounded("a_precise_event_lands_exactly_around_the_skid_margin") {
        return;
    }
    let margin = skid_margin();
    precise_events_land_exactly(&[margin - 1, margin, margin + 5, margin + 6]);
}

#[test]
fn a_precise_event_lands_exactly_around_the_staging_edge() {
    if bounded("a_precise_event_lands_exactly_around_the_staging_edge") {
        return;
    }
    // The longest request that is not staged, and the shortest that is.
    let edge = reverie::pmu_config::try_get_pmu_config()
        .unwrap()
        .first_stage_margin()
        + reverie::pmu_config::SINGLESTEP_TIMEOUT_RCBS;
    precise_events_land_exactly(&[edge, edge + 1]);
}

#[test]
fn a_precise_event_lands_exactly_far_off() {
    if bounded("a_precise_event_lands_exactly_far_off") {
        return;
    }
    precise_events_land_exactly(&[1_000_000, 100_000_000]);
}

/// A hand-built IRETQ to the next instruction, in the same mode.
const IRETQ_TO_NEXT: &str = "mov %ss,%eax\npush %rax\nlea 8(%rsp),%rax\npush %rax\npushfq\n\
     mov %cs,%eax\npush %rax\nlea 9f(%rip),%rax\npush %rax\niretq\n9:\n";

#[test]
fn a_stepped_guest_never_sees_the_trap_flag() {
    if bounded("a_stepped_guest_never_sees_the_trap_flag") {
        return;
    }
    // In the window, the guest ORs into r15 the TF of the images it reads
    // through PUSHF of both widths, also after RDTSC, CPUID and a getpid,
    // then loads CF, PF, AF, ZF, SF and OF with POPF, reads them back into
    // rbx, and keeps rsp in rbp.
    let read = "pushfq\npop %rax\nand $0x100,%eax\nor %eax,%r15d\n";
    let read16 = "pushfw\nmovzwl (%rsp),%eax\nadd $2,%rsp\nand $0x100,%eax\nor %eax,%r15d\n";
    let before = format!(
        "xor %r15d,%r15d\n{read}{read16}pushfw\npopfw\nrdtsc\n{read}xor %eax,%eax\ncpuid\n{read}\
         mov $39,%eax\nsyscall\n{read16}mov %rsp,%rbp\npush $0x8d7\npopfq\npushfq\npop %rbx\n"
    );
    let k = 40;
    let program = labelled(&before, k + PRECISE_TAIL, EXIT_WITH_TRAP_FLAG_SEEN);
    let plan = Plan {
        no_syscalls: true,
        ..precise(k)
    };
    let r = lands_exactly(&program, plan.clone(), k, |r| after_branch(r, k), false);
    // As a CPL 3 POPF loads them: IF stays as it was.
    assert_eq!(
        (r.rbx, r.rsp),
        (0x8d7 | (r.eflags & 0x200), r.rbp),
        "{r:x?}"
    );
    // Refused by name inside the window: a POPF of either width that sets
    // TF, a load of SS, and IRETQ. The latter two run as usual outside it.
    for (before, refusal) in [
        (
            "pushfq\norq $0x100,(%rsp)\npopfq\n",
            "sets its own trap flag",
        ),
        (
            "pushfw\norw $0x100,(%rsp)\npopfw\n",
            "sets its own trap flag",
        ),
        ("mov %ss,%eax\nmov %eax,%ss\n", "loads SS"),
        (IRETQ_TO_NEXT, "runs IRETQ"),
    ] {
        let program = labelled(before, k + PRECISE_TAIL, EXIT);
        let (events, ending) = run_ending(&program, plan.clone());
        let failure = ending.expect_err(&format!("{refusal}: the run must fail: {events:?}"));
        assert!(failure.contains(refusal), "{failure}");
        if !refusal.contains("trap flag") {
            let mut outside = plan.clone();
            outside.precise = false;
            run(&program, outside);
        }
    }
}

/// After `lead` (`base` RCBs), 100-byte REP MOVSB and REP STOSB, five LOOP
/// iterations, a JRCXZ and a JNZ to a REP MOVSB: a precise request for each
/// of their branches lands exactly. Adopted from a review's probes.
fn loop_jrcxz_and_rep_land_exactly(lead: &str, base: u64) {
    let program = Program::new(&format!(
        "lea 8f(%rip),%r12\nlea 5f(%rip),%r13\nlea 6f(%rip),%r14\nlea 4f(%rip),%r8\n{lead}\
         lea srcbuf(%rip),%rsi\nlea dstbuf(%rip),%rdi\nmov $100,%ecx\nrep movsb\n\
         mov $100,%ecx\nrep stosb\nmov $5,%ecx\n8: loop 8b\n5: xor %ecx,%ecx\njrcxz 6f\nnop\n\
         6: mov $1,%eax\nmov $64,%ecx\nlea srcbuf(%rip),%rsi\nlea dstbuf(%rip),%rdi\n\
         test %eax,%eax\njnz 4f\nnop\n4: rep movsb\n{}{EXIT}\
         .data\nsrcbuf: .fill 256,1,0x5a\ndstbuf: .fill 256,1,0\n",
        branches(PRECISE_TAIL)
    ));
    for (offset, rip, rcx) in [
        (1, (|r: &Registers| r.r12) as fn(&Registers) -> u64, 4),
        (3, |r| r.r12, 2),
        (4, |r| r.r12, 1),
        (5, |r| r.r13, 0),
        (6, |r| r.r14, 0),
        (7, |r| r.r8, 64),
    ] {
        let k = base + offset;
        let plan = precise(k);
        let kicked = k > skid_margin() + reverie::pmu_config::SINGLESTEP_TIMEOUT_RCBS;
        let registers = lands_exactly(&program, plan, k, rip, kicked);
        assert_eq!(registers.rcx, rcx, "{k}: {registers:x?}");
    }
}

#[test]
fn loop_jrcxz_and_rep_land_exactly_inside_the_window() {
    if bounded("loop_jrcxz_and_rep_land_exactly_inside_the_window") {
        return;
    }
    loop_jrcxz_and_rep_land_exactly("", 0);
}

#[test]
fn loop_jrcxz_and_rep_land_exactly_after_a_kick() {
    if bounded("loop_jrcxz_and_rep_land_exactly_after_a_kick") {
        return;
    }
    loop_jrcxz_and_rep_land_exactly(&branches(999_993), 999_993);
}

/// A getpid right after branch 999, the last of its loop, then the tail;
/// r8 holds the getpid's first instruction.
fn getpid_after_branch_999() -> Program {
    labelled(
        "lea 4f(%rip),%r8\n",
        999,
        &format!("4: mov $39,%eax\nsyscall\n{}{EXIT}", branches(PRECISE_TAIL)),
    )
}

/// A guest whose SIGSEGV handler steps over the 8-byte load that faults,
/// retires `rcbs` RCBs and, right after the last, makes the rt_sigreturn
/// itself, to return to a loop that makes no syscall. r12 holds the
/// instruction it returns to.
fn signal_return_program(rcbs: usize) -> Program {
    Program::new(&format!(
        "lea 9f(%rip),%r12\nmov ${}, %edi\nlea action(%rip), %rsi\nxor %edx, %edx\n\
         mov $8, %r10d\nmov $13, %eax\nsyscall\nmovq 0x10,%rax\n9:\n{}{EXIT}\
         handler: addq $8,168(%rdx)\nadd $8,%rsp\nmov $15,%eax\n{}syscall\nrestorer: ud2\n\
         .data\n.balign 8\naction: .quad handler, 0x4000004, restorer, 0\n",
        libc::SIGSEGV,
        branches(PRECISE_TAIL),
        "xor %ecx,%ecx\njz 7f\n7:\n".repeat(rcbs),
    ))
}

#[test]
fn a_request_due_at_rt_sigreturn_is_delivered_with_the_registers_it_restores() {
    if bounded("a_request_due_at_rt_sigreturn_is_delivered_with_the_registers_it_restores") {
        return;
    }
    // The signal's callback requests 1 RCB. The handler's one branch reaches
    // the target and the earliest overflow, 2 RCBs on, comes later, so
    // rt_sigreturn's exit is the first at the target.
    let plan = Plan {
        requests: vec![],
        rearm_at_signal: Some(1),
        registers: true,
        ..Plan::default()
    };
    let events = run(&signal_return_program(1), plan);
    let (requested_at, _) = last_request(&events);
    assert_eq!(timer_clocks(&events), [requested_at + 1], "{events:?}");
    let r = registers_of(&events);
    assert_eq!(r.rip, r.r12, "{r:x?}");
}

#[test]
fn with_no_skid_margin_a_precise_request_is_late_and_still_delivered() {
    // With no skid margin, a request is programmed at its target.
    if bounded_with(
        "with_no_skid_margin_a_precise_request_is_late_and_still_delivered",
        &[(reverie::pmu_config::SKID_MARGIN_OVERRIDE_ENV, "0")],
    ) {
        return;
    }
    assert_eq!(skid_margin(), 0);
    // An unstepped exit exactly at the target, the getpid right after branch
    // 999 or the kick before it, is late.
    let program = getpid_after_branch_999();
    let plan = Plan {
        no_syscalls: true,
        ..precise(999)
    };
    for _ in 0..REPEATS {
        let _ = reverie::take_skid_overshoot_count();
        let events = run(&program, plan.clone());
        assert_eq!(timer_clocks(&events), [999], "{events:?}");
        assert_eq!(reverie::take_skid_overshoot_count(), 1, "{events:?}");
        assert_eq!(WINDOW_ENTRIES.load(Ordering::Relaxed), 0, "{events:?}");
    }
    // A request for 6 RCBs from the signal's callback passes its target in
    // the handler, unstepped, and is late at rt_sigreturn (or at an earlier
    // kick), and delivered once to a guest that makes no syscall after it.
    let program = signal_return_program(6);
    let plan = Plan {
        requests: vec![],
        rearm_at_signal: Some(6),
        precise: true,
        registers: true,
        ..Plan::default()
    };
    let mut at_return = 0;
    for _ in 0..REPEATS {
        let _ = reverie::take_skid_overshoot_count();
        let events = run(&program, plan.clone());
        let (requested_at, _) = last_request(&events);
        assert_eq!(timer_clocks(&events), [requested_at + 6], "{events:?}");
        assert_eq!(reverie::take_skid_overshoot_count(), 1, "{events:?}");
        let r = registers_of(&events);
        at_return += usize::from(r.rip == r.r12);
    }
    assert!(at_return > 0, "never delivered at rt_sigreturn");
    println!("late at its target, delivered at rt_sigreturn in {at_return} of {REPEATS} runs");
}

#[test]
fn a_syscall_inside_the_stepping_window() {
    if bounded("a_syscall_inside_the_stepping_window") {
        return;
    }
    // A request for 100 RCBs, then a getpid at clock 10.
    let program = labelled(
        &format!("{TEN_RCBS}mov $39,%eax\nsyscall\n"),
        1_000 + PRECISE_TAIL,
        EXIT,
    );
    let plan = precise(100);
    // Subscribed, the getpid cancels the request; one made in its callback
    // lands exactly, and without one nothing comes.
    let rearmed = Plan {
        rearm_at_getpid: Some(50),
        ..plan.clone()
    };
    lands_exactly(&program, rearmed, 60, |r| after_branch(r, 50), false);
    let events = run(&program, plan.clone());
    assert_eq!(timer_clocks(&events), [0; 0], "{events:?}");
    // Unsubscribed, the backend answers it and the steps go on after it.
    let quiet = Plan {
        no_syscalls: true,
        ..plan
    };
    lands_exactly(&program, quiet.clone(), 100, |r| after_branch(r, 90), false);
    // The guest of the unstepped arrival control (see
    // `with_no_skid_margin_a_precise_request_is_late_and_still_delivered`):
    // stepped from the start, its request lands exactly at the getpid.
    let quiet = Plan {
        requests: vec![999],
        ..quiet
    };
    lands_exactly(&getpid_after_branch_999(), quiet, 999, |r| r.r8, false);
}

#[test]
fn rdtsc_and_cpuid_inside_the_stepping_window() {
    if bounded("rdtsc_and_cpuid_inside_the_stepping_window") {
        return;
    }
    let program = labelled(
        &format!("{TEN_RCBS}rdtsc\nxor %eax,%eax\ncpuid\n"),
        1_000 + PRECISE_TAIL,
        EXIT,
    );
    let plan = precise(100);
    // Unsubscribed, each runs unstepped to the next instruction, and the
    // steps go on from there.
    lands_exactly(&program, plan.clone(), 100, |r| after_branch(r, 90), false);
    // Subscribed, each is an event of its own, which cancels the request.
    for (name, plan, witness) in [
        (
            "RDTSC",
            Plan {
                rdtsc: true,
                ..plan.clone()
            },
            Event::Rdtsc,
        ),
        (
            "CPUID",
            Plan {
                cpuid: true,
                ..plan
            },
            Event::Cpuid,
        ),
    ] {
        let events = run(&program, plan);
        assert!(events.contains(&witness), "{name}: {events:?}");
        assert_eq!(timer_clocks(&events), [0; 0], "{name}: {events:?}");
    }
}

#[test]
fn a_fault_inside_the_stepping_window_leaves_no_trap_flag_in_its_frame() {
    if bounded("a_fault_inside_the_stepping_window_leaves_no_trap_flag_in_its_frame") {
        return;
    }
    // A SIGSEGV handler that collects the trap flag of the frame's saved
    // RFLAGS into the frame's r15, and steps over the 8-byte load that
    // faults; installed first. Then the marker, where 300 RCBs are
    // requested, ten RCBs, the load at clock 10, and the loop.
    let program = |fault: &str| {
        labelled(
            &format!(
                "mov ${}, %edi\nlea action(%rip), %rsi\nxor %edx, %edx\nmov $8, %r10d\n\
                 mov $13, %eax\nsyscall\nxor %r15d,%r15d\n{GETPPID}{TEN_RCBS}{fault}",
                libc::SIGSEGV
            ),
            1_000 + PRECISE_TAIL,
            &format!(
                "{EXIT_WITH_TRAP_FLAG_SEEN}\
                 handler: mov 176(%rdx),%rax\nand $0x100,%eax\nor %rax,96(%rdx)\n\
                 addq $8,168(%rdx)\nret\nrestorer: mov $15,%eax\nsyscall\nud2\n\
                 .data\n.balign 8\naction: .quad handler, 0x4000004, restorer, 0\n"
            ),
        )
    };
    let faulting = program("movq 0x10,%rax\n");
    let plan = Plan {
        arm: Arm::Marker,
        ..precise(300)
    };
    // The fault's signal is an event of its own, which cancels the request.
    let events = run(&faulting, plan.clone());
    assert!(events.contains(&Event::Signal(libc::SIGSEGV)), "{events:?}");
    assert_eq!(timer_clocks(&events), [0; 0], "{events:?}");
    // One made in the signal's callback lands exactly: the steps go on
    // through the handler and after its rt_sigreturn.
    let rearmed = Plan {
        rearm_at_signal: Some(200),
        ..plan.clone()
    };
    lands_exactly(&faulting, rearmed, 210, |r| after_branch(r, 200), false);
    // The control: without the fault, the request lands exactly.
    lands_exactly(&program(""), plan, 300, |r| after_branch(r, 290), false);
}

#[test]
fn a_replaced_or_stale_precise_request_still_lands_exactly() {
    if bounded("a_replaced_or_stale_precise_request_still_lands_exactly") {
        return;
    }
    let program = labelled("", 600 + PRECISE_TAIL, EXIT);
    for (requests, target) in [(vec![500, 300], 300), (vec![300, 500], 500)] {
        let plan = Plan {
            requests,
            precise: true,
            ..Plan::default()
        };
        lands_exactly(&program, plan, target, |r| after_branch(r, target), false);
    }
    // A request for 3,000 RCBs, programmed 1,000 RCBs on, cancelled by a
    // getpid at clock 10 whose callback requests 100,000: the event keeps
    // its pending overflow at 1,000, now stale, which changes nothing.
    let plan = precise(3_000);
    let program = |call: &str| labelled(&format!("{TEN_RCBS}{call}"), 200_000 + PRECISE_TAIL, EXIT);
    let rearmed = Plan {
        rearm_at_getpid: Some(100_000),
        ..plan.clone()
    };
    lands_exactly(
        &program("mov $39,%eax\nsyscall\n"),
        rearmed,
        100_010,
        |r| after_branch(r, 100_000),
        true,
    );
    // The control: without the getpid, the first request lands exactly.
    lands_exactly(&program(""), plan, 3_000, |r| after_branch(r, 2_990), true);
}

/// Where the guests of the signal tests below keep their SIGUSR1 handler's
/// record, which they write to stdout before they exit: the interrupted
/// context in the handler's frame (rip, rax, rbx, rcx, eflags, r12, r14 and
/// r15), then how many times the handler ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    rip: u64,
    rax: u64,
    rbx: u64,
    rcx: u64,
    eflags: u64,
    r12: u64,
    r14: u64,
    r15: u64,
    count: u64,
}

impl Record {
    fn read(stdout: &[u8]) -> Self {
        assert_eq!(stdout.len(), 72, "{stdout:?}");
        let quad = |i: usize| u64::from_ne_bytes(stdout[8 * i..8 * i + 8].try_into().unwrap());
        Self {
            rip: quad(0),
            rax: quad(1),
            rbx: quad(2),
            rcx: quad(3),
            eflags: quad(4),
            r12: quad(5),
            r14: quad(6),
            r15: quad(7),
            count: quad(8),
        }
    }
}

/// SA_RESTORER and SA_SIGINFO.
const HANDLER_FLAGS: u64 = 0x0400_0004;

/// The SIGUSR1 handler that fills the [`Record`] from its frame's ucontext
/// (in rdx) and sets `flag`, its restorer, and the data both use. `actions`
/// adds sigaction records before `usr1_action`.
fn signal_record(flags: u64, actions: &str) -> String {
    let save: String = [168, 144, 128, 152, 176, 72, 88, 96]
        .iter()
        .enumerate()
        .map(|(i, at)| format!("mov {at}(%rdx),%rax\nmov %rax,record+{}(%rip)\n", 8 * i))
        .collect();
    format!(
        "usr1:\nincq record+64(%rip)\n{save}movb $1,flag(%rip)\nret\n\
         restorer: mov $15,%eax\nsyscall\nud2\n\
         .data\n.balign 8\n{actions}usr1_action: .quad usr1, {flags:#x}, restorer, 0\n\
         record: .quad 0,0,0,0,0,0,0,0,0\npid: .quad 0\ntid: .quad 0\nmask: .quad 0x200\n\
         flag: .byte 0\n.bss\n.balign 16\nstack: .skip 65536\nstack_end:\n"
    )
}

/// Writes the [`Record`] and exits with status 0.
const WRITE_RECORD: &str = "mov $1,%edi\nlea record(%rip),%rsi\nmov $72,%edx\nmov $1,%eax\nsyscall\n\
     xor %edi,%edi\nmov $231,%eax\nsyscall\nud2\n";

/// Installs the SIGUSR1 handler of [`signal_record`] and starts a sibling
/// thread that sends SIGUSR1 to this one, with a `tgkill`, and exits.
const SIBLING: &str = "mov $10,%edi\nlea usr1_action(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\n\
     mov $13,%eax\nsyscall\nmov $39,%eax\nsyscall\nmov %rax,pid(%rip)\n\
     mov $186,%eax\nsyscall\nmov %rax,tid(%rip)\n\
     mov $0x50f00,%edi\nlea stack_end(%rip),%rsi\nxor %edx,%edx\nxor %r10d,%r10d\n\
     xor %r8d,%r8d\nmov $56,%eax\nsyscall\ntest %rax,%rax\njnz 8f\n\
     mov pid(%rip),%rdi\nmov tid(%rip),%rsi\nmov $10,%edx\nmov $234,%eax\nsyscall\n\
     xor %edi,%edi\nmov $60,%eax\nsyscall\nud2\n8:\n";

/// How many iterations the spinner of [`spinner`] runs at most.
const SPINS: u64 = 1_000_000;

/// A guest whose sibling sends it SIGUSR1 (see [`SIBLING`]), which then
/// reaches the marker and spins without a syscall, 2 RCBs an iteration, with
/// rax at -ERESTARTSYS and r12 at the loop's head, until its handler has run
/// or for [`SPINS`] iterations. With `blocked`, SIGUSR1 is blocked before the
/// marker and unblocked after the loop, with r12 at that call's return.
fn spinner(flags: u64, blocked: bool) -> Program {
    spinner_after(flags, blocked, "")
}

/// [`spinner`], running `prefix` right before the marker.
fn spinner_after(flags: u64, blocked: bool, prefix: &str) -> Program {
    let mask = |how: u32| {
        format!(
            "mov ${how},%edi\nlea mask(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $14,%eax\nsyscall\n"
        )
    };
    let (block, unblock) = if blocked {
        (mask(0), format!("lea 3f(%rip),%r12\n{}3:\n", mask(1)))
    } else {
        (String::new(), String::new())
    };
    Program::new(&format!(
        "{SIBLING}{block}{prefix}{GETPPID}lea 1f(%rip),%r12\nmov $-512,%rax\nxor %ebx,%ebx\nmov ${SPINS},%rcx\n\
         1: inc %rbx\ncmpb $0,flag(%rip)\njne 2f\ndec %rcx\njnz 1b\n2:\n{unblock}{WRITE_RECORD}{}",
        signal_record(flags, "")
    ))
}

/// A precise request for this many RCBs at the marker: stepped from the
/// marker on, so it is never late.
const SPIN_TICKS: u64 = 1_000;

fn spinner_plan() -> Plan {
    Plan {
        arm: Arm::Marker,
        requests: vec![SPIN_TICKS],
        precise: true,
        registers: true,
        rendezvous: true,
        deliver: true,
        ..Plan::default()
    }
}

/// Runs `program`, checks that it exits with status 0, and returns the
/// Tool's events and the guest's [`Record`].
fn run_recorded(program: &Program, plan: Plan) -> (Vec<Event>, Record) {
    let (events, ending) = run_ending(program, plan);
    let (code, stdout, stderr) = ending.unwrap_or_else(|failure| panic!("{failure}: {events:?}"));
    assert_eq!((code, stderr), (0, vec![]), "{events:?}");
    (events, Record::read(&stdout))
}

/// The clock at the callback of each delivered SIGUSR1, and the index of
/// its event.
fn sigusr1_clocks(events: &[Event]) -> Vec<(usize, u64)> {
    events
        .iter()
        .enumerate()
        .filter_map(|(at, event)| match event {
            Event::Signalled { signal, clock } if *signal == libc::SIGUSR1 => Some((at, *clock)),
            _ => None,
        })
        .collect()
}

/// The index of the first timer event, and its clock.
fn first_timer(events: &[Event]) -> (usize, u64) {
    events
        .iter()
        .enumerate()
        .find_map(|(at, event)| match event {
            Event::Timer { clock } => Some((at, *clock)),
            _ => None,
        })
        .expect("a timer event")
}

#[test]
fn a_spinner_signalled_by_a_sibling_gets_its_handler_at_the_next_timer_boundary() {
    if bounded("a_spinner_signalled_by_a_sibling_gets_its_handler_at_the_next_timer_boundary") {
        return;
    }
    // The sibling's tgkill runs while the timer event's callback waits for
    // it, so SIGUSR1 is pending when the callback returns, at the boundary
    // right after branch 1,000. It is delivered there, before the guest runs
    // on: the handler's frame holds the registers the timer event saw, and
    // the loop's head, its 500 iterations and rax as the loop left it. That
    // rax is -ERESTARTSYS changes nothing, with SA_RESTART or without: no
    // syscall is interrupted there, so nothing restarts.
    let mut first = None;
    for flags in [HANDLER_FLAGS, HANDLER_FLAGS | libc::SA_RESTART as u64] {
        let program = spinner(flags, false);
        for _ in 0..REPEATS {
            let (events, record) = run_recorded(&program, spinner_plan());
            let context = format!("{flags:#x}: {record:x?} {events:?}");
            let (requested_at, _) = last_request(&events);
            let target = requested_at + SPIN_TICKS;
            let (timer_at, timer_clock) = first_timer(&events);
            assert_eq!(timer_clocks(&events), [target], "{context}");
            let delivered = sigusr1_clocks(&events);
            assert_eq!(delivered.len(), 1, "{context}");
            assert!(delivered[0].0 > timer_at, "{context}");
            assert_eq!(delivered[0].1, timer_clock, "{context}");
            let r = registers_of(&events);
            assert_eq!(record.count, 1, "{context}");
            assert_eq!(
                (
                    record.rip,
                    record.rax,
                    record.rbx,
                    record.rcx,
                    record.eflags
                ),
                (r.rip, r.rax, r.rbx, r.rcx, r.eflags),
                "{context}"
            );
            assert_eq!(record.rip, record.r12, "{context}");
            assert_eq!(record.rax, -512_i64 as u64, "{context}");
            assert_eq!(record.rbx, SPIN_TICKS / 2, "{context}");
            assert_eq!(record.rcx, SPINS - SPIN_TICKS / 2, "{context}");
            assert_eq!(*first.get_or_insert(record), record, "{context}");
        }
    }
    println!("delivered at the timer boundary with {first:x?}");
}

/// Sets the FS base to the address of `record`, kept in r13, and the GS base
/// to that of `pid`, kept in r15 (arch_prctl ARCH_SET_FS and ARCH_SET_GS).
const SET_BASES: &str = "lea record(%rip),%r13\nmov $0x1002,%edi\nmov %r13,%rsi\nmov $158,%eax\nsyscall\n\
     lea pid(%rip),%r15\nmov $0x1001,%edi\nmov %r15,%rsi\nmov $158,%eax\nsyscall\n";

#[test]
fn a_signal_hook_at_a_timer_boundary_sees_the_timer_events_registers() {
    if bounded("a_signal_hook_at_a_timer_boundary_sees_the_timer_events_registers") {
        return;
    }
    // With the FS and GS bases set, the signal's callback at the timer
    // boundary sees the complete user registers the timer event's callback
    // saw there: the general registers, orig_rax -1, the segment selectors
    // and both bases.
    let plan = Plan {
        signal_registers: true,
        ..spinner_plan()
    };
    let (events, record) = run_recorded(&spinner_after(HANDLER_FLAGS, false, SET_BASES), plan);
    let context = format!("{record:x?} {events:?}");
    assert_eq!(record.count, 1, "{context}");
    let seen: Vec<&Registers> = events
        .iter()
        .filter_map(|event| match event {
            Event::Registers(registers) => Some(registers),
            _ => None,
        })
        .collect();
    assert_eq!(seen.len(), 2, "{context}");
    assert_eq!(seen[0], seen[1], "{context}");
    let r = seen[1];
    assert_ne!((r.r13, r.r15), (0, 0), "{context}");
    assert_eq!((r.fs_base, r.gs_base), (r.r13, r.r15), "{context}");
    assert_eq!(
        (r.orig_rax, r.cs & 3, r.ss & 3),
        (u64::MAX, 3, 3),
        "{context}"
    );
}

#[test]
fn a_signal_hook_before_a_new_threads_first_instruction_sees_its_registers() {
    if bounded("a_signal_hook_before_a_new_threads_first_instruction_sees_its_registers") {
        return;
    }
    // The user boundary of a new thread shares the timer boundary's signal
    // hook context. The guest clones a thread whose TLS (the FS base) is
    // `record`, and sends it SIGUSR1 while the Tool holds its start; the
    // thread takes it before its first instruction, and the signal's
    // callback sees its complete registers: the FS base it was given (also
    // in r8, the clone's TLS argument), user segment selectors, orig_rax -1.
    let program = Program::new(&format!(
        "mov $10,%edi\nlea usr1_action(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\nsyscall\n\
         mov $39,%eax\nsyscall\nmov %rax,pid(%rip)\n\
         mov $0xd0f00,%edi\nlea stack_end(%rip),%rsi\nxor %edx,%edx\nxor %r10d,%r10d\n\
         lea record(%rip),%r8\nmov $56,%eax\nsyscall\ntest %rax,%rax\njz 8f\n\
         mov pid(%rip),%rdi\nmov %rax,%rsi\nmov $10,%edx\nmov $234,%eax\nsyscall\n\
         mov $2000000000,%ecx\n9: cmpb $0,flag(%rip)\njne 7f\ndec %rcx\njnz 9b\n7:\n{WRITE_RECORD}\
         8: xor %edi,%edi\nmov $60,%eax\nsyscall\nud2\n{}",
        signal_record(HANDLER_FLAGS, "")
    ));
    let plan = Plan {
        hold_thread_start: true,
        signal_registers: true,
        deliver: true,
        ..Plan::default()
    };
    let (events, record) = run_recorded(&program, plan);
    let context = format!("{record:x?} {events:?}");
    assert_eq!(record.count, 1, "{context}");
    let r = registers_of(&events);
    assert_ne!(r.r8, 0, "{context}");
    assert_eq!(r.fs_base, r.r8, "{context}");
    assert_eq!(
        (r.orig_rax, r.rax, r.cs & 3, r.ss & 3),
        (u64::MAX, 0, 3, 3),
        "{context}"
    );
    assert_eq!(record.rip, r.rip, "{context}");
}

#[test]
fn a_blocked_signal_waits_at_the_timer_boundary_for_its_unblock() {
    if bounded("a_blocked_signal_waits_at_the_timer_boundary_for_its_unblock") {
        return;
    }
    // SIGUSR1 is blocked, so the timer boundary leaves it pending: the loop
    // runs to its end, and the unblock's return delivers it, with the
    // handler's frame at that call's return (where SYSCALL left rcx).
    let (events, record) = run_recorded(&spinner(HANDLER_FLAGS, true), spinner_plan());
    let context = format!("{record:x?} {events:?}");
    let (requested_at, _) = last_request(&events);
    assert_eq!(
        timer_clocks(&events),
        [requested_at + SPIN_TICKS],
        "{context}"
    );
    assert_eq!(record.count, 1, "{context}");
    assert_eq!((record.rip, record.rax), (record.r12, 0), "{context}");
    assert_eq!((record.rbx, record.rcx), (SPINS, record.rip), "{context}");
    let delivered = sigusr1_clocks(&events);
    assert_eq!(delivered.len(), 1, "{context}");
    assert_eq!(delivered[0].1, requested_at + 2 * SPINS, "{context}");
}

#[test]
fn a_signal_pending_at_a_syscall_return_timer_event_follows_it() {
    if bounded("a_signal_pending_at_a_syscall_return_timer_event_follows_it") {
        return;
    }
    // The guest of
    // `a_timer_event_reaches_a_guest_making_syscalls_the_tool_does_not_see`,
    // with the sibling: its tgkill is the only syscall the Tool sees, and it
    // runs while the timer event's callback, at the return of a getpid,
    // waits for it. The signal is delivered at that same return, after the
    // callback, as the getpid's own: the handler's frame holds the registers
    // the timer event saw, with getpid's result and the loop's count.
    let program = Program::new(&format!(
        "{SIBLING}lea 7f(%rip),%r14\nmov $50000,%r15\n4: mov $3,%rbx\n5: dec %rbx\njnz 5b\n\
         mov $39,%eax\nsyscall\n7: dec %r15\njnz 4b\n{WRITE_RECORD}{}",
        signal_record(HANDLER_FLAGS, "")
    ));
    let plan = Plan {
        requests: vec![100_000],
        only_tgkill: true,
        registers: true,
        rendezvous: true,
        deliver: true,
        ..Plan::default()
    };
    let (events, record) = run_recorded(&program, plan);
    let context = format!("{record:x?} {events:?}");
    let (timer_at, timer_clock) = first_timer(&events);
    assert_eq!(timer_clocks(&events).len(), 1, "{context}");
    let delivered = sigusr1_clocks(&events);
    assert_eq!(delivered.len(), 1, "{context}");
    assert!(delivered[0].0 > timer_at, "{context}");
    assert_eq!(delivered[0].1, timer_clock, "{context}");
    let r = registers_of(&events);
    assert_eq!(
        r.rip, r.r14,
        "the timer event at a getpid's return: {context}"
    );
    assert_eq!(record.count, 1, "{context}");
    assert_eq!(
        (record.rip, record.rax, record.rbx, record.r14, record.r15),
        (r.rip, r.rax, r.rbx, r.r14, r.r15),
        "{context}"
    );
}

#[test]
fn a_signal_pending_at_an_rt_sigreturn_timer_event_follows_it() {
    if bounded("a_signal_pending_at_an_rt_sigreturn_timer_event_follows_it") {
        return;
    }
    // The guest of
    // `a_request_due_at_rt_sigreturn_is_delivered_with_the_registers_it_restores`,
    // with SIGUSR1 blocked by the SIGSEGV handler's mask. SIGSEGV's callback
    // sends SIGUSR1 to the thread, which stays pending through the handler,
    // and requests 1 RCB, which comes due at the handler's rt_sigreturn. The
    // mask that call restores unblocks SIGUSR1, which is delivered at its
    // return, after the timer event, with the registers it restores.
    let program = Program::new(&format!(
        "lea 9f(%rip),%r12\nmov $11,%edi\nlea segv_action(%rip),%rsi\nxor %edx,%edx\n\
         mov $8,%r10d\nmov $13,%eax\nsyscall\nmov $10,%edi\nlea usr1_action(%rip),%rsi\n\
         xor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\nsyscall\nmovq 0x10,%rax\n\
         9: mov ${SPINS},%rcx\n1: cmpb $0,flag(%rip)\njne 2f\ndec %rcx\njnz 1b\n2:\n{WRITE_RECORD}\
         segv: addq $8,168(%rdx)\nadd $8,%rsp\nmov $15,%eax\nxor %ecx,%ecx\njz 7f\n7: syscall\nud2\n\
         {}",
        signal_record(
            HANDLER_FLAGS,
            &format!("segv_action: .quad segv, {HANDLER_FLAGS:#x}, restorer, 0x200\n")
        )
    ));
    let plan = Plan {
        requests: vec![],
        rearm_at_signal: Some(1),
        registers: true,
        deliver: true,
        self_signal_at_fault: true,
        ..Plan::default()
    };
    let (events, record) = run_recorded(&program, plan);
    let context = format!("{record:x?} {events:?}");
    let (timer_at, timer_clock) = first_timer(&events);
    let delivered = sigusr1_clocks(&events);
    assert_eq!(delivered.len(), 1, "{context}");
    assert!(delivered[0].0 > timer_at, "{context}");
    assert_eq!(delivered[0].1, timer_clock, "{context}");
    let r = registers_of(&events);
    assert_eq!(r.rip, r.r12, "the timer event at rt_sigreturn: {context}");
    assert_eq!(record.count, 1, "{context}");
    assert_eq!((record.rip, record.rax), (r.rip, r.rax), "{context}");
}

/// The x87, SSE and AVX state a guest of the FPU tests below reads: MXCSR
/// (STMXCSR), the x87 control word (FNSTCW), the x87 status and tag words
/// (FNSTENV, whose instruction and operand pointers are left out), and YMM5,
/// whose low half is XMM5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FpuState {
    mxcsr: u32,
    control: u16,
    status: u16,
    tags: u16,
    ymm5: [u64; 4],
}

impl FpuState {
    /// Linux's initial state, which `handle_signal` gives a handler
    /// (`fpu__clear_user_states`): MXCSR 0x1f80, x87 control word 0x37f, an
    /// empty x87 stack (TOP 0, every register tagged empty) and zero vector
    /// registers.
    const INITIAL: Self = Self {
        mxcsr: 0x1f80,
        control: 0x37f,
        status: 0,
        tags: 0xffff,
        ymm5: [0; 4],
    };

    /// The state [`FPU_LOAD`] leaves, with TOP 6 (bits 11 to 13) and no
    /// other bit of the status word, whose condition codes FLD leaves
    /// undefined.
    const LOADED: Self = Self {
        mxcsr: 0x7f80,
        control: 0x027f,
        status: 6 << 11,
        tags: 0x0fff,
        ymm5: FPU_YMM5,
    };

    /// The block [`fpu_save`] writes at the start of `bytes`.
    fn read(bytes: &[u8]) -> Self {
        let half = |at: usize| u16::from_ne_bytes(bytes[at..at + 2].try_into().unwrap());
        let quad = |at: usize| u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap());
        Self {
            mxcsr: u32::from_ne_bytes(bytes[..4].try_into().unwrap()),
            control: half(8),
            // FNSTENV's 28-byte image: the control, status and tag words
            // each fill four bytes.
            status: half(20),
            tags: half(24),
            ymm5: [quad(48), quad(56), quad(64), quad(72)],
        }
    }
}

/// What a guest of the FPU tests below writes to stdout before it exits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FpuRecord {
    /// The state at the handler's first instruction.
    handler: FpuState,
    /// How many times the handler ran.
    entries: u64,
    /// The interrupted rip in the handler's frame, and the frame's r12, where
    /// the guest keeps the instruction at which the signal should come.
    rip: u64,
    r12: u64,
    /// The state after the handler returned.
    after: FpuState,
    /// ST0 and ST1 after the handler returned, as FSTP m80 stores them.
    stack: [[u8; 10]; 2],
}

impl FpuRecord {
    fn read(stdout: &[u8]) -> Self {
        assert_eq!(stdout.len(), FPU_RECORD_SIZE, "{stdout:?}");
        let quad = |at: usize| u64::from_ne_bytes(stdout[at..at + 8].try_into().unwrap());
        Self {
            handler: FpuState::read(&stdout[..80]),
            entries: quad(80),
            rip: quad(88),
            r12: quad(96),
            after: FpuState::read(&stdout[104..184]),
            stack: [
                stdout[184..194].try_into().unwrap(),
                stdout[200..210].try_into().unwrap(),
            ],
        }
    }

    /// Everything but the frame's rip and r12, which tell where the signal
    /// came: natively, a sibling's signal comes wherever the guest then is.
    fn fpu(&self) -> (FpuState, u64, FpuState, [[u8; 10]; 2]) {
        (self.handler, self.entries, self.after, self.stack)
    }
}

const FPU_RECORD_SIZE: usize = 216;

/// MXCSR 0x7f80 (round toward zero), x87 control word 0x027f (double
/// precision), 1.5 and then -3.25 on the x87 stack, and a nonzero YMM5: the
/// interrupted state, which a handler must not see and which must be intact
/// after it returns.
const FPU_LOAD: &str = "ldmxcsr fpu_mxcsr(%rip)\nfldcw fpu_control(%rip)\nfldt fpu_first(%rip)\n\
     fldt fpu_second(%rip)\nvmovdqu fpu_ymm5(%rip),%ymm5\n";

/// The bytes of -3.25 and 1.5 as FSTP m80 stores them: ST0 and ST1 after
/// [`FPU_LOAD`].
const FPU_STACK: [[u8; 10]; 2] = [
    [0, 0, 0, 0, 0, 0, 0, 0xd0, 0x00, 0xc0],
    [0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0x3f],
];

const FPU_YMM5: [u64; 4] = [
    0x1111_1111_1111_1111,
    0x2222_2222_2222_2222,
    0x3333_3333_3333_3333,
    0x4444_4444_4444_4444,
];

/// Saves an [`FpuState`] at `offset` in `fpu_record`.
fn fpu_save(offset: usize) -> String {
    format!(
        "stmxcsr fpu_record+{offset}(%rip)\nfnstcw fpu_record+{}(%rip)\n\
         fnstenv fpu_record+{}(%rip)\nvmovdqu %ymm5,fpu_record+{}(%rip)\n",
        offset + 8,
        offset + 16,
        offset + 48
    )
}

/// After the handler returned: saves the state, pops ST0 and ST1 into the
/// record, writes the record and exits with status 0.
fn fpu_after() -> String {
    format!(
        "{}fstpt fpu_record+184(%rip)\nfstpt fpu_record+200(%rip)\n\
         mov $1,%edi\nlea fpu_record(%rip),%rsi\nmov ${FPU_RECORD_SIZE},%edx\nmov $1,%eax\nsyscall\n\
         xor %edi,%edi\nmov $231,%eax\nsyscall\nud2\n",
        fpu_save(104)
    )
}

/// Installs the handler of [`fpu_handler`] for `signal`, with the sigaction
/// record `action`.
fn fpu_install(signal: i32, action: &str) -> String {
    format!(
        "mov ${signal},%edi\nlea {action}(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\nsyscall\n"
    )
}

/// The handler, its restorer and the data. The handler saves the state it
/// starts with, counts its entries, keeps its frame's rip and r12, runs
/// `extra` and sets `flag`; `action` names its sigaction record. The data
/// includes what [`SIBLING`] uses.
fn fpu_handler(action: &str, extra: &str) -> String {
    fpu_handler_loading(action, extra, 0x7f80)
}

/// [`fpu_handler`], with [`FPU_LOAD`] loading `mxcsr` as MXCSR.
fn fpu_handler_loading(action: &str, extra: &str, mxcsr: u32) -> String {
    format!(
        "fpu_handler:\n{}incq fpu_record+80(%rip)\nmov 168(%rdx),%rax\nmov %rax,fpu_record+88(%rip)\n\
         mov 72(%rdx),%rax\nmov %rax,fpu_record+96(%rip)\n{extra}movb $1,flag(%rip)\nret\n\
         restorer: mov $15,%eax\nsyscall\nud2\n\
         .data\n.balign 8\n{action}: .quad fpu_handler, {HANDLER_FLAGS:#x}, restorer, 0\n\
         pid: .quad 0\ntid: .quad 0\nflag: .byte 0\n\
         fpu_mxcsr: .long {mxcsr:#x}\nfpu_control: .short 0x027f\n\
         .balign 16\nfpu_first: .quad 0xc000000000000000\n.short 0x3fff\n\
         .balign 16\nfpu_second: .quad 0xd000000000000000\n.short 0xc000\n\
         .balign 32\nfpu_ymm5: .quad {:#x}, {:#x}, {:#x}, {:#x}\n\
         .balign 64\nfpu_record: .zero {FPU_RECORD_SIZE}\n\
         .bss\n.balign 16\nstack: .skip 65536\nstack_end:\n",
        fpu_save(0),
        FPU_YMM5[0],
        FPU_YMM5[1],
        FPU_YMM5[2],
        FPU_YMM5[3],
    )
}

/// Checks a record of a guest that loaded [`FPU_LOAD`] and then took one
/// signal: its handler started in Linux's initial state, and the interrupted
/// code found its own state again after the handler returned.
fn check_fpu_record(record: &FpuRecord, context: &str) {
    check_loaded_fpu_record(record, context, 0x7f80);
}

/// [`check_fpu_record`], where the interrupted code finds MXCSR `mxcsr`
/// after the handler returned.
fn check_loaded_fpu_record(record: &FpuRecord, context: &str, mxcsr: u32) {
    let context = format!("{context}: {record:x?}");
    assert_eq!(record.entries, 1, "{context}");
    assert_eq!(record.handler, FpuState::INITIAL, "{context}");
    let after = FpuState {
        status: record.after.status & 7 << 11,
        ..record.after
    };
    let loaded = FpuState {
        mxcsr,
        ..FpuState::LOADED
    };
    assert_eq!(after, loaded, "{context}");
    assert_eq!(record.stack, FPU_STACK, "{context}");
}

/// Runs `program` natively, the Linux reference, checks that it exits with
/// status 0 and writes nothing to stderr, and returns its stdout.
fn native_stdout(program: &Program) -> Vec<u8> {
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "30s"])
        .arg(&program.executable)
        .current_dir(&program.directory)
        .output()
        .unwrap();
    assert!(
        output.status.success() && output.stderr.is_empty(),
        "native: {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Runs `program` natively and returns its record.
fn native_fpu_record(program: &Program) -> FpuRecord {
    FpuRecord::read(&native_stdout(program))
}

/// Runs `program` under the backend's own runtime, with no Tool, checks that
/// it exits with status 0 and writes nothing to stderr, and returns its
/// stdout.
fn direct_stdout(program: &Program) -> Vec<u8> {
    let mut backend = KvmBackend::new(program.memory).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(&program.executable).unwrap(),
            &[program.executable.to_str().unwrap()],
            &[],
            &program.directory,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!((code, stderr), (0, vec![]));
    stdout
}

/// Runs `program` under the backend's own runtime and returns its record.
fn direct_fpu_record(program: &Program) -> FpuRecord {
    FpuRecord::read(&direct_stdout(program))
}

/// Runs `program` under a [`TimerTool`] following `plan`, checks that it
/// exits with status 0 and writes nothing to stderr, and returns the Tool's
/// events and its stdout.
fn tool_stdout(program: &Program, plan: Plan) -> (Vec<Event>, Vec<u8>) {
    let (events, ending) = run_ending(program, plan);
    let (code, stdout, stderr) = ending.unwrap_or_else(|failure| panic!("{failure}: {events:?}"));
    assert_eq!((code, stderr), (0, vec![]), "{events:?}");
    (events, stdout)
}

/// Runs `program` under a [`TimerTool`] following `plan` and returns the
/// Tool's events and the record.
fn tool_fpu_record(program: &Program, plan: Plan) -> (Vec<Event>, FpuRecord) {
    let (events, stdout) = tool_stdout(program, plan);
    (events, FpuRecord::read(&stdout))
}

/// The stdout of `program` under the backend's own runtime and under a Tool
/// that delivers every signal.
fn kvm_stdouts(program: &Program) -> [(&'static str, Vec<u8>); 2] {
    let plan = Plan {
        deliver: true,
        ..Plan::default()
    };
    [
        ("runtime", direct_stdout(program)),
        ("tool", tool_stdout(program, plan).1),
    ]
}

/// Checks a guest whose signal comes at the instruction it marks in r12, in
/// every run: natively, under the backend's runtime and under a Tool. Each
/// run's handler starts in Linux's initial FPU state, the interrupted code's
/// state is intact after it, and KVM's records equal the native one.
fn fpu_state_matches_native_at_mark(program: &Program) {
    fpu_matches_native_at_mark(program, check_fpu_record);
}

/// [`fpu_state_matches_native_at_mark`], with `check` for each record.
fn fpu_matches_native_at_mark(program: &Program, check: impl Fn(&FpuRecord, &str)) {
    let native = native_fpu_record(program);
    check(&native, "native");
    assert_eq!(native.rip, native.r12, "native: {native:x?}");
    let plan = Plan {
        deliver: true,
        ..Plan::default()
    };
    for (name, record) in [
        ("runtime", direct_fpu_record(program)),
        ("tool", tool_fpu_record(program, plan).1),
    ] {
        check(&record, name);
        assert_eq!(record.rip, record.r12, "{name}: {record:x?}");
        assert_eq!(
            record.fpu(),
            native.fpu(),
            "{name} {record:x?}, native {native:x?}"
        );
    }
}

#[test]
fn a_handler_at_a_syscall_return_starts_with_linuxs_initial_fpu_state() {
    if bounded("a_handler_at_a_syscall_return_starts_with_linuxs_initial_fpu_state") {
        return;
    }
    // The guest loads its FPU state and sends SIGUSR1 to itself with tgkill,
    // which is delivered at that call's return.
    let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", ""));
    fpu_state_matches_native_at_mark(&program);
}

/// A guest that runs `load` and sends SIGUSR1 to itself with tgkill, marking
/// that call's return in r12, and installs `handler` (an [`fpu_handler`])
/// for it.
fn fpu_at_syscall_return(load: &str, handler: &str) -> Program {
    Program::new(&format!(
        "{}mov $39,%eax\nsyscall\nmov %rax,pid(%rip)\nmov $186,%eax\nsyscall\nmov %rax,tid(%rip)\n\
         {load}mov pid(%rip),%rdi\nmov tid(%rip),%rsi\nmov $10,%edx\nlea 1f(%rip),%r12\n\
         mov $234,%eax\nsyscall\n1:\n{}{handler}",
        fpu_install(libc::SIGUSR1, "usr1_action"),
        fpu_after(),
    ))
}

#[test]
fn a_handler_at_a_user_trap_starts_with_linuxs_initial_fpu_state() {
    if bounded("a_handler_at_a_user_trap_starts_with_linuxs_initial_fpu_state") {
        return;
    }
    // The guest loads its FPU state and runs a ud2, whose SIGILL handler
    // steps over it.
    let program = Program::new(&format!(
        "{}{FPU_LOAD}lea 1f(%rip),%r12\n1: ud2\n{}{}",
        fpu_install(libc::SIGILL, "ill_action"),
        fpu_after(),
        fpu_handler("ill_action", "addq $2,168(%rdx)\n")
    ));
    fpu_state_matches_native_at_mark(&program);
}

#[test]
fn a_handler_at_a_timer_boundary_starts_with_linuxs_initial_fpu_state() {
    if bounded("a_handler_at_a_timer_boundary_starts_with_linuxs_initial_fpu_state") {
        return;
    }
    // The spinner of `a_spinner_signalled_by_a_sibling_gets_its_handler_at_the_next_timer_boundary`,
    // which loads its FPU state before it starts the sibling and spins until
    // its handler has run. Natively, the sibling's SIGUSR1 comes wherever
    // the guest then is; under the Tool, at the timer boundary at the loop's
    // head.
    let program = Program::new(&format!(
        "{FPU_LOAD}{SIBLING}{GETPPID}lea 1f(%rip),%r12\nmov $2000000000,%rcx\n\
         1: cmpb $0,flag(%rip)\njne 2f\ndec %rcx\njnz 1b\n2:\n{}{}",
        fpu_after(),
        fpu_handler("usr1_action", "")
    ));
    let native = native_fpu_record(&program);
    check_fpu_record(&native, "native");
    for _ in 0..REPEATS {
        let (events, record) = tool_fpu_record(&program, spinner_plan());
        let context = format!("{record:x?} {events:?}");
        let (timer_at, timer_clock) = first_timer(&events);
        let delivered = sigusr1_clocks(&events);
        assert_eq!(delivered.len(), 1, "{context}");
        assert!(delivered[0].0 > timer_at, "{context}");
        assert_eq!(delivered[0].1, timer_clock, "{context}");
        let r = registers_of(&events);
        assert_eq!((record.rip, record.r12), (r.rip, r.rip), "{context}");
        check_fpu_record(&record, "tool");
        assert_eq!(record.fpu(), native.fpu(), "{context}, native {native:x?}");
    }
}

/// The MXCSR_MASK field of an FXSAVE image taken on this CPU, which Linux
/// writes into every signal frame.
fn cpu_mxcsr_mask() -> u32 {
    #[repr(C, align(16))]
    struct FxsaveArea([u8; 512]);
    let mut area = FxsaveArea([0; 512]);
    // SAFETY: FXSAVE writes exactly this 512-byte, 16-byte-aligned area.
    unsafe { std::arch::x86_64::_fxsave64(area.0.as_mut_ptr()) };
    u32::from_ne_bytes(area.0[28..32].try_into().unwrap())
}

/// DAZ, MXCSR bit 6: denormal operands are read as zero.
const DAZ: u32 = 1 << 6;

#[test]
fn an_interrupted_mxcsr_with_daz_survives_a_signal_handler() {
    if bounded("an_interrupted_mxcsr_with_daz_survives_a_signal_handler") {
        return;
    }
    assert_ne!(cpu_mxcsr_mask() & DAZ, 0, "this CPU has no DAZ");
    // The guest loads MXCSR 0x1fc0, with DAZ, as -ffast-math startup code
    // does; Linux saves it in the frame and restores it at rt_sigreturn.
    let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler_loading("usr1_action", "", 0x1fc0));
    fpu_matches_native_at_mark(&program, |record, context| {
        check_loaded_fpu_record(record, context, 0x1fc0)
    });
}

#[test]
fn a_handler_may_set_daz_in_its_frames_mxcsr() {
    if bounded("a_handler_may_set_daz_in_its_frames_mxcsr") {
        return;
    }
    assert_ne!(cpu_mxcsr_mask() & DAZ, 0, "this CPU has no DAZ");
    // The handler writes MXCSR 0x5fc0 (DAZ, rounding up) into its frame, and
    // the interrupted code resumes with it.
    let edit = "mov 224(%rdx),%rax\nmovl $0x5fc0,24(%rax)\n";
    let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", edit));
    fpu_matches_native_at_mark(&program, |record, context| {
        check_loaded_fpu_record(record, context, 0x5fc0)
    });
}

/// A C program built with -ffast-math, whose startup code sets DAZ and FTZ,
/// that takes a signal and returns from its handler.
const FAST_MATH_GUEST: &str = r#"#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>

static volatile sig_atomic_t entries;
static volatile unsigned int handler_mxcsr;

static void handler(int signal) {
  (void)signal;
  handler_mxcsr = _mm_getcsr();
  entries++;
}

int main(void) {
  struct sigaction action;
  memset(&action, 0, sizeof action);
  action.sa_handler = handler;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGUSR1, &action, NULL) != 0)
    return 1;
  unsigned int before = _mm_getcsr();
  if (raise(SIGUSR1) != 0)
    return 2;
  unsigned int after = _mm_getcsr();
  volatile float tiny = 1e-40f;
  volatile float sum = tiny + 0.0f;
  printf("mxcsr %#x before, %#x in the handler, %#x after; %d handler entries; subnormal + 0 is %s\n",
         before, handler_mxcsr, after, (int)entries, sum == 0.0f ? "zero" : "subnormal");
  return 0;
}
"#;

#[test]
fn a_fast_math_program_returns_from_a_signal_handler() {
    if bounded("a_fast_math_program_returns_from_a_signal_handler") {
        return;
    }
    let program = Program::c(FAST_MATH_GUEST, &["-ffast-math"]);
    let native = native_stdout(&program);
    assert_eq!(
        String::from_utf8_lossy(&native),
        "mxcsr 0x9fc0 before, 0x1f80 in the handler, 0x9fc0 after; 1 handler entries; \
         subnormal + 0 is zero\n",
        "native"
    );
    for (name, stdout) in kvm_stdouts(&program) {
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&native),
            "{name}"
        );
    }
}

#[test]
fn a_handlers_edits_to_fpu_state_the_interrupted_code_never_used_take_effect() {
    if bounded("a_handlers_edits_to_fpu_state_the_interrupted_code_never_used_take_effect") {
        return;
    }
    // The guest uses no x87, SSE or AVX instruction before its signal, so
    // that state is initial. Its handler sets the frame's x87 control word to
    // 0x027f, MXCSR to 0x5f80 and XMM5 to a pattern; Linux marks x87 and SSE
    // present in every frame, so rt_sigreturn applies the three edits.
    let edit = "mov 224(%rdx),%rax\nmovw $0x027f,(%rax)\nmovl $0x5f80,24(%rax)\n\
                movabs $0x5555555555555555,%rcx\nmov %rcx,240(%rax)\nmov %rcx,248(%rax)\n";
    let program = fpu_at_syscall_return("", &fpu_handler("usr1_action", edit));
    fpu_matches_native_at_mark(&program, |record, context| {
        let context = format!("{context}: {record:x?}");
        assert_eq!(record.entries, 1, "{context}");
        assert_eq!(record.handler, FpuState::INITIAL, "{context}");
        let pattern = 0x5555_5555_5555_5555;
        assert_eq!(
            (record.after.control, record.after.mxcsr, record.after.ymm5),
            (0x027f, 0x5f80, [pattern, pattern, 0, 0]),
            "{context}"
        );
    });
}

#[test]
fn rt_sigreturn_takes_mxcsr_from_a_frame_whose_header_leaves_sse_initial() {
    if bounded("rt_sigreturn_takes_mxcsr_from_a_frame_whose_header_leaves_sse_initial") {
        return;
    }
    // The handler sets its frame's MXCSR to 0x5f80 and clears the SSE and YMM
    // bits of its XSTATE_BV, keeping the x87 bit or clearing it too. Linux's
    // XRSTOR then zeroes XMM5 and YMM5 but still loads MXCSR from the frame.
    for header in [1, 0] {
        let edit = format!("mov 224(%rdx),%rax\nmovl $0x5f80,24(%rax)\nmovq ${header},512(%rax)\n");
        let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", &edit));
        fpu_matches_native_at_mark(&program, |record, context| {
            let context = format!("{context}, XSTATE_BV {header}: {record:x?}");
            assert_eq!(record.entries, 1, "{context}");
            assert_eq!(
                (record.after.mxcsr, record.after.ymm5),
                (0x5f80, [0; 4]),
                "{context}"
            );
        });
    }
}

/// Runs `program` natively, with no core dump, and returns how it ended.
fn native_output(program: &Program) -> std::process::Output {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new("timeout");
    command
        .args(["--kill-after=2s", "30s"])
        .arg(&program.executable)
        .current_dir(&program.directory);
    // SAFETY: setrlimit is async-signal-safe and touches no memory the
    // parent shares.
    unsafe {
        command.pre_exec(|| {
            // A core_pattern that pipes core dumps to a program ignores
            // RLIMIT_CORE except for the value 1, with which the kernel
            // skips the dump.
            let one = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            match libc::setrlimit(libc::RLIMIT_CORE, &one) {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error()),
            }
        });
    }
    command.output().unwrap()
}

/// Checks that `program` ends with SIGSEGV and writes nothing, natively,
/// under the backend's own runtime and under a Tool that delivers every
/// signal.
fn segfaults_natively_and_on_kvm(program: &Program) {
    use std::os::unix::process::ExitStatusExt;
    let output = native_output(program);
    // timeout ends itself with the signal that ended its child.
    assert_eq!(
        (output.status.signal(), output.stdout, output.stderr),
        (Some(libc::SIGSEGV), vec![], vec![]),
        "native: {}",
        output.status
    );
    let mut backend = KvmBackend::new(program.memory).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(&program.executable).unwrap(),
            &[program.executable.to_str().unwrap()],
            &[],
            &program.directory,
        )
        .unwrap();
    assert_eq!(
        backend.run_static_elf_captured().unwrap(),
        (128 + libc::SIGSEGV, vec![], vec![]),
        "runtime"
    );
    let plan = Plan {
        deliver: true,
        ..Plan::default()
    };
    let (events, ending) = run_ending(program, plan);
    assert_eq!(
        ending,
        Ok((128 + libc::SIGSEGV, vec![], vec![])),
        "tool: {events:?}"
    );
}

#[test]
fn rt_sigreturn_ignores_mxcsr_where_linux_does_not_load_it() {
    if bounded("rt_sigreturn_ignores_mxcsr_where_linux_does_not_load_it") {
        return;
    }
    // The handler sets a reserved MXCSR bit in its frame, and the frame's
    // software xfeatures and XSTATE_BV to x87 alone or to nothing. XRSTOR
    // loads, and so checks, MXCSR only for requested SSE or YMM state, and
    // Linux initializes SSE and YMM state afterwards: MXCSR 0x1f80 and zero
    // YMM5. x87 state comes from the frame when it is requested, and is
    // initialized otherwise, which leaves FSTP an empty stack to store.
    for bit in [16, 31] {
        let reserved = 1u32 << bit;
        for features in [1, 0] {
            let edit = format!(
                "mov 224(%rdx),%rax\norl ${reserved:#x},24(%rax)\nmovq ${features},472(%rax)\n\
                 movq ${features},512(%rax)\n"
            );
            let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", &edit));
            fpu_matches_native_at_mark(&program, |record, context| {
                let context =
                    format!("{context}, MXCSR bit {bit}, features {features}: {record:x?}");
                assert_eq!(record.entries, 1, "{context}");
                assert_eq!(record.handler, FpuState::INITIAL, "{context}");
                assert_eq!(
                    (record.after.mxcsr, record.after.ymm5),
                    (0x1f80, [0; 4]),
                    "{context}"
                );
                if features == 1 {
                    assert_eq!(
                        (record.after.control, record.after.tags, record.stack),
                        (0x027f, FpuState::LOADED.tags, FPU_STACK),
                        "{context}"
                    );
                } else {
                    assert_eq!(
                        (record.after.control, record.after.status, record.after.tags),
                        (0x037f, 0, 0xffff),
                        "{context}"
                    );
                }
            });
        }
        // With SSE requested, as in the frame as built, the bit faults.
        let edit = format!("mov 224(%rdx),%rax\norl ${reserved:#x},24(%rax)\n");
        let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", &edit));
        segfaults_natively_and_on_kvm(&program);
    }
}

#[test]
fn rt_sigreturn_initializes_ymm_state_the_frames_features_leave_out() {
    if bounded("rt_sigreturn_initializes_ymm_state_the_frames_features_leave_out") {
        return;
    }
    // The handler sets its frame's software xfeatures to x87 and SSE,
    // leaving XSTATE_BV marking YMM present. XRSTOR ignores that bit, and
    // Linux initializes YMM state afterwards: YMM5's upper half is zero,
    // and the rest comes from the frame, MXCSR 0x7f80 included where the
    // host's format keeps it.
    let edit = "mov 224(%rdx),%rax\nmovq $3,472(%rax)\n";
    let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", edit));
    fpu_matches_native_but_mxcsr_at_mark(&program, 0x7f80, |record, context| {
        let context = format!("{context}: {record:x?}");
        assert_eq!(record.entries, 1, "{context}");
        assert_eq!(
            (record.after.control, record.stack),
            (0x027f, FPU_STACK),
            "{context}"
        );
        assert_eq!(
            record.after.ymm5,
            [FPU_YMM5[0], FPU_YMM5[1], 0, 0],
            "{context}"
        );
    });
}

#[test]
fn rt_sigreturn_restores_a_frame_without_magic2_as_legacy_state() {
    if bounded("rt_sigreturn_restores_a_frame_without_magic2_as_legacy_state") {
        return;
    }
    // The handler sets its frame's MXCSR to 0x5f80 and XMM5 to a pattern,
    // and clears FP_XSTATE_MAGIC2 after the frame's xstate_size bytes.
    // Linux then restores the frame's legacy FXSAVE image, the edits
    // included (MXCSR where the host's format keeps it), and initializes
    // YMM state.
    let edit = "mov 224(%rdx),%rax\nmovl $0x5f80,24(%rax)\nmovabs $0x5555555555555555,%rcx\n\
                mov %rcx,240(%rax)\nmov %rcx,248(%rax)\nmov 480(%rax),%ecx\nmovl $0,(%rax,%rcx)\n";
    let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", edit));
    fpu_matches_native_but_mxcsr_at_mark(&program, 0x5f80, |record, context| {
        let context = format!("{context}: {record:x?}");
        assert_eq!(record.entries, 1, "{context}");
        let pattern = 0x5555_5555_5555_5555;
        assert_eq!(
            (record.after.control, record.stack),
            (0x027f, FPU_STACK),
            "{context}"
        );
        assert_eq!(record.after.ymm5, [pattern, pattern, 0, 0], "{context}");
    });
}

/// Whether this host's Linux keeps FPU state in the compacted format, as it
/// does when it uses XSAVEC or XSAVES (`fpu__init_system_xstate`); the
/// kernel lists the features it uses in /proc/cpuinfo.
fn linux_uses_compacted_xstate() -> bool {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap();
    let flags = cpuinfo
        .lines()
        .find(|line| line.starts_with("flags"))
        .expect("a flags line in /proc/cpuinfo");
    flags
        .split_whitespace()
        .any(|flag| flag == "xsavec" || flag == "xsaves")
}

/// [`fpu_matches_native_at_mark`] for a frame whose features include SSE but
/// not YMM, or that Linux restores as a legacy FXSAVE image. Linux then
/// initializes YMM state with an XRSTOR of its initial state, which on a
/// host whose kernel keeps FPU state in the standard format also loads that
/// state's MXCSR, 0x1f80; with the compacted format MXCSR stays `restored`,
/// the frame's. So natively MXCSR must be Linux's answer for this host;
/// under KVM it must be `restored`, the backend's answer on every host; and
/// every other field must equal the native one.
fn fpu_matches_native_but_mxcsr_at_mark(
    program: &Program,
    restored: u32,
    check: impl Fn(&FpuRecord, &str),
) {
    let native = native_fpu_record(program);
    let native_mxcsr = if linux_uses_compacted_xstate() {
        restored
    } else {
        0x1f80
    };
    assert_eq!(native.after.mxcsr, native_mxcsr, "native: {native:x?}");
    check(&native, "native");
    assert_eq!(native.rip, native.r12, "native: {native:x?}");
    // Everything but the MXCSR the guest finds after the return.
    let rest = |record: &FpuRecord| {
        let mut fpu = record.fpu();
        fpu.2.mxcsr = 0;
        fpu
    };
    let plan = Plan {
        deliver: true,
        ..Plan::default()
    };
    for (name, record) in [
        ("runtime", direct_fpu_record(program)),
        ("tool", tool_fpu_record(program, plan).1),
    ] {
        assert_eq!(record.after.mxcsr, restored, "{name}: {record:x?}");
        check(&record, name);
        assert_eq!(record.rip, record.r12, "{name}: {record:x?}");
        assert_eq!(
            rest(&record),
            rest(&native),
            "{name} {record:x?}, native {native:x?}"
        );
    }
}

#[test]
fn rt_sigreturn_ignores_the_software_reserved_padding() {
    if bounded("rt_sigreturn_ignores_the_software_reserved_padding") {
        return;
    }
    // The handler sets its frame's MXCSR to 0x5f80 and a padding byte of
    // the software-reserved bytes, which Linux never reads.
    let edit = "mov 224(%rdx),%rax\nmovl $0x5f80,24(%rax)\nmovb $0xa5,490(%rax)\n";
    let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", edit));
    fpu_matches_native_at_mark(&program, |record, context| {
        check_loaded_fpu_record(record, context, 0x5f80)
    });
}

/// What the guest of
/// `a_frame_after_a_null_fpregs_return_carries_the_cpus_mxcsr_mask` writes:
/// how many times each handler ran; the MXCSR_MASK and MXCSR in SIGUSR2's
/// frame; MXCSR as SIGUSR2's handler starts; the bits of a subnormal plus
/// zero there, computed with DAZ when that frame's mask offers it; the
/// frame's rip and r12; MXCSR once both handlers have returned; the frame's
/// XSTATE_BV; and YMM5 once both handlers have returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QueuedRecord {
    first_entries: u64,
    second_entries: u64,
    frame_mask: u32,
    frame_mxcsr: u32,
    handler_mxcsr: u32,
    sum: u32,
    rip: u64,
    r12: u64,
    after_mxcsr: u32,
    frame_xstate_bv: u64,
    after_ymm5: [u64; 4],
}

impl QueuedRecord {
    fn read(stdout: &[u8]) -> Self {
        assert_eq!(stdout.len(), 112, "{stdout:?}");
        let quad = |i: usize| u64::from_ne_bytes(stdout[8 * i..8 * i + 8].try_into().unwrap());
        Self {
            first_entries: quad(0),
            second_entries: quad(1),
            frame_mask: quad(2) as u32,
            frame_mxcsr: quad(3) as u32,
            handler_mxcsr: quad(4) as u32,
            sum: quad(5) as u32,
            rip: quad(6),
            r12: quad(7),
            after_mxcsr: quad(8) as u32,
            frame_xstate_bv: quad(9),
            after_ymm5: [quad(10), quad(11), quad(12), quad(13)],
        }
    }

    /// The record without what may differ from the native one: the frame's
    /// rip and r12, and its XSTATE_BV bit for PKRU, which the guest lacks.
    fn comparable(self) -> Self {
        const PKRU: u64 = 1 << 9;
        Self {
            rip: 0,
            r12: 0,
            frame_xstate_bv: self.frame_xstate_bv & !PKRU,
            ..self
        }
    }
}

#[test]
fn a_frame_after_a_null_fpregs_return_carries_the_cpus_mxcsr_mask() {
    if bounded("a_frame_after_a_null_fpregs_return_carries_the_cpus_mxcsr_mask") {
        return;
    }
    // The guest loads MXCSR 0x7f80 and a nonzero YMM5 and sends itself
    // SIGUSR1, whose handler blocks SIGUSR2 (its sa_mask), sends it, sets
    // uc_mcontext.fpregs to NULL and returns. rt_sigreturn installs the
    // initial FPU state and unblocks SIGUSR2, which is delivered at once, at
    // the same return; its frame records that state with the CPU's
    // MXCSR_MASK, and with x87 and SSE state present and YMM state absent.
    // Its handler sets DAZ when that mask offers it, as a program probing
    // for DAZ does, and adds zero to a subnormal; it also writes the upper
    // half of YMM5 in its frame without marking YMM present, an edit
    // rt_sigreturn ignores.
    let program = Program::new(
        "mov $10,%edi\nlea usr1_action(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\nsyscall\n\
         mov $12,%edi\nlea usr2_action(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\nsyscall\n\
         mov $39,%eax\nsyscall\nmov %rax,pid(%rip)\nmov $186,%eax\nsyscall\nmov %rax,tid(%rip)\n\
         ldmxcsr loaded(%rip)\nvmovdqu loaded_ymm5(%rip),%ymm5\n\
         mov pid(%rip),%rdi\nmov tid(%rip),%rsi\nmov $10,%edx\nlea 1f(%rip),%r12\n\
         mov $234,%eax\nsyscall\n1: stmxcsr rec+64(%rip)\nvmovdqu %ymm5,rec+80(%rip)\n\
         mov $1,%edi\nlea rec(%rip),%rsi\nmov $112,%edx\nmov $1,%eax\nsyscall\n\
         xor %edi,%edi\nmov $231,%eax\nsyscall\nud2\n\
         first: mov %rdx,%r9\nmov pid(%rip),%rdi\nmov tid(%rip),%rsi\nmov $12,%edx\nmov $234,%eax\nsyscall\n\
         movq $0,224(%r9)\nincq rec(%rip)\nret\n\
         second: mov 224(%rdx),%r8\nmov 28(%r8),%eax\nmov %rax,rec+16(%rip)\n\
         mov 24(%r8),%eax\nmov %rax,rec+24(%rip)\nstmxcsr rec+32(%rip)\n\
         mov 168(%rdx),%rax\nmov %rax,rec+48(%rip)\nmov 72(%rdx),%rax\nmov %rax,rec+56(%rip)\n\
         mov 512(%r8),%rax\nmov %rax,rec+72(%rip)\n\
         movabs $0x6666666666666666,%rax\nmov %rax,656(%r8)\nmov %rax,664(%r8)\n\
         testl $0x40,28(%r8)\njz 2f\nldmxcsr daz(%rip)\n\
         2: movss subnormal(%rip),%xmm0\naddss zero(%rip),%xmm0\nmovd %xmm0,%eax\nmov %rax,rec+40(%rip)\n\
         incq rec+8(%rip)\nret\n\
         restorer: mov $15,%eax\nsyscall\nud2\n\
         .data\n.balign 8\nusr1_action: .quad first, 0x4000004, restorer, 0x800\n\
         usr2_action: .quad second, 0x4000004, restorer, 0\npid: .quad 0\ntid: .quad 0\n\
         loaded: .long 0x7f80\ndaz: .long 0x1fc0\nsubnormal: .long 1\nzero: .long 0\n\
         .balign 32\nloaded_ymm5: .quad 0x1111111111111111, 0x2222222222222222, \
         0x3333333333333333, 0x4444444444444444\n\
         .balign 8\nrec: .zero 112\n",
    );
    let native = QueuedRecord::read(&native_stdout(&program));
    let mask = cpu_mxcsr_mask();
    let expected = QueuedRecord {
        first_entries: 1,
        second_entries: 1,
        frame_mask: mask,
        frame_mxcsr: 0x1f80,
        handler_mxcsr: 0x1f80,
        sum: if mask & DAZ != 0 { 0 } else { 1 },
        after_mxcsr: 0x1f80,
        after_ymm5: [0; 4],
        ..native
    };
    assert_eq!(native, expected, "native");
    assert_eq!(native.rip, native.r12, "native: {native:x?}");
    assert_eq!(
        native.comparable().frame_xstate_bv,
        0b011,
        "native: {native:x?}"
    );
    for (name, stdout) in kvm_stdouts(&program) {
        let record = QueuedRecord::read(&stdout);
        assert_eq!(record.rip, record.r12, "{name}: {record:x?}");
        assert_eq!(
            record.comparable(),
            native.comparable(),
            "{name}: {record:x?}, native {native:x?}"
        );
    }
}
