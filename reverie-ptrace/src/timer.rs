/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Timers monitor a specified thread using the PMU and deliver a signal
//! after a specified number of events occur. The signal is then identified
//! and transformed into a reverie timer event. This is intended to allow
//! tools to break busywaits or other spins in a reliable manner. Timers
//! are ideally deterministic so that `detcore` can use them.
//!
//! Due to PMU skid, precise timer events must be driven to completion via
//! single stepping. This means the PMI is scheduled early, and events with very
//! short timeouts require immediate single stepping. Immediate stepping is
//! acheived by artificially generating a signal that will then be delivered
//! immediately upon resumption of the guest.
//!
//! Proper use of timers requires that all delivered signals of type
//! `Timer::signal_type()` be passed through `Timer::handle_signal`, and that
//! `Timer::observe_event()` be called whenever a Tool-observable reverie event
//! occurs. Additionally, `Timer::finalize_requests()` must be called
//!  - after the end of the tool callback in which the user could have
//!    requested a timer event, i.e. those with `&mut guest` access.
//!  - after any reverie-critical single-stepping occurs (e.g. in syscall
//!    injections),
//!  - before resumption of the guest,
//! which _usually_ means immediately after the tool callback returns.

use std::cmp::Ordering::Equal;
use std::cmp::Ordering::Greater;
use std::cmp::Ordering::Less;

use reverie::Errno;
use reverie::Pid;
use reverie::RegDisplay;
use reverie::RegDisplayOptions;
use reverie::Signal;
use reverie::Tid;
use safeptrace::Error as TraceError;
use safeptrace::Event as TraceEvent;
use safeptrace::Stopped;
use safeptrace::Wait;
use thiserror::Error;
use tracing::debug;
use tracing::trace;
use tracing::warn;

use crate::perf::*;

// This signal is unused, in that the kernel will never send it to a process.
const MARKER_SIGNAL: Signal = reverie::PERF_EVENT_SIGNAL;

#[cfg(target_arch = "x86_64")]
pub(crate) fn get_rcb_perf_config() -> u64 {
    let c = raw_cpuid::CpuId::new();
    let fi = c.get_feature_info().unwrap();
    // based on rr's PerfCounters_x86.h and PerfCounters.cc
    match (fi.family_id(), fi.model_id()) {
        (0x06, 0x1A) | (0x06, 0x1E) | (0x06, 0x2E) => 0x5101c4, // Intel Nehalem
        (0x06, 0x25) | (0x06, 0x2C) | (0x06, 0x2F) => 0x5101c4, // Intel Westmere
        (0x06, 0x2A) | (0x06, 0x2D) | (0x06, 0x3E) => 0x5101c4, // Intel SanyBridge
        (0x06, 0x3A) => 0x5101c4,                               // Intel IvyBridge
        (0x06, 0x3C) | (0x06, 0x3F) | (0x06, 0x45) | (0x06, 0x46) => 0x5101c4, // Intel Haswell
        (0x06, 0x3D) | (0x06, 0x47) | (0x06, 0x4F) | (0x06, 0x56) => 0x5101c4, // Intel Broadwell
        (0x06, 0x4E) | (0x06, 0x55) | (0x06, 0x5E) => 0x5101c4, // Intel Skylake
        (0x06, 0x8E) | (0x06, 0x9E) => 0x5101c4,                // Intel Kabylake
        (0x06, 0xA5) | (0x06, 0xA6) => 0x5101c4,                // Intel Cometlake
        (0x06, 0x8D) => 0x5101c4, // Intel Alder Lake (e.g. i7-11800H laptop)
        (0x06, 0x8F) => 0x5101c4, // Intel Sapphire Rapids
        (0x06, 0x86) => 0x5101c4, // Intel Icelake
        (0x17, 0x8) => 0x5100d1,  // AMD Zen, Pinnacle Ridge
        (0x17, 0x31) => 0x5100d1, // AMD Zen, Castle Peak
        (0x17, 0x71) => 0x5100d1, // AMD Zen 2, Matisse
        (0x19, 0x01) => 0x5100d1, // AMD Zen, Milan
        (0x19, 0x50) => 0x5100d1, // AMD Zen, Cezanne
        oth => panic!(
            "Unsupported processor with feature info: {:?}\n Full family_model: {:?}",
            fi, oth
        ),
    }
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn get_rcb_perf_config() -> u64 {
    // TODO:
    //  1. Compute the microarchitecture from
    //     `/sys/devices/system/cpu/cpu*/regs/identification/midr_el1`
    //  2. Look up the microarchitecture in a table to determine what features
    //     we can enable.
    // References:
    //  - https://github.com/rr-debugger/rr/blob/master/src/PerfCounters.cc#L156
    const BR_RETIRED: u64 = 0x21;

    // For now, always assume that we can get retired branch events.
    BR_RETIRED
}

/// Returns true if the current CPU supports precise_ip.
#[cfg(target_arch = "x86_64")]
pub(crate) fn has_precise_ip() -> bool {
    let cpu = raw_cpuid::CpuId::new();
    let has_debug_store = cpu.get_feature_info().map_or(false, |info| info.has_ds());

    debug!(
        "Setting precise_ip to {} for cpu {:?}",
        has_debug_store, cpu
    );

    has_debug_store
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn has_precise_ip() -> bool {
    // Assume, for now, that aarch64 can use precise_ip.
    true
}

/// A timer monitoring a single thread. The underlying implementation is eagerly
/// initialized, but left empty if perf is not supported. In that case, any
/// methods with semantics that require a functioning clock or timer will panic.
#[derive(Debug)]
pub struct Timer {
    inner: Option<TimerImpl>,
}

/// Data requires to request a timer event
#[derive(Debug, Copy, Clone)]
pub enum TimerEventRequest {
    /// Event should fire after precisely this many RCBs.
    Precise(u64),

    /// Event should fire after at least this many RCBs.
    Imprecise(u64),

    /// Event should fire after precisely this many RCBS and this many instructions
    PreciseInstruction(u64, u64),
}

/// The possible results of handling a timer signal.
#[derive(Error, Debug, Eq, PartialEq)]
pub enum HandleFailure {
    #[error(transparent)]
    TraceError(#[from] TraceError),

    #[error("Unexpected event while single stepping")]
    Event(Wait),

    /// The timer signal was for a timer event that was otherwise cancelled. The
    /// task is returned unchanged.
    #[error("Timer event was cancelled and should not fire")]
    Cancelled(Stopped),

    /// The signal causing the signal-delivery stop was not actually meant for
    /// this timer. The task is returned unchanged.
    #[error("Pending signal was not for this timer")]
    ImproperSignal(Stopped),
}

impl Timer {
    /// Create a new timer monitoring the specified thread.
    pub fn new(guest_pid: Pid, guest_tid: Tid) -> Self {
        // No errors are exposed here, as the construction should be
        // bullet-proof, and if it wasn't, consumers wouldn't be able to
        // meaningfully handle the error anyway.
        Self {
            inner: if is_perf_supported() {
                Some(TimerImpl::new(guest_pid, guest_tid).unwrap())
            } else {
                None
            },
        }
    }

    fn inner(&self) -> &TimerImpl {
        self.inner.as_ref().expect("Perf support required")
    }

    fn inner_noinit(&self) -> Option<&TimerImpl> {
        self.inner.as_ref()
    }

    fn inner_mut_noinit(&mut self) -> Option<&mut TimerImpl> {
        self.inner.as_mut()
    }

    /// Read the thread-local deterministic clock. Represents total elapsed RCBs
    /// on this thread since the timer was constructed, which should be at or
    /// near thread creation time.
    pub fn read_clock(&self) -> u64 {
        self.inner().read_clock()
    }

    /// Approximately convert a duration to the internal notion of timer ticks.
    pub fn as_ticks(dur: core::time::Duration) -> u64 {
        // assumptions: 10% conditional branches, 3 GHz, avg 2 IPC
        // this gives: 0.6B branch / sec = 0.6 branch / ns
        (dur.as_secs() * 600_000_000) + (u64::from(dur.subsec_nanos()) * 6 / 10)
    }

    /// Return the signal type sent by the timer. This is intended to allow
    /// pre-filtering signals without the full overhead of gathering signal info
    /// to pass to ['Timer::generated_signal`].
    pub fn signal_type() -> Signal {
        MARKER_SIGNAL
    }

    /// Request a timer event to occur in the future at a time specified by
    /// `evt`.
    ///
    /// This is *not* idempotent and will replace the outstanding request. If it
    /// is called repeatedly no events will be delivered.
    pub fn request_event(&mut self, evt: TimerEventRequest) -> Result<(), Errno> {
        self.inner_mut_noinit()
            .ok_or(Errno::ENODEV)?
            .request_event(evt)
    }

    /// Must be called whenever a Tool-observable reverie event occurs. This
    /// ensures proper cancellation semantics are observed. See the internal
    /// `timer::EventStatus` type for details.
    pub fn observe_event(&mut self) {
        if let Some(t) = self.inner_mut_noinit() {
            t.observe_event();
        }
    }

    /// Cancel pending timer notifications. This is idempotent.
    ///
    /// If there was a previous call to [`Timer::enable_interval'], this
    /// will prevent the delivery of that notification. This also has the effect
    /// of reseting the "elapsed ticks." That is, if the current notification
    /// duration is `N` ticks, then a full `N` ticks must elapse after the next
    /// call to [`enable_interval`](Timer::enable_interval) before a
    /// notification is delivered.
    ///
    /// While [`Timer::cancel`] actually disables the counting of RCBs, this
    /// method simply sets a flag to subsequent delivered signals until
    /// [`Timer::request_event`] is called again. Thus, this method is lighter
    /// if called multiple times, but still results in a signal delivery, while
    /// [`Timer::cancel`] must perform a syscall, but will actually cancel the
    /// signal.
    #[allow(dead_code)]
    pub fn schedule_cancellation(&mut self) {
        if let Some(t) = self.inner_mut_noinit() {
            t.schedule_cancellation();
        }
    }

    /// Cancel pending timer notifications. This is idempotent.
    ///
    /// If there was a previous call to [`Timer::enable_interval'], this
    /// will prevent the delivery of that notification. This also has the effect
    /// of reseting the "elapsed ticks." That is, if the current notification
    /// duration is `N` ticks, then a full `N` ticks must elapse after the next
    /// call to [`enable_interval`](Timer::enable_interval) before a
    /// notification is delivered.
    ///
    /// See [`Timer::schedule_cancellation`] for a comparison with this
    /// method.
    #[allow(dead_code)]
    pub fn cancel(&self) -> Result<(), Errno> {
        self.inner_noinit().map(|t| t.cancel()).unwrap_or(Ok(()))
    }

    /// Perform finalization actions on requests for timer events before guest
    /// resumption. See the module-level documentation for rules about when this can and
    /// should be called.
    ///
    /// Currently, this will, if necessary, `tgkill` a timer signal to the guest
    /// thread.
    pub fn finalize_requests(&self) {
        if let Some(t) = self.inner_noinit() {
            t.finalize_requests();
        }
    }

    /// When a signal is received, this method drives the timer event to
    /// completion via single stepping, after checking that the signal was meant
    /// for this specific timer. This *must* be called when a timer signal is
    /// received for correctness.
    ///
    /// Preconditions: task is in signal-delivery-stop.
    /// Postconditions: if a signal meant for this timer was the cause of the
    /// stop, the tracee will be at the precise instruction the timer event
    /// should fire at.
    pub async fn handle_signal(&mut self, task: Stopped) -> Result<Stopped, HandleFailure> {
        match self.inner_mut_noinit() {
            Some(t) => t.handle_signal(task).await,
            None => {
                warn!("Stray SIGSTKFLT indicates a bug!");
                Err(HandleFailure::ImproperSignal(task))
            }
        }
    }
}

/// The lazy-initialized part of a `Timer` that holds the functionality.
#[derive(Debug)]
struct TimerImpl {
    /// A non-resetting counter functioning as a thread-local clock.
    clock: PerfCounter,

    /// A separate counter used to generate signals for timer events
    timer: PerfCounter,

    /// Information about the active timer event, including expected counter
    /// values.
    event: ActiveEvent,

    /// The cancellation status of the active timer event.
    timer_status: EventStatus,

    /// Whether or not the active timer event requires an artificial signal
    send_artificial_signal: bool,

    /// Pid (tgid) of the monitored thread
    guest_pid: Pid,

    /// Tid of the monitored thread
    guest_tid: Tid,
}

/// Tracks cancellation status of a timer event in response to other reverie
/// events.
///
/// Whenever a reverie event occurs, this should tick "forward" once. If the
/// timer signal is first to occur, then the cancellation will be pending, and
/// the event will fire. If instead some other event occured, the tick will
/// result in `Cancelled` and the event will not fire.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum EventStatus {
    Scheduled,
    Armed,
    Cancelled,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ActiveEvent {
    Precise {
        /// Expected clock value when event fires.
        clock_target: u64,
        /// Instruction offset from clock target
        offset: u64,
    },
    Imprecise {
        /// Expected minimum clock value when event fires.
        clock_min: u64,
    },
}

impl ActiveEvent {
    /// Given the current clock, determine if another event is required to get the
    /// clock to its expected state
    fn reschedule_if_spurious_wakeup(&self, curr_clock: u64) -> Option<TimerEventRequest> {
        match self {
            ActiveEvent::Precise {
                clock_target,
                offset: _,
            } => {
                if clock_target.saturating_sub(curr_clock) > MAX_SINGLE_STEP_COUNT {
                    Some(TimerEventRequest::Precise(*clock_target - curr_clock))
                } else {
                    None
                }
            }
            ActiveEvent::Imprecise { clock_min } => {
                if *clock_min > curr_clock {
                    Some(TimerEventRequest::Imprecise(*clock_min - curr_clock))
                } else {
                    None
                }
            }
        }
    }
}

impl EventStatus {
    pub fn next(self) -> Self {
        match self {
            EventStatus::Scheduled => EventStatus::Armed,
            EventStatus::Armed => EventStatus::Cancelled,
            EventStatus::Cancelled => EventStatus::Cancelled,
        }
    }

    pub fn tick(&mut self) {
        *self = self.next()
    }
}

/// This is the experimentally determined maximum number of RCBs an overflow
/// interrupt is delivered after the originating RCB.
///
/// If this is number is too small, timer event delivery will be delayed and
/// non-deterministic, which, if observed, will result in a panic.
/// If this number is too big, we degrade performance from excessive single
/// stepping.
///
/// `rr` uses a value of 100 for almost all platforms, but with precise_ip = 0.
/// Enabling Intel PEBS via precise_ip > 0 seems to reduce observed skid by 1/2,
/// in synthetic benchmarks, though it makes counter _values_ incorrect. As a
/// result, we choose 60.
const SKID_MARGIN_RCBS: u64 = 60;

/// We refuse to schedule a "perf timeout" for this or fewer RCBs, instead
/// choosing to directly single step. This is because I am somewhat paranoid
/// about perf event throttling, which isn't well-documented.
const SINGLESTEP_TIMEOUT_RCBS: u64 = 5;

/// The maximum single step count we expect can occur when a precise timer event
/// is requested that leaves less than the minimum perf timeout remaining.
const MAX_SINGLE_STEP_COUNT: u64 = SKID_MARGIN_RCBS + SINGLESTEP_TIMEOUT_RCBS;

/// This ClockCounter represents a pair in a form of (rcb, instr) that gets increased
/// while single-stepping to reach target (target_rcb, target_instr)
#[derive(Debug, Eq, PartialEq)]
struct ClockCounter {
    rcbs: u64,
    instr: u64,
    target_rcb: u64,
}

impl std::fmt::Display for ClockCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rcb: {}, instr: {}", self.rcbs, self.instr)
    }
}

impl ClockCounter {
    pub fn new(rcb: u64, instr: u64, target_rcb: u64) -> Self {
        Self {
            rcbs: rcb,
            instr,
            target_rcb,
        }
    }

    /// This method counts instructions & rcbs together in an attempt to reach target_rcb
    ///
    /// With each attempt we either increment rcb or instruction counter based on the read clock value.
    /// If we reach target_rcb we no longer increase rcb counter and allow to meet at the target instruction counter
    pub fn single_step_with_clock(&mut self, rcbs: u64) {
        match (self.rcbs.cmp(&self.target_rcb), self.rcbs.cmp(&rcbs)) {
            (Less, Less) => {
                self.instr = 0;
                self.rcbs = rcbs;
            }

            (Less | Equal, Equal) => {
                self.instr += 1;
            }

            (Equal, Less) => {
                self.instr += 1;
            }

            (_, Greater) => panic!(
                "current counter rcb value {} is greater than privided rcb value {}",
                self.rcbs, rcbs
            ),
            (Greater, _) => panic!(
                "current counter rcb value {} is greater than target rcb value {}",
                self.rcbs, self.target_rcb
            ),
        }
    }

    /// If a counter behind a given (rcb, instr) pair.
    ///
    /// Note: this is not always comparable. [None] will be returned in this case
    fn is_behind(&self, rcbs: u64, instr: u64) -> Option<bool> {
        match self.target_rcb.cmp(&rcbs) {
            Less => None,
            Greater | Equal => match self.rcbs.cmp(&rcbs) {
                Less => Some(true),
                Equal => Some(self.instr < instr),
                Greater => Some(false),
            },
        }
    }

    fn rcbs(&self) -> u64 {
        self.rcbs
    }
}

impl TimerImpl {
    pub fn new(guest_pid: Pid, guest_tid: Tid) -> Result<Self, Errno> {
        let evt = Event::Raw(get_rcb_perf_config());

        // measure the target tid irrespective of CPU
        let mut builder = Builder::new(guest_tid.as_raw(), -1);
        builder
            .sample_period(PerfCounter::DISABLE_SAMPLE_PERIOD)
            .event(evt);

        if has_precise_ip() {
            // set precise_ip to lowest value to enable PEBS (TODO: AMD?)
            builder.precise_ip(1);
        }

        let timer = builder.check_for_pmu_bugs().create()?;
        timer.set_signal_delivery(guest_tid, MARKER_SIGNAL)?;
        timer.reset()?;
        // measure the target tid irrespective of CPU
        let clock = Builder::new(guest_tid.as_raw(), -1)
            // counting event
            .sample_period(0)
            .event(evt)
            .fast_reads(true)
            .create()?;
        clock.reset()?;
        clock.enable()?;

        Ok(Self {
            timer,
            clock,
            event: ActiveEvent::Precise {
                clock_target: 0,
                offset: 0,
            },
            timer_status: EventStatus::Cancelled,
            send_artificial_signal: false,
            guest_pid,
            guest_tid,
        })
    }

    pub fn request_event(&mut self, evt: TimerEventRequest) -> Result<(), Errno> {
        let (delivery, notification) = match evt {
            TimerEventRequest::Precise(ticks) | TimerEventRequest::PreciseInstruction(ticks, _) => {
                (ticks, ticks.saturating_sub(SKID_MARGIN_RCBS))
            }
            TimerEventRequest::Imprecise(ticks) => (ticks, ticks),
        };
        if delivery == 0 {
            return Err(Errno::EINVAL); // bail before setting timer
        }
        self.send_artificial_signal = if notification <= SINGLESTEP_TIMEOUT_RCBS {
            // If there's an existing event making use of the timer counter,
            // we need to "overwrite" it the same way setting an actual RCB
            // notification does.
            self.timer.disable()?;
            true
        } else {
            self.timer.reset()?;
            self.timer.set_period(notification)?;
            self.timer.enable()?;
            false
        };
        let clock = self.read_clock() + delivery;
        self.event = match evt {
            TimerEventRequest::Precise(_) => ActiveEvent::Precise {
                clock_target: clock,
                offset: 0,
            },
            TimerEventRequest::PreciseInstruction(_, instr_offset) => ActiveEvent::Precise {
                clock_target: clock,
                offset: instr_offset,
            },
            TimerEventRequest::Imprecise(_) => ActiveEvent::Imprecise { clock_min: clock },
        };
        self.timer_status = EventStatus::Scheduled;
        Ok(())
    }

    pub fn observe_event(&mut self) {
        self.timer_status.tick()
    }

    pub fn schedule_cancellation(&mut self) {
        self.timer_status = EventStatus::Cancelled;
    }

    pub fn cancel(&self) -> Result<(), Errno> {
        self.timer.disable()
    }

    fn is_timer_generated_signal(signal: &libc::siginfo_t) -> bool {
        // The signal that gets sent is SIGPOLL. We reconfigured the signal
        // number, but the struct info is the same. Per the perf manpage, signal
        // notifications will come indicating either POLL_IN or POLL_HUP.
        signal.si_signo == MARKER_SIGNAL as i32
            && (signal.si_code == i32::from(libc::POLLIN)
                || signal.si_code == i32::from(libc::POLLHUP))
    }

    fn generated_signal(&self, signal: &libc::siginfo_t) -> bool {
        signal.si_signo == MARKER_SIGNAL as i32
            // If we sent an artificial signal, it doesn't have any siginfo
            && (self.send_artificial_signal
            // If not, the fd should match. This could possibly lead to a
            // collision, because an fd comparing-equal to this one in another
            // process could also send a signal. However, that it would also do so
            // as SIGSTKFLT is effectively not going to happen.
                || (Self::is_timer_generated_signal(signal)
                    && get_si_fd(signal) == self.timer.raw_fd()))
    }

    pub fn read_clock(&self) -> u64 {
        self.clock.ctr_value_fast().expect("Failed to read clock")
    }

    pub fn finalize_requests(&self) {
        if self.send_artificial_signal {
            debug!("Sending artificial timer signal");

            // Give the guest a kick via an "artificial signal".  This gives us something
            // to handle in `handle_signal` and thus drives single-stepping.
            Errno::result(unsafe {
                libc::syscall(
                    libc::SYS_tgkill,
                    self.guest_pid.as_raw(),
                    self.guest_tid.as_raw(),
                    MARKER_SIGNAL as i32,
                )
            })
            .expect("Timer tgkill error indicates a bug");
        }
    }

    pub async fn handle_signal(&mut self, task: Stopped) -> Result<Stopped, HandleFailure> {
        let signal = task.getsiginfo()?;
        if !self.generated_signal(&signal) {
            warn!(
                ?signal,
                "Passed a signal that wasn't for this timer, likely indicating a bug!",
            );
            return Err(HandleFailure::ImproperSignal(task));
        }

        match self.timer_status {
            EventStatus::Scheduled => panic!(
                "Timer event status should tick at least once before the signal \
                is handled. This is a bug!"
            ),
            EventStatus::Armed => {}
            EventStatus::Cancelled => {
                debug!("Delivered timer signal cancelled due to status");
                self.disable_timer_before_stepping();
                return Err(HandleFailure::Cancelled(task));
            }
        };

        // At this point, we've decided that a timer event is to be delivered.

        // Ensure any new timer signals don't mess with us while single-stepping
        self.disable_timer_before_stepping();

        // Last check to see if this an unexpected wakeup (a signal before the minimum expected)
        let ctr = self.read_clock();

        if let Some(additional_timer_request) = self.event.reschedule_if_spurious_wakeup(ctr) {
            debug!("Spurious wakeup - rescheduling new timer event");
            if let Err(errno) = self.request_event(additional_timer_request) {
                warn!(
                    "Attempted to reschedule a timer signal after an early wakeup, but failed with - {:?}. A panic will likely follow",
                    errno
                );
            } else {
                return Err(HandleFailure::Cancelled(task));
            };
        }

        // Before we drive the event to completion, clear `send_artificial_signal` flag so that:
        // - another signal isn't generated anytime Timer::finalize_requests() is called
        // - spurious SIGSTKFLTs aren't let errantly let through
        // Cancellations should prevent spurious timer events in any case.
        self.send_artificial_signal = false;

        match self.event {
            ActiveEvent::Precise {
                clock_target,
                offset,
            } => {
                self.attempt_single_step(task, ctr, clock_target, offset)
                    .await
            }
            ActiveEvent::Imprecise { clock_min } => {
                debug!(
                    "Imprecise timer event delivered. Ctr val: {}, min val: {}",
                    ctr, clock_min
                );
                assert!(ctr >= clock_min, "ctr = {}, clock_min = {}", ctr, clock_min);
                Ok(task)
            }
        }
    }

    async fn attempt_single_step(
        &self,
        task: Stopped,
        ctr_initial: u64,
        target_rcb: u64,
        target_instr: u64,
    ) -> Result<Stopped, HandleFailure> {
        assert!(
            ctr_initial <= target_rcb,
            "Clock perf counter exceeds target value at start of attempted single-step: \
                {} > {}. Consider increasing SKID_MARGIN_RCBS.",
            ctr_initial,
            target_rcb
        );
        let mut current = ClockCounter::new(ctr_initial, 0, target_rcb);
        assert!(
            target_rcb - current.rcbs() <= MAX_SINGLE_STEP_COUNT,
            "Single steps from {} to {} requested ({} steps), but that exceeds the skid margin + minimum perf timer steps ({}). \
                This probably indicates a bug",
            current.rcbs(),
            target_rcb,
            (target_rcb - current.rcbs()),
            MAX_SINGLE_STEP_COUNT
        );
        debug!(
            "Timer will single-step from ctr {} to {}",
            current, target_rcb
        );
        let mut task = task;
        loop {
            if !current
                .is_behind(target_rcb, target_instr)
                .expect("counter should increase monotonically and stay at target_rcb until equal. This is most likely a BUG with counter tracking")
            {
                break;
            }
            #[cfg(target_arch = "x86_64")]
            trace!(
                "[instruction]\n{}\n{}",
                crate::decoder::decode_instruction(&task)?,
                task.getregs()?
                    .display_with_options(RegDisplayOptions { multiline: true })
            );
            task = match task.step(None)?.next_state().await? {
                // a successful single step results in SIGTRAP stop
                Wait::Stopped(new_task, TraceEvent::Signal(Signal::SIGTRAP)) => new_task,
                wait => return Err(HandleFailure::Event(wait)),
            };
            current.single_step_with_clock(self.read_clock());
        }
        Ok(task)
    }

    /// Imagine our skid margin is 50 RCBs, and we set the timer for 5 RCBs.
    /// Since we step for 50, the timer will trigger multiple times unless we
    /// disable it before stepping. This would count as a state machine
    /// transition and errantly cancel the delivery of the timer event.
    fn disable_timer_before_stepping(&self) {
        self.timer
            .disable()
            .expect("Must be able to disable timer before stepping");
    }
}

#[cfg(target_os = "linux")]
fn get_si_fd(signal: &libc::siginfo_t) -> libc::c_int {
    // This almost certainly broken for anything other than linux (glibc?).
    //
    // The `libc` crate doesn't expose these fields properly, because the
    // current version was released before union support, and `siginfo_t` is a
    // messy enum/union, making this super fragile.
    //
    // `libc` has an accessor system in place, but only for a few particular
    // signal types as of right now. We could submit a PR for SIGPOLL/SIGIO, but
    // until then, this is copies the currently used accessor idea.

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct sifields_sigpoll {
        si_band: libc::c_long,
        si_fd: libc::c_int,
    }
    #[repr(C)]
    union sifields {
        _align_pointer: *mut libc::c_void,
        sigpoll: sifields_sigpoll,
    }
    #[repr(C)]
    struct siginfo_f {
        _siginfo_base: [libc::c_int; 3],
        sifields: sifields,
        padding: [libc::c_int; 24],
    }

    // These compile to no-op or unconditional runtime panic, which is good,
    // because code not using timers continues to work.
    assert_eq!(
        core::mem::size_of::<siginfo_f>(),
        core::mem::size_of_val(signal),
    );
    assert_eq!(
        core::mem::align_of::<siginfo_f>(),
        core::mem::align_of_val(signal),
    );

    unsafe {
        (*(signal as *const _ as *const siginfo_f))
            .sifields
            .sigpoll
            .si_fd
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::ClockCounter;

    #[test_case(ClockCounter::new(0, 0, 10), 0, 1, Some(true))]
    #[test_case(ClockCounter::new(2, 100, 200), 3, 0, Some(true))]
    #[test_case(ClockCounter::new(1, 10, 200), 1, 11, Some(true))]
    #[test_case(ClockCounter::new(2, 100, 2), 3, 0, None)]
    #[test_case(ClockCounter::new(4, 4, 4), 4, 5, Some(true))]
    #[test_case(ClockCounter::new(4, 4, 4), 4, 3, Some(false))]
    #[test_case(ClockCounter::new(4, 4, 4), 4, 4, Some(false))]
    fn test_clock_counter_is_behind(
        counter: ClockCounter,
        target_rcb: u64,
        target_instr: u64,
        expected: Option<bool>,
    ) {
        assert_eq!(counter.is_behind(target_rcb, target_instr), expected);
    }

    #[test_case(ClockCounter::new(0, 0, 0), 0, (0, 1))]
    #[test_case(ClockCounter::new(0, 1, 0), 1, (0, 2))]
    #[test_case(ClockCounter::new(0, 1, 0), 2, (0, 2))]
    #[test_case(ClockCounter::new(0, 1, 1), 0, (0, 2))]
    #[test_case(ClockCounter::new(0, 1, 1), 1, (1, 0))]
    #[test_case(ClockCounter::new(0, 1, 1), 2, (2, 0))]
    #[test_case(ClockCounter::new(0, 1, 1), 3, (3, 0))]
    #[test_case(ClockCounter::new(10, 0, 11), 10, (10, 1))]
    #[test_case(ClockCounter::new(10, 1, 11), 10, (10, 2))]
    #[test_case(ClockCounter::new(10, 1, 11), 11, (11, 0))]
    #[test_case(ClockCounter::new(10, 1, 11), 12, (12, 0))]
    fn test_increment_counter_with_clock(
        mut counter: ClockCounter,
        new_clock: u64,
        expected: (u64, u64),
    ) {
        counter.single_step_with_clock(new_clock);
        assert_eq!((counter.rcbs, counter.instr), expected);
    }
}
