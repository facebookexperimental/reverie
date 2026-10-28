/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A preemption timer for one guest thread: a second guest-only perf event
//! whose overflow only kicks the vCPU out of `KVM_RUN`, and the state of the
//! one event a timer request names, decided from the thread's clock.
//!
//! The clock (see `clock.rs`) is a counting event for the retired conditional
//! branches (RCBs) of one guest thread in guest user mode. The timer event has
//! the same encoding and the same filter, so it counts exactly what the clock
//! counts, but it samples: at its overflow Linux sends [`KICK_SIGNAL`] to the
//! vCPU's host thread, which ends `KVM_RUN` with `EINTR` (see below for how
//! the signal stays out of host code). Ending `KVM_RUN` is the signal's only
//! effect. Every decision is made from the clock value read at the exit,
//! never from the signal or the timer's own count, so a late, spurious or
//! lost kick can change when the backend looks, never what it decides at a
//! given count.
//!
//! Two events, not one. Linux throttles a sampling event that overflows more
//! often than `perf_event_max_sample_rate` allows, and a throttled event stops
//! counting. A sampling clock would then lose counts silently: a stopped but
//! scheduled event still accrues `time_running`, so the clock's residency
//! check would pass. A counting event is never throttled. The timer also stays
//! out of the clock's perf group, because throttling stops a whole group. A
//! throttled timer is harmless: the overflow that throttles it is still
//! notified, and the next `PERF_EVENT_IOC_PERIOD` un-throttles it.
//!
//! Programming is lazy. A thread that has never armed a timer has no timer
//! event, and its entries issue no syscall for one. While a request is armed,
//! an entry reprograms the event (one `PERF_EVENT_IOC_PERIOD`) only when it has
//! no pending overflow, when the clock has reached that overflow, or when the
//! overflow would come later than the request now needs. A request whose
//! target is unchanged costs nothing per entry. The pending overflow is a
//! clock value, so it is kept only while the event counts exactly what the
//! clock counts. An entry that runs the clock with the event disabled (an
//! unarmed entry on pinned placement, or one after another binding disabled
//! both events) forgets it, and the next armed entry programs the event
//! afresh. A distance longer than [`MAX_PERIOD`] is programmed in pieces.
//!
//! Between the overflow and the exit that the kick causes, the guest keeps
//! running for the interrupt's latency (the skid), so a precise request is
//! first programmed one skid margin short of its target. From that close to
//! the target, the guest is single-stepped to it (see below), and the event
//! is programmed at the target itself, for the stretches that run unstepped.
//!
//! An exit that finds a precise request's target reached is late, even at
//! exactly the target, unless it ended a single step that retired the target
//! branch: an asynchronous exit does not stop the guest at the instruction
//! boundary right after the target branch, and non-branch instructions may
//! have run past it. Such an exit is recorded as every backend records a late
//! timer event: the canonical [`reverie::SKID_OVERSHOOT_MARKER`] line and the
//! process-global witness count. It is delivered at the clock it found, as
//! reverie-ptrace delivers an event its notification overshot.
//!
//! A kick never interrupts a host call. The interrupt behind a kick can be
//! held past the exit it would have caused, even across several further
//! exits, so its signal can arrive while the vCPU thread runs host code, where
//! an empty handler would still interrupt the call in progress (a sleep or a
//! poll returns `EINTR`, a read or write that has moved some bytes returns a
//! short count) and LinuxEmu would pass that result to the guest. On a
//! PREEMPT_RT kernel perf sends the signal from a thread, so this would be
//! routine there. So the vCPU thread keeps [`KICK_SIGNAL`] blocked in host
//! code, and `KVM_RUN` alone runs with it unblocked, as gVisor's KVM platform
//! does for its own kick signal:
//! - Opening a timer event blocks the signal on the thread and sets the vCPU's
//!   signal mask (`KVM_SET_SIGNAL_MASK`) to the thread's mask from before with
//!   only the kick signal unblocked. Linux installs that mask for `KVM_RUN`
//!   and restores the thread's own when it returns, so `KVM_RUN` runs under
//!   the thread's mask exactly, signal 64 (the entry signal) and `SIGURG` (the
//!   worker interrupt) included, except that a kick ends it.
//! - A kick that ends `KVM_RUN` is left pending by the restored mask, and the
//!   `EINTR` exit takes it with one `rt_sigtimedwait` with a zero timeout. A
//!   kick that arrives in host code stays pending and interrupts nothing; it
//!   ends the next `KVM_RUN` at once, before the guest runs, and is taken at
//!   that exit. The signal does not queue, so each kick costs at most that one
//!   extra exit.
//! - The vCPU mask follows the thread's mask. When reverie-kvm changes the
//!   thread's `SIGURG` state, the vCPU's next counted entry on that thread
//!   composes the mask again, and so does an `EINTR` exit that takes no kick.
//!   A signal blocked on the thread since the mask was composed then costs one
//!   exit for each kick pending with it, each of which takes its kick, plus at
//!   most one more exit, which takes no kick and composes the mask again. An
//!   entry with no timer event withdraws a mask composed on another thread or
//!   before such a change, and a new guest lifetime withdraws the mask too.
//! - The empty handler stays installed, so that a kick on a thread that
//!   unblocked the signal again runs it rather than the default action, which
//!   ends the process.
//!
//! A thread that never opens a timer event has no vCPU mask and pays nothing:
//! its entries issue exactly the syscalls they would without this module.
//!
//! `KvmGuest::set_timer` requests an imprecise event ([`TimerKind::Imprecise`])
//! under the Reverie contract, as reverie-ptrace (its `Timer` and
//! `TracedTask::set_timer`) implements it except where
//! <https://github.com/rrnewton/reverie/issues/1176> says:
//! - A thread has one request, and a new one replaces it. `Rcbs(r)` and
//!   `RcbsAndInstructions(r, _)` request `r` RCBs, and `Time` is converted at
//!   reverie-ptrace's rate ([`rcbs_for_duration`]). A request for 0 RCBs is
//!   refused with `EINVAL` and leaves the outstanding one in place. The event
//!   is programmed at the target, with no skid margin, and the clock read
//!   when it is delivered is at least the target; it is never late.
//! - The next event of another kind decides the request. Before each Tool
//!   callback for another event (a subscribed syscall, a signal, CPUID or
//!   RDTSC, an exec's post-exec callback, and the thread's exit) the request
//!   is cancelled, so a request made inside that callback is a new one. The
//!   initial exec cancels too. A syscall the Tool injects is not an event and
//!   cancels nothing, and an exit with no Tool callback (an unsubscribed or
//!   backend-owned syscall, the VMware backdoor probe, a kick) leaves the
//!   request as it is.
//! - Once an exit has found the clock at the target or past it, the request
//!   is delivered through `Tool::handle_timer_event`, once, before the guest
//!   runs on. At a kick that stopped the guest in user mode, between two
//!   instructions, the callback sees the live registers. At the exit of a
//!   syscall that made no Tool callback, it runs once the syscall has
//!   completed, at its return, with the user registers the guest resumes
//!   with, before a pending signal is selected there: so a guest that makes
//!   such syscalls faster than a kick lands gets its event within a syscall
//!   of the target. There `orig_rax` reads -1, where reverie-ptrace shows the
//!   syscall's number. At an `rt_sigreturn` it runs likewise, with the user
//!   registers that call restores. Found due anywhere else (by a kick that
//!   stopped the guest in ring 0), it is armed again at its target (see
//!   `KvmBackend::timer_instruction_boundary`).
//! - After the callback, one pending signal is selected at the same point and
//!   delivered. Linux's return to user mode after a preemption calls
//!   `schedule()` before `arch_do_signal_or_restart()`
//!   (`exit_to_user_mode_loop`, `kernel/entry/common.c`), so at each of the
//!   three points the timer event comes first and the signal second. Linux
//!   then delivers every other eligible signal on the same return, each
//!   frame on top of the last; like its other boundaries, this backend
//!   delivers one per return, and the next waits for the next return. At a
//!   user instruction boundary the signal's frame holds the live registers,
//!   and nothing restarts: the interrupt that preempts a thread (the local
//!   APIC timer or a reschedule IPI) enters with `orig_ax` -1, so
//!   `handle_signal` in `arch/x86/kernel/signal.c` finds no syscall. The
//!   signal hook sees the complete registers the timer event's callback saw,
//!   segment selectors and FS and GS bases included. A boundary with no
//!   eligible pending signal makes no selection. One where KVM has yet to
//!   inject an exception (a host interrupt ended its delivery) defers the
//!   selection to the first user boundary with no event left to inject: the
//!   one that exception's own boundary leaves, after a fault's signal (whose
//!   frame the signal's then goes on top of, under the mask that delivery
//!   left) or after an intercepted CPUID or RDTSC's callback. At a syscall's
//!   return the selection is the syscall's own, with its restart rules, and
//!   at an `rt_sigreturn` it sees the registers and the mask that call
//!   restores. Selection, masking, the Tool's signal hook and the frame are
//!   those of every other boundary. A signal that another thread sends while
//!   the callback runs counts.
//! - The callback can inject syscalls that return, and exits. A process
//!   action, a tail injection other than an exit, a signal that needs a
//!   syscall return frame, or an `rt_sigprocmask` that would make a pending
//!   signal deliverable is refused before it has any effect and ends the run
//!   (`Error::TimerCallbackInjectionUnsupported`), so a Tool cannot take the
//!   refusal for an ordinary failure of the syscall. The refusal stays the
//!   callback's outcome: an injection the callback makes afterwards, having
//!   dropped the refused one, never runs, and a later exit or retirement
//!   does not replace it. Its writes to guest memory are not held back (see
//!   the limits below). An `rt_sigprocmask` with invalid arguments still
//!   returns its `EINVAL` or `EFAULT`, and one that makes no pending signal
//!   deliverable runs as usual.
//!
//! `KvmGuest::set_timer_precise` requests a precise event
//! ([`TimerKind::Precise`]), delivered exactly when the clock reaches its
//! target, at the instruction boundary right after the target branch:
//! - The schedule maps as for `set_timer`, except that `RcbsAndInstructions`
//!   is refused with an `Unsupported` error: this backend does not step
//!   instructions past the count. A request is staged as reverie-ptrace
//!   stages one ([`reverie::pmu_config::PmuConfig::stages`]): one longer than
//!   the first stage margin plus [`SINGLESTEP_TIMEOUT_RCBS`] is programmed
//!   one first stage margin short of its target, and the first exit at or
//!   past that point sizes the second stage margin from the RCBs and the host
//!   time (`CLOCK_MONOTONIC`) since the request. Any other is programmed one
//!   skid margin short. Staging changes where the last kick comes, never
//!   where the event is delivered.
//! - Once the clock is no more than the margin plus
//!   [`SINGLESTEP_TIMEOUT_RCBS`] short of the target, every entry runs under
//!   KVM's guest debugging (`KvmBackend::prepare_timer_steps`): it
//!   single-steps one user instruction (`KVM_GUESTDBG_SINGLESTEP`, one
//!   `KVM_SET_GUEST_DEBUG` for a whole run of steps), or runs unstepped up
//!   to a user instruction where an execution breakpoint
//!   (`KVM_GUESTDBG_USE_HW_BP`) takes it back, or runs unstepped to an exit
//!   that comes before any user instruction. A step retires at most one
//!   conditional branch, so the first step that leaves the clock at the
//!   target stops the guest exactly at the boundary after the target branch,
//!   which is the same boundary in every run whichever instruction the steps
//!   started from. The request is due on time there, and the next iteration
//!   delivers it with the live registers.
//! - The trap flag (TF) a step sets is in the guest's real RFLAGS, so
//!   iced-x86 decodes the instruction at RIP first, and no instruction that
//!   saves or loads RFLAGS is stepped (see `step_filter::StepClass` for each
//!   kind). PUSHF and POPF run natively to a breakpoint on the next
//!   instruction, with no check before them that another thread could
//!   outrun; a guest whose POPF or `rt_sigreturn` loads its own TF is
//!   refused by name there, before its next instruction, as are IRETQ and a
//!   load of SS anywhere in the window. A fault during a step leaves TF in
//!   the frame the CPU pushed; the frame loses it before anything reads it
//!   (`KvmBackend::scrub_stepped_exception_frame`), even when a host
//!   interrupt ends the entry inside the exception stub ([`SteppedFault`]),
//!   and the fault, the guest's own, cancels the request as before.
//! - In ring 0, the syscall trampoline stopped at its VMCALL runs to a
//!   breakpoint at the user instruction it returns to, which the syscall
//!   frame names, so the steps go on after a syscall that made no Tool
//!   callback, or after an `rt_sigreturn`; a host interrupt that stops it on
//!   its way back keeps that run, and for an IRETQ return the staged flags
//!   lose RF, which would hold that breakpoint off. Anywhere else in ring 0
//!   the entry runs unstepped: its exit comes first.
//! - Every other entry runs unstepped: a vCPU leaves guest debugging off
//!   unless an entry asks for it, and a register write since the last step
//!   sets it again before the next.
//!
//! `BackendCapabilities::KVM` keeps `delivers_preemption_timer_events` false,
//! so no Tool can rely on a timer event from this backend.
//!
//! Limits, to address before that capability is set:
//! - Nothing checks the timer event's residency. A pinned event that the PMU
//!   cannot schedule never kicks: a guest that makes no exit runs on, and its
//!   next exit finds the request due, late if it is precise.
//! - Only counted entries displace another binding's events. An uncounted
//!   vCPU on the same host task leaves an enabled timer counting its branches:
//!   the timer overflows early, inside that vCPU's run, and reloads a whole
//!   period. Its kick stays pending (that vCPU has no vCPU mask) and ends the
//!   armed vCPU's next entry at once, so the request comes due at a later exit
//!   (late, if it is precise).
//! - Nothing refuses a PREEMPT_RT kernel or nested virtualization, where the
//!   kick's latency has not been measured.
//! - A precise request is late when the PMU interrupt behind its last kick
//!   comes after the margin, from the hardware's interrupt latency: at the
//!   2,000 RCB margin on an EPYC 9D85, about one kick in a thousand on an
//!   idle host, and up to about one in a hundred on a busy one.
//! - Every other instruction in the stepping window is a step of its own,
//!   with no block steps yet. In a release build a step costs about 3.3
//!   microseconds under following placement, and about 17 under pinned
//!   placement, where every entry also pins and restores the CPU and enables
//!   and disables the events: about 12 syscalls per step, against 1.
//! - REPE and REPNE CMPS and SCAS, and REP LODS, retire no counted branch
//!   per iteration on this AMD host but are stepped one iteration at a time
//!   until that is measured on Intel, so the window does not bound their
//!   cost: a 256 KiB REPE CMPSB in the window took 0.93 s in a release build
//!   (262,218 steps), against 37 ms for an imprecise request.
//! - IRETQ, a load of SS and the guest's own TF are refused only inside the
//!   stepping window, whose start depends on when a kick lands, so a guest
//!   that uses them near a precise target can be refused in one run and not
//!   in another.
//! - The instruction at RIP is decoded from guest memory before the entry
//!   that runs it. A peer thread that rewrites it in between, which needs a
//!   writable executable mapping (or a writable alias of one) and a peer
//!   running at the same time as the stepped thread, can have an
//!   instruction that saves RFLAGS (PUSHF, or SYSCALL into R11) stepped,
//!   which shows the step's TF, or a run end at a breakpoint that is no
//!   longer the next instruction, which makes the event late and recorded.
//!   An instruction rewritten into a POPF or IRETQ that is then stepped
//!   replaces TF with its image's: a clear image ends the steps, so the
//!   event is late and recorded; a set one is taken over by the steps and
//!   dropped when they stop, instead of being refused by name. An on-time
//!   event is never delivered at another point; a late one is delivered
//!   later, and recorded. A Tool that serializes
//!   guest threads never runs such a peer. Linux's ptrace single step, which
//!   reverie-ptrace uses, shows TF to every stepped PUSHF and decodes POPF
//!   and IRET just as racily (`arch/x86/kernel/step.c`). Before the
//!   capability is set, decide whether a Tool that does not serialize
//!   threads needs byte-stable stepping.
//! - A signal sent to a running thread waits for that thread's next timer
//!   event, syscall or fault; Linux interrupts the thread for it at once.
//! - A timer event's callback cannot make a signal deliverable to its own
//!   thread (see above), where reverie-ptrace delivers one that the callback
//!   sends to the thread once the callback returns.
//! - After a refused injection, the callback's own guest-memory and stack
//!   writes, through handles it already holds, still reach memory until the
//!   callback returns or suspends; the run then fails with the named reason.
//! - Only a Tool callback for another event cancels a request, so the
//!   parent's request survives a fork, clone or vfork that the Tool does not
//!   subscribe to. reverie-ptrace differs in three places
//!   (<https://github.com/rrnewton/reverie/issues/1176>): its new-child and
//!   vfork-done stops cancel a request though they make no callback on the
//!   parent, its report of a held signal (`report_signal`) makes a callback
//!   without cancelling, and its ordinary injected exec reaches the post-exec
//!   callback without cancelling.
//! - Nothing checks that the kick signal stays blocked on the vCPU thread:
//!   code that unblocks it there lets a late kick interrupt a host call again.
//! - While the vCPU mask stays installed, a signal that code outside
//!   reverie-kvm unblocks on the vCPU thread does not end `KVM_RUN` until the
//!   mask is composed again (see above). The mask can outlive its timer event:
//!   when the binding is reopened on the same thread (on another CPU under
//!   pinned placement, or with another raw encoding) while the request is idle
//!   or already due, no new timer event opens, and the mask composed before
//!   stays installed.

use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::OnceLock;

use perf_event_open_sys::bindings as perf;
use perf_event_open_sys::ioctls;
use reverie::pmu_config::SINGLESTEP_TIMEOUT_RCBS;

use crate::Error;
use crate::Result;

/// The host signal a timer overflow sends to its vCPU thread: Reverie's
/// [`reverie::PERF_EVENT_SIGNAL`], `SIGSTKFLT`. It is separate from the entry
/// signal (real-time signal 64), whose handler refuses any instance that no
/// closer recorded.
pub(crate) const KICK_SIGNAL: libc::c_int = libc::SIGSTKFLT;

const _: () = assert!(reverie::PERF_EVENT_SIGNAL as libc::c_int == KICK_SIGNAL);

/// The longest period programmed at once. Linux refuses a period with bit 63
/// set, and x86 programs at most its counter's maximum period at a time and
/// reloads the rest silently. A longer distance is programmed in pieces of
/// this size, each forgotten and reprogrammed when the clock reaches it.
pub(crate) const MAX_PERIOD: u64 = 1 << 60;

/// A period long enough that the event never overflows: at this length the
/// silent reloads take days of guest execution to run out.
const QUIET_PERIOD: u64 = MAX_PERIOD;

/// Linux programs a sampling period below 2 as 2: a period of 1 cannot
/// overflow at the next branch.
const MIN_PERIOD: u64 = 2;

// Not available in the libc crate.
const F_SETSIG: libc::c_int = 10;
const F_SETOWN_EX: libc::c_int = 15;
const F_OWNER_TID: libc::c_int = 0;

#[repr(C)]
struct FOwnerEx {
    type_: libc::c_int,
    pid: libc::pid_t,
}

fn failure(message: impl Into<String>) -> Error {
    Error::GuestClock(message.into())
}

fn host_failure(operation: &str) -> Error {
    failure(format!(
        "preemption timer: {operation}: {}",
        std::io::Error::last_os_error()
    ))
}

/// Serializes the tests that read or drain the process-global witness count
/// (`reverie::take_skid_overshoot_count`), which a plain `cargo test` shares
/// among the threads of one process.
#[cfg(test)]
pub(crate) static WITNESS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Takes the witness count's turn, drained to zero.
#[cfg(test)]
pub(crate) fn witness_turn() -> std::sync::MutexGuard<'static, ()> {
    let guard = WITNESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _ = reverie::take_skid_overshoot_count();
    guard
}

#[cfg(test)]
thread_local! {
    /// Kicks this thread's handler has taken.
    pub(crate) static KICKS_TAKEN: std::sync::atomic::AtomicU64 =
        const { std::sync::atomic::AtomicU64::new(0) };
    /// Kicks taken from this thread's pending signals at `EINTR` exits.
    pub(crate) static KICKS_DRAINED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Host syscalls this thread issued for a timer: signal reservation, event
    /// creation and setup, every programming ioctl, the vCPU signal mask, and
    /// every drain of a pending kick.
    pub(crate) static TIMER_SYSCALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

thread_local! {
    /// Changes reverie-kvm made to this thread's signal mask, other than
    /// blocking the kick signal. A vCPU signal mask composed from this
    /// thread's mask at an earlier count may no longer match it.
    static MASK_CHANGES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Records that reverie-kvm changed the calling thread's signal mask, so that
/// a vCPU signal mask composed from it before is composed again at its vCPU's
/// next counted entry on this thread.
pub(crate) fn note_thread_mask_change() {
    MASK_CHANGES.with(|changes| changes.set(changes.get().wrapping_add(1)));
}

/// The calling thread's count of [`note_thread_mask_change`] calls.
pub(crate) fn thread_mask_changes() -> u64 {
    MASK_CHANGES.with(|changes| changes.get())
}

fn count_syscall() {
    #[cfg(test)]
    TIMER_SYSCALLS.with(|count| count.set(count.get() + 1));
}

extern "C" fn kick(_signal: libc::c_int) {
    // Nothing to do. A vCPU thread blocks the kick signal outside KVM_RUN,
    // so a kick reaches this handler only on a thread that unblocked it
    // again; the handler keeps that kick from taking the default action,
    // which ends the process. A const thread local without a destructor is
    // a plain TLS access, safe in a signal handler.
    #[cfg(test)]
    KICKS_TAKEN.with(|kicks| kicks.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
}

/// A kernel `sigset_t` on x86-64 Linux, as `KVM_SET_SIGNAL_MASK` and
/// `rt_sigtimedwait` take it: bit `n - 1` for signal `n`.
pub(crate) type KernelSigset = u64;

const fn kernel_bit(signal: libc::c_int) -> KernelSigset {
    1 << (signal - 1)
}

/// Blocks [`KICK_SIGNAL`] on the calling thread, and returns the thread's
/// signal mask from just before. The raw `rt_sigprocmask` reports the whole
/// kernel mask, including the two signals glibc reserves for itself.
pub(crate) fn block_kick_signal() -> Result<KernelSigset> {
    let set = kernel_bit(KICK_SIGNAL);
    let mut previous: KernelSigset = 0;
    count_syscall();
    // SAFETY: both sets are initialized kernel sigsets of the size passed;
    // the change affects only this thread.
    if unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_BLOCK,
            std::ptr::from_ref(&set),
            std::ptr::from_mut(&mut previous),
            std::mem::size_of::<KernelSigset>(),
        )
    } != 0
    {
        return Err(host_failure("block host signal SIGSTKFLT"));
    }
    Ok(previous)
}

/// The signal mask `KVM_RUN` runs under for a thread whose own mask is
/// `thread_mask`: the same signals blocked, except [`KICK_SIGNAL`].
pub(crate) const fn vcpu_signal_mask(thread_mask: KernelSigset) -> KernelSigset {
    thread_mask & !kernel_bit(KICK_SIGNAL)
}

/// `KVM_SET_SIGNAL_MASK`: `_IOW(KVMIO, 0x8b, struct kvm_signal_mask)`, whose
/// flexible array leaves the struct 4 bytes long.
const KVM_SET_SIGNAL_MASK: libc::c_ulong = (1 << 30) | (4 << 16) | (0xae << 8) | 0x8b;

/// `struct kvm_signal_mask` with its array sized for x86-64's `sigset_t`.
#[repr(C)]
struct KvmSignalMask {
    len: u32,
    sigset: [u8; 8],
}

/// Makes `KVM_RUN` on `vcpu` run under `mask` in place of the calling
/// thread's own signal mask, or under the thread's own mask again for None.
/// Linux installs the mask when `KVM_RUN` starts and restores the thread's
/// own when it returns (`kvm_sigset_activate`, `kvm_sigset_deactivate`). The
/// setting belongs to the vCPU, whichever thread runs it.
pub(crate) fn set_vcpu_signal_mask(
    vcpu: std::os::fd::RawFd,
    mask: Option<KernelSigset>,
) -> Result<()> {
    let argument = mask.map(|mask| KvmSignalMask {
        len: std::mem::size_of::<KernelSigset>() as u32,
        sigset: mask.to_ne_bytes(),
    });
    let pointer = argument
        .as_ref()
        .map_or(std::ptr::null(), std::ptr::from_ref);
    count_syscall();
    // SAFETY: KVM reads `len`, then `len` bytes of the set, from the
    // initialized argument, which outlives the call; a null pointer makes it
    // read nothing.
    if unsafe { libc::ioctl(vcpu, KVM_SET_SIGNAL_MASK as _, pointer) } < 0 {
        return Err(host_failure("set the vCPU signal mask"));
    }
    Ok(())
}

/// Takes a kick left pending on the calling thread, without waiting: one
/// `rt_sigtimedwait` with a zero timeout. Returns whether there was one.
pub(crate) fn drain_kick() -> Result<bool> {
    let set = kernel_bit(KICK_SIGNAL);
    let zero = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    count_syscall();
    // SAFETY: the set and the timeout are initialized and outlive the call,
    // and a null info pointer asks for no siginfo.
    let taken = unsafe {
        libc::syscall(
            libc::SYS_rt_sigtimedwait,
            std::ptr::from_ref(&set),
            std::ptr::null_mut::<libc::siginfo_t>(),
            std::ptr::from_ref(&zero),
            std::mem::size_of::<KernelSigset>(),
        )
    };
    if taken == i64::from(KICK_SIGNAL) {
        #[cfg(test)]
        KICKS_DRAINED.with(|kicks| kicks.set(kicks.get() + 1));
        return Ok(true);
    }
    if taken < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN) {
        return Ok(false);
    }
    Err(host_failure("take a pending kick"))
}

fn query_kick_disposition() -> std::result::Result<usize, i32> {
    count_syscall();
    // SAFETY: the action storage is initialized and outlives the call.
    unsafe {
        let mut current: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(KICK_SIGNAL, std::ptr::null(), &mut current) != 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO));
        }
        Ok(current.sa_sigaction)
    }
}

/// Reserves [`KICK_SIGNAL`] for timer kicks and blocks it on the calling
/// thread, which is about to own a timer event. Returns the thread's signal
/// mask from just before, for the vCPU signal mask (see the module
/// documentation).
///
/// The first call in a process installs a handler that does nothing, with
/// `SA_RESTART`, and refuses with `EBUSY` if the signal already has a handler
/// or is ignored: it has another owner. The handler is never restored. Every
/// call checks that the installed handler is still in place, so a replacement
/// is refused at the next timer this process opens. The vCPU thread blocks
/// the signal, so a kick that arrives while it runs host code stays pending
/// and interrupts no host call. The handler is kept all the same: on a thread
/// that unblocks the signal again, a kick runs it rather than the default
/// action, which ends the process.
pub(crate) fn reserve_kick_signal() -> Result<KernelSigset> {
    static INSTALL: OnceLock<std::result::Result<usize, i32>> = OnceLock::new();
    let installed = *INSTALL.get_or_init(|| {
        if query_kick_disposition()? != libc::SIG_DFL {
            return Err(libc::EBUSY);
        }
        count_syscall();
        // SAFETY: the action storage is initialized and outlives the call;
        // the handler performs no allocation or locking.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = kick as *const () as usize;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(KICK_SIGNAL, &action, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO));
            }
            // The address passed to the kernel, which is what a later query
            // returns. In optimized builds the linker may fold this handler
            // with an identical one; re-deriving `kick as usize` could then
            // name a different symbol.
            Ok(action.sa_sigaction)
        }
    });
    let installed = installed.map_err(|errno| {
        failure(format!(
            "preemption timer: reserve host signal SIGSTKFLT: {}",
            std::io::Error::from_raw_os_error(errno)
        ))
    })?;
    match query_kick_disposition() {
        Ok(current) if current == installed => {}
        Ok(_) => {
            return Err(failure(
                "preemption timer: host signal SIGSTKFLT disposition changed",
            ));
        }
        Err(errno) => {
            return Err(failure(format!(
                "preemption timer: query host signal SIGSTKFLT: {}",
                std::io::Error::from_raw_os_error(errno)
            )));
        }
    }
    block_kick_signal()
}

/// The sampling event that kicks one guest thread's vCPU out of `KVM_RUN`
/// when it overflows. It counts what that thread's clock counts. Nothing
/// reads its count to decide anything.
pub(crate) struct TimerEvent {
    fd: Arc<OwnedFd>,
    enabled: bool,
    /// The clock value at which the current programming next overflows, while
    /// the clock has not reached it and the event has counted every branch
    /// the clock counted since the programming.
    overflow_at: Option<u64>,
    /// A finite period is programmed. The event reloads it after each
    /// overflow, so it keeps overflowing until it is reprogrammed.
    live: bool,
    /// The clock value at the entry that opened the event, from which its
    /// own count started.
    #[cfg(test)]
    pub(crate) opened_clock: u64,
}

/// What an entry must do to the timer event for the overflow it wants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Programming {
    /// Leave the event as it is.
    Keep,
    /// Program this period, counted from the entry's clock.
    Period(u64),
    /// Program [`QUIET_PERIOD`].
    Quiet,
}

/// The programming an entry at `clock` needs for an event that next
/// overflows at `overflow_at` and that counts and keeps overflowing when
/// `active` (enabled with a finite period), so that it overflows at `wanted`,
/// or never when `wanted` is None.
///
/// A pending overflow that comes no later than `wanted` is kept: the overflow
/// it causes only makes the backend look earlier than needed, while
/// reprogramming would cost a syscall now. A new period is never shorter than
/// [`MIN_PERIOD`] and never longer than [`MAX_PERIOD`]. A disabled event
/// cannot overflow, so it need not be quieted.
fn programming(
    clock: u64,
    wanted: Option<u64>,
    overflow_at: Option<u64>,
    active: bool,
) -> Programming {
    match wanted {
        Some(wanted) if overflow_at.is_some_and(|at| clock < at && at <= wanted) => {
            Programming::Keep
        }
        Some(wanted) => {
            Programming::Period(wanted.saturating_sub(clock).clamp(MIN_PERIOD, MAX_PERIOD))
        }
        None if active => Programming::Quiet,
        None => Programming::Keep,
    }
}

impl TimerEvent {
    /// Opens a disabled, quiet timer event for host task `tid` on `cpu` (-1
    /// for any CPU) with the clock's raw RCB encoding, owned by that task:
    /// each overflow sends it [`KICK_SIGNAL`]. Reserves the signal and blocks
    /// it on the calling thread, which must be `tid`, and returns that
    /// thread's signal mask from before, for the vCPU signal mask.
    pub(crate) fn open(
        tid: libc::pid_t,
        cpu: libc::c_int,
        raw_event: u64,
    ) -> Result<(Self, KernelSigset)> {
        let thread_mask = reserve_kick_signal()?;
        let mut attr = perf::perf_event_attr {
            type_: perf::PERF_TYPE_RAW,
            size: std::mem::size_of::<perf::perf_event_attr>() as u32,
            config: raw_event,
            ..Default::default()
        };
        attr.__bindgen_anon_1.sample_period = QUIET_PERIOD;
        attr.__bindgen_anon_2.wakeup_events = 1;
        // The clock's filter (CounterBinding::open): guest user mode only.
        attr.set_disabled(1);
        attr.set_pinned(1);
        attr.set_exclude_host(1);
        attr.set_exclude_guest(0);
        attr.set_exclude_kernel(1);
        attr.set_exclude_user(0);
        attr.set_exclude_hv(1);
        attr.set_inherit(0);
        count_syscall();
        // SAFETY: attr describes a sampling event for this actual host task;
        // the returned descriptor is newly owned. No group: see the module
        // documentation.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr,
                tid,
                cpu,
                -1,
                perf::PERF_FLAG_FD_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(host_failure(&format!(
                "perf_event_open tid {tid} cpu {cpu} event {raw_event:#x}"
            )));
        }
        // SAFETY: a newly returned descriptor that nothing else owns.
        let event = Self {
            fd: Arc::new(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) }),
            enabled: false,
            overflow_at: None,
            live: false,
            #[cfg(test)]
            opened_clock: 0,
        };
        // The event is disabled and quiet, so it cannot overflow before its
        // signal and owner are set. Each overflow then queues KICK_SIGNAL for
        // this task (si_code POLL_IN), not SIGIO for the process.
        let owner = FOwnerEx {
            type_: F_OWNER_TID,
            pid: tid,
        };
        let raw = event.fd.as_raw_fd();
        count_syscall();
        // SAFETY: fcntl on a live descriptor with an integer argument.
        if unsafe { libc::fcntl(raw, F_SETSIG, KICK_SIGNAL) } < 0 {
            return Err(host_failure("set overflow signal"));
        }
        count_syscall();
        // SAFETY: fcntl reads the initialized owner, which outlives the call.
        if unsafe { libc::fcntl(raw, F_SETOWN_EX, &owner as *const FOwnerEx) } < 0 {
            return Err(host_failure("set overflow signal owner"));
        }
        count_syscall();
        // SAFETY: fcntl on a live descriptor with an integer argument.
        if unsafe { libc::fcntl(raw, libc::F_SETFL, libc::O_ASYNC) } < 0 {
            return Err(host_failure("enable overflow signal"));
        }
        Ok((event, thread_mask))
    }

    pub(crate) fn fd(&self) -> &Arc<OwnedFd> {
        &self.fd
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    /// Another binding on this host task disabled the event, together with
    /// its clock, so that neither counts while another guest runs. The
    /// pending overflow stays valid while both stay disabled; an entry that
    /// runs the clock without enabling the event forgets it (see
    /// [`Self::prepare`]).
    pub(crate) fn mark_disabled(&mut self) {
        self.enabled = false;
    }

    fn set_period(&mut self, period: u64) -> Result<()> {
        let mut period = period;
        count_syscall();
        // The bindings take the period by value; the ioctl reads it through a
        // pointer.
        // SAFETY: the ioctl reads one u64 from initialized storage.
        if unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                perf::PERIOD as _,
                std::ptr::from_mut(&mut period),
            )
        } < 0
        {
            return Err(host_failure("program period"));
        }
        Ok(())
    }

    pub(crate) fn enable(&mut self) -> Result<()> {
        // Mark before the ioctl so even an ambiguous failure is cleaned up.
        self.enabled = true;
        count_syscall();
        // SAFETY: the descriptor is a live perf event.
        if unsafe { ioctls::ENABLE(self.fd.as_raw_fd(), 0) } < 0 {
            return Err(host_failure("enable"));
        }
        Ok(())
    }

    pub(crate) fn disable(&mut self) -> Result<()> {
        if self.enabled {
            count_syscall();
            // SAFETY: the descriptor is a live perf event.
            if unsafe { ioctls::DISABLE(self.fd.as_raw_fd(), 0) } < 0 {
                return Err(host_failure("disable"));
            }
            self.enabled = false;
        }
        Ok(())
    }

    /// Makes the event overflow at `wanted` (never, for None) for an entry at
    /// `clock`, with as few syscalls as [`programming`] allows, and enables it
    /// when it is wanted. With nothing wanted and nothing pending, issues none.
    ///
    /// An event left disabled for the entry misses every branch the entry
    /// retires, while the clock counts them, so its pending overflow no
    /// longer names a clock value. It is forgotten, and the next entry that
    /// wants an overflow programs one afresh.
    pub(crate) fn prepare(&mut self, clock: u64, wanted: Option<u64>) -> Result<()> {
        match programming(clock, wanted, self.overflow_at, self.enabled && self.live) {
            Programming::Keep => {}
            Programming::Period(period) => {
                self.set_period(period)?;
                self.overflow_at = Some(clock.saturating_add(period));
                self.live = true;
            }
            Programming::Quiet => {
                self.set_period(QUIET_PERIOD)?;
                self.overflow_at = None;
                self.live = false;
            }
        }
        if wanted.is_some() && !self.enabled {
            self.enable()?;
        }
        if !self.enabled {
            self.overflow_at = None;
        }
        Ok(())
    }

    /// Forgets a pending overflow that the clock read at an exit has reached.
    /// The event has overflowed and reloaded its period, so its next overflow
    /// is not one an entry relies on.
    pub(crate) fn observe_exit(&mut self, clock: u64) {
        if self.overflow_at.is_some_and(|at| clock >= at) {
            self.overflow_at = None;
        }
    }

    /// The pending overflow, for tests.
    #[cfg(test)]
    pub(crate) fn overflow_at(&self) -> Option<u64> {
        self.overflow_at
    }

    /// Records the clock value at the entry that opened the event, for tests.
    #[cfg(test)]
    pub(crate) fn opened_at(mut self, clock: u64) -> Self {
        self.opened_clock = clock;
        self
    }
}

/// Whether a request names an exact count, or any count from its target on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TimerKind {
    /// Due exactly when the clock reaches the target, as for
    /// `Guest::set_timer_precise`: single steps take the guest there.
    Precise,
    /// Due at the target or at any later count, as for `Guest::set_timer`.
    Imprecise,
}

/// A request whose target an exit reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TimerDue {
    /// The clock value the request named.
    pub(crate) target: u64,
    /// The clock value read at the exit that reached it.
    pub(crate) clock: u64,
    /// The exit came too late for the request: never for an imprecise one,
    /// and for a precise one unless it ended a single step that retired the
    /// target branch (see the module documentation). Any other exit at or
    /// past a precise target is late, even exactly at it.
    pub(crate) late: bool,
    /// The request's kind.
    pub(crate) kind: TimerKind,
}

/// The first stage of a staged precise request (see
/// [`reverie::pmu_config::PmuConfig::stages`]): when it was requested, by
/// the host's monotonic clock and by the guest's clock. The guest did not run
/// between the request and the entry that programmed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FirstStage {
    pub(crate) requested_ns: u64,
    pub(crate) requested_clock: u64,
}

/// The host's `CLOCK_MONOTONIC` in nanoseconds, read through the vDSO: no
/// syscall.
pub(crate) fn monotonic_ns() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the timespec is initialized and outlives the call.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    (now.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(now.tv_nsec as u64)
}

/// The one timer request of a guest thread, decided from its clock alone.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum TimerState {
    /// No request.
    #[default]
    Idle,
    /// A request whose target the clock has not reached.
    Armed {
        target: u64,
        kind: TimerKind,
        /// How far short of the target a precise request is programmed: the
        /// first stage margin while `first_stage` is present, then the second
        /// stage margin, or the PMU skid margin for an unstaged request. 0
        /// for an imprecise request, which is programmed at its target.
        margin: u64,
        /// Present while a staged precise request is in its first stage.
        first_stage: Option<FirstStage>,
    },
    /// A request whose target an exit reached. It stays here until it is
    /// delivered, replaced or cancelled, and is recorded only once.
    Due(TimerDue),
}

impl TimerState {
    /// An armed request due when the clock, now `clock`, has advanced `ticks`
    /// RCBs. `margin` is the margin a precise request is first programmed
    /// with, and `first_stage` is present for a staged one. A request for 0
    /// RCBs names the current count, which no exit can reach, and is refused,
    /// as is one past the clock's range.
    pub(crate) fn request(
        clock: u64,
        ticks: u64,
        kind: TimerKind,
        margin: u64,
        first_stage: Option<FirstStage>,
    ) -> Result<Self> {
        if ticks == 0 {
            return Err(failure(
                "preemption timer: a request for 0 RCBs names the current count",
            ));
        }
        let target = clock.checked_add(ticks).ok_or_else(|| {
            failure(format!(
                "preemption timer: {ticks} RCBs from {clock} overflows the clock"
            ))
        })?;
        Ok(Self::Armed {
            target,
            kind,
            margin,
            first_stage,
        })
    }

    /// The clock value at which the timer event should next overflow for an
    /// entry at `clock`, or None when nothing should kick the entry.
    ///
    /// A precise request more than one skid margin plus
    /// [`SINGLESTEP_TIMEOUT_RCBS`] short of its target is first programmed one
    /// margin short of it. Closer, and for an imprecise request, it is
    /// programmed at the target. The result is always at least
    /// [`MIN_PERIOD`] past `clock`, because Linux programs no shorter period.
    pub(crate) fn wanted_overflow(&self, clock: u64) -> Option<u64> {
        let Self::Armed {
            target,
            kind,
            margin,
            ..
        } = *self
        else {
            return None;
        };
        let point = match kind {
            TimerKind::Precise
                if target.saturating_sub(clock)
                    > margin.saturating_add(SINGLESTEP_TIMEOUT_RCBS) =>
            {
                target - margin
            }
            TimerKind::Precise | TimerKind::Imprecise => target,
        };
        Some(point.max(clock.saturating_add(MIN_PERIOD)))
    }

    /// Whether the next entry at `clock` must single-step toward a precise
    /// request's target: the clock is short of it by no more than the margin
    /// plus [`SINGLESTEP_TIMEOUT_RCBS`], the point from which the timer event
    /// is programmed at the target itself (see [`Self::wanted_overflow`]).
    pub(crate) fn stepping(&self, clock: u64) -> bool {
        matches!(
            *self,
            Self::Armed {
                target,
                kind: TimerKind::Precise,
                margin,
                first_stage: None,
            } if clock < target
                && target - clock <= margin.saturating_add(SINGLESTEP_TIMEOUT_RCBS)
        )
    }

    /// Decides the exit at which the clock read `clock`. `stepped` says the
    /// entry it ended ran a single step. An armed request whose target the
    /// clock reached becomes due; a precise one is on time only when a single
    /// step retired the target branch, so that the vCPU stands at the
    /// boundary right after it, and any other is recorded as late. A staged
    /// request whose first stage the clock reached gets its second stage
    /// margin, from the RCBs and the host time since it was requested.
    /// Returns the request this exit made due, at most once.
    pub(crate) fn observe_exit(&mut self, clock: u64, stepped: bool) -> Option<TimerDue> {
        let Self::Armed {
            target,
            kind,
            margin,
            first_stage,
        } = *self
        else {
            return None;
        };
        if clock < target {
            if let Some(first) = first_stage
                && clock >= target - margin
                && let Some(config) = reverie::pmu_config::try_get_pmu_config()
            {
                let elapsed = monotonic_ns().saturating_sub(first.requested_ns);
                *self = Self::Armed {
                    target,
                    kind,
                    margin: config
                        .second_stage_margin(clock - first.requested_clock, Some(elapsed)),
                    first_stage: None,
                };
            }
            return None;
        }
        let due = TimerDue {
            target,
            clock,
            late: matches!(kind, TimerKind::Precise) && !(stepped && clock == target),
            kind,
        };
        if due.late {
            record_late(&due);
        }
        *self = Self::Due(due);
        Some(due)
    }

    /// The target of an armed or due request.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only tests read the target until a backend delivers timer events"
        )
    )]
    pub(crate) fn target(&self) -> Option<u64> {
        match *self {
            Self::Idle => None,
            Self::Armed { target, .. } => Some(target),
            Self::Due(due) => Some(due.target),
        }
    }

    /// The request an exit made due, while it is not delivered, replaced or
    /// cancelled.
    pub(crate) fn due(&self) -> Option<TimerDue> {
        match *self {
            Self::Due(due) => Some(due),
            Self::Idle | Self::Armed { .. } => None,
        }
    }

    /// Takes the due request for delivery and leaves no request, so that it
    /// is delivered once and a request made while it is handled is a new one.
    pub(crate) fn take_due(&mut self) -> Option<TimerDue> {
        let due = self.due()?;
        *self = Self::Idle;
        Some(due)
    }

    /// Arms a due imprecise request again at its own target, for an exit that
    /// found it due where it cannot be delivered. The clock has reached the
    /// target, so the next entry programs the earliest overflow the event
    /// allows, [`MIN_PERIOD`] RCBs on (see [`Self::wanted_overflow`]), and the
    /// next exit finds the request due again, still on time. A late precise
    /// request is armed the same way, as an imprecise one: it was recorded
    /// once, when it came due, and only its delivery remains. A precise one
    /// on time was made due by a single step, which leaves the vCPU in user
    /// mode, where it is delivered.
    pub(crate) fn defer_due(&mut self) {
        if let Self::Due(TimerDue {
            target, kind, late, ..
        }) = *self
            && (kind == TimerKind::Imprecise || late)
        {
            *self = Self::Armed {
                target,
                kind: TimerKind::Imprecise,
                margin: 0,
                first_stage: None,
            };
        }
    }
}

/// Whether the exception frame the guest's stub will halt with holds a single
/// step's trap flag: the stepped instruction faulted, and the CPU saved
/// RFLAGS with TF set. It is kept from the stepped entry until that stub's
/// HLT, whatever the entries in between ran: a host interrupt can end the
/// stepped entry inside the stub, before its HLT, and the entry that runs the
/// stub on is not stepped.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SteppedFault(bool);

impl SteppedFault {
    /// Notes a stepped entry that a host signal interrupted, with the vCPU
    /// found in ring 0 or not: only a fault takes a stepped instruction there.
    pub(crate) fn interrupted(&mut self, in_ring_0: bool) {
        self.0 |= in_ring_0;
    }

    /// At an exception stub's HLT, whether its frame must lose TF: a stepped
    /// entry pushed it, this one (`stepped`) or an interrupted one before it.
    pub(crate) fn take_at_halt(&mut self, stepped: bool) -> bool {
        std::mem::take(&mut self.0) || stepped
    }
}

/// The RCB count `Guest::set_timer` requests for `TimerSchedule::Time`,
/// converted as reverie-ptrace converts it (`Timer::as_ticks`): 0.6 RCB per
/// nanosecond, from its assumptions of 10% conditional branches, 3 GHz and 2
/// instructions per cycle. `TimerSchedule::Time` makes the conversion best
/// effort. Where reverie-ptrace's arithmetic would overflow, this saturates.
pub(crate) fn rcbs_for_duration(duration: std::time::Duration) -> u64 {
    duration
        .as_secs()
        .saturating_mul(600_000_000)
        .saturating_add(u64::from(duration.subsec_nanos()) * 6 / 10)
}

/// Records a late precise request with the canonical marker and the
/// process-global witness count. It uses the recorder that counts an arrival
/// at exactly the target, `record_missed_if_target_reached`: an asynchronous
/// exit at the target may already be past its delivery point, the boundary
/// right after the target branch.
fn record_late(due: &TimerDue) {
    match reverie::pmu_config::try_get_pmu_config() {
        Some(config) => {
            config.record_missed_if_target_reached(due.clock, due.target, 0);
        }
        // A request takes its margin from this configuration, so it exists
        // whenever a request was armed. Should it not, keep the witness.
        None => reverie::record_skid_overshoot(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARGIN: u64 = 2_000;

    fn armed(target: u64, kind: TimerKind) -> TimerState {
        TimerState::Armed {
            target,
            kind,
            margin: MARGIN,
            first_stage: None,
        }
    }

    #[test]
    fn requests_name_a_count_ahead_of_the_clock() {
        assert_eq!(
            TimerState::request(10, 5, TimerKind::Precise, MARGIN, None).unwrap(),
            armed(15, TimerKind::Precise)
        );
        assert!(
            TimerState::request(10, 0, TimerKind::Imprecise, MARGIN, None)
                .unwrap_err()
                .to_string()
                .contains("0 RCBs")
        );
        assert!(
            TimerState::request(u64::MAX - 1, 2, TimerKind::Precise, MARGIN, None)
                .unwrap_err()
                .to_string()
                .contains("overflows")
        );
    }

    #[test]
    fn precise_requests_are_programmed_one_margin_short_until_close() {
        let target = 100_000;
        let state = armed(target, TimerKind::Precise);
        // Far from the target: one margin short of it.
        assert_eq!(state.wanted_overflow(0), Some(target - MARGIN));
        let edge = target - MARGIN - SINGLESTEP_TIMEOUT_RCBS;
        assert_eq!(state.wanted_overflow(edge - 1), Some(target - MARGIN));
        // Within the margin plus the single-step allowance: at the target.
        assert_eq!(state.wanted_overflow(edge), Some(target));
        assert_eq!(state.wanted_overflow(target - 2), Some(target));
        // One short: Linux's shortest period lands one past the target.
        assert_eq!(state.wanted_overflow(target - 1), Some(target + 1));
        // Imprecise requests are always programmed at the target.
        let state = armed(target, TimerKind::Imprecise);
        assert_eq!(state.wanted_overflow(0), Some(target));
        assert_eq!(state.wanted_overflow(target - 1), Some(target + 1));
        // Nothing is wanted without an armed request.
        assert_eq!(TimerState::Idle.wanted_overflow(0), None);
        let due = TimerState::Due(TimerDue {
            target,
            clock: target,
            late: true,
            kind: TimerKind::Precise,
        });
        assert_eq!(due.wanted_overflow(target), None);
    }

    #[test]
    fn exits_decide_from_the_clock_and_record_a_late_precise_request_once() {
        // The witness count is process-global: take the turn every test that
        // reads it takes, so that a parallel `cargo test` cannot interleave.
        let _turn = witness_turn();
        let config = reverie::pmu_config::try_get_pmu_config();
        let mut state = armed(1_000, TimerKind::Precise);
        // Short of the target: nothing changes and nothing is recorded.
        assert_eq!(state.observe_exit(999, false), None);
        assert_eq!(state, armed(1_000, TimerKind::Precise));
        // Exactly at the target: late, because an exit is asynchronous.
        let due = TimerDue {
            target: 1_000,
            clock: 1_000,
            late: true,
            kind: TimerKind::Precise,
        };
        assert_eq!(state.observe_exit(1_000, false), Some(due));
        assert_eq!(state.due(), Some(due));
        assert_eq!(state.target(), Some(1_000));
        // Later exits find it already due and record nothing more.
        assert_eq!(state.observe_exit(5_000, false), None);
        assert_eq!(state.due(), Some(due));
        // Past the target: late, with the overshoot the clock shows.
        let mut past = armed(1_000, TimerKind::Precise);
        assert_eq!(
            past.observe_exit(1_007, false),
            Some(TimerDue {
                target: 1_000,
                clock: 1_007,
                late: true,
                kind: TimerKind::Precise,
            })
        );
        // An imprecise request reached at or after its target is on time.
        let mut imprecise = armed(1_000, TimerKind::Imprecise);
        assert_eq!(
            imprecise.observe_exit(1_000, false),
            Some(TimerDue {
                target: 1_000,
                clock: 1_000,
                late: false,
                kind: TimerKind::Imprecise,
            })
        );
        let witnessed = reverie::take_skid_overshoot_count();
        assert_eq!(witnessed, 2, "one witness per late precise request");
        if let Some(config) = config {
            assert_eq!(
                config.format_skid_overshoot_marker(1_000, 1_000),
                format!(
                    "{} rcb_actual=1000 rcb_target=1000 skid_margin={} overshoot=0",
                    reverie::SKID_OVERSHOOT_MARKER,
                    config.skid_margin()
                )
            );
        }
    }

    #[test]
    fn a_due_request_is_taken_once_or_armed_again_at_its_target() {
        let _turn = witness_turn();
        let mut state = TimerState::Armed {
            target: 1_000,
            kind: TimerKind::Imprecise,
            margin: 0,
            first_stage: None,
        };
        assert_eq!(state.take_due(), None, "an armed request is not due");
        assert_eq!(state.observe_exit(1_004, false), due_at(1_000, 1_004));
        // Found due where it cannot be delivered: armed again at its target,
        // and the next entry wants the earliest overflow past the clock.
        state.defer_due();
        assert_eq!(
            state,
            TimerState::Armed {
                target: 1_000,
                kind: TimerKind::Imprecise,
                margin: 0,
                first_stage: None,
            }
        );
        assert_eq!(state.wanted_overflow(1_004), Some(1_004 + MIN_PERIOD));
        // The next exit finds it due again, on time, and delivery takes it.
        assert_eq!(state.observe_exit(1_006, false), due_at(1_000, 1_006));
        assert_eq!(state.take_due(), due_at(1_000, 1_006));
        assert_eq!(state, TimerState::Idle);
        assert_eq!(state.take_due(), None, "a request is delivered once");
        assert_eq!(state.wanted_overflow(1_006), None);
        // A late precise request, recorded once when it came due, is armed
        // again the same way, and its delivery records nothing more.
        let mut precise = armed(1_000, TimerKind::Precise);
        assert!(precise.observe_exit(1_000, false).unwrap().late);
        assert_eq!(reverie::take_skid_overshoot_count(), 1);
        precise.defer_due();
        assert_eq!(precise.wanted_overflow(1_000), Some(1_000 + MIN_PERIOD));
        assert_eq!(precise.observe_exit(1_003, false), due_at(1_000, 1_003));
        assert_eq!(reverie::take_skid_overshoot_count(), 0);
        // One on time stays due, for delivery in user mode.
        let mut precise = armed(1_000, TimerKind::Precise);
        let on_time = precise.observe_exit(1_000, true);
        precise.defer_due();
        assert_eq!(precise.due(), on_time);
    }

    #[test]
    fn a_stepped_fault_frame_is_scrubbed_at_its_halt_across_interruptions() {
        // A stepped entry that reaches the stub's HLT.
        assert!(SteppedFault::default().take_at_halt(true));
        // Interrupted in the stub, then run on unstepped to its HLT, which
        // scrubs once.
        let mut fault = SteppedFault::default();
        fault.interrupted(true);
        assert!(fault.take_at_halt(false));
        assert!(!fault.take_at_halt(false));
        // Interrupted in user mode, before its instruction ran: no frame.
        let mut fault = SteppedFault::default();
        fault.interrupted(false);
        assert!(!fault.take_at_halt(false));
    }

    fn due_at(target: u64, clock: u64) -> Option<TimerDue> {
        Some(TimerDue {
            target,
            clock,
            late: false,
            kind: TimerKind::Imprecise,
        })
    }

    #[test]
    fn a_precise_request_is_stepped_within_its_margin_and_on_time_only_after_a_step() {
        let _turn = witness_turn();
        let target = 100_000;
        let state = armed(target, TimerKind::Precise);
        let edge = target - MARGIN - SINGLESTEP_TIMEOUT_RCBS;
        // Stepped from the point at which the event is programmed at the target.
        assert!(!state.stepping(edge - 1));
        assert!(state.stepping(edge));
        assert!(state.stepping(target - 1));
        assert!(!state.stepping(target));
        // Never an imprecise request, nor one in its first stage.
        assert!(!armed(target, TimerKind::Imprecise).stepping(target - 1));
        let staged = TimerState::Armed {
            target,
            kind: TimerKind::Precise,
            margin: MARGIN,
            first_stage: Some(FirstStage {
                requested_ns: 0,
                requested_clock: 0,
            }),
        };
        assert!(!staged.stepping(target - 1));
        // A step that retires the target branch makes it due on time and
        // records nothing; a step can retire one branch at most, so it never
        // passes the target, and anything else at the target is late.
        let mut stepped = armed(target, TimerKind::Precise);
        assert_eq!(stepped.observe_exit(target - 1, true), None);
        assert_eq!(
            stepped.observe_exit(target, true),
            Some(TimerDue {
                target,
                clock: target,
                late: false,
                kind: TimerKind::Precise,
            })
        );
        let mut overshot = armed(target, TimerKind::Precise);
        assert!(overshot.observe_exit(target + 1, true).unwrap().late);
        assert_eq!(reverie::take_skid_overshoot_count(), 1);
    }

    #[test]
    fn a_staged_request_takes_its_second_stage_margin_once_its_first_stage_is_reached() {
        let Some(config) = reverie::pmu_config::try_get_pmu_config() else {
            println!("NOT EXECUTED: this CPU has no PMU profile");
            return;
        };
        let first = config.first_stage_margin();
        let target = 1_000_000;
        let mut state = TimerState::Armed {
            target,
            kind: TimerKind::Precise,
            margin: first,
            first_stage: Some(FirstStage {
                requested_ns: monotonic_ns(),
                requested_clock: 0,
            }),
        };
        // Short of the first stage point: still in the first stage.
        assert_eq!(state.wanted_overflow(0), Some(target - first));
        assert_eq!(state.observe_exit(target - first - 1, false), None);
        assert!(matches!(
            state,
            TimerState::Armed {
                first_stage: Some(_),
                ..
            }
        ));
        // At it: the second stage margin, between the skid margin and the
        // first stage margin, sized by the guest's rate since the request.
        assert_eq!(state.observe_exit(target - first, false), None);
        let TimerState::Armed {
            margin,
            first_stage: None,
            ..
        } = state
        else {
            panic!("still in the first stage: {state:?}");
        };
        assert!((config.skid_margin()..=first).contains(&margin), "{margin}");
    }

    #[test]
    fn durations_convert_to_rcbs_as_reverie_ptrace_converts_them() {
        assert_eq!(rcbs_for_duration(std::time::Duration::ZERO), 0);
        assert_eq!(rcbs_for_duration(std::time::Duration::from_nanos(10)), 6);
        assert_eq!(
            rcbs_for_duration(std::time::Duration::new(2, 500)),
            1_200_000_300
        );
        assert_eq!(rcbs_for_duration(std::time::Duration::MAX), u64::MAX);
    }

    #[test]
    fn programming_is_lazy() {
        // Nothing wanted and nothing pending: no syscall.
        assert_eq!(programming(5, None, None, false), Programming::Keep);
        // Nothing wanted, but an active finite period: quiet it once.
        assert_eq!(programming(5, None, Some(9), true), Programming::Quiet);
        assert_eq!(programming(5, None, None, true), Programming::Quiet);
        // A disabled event cannot overflow, so it is left alone.
        assert_eq!(programming(5, None, Some(9), false), Programming::Keep);
        // No pending overflow: program one.
        assert_eq!(
            programming(5, Some(105), None, true),
            Programming::Period(100)
        );
        // A pending overflow at or before the wanted point is kept, so an
        // unchanged target costs no syscall.
        assert_eq!(
            programming(5, Some(105), Some(105), true),
            Programming::Keep
        );
        assert_eq!(
            programming(5, Some(205), Some(105), true),
            Programming::Keep
        );
        // A pending overflow later than wanted, or already reached, is
        // reprogrammed from the entry's clock.
        assert_eq!(
            programming(5, Some(105), Some(106), true),
            Programming::Period(100)
        );
        assert_eq!(
            programming(105, Some(205), Some(105), true),
            Programming::Period(100)
        );
        // Never shorter than Linux's shortest period.
        assert_eq!(
            programming(5, Some(6), None, true),
            Programming::Period(MIN_PERIOD)
        );
        // Never longer than the longest period programmed at once: a farther
        // overflow is programmed in pieces. Linux refuses bit 63 outright.
        assert_eq!(
            programming(5, Some(5 + MAX_PERIOD), None, true),
            Programming::Period(MAX_PERIOD)
        );
        assert_eq!(
            programming(5, Some(5 + MAX_PERIOD + 1), None, true),
            Programming::Period(MAX_PERIOD)
        );
        assert_eq!(
            programming(0, Some(1 << 63), None, true),
            Programming::Period(MAX_PERIOD)
        );
        assert_eq!(
            programming(0, Some(u64::MAX), None, true),
            Programming::Period(MAX_PERIOD)
        );
        const { assert!(MAX_PERIOD & (1 << 63) == 0) };
        // A piece is kept until the clock reaches it, then the next follows.
        assert_eq!(
            programming(5, Some(u64::MAX), Some(5 + MAX_PERIOD), true),
            Programming::Keep
        );
        assert_eq!(
            programming(5 + MAX_PERIOD, Some(u64::MAX), Some(5 + MAX_PERIOD), true),
            Programming::Period(MAX_PERIOD)
        );
    }

    fn current_mask() -> libc::sigset_t {
        // SAFETY: initialized writable storage; this query changes no mask.
        unsafe {
            let mut mask = std::mem::zeroed();
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask),
                0
            );
            mask
        }
    }

    fn blocked(signal: libc::c_int) -> bool {
        // SAFETY: a valid initialized set.
        unsafe { libc::sigismember(&current_mask(), signal) == 1 }
    }

    /// The calling thread's whole kernel signal mask.
    fn raw_mask() -> KernelSigset {
        let mut mask: KernelSigset = 0;
        // SAFETY: a query into an initialized kernel sigset of the size passed.
        let queried = unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_BLOCK,
                std::ptr::null::<KernelSigset>(),
                std::ptr::from_mut(&mut mask),
                std::mem::size_of::<KernelSigset>(),
            )
        };
        assert_eq!(queried, 0);
        mask
    }

    fn unblock_kick_signal_here() {
        // SAFETY: valid set storage; affects only this thread.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, KICK_SIGNAL);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()),
                0
            );
        }
    }

    #[test]
    fn the_vcpu_signal_mask_is_the_thread_mask_without_the_kick_signal() {
        let kick = kernel_bit(KICK_SIGNAL);
        assert_eq!(kick, 1 << 15, "SIGSTKFLT is signal 16");
        for thread_mask in [0, kick, u64::MAX, !kick, 1 << 63 | 1 << 22 | kick] {
            assert_eq!(vcpu_signal_mask(thread_mask), thread_mask & !kick);
        }
        // Signal 64, the entry signal, and SIGURG keep the thread's state.
        let entry = kernel_bit(64);
        let urg = kernel_bit(libc::SIGURG);
        assert_eq!(vcpu_signal_mask(entry | urg | kick), entry | urg);
        assert_eq!(vcpu_signal_mask(kick), 0);
        assert_eq!(std::mem::size_of::<KvmSignalMask>(), 12);
        assert_eq!(std::mem::offset_of!(KvmSignalMask, sigset), 4);
        assert_eq!(KVM_SET_SIGNAL_MASK, 0x4004_ae8b);
    }

    extern "C" fn foreign_handler(_: libc::c_int) {}

    fn set_disposition(handler: usize) {
        // SAFETY: initialized action storage.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler;
            libc::sigemptyset(&mut action.sa_mask);
            assert_eq!(
                libc::sigaction(KICK_SIGNAL, &action, std::ptr::null_mut()),
                0
            );
        }
    }

    #[test]
    fn kick_signal_reservation_is_idempotent_and_refuses_other_owners() {
        const CHILD: &str = "REVERIE_KVM_KICK_SIGNAL_CHILD";
        const TEST: &str = "preemption_timer::tests::kick_signal_reservation_is_idempotent_and_refuses_other_owners";
        let Ok(case) = std::env::var(CHILD) else {
            // Dispositions are process-wide: each case runs in a fresh
            // process so it cannot alter the parallel test runner.
            for case in ["repeated", "foreign", "ignored", "replaced"] {
                let output = std::process::Command::new("timeout")
                    .args(["--kill-after=2s", "20s"])
                    .arg(std::env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                    .env(CHILD, case)
                    .output()
                    .unwrap();
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(
                    output.status.success(),
                    "{case}: {}{}",
                    stdout,
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    stdout.contains(&format!("kick signal case {case}: passed")),
                    "{case} must execute in the child: {stdout}"
                );
            }
            return;
        };
        match case.as_str() {
            "repeated" => {
                unblock_kick_signal_here();
                let mask = raw_mask();
                assert_eq!(mask & kernel_bit(KICK_SIGNAL), 0);
                // Reservation blocks the caller's kick signal and returns the
                // caller's mask from before.
                assert_eq!(reserve_kick_signal().unwrap(), mask);
                assert!(blocked(KICK_SIGNAL), "reservation blocks the caller");
                assert_eq!(
                    raw_mask(),
                    mask | kernel_bit(KICK_SIGNAL),
                    "reservation changes nothing else"
                );
                // Not compared with `kick as usize`: the linker may fold the
                // handler with an identical function (see reserve_kick_signal).
                let installed = query_kick_disposition().unwrap();
                assert_ne!(installed, libc::SIG_DFL);
                assert_ne!(installed, libc::SIG_IGN);
                // Again, with the signal blocked already.
                assert_eq!(
                    reserve_kick_signal().unwrap(),
                    mask | kernel_bit(KICK_SIGNAL)
                );
                assert!(blocked(KICK_SIGNAL));
                assert_eq!(query_kick_disposition().unwrap(), installed);
                // Another thread reserves too, and blocks it on itself.
                std::thread::spawn(move || {
                    unblock_kick_signal_here();
                    reserve_kick_signal().unwrap();
                    assert!(blocked(KICK_SIGNAL));
                    assert_eq!(query_kick_disposition().unwrap(), installed);
                })
                .join()
                .unwrap();
                // A kick blocked here stays pending, and the drain takes it.
                // SAFETY: a thread-directed signal to this thread.
                assert_eq!(
                    unsafe { libc::pthread_kill(libc::pthread_self(), KICK_SIGNAL) },
                    0
                );
                assert!(drain_kick().unwrap());
                assert!(!drain_kick().unwrap(), "one kick, taken once");
                // On a thread that unblocks the signal again, the empty
                // handler takes a kick: it never kills the process.
                unblock_kick_signal_here();
                let before =
                    KICKS_TAKEN.with(|kicks| kicks.load(std::sync::atomic::Ordering::Relaxed));
                // SAFETY: a thread-directed signal to this thread.
                assert_eq!(
                    unsafe { libc::pthread_kill(libc::pthread_self(), KICK_SIGNAL) },
                    0
                );
                let after =
                    KICKS_TAKEN.with(|kicks| kicks.load(std::sync::atomic::Ordering::Relaxed));
                assert_eq!(after, before + 1);
            }
            "foreign" | "ignored" => {
                let handler = if case == "ignored" {
                    libc::SIG_IGN
                } else {
                    foreign_handler as *const () as usize
                };
                set_disposition(handler);
                let error = reserve_kick_signal().unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains(&std::io::Error::from_raw_os_error(libc::EBUSY).to_string()),
                    "{error}"
                );
                assert_eq!(query_kick_disposition().unwrap(), handler);
                // The refusal is remembered: a second call refuses as well.
                assert!(reserve_kick_signal().is_err());
            }
            "replaced" => {
                reserve_kick_signal().unwrap();
                set_disposition(foreign_handler as *const () as usize);
                let error = reserve_kick_signal().unwrap_err();
                assert!(error.to_string().contains("disposition changed"), "{error}");
                assert_eq!(
                    query_kick_disposition().unwrap(),
                    foreign_handler as *const () as usize
                );
            }
            other => panic!("unknown case {other}"),
        }
        println!("kick signal case {case}: passed");
    }
}
