// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

//! Signal phase 1, the runtime's half: the guest's virtual SIGALRM action and
//! signal mask (dev-hermit
//! `ai_docs/transient/liteinst-inguest-signal-handlers-design-20261007.md`,
//! sections 3, 5 and 6; step I3b).
//!
//! While a guest SIGALRM handler is installed ("handled"), the guest never
//! sees the physical state:
//! - the physical SIGALRM action is the runtime's trampoline, returning
//!   through the runtime's restorer; the guest's action is virtual, and is
//!   what queries return;
//! - the physical mask always blocks SIGALRM, so no physical SIGALRM reaches
//!   guest code outside a delivery the runtime prepared; the guest's mask is
//!   virtual: physical = (virtual ∪ {SIGALRM}) minus the reserved signals;
//! - `rt_sigpending` hides the physical SIGALRM (the scheduler's ledger, not
//!   the kernel, holds a handled process's pending SIGALRM; Detcore adds it);
//! - a `sigaltstack` query returns a disabled stack.
//!
//! The state is per process. Phase 1's in-guest processes have one thread
//! (a non-fork clone is refused), so the process's virtual mask is that
//! thread's; a fork child inherits all of it with the memory.
//!
//! Everything here runs inside the guest call's own turn, from the call
//! Detcore forwards, never concurrently.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use crate::guest::restorer;
use crate::guest::support::KernelSigaction;
use crate::signal::SA_RESTORER;
use crate::signal::raw_sigaction;
use crate::signal::raw_sigprocmask;
use crate::trap::raw_syscall6;

const SIGSET_SIZE: u64 = core::mem::size_of::<u64>() as u64;

/// SIGALRM's bit in a kernel signal set.
pub const SIGALRM_BIT: u64 = 1 << (libc::SIGALRM - 1);

/// Linux never blocks these; every mask the runtime records drops them.
const UNBLOCKABLE: u64 = (1 << (libc::SIGKILL - 1)) | (1 << (libc::SIGSTOP - 1));

/// The kernel's `SA_EXPOSE_TAGBITS` (part of `UAPI_SA_FLAGS` on every
/// architecture; the libc crate does not export it).
const SA_EXPOSE_TAGBITS: u32 = 0x0000_0800;

/// The action flags Linux keeps (`UAPI_SA_FLAGS` with x86-64's
/// `SA_RESTORER`); it clears every other bit of a new action, so a guest can
/// probe for an unsupported flag. Built from unsigned values: `SA_RESETHAND`
/// is negative as a C `int`.
pub const UAPI_SA_FLAGS: u64 = (libc::SA_NOCLDSTOP as u32
    | libc::SA_NOCLDWAIT as u32
    | libc::SA_SIGINFO as u32
    | libc::SA_ONSTACK as u32
    | libc::SA_RESTART as u32
    | libc::SA_NODEFER as u32
    | libc::SA_RESETHAND as u32
    | SA_EXPOSE_TAGBITS
    | SA_RESTORER as u32) as u64;

/// The flags phase 1 refuses on a SIGALRM handler.
const REFUSED_SA_FLAGS: u64 = (libc::SA_RESETHAND as u32 | libc::SA_NODEFER as u32) as u64;

/// The exit status when the runtime cannot undo a half-made change to the
/// physical SIGALRM state (a guest seccomp filter refused the undo), or a
/// guest call's frame shows physical signal state the runtime did not set
/// ([`check_entry_frame`]).
pub const SIGNAL_STATE_LOST_STATUS: i32 = 116;

/// The exit status when a SIGALRM reaches the trampoline without a delivery
/// the runtime prepared.
pub const UNPREPARED_SIGALRM_STATUS: i32 = 117;

static ADMITTED: AtomicBool = AtomicBool::new(false);
static HANDLED: AtomicBool = AtomicBool::new(false);

/// Admit guest SIGALRM handlers in this process (the backend decides, once,
/// at initialization: phase 1's Tool mode with site patching off). A fork
/// child inherits the decision.
pub fn set_admitted(admitted: bool) {
    ADMITTED.store(admitted, Ordering::Release);
}

/// Whether guest SIGALRM handlers are admitted in this process.
pub fn admitted() -> bool {
    ADMITTED.load(Ordering::Acquire)
}

/// The process's seccomp filter count once the runtime's own filter is in
/// place; 0 until recorded.
static FILTER_BASELINE: AtomicU64 = AtomicU64::new(0);

/// Record the process's seccomp filter count right after the runtime
/// installed its own filter. While handlers are admitted the guest cannot add
/// a filter (the runtime refuses it), and a handler is admitted only while
/// the count still equals this: so no guest filter can fabricate the result
/// of the runtime's own signal calls (a `SECCOMP_RET_ERRNO` of 0 reports
/// success without running the call).
pub fn record_filter_baseline() -> std::io::Result<()> {
    let count = unsafe { seccomp_filter_count() }
        .ok_or_else(|| std::io::Error::other("cannot read Seccomp_filters"))?;
    FILTER_BASELINE.store(count, Ordering::Release);
    Ok(())
}

/// Parse a `/proc/self/status` `Seccomp_filters:` line.
pub fn seccomp_filters_line(line: &[u8]) -> Option<u64> {
    let rest = line.strip_prefix(b"Seccomp_filters:")?;
    let digits: Vec<u8> = rest
        .iter()
        .copied()
        .skip_while(|byte| *byte == b' ' || *byte == b'\t')
        .take_while(u8::is_ascii_digit)
        .collect();
    core::str::from_utf8(&digits).ok()?.parse().ok()
}

/// Whether any of this process's memory has a protection key other than 0
/// (a `ProtectionKey:` line of `/proc/self/smaps`); `None` if it cannot be
/// read. Signal phase 1 admits handlers only where every buffer has key 0,
/// whose rights the runtime applies itself ([`GuestRights`]).
///
/// # Safety
///
/// Issues raw syscalls through the trusted gate.
pub unsafe fn protection_keys_in_use() -> Option<bool> {
    unsafe { protection_keys_in_use_in(c"/proc/self/smaps") }
}

/// [`protection_keys_in_use`] over the smaps-format file at `path`: `None`
/// unless the whole file was read.
unsafe fn protection_keys_in_use_in(path: &core::ffi::CStr) -> Option<bool> {
    let scan = unsafe {
        crate::guest::support::scan_proc_lines_checked(path, |line| {
            let rest = line.strip_prefix(b"ProtectionKey:")?;
            let key = core::str::from_utf8(rest)
                .ok()?
                .trim()
                .parse::<u64>()
                .ok()?;
            (key != 0).then_some(())
        })
    };
    scan.ok().map(|found| found.is_some())
}

/// This process's seccomp filter count, from `/proc/self/status`.
///
/// # Safety
///
/// Issues raw syscalls through the trusted gate.
pub unsafe fn seccomp_filter_count() -> Option<u64> {
    unsafe { crate::guest::support::scan_proc_lines(c"/proc/self/status", seccomp_filters_line) }
}

/// Whether the process still has only the filters it had when the runtime
/// recorded its baseline.
fn filters_are_the_runtimes() -> bool {
    let baseline = FILTER_BASELINE.load(Ordering::Acquire);
    baseline != 0 && unsafe { seccomp_filter_count() } == Some(baseline)
}

/// Whether `rt_sigaction(args)` installs a SIGALRM action this module
/// decides: the runtime's guards must let it through to [`intercept`].
pub fn decides_action(number: i64, args: [u64; 6]) -> bool {
    // Linux reads the signal argument as a C int.
    number == libc::SYS_rt_sigaction && args[0] as i32 == libc::SIGALRM && admitted()
}
static VIRTUAL_HANDLER: AtomicU64 = AtomicU64::new(0);
static VIRTUAL_FLAGS: AtomicU64 = AtomicU64::new(0);
static VIRTUAL_RESTORER: AtomicU64 = AtomicU64::new(0);
static VIRTUAL_ACTION_MASK: AtomicU64 = AtomicU64::new(0);
static VIRTUAL_MASK: AtomicU64 = AtomicU64::new(0);

/// Whether a guest SIGALRM handler is installed in this process.
pub fn handled() -> bool {
    HANDLED.load(Ordering::Acquire)
}

/// The guest's virtual signal mask; meaningful while [`handled`].
pub fn virtual_mask() -> u64 {
    VIRTUAL_MASK.load(Ordering::Acquire)
}

fn virtual_action() -> KernelSigaction {
    KernelSigaction {
        handler: VIRTUAL_HANDLER.load(Ordering::Acquire),
        flags: VIRTUAL_FLAGS.load(Ordering::Acquire),
        restorer: VIRTUAL_RESTORER.load(Ordering::Acquire),
        mask: VIRTUAL_ACTION_MASK.load(Ordering::Acquire),
    }
}

fn set_virtual_action(action: &KernelSigaction) {
    VIRTUAL_HANDLER.store(action.handler, Ordering::Release);
    VIRTUAL_FLAGS.store(action.flags, Ordering::Release);
    VIRTUAL_RESTORER.store(action.restorer, Ordering::Release);
    VIRTUAL_ACTION_MASK.store(action.mask, Ordering::Release);
}

/// The physical mask for a virtual mask while SIGALRM is handled (`handled`
/// true) or not, without the runtime's reserved signals.
pub fn physical_mask(virtual_mask: u64, handled: bool, reserved: u64) -> u64 {
    let alarm = if handled { SIGALRM_BIT } else { 0 };
    ((virtual_mask | alarm) & !reserved) & !UNBLOCKABLE
}

/// The physical action for an admitted guest SIGALRM action: the trampoline,
/// `SA_SIGINFO`, the runtime's restorer, the guest's `SA_RESTART` only, and
/// a mask of the guest's `sa_mask` plus SIGALRM, without the reserved
/// signals. `SA_ONSTACK` is never set: phase 1 refuses a guest stack.
pub fn physical_action(guest: &KernelSigaction, trampoline: u64, reserved: u64) -> KernelSigaction {
    KernelSigaction {
        handler: trampoline,
        flags: (libc::SA_SIGINFO | SA_RESTORER) as u64 | (guest.flags & libc::SA_RESTART as u64),
        restorer: crate::signal::signal_restorer(),
        mask: physical_mask(guest.mask, true, reserved),
    }
}

/// Why phase 1 refuses a guest SIGALRM handler, before anything changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandlerRefusal {
    /// `SA_RESETHAND` or `SA_NODEFER`.
    UnsupportedFlags,
    /// No `SA_RESTORER`, or a restorer that is not glibc's `__restore_rt`.
    Restorer,
}

/// Phase 1's checks on a new guest SIGALRM handler's own fields (design
/// section 6, step 2); `restorer_accepted` decides the restorer.
pub fn handler_refusal(
    action: &KernelSigaction,
    restorer_accepted: impl FnOnce(u64) -> bool,
) -> Option<HandlerRefusal> {
    if action.flags & REFUSED_SA_FLAGS != 0 {
        return Some(HandlerRefusal::UnsupportedFlags);
    }
    if action.flags & SA_RESTORER as u64 == 0 || !restorer_accepted(action.restorer) {
        return Some(HandlerRefusal::Restorer);
    }
    None
}

/// The next virtual mask for `rt_sigprocmask(how, set)`, or EINVAL for an
/// unknown `how`. SIGKILL and SIGSTOP are dropped, as Linux drops them.
pub fn next_mask(current: u64, how: i32, set: u64) -> Result<u64, i32> {
    let next = match how {
        libc::SIG_BLOCK => current | set,
        libc::SIG_UNBLOCK => current & !set,
        libc::SIG_SETMASK => set,
        _ => return Err(libc::EINVAL),
    };
    Ok(next & !UNBLOCKABLE)
}

fn self_tid() -> Result<i64, i32> {
    let tid = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) };
    if tid < 0 { Err(-tid as i32) } else { Ok(tid) }
}

/// Copy `len` bytes from `from` to `to`, both in this address space, through
/// `process_vm_writev`, so an unreadable or unwritable guest address fails
/// with EFAULT instead of faulting the runtime.
fn copy_within_process(from: u64, to: u64, len: usize) -> Result<(), i32> {
    let tid = self_tid()?;
    let source = libc::iovec {
        iov_base: from as usize as *mut libc::c_void,
        iov_len: len,
    };
    let destination = libc::iovec {
        iov_base: to as usize as *mut libc::c_void,
        iov_len: len,
    };
    let copied = unsafe {
        raw_syscall6(
            libc::SYS_process_vm_writev,
            [
                tid as u64,
                (&raw const source) as u64,
                1,
                (&raw const destination) as u64,
                1,
                0,
            ],
        )
    };
    if copied == len as i64 {
        Ok(())
    } else if copied >= 0 || copied == -i64::from(libc::EFAULT) {
        Err(libc::EFAULT)
    } else {
        Err(-copied as i32)
    }
}

/// The guest's protection-key rights for a call, from the PKRU its trap
/// saved (`None`: no saved value, so no key is enforced: the processor has
/// no protection keys enabled, or the call did not arrive through a trap,
/// where the calling thread's own rights apply to the kernel's copies), and
/// the arguments of the guest's original call.
///
/// A process that admits handlers has no protection key but key 0: it
/// allocates none (`pkey_alloc` is refused from initialization) and gets no
/// implicit execute-only key (an execute-only mapping is refused). So Linux
/// would answer EFAULT for any copy that the guest's rights for key 0 deny.
/// The runtime's copies run with every key open (the fallback path's
/// rights), so they apply key 0's bits themselves, to the guest's own
/// buffers only: an address that is one of the original call's arguments.
/// A buffer a Tool supplies (its own scratch for a private call) keeps the
/// caller's rights: access-disable refuses every copy, write-disable refuses a
/// copy out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuestRights {
    /// The guest's saved PKRU.
    pub pkru: Option<u32>,
    /// The arguments of the guest's original call.
    pub original_args: [u64; 6],
}

impl GuestRights {
    fn applies(self, address: u64) -> bool {
        address != 0 && self.original_args.contains(&address)
    }

    fn may_read(self, address: u64) -> bool {
        !self.applies(address) || self.pkru.is_none_or(|pkru| pkru & 1 == 0)
    }

    fn may_write(self, address: u64) -> bool {
        !self.applies(address) || self.pkru.is_none_or(|pkru| pkru & 0b11 == 0)
    }
}

/// Whether the call reads a guest buffer, one of the original call's own,
/// that the guest's key-0 rights deny: Linux fails such a call with EFAULT
/// before it changes anything. This covers the calls a Tool forwards to read
/// a guest's set or action (Detcore's validation probes) as well as the
/// virtualized ones.
pub fn original_input_denied(rights: GuestRights, number: i64, args: [u64; 6]) -> bool {
    // Linux checks the set size (EINVAL) before it copies anything in.
    admitted()
        && matches!(number, libc::SYS_rt_sigaction | libc::SYS_rt_sigprocmask)
        && args[3] == SIGSET_SIZE
        && !rights.may_read(args[1])
}

fn read_guest<T: Default>(rights: GuestRights, address: u64) -> Result<T, i32> {
    if !rights.may_read(address) {
        return Err(libc::EFAULT);
    }
    let mut value = T::default();
    copy_within_process(address, (&raw mut value) as u64, core::mem::size_of::<T>())?;
    Ok(value)
}

fn write_guest<T>(rights: GuestRights, address: u64, value: &T) -> Result<(), i32> {
    if !rights.may_write(address) {
        return Err(libc::EFAULT);
    }
    copy_within_process(
        (value as *const T) as u64,
        address,
        core::mem::size_of::<T>(),
    )
}

fn physical_sigalrm_pending() -> Result<bool, i32> {
    let mut pending = 0_u64;
    let result = unsafe {
        raw_syscall6(
            libc::SYS_rt_sigpending,
            [(&raw mut pending) as u64, SIGSET_SIZE, 0, 0, 0, 0],
        )
    };
    if result < 0 {
        Err(-result as i32)
    } else {
        Ok(pending & SIGALRM_BIT != 0)
    }
}

fn current_physical_mask() -> Result<u64, i32> {
    let mut mask = 0_u64;
    unsafe { raw_sigprocmask(libc::SIG_BLOCK, None, Some(&mut mask)) }?;
    Ok(mask)
}

fn install_physical_mask(virtual_mask: u64, handled: bool, reserved: u64) -> Result<(), i32> {
    let physical = physical_mask(virtual_mask, handled, reserved);
    unsafe { raw_sigprocmask(libc::SIG_SETMASK, Some(&physical), None) }?;
    // Read it back into a sentinel: a call that reported success without
    // running (a seccomp filter's errno of 0) leaves the sentinel.
    let mut installed = !physical;
    unsafe { raw_sigprocmask(libc::SIG_BLOCK, None, Some(&mut installed)) }?;
    if installed != physical {
        lose_signal_state();
    }
    Ok(())
}

/// Install `action` as the physical SIGALRM action and read it back into a
/// sentinel; a mismatch (a call that reported success without running) ends
/// the process, since the physical state is then unknown.
fn install_physical_action(action: &KernelSigaction) -> Result<(), i32> {
    unsafe { raw_sigaction(libc::SIGALRM, Some(action), None) }?;
    let mut installed = KernelSigaction {
        handler: !action.handler,
        flags: !action.flags,
        restorer: !action.restorer,
        mask: !action.mask,
    };
    unsafe { raw_sigaction(libc::SIGALRM, None, Some(&mut installed)) }?;
    if installed != *action {
        lose_signal_state();
    }
    Ok(())
}

/// What the runtime needs from its backend to decide a guest call.
pub struct Policy {
    /// Signals the runtime keeps unblocked for itself.
    pub reserved: u64,
    /// The guest's protection-key rights for this call.
    pub rights: GuestRights,
}

/// Decide a guest signal call Detcore forwards. `Some(result)` is the call's
/// result (a value or a negated errno) and the call must not be forwarded;
/// `None` forwards it as before.
///
/// # Safety
///
/// Changes process-wide signal state through raw syscalls; call only from
/// the runtime's forwarding of a guest call.
pub unsafe fn intercept(policy: &Policy, number: i64, args: [u64; 6]) -> Option<i64> {
    let result = match number {
        libc::SYS_rt_sigaction if decides_action(number, args) => {
            if args[3] != SIGSET_SIZE {
                return None;
            }
            sigaction(policy, args)
        }
        libc::SYS_rt_sigprocmask if handled() => {
            if args[3] != SIGSET_SIZE {
                return None;
            }
            sigprocmask(policy, args)
        }
        libc::SYS_rt_sigpending if handled() => sigpending(policy, args),
        // The guest's alternate stack is virtual, and always disabled, in
        // every process that admits handlers: before, during and after one.
        libc::SYS_sigaltstack if admitted() && args[0] == 0 => sigaltstack_query(policy, args),
        _ => return None,
    };
    Some(match result {
        Ok(value) => value,
        Err(errno) => -i64::from(errno),
    })
}

fn sigaction(policy: &Policy, args: [u64; 6]) -> Result<i64, i32> {
    let was_handled = handled();
    let new = if args[1] == 0 {
        None
    } else {
        Some(read_guest::<KernelSigaction>(policy.rights, args[1])?)
    };
    let old = match new {
        None if !was_handled => {
            // A query of an unhandled SIGALRM is the kernel's.
            let mut old = KernelSigaction::default();
            unsafe { raw_sigaction(libc::SIGALRM, None, Some(&mut old)) }?;
            old
        }
        None => virtual_action(),
        Some(new) => change_action(policy, new, was_handled)?,
    };
    if args[2] != 0 {
        // After the change, as Linux copies the old action out last.
        write_guest(policy.rights, args[2], &old)?;
    }
    Ok(0)
}

fn change_action(
    policy: &Policy,
    mut new: KernelSigaction,
    was_handled: bool,
) -> Result<KernelSigaction, i32> {
    let mut old_physical = KernelSigaction::default();
    unsafe { raw_sigaction(libc::SIGALRM, None, Some(&mut old_physical)) }?;
    let old = if was_handled {
        virtual_action()
    } else {
        old_physical
    };
    new.flags &= UAPI_SA_FLAGS;
    new.mask &= !UNBLOCKABLE;
    let to_handler = new.handler != libc::SIG_DFL as u64 && new.handler != libc::SIG_IGN as u64;
    // Every change below is transactional: nothing the guest can see, and no
    // runtime state, changes unless every physical step succeeded. A step can
    // fail if a guest seccomp filter refuses the runtime's own call.
    if !to_handler {
        // Detcore refuses a change to SIG_DFL while an entry is pending; an
        // entry that becomes ignored is discarded by the scheduler.
        install_physical_action(&new)?;
        if was_handled {
            if let Err(error) = install_physical_mask(virtual_mask(), false, policy.reserved) {
                restore_physical_action(&old_physical);
                return Err(error);
            }
            HANDLED.store(false, Ordering::Release);
        }
        return Ok(old);
    }
    if handler_refusal(&new, |address| unsafe {
        restorer::glibc_restorer_accepted(address)
    })
    .is_some()
        || !restorer::can_protect_restorer(new.restorer)
        || !filters_are_the_runtimes()
    {
        return Err(libc::EPERM);
    }
    let next_mask = if was_handled {
        virtual_mask()
    } else {
        // Installation preflight: no physical SIGALRM may be stranded
        // behind the handler.
        if physical_sigalrm_pending()? {
            return Err(libc::EPERM);
        }
        current_physical_mask()? & !UNBLOCKABLE
    };
    let physical = physical_action(
        &new,
        sigalrm_trampoline as *const () as u64,
        policy.reserved,
    );
    install_physical_action(&physical)?;
    if let Err(error) = install_physical_mask(next_mask, true, policy.reserved) {
        restore_physical_action(&old_physical);
        return Err(error);
    }
    if !restorer::protect_restorer(new.restorer) {
        // can_protect_restorer said there was room, and nothing else runs.
        lose_signal_state();
    }
    VIRTUAL_MASK.store(next_mask, Ordering::Release);
    set_virtual_action(&new);
    RESERVED.store(policy.reserved, Ordering::Release);
    HANDLED.store(true, Ordering::Release);
    Ok(old)
}

/// Put back the physical SIGALRM action a failed change replaced, or end the
/// process if even that is refused.
fn restore_physical_action(old: &KernelSigaction) {
    if unsafe { raw_sigaction(libc::SIGALRM, Some(old), None) }.is_err() {
        lose_signal_state();
    }
}

fn lose_signal_state() -> ! {
    const MESSAGE: &[u8] = b"reverie-inguest: the runtime could not undo a failed change to the \
physical SIGALRM state; the process ends\n";
    unsafe {
        let _ = raw_syscall6(
            libc::SYS_write,
            [
                libc::STDERR_FILENO as u64,
                MESSAGE.as_ptr() as u64,
                MESSAGE.len() as u64,
                0,
                0,
                0,
            ],
        );
        crate::guest::support::exit_now(SIGNAL_STATE_LOST_STATUS)
    }
}

fn sigprocmask(policy: &Policy, args: [u64; 6]) -> Result<i64, i32> {
    let old = virtual_mask();
    if args[1] != 0 {
        let set = read_guest::<u64>(policy.rights, args[1])?;
        let next = next_mask(old, args[0] as i32, set)?;
        install_physical_mask(next, true, policy.reserved)?;
        VIRTUAL_MASK.store(next, Ordering::Release);
    }
    if args[2] != 0 {
        write_guest(policy.rights, args[2], &old)?;
    }
    Ok(0)
}

fn sigpending(policy: &Policy, args: [u64; 6]) -> Result<i64, i32> {
    // Linux accepts any size up to its set's and copies that many bytes; a
    // size of 0 copies nothing and never touches the destination.
    let size = args[1];
    if size > SIGSET_SIZE {
        return Err(libc::EINVAL);
    }
    let mut pending = 0_u64;
    let result = unsafe {
        raw_syscall6(
            libc::SYS_rt_sigpending,
            [(&raw mut pending) as u64, SIGSET_SIZE, 0, 0, 0, 0],
        )
    };
    if result < 0 {
        return Err(-result as i32);
    }
    // Linux reports pending ∩ blocked; the guest's blocked set is virtual.
    let visible = pending & !SIGALRM_BIT & virtual_mask();
    if size != 0 {
        if !policy.rights.may_write(args[0]) {
            return Err(libc::EFAULT);
        }
        // The set is little-endian: its first `size` bytes are the prefix.
        copy_within_process((&raw const visible) as u64, args[0], size as usize)?;
    }
    Ok(0)
}

/// A disabled `stack_t` as Linux writes it: `ss_sp` 0, `ss_flags`
/// `SS_DISABLE`, the four padding bytes zero, `ss_size` 0.
pub fn disabled_stack_bytes() -> [u8; 24] {
    let mut bytes = [0_u8; 24];
    bytes[8..12].copy_from_slice(&libc::SS_DISABLE.to_ne_bytes());
    bytes
}

fn sigaltstack_query(policy: &Policy, args: [u64; 6]) -> Result<i64, i32> {
    if args[1] != 0 {
        write_guest(policy.rights, args[1], &disabled_stack_bytes())?;
    }
    Ok(0)
}

// Signal phase 1, step I4: delivery (design section 4, "The commit" steps 4
// to 8, and "The trampoline").

/// The exit status when a SIGALRM delivery cannot be completed as Linux
/// would (a physical SIGALRM already pending, the instance cannot be queued,
/// or the guest changed its alternate stack in the frame): a determinism loss.
pub const DELIVERY_LOST_STATUS: i32 = 115;

static PREPARED: AtomicBool = AtomicBool::new(false);
static PREPARED_NONCE: AtomicU64 = AtomicU64::new(0);
// Selected Tool metadata belongs to the same one-use activation as the action
// and masks. It is distinct from the private SI_QUEUE nonce packet below.
static PREPARED_SIGINFO: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];
static PREPARED_HANDLER: AtomicU64 = AtomicU64::new(0);
static PREPARED_FLAGS: AtomicU64 = AtomicU64::new(0);
static PREPARED_ACTION_MASK: AtomicU64 = AtomicU64::new(0);
static PREPARED_SAVED_MASK: AtomicU64 = AtomicU64::new(0);
static PREPARED_ACTIVATION_BASE: AtomicU64 = AtomicU64::new(0);
static NEXT_NONCE: AtomicU64 = AtomicU64::new(1);
/// The mask the next completion marker installs in its fresh frame (the
/// delivery window), while `WINDOW_OPEN`.
static WINDOW_MASK: AtomicU64 = AtomicU64::new(0);
static WINDOW_OPEN: AtomicBool = AtomicBool::new(false);

/// `SI_QUEUE` from Linux's siginfo codes, used only by the private transport.
const SI_QUEUE: i32 = -1;

/// The window mask for a thread whose virtual mask is `virtual_mask`: the
/// physical mask without SIGALRM, so the queued instance is delivered as soon
/// as the completion marker's frame returns.
pub fn window_mask(virtual_mask: u64, reserved: u64) -> u64 {
    physical_mask(virtual_mask, true, reserved) & !SIGALRM_BIT
}

/// The guest's mask while its handler runs, as Linux computes it without
/// `SA_NODEFER`: the activation base, the action's mask, and SIGALRM.
pub fn activation_mask(base: u64, action_mask: u64) -> u64 {
    (base | action_mask | SIGALRM_BIT) & !UNBLOCKABLE
}

/// Prepare one SIGALRM delivery at the current syscall's completion (design
/// section 4, steps 4 to 7): retain the selected event's full siginfo alongside
/// the virtual action and masks, check that
/// no physical SIGALRM is pending, queue the runtime's own instance (blocked
/// by the physical mask, so only queued), and open the window the completion
/// marker installs. EINVAL when no guest handler is installed or a delivery is
/// already prepared; EIO when the instance cannot be made (the caller must
/// then record a loss: the ledger entry is already taken).
///
/// # Safety
///
/// Only from a guest call's own turn, in a fallback dispatch whose completion
/// marker will follow. The event must be an already-selected SIGALRM for this
/// receiver; target selection remains the caller's responsibility.
pub unsafe fn prepare_delivery(event: reverie::SignalEvent, reserved: u64) -> Result<(), i32> {
    if !handled() || PREPARED.load(Ordering::Acquire) || WINDOW_OPEN.load(Ordering::Acquire) {
        return Err(libc::EINVAL);
    }
    if physical_sigalrm_pending()? {
        return Err(libc::EIO);
    }
    let action = virtual_action();
    let current = virtual_mask();
    let nonce = NEXT_NONCE.fetch_add(1, Ordering::AcqRel);
    PREPARED_HANDLER.store(action.handler, Ordering::Release);
    PREPARED_FLAGS.store(action.flags, Ordering::Release);
    PREPARED_ACTION_MASK.store(action.mask, Ordering::Release);
    PREPARED_SAVED_MASK.store(current, Ordering::Release);
    PREPARED_ACTIVATION_BASE.store(current, Ordering::Release);
    PREPARED_NONCE.store(nonce, Ordering::Release);
    // All admission checks precede this write: a rejected replacement must
    // leave the already prepared event untouched. PREPARED publishes all words.
    let selected = event.siginfo();
    for (slot, bytes) in PREPARED_SIGINFO.iter().zip(selected.as_chunks::<8>().0) {
        slot.store(u64::from_ne_bytes(*bytes), Ordering::Relaxed);
    }
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let uid = unsafe { raw_syscall6(libc::SYS_getuid, [0; 6]) };
    let mut info = [0_u8; 128];
    info[0..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
    info[8..12].copy_from_slice(&SI_QUEUE.to_ne_bytes());
    info[16..20].copy_from_slice(&(pid as i32).to_ne_bytes());
    info[20..24].copy_from_slice(&(uid as u32).to_ne_bytes());
    info[24..32].copy_from_slice(&nonce.to_ne_bytes());
    PREPARED.store(true, Ordering::Release);
    let queued = unsafe {
        raw_syscall6(
            libc::SYS_rt_sigqueueinfo,
            [
                pid as u64,
                libc::SIGALRM as u64,
                info.as_ptr() as u64,
                0,
                0,
                0,
            ],
        )
    };
    if queued < 0 {
        PREPARED.store(false, Ordering::Release);
        return Err(libc::EIO);
    }
    WINDOW_MASK.store(window_mask(current, reserved), Ordering::Release);
    WINDOW_OPEN.store(true, Ordering::Release);
    Ok(())
}

/// The runtime's own alternate stack, recorded at admission: `ss_sp`,
/// `ss_flags` and `ss_size`.
static RUNTIME_STACK_POINTER: AtomicU64 = AtomicU64::new(0);
static RUNTIME_STACK_FLAGS: AtomicU64 = AtomicU64::new(0);
static RUNTIME_STACK_SIZE: AtomicU64 = AtomicU64::new(0);
static RUNTIME_STACK_RECORDED: AtomicBool = AtomicBool::new(false);

/// Record the thread's physical alternate stack, the runtime's own, once the
/// runtime is installed. The guest's stack is virtual from then on, so a
/// guest call's frame must always show this one.
pub fn record_runtime_stack() -> std::io::Result<()> {
    let mut stack = [0_u8; 24];
    let result = unsafe {
        raw_syscall6(
            libc::SYS_sigaltstack,
            [0, stack.as_mut_ptr() as u64, 0, 0, 0, 0],
        )
    };
    if result < 0 {
        return Err(std::io::Error::from_raw_os_error(-result as i32));
    }
    let (pointer, flags, size) = stack_fields(&stack);
    RUNTIME_STACK_POINTER.store(pointer, Ordering::Release);
    RUNTIME_STACK_FLAGS.store(flags, Ordering::Release);
    RUNTIME_STACK_SIZE.store(size, Ordering::Release);
    RUNTIME_STACK_RECORDED.store(true, Ordering::Release);
    Ok(())
}

/// A `stack_t` image's `ss_sp`, `ss_flags` and `ss_size`, without its
/// padding (the kernel writes the fields, not the padding).
fn stack_fields(stack: &[u8; 24]) -> (u64, u64, u64) {
    let pointer = u64::from_ne_bytes(stack[0..8].try_into().unwrap());
    let flags = u64::from(u32::from_ne_bytes(stack[8..12].try_into().unwrap()));
    let size = u64::from_ne_bytes(stack[16..24].try_into().unwrap());
    (pointer, flags, size)
}

/// The frame invariant (design section 3), from a guest call's entry frame
/// in a process with SIGALRM handled: its `uc_sigmask` is the physical mask
/// derived from the virtual state, and its `uc_stack` is the runtime's own
/// alternate stack.
pub fn entry_frame_matches(mask: u64, stack: &[u8; 24]) -> bool {
    let reserved = RESERVED.load(Ordering::Acquire);
    RUNTIME_STACK_RECORDED.load(Ordering::Acquire)
        && mask == physical_mask(virtual_mask(), true, reserved)
        && stack_fields(stack)
            == (
                RUNTIME_STACK_POINTER.load(Ordering::Acquire),
                RUNTIME_STACK_FLAGS.load(Ordering::Acquire),
                RUNTIME_STACK_SIZE.load(Ordering::Acquire),
            )
}

/// Check the frame invariant at a guest call's entry; on a mismatch the
/// physical signal state was changed by a path the runtime does not own, and
/// the process ends before the call can commit a delivery.
pub fn check_entry_frame(mask: u64, stack: [u8; 24]) {
    if entry_frame_matches(mask, &stack) {
        return;
    }
    const MESSAGE: &[u8] = b"reverie-inguest: a guest call's frame shows a signal mask or \
alternate stack the runtime did not set; the process ends\n";
    unsafe {
        let _ = raw_syscall6(
            libc::SYS_write,
            [
                libc::STDERR_FILENO as u64,
                MESSAGE.as_ptr() as u64,
                MESSAGE.len() as u64,
                0,
                0,
                0,
            ],
        );
        crate::guest::support::exit_now(SIGNAL_STATE_LOST_STATUS)
    }
}

/// Set by [`prepare_delivery_before_syscall`]: the current fallback syscall
/// is not run, and its continuation resumes at the `syscall` instruction.
static ENTRY_DELIVERY: AtomicBool = AtomicBool::new(false);

/// [`prepare_delivery`] from a syscall's entry (the I4 addendum's point c):
/// the delivery happens before the syscall, which then starts from the
/// beginning once the handler returns.
///
/// # Safety
///
/// As [`prepare_delivery`]; the caller must not run the syscall.
pub unsafe fn prepare_delivery_before_syscall(
    event: reverie::SignalEvent,
    reserved: u64,
) -> Result<(), i32> {
    unsafe { prepare_delivery(event, reserved) }?;
    ENTRY_DELIVERY.store(true, Ordering::Release);
    Ok(())
}

/// Whether the syscall whose callback just returned is to start again from
/// its `syscall` instruction (its entry delivery was prepared), taken once.
pub fn take_entry_delivery() -> bool {
    ENTRY_DELIVERY.swap(false, Ordering::AcqRel)
}

/// The delivery window for the completion marker's fresh frame, taken once.
pub fn take_window() -> Option<u64> {
    WINDOW_OPEN
        .swap(false, Ordering::AcqRel)
        .then(|| WINDOW_MASK.load(Ordering::Acquire))
}

/// Offsets in Linux's x86-64 `ucontext_t` prefix.
const UC_STACK_OFFSET: usize = 16;
const UC_SIGMASK_OFFSET: usize = 296;
/// `uc_mcontext.gregs[REG_OLDMASK]` (Linux's `sigcontext.oldmask`): the
/// kernel stores the first word of the pre-delivery mask there too.
const UC_OLDMASK_OFFSET: usize = 40 + 8 * libc::REG_OLDMASK as usize;

fn delivery_lost(message: &[u8]) -> ! {
    unsafe {
        let _ = raw_syscall6(
            libc::SYS_write,
            [
                libc::STDERR_FILENO as u64,
                message.as_ptr() as u64,
                message.len() as u64,
                0,
                0,
                0,
            ],
        );
        crate::guest::support::exit_now(DELIVERY_LOST_STATUS)
    }
}

// Calls the guest's SIGALRM handler (rcx) with the trampoline's three
// arguments (rdi, rsi, rdx; Linux passes all three whatever SA_SIGINFO says),
// and on its return restores the rights in r8d before any memory write when
// r9 is nonzero (OSPKE). A handler may deny writes to key 0, this very stack
// included, with WRPKRU and return: Linux's restorer writes no memory before
// rt_sigreturn restores the frame's PKRU, so the runtime must not either.
// The pops only read.
core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .type reverie_inguest_sigalrm_call_handler, @function
    .hidden reverie_inguest_sigalrm_call_handler
reverie_inguest_sigalrm_call_handler:
    push rbx
    push r12
    push r13
    mov ebx, r8d
    mov r12, r9
    call rcx
    test r12, r12
    jz 1f
    mov eax, ebx
    xor ecx, ecx
    xor edx, edx
    wrpkru
    lfence
1:
    pop r13
    pop r12
    pop rbx
    ret
    .size reverie_inguest_sigalrm_call_handler, .-reverie_inguest_sigalrm_call_handler
"#
);

unsafe extern "C" {
    fn reverie_inguest_sigalrm_call_handler(
        signal: libc::c_int,
        info: *mut libc::siginfo_t,
        context: *mut libc::c_void,
        handler: u64,
        rights: u32,
        ospke: u64,
    );
}

/// The current PKRU; only with OSPKE.
fn read_pkru() -> u32 {
    let rights: u32;
    unsafe {
        core::arch::asm!(
            "rdpkru",
            in("ecx") 0_u32,
            out("eax") rights,
            out("edx") _,
            options(nomem, nostack, preserves_flags),
        )
    };
    rights
}

/// The physical SIGALRM handler while a guest handler is installed.
///
/// It runs only the delivery the runtime prepared: the instance must carry
/// `SI_QUEUE`, this process's pid and the prepared nonce, or the process
/// ends before any guest code runs. It then shows the guest Linux's view:
/// the Tool-selected full siginfo, the saved-return mask in `uc_sigmask`, a disabled
/// alternate stack in `uc_stack`, and the activation mask as its virtual mask;
/// calls the guest's handler; and on its return takes `uc_sigmask` (which the
/// guest may have edited) as the virtual mask, puts the physical mask and the
/// runtime's own alternate stack back in the frame, and returns through the
/// runtime's restorer. The frame's saved PKRU is never touched, so
/// rt_sigreturn restores it (or the guest's edit of it) as Linux would.
unsafe extern "C" fn sigalrm_trampoline(
    signal: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    let prepared = PREPARED.swap(false, Ordering::AcqRel);
    let nonce = PREPARED_NONCE.load(Ordering::Acquire);
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) } as i32;
    let authentic = prepared
        && signal == libc::SIGALRM
        && !info.is_null()
        && !context.is_null()
        && unsafe {
            let bytes = info.cast::<u8>();
            bytes.add(8).cast::<i32>().read_unaligned() == SI_QUEUE
                && bytes.add(16).cast::<i32>().read_unaligned() == pid
                && bytes.add(24).cast::<u64>().read_unaligned() == nonce
        };
    if !authentic {
        unsafe { sigalrm_unprepared() }
    }
    // Move the snapshot into this activation before any guest code runs: a
    // nested delivery prepares its own.
    let handler = PREPARED_HANDLER.load(Ordering::Acquire);
    let flags = PREPARED_FLAGS.load(Ordering::Acquire);
    let action_mask = PREPARED_ACTION_MASK.load(Ordering::Acquire);
    let saved = PREPARED_SAVED_MASK.load(Ordering::Acquire);
    let base = PREPARED_ACTIVATION_BASE.load(Ordering::Acquire);
    let mut selected = [0_u8; 128];
    for (bytes, slot) in selected
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(&PREPARED_SIGINFO)
    {
        bytes.copy_from_slice(&slot.load(Ordering::Relaxed).to_ne_bytes());
    }
    // The rights the kernel entered this handler with; restored when the
    // guest's handler returns.
    let ospke = crate::trap::pkru_present();
    let rights = if ospke { read_pkru() } else { 0 };
    let context = context.cast::<u8>();
    unsafe {
        // Authentication consumed the private transport. Expose only the
        // already selected metadata, including its original signal code.
        core::ptr::copy_nonoverlapping(selected.as_ptr(), info.cast::<u8>(), selected.len());
    }
    let runtime_stack =
        unsafe { core::ptr::read_unaligned(context.add(UC_STACK_OFFSET).cast::<[u8; 24]>()) };
    let physical_oldmask = unsafe {
        context
            .add(UC_OLDMASK_OFFSET)
            .cast::<u64>()
            .read_unaligned()
    };
    unsafe {
        context
            .add(UC_SIGMASK_OFFSET)
            .cast::<u64>()
            .write_unaligned(saved);
        // Linux also stores the saved mask in sigcontext.oldmask.
        context
            .add(UC_OLDMASK_OFFSET)
            .cast::<u64>()
            .write_unaligned(saved);
        core::ptr::write_unaligned(
            context.add(UC_STACK_OFFSET).cast::<[u8; 24]>(),
            disabled_stack_bytes(),
        );
    }
    VIRTUAL_MASK.store(activation_mask(base, action_mask), Ordering::Release);
    if flags & libc::SA_SIGINFO as u64 == 0 {
        // Linux copies siginfo to the frame only for SA_SIGINFO.
        unsafe { core::ptr::write_bytes(info.cast::<u8>(), 0, 128) };
    }
    unsafe {
        reverie_inguest_sigalrm_call_handler(
            libc::SIGALRM,
            info,
            context.cast(),
            handler,
            rights,
            u64::from(ospke),
        )
    };
    let edited = unsafe {
        context
            .add(UC_SIGMASK_OFFSET)
            .cast::<u64>()
            .read_unaligned()
    };
    let stack =
        unsafe { core::ptr::read_unaligned(context.add(UC_STACK_OFFSET).cast::<[u8; 24]>()) };
    // By its fields: Linux ignores the padding after ss_flags.
    if stack_fields(&stack) != stack_fields(&disabled_stack_bytes()) {
        delivery_lost(
            b"reverie-inguest: a SIGALRM handler changed uc_stack, which phase 1 does \
not support; the process ends\n",
        );
    }
    let next = edited & !UNBLOCKABLE;
    VIRTUAL_MASK.store(next, Ordering::Release);
    let reserved = RESERVED.load(Ordering::Acquire);
    unsafe {
        context
            .add(UC_SIGMASK_OFFSET)
            .cast::<u64>()
            .write_unaligned(physical_mask(next, handled(), reserved));
        core::ptr::write_unaligned(
            context.add(UC_STACK_OFFSET).cast::<[u8; 24]>(),
            runtime_stack,
        );
        // rt_sigreturn ignores oldmask; put back what the kernel wrote.
        context
            .add(UC_OLDMASK_OFFSET)
            .cast::<u64>()
            .write_unaligned(physical_oldmask);
    }
}

/// The runtime's reserved signals, recorded at admission for the trampoline,
/// which runs outside any guest call.
static RESERVED: AtomicU64 = AtomicU64::new(0);

/// A SIGALRM the runtime did not prepare: the process ends before any guest
/// code runs.
unsafe fn sigalrm_unprepared() -> ! {
    const MESSAGE: &[u8] = b"reverie-inguest: a SIGALRM the runtime did not prepare reached the \
guest's handler; the process ends\n";
    unsafe {
        let _ = raw_syscall6(
            libc::SYS_write,
            [
                libc::STDERR_FILENO as u64,
                MESSAGE.as_ptr() as u64,
                MESSAGE.len() as u64,
                0,
                0,
                0,
            ],
        );
        crate::guest::support::exit_now(UNPREPARED_SIGALRM_STATUS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGSYS_BIT: u64 = 1 << (libc::SIGSYS - 1);

    #[test]
    fn the_physical_mask_always_blocks_sigalrm_while_handled() {
        let usr1 = 1 << (libc::SIGUSR1 - 1);
        assert_eq!(physical_mask(usr1, true, SIGSYS_BIT), usr1 | SIGALRM_BIT);
        assert_eq!(physical_mask(usr1, false, SIGSYS_BIT), usr1);
        assert_eq!(
            physical_mask(usr1 | SIGALRM_BIT, false, SIGSYS_BIT),
            usr1 | SIGALRM_BIT
        );
        assert_eq!(
            physical_mask(u64::MAX, true, SIGSYS_BIT),
            !SIGSYS_BIT & !UNBLOCKABLE
        );
    }

    #[test]
    fn the_physical_action_is_the_trampoline_with_only_sa_restart_kept() {
        let guest = KernelSigaction {
            handler: 0x1000,
            flags: (libc::SA_RESTART | libc::SA_ONSTACK | libc::SA_SIGINFO) as u64
                | SA_RESTORER as u64,
            restorer: 0x2000,
            mask: (1 << (libc::SIGUSR2 - 1)) | SIGSYS_BIT,
        };
        let physical = physical_action(&guest, 0x3000, SIGSYS_BIT);
        assert_eq!(physical.handler, 0x3000);
        assert_eq!(physical.restorer, crate::signal::signal_restorer());
        assert_eq!(
            physical.flags,
            (libc::SA_SIGINFO | SA_RESTORER | libc::SA_RESTART) as u64
        );
        assert_eq!(physical.mask, (1 << (libc::SIGUSR2 - 1)) | SIGALRM_BIT);
        let plain = KernelSigaction {
            flags: SA_RESTORER as u64,
            ..guest
        };
        assert_eq!(
            physical_action(&plain, 0x3000, SIGSYS_BIT).flags,
            (libc::SA_SIGINFO | SA_RESTORER) as u64
        );
    }

    #[test]
    fn handler_refusals_follow_design_section_six() {
        let base = KernelSigaction {
            handler: 0x1000,
            flags: SA_RESTORER as u64,
            restorer: 0x2000,
            mask: 0,
        };
        assert_eq!(handler_refusal(&base, |_| true), None);
        assert_eq!(
            handler_refusal(&base, |_| false),
            Some(HandlerRefusal::Restorer)
        );
        let no_restorer = KernelSigaction { flags: 0, ..base };
        assert_eq!(
            handler_refusal(&no_restorer, |_| true),
            Some(HandlerRefusal::Restorer)
        );
        for flag in [libc::SA_RESETHAND, libc::SA_NODEFER] {
            let flagged = KernelSigaction {
                flags: base.flags | flag as u64,
                ..base
            };
            assert_eq!(
                handler_refusal(&flagged, |_| true),
                Some(HandlerRefusal::UnsupportedFlags)
            );
        }
        let restart = KernelSigaction {
            flags: base.flags | (libc::SA_RESTART | libc::SA_SIGINFO | libc::SA_ONSTACK) as u64,
            ..base
        };
        assert_eq!(handler_refusal(&restart, |_| true), None);
    }

    #[test]
    fn flag_masks_are_built_without_sign_extension() {
        // SA_RESETHAND | SA_NODEFER, as the kernel's unsigned flags.
        assert_eq!(REFUSED_SA_FLAGS, 0xc000_0000);
        assert_eq!(UAPI_SA_FLAGS, 0xdc00_0807);
        // SA_UNSUPPORTED and every high bit are cleared.
        assert_eq!(UAPI_SA_FLAGS & 0x400, 0);
        assert_eq!(UAPI_SA_FLAGS >> 32, 0);
        // High flag bits are not mistaken for refused flags.
        let high = KernelSigaction {
            handler: 0x1000,
            flags: 0xffff_ffff_0000_0000 | SA_RESTORER as u64,
            restorer: 0x2000,
            mask: 0,
        };
        assert_eq!(handler_refusal(&high, |_| true), None);
    }

    #[test]
    fn the_signal_argument_is_a_c_int() {
        set_admitted(true);
        let alias = [0x1_0000_0000 | libc::SIGALRM as u64, 0, 0, 8, 0, 0];
        assert!(decides_action(libc::SYS_rt_sigaction, alias));
        assert!(!decides_action(
            libc::SYS_rt_sigaction,
            [libc::SIGUSR1 as u64, 0, 0, 8, 0, 0]
        ));
        set_admitted(false);
        assert!(!decides_action(libc::SYS_rt_sigaction, alias));
    }

    #[test]
    fn the_disabled_stack_is_linuxs_byte_image() {
        let bytes = disabled_stack_bytes();
        assert_eq!(core::mem::size_of::<libc::stack_t>(), bytes.len());
        assert_eq!(core::mem::offset_of!(libc::stack_t, ss_flags), 8);
        assert_eq!(core::mem::offset_of!(libc::stack_t, ss_size), 16);
        assert_eq!(&bytes[8..12], &libc::SS_DISABLE.to_ne_bytes());
        assert!(bytes[..8].iter().chain(&bytes[12..]).all(|byte| *byte == 0));
    }

    #[test]
    fn key_zero_rights_apply_to_the_guests_own_buffers_only() {
        let original = [0, 0x5000, 0x6000, 8, 0, 0];
        let rights = |pkru| GuestRights {
            pkru,
            original_args: original,
        };
        let none = rights(None);
        assert!(none.may_read(0x5000) && none.may_write(0x6000));
        let open = rights(Some(0x5555_5554));
        assert!(open.may_read(0x5000) && open.may_write(0x6000));
        let write_disabled = rights(Some(0b10));
        assert!(write_disabled.may_read(0x5000) && !write_disabled.may_write(0x6000));
        let access_disabled = rights(Some(0b01));
        assert!(!access_disabled.may_read(0x5000) && !access_disabled.may_write(0x6000));
        // A Tool's own scratch keeps the caller's rights; so does NULL.
        assert!(access_disabled.may_read(0x7000) && access_disabled.may_write(0x7000));
        assert!(access_disabled.may_read(0));
        assert_eq!(
            read_guest::<u64>(access_disabled, 0x5000),
            Err(libc::EFAULT)
        );
        let value = 7_u64;
        let local = (&raw const value) as u64;
        let local_original = GuestRights {
            pkru: Some(0b10),
            original_args: [0, 0, local, 0, 0, 0],
        };
        assert_eq!(
            write_guest(local_original, local, &value),
            Err(libc::EFAULT)
        );
        set_admitted(true);
        assert!(original_input_denied(
            access_disabled,
            libc::SYS_rt_sigaction,
            [libc::SIGKILL as u64, 0x5000, 0, 8, 0, 0]
        ));
        assert!(!original_input_denied(
            access_disabled,
            libc::SYS_rt_sigaction,
            [libc::SIGKILL as u64, 0x7000, 0, 8, 0, 0]
        ));
        assert!(!original_input_denied(
            write_disabled,
            libc::SYS_rt_sigprocmask,
            [0, 0x5000, 0, 8, 0, 0]
        ));
        // A size other than 8 is Linux's EINVAL first: the copy never happens.
        for number in [libc::SYS_rt_sigaction, libc::SYS_rt_sigprocmask] {
            assert!(original_input_denied(
                access_disabled,
                number,
                [libc::SIGKILL as u64, 0x5000, 0, 8, 0, 0]
            ));
            for size in [0, 4, 16] {
                assert!(!original_input_denied(
                    access_disabled,
                    number,
                    [libc::SIGKILL as u64, 0x5000, 0, size, 0, 0]
                ));
            }
        }
        set_admitted(false);
        assert!(!original_input_denied(
            access_disabled,
            libc::SYS_rt_sigaction,
            [libc::SIGKILL as u64, 0x5000, 0, 8, 0, 0]
        ));
    }

    /// The key inventory answers only after reading the whole file: a file
    /// that cannot be opened gives no answer (admission is then refused); a
    /// key other than 0 anywhere is found; all zeros is "none in use".
    #[test]
    fn the_protection_key_inventory_needs_the_whole_file() {
        let directory = std::env::temp_dir().join(format!("sigalrm-pkeys-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let write = |name: &str, text: &str| {
            let path = directory.join(name);
            std::fs::write(&path, text).unwrap();
            std::ffi::CString::new(path.into_os_string().into_encoded_bytes()).unwrap()
        };
        let zeros = write(
            "zeros",
            "7f00-7f01 r-xp 0 00:00 0\nProtectionKey:         0\n",
        );
        let keyed = write(
            "keyed",
            "7f00-7f01 r-xp 0 00:00 0\nProtectionKey:         0\n7f02-7f03 rw-p 0 00:00 0\nProtectionKey:         1\n",
        );
        assert_eq!(unsafe { protection_keys_in_use_in(&zeros) }, Some(false));
        assert_eq!(unsafe { protection_keys_in_use_in(&keyed) }, Some(true));
        assert_eq!(
            unsafe { protection_keys_in_use_in(c"/nonexistent/sigalrm/smaps") },
            None
        );
        // A directory opens but cannot be read: no answer either.
        let dir = std::ffi::CString::new(directory.clone().into_os_string().into_encoded_bytes())
            .unwrap();
        assert_eq!(unsafe { protection_keys_in_use_in(&dir) }, None);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn seccomp_filter_lines_are_parsed() {
        assert_eq!(seccomp_filters_line(b"Seccomp_filters:\t1"), Some(1));
        assert_eq!(seccomp_filters_line(b"Seccomp_filters:\t12"), Some(12));
        assert_eq!(seccomp_filters_line(b"Seccomp:\t2"), None);
    }

    #[test]
    fn a_stack_image_is_compared_by_its_fields_not_its_padding() {
        let mut stack = [0_u8; 24];
        stack[0..8].copy_from_slice(&0x7000_u64.to_ne_bytes());
        stack[8..12].copy_from_slice(&2_u32.to_ne_bytes());
        stack[16..24].copy_from_slice(&0x1_0000_u64.to_ne_bytes());
        let mut padded = stack;
        padded[12..16].copy_from_slice(&[0xff; 4]);
        assert_eq!(stack_fields(&stack), (0x7000, 2, 0x1_0000));
        assert_eq!(stack_fields(&padded), stack_fields(&stack));
        let mut other = stack;
        other[18] = 0;
        assert_ne!(stack_fields(&other), stack_fields(&stack));
    }

    #[test]
    fn mask_changes_follow_linux() {
        let usr1 = 1 << (libc::SIGUSR1 - 1);
        let kill = 1 << (libc::SIGKILL - 1);
        assert_eq!(next_mask(0, libc::SIG_BLOCK, usr1 | kill), Ok(usr1));
        assert_eq!(
            next_mask(usr1 | SIGALRM_BIT, libc::SIG_UNBLOCK, usr1),
            Ok(SIGALRM_BIT)
        );
        assert_eq!(
            next_mask(usr1, libc::SIG_SETMASK, SIGALRM_BIT),
            Ok(SIGALRM_BIT)
        );
        assert_eq!(next_mask(usr1, 7, 0), Err(libc::EINVAL));
    }
}
