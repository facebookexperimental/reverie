/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Inactive, installer-owned native exec injection boundary. No driver is
//! installed by this module. It neither provisions descriptors nor claims a
//! kernel exec; a concrete trusted native driver owns that unsafe launch chain.

use std::sync::Arc;

use reverie::Tool;
use reverie::UnsupportedOperation;
use reverie::UnsupportedRefusal;
use reverie::syscalls::Errno;

use super::event::SyscallDispatch;
use super::event::SyscallEvent;
use super::exec_private::NativeExecCallbackFacts;
use super::exec_private::{self};
use super::rpc::CoordinatorRpc;

/// The exact incoming kernel operation. Fields are immutable to the driver.
/// Pointer values are the original guest arguments, never dereferenced here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalExec {
    number: i64,
    args: [u64; 6],
    pkru: Option<u32>,
}

impl OriginalExec {
    /// Original syscall number, including execve when the Tool normalizes it.
    pub fn number(&self) -> i64 {
        self.number
    }
    /// All six original argument registers, without rewriting ignored slots.
    pub fn args(&self) -> [u64; 6] {
        self.args
    }
    /// Actual guest PKRU saved by the original dispatch path.
    pub fn pkru(&self) -> Option<u32> {
        self.pkru
    }

    fn accepts(&self, number: i64, args: [u64; 6]) -> bool {
        if number != libc::SYS_execveat {
            return false;
        }
        if self.number == libc::SYS_execveat {
            return args == self.args;
        }
        if self.number != libc::SYS_execve {
            return false;
        }
        // Derive the exact operation through the same conversion as Detcore.
        // In particular the shared conversion retains the original sixth slot.
        let raw = reverie::syscalls::SyscallArgs::new(
            self.args[0] as usize,
            self.args[1] as usize,
            self.args[2] as usize,
            self.args[3] as usize,
            self.args[4] as usize,
            self.args[5] as usize,
        );
        let normalized: reverie::syscalls::SyscallArgs =
            reverie::syscalls::Execveat::from(reverie::syscalls::Execve::from(raw)).into();
        args == [
            normalized.arg0 as u64,
            normalized.arg1 as u64,
            normalized.arg2 as u64,
            normalized.arg3 as u64,
            normalized.arg4 as u64,
            normalized.arg5 as u64,
        ]
    }
}

/// Read-only observations of one actual native original dispatch. This is not
/// a watched-birth, target or interpreter authority and is not serializable.
/// The driver must supply those independent identities and revalidate them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecCut {
    original: OriginalExec,
    native: NativeExecCallbackFacts,
    instruction_pointer: u64,
    context: usize,
    fallback: bool,
}

impl ExecCut {
    /// Operation that the physical backend must execute, not its normalization.
    pub fn original(&self) -> &OriginalExec {
        &self.original
    }
    /// Actual callback ownership, FS, mask and current registration observations.
    pub fn native(&self) -> &NativeExecCallbackFacts {
        &self.native
    }
    /// Whether the genuine event used the owned fallback continuation.
    pub fn is_fallback(&self) -> bool {
        self.fallback
    }

    /// Actual running fallback's kernel-frame mask receipt, if available.
    /// This grants no Issue or target/bootstrap authority.
    pub fn resume_mask_receipt(&self) -> Option<super::continuation::NativeExecResumeReceipt> {
        super::continuation::native_exec_resume_receipt(&self.original_event())
    }

    pub(crate) fn original_event(&self) -> SyscallEvent {
        SyscallEvent {
            number: self.original.number,
            args: self.original.args,
            guest_pkru: self.original.pkru,
            instruction_pointer: self.instruction_pointer,
            context: self.context,
            dispatch: if self.fallback {
                SyscallDispatch::Fallback
            } else {
                SyscallDispatch::Trap
            },
            result: 0,
        }
    }

    fn capture(event: &SyscallEvent, site: &ExecSite) -> Result<Self, UnsupportedRefusal> {
        site.validate()?;
        if !is_exec(event.number) {
            return Err(refusal(
                "reverie-inguest: nested exec has no original exec dispatch",
            ));
        }
        if !matches!(
            event.dispatch,
            SyscallDispatch::Trap | SyscallDispatch::Fallback
        ) {
            return Err(refusal(
                "reverie-inguest: native exec requires an owned trap or fallback",
            ));
        }
        let native = exec_private::native_exec_callback_facts().ok_or_else(|| {
            refusal("reverie-inguest: native exec callback ownership or registrations differ")
        })?;
        if native.native_tid != site.tid || site.pid != site.tid || site.main_tid != site.tid {
            return Err(refusal(
                "reverie-inguest: native exec requires the actual main PID/TID",
            ));
        }
        Ok(Self {
            original: OriginalExec {
                number: event.number,
                args: event.args,
                pkru: event.guest_pkru,
            },
            native,
            instruction_pointer: event.instruction_pointer,
            context: event.context,
            fallback: matches!(event.dispatch, SyscallDispatch::Fallback),
        })
    }

    fn revalidate(&self, event: &SyscallEvent, site: &ExecSite) -> Result<(), UnsupportedRefusal> {
        if Self::capture(event, site)? != *self {
            return Err(refusal(
                "reverie-inguest: native exec original event or physical cut changed",
            ));
        }
        Ok(())
    }
}

pub(super) struct ExecSite {
    pub tid: i32,
    pub pid: i32,
    pub main_tid: i32,
    pub in_handler: bool,
    pub staged_signals: bool,
    pub ending: bool,
    pub signal_delivery: bool,
    pub guest_filter: bool,
    pub guest_signal_mode: bool,
    pub fork_state: bool,
}

impl ExecSite {
    fn validate(&self) -> Result<(), UnsupportedRefusal> {
        if !self.in_handler
            || self.staged_signals
            || self.ending
            || self.signal_delivery
            || self.guest_filter
            || self.guest_signal_mode
            || self.fork_state
        {
            return Err(refusal(
                "reverie-inguest: native exec dispatch is not quiescent",
            ));
        }
        Ok(())
    }
}

/// A provision/revalidation refusal permits ordinary Detcore rollback only
/// after any native ticket and FD leases have been cancelled. A terminal
/// transport/ownership failure must never be disguised as a returned errno.
#[derive(Clone, Copy, Debug)]
pub enum NativeExecFailure {
    /// Named backend refusal; no replacement image ran.
    Refused(UnsupportedRefusal),
    /// Irreversible transport, ticket or descriptor-ownership failure.
    Terminal(TerminalExecFailure),
}

/// The continuing owned run cannot safely return into its old Tool future.
#[derive(Clone, Copy, Debug)]
pub struct TerminalExecFailure {
    /// Static, bounded backend diagnostic; no guest-controlled formatting.
    pub diagnostic: &'static str,
}

/// Genuine returned kernel exec errno and its actual permission effect.
/// Authorization continues to compare immutable OriginalExec; the host applies
/// this result to the current event even on errno before guest completion.
#[derive(Clone, Copy, Debug)]
pub struct ReturnedNativeExec {
    /// Kernel errno, never a named refusal or successful exec.
    pub errno: Errno,
    /// Actual post-kernel guest PKRU, or the scalar gate's None.
    pub pkru: Option<u32>,
}

/// An installer-selected driver for the actual outer Tool, never its subtool.
/// Ordinary hosts keep None; there is no Config/environment selector.
///
/// # Safety
/// The installer must retain genuine watched-birth and immutable target,
/// namespace/interpreter authority for this exact host. Capture is a read-only
/// operation before the Tool handler: it must validate the real old state,
/// retain the actual old table's nonserializable preparation receipt, and make
/// no scheduler/time/PRNG change, ticket or FD provision. Capture failures are
/// deferred until injection so existing preparation/rollback still executes.
/// Returned sessions must obey their contracts; credentials/digests do not
/// attest kernel exec. Never serialize a future, guard or continuation.
pub unsafe trait NativeExecDriver<T: Tool>: Send + Sync {
    /// Bind the genuine newly constructed initial state before its real
    /// thread-start callback. No successor invokes this hook. The caller owns
    /// the actual shared InitialImage lifecycle and same native control; the
    /// implementation must check the actual physical leader, never a request
    /// ID or model snapshot. Ordinary hosts have no driver and skip this.
    fn bind_initial_state(
        &self,
        _tool: &T,
        _state: &mut T::ThreadState,
        _physical_tid: i32,
    ) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "native driver has no initial physical-state binding",
        ))
    }

    /// Bind the actual fresh Guest signal answer before native post-exec.
    /// The caller queries that genuine lifecycle Guest, not a saved frame or
    /// serialized identity. Ordinary hosts have no driver and skip this hook.
    fn bind_post_exec_state(
        &self,
        _state: &mut T::ThreadState,
        _mode: reverie::BackendSignalControlMode,
        _actual: Option<reverie::SignalTaskIdentity>,
    ) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "native driver has no fresh signal-state binding",
        ))
    }

    /// Validate every physical guest mapping/permission operation against the
    /// actual retained immutable executable catalog. Enforce both executable
    /// grants and attempted writes to executable file extents, before a COW
    /// page can be modified. This runs without suspension immediately before
    /// the call, using the same one-thread/fd/mapping writer exclusion as the
    /// installed owner. Initial/Complete scans do not replace this policy.
    /// The default refuses relevant operations; a mock/inactive driver cannot
    /// accidentally grant executable mapping authority.
    fn check_mapping(&self, number: i64, args: [u64; 6]) -> Result<(), UnsupportedRefusal> {
        if matches!(
            number,
            libc::SYS_mmap
                | libc::SYS_mprotect
                | libc::SYS_pkey_mprotect
                | libc::SYS_shmat
                | libc::SYS_remap_file_pages
                | libc::SYS_personality
        ) {
            Err(refusal("native executable mapping owner is not installed"))
        } else {
            let _ = args;
            Ok(())
        }
    }

    /// Inspect the actual old state while its dispatch guards are still owned.
    /// Retain receipt/session data borrowing only this genuine driver owner.
    /// Never retain a borrow of `state`, because the Tool prepares its
    /// replacement in that same storage; the original data receipt keeps the
    /// admission borrow alive through physical handoff or cancellation.
    fn capture_old<'owner>(
        &'owner self,
        tool: &T,
        state: &T::ThreadState,
        cut: &ExecCut,
        rpc: &CoordinatorRpc<T::GlobalState>,
    ) -> Result<Box<dyn NativeExecSession<T> + 'owner>, UnsupportedRefusal>;
}

/// One original dispatch's retained old-state receipt.
///
/// # Safety
/// Prepare must revalidate the real already-prepared Tool/state against its
/// live old receipt, including descriptions dropped by CLOEXEC, before any
/// physical exec. It must perform bounded authenticated state/runtime handling,
/// exact immutable target/bootstrap/mask qualification and neutral control RPC.
/// A Refused prepare result must own no outstanding ticket or FD lease; cleanup
/// failure is Terminal. Any returned transaction owns all native provision
/// leases. The synchronous methods may borrow live data only for their call.
pub unsafe trait NativeExecSession<T: Tool>: Send + Sync {
    /// Prepare using direct live borrows, without reacquiring ToolHost locks.
    fn prepare<'a>(
        &'a mut self,
        tool: &T,
        state: &T::ThreadState,
        cut: &ExecCut,
        rpc: &CoordinatorRpc<T::GlobalState>,
    ) -> Result<Box<dyn PreparedNativeExec<T> + 'a>, NativeExecFailure>;
}

/// Affine native ticket and reserved bootstrap FD/OFD leases.
///
/// # Safety
/// Revalidate must compare the same real prepared state/old receipt, runtime
/// counters, observer/empty-forwarding cut and immutable objects. Issue/call
/// must repeat its final physical checks after the last neutral acknowledgment,
/// preserve the independently proved current guest resume mask/registrations,
/// and execute exactly `cut.original()` through the authenticated fixed native
/// leaf. This first physical domain requires actual Fallback with the retained
/// genuine kernel-frame resume receipt; Trap/hook observations cannot qualify.
/// After statistics seal, use only the separately installed preallocated
/// raw native-control exchange, never the ordinary counted/timed RPC path.
/// The final exact live Tool/state encoding must be rechecked against the seal
/// using the actual borrows passed to issue_and_call, after its final control
/// acknowledgment. No Rust/TLS/libc runs between Guest FS selection and Tool FS restore.
/// Success replaces the image and cannot return. Any Ok value below is ONLY a
/// genuine returned kernel errno, never a successful exec or an invented errno.
/// The actual returned PKRU must survive cancellation unchanged; cancellation
/// must not mutate the restored FS/mask/guest registrations.
/// Cancellation consumes the ticket and all FD leases; lease/cancel/transport
/// uncertainty is Terminal. Abandonment cannot silently release authorization.
pub unsafe trait PreparedNativeExec<T: Tool>: Send + Sync {
    /// Recheck actual prepared data after provision and before Issue.
    fn revalidate(
        &mut self,
        tool: &T,
        state: &T::ThreadState,
        cut: &ExecCut,
        rpc: &CoordinatorRpc<T::GlobalState>,
    ) -> Result<(), NativeExecFailure>;
    /// Issue and physically execute only the exact original event operation.
    ///
    /// # Safety
    /// Caller owns the same live dispatch/cut and has just revalidated it.
    /// Implementations must also enforce the final launch contract above.
    unsafe fn issue_and_call(
        &mut self,
        tool: &T,
        state: &T::ThreadState,
        cut: &ExecCut,
        rpc: &CoordinatorRpc<T::GlobalState>,
    ) -> Result<ReturnedNativeExec, NativeExecFailure>;
    /// Cancel a returned/refused operation and consume every provision lease.
    fn cancel(
        self: Box<Self>,
        rpc: &CoordinatorRpc<T::GlobalState>,
    ) -> Result<(), TerminalExecFailure>;
}

struct PreparedAttempt<'a, T: Tool> {
    prepared: Option<Box<dyn PreparedNativeExec<T> + 'a>>,
    active: bool,
}
impl<T: Tool> PreparedAttempt<'_, T> {
    fn cancel(mut self, rpc: &CoordinatorRpc<T::GlobalState>) {
        match self
            .prepared
            .take()
            .expect("owned native exec transaction")
            .cancel(rpc)
        {
            Ok(()) => self.active = false,
            Err(error) => terminate(error),
        }
    }
}
impl<T: Tool> Drop for PreparedAttempt<'_, T> {
    fn drop(&mut self) {
        if self.active {
            terminate(TerminalExecFailure {
                diagnostic: "reverie-inguest: native exec transaction abandoned before cancellation",
            });
        }
    }
}

pub(super) struct ExecInjection<'a, T: Tool> {
    tool: &'a T,
    main_tid: i32,
    captured: Result<(ExecCut, Box<dyn NativeExecSession<T> + 'a>), UnsupportedRefusal>,
    attempted: bool,
}

impl<'a, T: Tool> ExecInjection<'a, T> {
    pub(super) fn capture(
        tool: &'a T,
        driver: &'a Arc<dyn NativeExecDriver<T>>,
        events: (&SyscallEvent, &SyscallEvent),
        site: &ExecSite,
        state: &T::ThreadState,
        rpc: &CoordinatorRpc<T::GlobalState>,
    ) -> Self {
        let captured = ExecCut::capture(events.0, site).and_then(|cut| {
            cut.revalidate(events.1, site)?;
            driver
                .capture_old(tool, state, &cut, rpc)
                .map(|session| (cut, session))
        });
        Self {
            tool,
            main_tid: site.main_tid,
            captured,
            attempted: false,
        }
    }

    pub(super) fn main_tid(&self) -> i32 {
        self.main_tid
    }

    pub(super) fn inject(
        &mut self,
        operation: (i64, [u64; 6]),
        event: &SyscallEvent,
        site: &ExecSite,
        state: &T::ThreadState,
        rpc: &CoordinatorRpc<T::GlobalState>,
    ) -> Result<ReturnedNativeExec, UnsupportedRefusal> {
        if core::mem::replace(&mut self.attempted, true) {
            return Err(refusal(
                "reverie-inguest: native exec already attempted in this dispatch",
            ));
        }
        let (cut, session) = self.captured.as_mut().map_err(|error| *error)?;
        cut.revalidate(event, site)?;
        if !cut.original.accepts(operation.0, operation.1) {
            return Err(refusal(
                "reverie-inguest: native exec injection differs from the original operation",
            ));
        }
        let prepared = match session.prepare(self.tool, state, cut, rpc) {
            Ok(prepared) => prepared,
            Err(error) => return failed(error),
        };
        let mut attempt = PreparedAttempt {
            prepared: Some(prepared),
            active: true,
        };
        let validated = attempt
            .prepared
            .as_mut()
            .unwrap()
            .revalidate(self.tool, state, cut, rpc);
        match validated {
            Ok(()) => {}
            Err(NativeExecFailure::Terminal(error)) => terminate(error),
            Err(NativeExecFailure::Refused(error)) => {
                attempt.cancel(rpc);
                return Err(error);
            }
        }
        // Repeat physical ownership after provision/revalidation. The driver
        // also repeats checks after its final Issue acknowledgment, without any
        // additional allocating/counting/scheduling operation before the leaf.
        if let Err(error) = cut.revalidate(event, site) {
            attempt.cancel(rpc);
            return Err(error);
        }
        let result = unsafe {
            attempt
                .prepared
                .as_mut()
                .unwrap()
                .issue_and_call(self.tool, state, cut, rpc)
        };
        match result {
            Err(NativeExecFailure::Terminal(error)) => terminate(error),
            returned => {
                attempt.cancel(rpc);
                match returned {
                    Ok(errno) => Ok(errno),
                    Err(error) => failed(error),
                }
            }
        }
    }
}

fn failed<T>(failure: NativeExecFailure) -> Result<T, UnsupportedRefusal> {
    match failure {
        NativeExecFailure::Refused(error) => Err(error),
        NativeExecFailure::Terminal(error) => terminate(error),
    }
}

pub(super) fn is_exec(number: i64) -> bool {
    matches!(number, libc::SYS_execve | libc::SYS_execveat)
}
fn refusal(diagnostic: &'static str) -> UnsupportedRefusal {
    UnsupportedRefusal::new(
        UnsupportedOperation::NativeExec,
        Errno::EOPNOTSUPP,
        diagnostic,
    )
}
fn terminate(error: TerminalExecFailure) -> ! {
    let message = error.diagnostic.as_bytes();
    unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_write,
            [
                libc::STDERR_FILENO as u64,
                message.as_ptr() as u64,
                message.len().min(256) as u64,
                0,
                0,
                0,
            ],
        );
        exec_private::initialization_failed(core::ptr::null_mut())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mock_boundary_nonhandler_signal_ending_filter_and_fork_cuts_are_refused() {
        for invalid in 0..8 {
            let mut site = ExecSite {
                tid: 7,
                pid: 7,
                main_tid: 7,
                in_handler: true,
                staged_signals: false,
                ending: false,
                signal_delivery: false,
                guest_filter: false,
                guest_signal_mode: false,
                fork_state: false,
            };
            assert!(site.validate().is_ok());
            match invalid {
                0 => site.in_handler = false,
                1 => site.staged_signals = true,
                2 => site.ending = true,
                3 => site.signal_delivery = true,
                4 => site.guest_filter = true,
                5 => site.guest_signal_mode = true,
                6 => site.fork_state = true,
                7 => {
                    site.staged_signals = true;
                    site.guest_filter = true;
                }
                _ => unreachable!(),
            }
            let error = site.validate().unwrap_err();
            assert_eq!(error.operation, UnsupportedOperation::NativeExec);
            assert_eq!(error.errno, Errno::EOPNOTSUPP);
        }
    }
    #[test]
    fn mock_boundary_exact_execveat_compares_every_original_argument() {
        let original = OriginalExec {
            number: libc::SYS_execveat,
            args: [7, 0x1000, 0x2000, 0x3000, 0x1000, 9],
            pkru: Some(0x40),
        };
        assert!(original.accepts(libc::SYS_execveat, original.args));
        for i in 0..6 {
            let mut changed = original.args;
            changed[i] ^= 1;
            assert!(
                !original.accepts(libc::SYS_execveat, changed),
                "argument {i}"
            );
        }
        assert!(!original.accepts(libc::SYS_execve, original.args));
        assert!(!original.accepts(libc::SYS_getpid, original.args));
    }
    // Use the exact shared conversion used by Detcore, never a test normalizer.
    fn converted_execve_args(args: [u64; 6]) -> [u64; 6] {
        let raw = reverie::syscalls::SyscallArgs::new(
            args[0] as usize,
            args[1] as usize,
            args[2] as usize,
            args[3] as usize,
            args[4] as usize,
            args[5] as usize,
        );
        let converted: reverie::syscalls::SyscallArgs =
            reverie::syscalls::Execveat::from(reverie::syscalls::Execve::from(raw)).into();
        [
            converted.arg0 as u64,
            converted.arg1 as u64,
            converted.arg2 as u64,
            converted.arg3 as u64,
            converted.arg4 as u64,
            converted.arg5 as u64,
        ]
    }

    #[test]
    fn mock_boundary_only_exact_detcore_normalization_preserves_original_execve() {
        let original = OriginalExec {
            number: libc::SYS_execve,
            args: [0x1000, 0x2000, 0x3000, 0x77, 0x88, 0x99],
            pkru: None,
        };
        let normalized = converted_execve_args(original.args());
        assert_eq!(
            normalized,
            [
                libc::AT_FDCWD as i64 as u64,
                0x1000,
                0x2000,
                0x3000,
                0,
                0x99
            ]
        );
        assert!(original.accepts(libc::SYS_execveat, normalized));
        for i in 0..6 {
            let mut changed = normalized;
            changed[i] ^= 1;
            assert!(
                !original.accepts(libc::SYS_execveat, changed),
                "argument {i}"
            );
        }
        assert!(!original.accepts(libc::SYS_execve, original.args));
        assert_eq!(original.number(), libc::SYS_execve);
        assert_eq!(original.args(), [0x1000, 0x2000, 0x3000, 0x77, 0x88, 0x99]);
        assert_eq!(UnsupportedOperation::NonLeaderExec as u8, 0);
        assert_eq!(UnsupportedOperation::NativeExec as u8, 1);
        assert_eq!(original.pkru(), None);
    }

    #[test]
    fn mock_boundary_shared_execve_conversion_zero_tail_preserves_original_and_pkru() {
        let original = OriginalExec {
            number: libc::SYS_execve,
            args: [0x1000, 0x2000, 0x3000, 0x77, 0x88, 0],
            pkru: Some(0x40),
        };
        let before = original;
        let normalized = converted_execve_args(original.args());
        assert_eq!(normalized[5], 0);
        assert!(original.accepts(libc::SYS_execveat, normalized));
        for i in 0..6 {
            let mut changed = normalized;
            changed[i] ^= 1;
            assert!(
                !original.accepts(libc::SYS_execveat, changed),
                "argument {i}"
            );
        }
        assert!(!original.accepts(libc::SYS_execve, original.args()));
        assert_eq!(original, before);
        assert_eq!(original.pkru(), Some(0x40));
    }

    #[test]
    fn mock_boundary_forged_zero_tail_from_nonzero_original_execve_refuses() {
        let original = OriginalExec {
            number: libc::SYS_execve,
            args: [0x1000, 0x2000, 0x3000, 0x77, 0x88, 0x99],
            pkru: Some(0x40),
        };
        let before = original;
        let mut forged = converted_execve_args(original.args());
        assert_eq!(forged[5], 0x99);
        forged[5] = 0;
        assert!(!original.accepts(libc::SYS_execveat, forged));
        assert_eq!(original, before);
        assert_eq!(original.pkru(), Some(0x40));
    }
}

#[cfg(test)]
#[path = "native_exec_leaf_tests.rs"]
mod native_exec_leaf_tests;
