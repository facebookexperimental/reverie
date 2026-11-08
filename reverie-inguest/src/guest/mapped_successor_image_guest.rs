/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Mapped successor restored-root lifecycle with guarded injection.
//! Only callback order and published state are native parity; this
//! guest's entry registers and physical call are mapped-specific.

use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

use super::*;
use crate::guest::exec_private::InitialLifecyclePermit;
use crate::guest::exec_private::MappedSuccessorEntry;

const REFUSAL_NAMES: [&str; 14] = [
    "none",
    "mapped successor lifecycle guarded injection refused",
    "mapped successor lifecycle register inspection is unsupported",
    "mapped successor lifecycle register mutation is unsupported",
    "mapped successor lifecycle guest stack is unsupported",
    "mapped successor lifecycle timer programming is unsupported",
    "mapped successor lifecycle RCB clock is unsupported",
    "mapped successor lifecycle daemonization is unsupported",
    "mapped successor lifecycle tail injection is unsupported",
    "mapped successor lifecycle signal delivery is unsupported",
    "mapped successor lifecycle siginfo mutation is unsupported",
    "mapped successor lifecycle child signal publication is unsupported",
    "mapped successor lifecycle alarm publication is unsupported",
    "mapped successor lifecycle parked signal control is unsupported",
];

pub(super) struct MappedSuccessorImageGuest<'a, T: Tool, R: HostRuntime> {
    tid: Pid,
    state: &'a mut T::ThreadState,
    rpc: &'a CoordinatorRpc<T::GlobalState>,
    runtime: &'a R,
    cpuid_interception: bool,
    tail: &'a TailResult,
    permit: &'a InitialLifecyclePermit<'a>,
    entry: &'a MappedSuccessorEntry,
    #[cfg(feature = "exec-native-injection")]
    mapping_driver: Option<&'a dyn crate::guest::native_exec::NativeExecDriver<T>>,
    refusal: AtomicUsize,
}

impl<'a, T: Tool, R: HostRuntime> MappedSuccessorImageGuest<'a, T, R> {
    pub(super) fn new(
        tid: Pid,
        state: &'a mut T::ThreadState,
        host: &'a ToolHost<T, R>,
        tail: &'a TailResult,
        permit: &'a InitialLifecyclePermit<'a>,
        entry: &'a MappedSuccessorEntry,
    ) -> Self {
        Self {
            tid,
            state,
            rpc: &host.rpc,
            runtime: &host.runtime,
            cpuid_interception: host.cpuid_interception,
            tail,
            permit,
            entry,
            #[cfg(feature = "exec-native-injection")]
            mapping_driver: host.native_exec_driver.as_deref(),
            refusal: AtomicUsize::new(0),
        }
    }

    fn refuse(&self, operation: usize) -> Errno {
        let _ = self
            .refusal
            .compare_exchange(0, operation, Ordering::AcqRel, Ordering::Acquire);
        Errno::EOPNOTSUPP
    }

    fn terminal(&self, operation: usize) -> ! {
        self.refuse(operation);
        self.permit.terminate()
    }

    pub(super) fn check_refusal(&self) -> io::Result<()> {
        let operation = self.refusal.load(Ordering::Acquire);
        if operation == 0 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                REFUSAL_NAMES[operation],
            ))
        }
    }
}

#[reverie::tool]
impl<T: Tool, R: HostRuntime> GlobalRPC<T::GlobalState> for MappedSuccessorImageGuest<'_, T, R> {
    async fn send_rpc(
        &self,
        message: <T::GlobalState as GlobalTool>::Request,
    ) -> <T::GlobalState as GlobalTool>::Response {
        if self.refusal.load(Ordering::Acquire) != 0
            || self.permit.validate_mapped_injection().is_err()
        {
            self.permit.terminate();
        }
        self.rpc.send_rpc(message).await
    }

    fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        self.rpc.config()
    }
}

#[reverie::tool]
impl<'a, T: Tool, R: HostRuntime> Guest<T> for MappedSuccessorImageGuest<'a, T, R> {
    fn reserved_input_control(&self) -> Option<reverie::reserved_input::ReservedInputControl> {
        None
    }

    type Memory = GuestMemory<'a>;
    type Stack = LocalStack;

    fn tid(&self) -> Pid {
        self.tid
    }

    fn pid(&self) -> Pid {
        self.tid
    }

    fn ppid(&self) -> Option<Pid> {
        None
    }

    fn is_runtime_owned_fd(&self, fd: i32) -> bool {
        crate::guest::protect::is_runtime_owned_fd(fd)
    }

    fn memory(&self) -> Self::Memory {
        GuestMemory::new(self.tail)
    }

    fn thread_state_mut(&mut self) -> &mut T::ThreadState {
        self.state
    }

    fn thread_state(&self) -> &T::ThreadState {
        self.state
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        self.permit.regs(self.entry)
    }

    async fn set_regs(&mut self, _regs: libc::user_regs_struct) -> Result<(), Error> {
        Err(self.refuse(3).into())
    }

    async fn stack(&mut self) -> Self::Stack {
        self.terminal(4)
    }

    async fn daemonize(&mut self) {
        self.terminal(7)
    }

    async fn inject_with_purpose<S: SyscallInfo>(
        &mut self,
        syscall: S,
        purpose: reverie::InjectionPurpose,
    ) -> std::result::Result<i64, reverie::Error> {
        match purpose {
            reverie::InjectionPurpose::Application
            | reverie::InjectionPurpose::Pselect6WrapperValidation => {
                self.inject(syscall).await.map_err(reverie::Error::from)
            }
        }
    }

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        if self.refusal.load(Ordering::Acquire) != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let (number, args) = syscall.into_parts();
        let number = number.id() as i64;
        let args = [
            args.arg0 as u64,
            args.arg1 as u64,
            args.arg2 as u64,
            args.arg3 as u64,
            args.arg4 as u64,
            args.arg5 as u64,
        ];
        let (mut args, mask) = match guard_lifecycle_injection(self.runtime, number, args, || {
            #[cfg(feature = "exec-native-injection")]
            {
                self.mapping_driver
                    .is_none_or(|driver| driver.check_mapping(number, args).is_ok())
            }
            #[cfg(not(feature = "exec-native-injection"))]
            {
                true
            }
        }) {
            GuardedLifecycleInjection::Physical { args, mask } => (args, mask),
            GuardedLifecycleInjection::Refused(result) => {
                self.refuse(1);
                return result;
            }
        };
        if let Some(mask) = mask.as_ref() {
            args[1] = mask as *const u64 as u64;
        }
        let result = unsafe {
            crate::guest::exec_private::physical_mapped_lifecycle_syscall(
                self.permit,
                number,
                args,
                self.permit.pkru(self.entry),
            )
        };
        match result {
            Ok(result) => Errno::from_ret(result.result as usize).map(|value| value as i64),
            Err(_) => Err(self.refuse(1)),
        }
    }

    async fn tail_inject<S: SyscallInfo>(&mut self, _syscall: S) -> Never {
        self.terminal(8)
    }

    fn set_timer(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        Err(self.refuse(5).into())
    }

    fn set_timer_precise(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        Err(self.refuse(5).into())
    }

    fn read_clock(&mut self) -> Result<u64, Error> {
        Err(self.refuse(6).into())
    }

    fn backtrace(&mut self) -> Option<reverie::Backtrace> {
        self.terminal(4)
    }

    fn has_cpuid_interception(&self) -> bool {
        self.cpuid_interception && self.runtime.cpuid_interception_enabled()
    }

    async fn defer_signal_delivery(&mut self, _event: reverie::SignalEvent) -> Result<(), Error> {
        Err(self.refuse(9).into())
    }

    async fn defer_signal_delivery_before_syscall(
        &mut self,
        _event: reverie::SignalEvent,
    ) -> Result<(), Error> {
        Err(self.refuse(9).into())
    }

    fn set_signal_info(&mut self, _info: [u8; reverie::SIGNAL_INFO_SIZE]) -> Result<(), Errno> {
        Err(self.refuse(10))
    }

    async fn queue_child_exit_signal(
        &mut self,
        _event: reverie::SignalEvent,
    ) -> reverie::ChildExitSignalOutcome {
        reverie::ChildExitSignalOutcome::RejectedBeforeCommit {
            kind: reverie::ChildExitSignalErrorKind::Unsupported,
            errno: self.refuse(11),
        }
    }

    async fn queue_process_alarm_signal(
        &mut self,
        _event: reverie::SignalEvent,
    ) -> reverie::ProcessAlarmSignalOutcome {
        reverie::ProcessAlarmSignalOutcome::RejectedBeforeCommit {
            kind: reverie::ProcessAlarmSignalErrorKind::Unsupported,
            errno: self.refuse(12),
        }
    }

    async fn observe_parked_signal(
        &mut self,
        _site: reverie::CallbackSignalSite,
        _lease: reverie::ParkedObservationLease,
    ) -> Result<reverie::ParkedSignalObservation, reverie::SignalObservationFailure> {
        Err(reverie::SignalObservationFailure::RejectedBeforeRemoval {
            errno: self.refuse(13),
        })
    }

    async fn terminate_from_parked_signal(
        &mut self,
        _selection: reverie::PreparedSignalToken,
    ) -> Result<Never, reverie::SignalObservationFailure> {
        Err(reverie::SignalObservationFailure::RejectedBeforeRemoval {
            errno: self.refuse(13),
        })
    }

    async fn cancel_parked_signal(
        &mut self,
        _context: reverie::ParkedSignalFailureContext,
    ) -> Result<Never, reverie::SignalObservationFailure> {
        Err(reverie::SignalObservationFailure::RejectedBeforeRemoval {
            errno: self.refuse(13),
        })
    }
}
