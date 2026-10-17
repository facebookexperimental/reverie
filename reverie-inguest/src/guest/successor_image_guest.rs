/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Bounded successor lifecycle on the real restored Tool/state. No fake syscall
//! event and no repeated thread-start. Native entry storage is affine-owned.

use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

use super::*;
use crate::guest::exec_private::ImageGuestEntry;
use crate::guest::exec_private::LifecyclePermit;

const REFUSAL_NAMES: [&str; 14] = [
    "none",
    "successor lifecycle guarded injection refused",
    "successor lifecycle register inspection is unsupported",
    "successor lifecycle register mutation is unsupported",
    "successor lifecycle guest stack is unsupported",
    "successor lifecycle timer programming is unsupported",
    "successor lifecycle RCB clock is unsupported",
    "successor lifecycle daemonization is unsupported",
    "successor lifecycle tail injection is unsupported",
    "successor lifecycle signal delivery is unsupported",
    "successor lifecycle siginfo mutation is unsupported",
    "successor lifecycle child signal publication is unsupported",
    "successor lifecycle alarm publication is unsupported",
    "successor lifecycle parked signal control is unsupported",
];

pub(super) struct SuccessorImageGuest<'a, T: Tool, R: HostRuntime> {
    tid: Pid,
    state: &'a mut T::ThreadState,
    rpc: &'a CoordinatorRpc<T::GlobalState>,
    runtime: &'a R,
    cpuid_interception: bool,
    tail: &'a TailResult,
    permit: &'a LifecyclePermit<'a>,
    entry: &'a mut ImageGuestEntry,
    #[cfg(feature = "exec-native-injection")]
    mapping_driver: Option<&'a dyn crate::guest::native_exec::NativeExecDriver<T>>,
    refusal: AtomicUsize,
}

impl<'a, T: Tool, R: HostRuntime> SuccessorImageGuest<'a, T, R> {
    pub(super) fn new(
        tid: Pid,
        state: &'a mut T::ThreadState,
        host: &'a ToolHost<T, R>,
        tail: &'a TailResult,
        permit: &'a LifecyclePermit<'a>,
        entry: &'a mut ImageGuestEntry,
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
        // Retain the first refused operation across the genuine post-exec. There is
        // no reset/take operation, even if the Tool handles or ignores errno.
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
impl<T: Tool, R: HostRuntime> GlobalRPC<T::GlobalState> for SuccessorImageGuest<'_, T, R> {
    async fn send_rpc(
        &self,
        message: <T::GlobalState as GlobalTool>::Request,
    ) -> <T::GlobalState as GlobalTool>::Response {
        if self.refusal.load(Ordering::Acquire) != 0 || self.permit.validate().is_err() {
            self.permit.terminate();
        }
        self.rpc.send_rpc(message).await
    }

    fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        self.rpc.config()
    }
}

#[reverie::tool]
impl<'a, T: Tool, R: HostRuntime> Guest<T> for SuccessorImageGuest<'a, T, R> {
    type Memory = GuestMemory<'a>;
    type Stack = LocalStack;

    fn tid(&self) -> Pid {
        self.tid
    }

    fn pid(&self) -> Pid {
        // The affine entry verified the actual native pid equals this tid.
        self.tid
    }

    fn ppid(&self) -> Option<Pid> {
        None
    }

    // Guest::auxv's ordinary implementation reads this actual process's
    // kernel auxv. Private GNU getauxval is deliberately not used.
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

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        if self.refusal.load(Ordering::Acquire) != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let (number, args) = syscall.into_parts();
        let number = number.id() as i64;
        let mut args = [
            args.arg0 as u64,
            args.arg1 as u64,
            args.arg2 as u64,
            args.arg3 as u64,
            args.arg4 as u64,
            args.arg5 as u64,
        ];
        // Lifecycle may not create/replace/terminate an image, admit an extra
        // filter/namespace, stage delivery, or activate keys/guest handlers.
        if matches!(
            number,
            libc::SYS_clone
                | libc::SYS_clone3
                | libc::SYS_fork
                | libc::SYS_vfork
                | libc::SYS_execve
                | libc::SYS_execveat
                | libc::SYS_exit
                | libc::SYS_exit_group
                | libc::SYS_rt_sigreturn
                | libc::SYS_rseq
                | libc::SYS_seccomp
                | libc::SYS_unshare
                | libc::SYS_setns
                | libc::SYS_mount
                | libc::SYS_umount2
                | libc::SYS_chroot
                | libc::SYS_pivot_root
                | libc::SYS_pkey_alloc
                | libc::SYS_pkey_free
                | libc::SYS_pkey_mprotect
                | libc::SYS_kill
                | libc::SYS_tkill
                | libc::SYS_tgkill
                | libc::SYS_rt_sigqueueinfo
                | libc::SYS_rt_tgsigqueueinfo
        ) || (number == libc::SYS_prctl && args[0] == libc::PR_SET_SECCOMP as u64)
            || (number == libc::SYS_arch_prctl && args[0] == 0x1001)
        {
            return Err(self.refuse(1));
        }
        #[cfg(feature = "exec-native-injection")]
        if let Some(driver) = self.mapping_driver
            && driver.check_mapping(number, args).is_err()
        {
            return Err(self.refuse(1));
        }
        if let Some(error) = injected_syscall_guard(self.runtime, number, args) {
            self.refuse(1);
            return Err(error);
        }
        if let Some(result) = super::super::restorer::mapping_change_result(number, args) {
            self.refuse(1);
            return Errno::from_ret(result as usize).map(|value| value as i64);
        }
        if let Some(result) =
            unsafe { super::super::protect::protect_forwarded_descriptor_change(number, args) }
        {
            self.refuse(1);
            return Errno::from_ret(result as usize).map(|value| value as i64);
        }
        // No fabricated event or stale old-image PKRU enters this route.
        let mask = match stripped_signal_mask(self.runtime, number, args) {
            Ok(mask) => mask,
            Err(error) => {
                self.refuse(1);
                return Err(error);
            }
        };
        if let Some(mask) = mask.as_ref() {
            args[1] = mask as *const u64 as u64;
        }
        let result = unsafe {
            crate::guest::exec_private::physical_lifecycle_syscall(
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

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;
    use crate::guest::exec_private::mark_successor_test_frontend_installed;
    use crate::guest::exec_private::successor_test_owner;

    #[derive(Default)]
    struct EchoGlobal;

    #[reverie::tool]
    impl GlobalTool for EchoGlobal {
        type Request = u64;
        type Response = u64;
        type Config = u64;

        async fn receive_rpc(&self, _from: Pid, message: u64) -> u64 {
            message + 10
        }
    }

    #[derive(Default)]
    struct LifecycleTool {
        mode: usize,
        memory: usize,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    #[reverie::tool]
    impl Tool for LifecycleTool {
        type GlobalState = EchoGlobal;
        type ThreadState = (u64, u64); // carried counter and noninitial PRNG state

        fn init_thread_state(
            &self,
            _child: Pid,
            _parent: Option<(Pid, &(u64, u64))>,
        ) -> (u64, u64) {
            panic!("successor must not initialize replacement state");
        }
        async fn handle_thread_start<G: Guest<Self>>(&self, _guest: &mut G) -> Result<(), Error> {
            panic!("successor must not call thread_start");
        }
        async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
            self.calls.lock().unwrap().push("post-exec");
            assert_eq!(*guest.thread_state(), (99, 0x1234_5678_abcd_4321));
            assert_eq!(*guest.config(), 901);
            assert_eq!(guest.send_rpc(2).await, 12);
            let regs = guest.regs().await;
            assert_eq!(regs.rsp, 0x1234_0000);
            assert_eq!(regs.rip, 0x5678_0000);
            assert_ne!(regs.fs_base, 0);
            match self.mode {
                1 => {
                    // A real phase6 physical call, with the actual PID result.
                    assert_eq!(
                        guest.inject(reverie::syscalls::Getpid::default()).await?,
                        raw_pid(libc::SYS_getpid).as_raw() as i64
                    );
                }
                2 => {
                    assert_eq!(
                        guest
                            .inject(reverie::syscalls::Fork::default())
                            .await
                            .unwrap_err(),
                        Errno::EOPNOTSUPP
                    );
                    return Ok(()); // Ignored refusal must remain irreversible.
                }
                3 => {
                    assert_eq!(
                        guest
                            .set_regs(regs)
                            .await
                            .unwrap_err()
                            .into_errno()
                            .unwrap(),
                        Errno::EOPNOTSUPP
                    );
                    return Ok(());
                }
                4 => return Err(Errno::EIO),
                5 => {
                    guest
                        .tail_inject(reverie::syscalls::Getpid::default())
                        .await;
                }
                _ => {}
            }
            // Continue the restored stream; compare to a precomputed oracle
            // rather than starting from an initial seed or checking call count.
            let state = guest.thread_state_mut();
            state.0 += 1;
            state.1 ^= state.1 << 13;
            state.1 ^= state.1 >> 7;
            state.1 ^= state.1 << 17;
            let address = AddrMut::from_raw(self.memory).unwrap();
            assert_eq!(guest.memory().write(address, &[0x5a; 16])?, 16);
            Ok(())
        }
        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            _syscall: Syscall,
        ) -> Result<i64, Error> {
            self.calls.lock().unwrap().push("syscall");
            assert_eq!(*guest.thread_state(), (100, 0xf2c4b6db626031e7));
            assert_eq!(guest.send_rpc(3).await, 13);
            guest.thread_state_mut().0 += 1;
            Ok(77)
        }
    }

    struct TestRuntime;

    impl HostRuntime for TestRuntime {
        fn fork_child_rebind(&self) {
            panic!("test lifecycle must not fork")
        }
        fn emit_stage(&self, _stage: &[u8]) {}
        fn fork_child_reset(&self, _event: &SyscallEvent) {
            panic!("test lifecycle must not rebind")
        }
        fn cpuid_interception_enabled(&self) -> bool {
            false
        }
        fn exit_process_stats(&self, _tid: Pid) -> io::Result<()> {
            Ok(())
        }
        fn read_clock(&self) -> io::Result<u64> {
            panic!("ImageGuest must not query a fabricated clock")
        }
        fn signal_action_supported(&self, number: i64, args: [u64; 6]) -> bool {
            crate::guest::signal::signal_action_supported(number, args)
        }
        fn reserved_signal_mask(&self) -> u64 {
            1_u64 << (libc::SIGSYS - 1)
        }
    }

    fn read_frame(stream: &mut UnixStream) -> Option<Vec<u8>> {
        let mut header = [0_u8; 4];
        match stream.read(&mut header[..1]).unwrap() {
            0 => return None,
            1 => {}
            _ => unreachable!(),
        }
        stream.read_exact(&mut header[1..]).unwrap();
        let length = u32::from_be_bytes(header) as usize;
        assert!(length <= 128);
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).unwrap();
        Some(payload)
    }

    fn write_frame(stream: &mut UnixStream, payload: &[u8]) {
        stream
            .write_all(&(payload.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(payload).unwrap();
    }

    fn test_rpc() -> (
        CoordinatorRpc<EchoGlobal>,
        std::thread::JoinHandle<Vec<u64>>,
    ) {
        let (client, mut server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let tid = raw_pid(libc::SYS_gettid);
        let worker = std::thread::spawn(move || {
            write_frame(
                &mut server,
                &reverie_rpc_transport::codec::encode(&901_u64).unwrap(),
            );
            let mut requests = Vec::new();
            while let Some(frame) = read_frame(&mut server) {
                let envelope: reverie_rpc_transport::RequestEnvelope<u64> =
                    reverie_rpc_transport::codec::decode(&frame).unwrap();
                assert_eq!(envelope.from, tid);
                requests.push(envelope.request);
                write_frame(
                    &mut server,
                    &reverie_rpc_transport::codec::encode(&(envelope.request + 10)).unwrap(),
                );
            }
            requests
        });
        let client = reverie_rpc_transport::BlockingRpcClient::from_connected_stream(
            crate::guest::rpc::GuestRpcStream::from(client),
            tid,
        )
        .unwrap();
        let rpc = CoordinatorRpc::from_live_client("unused-lifecycle-test", client, |_, _| {
            panic!("test lifecycle must retain its original connection")
        })
        .unwrap();
        (rpc, worker)
    }

    fn isolated(body: impl FnOnce() + std::panic::UnwindSafe, expected: i32) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let status = if std::panic::catch_unwind(body).is_ok() {
                0
            } else {
                125
            };
            unsafe { libc::_exit(status) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child wait status {status}");
        assert_eq!(libc::WEXITSTATUS(status), expected);
    }

    fn host(
        mode: usize,
        memory: usize,
        calls: Arc<Mutex<Vec<&'static str>>>,
    ) -> (
        Box<ToolHost<LifecycleTool, TestRuntime>>,
        std::thread::JoinHandle<Vec<u64>>,
    ) {
        let (rpc, worker) = test_rpc();
        let tool = LifecycleTool {
            mode,
            memory,
            calls,
        };
        (
            Box::new(ToolHost::new(
                tool,
                rpc,
                raw_pid(libc::SYS_getpid),
                HashSet::from([Sysno::getpid]),
                false,
                TestRuntime,
            )),
            worker,
        )
    }

    #[test]
    fn successor_real_post_exec_continues_state_and_physical_injection_before_dispatch_once() {
        isolated(
            || {
                let (native, owner, mut entry) = successor_test_owner();
                let calls = Arc::new(Mutex::new(Vec::new()));
                let mut memory = Box::new([0_u8; 16]);
                let (host, worker) = host(1, memory.as_mut_ptr() as usize, calls.clone());
                unsafe { host.bind_successor_image_control(&owner) }.unwrap();
                unsafe { host.restore_prepared_exec_state((99, 0x1234_5678_abcd_4321), &owner) }
                    .unwrap();
                assert!(host.states.lock().is_empty());
                assert!(calls.lock().unwrap().is_empty());
                mark_successor_test_frontend_installed(&owner);
                host.run_post_exec_before_loader(&mut entry, &owner)
                    .unwrap();
                assert_eq!(native.successor_test_phase(), 2);
                assert_eq!(*memory, [0x5a; 16]); // pre-loader consumer, before dispatch
                assert_eq!(*calls.lock().unwrap(), ["post-exec"]);
                assert_eq!(
                    host.states.lock().get(&raw_pid(libc::SYS_gettid).as_raw()),
                    Some(&(100, 0xf2c4b6db626031e7))
                );
                assert!(host.prepared_exec.lock().is_none());
                // A controlled component dispatch after completion; this supplies
                // no native frontend/kernel-exec or successor acceptance credit.
                let mut event = SyscallEvent {
                    number: libc::SYS_getpid,
                    args: [0; 6],
                    instruction_pointer: 0,
                    result: 0,
                    context: 0,
                    dispatch: SyscallDispatch::Trap,
                    guest_pkru: None,
                };
                unsafe { host.dispatch(&mut event) };
                assert_eq!(event.result, 77);
                assert_eq!(*calls.lock().unwrap(), ["post-exec", "syscall"]);
                assert!(
                    host.run_post_exec_before_loader(&mut entry, &owner)
                        .is_err()
                );
                assert_eq!(*calls.lock().unwrap(), ["post-exec", "syscall"]);
                drop(host);
                assert_eq!(worker.join().unwrap(), [2, 3]);
            },
            0,
        );
    }

    #[test]
    fn successor_ignored_refusal_and_hook_error_never_publish_completed_state() {
        for mode in [2, 3, 4] {
            isolated(
                move || {
                    let (native, owner, mut entry) = successor_test_owner();
                    let calls = Arc::new(Mutex::new(Vec::new()));
                    let mut memory = Box::new([0_u8; 16]);
                    let (host, worker) = host(mode, memory.as_mut_ptr() as usize, calls.clone());
                    unsafe { host.bind_successor_image_control(&owner) }.unwrap();
                    unsafe {
                        host.restore_prepared_exec_state((99, 0x1234_5678_abcd_4321), &owner)
                    }
                    .unwrap();
                    mark_successor_test_frontend_installed(&owner);
                    let error = host
                        .run_post_exec_before_loader(&mut entry, &owner)
                        .unwrap_err();
                    if mode == 4 {
                        assert_eq!(error.raw_os_error(), Some(libc::EIO));
                    } else {
                        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
                    }
                    assert!(host.states.lock().is_empty());
                    let pending = host.prepared_exec.lock();
                    assert!(matches!(
                        pending.as_ref().unwrap().phase,
                        PreparedExecPhase::Failed
                    ));
                    assert_eq!(pending.as_ref().unwrap().state, (99, 0x1234_5678_abcd_4321));
                    drop(pending);
                    assert_eq!(*memory, [0; 16]);
                    assert_eq!(native.successor_test_runtime_ready(), 0);
                    assert!(
                        host.run_post_exec_before_loader(&mut entry, &owner)
                            .is_err()
                    );
                    assert_eq!(*calls.lock().unwrap(), ["post-exec"]);
                    drop(host);
                    assert_eq!(worker.join().unwrap(), [2]);
                },
                0,
            );
        }
    }

    #[test]
    fn successor_pending_state_cannot_enter_dispatch_or_completed_restore_or_tail_route() {
        for mode in [0, 5] {
            isolated(
                move || {
                    let (_native, owner, mut entry) = successor_test_owner();
                    let (host, _worker) = host(mode, 0, Arc::new(Mutex::new(Vec::new())));
                    unsafe { host.bind_successor_image_control(&owner) }.unwrap();
                    unsafe {
                        host.restore_prepared_exec_state((99, 0x1234_5678_abcd_4321), &owner)
                    }
                    .unwrap();
                    assert!(host.restore_current_thread_state((1, 2)).is_err());
                    if mode == 5 {
                        mark_successor_test_frontend_installed(&owner);
                        let _ = host.run_post_exec_before_loader(&mut entry, &owner);
                    } else {
                        let mut event = SyscallEvent {
                            number: libc::SYS_getpid,
                            args: [0; 6],
                            instruction_pointer: 0,
                            result: 0,
                            context: 0,
                            dispatch: SyscallDispatch::Trap,
                            guest_pkru: None,
                        };
                        unsafe { host.dispatch(&mut event) };
                    }
                    panic!("incomplete successor route returned");
                },
                127,
            );
        }
    }

    #[test]
    fn successor_duplicate_restore_and_wrong_host_cannot_use_restored_state() {
        isolated(
            || {
                let (_native, owner, mut entry) = successor_test_owner();
                let calls = Arc::new(Mutex::new(Vec::new()));
                let (first, worker1) = host(0, 0, calls.clone());
                let (other, worker2) = host(0, 0, calls.clone());
                unsafe { first.bind_successor_image_control(&owner) }.unwrap();
                unsafe { first.restore_prepared_exec_state((99, 0x1234_5678_abcd_4321), &owner) }
                    .unwrap();
                mark_successor_test_frontend_installed(&owner);
                assert!(
                    other
                        .run_post_exec_before_loader(&mut entry, &owner)
                        .is_err()
                );
                assert!(
                    first
                        .run_post_exec_before_loader(&mut entry, &owner)
                        .is_err()
                );
                assert!(calls.lock().unwrap().is_empty());
                assert!(first.states.lock().is_empty());
                drop(first);
                drop(other);
                assert!(worker1.join().unwrap().is_empty());
                assert!(worker2.join().unwrap().is_empty());
            },
            0,
        );
        isolated(
            || {
                let (_native, owner, mut entry) = successor_test_owner();
                let calls = Arc::new(Mutex::new(Vec::new()));
                let (host, worker) = host(0, 0, calls.clone());
                unsafe { host.bind_successor_image_control(&owner) }.unwrap();
                unsafe { host.restore_prepared_exec_state((99, 0x1234_5678_abcd_4321), &owner) }
                    .unwrap();
                assert!(unsafe { host.restore_prepared_exec_state((1, 2), &owner) }.is_err());
                mark_successor_test_frontend_installed(&owner);
                assert!(
                    host.run_post_exec_before_loader(&mut entry, &owner)
                        .is_err()
                );
                assert!(calls.lock().unwrap().is_empty());
                drop(host);
                assert!(worker.join().unwrap().is_empty());
            },
            0,
        );
    }
}
