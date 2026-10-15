/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Bounded eager InitialImage lifecycle, before guest ld.so runs. There is no
//! syscall event, resumable callback frame, guest stack or register snapshot.

use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

use super::*;
use crate::guest::exec_private::InitialImageControl;

const REFUSAL_NAMES: [&str; 14] = [
    "none",
    "InitialImage lifecycle syscall injection is unsupported",
    "InitialImage lifecycle register inspection is unsupported",
    "InitialImage lifecycle register mutation is unsupported",
    "InitialImage lifecycle guest stack is unsupported",
    "InitialImage lifecycle timer programming is unsupported",
    "InitialImage lifecycle RCB clock is unsupported",
    "InitialImage lifecycle daemonization is unsupported",
    "InitialImage lifecycle tail injection is unsupported",
    "InitialImage lifecycle signal delivery is unsupported",
    "InitialImage lifecycle siginfo mutation is unsupported",
    "InitialImage lifecycle child signal publication is unsupported",
    "InitialImage lifecycle alarm publication is unsupported",
    "InitialImage lifecycle parked signal control is unsupported",
];

pub(super) struct ImageGuest<'a, T: Tool, R: HostRuntime> {
    tid: Pid,
    state: &'a mut T::ThreadState,
    rpc: &'a CoordinatorRpc<T::GlobalState>,
    runtime: &'a R,
    cpuid_interception: bool,
    tail: &'a TailResult,
    control: &'a InitialImageControl,
    refusal: AtomicUsize,
}

impl<'a, T: Tool, R: HostRuntime> ImageGuest<'a, T, R> {
    pub(super) fn new(
        tid: Pid,
        state: &'a mut T::ThreadState,
        rpc: &'a CoordinatorRpc<T::GlobalState>,
        runtime: &'a R,
        cpuid_interception: bool,
        tail: &'a TailResult,
        control: &'a InitialImageControl,
    ) -> Self {
        Self {
            tid,
            state,
            rpc,
            runtime,
            cpuid_interception,
            tail,
            control,
            refusal: AtomicUsize::new(0),
        }
    }

    fn refuse(&self, operation: usize) -> Errno {
        // Retain the first attempted operation across both callbacks. There is
        // no reset/take operation, even if the Tool handles or ignores errno.
        let _ = self
            .refusal
            .compare_exchange(0, operation, Ordering::AcqRel, Ordering::Acquire);
        Errno::EOPNOTSUPP
    }

    fn terminal(&self, operation: usize) -> ! {
        self.refuse(operation);
        self.control.terminate_lifecycle()
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
impl<T: Tool, R: HostRuntime> GlobalRPC<T::GlobalState> for ImageGuest<'_, T, R> {
    async fn send_rpc(
        &self,
        message: <T::GlobalState as GlobalTool>::Request,
    ) -> <T::GlobalState as GlobalTool>::Response {
        if self.refusal.load(Ordering::Acquire) != 0 {
            self.control.terminate_lifecycle();
        }
        self.rpc.send_rpc(message).await
    }

    fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        self.rpc.config()
    }
}

#[reverie::tool]
impl<'a, T: Tool, R: HostRuntime> Guest<T> for ImageGuest<'a, T, R> {
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
        GuestMemory {
            local: LocalMemory::new(),
            tail: self.tail,
        }
    }

    fn thread_state_mut(&mut self) -> &mut T::ThreadState {
        self.state
    }

    fn thread_state(&self) -> &T::ThreadState {
        self.state
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        self.terminal(2)
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

    async fn inject<S: SyscallInfo>(&mut self, _syscall: S) -> Result<i64, Errno> {
        Err(self.refuse(1))
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
    use crate::guest::exec_private::lifecycle_test_owner;
    use crate::guest::exec_private::mark_lifecycle_test_frontend_installed;

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
        type ThreadState = u64;

        fn init_thread_state(&self, child: Pid, parent: Option<(Pid, &u64)>) -> u64 {
            assert_eq!(child, raw_pid(libc::SYS_gettid));
            assert!(parent.is_none());
            self.calls.lock().unwrap().push("init");
            0
        }

        async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
            self.calls.lock().unwrap().push("start");
            assert_eq!(guest.pid(), raw_pid(libc::SYS_getpid));
            assert_eq!(guest.tid(), raw_pid(libc::SYS_gettid));
            assert!(guest.ppid().is_none());
            assert_eq!(*guest.config(), 901);
            assert_eq!(guest.send_rpc(1).await, 11);
            assert_eq!(*guest.thread_state(), 0);
            *guest.thread_state_mut() = 1;
            match self.mode {
                1 => {
                    let error = guest
                        .inject(reverie::syscalls::Getpid::default())
                        .await
                        .unwrap_err();
                    assert_eq!(error, Errno::EOPNOTSUPP);
                }
                2 => {
                    let error = guest
                        .set_regs(unsafe { core::mem::zeroed() })
                        .await
                        .unwrap_err();
                    assert_eq!(error.into_errno().unwrap(), Errno::EOPNOTSUPP);
                }
                3 => {
                    let error = guest.set_timer(TimerSchedule::Rcbs(1)).unwrap_err();
                    assert_eq!(error.into_errno().unwrap(), Errno::EOPNOTSUPP);
                }
                4 => {
                    let error = guest.set_timer_precise(TimerSchedule::Rcbs(1)).unwrap_err();
                    assert_eq!(error.into_errno().unwrap(), Errno::EOPNOTSUPP);
                }
                5 => {
                    let error = guest.read_clock().unwrap_err();
                    assert_eq!(error.into_errno().unwrap(), Errno::EOPNOTSUPP);
                }
                6 => {
                    let _ = guest.regs().await;
                }
                7 => {
                    let _ = guest.stack().await;
                }
                8 => {
                    guest
                        .tail_inject(reverie::syscalls::Getpid::default())
                        .await;
                }
                10 => return Err(Errno::EIO.into()),
                12 => {
                    guest.daemonize().await;
                }
                13 => {
                    assert!(guest.backtrace().is_none());
                }
                _ => {}
            }
            Ok(()) // Intentionally ignores supported-return-type refusals.
        }

        async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
            self.calls.lock().unwrap().push("post-exec");
            assert_eq!(*guest.thread_state(), 1);
            assert_eq!(guest.send_rpc(2).await, 12);
            if self.mode == 9 {
                assert_eq!(
                    guest
                        .inject(reverie::syscalls::Getpid::default())
                        .await
                        .unwrap_err(),
                    Errno::EOPNOTSUPP
                );
                return Ok(()); // The irreversible witness must still refuse.
            }
            if self.mode == 11 {
                return Err(Errno::EIO);
            }
            let address = AddrMut::from_raw(self.memory).unwrap();
            assert_eq!(guest.memory().write(address, &[0x5a; 16])?, 16);
            *guest.thread_state_mut() = 2;
            Ok(())
        }

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            _syscall: Syscall,
        ) -> Result<i64, Error> {
            self.calls.lock().unwrap().push("syscall");
            assert_eq!(*guest.thread_state(), 2);
            assert_eq!(guest.send_rpc(3).await, 13);
            *guest.thread_state_mut() = 3;
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
        fn signal_action_supported(&self, _number: i64, _args: [u64; 6]) -> bool {
            false
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
    fn eager_callbacks_write_memory_before_dispatch_and_do_not_repeat() {
        isolated(
            || {
                let (_native, owner) = lifecycle_test_owner();
                let calls = Arc::new(Mutex::new(Vec::new()));
                let mut memory = Box::new([0_u8; 16]);
                let (host, worker) = host(0, memory.as_mut_ptr() as usize, calls.clone());
                unsafe { host.bind_initial_image_control(&owner) }.unwrap();
                mark_lifecycle_test_frontend_installed(&owner);
                host.initialize_initial_image_lifecycle(&owner).unwrap();
                // This consumer runs before any dispatch, not in its callback.
                assert_eq!(*memory, [0x5a; 16]);
                assert_eq!(*calls.lock().unwrap(), ["init", "start", "post-exec"]);
                assert_eq!(
                    host.states.lock().get(&raw_pid(libc::SYS_gettid).as_raw()),
                    Some(&2)
                );
                // Component dispatch of a controlled Getpid event. This is not
                // a claimed real SIGSYS/native-entry execution.
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
                assert_eq!(
                    *calls.lock().unwrap(),
                    ["init", "start", "post-exec", "syscall"]
                );
                assert_eq!(
                    host.states.lock().get(&raw_pid(libc::SYS_gettid).as_raw()),
                    Some(&3)
                );
                drop(host);
                assert_eq!(worker.join().unwrap(), [1, 2, 3]);
            },
            0,
        );
    }

    #[test]
    fn ignored_initial_lifecycle_errors_cannot_publish_thread_state() {
        for mode in [1, 2, 3, 4, 5, 9] {
            isolated(
                move || {
                    let (_native, owner) = lifecycle_test_owner();
                    let calls = Arc::new(Mutex::new(Vec::new()));
                    let mut memory = Box::new([0_u8; 16]);
                    let (host, worker) = host(mode, memory.as_mut_ptr() as usize, calls.clone());
                    unsafe { host.bind_initial_image_control(&owner) }.unwrap();
                    mark_lifecycle_test_frontend_installed(&owner);
                    let error = host.initialize_initial_image_lifecycle(&owner).unwrap_err();
                    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
                    let operation = match mode {
                        1 | 9 => "syscall injection",
                        2 => "register mutation",
                        3 | 4 => "timer programming",
                        5 => "RCB clock",
                        _ => unreachable!(),
                    };
                    assert!(error.to_string().contains(operation));
                    assert!(host.states.lock().is_empty());
                    assert_eq!(*memory, [0; 16]);
                    assert!(
                        owner
                            .finish()
                            .unwrap_err()
                            .to_string()
                            .contains("lifecycle did not complete")
                    );
                    let error = host.initialize_initial_image_lifecycle(&owner).unwrap_err();
                    assert!(error.to_string().contains("attempted twice"));
                    let expected = if mode == 9 { vec![1, 2] } else { vec![1] };
                    drop(host);
                    assert_eq!(worker.join().unwrap(), expected);
                },
                0,
            );
        }
    }

    #[test]
    fn initial_lifecycle_nonresult_requests_terminate_without_fabricated_values() {
        for mode in [6, 7, 8, 12, 13] {
            isolated(
                move || {
                    let (_native, owner) = lifecycle_test_owner();
                    let (host, _worker) = host(mode, 0, Arc::new(Mutex::new(Vec::new())));
                    unsafe { host.bind_initial_image_control(&owner) }.unwrap();
                    mark_lifecycle_test_frontend_installed(&owner);
                    let _ = host.initialize_initial_image_lifecycle(&owner);
                    panic!("non-Result request returned instead of terminating")
                },
                127,
            );
        }
    }

    #[test]
    fn failed_initial_hooks_never_publish_partial_thread_state() {
        for mode in [10, 11] {
            isolated(
                move || {
                    let (_native, owner) = lifecycle_test_owner();
                    let calls = Arc::new(Mutex::new(Vec::new()));
                    let mut memory = Box::new([0_u8; 16]);
                    let (host, worker) = host(mode, memory.as_mut_ptr() as usize, calls.clone());
                    unsafe { host.bind_initial_image_control(&owner) }.unwrap();
                    mark_lifecycle_test_frontend_installed(&owner);
                    let error = host.initialize_initial_image_lifecycle(&owner).unwrap_err();
                    assert_eq!(error.raw_os_error(), Some(libc::EIO));
                    assert!(host.states.lock().is_empty());
                    assert_eq!(*memory, [0; 16]);
                    assert!(
                        owner
                            .finish()
                            .unwrap_err()
                            .to_string()
                            .contains("lifecycle did not complete")
                    );
                    let expected = if mode == 10 { vec![1] } else { vec![1, 2] };
                    drop(host);
                    assert_eq!(worker.join().unwrap(), expected);
                },
                0,
            );
        }
    }

    #[test]
    fn initial_lifecycle_refuses_duplicate_existing_state_and_other_host() {
        isolated(
            || {
                let (_native, owner) = lifecycle_test_owner();
                let calls = Arc::new(Mutex::new(Vec::new()));
                let mut memory = Box::new([0_u8; 16]);
                let (host, worker) = host(0, memory.as_mut_ptr() as usize, calls.clone());
                unsafe { host.bind_initial_image_control(&owner) }.unwrap();
                mark_lifecycle_test_frontend_installed(&owner);
                host.states
                    .lock()
                    .insert(raw_pid(libc::SYS_gettid).as_raw(), 41);
                let error = host.initialize_initial_image_lifecycle(&owner).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
                assert_eq!(
                    host.states.lock().get(&raw_pid(libc::SYS_gettid).as_raw()),
                    Some(&41)
                );
                assert!(calls.lock().unwrap().is_empty());
                drop(host);
                assert!(worker.join().unwrap().is_empty());
            },
            0,
        );
        isolated(
            || {
                let (_native, owner) = lifecycle_test_owner();
                let calls = Arc::new(Mutex::new(Vec::new()));
                let (first, worker1) = host(0, 0, calls.clone());
                let (other, worker2) = host(0, 0, calls.clone());
                unsafe { first.bind_initial_image_control(&owner) }.unwrap();
                mark_lifecycle_test_frontend_installed(&owner);
                let error = other
                    .initialize_initial_image_lifecycle(&owner)
                    .unwrap_err();
                assert!(error.to_string().contains("installed host/frontend"));
                assert!(calls.lock().unwrap().is_empty());
                assert!(first.initialize_initial_image_lifecycle(&owner).is_err());
                drop(first);
                drop(other);
                assert!(worker1.join().unwrap().is_empty());
                assert!(worker2.join().unwrap().is_empty());
            },
            0,
        );
    }
}
