/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Actual common Tool-entry controls with native-mechanism test callbacks.
//! These exercise real lifecycle handlers and real RpcServer exchanges, not
//! a scheduler, native C loader, private image, or physical guest.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde::Deserialize;
use serde::Serialize;

use super::super::native_test_support as fixture;
use super::super::native_test_support::Callback;
use super::super::native_test_support::Remote;
use super::super::native_test_support::Reply;
use super::super::native_test_support::Request;
use super::super::native_test_support::Runtime;
use super::super::native_test_support::Server;
use super::*;
use crate::tool_host::NativeCallbackOutcome;

#[derive(Clone, Default, Serialize, Deserialize)]
struct State {
    seed: u64,
    starts: u64,
    posts: u64,
    syscalls: u64,
    order: Vec<u64>,
    initialized_for: i32,
    parent_seed: Option<u64>,
    #[serde(skip)]
    copied_parent_drop: Option<native_copied_tests::ParentDrop>,
    #[serde(skip)]
    copied_child_order: Option<std::sync::Arc<native_copied_tests::DropOrder>>,
}
impl State {
    fn seeded() -> Self {
        Self {
            seed: 71,
            ..Self::default()
        }
    }
}

#[derive(Default)]
struct Probe {
    saved_stack: AtomicUsize,
    syscall_entries: AtomicUsize,
    initializer_entries: AtomicUsize,
    block_initializer: bool,
}

#[reverie::tool]
impl Tool for Probe {
    type GlobalState = Remote;
    type ThreadState = State;

    fn init_thread_state(
        &self,
        child: reverie::Tid,
        parent: Option<(reverie::Tid, &State)>,
    ) -> State {
        assert_eq!(
            child.as_raw(),
            fixture::actual_pid(libc::SYS_gettid).as_raw()
        );
        self.initializer_entries.fetch_add(1, Ordering::SeqCst);
        let request = if parent.is_some() {
            311
        } else if self.block_initializer {
            100
        } else {
            310
        };
        assert_eq!(
            super::super::installed_tool::blocking_global_rpc::<Remote>(Request(request)).unwrap(),
            Reply(child.as_raw(), request),
        );
        State {
            seed: 71,
            initialized_for: child.as_raw(),
            parent_seed: parent.map(|(_, state)| state.seed),
            ..State::default()
        }
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        if let Some(order) = &guest.thread_state().copied_child_order {
            assert_eq!(order.parent_drops.load(Ordering::SeqCst), 0);
        }
        assert_eq!(
            guest.thread_state().seed,
            71,
            "original initialized state was replaced"
        );
        assert_eq!(guest.thread_state().starts, 0);
        assert_eq!(guest.thread_state().posts, 0);
        assert_eq!(guest.config(), &71);
        assert_eq!(guest.read_clock()?, 17);
        assert_eq!(guest.regs().await.rip, 0x1234);
        assert!(guest.has_cpuid_interception());
        guest.thread_state_mut().starts += 1;
        guest.thread_state_mut().order.push(1);
        if let Some(order) = &guest.thread_state().copied_child_order {
            order.child_start_completed.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        assert_eq!(guest.thread_state().starts, 1);
        assert_eq!(guest.thread_state().posts, 0);
        guest.thread_state_mut().posts += 1;
        guest.thread_state_mut().order.push(2);
        Ok(())
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(guest.thread_state().starts, 1);
        self.syscall_entries.fetch_add(1, Ordering::SeqCst);
        guest.thread_state_mut().syscalls += 1;
        guest.thread_state_mut().order.push(3);
        let (_, args) = call.into_parts();
        match args.arg0 as u64 {
            7 => {
                let mut stack = guest.stack().await;
                let saved = stack.push(0x7197_u64).as_raw();
                self.saved_stack.store(saved, Ordering::SeqCst);
                drop(stack.commit()?);
                guest.tail_inject(call).await
            }
            8 => Err(Errno::ERESTARTSYS.into()),
            9 => Err(io::Error::other("native fixture fatal Tool I/O failure").into()),
            value @ (100 | 101 | 500) => {
                let Reply(from, answer) = guest.send_rpc(Request(value)).await;
                assert_eq!(from, guest.tid().as_raw());
                assert_eq!(answer, value);
                Ok(answer as i64)
            }
            200 => {
                // Exercise the actual native poll/wake entry, independently
                // from the synchronous socket-progress control below.
                let (sender, receiver) = std::sync::mpsc::channel();
                let mut worker = None;
                let (value, worker) = std::future::poll_fn(move |context| {
                    if worker.is_none() {
                        let sender = sender.clone();
                        let waker = context.waker().clone();
                        worker = Some(std::thread::spawn(move || {
                            sender.send(200).unwrap();
                            waker.wake();
                        }));
                        return std::task::Poll::Pending;
                    }
                    match receiver.try_recv() {
                        Ok(value) => std::task::Poll::Ready((value, worker.take().unwrap())),
                        Err(std::sync::mpsc::TryRecvError::Empty) => std::task::Poll::Pending,
                        Err(error) => panic!("wake worker failed: {error}"),
                    }
                })
                .await;
                worker.join().unwrap();
                Ok(value)
            }
            _ => Ok(guest.inject(call).await?),
        }
    }
    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        request: Rdtsc,
    ) -> Result<reverie::RdtscResult, Errno> {
        assert_eq!(guest.thread_state().posts, 1);
        guest.thread_state_mut().order.push(4);
        Ok(reverie::RdtscResult {
            tsc: 0x7197,
            aux: (request == Rdtsc::Tscp).then_some(83),
        })
    }
    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: reverie::Signal,
    ) -> Result<Option<reverie::Signal>, Errno> {
        guest.thread_state_mut().order.push(5);
        let mut info = guest.signal_info().expect("authentic owned native siginfo");
        assert_eq!(
            i32::from_ne_bytes(info[..4].try_into().unwrap()),
            signal as i32
        );
        info[16..20].copy_from_slice(&83_i32.to_ne_bytes());
        guest.set_signal_info(info)?;
        Ok(Some(signal))
    }
    async fn on_exit_thread<G: GlobalRPC<Remote>>(
        &self,
        tid: Pid,
        global: &G,
        state: State,
        status: reverie::ExitStatus,
    ) -> Result<(), Error> {
        assert_eq!(status, reverie::ExitStatus::Exited(0));
        assert_eq!(
            (state.seed, state.starts, state.posts, state.syscalls),
            (71, 1, 1, 1)
        );
        assert_eq!(state.order, [1, 2, 3]);
        assert_eq!(global.config(), &71);
        assert_eq!(
            global.send_rpc(Request(301)).await,
            Reply(tid.as_raw(), 301)
        );
        // Real Detcore synchronous helpers use this same installed global
        // entry. Check selected routing during the consuming callback too.
        assert_eq!(
            super::super::installed_tool::blocking_global_rpc::<Remote>(Request(303)).unwrap(),
            Reply(tid.as_raw(), 303)
        );
        Ok(())
    }
    async fn on_exit_process<G: GlobalRPC<Remote>>(
        self,
        pid: Pid,
        global: &G,
        status: reverie::ExitStatus,
    ) -> Result<(), Error> {
        assert_eq!(status, reverie::ExitStatus::Exited(0));
        assert_eq!(
            global.send_rpc(Request(302)).await,
            Reply(pid.as_raw(), 302)
        );
        Ok(())
    }
}

fn make_host() -> (ToolHost<Probe, Runtime>, std::os::unix::net::UnixStream) {
    make_host_with_probe(Probe::default())
}

fn make_host_with_probe(
    probe: Probe,
) -> (ToolHost<Probe, Runtime>, std::os::unix::net::UnixStream) {
    let (rpc, peer) = fixture::configured_rpc();
    let subscriptions = [Sysno::getpid].into_iter().collect();
    let host = unsafe {
        ToolHost::new_native(
            probe,
            rpc,
            fixture::actual_pid(libc::SYS_getpid),
            subscriptions,
            true,
            Runtime,
        )
    };
    (host, peer)
}
fn event(operation: u64) -> SyscallEvent {
    SyscallEvent {
        number: libc::SYS_getpid,
        args: [operation, 0, 0, 0, 0, 0],
        instruction_pointer: 0x1234,
        result: 0,
        context: 0,
        dispatch: SyscallDispatch::InstalledHook,
        guest_pkru: None,
    }
}
fn value(result: NativeCallResult<'_, Probe, i64>) -> i64 {
    match result {
        NativeCallResult::Return(value) => value,
        NativeCallResult::Deferred(_) => panic!("expected completed native handler"),
    }
}

#[test]
fn native_actual_entries_preserve_initialized_lifecycle_and_event_order() {
    let server = Server::new();
    let (host, _peer) = make_host();
    let rpc = NativeRpc::new(server.path.clone(), host.rpc.shared_config()).unwrap();
    let callback = Callback::new(1);
    let id = callback.identity();
    let services = callback.services(None);
    let handle = unsafe {
        host.register_native_image_thread(id, State::seeded())
            .unwrap()
    };
    for _ in 0..2 {
        let lease = unsafe { host.enter_native_callback(handle, id).unwrap() };
        assert_eq!(
            value(unsafe {
                host.dispatch_native_syscall(lease, &services, &rpc, &mut event(1))
                    .unwrap()
            }),
            i64::from(id.physical_pid().as_raw())
        );
    }
    let lease = unsafe { host.enter_native_callback(handle, id).unwrap() };
    match unsafe {
        host.dispatch_native_instruction(
            lease,
            &services,
            &rpc,
            &mut event(0),
            NativeInstruction::Rdtsc(Rdtsc::Tscp),
        )
        .unwrap()
    } {
        NativeCallResult::Return(NativeInstructionResult::Rdtsc(answer)) => {
            assert_eq!(answer.tsc, 0x7197);
            assert_eq!(answer.aux, Some(83));
        }
        _ => panic!("wrong instruction completion"),
    }
    let mut info = [0_u8; reverie::SIGNAL_INFO_SIZE];
    info[..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes());
    let signal_services = callback.services(Some(info));
    let lease = unsafe { host.enter_native_callback(handle, id).unwrap() };
    match unsafe {
        host.dispatch_native_signal(lease, &signal_services, &rpc, &mut event(0), libc::SIGUSR1)
            .unwrap()
    } {
        NativeCallResult::Return(NativeSignalResult::Deliver { signal, info }) => {
            assert_eq!(signal, reverie::Signal::SIGUSR1);
            assert_eq!(&info[16..20], &83_i32.to_ne_bytes());
        }
        _ => panic!("wrong signal completion"),
    }
    let state = unsafe { host.retire_native_thread(handle, id).unwrap() };
    assert_eq!(
        (state.seed, state.starts, state.posts, state.syscalls),
        (71, 1, 1, 2)
    );
    assert_eq!(state.order, [1, 2, 3, 3, 4, 5]);
    assert_eq!(callback.admitted.load(Ordering::SeqCst), 1);
    assert_eq!(callback.count(libc::SYS_getpid), 2);
    assert!(
        server.global.seen.lock().unwrap().is_empty(),
        "no fabricated lifecycle RPC"
    );
    // The native C filter selects interception independently of the local
    // subscription set. A valid event must still enter Tool when absent from
    // that set; the old native driver always called its Tool handler.
    assert!(!host.subscriptions.contains(&Sysno::getuid));
    let handle = unsafe {
        host.register_native_image_thread(id, State::seeded())
            .unwrap()
    };
    let lease = unsafe { host.enter_native_callback(handle, id).unwrap() };
    let mut unsubscribed = event(1);
    unsubscribed.number = libc::SYS_getuid;
    assert_eq!(
        value(unsafe {
            host.dispatch_native_syscall(lease, &services, &rpc, &mut unsubscribed)
                .unwrap()
        }),
        i64::from(unsafe { libc::getuid() })
    );
    let state = unsafe { host.retire_native_thread(handle, id).unwrap() };
    assert_eq!((state.starts, state.posts, state.syscalls), (1, 1, 1));
    assert_eq!(state.order, [1, 2, 3]);
    assert_eq!(callback.count(libc::SYS_getuid), 1);
    fixture::close_test_primary(&rpc, &callback);
}

#[test]
fn native_real_tool_rpc_allows_sibling_progress_while_primary_waits() {
    let server = Server::new();
    let (host, _peer) = make_host();
    let rpc = NativeRpc::new(server.path.clone(), host.rpc.shared_config()).unwrap();
    let (waiting_tx, waiting_rx) = std::sync::mpsc::channel();
    *server.global.first_pending.lock().unwrap() = Some(waiting_tx);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            let callback = Callback::new(1);
            let id = callback.identity();
            let services = callback.services(None);
            let handle = unsafe {
                host.register_native_image_thread(id, State::seeded())
                    .unwrap()
            };
            let lease = unsafe { host.enter_native_callback(handle, id).unwrap() };
            assert_eq!(
                value(unsafe {
                    host.dispatch_native_syscall(lease, &services, &rpc, &mut event(100))
                        .unwrap()
                }),
                100
            );
            assert_eq!(
                unsafe { host.retire_native_thread(handle, id).unwrap() }.order,
                [1, 2, 3]
            );
        });
        // This notification comes from real GlobalTool::receive_rpc after the
        // first Tool has sent its request and waits on the actual primary.
        waiting_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(host.tool.try_lock().is_some());
        assert!(host.states.try_lock().is_some());
        let callback = Callback::new(1);
        let id = callback.identity();
        let services = callback.services(None);
        let handle = unsafe {
            host.register_native_image_thread(id, State::seeded())
                .unwrap()
        };
        let lease = unsafe { host.enter_native_callback(handle, id).unwrap() };
        assert_eq!(
            value(unsafe {
                host.dispatch_native_syscall(lease, &services, &rpc, &mut event(101))
                    .unwrap()
            }),
            101
        );
        assert_eq!(
            unsafe { host.retire_native_thread(handle, id).unwrap() }.order,
            [1, 2, 3]
        );
        assert_eq!(
            callback.count(libc::SYS_socket),
            1,
            "contention needs an independent connection"
        );
        fixture::assert_independent_connection_retired(
            &callback,
            rpc.descriptor(id.physical_pid()).expect("occupied primary"),
        );
        first.join().unwrap();
        let values = server
            .global
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|(_, n)| *n)
            .collect::<Vec<_>>();
        assert_eq!(values, [100, 101]);
        fixture::close_test_primary(&rpc, &callback);
    });
}

#[test]
fn native_actual_tool_decode_reentry_and_cross_thread_wake_preserve_progress() {
    let server = Server::new();
    let (host, _peer) = make_host();
    let rpc = NativeRpc::new(server.path.clone(), host.rpc.shared_config()).unwrap();
    let callback = Callback::new(1);
    let id = callback.identity();
    let services = callback.services(None);
    let handle = unsafe {
        host.register_native_image_thread(id, State::seeded())
            .unwrap()
    };
    for operation in [500, 200] {
        let lease = unsafe { host.enter_native_callback(handle, id).unwrap() };
        assert_eq!(
            value(unsafe {
                host.dispatch_native_syscall(lease, &services, &rpc, &mut event(operation))
                    .unwrap()
            }),
            operation as i64
        );
    }
    let requests = server
        .global
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|(_, n)| *n)
        .collect::<Vec<_>>();
    assert_eq!(requests, [500, 501]);
    assert_eq!(
        callback.count(libc::SYS_socket),
        1,
        "response decode reentered after primary release"
    );
    let state = unsafe { host.retire_native_thread(handle, id).unwrap() };
    assert_eq!((state.starts, state.posts, state.syscalls), (1, 1, 2));
    fixture::close_test_primary(&rpc, &callback);
}

#[test]
fn native_deferred_entry_retains_original_scratch_until_real_completion() {
    let server = Server::new();
    let (host, _peer) = make_host();
    let rpc = NativeRpc::new(server.path.clone(), host.rpc.shared_config()).unwrap();
    let callback = Callback::new(1);
    let id = callback.identity();
    let services = callback.services(None);
    let handle = unsafe {
        host.register_native_image_thread(id, State::seeded())
            .unwrap()
    };
    let lease = unsafe { host.enter_native_callback(handle, id).unwrap() };
    let deferred = match unsafe {
        host.dispatch_native_syscall(lease, &services, &rpc, &mut event(7))
            .unwrap()
    } {
        NativeCallResult::Deferred(deferred) => deferred,
        NativeCallResult::Return(_) => panic!("tail operation must remain affine"),
    };
    assert_eq!(deferred.operation(), (libc::SYS_getpid, [7, 0, 0, 0, 0, 0]));
    assert_eq!(
        unsafe { host.enter_native_callback(handle, id) }
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    let saved = host
        .tool
        .lock()
        .as_deref()
        .unwrap()
        .as_ref()
        .unwrap()
        .saved_stack
        .load(Ordering::SeqCst);
    assert_ne!(saved, 0);
    assert_eq!(unsafe { (saved as *const u64).read() }, 0x7197);
    assert_eq!(
        callback.count(libc::SYS_getpid),
        0,
        "Rust must not execute a deferred call early"
    );
    // This test owns the native stand-in: apply through the actual selected
    // invoker, then consume the original completion owner after its use ends.
    let (number, args) = deferred.operation();
    let answer = unsafe {
        callback
            .invocation()
            .invoke(number, args, reverie::InjectionPurpose::Application)
    };
    assert_eq!(answer, i64::from(id.physical_pid().as_raw()));
    unsafe { deferred.complete(callback.invocation()).unwrap() };
    let state = unsafe { host.retire_native_thread(handle, id).unwrap() };
    assert_eq!((state.starts, state.posts, state.syscalls), (1, 1, 1));
    fixture::close_test_primary(&rpc, &callback);
}

#[test]
fn native_post_event_reuses_original_state_scratch_and_rpc_before_completion() {
    let server = Server::new();
    let (host, _peer) = make_host();
    let rpc = NativeRpc::new(server.path.clone(), host.rpc.shared_config()).unwrap();
    let callback = Callback::new(1);
    let id = callback.identity();
    let services = callback.services(None);
    let handle = unsafe {
        host.register_native_image_thread(id, State::seeded())
            .unwrap()
    };
    let lease = unsafe { host.enter_native_callback(handle, id).unwrap() };
    let mut deferred = match unsafe {
        host.dispatch_native_syscall(lease, &services, &rpc, &mut event(7))
            .unwrap()
    } {
        NativeCallResult::Deferred(deferred) => deferred,
        NativeCallResult::Return(_) => panic!("original operation must remain deferred"),
    };
    let saved = host
        .tool
        .lock()
        .as_deref()
        .unwrap()
        .as_ref()
        .unwrap()
        .saved_stack
        .load(Ordering::SeqCst);
    assert_ne!(saved, 0);
    assert_eq!(unsafe { (saved as *const u64).read() }, 0x7197);
    assert_eq!(callback.count(libc::SYS_getpid), 0);
    let (number, args) = deferred.operation();
    let kernel_answer = unsafe {
        callback
            .invocation()
            .invoke(number, args, reverie::InjectionPurpose::Application)
    };
    assert_eq!(kernel_answer, i64::from(id.physical_pid().as_raw()));
    let step_result = unsafe {
        host.with_native_post_step(
            &mut deferred,
            &services,
            &rpc,
            &mut event(0),
            |_tool, guest, tail| {
                assert_eq!(guest.thread_state().order, [1, 2, 3]);
                assert_eq!(guest.thread_state().syscalls, 1);
                assert_eq!((saved as *const u64).read(), 0x7197);
                crate::tool_host::drive_native_callback(
                    async {
                        let Reply(from, answer) = guest.send_rpc(Request(300)).await;
                        assert_eq!(from, id.tid().as_raw());
                        assert_eq!(answer, 300);
                        // The original arena survives actual post-event RPC,
                        // not merely a copied marker or a manual map entry.
                        assert_eq!((saved as *const u64).read(), 0x7197);
                        guest.thread_state_mut().order.push(4);
                        Ok(300_i64)
                    },
                    tail,
                )
            },
        )
        .unwrap()
    };
    assert_eq!(step_result, 300);
    // The real Tool/RPC post step returned, but the C owner still has work.
    // It retains the SAME original scratch and unpublished thread state.
    assert_eq!(unsafe { (saved as *const u64).read() }, 0x7197);
    assert!(matches!(
        unsafe { host.enter_native_callback(handle, id) },
        Err(ref error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    let result = unsafe {
        host.with_native_post_event(
            deferred,
            &services,
            &rpc,
            &mut event(0),
            |_tool, guest, _tail| {
                assert_eq!(guest.thread_state().order, [1, 2, 3, 4]);
                assert_eq!((saved as *const u64).read(), 0x7197);
                crate::tool_host::NativeCallbackOutcome::Ready(Ok(step_result))
            },
        )
        .unwrap()
    };
    assert_eq!(value(result), 300);
    let state = unsafe { host.retire_native_thread(handle, id).unwrap() };
    assert_eq!((state.starts, state.posts, state.syscalls), (1, 1, 1));
    assert_eq!(state.order, [1, 2, 3, 4]);
    assert_eq!(callback.count(libc::SYS_getpid), 1);
    assert_eq!(
        *server.global.seen.lock().unwrap(),
        [(id.tid().as_raw(), 300)]
    );
    fixture::close_test_primary(&rpc, &callback);
}

#[test]
fn native_single_handler_error_is_not_restarted_or_published_as_success() {
    let server = Server::new();
    let (host, _peer) = make_host();
    let rpc = NativeRpc::new(server.path.clone(), host.rpc.shared_config()).unwrap();
    let callback = Callback::new(1);
    let id = callback.identity();
    let services = callback.services(None);
    let handle = unsafe {
        host.register_native_image_thread(id, State::seeded())
            .unwrap()
    };
    let lease = unsafe { host.enter_native_callback(handle, id).unwrap() };
    let error_result = value(unsafe {
        host.dispatch_native_syscall(lease, &services, &rpc, &mut event(8))
            .unwrap()
    });
    assert_eq!(error_result, -i64::from(Errno::ERESTARTSYS.into_raw()));
    assert_eq!(
        host.tool
            .lock()
            .as_deref()
            .unwrap()
            .as_ref()
            .unwrap()
            .syscall_entries
            .load(Ordering::SeqCst),
        1,
        "native single-handler errors must not enter the local restart loop"
    );
    assert_eq!(callback.admitted.load(Ordering::SeqCst), 1);
    assert_eq!(callback.count(libc::SYS_getpid), 0);
    // A Linux errno is a completed guest operation, not an abandoned native
    // callback. Reenter the actual same host/state; lifecycle callbacks must
    // not run again and the previous ERESTARTSYS must not be retried.
    let lease = unsafe { host.enter_native_callback(handle, id).unwrap() };
    let fatal = unsafe { host.dispatch_native_syscall(lease, &services, &rpc, &mut event(9)) }
        .err()
        .unwrap();
    assert!(matches!(fatal, Error::Io(_)));
    assert_eq!(
        host.tool
            .lock()
            .as_deref()
            .unwrap()
            .as_ref()
            .unwrap()
            .syscall_entries
            .load(Ordering::SeqCst),
        2,
        "one additional explicit operation must enter exactly one handler"
    );
    // Preserve the fatal failure refusal: a real non-guest I/O error leaves
    // the callback poisoned and must not be converted into guest success/EIO.
    assert_eq!(
        unsafe { host.enter_native_callback(handle, id) }
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::EIO)
    );
    assert_eq!(callback.count(libc::SYS_getpid), 0);
    fixture::close_test_primary(&rpc, &callback);
}

#[test]
fn native_wrong_current_thread_refuses_before_tool_or_socket_entry() {
    let server = Server::new();
    let (host, _peer) = make_host();
    let rpc = NativeRpc::new(server.path.clone(), host.rpc.shared_config()).unwrap();
    let callback = Callback::new(1);
    let id = callback.identity();
    let services = callback.services(None);
    let handle = unsafe {
        host.register_native_image_thread(id, State::seeded())
            .unwrap()
    };
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                // The negative fixture deliberately supplies the original facts
                // on another actual thread; its live NativeCurrent must reject.
                let lease = unsafe { host.enter_native_callback(handle, id).unwrap() };
                let error =
                    unsafe { host.dispatch_native_syscall(lease, &services, &rpc, &mut event(1)) }
                        .err()
                        .unwrap();
                assert!(
                    matches!(error, Error::Io(ref e) if e.raw_os_error() == Some(libc::ESTALE))
                );
            })
            .join()
            .unwrap();
    });
    assert_eq!(callback.admitted.load(Ordering::SeqCst), 0);
    assert!(callback.calls.lock().unwrap().is_empty());
    assert!(server.global.seen.lock().unwrap().is_empty());
    assert_eq!(
        unsafe { host.enter_native_callback(handle, id) }
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::EIO)
    );
}

#[test]
fn native_consuming_thread_and_process_exit_use_real_background_rpc_once() {
    let server = Server::new();
    let (host, _peer) = make_host();
    let rpc = NativeRpc::new(server.path.clone(), host.rpc.shared_config()).unwrap();
    let callback = Callback::new(1);
    let identity = callback.identity();
    let services = callback.services(None);
    let handle = unsafe {
        host.register_native_image_thread(identity, State::seeded())
            .unwrap()
    };
    let lease = unsafe { host.enter_native_callback(handle, identity).unwrap() };
    value(unsafe {
        host.dispatch_native_syscall(lease, &services, &rpc, &mut event(1))
            .unwrap()
    });
    // This ordinary test thread owns real standard Rust TLS/socket service.
    // It does not emulate or qualify entry into a native private loader.
    let background = unsafe {
        super::super::native_rpc::NativeBackgroundRpc::from_admitted(
            server.path.clone(),
            host.rpc.shared_config(),
        )
        .unwrap()
    };
    let before = callback.calls.lock().unwrap().len();
    unsafe {
        host.dispatch_native_thread_exit(
            handle,
            identity,
            NativeExitRpc::Background(background.for_thread(identity.tid()).unwrap()),
            reverie::ExitStatus::Exited(0),
        )
        .unwrap()
    };
    let error = unsafe {
        host.dispatch_native_thread_exit(
            handle,
            identity,
            NativeExitRpc::Background(background.for_thread(identity.tid()).unwrap()),
            reverie::ExitStatus::Exited(0),
        )
    }
    .err()
    .unwrap();
    assert!(matches!(error, Error::Io(ref e) if e.raw_os_error() == Some(libc::ESTALE)));
    unsafe {
        host.dispatch_native_process_exit(
            identity.pid(),
            background.for_thread(identity.pid()).unwrap(),
            reverie::ExitStatus::Exited(0),
        )
        .unwrap()
    };
    let error = unsafe {
        host.dispatch_native_process_exit(
            identity.pid(),
            background.for_thread(identity.pid()).unwrap(),
            reverie::ExitStatus::Exited(0),
        )
    }
    .err()
    .unwrap();
    assert!(matches!(error, Error::Io(ref e) if e.raw_os_error() == Some(libc::ESTALE)));
    assert_eq!(
        &*server.global.seen.lock().unwrap(),
        &[
            (identity.tid().as_raw(), 301),
            (identity.tid().as_raw(), 303),
            (identity.pid().as_raw(), 302)
        ]
    );
    assert_eq!(
        callback.calls.lock().unwrap().len(),
        before,
        "background finalizers must not use an application callback context"
    );
    fixture::close_test_primary(&rpc, &callback);
}

#[test]
fn native_application_thread_exit_retains_its_original_rpc_route() {
    let server = Server::new();
    let (host, _peer) = make_host();
    let rpc = NativeRpc::new(server.path.clone(), host.rpc.shared_config()).unwrap();
    let callback = Callback::new(1);
    let identity = callback.identity();
    let services = callback.services(None);
    let handle = unsafe {
        host.register_native_image_thread(identity, State::seeded())
            .unwrap()
    };
    let lease = unsafe { host.enter_native_callback(handle, identity).unwrap() };
    value(unsafe {
        host.dispatch_native_syscall(lease, &services, &rpc, &mut event(1))
            .unwrap()
    });
    unsafe {
        host.dispatch_native_thread_exit(
            handle,
            identity,
            NativeExitRpc::Application(rpc.application(callback.invocation())),
            reverie::ExitStatus::Exited(0),
        )
        .unwrap()
    };
    assert_eq!(
        callback.count(libc::SYS_socket),
        1,
        "exit RPC retains the prepared primary"
    );
    assert_eq!(
        &*server.global.seen.lock().unwrap(),
        &[
            (identity.tid().as_raw(), 301),
            (identity.tid().as_raw(), 303)
        ]
    );
    let background = unsafe {
        super::super::native_rpc::NativeBackgroundRpc::from_admitted(
            server.path.clone(),
            host.rpc.shared_config(),
        )
        .unwrap()
    };
    unsafe {
        host.dispatch_native_process_exit(
            identity.pid(),
            background.for_thread(identity.pid()).unwrap(),
            reverie::ExitStatus::Exited(0),
        )
        .unwrap()
    };
    fixture::close_test_primary(&rpc, &callback);
}

#[test]
fn native_wrong_background_thread_and_active_process_exit_refuse_before_consumption() {
    let server = Server::new();
    let (host, _peer) = make_host();
    let rpc = NativeRpc::new(server.path.clone(), host.rpc.shared_config()).unwrap();
    let callback = Callback::new(1);
    let identity = callback.identity();
    let handle = unsafe {
        host.register_native_image_thread(identity, State::seeded())
            .unwrap()
    };
    let background = unsafe {
        super::super::native_rpc::NativeBackgroundRpc::from_admitted(
            server.path.clone(),
            host.rpc.shared_config(),
        )
        .unwrap()
    };
    let error = unsafe {
        host.dispatch_native_process_exit(
            identity.pid(),
            background.for_thread(identity.pid()).unwrap(),
            reverie::ExitStatus::Exited(0),
        )
    }
    .err()
    .unwrap();
    assert!(matches!(error, Error::Io(ref e) if e.kind() == io::ErrorKind::WouldBlock));
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                assert_eq!(
                    background
                        .for_thread(identity.tid())
                        .err()
                        .unwrap()
                        .raw_os_error(),
                    Some(libc::ESTALE)
                );
            })
            .join()
            .unwrap();
    });
    assert!(server.global.seen.lock().unwrap().is_empty());
    let services = callback.services(None);
    let lease = unsafe { host.enter_native_callback(handle, identity).unwrap() };
    value(unsafe {
        host.dispatch_native_syscall(lease, &services, &rpc, &mut event(1))
            .unwrap()
    });
    unsafe {
        host.dispatch_native_thread_exit(
            handle,
            identity,
            NativeExitRpc::Background(background.for_thread(identity.tid()).unwrap()),
            reverie::ExitStatus::Exited(0),
        )
        .unwrap()
    };
    unsafe {
        host.dispatch_native_process_exit(
            identity.pid(),
            background.for_thread(identity.pid()).unwrap(),
            reverie::ExitStatus::Exited(0),
        )
        .unwrap()
    };
    fixture::close_test_primary(&rpc, &callback);
}

#[test]
fn native_initializer_uses_original_tool_parent_snapshot_and_rpc_once() {
    let server = Server::new();
    let (host, _peer) = make_host_with_probe(Probe {
        block_initializer: true,
        ..Probe::default()
    });
    let rpc = NativeRpc::new(server.path.clone(), host.rpc.shared_config()).unwrap();
    let (other, _other_peer) = make_host();
    let other_rpc = NativeRpc::new(server.path.clone(), other.rpc.shared_config()).unwrap();
    let callback = Callback::new(1);
    let identity = callback.identity();
    let services = callback.services(None);
    let wrong_config = NativeRpc::new(server.path.clone(), Arc::new(71)).unwrap();
    assert_eq!(
        unsafe { host.initialize_native_image_thread(&services, &wrong_config, |_| Ok(())) }
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ESTALE),
    );
    assert_eq!(
        host.tool
            .lock()
            .as_deref()
            .unwrap()
            .as_ref()
            .unwrap()
            .initializer_entries
            .load(Ordering::SeqCst),
        0
    );

    let (waiting_tx, waiting_rx) = std::sync::mpsc::channel();
    *server.global.first_pending.lock().unwrap() = Some(waiting_tx);
    std::thread::scope(|scope| {
        // Root init is inside a real blocking global RPC. A second actual
        // common Guest must still acquire its state/Tool and release that RPC.
        // Holding either process guard across Tool init would fail this path.
        let host_ref = &host;
        let rpc_ref = &rpc;
        let sibling = scope.spawn(move || {
            let host = host_ref;
            let rpc = rpc_ref;
            waiting_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let callback = Callback::new(1);
            let id = callback.identity();
            let services = callback.services(None);
            let handle = unsafe {
                host.register_native_image_thread(id, State::seeded())
                    .unwrap()
            };
            let lease = unsafe { host.enter_native_callback(handle, id).unwrap() };
            assert_eq!(
                value(unsafe {
                    host.dispatch_native_syscall(lease, &services, rpc, &mut event(101))
                        .unwrap()
                }),
                101
            );
            let state = unsafe { host.retire_native_thread(handle, id).unwrap() };
            assert_eq!(state.order, [1, 2, 3]);
        });
        let handle = unsafe {
            host.initialize_native_image_thread(&services, &rpc, |state| {
                assert_eq!(state.initialized_for, identity.tid().as_raw());
                assert_eq!(state.parent_seed, None);
                assert!(
                    host.tool.try_lock().is_some(),
                    "Tool slot held across initializer"
                );
                Ok(())
            })
            .unwrap()
        };
        sibling.join().unwrap();
        assert_eq!(
            unsafe { host.initialize_native_image_thread(&services, &rpc, |_| Ok(())) }
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists,
        );
        let lease = unsafe { host.enter_native_callback(handle, identity).unwrap() };
        assert_eq!(
            value(unsafe {
                host.dispatch_native_syscall(lease, &services, &rpc, &mut event(1))
                    .unwrap()
            }),
            i64::from(identity.physical_pid().as_raw())
        );

        let lease = unsafe { host.enter_native_callback(handle, identity).unwrap() };
        let mut deferred = match unsafe {
            host.dispatch_native_syscall(lease, &services, &rpc, &mut event(7))
                .unwrap()
        } {
            NativeCallResult::Deferred(deferred) => deferred,
            NativeCallResult::Return(_) => panic!("expected original native continuation"),
        };
        let (number, args) = deferred.operation();
        assert_eq!(
            unsafe {
                callback
                    .invocation()
                    .invoke(number, args, reverie::InjectionPurpose::Application)
            },
            i64::from(identity.physical_pid().as_raw())
        );

        type Snapshot = native_state::NativeParentSnapshot<State>;
        let (identity_tx, identity_rx) = std::sync::mpsc::channel();
        let (snapshot_tx, snapshot_rx) =
            std::sync::mpsc::channel::<(Snapshot, Snapshot, Snapshot)>();
        let host_ref = &host;
        let rpc_ref = &rpc;
        let other_ref = &other;
        let other_rpc_ref = &other_rpc;
        let child = scope.spawn(move || {
            let host = host_ref;
            let rpc = rpc_ref;
            let other = other_ref;
            let other_rpc = other_rpc_ref;
            let callback = Callback::new(1);
            let id = callback.identity();
            let services = callback.services(None);
            identity_tx.send(id).unwrap();
            let (foreign, parent, duplicate) =
                snapshot_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(parent.child_identity(), id);
            assert_eq!(parent.parent_identity(), identity);
            assert_eq!(
                unsafe {
                    other.initialize_native_thread(&services, other_rpc, foreign, |_, _| Ok(()))
                }
                .unwrap_err()
                .raw_os_error(),
                Some(libc::ESTALE)
            );
            assert_eq!(
                other
                    .tool
                    .lock()
                    .as_deref()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .initializer_entries
                    .load(Ordering::SeqCst),
                0
            );
            let handle = unsafe {
                host.initialize_native_thread(&services, rpc, parent, |state, parent| {
                    let (tid, snapshot) = parent.expect("actual parent snapshot");
                    assert_eq!(tid.as_raw(), identity.tid().as_raw());
                    assert_eq!(snapshot.seed, 79);
                    assert_eq!(snapshot.order, [1, 2, 3, 3]);
                    assert_eq!(state.initialized_for, id.tid().as_raw());
                    assert_eq!(state.parent_seed, Some(79));
                    assert!(host.tool.try_lock().is_some());
                    Ok(())
                })
                .unwrap()
            };
            assert_eq!(
                unsafe { host.initialize_native_thread(&services, rpc, duplicate, |_, _| Ok(())) }
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::AlreadyExists
            );
            let lease = unsafe { host.enter_native_callback(handle, id).unwrap() };
            assert_eq!(
                value(unsafe {
                    host.dispatch_native_syscall(lease, &services, rpc, &mut event(1))
                        .unwrap()
                }),
                i64::from(id.physical_pid().as_raw())
            );
            let state = unsafe { host.retire_native_thread(handle, id).unwrap() };
            assert_eq!((state.starts, state.posts, state.syscalls), (1, 0, 1));
            assert_eq!(state.order, [1, 3]);
            assert_eq!(state.parent_seed, Some(79));
        });
        let child_id = identity_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let stale_image = unsafe {
            native_state::NativeThreadIdentity::from_admitted(
                child_id.physical_pid(),
                child_id.physical_tid(),
                child_id.pid(),
                child_id.tid(),
                2,
            )
            .unwrap()
        };
        assert_eq!(
            unsafe {
                host.snapshot_native_parent(&mut deferred, &services, &rpc, stale_image, |_| Ok(()))
            }
            .err()
            .expect("different image generation must refuse")
            .raw_os_error(),
            Some(libc::ESTALE)
        );
        let foreign = unsafe {
            host.snapshot_native_parent(&mut deferred, &services, &rpc, child_id, |state| {
                state.seed = 79;
                Ok(())
            })
            .unwrap()
        };
        let parent = unsafe {
            host.snapshot_native_parent(&mut deferred, &services, &rpc, child_id, |_| Ok(()))
                .unwrap()
        };
        let duplicate = unsafe {
            host.snapshot_native_parent(&mut deferred, &services, &rpc, child_id, |_| Ok(()))
                .unwrap()
        };
        let post = unsafe {
            host.with_native_post_event(deferred, &services, &rpc, &mut event(0), |_, guest, _| {
                assert_eq!(guest.thread_state().seed, 79);
                assert_eq!(
                    super::super::installed_tool::blocking_global_rpc::<Remote>(Request(312))
                        .unwrap(),
                    Reply(identity.tid().as_raw(), 312)
                );
                guest.thread_state_mut().seed = 83;
                NativeCallbackOutcome::Ready(Ok(()))
            })
            .unwrap()
        };
        assert!(matches!(post, NativeCallResult::Return(())));
        let state = unsafe { host.retire_native_thread(handle, identity).unwrap() };
        assert_eq!(state.seed, 83);
        assert_eq!((state.starts, state.posts, state.syscalls), (1, 1, 2));
        assert_eq!(state.order, [1, 2, 3, 3]);
        // The genuine snapshot keeps its original parent generation even
        // after normal parent retirement; it does not use the parent's newer
        // state or manufacture a replacement state for a recycled TID.
        snapshot_tx
            .send((foreign, parent, duplicate))
            .unwrap_or_else(|_| {
                panic!("actual child stopped before receiving its parent snapshot")
            });
        child.join().unwrap();
        assert_eq!(
            host.tool
                .lock()
                .as_deref()
                .unwrap()
                .as_ref()
                .unwrap()
                .initializer_entries
                .load(Ordering::SeqCst),
            2
        );
    });
    let seen = server.global.seen.lock().unwrap();
    assert_eq!(
        seen.iter().filter(|(_, request)| *request == 100).count(),
        1
    );
    assert_eq!(
        seen.iter().filter(|(_, request)| *request == 101).count(),
        1
    );
    assert_eq!(
        seen.iter().filter(|(_, request)| *request == 311).count(),
        1
    );
    assert_eq!(
        seen.iter().filter(|(_, request)| *request == 312).count(),
        1
    );
    drop(seen);
    fixture::close_test_primary(&rpc, &callback);
}

#[test]
fn native_initializer_refuses_stale_post_context_without_reinitializing() {
    use std::sync::atomic::AtomicBool;

    use super::super::native_rpc::NativeInvocation;
    use super::super::native_services::NativeEventFacts;
    use super::super::native_services::NativeServiceTable;

    struct Current {
        callback: Callback,
        live: AtomicBool,
    }
    unsafe extern "C" fn current(context: usize) -> i32 {
        let owner = unsafe { &*(context as *const Current) };
        i32::from(
            owner.live.load(Ordering::SeqCst)
                && owner.callback.invocation().ensure_current().is_ok(),
        )
    }
    unsafe extern "C" fn invoke(
        context: usize,
        number: i64,
        args: *const u64,
        purpose: u32,
    ) -> i64 {
        let owner = unsafe { &*(context as *const Current) };
        let purpose = if purpose == reverie::InjectionPurpose::Application as u32 {
            reverie::InjectionPurpose::Application
        } else {
            assert_eq!(
                purpose,
                reverie::InjectionPurpose::Pselect6WrapperValidation as u32
            );
            reverie::InjectionPurpose::Pselect6WrapperValidation
        };
        unsafe {
            owner
                .callback
                .invocation()
                .invoke(number, args.cast::<[u64; 6]>().read(), purpose)
        }
    }
    unsafe extern "C" fn read(context: usize, regs: *mut libc::user_regs_struct) -> i32 {
        let owner = unsafe { &*(context as *const Current) };
        unsafe { regs.write(*owner.callback.regs.lock().unwrap()) };
        1
    }
    unsafe extern "C" fn write(context: usize, regs: *const libc::user_regs_struct) -> i32 {
        let owner = unsafe { &*(context as *const Current) };
        *owner.callback.regs.lock().unwrap() = unsafe { regs.read() };
        1
    }
    let table = NativeServiceTable {
        read_registers: read,
        write_registers: write,
        compare_exchange_u32: None,
        controller_capture: None,
        private_memory: None,
        mapping_capture: None,
        read_memory: None,
    };
    let server = Server::new();
    let (host, _peer) = make_host();
    let rpc = NativeRpc::new(server.path.clone(), host.rpc.shared_config()).unwrap();
    let current_owner = Current {
        callback: Callback::new(7),
        live: AtomicBool::new(true),
    };
    let identity = current_owner.callback.identity();
    let invocation = unsafe {
        NativeInvocation::from_admitted(
            &current_owner as *const Current as usize,
            invoke,
            current,
            identity,
        )
    };
    let services = unsafe {
        NativeServices::from_admitted(
            invocation,
            &table,
            NativeEventFacts {
                parent: None,
                branches: 17,
                cpuid_interception: true,
                pidfd_self_spelling: reverie::PidfdSelfSpelling::Unknown,
                auxv: &[(libc::AT_NULL, 0)],
                initial_stack: None,
                signal_info: None,
            },
        )
        .unwrap()
    };
    let error = unsafe {
        host.initialize_native_image_thread(&services, &rpc, |state| {
            assert_eq!(state.initialized_for, identity.tid().as_raw());
            current_owner.live.store(false, Ordering::SeqCst);
            Ok(())
        })
    }
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ESTALE));
    assert_eq!(
        host.tool
            .lock()
            .as_deref()
            .unwrap()
            .as_ref()
            .unwrap()
            .initializer_entries
            .load(Ordering::SeqCst),
        1
    );
    current_owner.live.store(true, Ordering::SeqCst);
    assert_eq!(
        unsafe { host.initialize_native_image_thread(&services, &rpc, |_| Ok(())) }
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        unsafe { host.register_native_image_thread(identity, State::seeded()) }
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        host.tool
            .lock()
            .as_deref()
            .unwrap()
            .as_ref()
            .unwrap()
            .initializer_entries
            .load(Ordering::SeqCst),
        1
    );
    fixture::close_test_primary(&rpc, &current_owner.callback);
}

#[test]
fn native_local_tool_entry_keeps_physical_guest_pid_and_virtual_rpc_identity() {
    let config = Arc::new(71);
    let global = Arc::new(Remote::default());
    let rpc = NativeRpc::local(Arc::clone(&global), Arc::clone(&config));
    let cached = CoordinatorRpc::from_native_local_configuration(config);
    assert_eq!(cached.raw_fd(), -1);
    let callback = Callback::with_tool_identity(1, Pid::from_raw(3), Pid::from_raw(71));
    let identity = callback.identity();
    let host = unsafe {
        ToolHost::new_native(
            Probe::default(),
            cached,
            Pid::from_raw(3),
            [Sysno::getpid].into_iter().collect(),
            true,
            Runtime,
        )
    };
    let handle = unsafe {
        host.register_native_image_thread(identity, State::seeded())
            .unwrap()
    };
    let services = callback.services(None);
    let lease = unsafe { host.enter_native_callback(handle, identity).unwrap() };
    let mut first = event(0);
    assert_eq!(
        value(unsafe {
            host.with_native_guest(lease, &services, &rpc, &mut first, |_tool, guest, _tail| {
                assert_eq!(guest.pid(), identity.physical_pid());
                assert_eq!(guest.tid(), identity.tid());
                assert_ne!(guest.pid(), identity.pid());
                assert_eq!(guest.thread_state().order, [1, 2]);
                NativeCallbackOutcome::Ready(Ok(37))
            })
            .unwrap()
        }),
        37
    );
    let lease = unsafe { host.enter_native_callback(handle, identity).unwrap() };
    assert_eq!(
        value(unsafe {
            host.dispatch_native_syscall(lease, &services, &rpc, &mut event(101))
                .unwrap()
        }),
        101
    );
    assert_eq!(
        *global.seen.lock().unwrap(),
        [(identity.tid().as_raw(), 101)]
    );
    assert!(callback.calls.lock().unwrap().is_empty());
    assert_eq!(rpc.descriptor(identity.physical_pid()), None);
}

#[path = "native_copied_tests.rs"]
mod native_copied_tests;

#[derive(Default)]
struct ExitOutcomeProbe {
    exits: Arc<AtomicUsize>,
}

#[reverie::tool]
impl Tool for ExitOutcomeProbe {
    type GlobalState = Remote;
    type ThreadState = u64;

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        assert_eq!(*guest.thread_state(), 71);
        *guest.thread_state_mut() = 72;
        Ok(())
    }

    async fn on_exit_thread<G: GlobalRPC<Remote>>(
        &self,
        tid: Pid,
        global: &G,
        state: u64,
        status: reverie::ExitStatus,
    ) -> Result<(), Error> {
        assert_eq!(state, 72, "exit did not consume the actual started state");
        assert_eq!(status, reverie::ExitStatus::SUCCESS);
        assert_eq!(global.config(), &71);
        assert_eq!(
            global.send_rpc(Request(301)).await,
            Reply(tid.as_raw(), 301)
        );
        self.exits.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::other("returned exit control error").into())
    }
}

#[test]
fn native_exit_outcome_distinguishes_completed_tool_error_from_owner_refusal() {
    for (index, (deferred, strict)) in [(false, false), (true, false), (false, true), (true, true)]
        .into_iter()
        .enumerate()
    {
        let server = Server::new();
        let (cache, _peer) = fixture::configured_rpc();
        let exits = Arc::new(AtomicUsize::new(0));
        let host = unsafe {
            ToolHost::new_native(
                ExitOutcomeProbe {
                    exits: Arc::clone(&exits),
                },
                cache,
                fixture::actual_pid(libc::SYS_getpid),
                [Sysno::getpid].into_iter().collect(),
                true,
                Runtime,
            )
        };
        let rpc = NativeRpc::new(server.path.clone(), host.rpc.shared_config()).unwrap();
        let callback = Callback::new(120 + index as u64);
        let identity = callback.identity();
        let services = callback.services(None);
        let handle = unsafe { host.register_native_thread(identity, 71).unwrap() };
        let lease = unsafe { host.enter_native_callback(handle, identity).unwrap() };
        let mut call = event(0);
        let entered = unsafe {
            host.with_native_guest(lease, &services, &rpc, &mut call, |_tool, _guest, _| {
                if deferred {
                    NativeCallbackOutcome::<Result<(), Error>>::Deferred {
                        number: libc::SYS_exit,
                        args: [0; 6],
                    }
                } else {
                    NativeCallbackOutcome::Ready(Ok(()))
                }
            })
            .unwrap()
        };
        let pending = match entered {
            NativeCallResult::Return(()) => {
                assert!(!deferred);
                None
            }
            NativeCallResult::Deferred(owner) => {
                assert!(deferred);
                Some(owner)
            }
        };
        if !deferred {
            let wrong = Callback::new(220 + index as u64);
            let refused = unsafe {
                host.dispatch_native_thread_exit_outcome(
                    handle,
                    wrong.identity(),
                    NativeExitRpc::Application(rpc.application(callback.invocation())),
                    reverie::ExitStatus::SUCCESS,
                )
            };
            assert!(
                refused.is_err(),
                "wrong identity reached a completed Tool result"
            );
            assert_eq!(exits.load(Ordering::SeqCst), 0);
        }
        let result = if let Some(owner) = pending {
            if strict {
                unsafe {
                    host.dispatch_native_deferred_thread_exit(
                        owner,
                        identity,
                        NativeExitRpc::Application(rpc.application(callback.invocation())),
                        reverie::ExitStatus::SUCCESS,
                    )
                }
                .map(|()| NativeCallbackOutcome::Ready(Ok(())))
            } else {
                unsafe {
                    host.dispatch_native_deferred_thread_exit_outcome(
                        owner,
                        identity,
                        NativeExitRpc::Application(rpc.application(callback.invocation())),
                        reverie::ExitStatus::SUCCESS,
                    )
                }
            }
        } else if strict {
            unsafe {
                host.dispatch_native_thread_exit(
                    handle,
                    identity,
                    NativeExitRpc::Application(rpc.application(callback.invocation())),
                    reverie::ExitStatus::SUCCESS,
                )
            }
            .map(|()| NativeCallbackOutcome::Ready(Ok(())))
        } else {
            unsafe {
                host.dispatch_native_thread_exit_outcome(
                    handle,
                    identity,
                    NativeExitRpc::Application(rpc.application(callback.invocation())),
                    reverie::ExitStatus::SUCCESS,
                )
            }
        };
        if strict {
            assert!(
                matches!(&result, Err(error)
                if error.to_string().contains("returned exit control error")),
                "the original strict API stopped propagating the actual Tool error"
            );
        } else {
            assert!(
                matches!(&result, Ok(NativeCallbackOutcome::Ready(Err(error)))
                if error.to_string().contains("returned exit control error")),
                "completed Tool failure was merged with mechanism/owner failure"
            );
        }
        assert_eq!(exits.load(Ordering::SeqCst), 1);
        assert!(
            unsafe {
                host.dispatch_native_thread_exit_outcome(
                    handle,
                    identity,
                    NativeExitRpc::Application(rpc.application(callback.invocation())),
                    reverie::ExitStatus::SUCCESS,
                )
            }
            .is_err(),
            "consumed lifecycle was admitted twice"
        );
        assert_eq!(exits.load(Ordering::SeqCst), 1);
        fixture::close_test_primary(&rpc, &callback);
    }
}
