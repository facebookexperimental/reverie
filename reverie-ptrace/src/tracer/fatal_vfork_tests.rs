/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod fatal_vfork_tests {
    use super::*;

    const CONTROLLED_TEST: &str = "tracer::tests::fatal_vfork_tests::failure_owns_initialized_vfork_child_before_parent_retirement";
    const ROLE: &str = "REVERIE_VFORK_REAP_ROLE";
    const DEADLINE: &str = "REVERIE_VFORK_REAP_DEADLINE_NS";
    thread_local! {
        static CHANNEL: std::cell::RefCell<Option<std::os::unix::net::UnixStream>> = const { std::cell::RefCell::new(None) };
    }

    fn channel_write<const N: usize>(values: [u64; N]) {
        CHANNEL.with(|slot| fatal_control_write(slot.borrow_mut().as_mut().unwrap(), values));
    }
    fn channel_read<const N: usize>() -> [u64; N] {
        CHANNEL.with(|slot| fatal_control_read(slot.borrow_mut().as_mut().unwrap()))
    }

    fn controlled_reaper(deadline: u64) {
        use std::os::unix::net::UnixStream;
        assert_eq!(fatal_subreaper_state(), 1);
        let (mut channel, child_channel) = UnixStream::pair().unwrap();
        channel
            .set_read_timeout(Some(fatal_remaining(deadline)))
            .unwrap();
        channel
            .set_write_timeout(Some(fatal_remaining(deadline)))
            .unwrap();
        let mut tracer = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                CONTROLLED_TEST,
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ROLE, "tracer")
            .env(DEADLINE, deadline.to_string())
            .stdin(std::process::Stdio::from(OwnedFd::from(child_channel)))
            .spawn()
            .unwrap();
        // Capture the child's regular pidfd while its original startup stop
        // is still held, before the failure callback is allowed to run.
        let [root, child, start, inode, terminal_none, retired, held] =
            fatal_control_read::<7>(&mut channel);
        let root = Pid::from_raw(i32::try_from(root).unwrap());
        let child = Pid::from_raw(i32::try_from(child).unwrap());
        let identity = untraced_process_identity(child);
        assert_eq!(identity.snapshot.start_time, start);
        assert_eq!(identity.proc_inode, inode);
        assert_eq!(identity.snapshot.ppid, root);
        // Mandatory real live-stopped negative before the failure is released.
        // The same terminal-handoff predicate must refuse this exact generation.
        let live_status = fatal_proc_read(&identity, c"status").unwrap();
        let mut live_poll = libc::pollfd {
            fd: identity.pidfd.as_ref().unwrap().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let live_ready = unsafe { libc::poll(&mut live_poll, 1, 0) };
        let live_stopped = identity.same_process()
            && identity.snapshot.tracer_pid.as_raw() != 0
            && live_status
                .lines()
                .any(|line| line.starts_with("State:\tt") || line.starts_with("State:\tT"));
        let live_product_retired = terminal_none == 0 && retired == 1 && held == 0;
        let live_natural_handoff = identity.snapshot.ppid.as_raw() == unsafe { libc::getpid() }
            && identity.snapshot.tracer_pid.as_raw() == 0
            && live_ready == 1;
        eprintln!(
            "initialized-vfork live-stopped negative: terminal_none={terminal_none}, retired={retired}, held={held}, stopped={live_stopped}, pidfd_poll={live_ready}, product_retired={live_product_retired}, natural_handoff={live_natural_handoff}"
        );
        assert_eq!([terminal_none, retired, held], [1, 0, 1]);
        assert!(live_stopped);
        assert_eq!(live_ready, 0);
        assert!(!(live_product_retired && live_natural_handoff));
        fatal_control_write(&mut channel, [1]);
        let facts = fatal_control_read::<11>(&mut channel);
        let stat = fatal_proc_read(&identity, c"stat");
        let status = fatal_proc_read(&identity, c"status");
        let snapshot = tracee_snapshot(child);
        let mut pollfd = libc::pollfd {
            fd: identity.pidfd.as_ref().unwrap().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let polled = unsafe { libc::poll(&mut pollfd, 1, 0) };
        let still_same = identity.same_process();
        let state = status.as_ref().unwrap();
        let actual = snapshot.as_ref().unwrap();
        let physical_ready = still_same
            && actual.ppid.as_raw() == unsafe { libc::getpid() }
            && actual.tracer_pid.as_raw() == 0
            && state.lines().any(|line| line.starts_with("State:\tZ"))
            && polled == 1
            && pollfd.revents & libc::POLLIN != 0;
        let product_ready = facts == [1, 1, 1, 1, 0, 0, 1, 0, 1, start, inode];
        eprintln!(
            "initialized-vfork sealed tracer completion before natural wait: product_ready={product_ready}, physical_ready={physical_ready}, facts={facts:?}, startup_start={start}, startup_inode={inode}, stat={stat:?}, status={status:?}, current={snapshot:?}, pidfd_poll={polled}, revents={}",
            pollfd.revents
        );
        assert!(
            product_ready && physical_ready,
            "actual tracer retirement and natural-parent handoff are both required"
        );
        let _remaining = fatal_remaining(deadline);
        let fd = identity.pidfd.as_ref().unwrap().as_raw_fd() as u32;
        let mut held: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    fd,
                    &mut held,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            },
            0
        );
        assert_eq!(unsafe { held.si_pid() }, child.as_raw());
        assert_eq!(held.si_code, libc::CLD_KILLED);
        assert_eq!(unsafe { held.si_status() }, libc::SIGKILL);
        assert!(std::path::Path::new(&format!("/proc/{child}")).exists());
        let mut reaped: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    fd,
                    &mut reaped,
                    libc::WEXITED | libc::WNOHANG,
                )
            },
            0
        );
        assert_eq!(unsafe { reaped.si_pid() }, child.as_raw());
        assert_eq!(reaped.si_code, libc::CLD_KILLED);
        assert_eq!(unsafe { reaped.si_status() }, libc::SIGKILL);
        assert!(!std::path::Path::new(&format!("/proc/{child}")).exists());
        assert!(!std::path::Path::new(&format!("/proc/{root}")).exists());
        let remaining = fatal_remaining(deadline);
        eprintln!(
            "initialized-vfork required natural-parent retirement: WNOWAIT=SIGKILL, consumed=SIGKILL, final_absence=true, remaining_ns={}",
            remaining.as_nanos()
        );
        fatal_control_write(&mut channel, [1]);
        let status = tracer.wait().unwrap();
        assert!(
            status.success(),
            "tracer's complete product predicate failed: {status}"
        );
        let _remaining = fatal_remaining(deadline);
    }

    async fn controlled_failure() {
        use std::os::unix::process::CommandExt;
        match std::env::var(ROLE).as_deref() {
            Ok("reaper") => {
                controlled_reaper(std::env::var(DEADLINE).unwrap().parse().unwrap());
            }
            Ok("tracer") => {
                assert_eq!(fatal_subreaper_state(), 0);
                control(true).await;
            }
            Err(_) => {
                let deadline = fatal_monotonic_ns() + 3_000_000_000;
                let mut command = std::process::Command::new(std::env::current_exe().unwrap());
                command
                    .args([
                        CONTROLLED_TEST,
                        "--exact",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(ROLE, "reaper")
                    .env(DEADLINE, deadline.to_string());
                unsafe {
                    command.pre_exec(|| {
                        if libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let status = command.status().unwrap();
                assert!(
                    status.success(),
                    "initialized-vfork tracer plus natural-parent predicate failed: {status}"
                );
                let _remaining = fatal_remaining(deadline);
            }
            role => panic!("unexpected initialized-vfork role: {role:?}"),
        }
    }

    type VforkEvents = Vec<(u8, Pid, Option<ExitStatus>)>;
    #[derive(Default)]
    struct VforkLog(Arc<StdMutex<VforkEvents>>);

    #[reverie::global_tool]
    impl GlobalTool for VforkLog {
        type Config = (bool, usize);
        type Request = (u8, Pid, Option<ExitStatus>);
        type Response = ();
        async fn receive_rpc(&self, _from: Pid, event: Self::Request) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[derive(Default)]
    struct VforkTool;

    fn word(address: usize, index: usize) -> &'static std::sync::atomic::AtomicUsize {
        // The parent fixture retains this shared mapping until all owned tasks
        // have completed, including any separately reported rescue.
        unsafe { &*(address as *const std::sync::atomic::AtomicUsize).add(index) }
    }

    #[reverie::tool]
    impl Tool for VforkTool {
        type GlobalState = VforkLog;
        type ThreadState = bool;

        fn subscriptions(_config: &(bool, usize)) -> Subscription {
            [Sysno::getpgid].into_iter().collect()
        }

        async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
            if guest.tid() == guest.pid() {
                FATAL_REAP_IDENTITIES.with(|slot| {
                    if let Some(identities) = slot.borrow_mut().as_mut() {
                        identities.push(untraced_process_identity(guest.tid()));
                    }
                });
            }
            guest.send_rpc((0, guest.tid(), None)).await;
            let (fail, address) = *guest.config();
            let root = word(address, 2).load(Ordering::SeqCst);
            if root != 0 && guest.pid().as_raw() as usize != root {
                if std::env::var(ROLE).as_deref() == Ok("tracer") {
                    let (start, inode) = FATAL_REAP_IDENTITIES.with(|slot| {
                        let slot = slot.borrow();
                        let identity = slot
                            .as_ref()
                            .unwrap()
                            .iter()
                            .find(|id| id.tid == guest.pid())
                            .unwrap();
                        (identity.snapshot.start_time, identity.proc_inode)
                    });
                    let (terminal_none, retired, held) = FATAL_REAP_OBSERVATIONS.with(|slot| {
                        let slot = slot.borrow();
                        let owner = slot
                            .as_ref()
                            .unwrap()
                            .iter()
                            .find(|owner| owner.tid == guest.tid())
                            .unwrap();
                        (
                            matches!(owner.terminal.observed_exit_status(), Ok(None)),
                            owner.terminal.wait(Duration::ZERO),
                            owner.held.lock().unwrap().is_some(),
                        )
                    });
                    channel_write([
                        root as u64,
                        guest.pid().as_raw() as u64,
                        start,
                        inode,
                        u64::from(terminal_none),
                        u64::from(retired),
                        u64::from(held),
                    ]);
                    assert_eq!(channel_read::<1>(), [1]);
                }
                word(address, 1).store(guest.pid().as_raw() as usize, Ordering::SeqCst);
                if fail {
                    struct Parked(usize);
                    impl Drop for Parked {
                        fn drop(&mut self) {
                            word(self.0, 3).store(0, Ordering::SeqCst);
                        }
                    }
                    *guest.thread_state_mut() = true;
                    word(address, 3).store(1, Ordering::SeqCst);
                    let _parked = Parked(address);
                    future::pending::<()>().await;
                }
            }
            Ok(())
        }

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            syscall: Syscall,
        ) -> Result<i64, Error> {
            let (fail, address) = *guest.config();
            assert_ne!(guest.tid(), guest.pid());
            assert_ne!(word(address, 1).load(Ordering::SeqCst), 0);
            guest.send_rpc((1, guest.tid(), None)).await;
            if fail {
                assert_eq!(
                    word(address, 3).load(Ordering::SeqCst),
                    1,
                    "vfork child must still be parked in its initialized callback"
                );
                Err(anyhow::Error::new(NonleaderFailure).into())
            } else {
                Ok(guest.inject(syscall).await?)
            }
        }

        async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
            &self,
            tid: Pid,
            global: &G,
            parked: bool,
            status: ExitStatus,
        ) -> Result<(), Error> {
            if parked {
                assert_eq!(status, ExitStatus::Signaled(Signal::SIGKILL, false));
            }
            global.send_rpc((2, tid, Some(status))).await;
            Ok(())
        }

        async fn on_exit_process<G: reverie::GlobalRPC<Self::GlobalState>>(
            self,
            pid: Pid,
            global: &G,
            status: ExitStatus,
        ) -> Result<(), Error> {
            global.send_rpc((3, pid, Some(status))).await;
            Ok(())
        }
    }

    async fn control(fail: bool) {
        let started = Instant::now();
        let absolute = std::env::var(DEADLINE)
            .ok()
            .map(|value| value.parse::<u64>().unwrap());
        let deadline = started
            + absolute
                .map(fatal_remaining)
                .unwrap_or(Duration::from_secs(3));
        let controlled = std::env::var(ROLE).as_deref() == Ok("tracer");
        let _observations = controlled.then(FatalReapObservationScope::new);
        let sentinel = controlled.then(|| fork_paused_child(deadline));
        let sentinel_identity = sentinel.map(untraced_process_identity);
        if controlled {
            let channel =
                unsafe { std::os::unix::net::UnixStream::from_raw_fd(libc::STDIN_FILENO) };
            channel
                .set_read_timeout(Some(fatal_remaining(absolute.unwrap())))
                .unwrap();
            channel
                .set_write_timeout(Some(fatal_remaining(absolute.unwrap())))
                .unwrap();
            CHANNEL.with(|slot| *slot.borrow_mut() = Some(channel));
        }
        let words = FatalWords::new();
        let address = words.0 as usize;
        let tracer = tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            spawn_fn_with_config::<VforkTool, _>(
                move || {
                    word(address, 2).store(unsafe { libc::getpid() } as usize, Ordering::SeqCst);
                    let sibling = std::thread::spawn(move || {
                        while word(address, 1).load(Ordering::SeqCst) == 0 {
                            std::thread::yield_now();
                        }
                        unsafe {
                            libc::syscall(libc::SYS_getpgid, 0);
                        }
                        word(address, 0).store(1, Ordering::SeqCst);
                        if fail {
                            loop {
                                unsafe {
                                    libc::pause();
                                }
                            }
                        }
                    });
                    // CLONE_VFORK gives the real kernel vfork parent suspension
                    // and PTRACE_EVENT_VFORK, while a distinct stack avoids the
                    // unsupported Rust call-frame sharing of libc::vfork.
                    extern "C" fn child_body(_: *mut libc::c_void) -> libc::c_int {
                        7
                    }
                    let mut stack = vec![0u8; 16 * 1024];
                    let stack_top = (unsafe { stack.as_mut_ptr().add(stack.len()) } as usize
                        & !15usize) as *mut libc::c_void;
                    let child = unsafe {
                        libc::clone(
                            child_body,
                            stack_top,
                            libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD,
                            std::ptr::null_mut::<libc::c_void>(),
                        )
                    };
                    assert!(child > 0);
                    let mut status = 0;
                    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
                    assert!(libc::WIFEXITED(status));
                    assert_eq!(libc::WEXITSTATUS(status), 7);
                    sibling.join().unwrap();
                },
                (fail, address),
                true,
            ),
        )
        .await
        .expect("vfork spawn exceeded single deadline")
        .unwrap();
        let root = tracer.guest_pid();
        let session = tracer.ordinary_session.clone();
        let identity = untraced_process_identity(root);
        let termination = tracer.termination_handle().unwrap();
        let log = tracer.gref.0.clone();
        let mut completion = Box::pin(tracer.wait_with_output_completion());
        let result = tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            &mut completion,
        )
        .await;
        let elapsed = started.elapsed();
        let root_retired = !identity.same_process();
        let child = Pid::from_raw(words.read(1) as i32);
        let original_child_absent = !std::path::Path::new(&format!("/proc/{child}")).exists();
        let physical = controlled.then(fatal_reap_readback);
        let after = words.read(0);
        let parked = words.read(3);
        let events = log.lock().unwrap().clone();
        let edges = session.observed_child_ops.lock().unwrap().clone();
        eprintln!("actual ptrace child edges: {edges:?}");
        let description = match &result {
            Ok(ToolRunOutcome::Complete(completed)) => format!("Complete({:?})", completed.result),
            Ok(ToolRunOutcome::CleanupPending(pending)) => {
                format!("Pending({:?})", pending.failure())
            }
            Ok(ToolRunOutcome::UnsupportedBackend(_)) => "UnsupportedBackend".to_owned(),
            Err(error) => format!("Timeout({error})"),
        };
        eprintln!(
            "vfork before rescue: fail={fail}, root={root}, child={child}, root_retired={root_retired}, after={after}, parked={parked}, elapsed={elapsed:?}, events={events:?}, outcome={description}"
        );
        let completed = match result {
            Ok(ToolRunOutcome::Complete(completed)) => completed,
            other => {
                let rescue_deadline = Instant::now() + Duration::from_secs(2);
                termination.terminate(Error::Tool(anyhow::Error::new(TestDeadline)));
                let signal = identity.send_signal(Signal::SIGKILL);
                let rescued = match other {
                    Err(_) => {
                        tokio::time::timeout(
                            rescue_deadline.saturating_duration_since(Instant::now()),
                            &mut completion,
                        )
                        .await
                    }
                    Ok(ToolRunOutcome::CleanupPending(pending)) => {
                        tokio::time::timeout(
                            rescue_deadline.saturating_duration_since(Instant::now()),
                            pending.resume_cleanup(),
                        )
                        .await
                    }
                    Ok(ToolRunOutcome::UnsupportedBackend(tracer)) => {
                        tokio::time::timeout(
                            rescue_deadline.saturating_duration_since(Instant::now()),
                            tracer.wait_with_output_completion(),
                        )
                        .await
                    }
                    Ok(ToolRunOutcome::Complete(_)) => unreachable!(),
                };
                eprintln!(
                    "vfork rescue only: signal={signal:?}, completed={}",
                    matches!(rescued, Ok(ToolRunOutcome::Complete(_)))
                );
                panic!("vfork did not Complete within original3s predicate: {description}");
            }
        };
        assert!(elapsed <= Duration::from_secs(3));
        assert!(root_retired);
        assert_eq!(
            edges
                .iter()
                .filter(|edge| **edge == (root, safeptrace::ChildOp::Vfork, child))
                .count(),
            1
        );
        assert_eq!(parked, 0, "initialized child callback was not cancelled");
        assert_reaped("vfork root", root);
        if controlled {
            // Explicit contract correction: ptracer completion can leave the
            // natural parent's zombie. Seal every original product obligation
            // before that independent owner performs its actual terminal wait.
            // The original immediate-absence diagnostic remains a failed artifact.
            let original_error = matches!(&completed.result, Err(failure)
                if matches!(failure.primary(), Error::Tool(error) if error.downcast_ref::<NonleaderFailure>().is_some())
                && failure.origin().phase == "ptrace syscall callback"
                && failure.captured_prefix().is_some_and(|prefix| prefix.stdout().is_empty() && prefix.stderr().is_empty()));
            let callbacks = events.iter().filter(|event| event.0 == 0).count() == 3
                && events.iter().filter(|event| event.0 == 1).count() == 1
                && events.iter().filter(|event| event.0 == 2).count() == 3
                && events.iter().filter(|event| event.0 == 3).count() == 2
                && events.iter().filter(|event| event.0 == 0).all(|start| {
                    events
                        .iter()
                        .filter(|event| {
                            event.0 == 2
                                && event.1 == start.1
                                && event.2 == Some(ExitStatus::Signaled(Signal::SIGKILL, false))
                        })
                        .count()
                        == 1
                })
                && *completed.global_state.0.lock().unwrap() == events;
            let owners = FATAL_REAP_OBSERVATIONS.with(|slot| {
                let slot = slot.borrow();
                let owners = slot.as_ref().unwrap();
                owners.len() == 3
                    && owners.iter().all(|owner| {
                        owner.terminal.observed_exit_status()
                            == Ok(Some(ExitStatus::Signaled(Signal::SIGKILL, false)))
                            && owner.terminal.wait(Duration::ZERO)
                            && owner.held.lock().unwrap().is_none()
                    })
            });
            let (start, inode) = FATAL_REAP_IDENTITIES.with(|slot| {
                let slot = slot.borrow();
                let identity = slot
                    .as_ref()
                    .unwrap()
                    .iter()
                    .find(|id| id.tid == child)
                    .unwrap();
                (identity.snapshot.start_time, identity.proc_inode)
            });
            let sentinel_safe = sentinel_identity.as_ref().unwrap().same_process()
                && unsafe {
                    libc::waitpid(
                        sentinel.unwrap().as_raw(),
                        std::ptr::null_mut(),
                        libc::WNOHANG,
                    )
                } == 0;
            eprintln!(
                "initialized-vfork original physical readback (sampled before prints/assertions/natural wait): {physical:?}"
            );
            channel_write([
                1,
                u64::from(original_error),
                u64::from(callbacks),
                u64::from(owners),
                after as u64,
                parked as u64,
                u64::from(root_retired),
                u64::from(original_child_absent),
                u64::from(sentinel_safe),
                start,
                inode,
            ]);
            assert_eq!(channel_read::<1>(), [1]);
            // The natural owner proved WNOWAIT SIGKILL, consumed the actual
            // status and final absence within the same pre-start deadline.
            assert_reaped("vfork child after natural-parent wait", child);
            sentinel_identity
                .as_ref()
                .unwrap()
                .send_signal(Signal::SIGKILL)
                .unwrap();
            assert_eq!(
                unsafe { libc::waitpid(sentinel.unwrap().as_raw(), std::ptr::null_mut(), 0) },
                sentinel.unwrap().as_raw()
            );
            CHANNEL.with(|slot| *slot.borrow_mut() = None);
        } else {
            assert_reaped("vfork child", child);
        }
        assert_eq!(*completed.global_state.0.lock().unwrap(), events);
        assert_eq!(events.iter().filter(|e| e.0 == 0).count(), 3);
        assert_eq!(events.iter().filter(|e| e.0 == 1).count(), 1);
        assert_eq!(events.iter().filter(|e| e.0 == 2).count(), 3);
        assert_eq!(events.iter().filter(|e| e.0 == 3).count(), 2);
        for start in events.iter().filter(|e| e.0 == 0) {
            let expected = if fail {
                ExitStatus::Signaled(Signal::SIGKILL, false)
            } else {
                ExitStatus::Exited(if start.1 == child { 7 } else { 0 })
            };
            assert_eq!(
                events
                    .iter()
                    .filter(|e| e.0 == 2 && e.1 == start.1 && e.2 == Some(expected))
                    .count(),
                1
            );
            assert_reaped("vfork task", start.1);
        }
        if fail {
            assert_eq!(after, 0, "failed sibling resumed user code");
            let failure = completed.result.expect_err("vfork failure lost");
            assert!(
                matches!(failure.primary(), Error::Tool(e) if e.downcast_ref::<NonleaderFailure>().is_some())
            );
            assert_eq!(failure.origin().phase, "ptrace syscall callback");
            assert_eq!(failure.captured_prefix().unwrap().stdout(), b"");
            assert_eq!(failure.captured_prefix().unwrap().stderr(), b"");
        } else {
            assert_eq!(after, 1);
            assert_eq!(completed.result.unwrap().status, ExitStatus::Exited(0));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failure_owns_initialized_vfork_child_before_parent_retirement() {
        controlled_failure().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn successful_vfork_consumes_every_state_once() {
        control(false).await;
    }
}
