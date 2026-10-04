/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod fatal_daemon_group_tests {
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::path::Path;

    use super::*;

    const TEST: &str = "tracer::tests::fatal_daemon_group_tests::real_daemon_broadcast_kills_sibling_after_leader_sys_exit";
    const ROLE: &str = "REVERIE_DAEMON_GROUP_ROLE";
    const DEADLINE: &str = "REVERIE_DAEMON_GROUP_DEADLINE_NS";
    const ROOT: usize = 0;
    const DAEMON: usize = 1;
    const SIBLING: usize = 2;
    const ROOT_RELEASE: usize = 3;
    const COMPLETED: usize = 4;
    const CONTINUED: usize = 5;
    const HEARTBEAT: usize = 6;
    const DAEMONIZED: usize = 7;
    const LEADER_RETURNED: usize = 8;
    const ROOT_RETURNED: usize = 9;

    fn word(address: usize, index: usize) -> &'static std::sync::atomic::AtomicUsize {
        unsafe { &*(address as *const std::sync::atomic::AtomicUsize).add(index) }
    }

    thread_local! {
        static IDENTITIES: std::cell::RefCell<Vec<TraceeIdentity>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    struct IdentitiesScope;
    impl Drop for IdentitiesScope {
        fn drop(&mut self) {
            IDENTITIES.with(|slot| slot.borrow_mut().clear());
        }
    }

    type Events = Vec<(u8, Pid, Pid, Option<ExitStatus>)>;
    #[derive(Default)]
    struct DaemonLog(Arc<StdMutex<Events>>);

    #[reverie::global_tool]
    impl GlobalTool for DaemonLog {
        type Config = usize;
        type Request = (u8, Pid, Pid, Option<ExitStatus>);
        type Response = ();
        async fn receive_rpc(&self, _: Pid, event: Self::Request) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[derive(Default)]
    struct DaemonTool;

    #[reverie::tool]
    impl Tool for DaemonTool {
        type GlobalState = DaemonLog;
        type ThreadState = i32;

        fn subscriptions(_: &usize) -> Subscription {
            [Sysno::getpgid].into_iter().collect()
        }

        async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
            *guest.thread_state_mut() = guest.pid().as_raw();
            let mut identity = TraceeIdentity::capture(guest.tid(), None, false).unwrap();
            if guest.tid() != guest.pid() {
                // Keep a thread pidfd for observation only. The daemon leader's
                // separate regular pidfd is the group capability used in rescue.
                let fd = unsafe {
                    libc::syscall(libc::SYS_pidfd_open, guest.tid().as_raw(), libc::O_EXCL)
                };
                assert!(fd >= 0, "thread pidfd capture: {}", Errno::last());
                identity.pidfd = Some(unsafe { OwnedFd::from_raw_fd(fd as i32) });
            }
            IDENTITIES.with(|slot| slot.borrow_mut().push(identity));
            guest.send_rpc((0, guest.pid(), guest.tid(), None)).await;
            Ok(())
        }

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            syscall: Syscall,
        ) -> Result<i64, Error> {
            let address = *guest.config();
            assert_eq!(syscall.number(), Sysno::getpgid);
            assert_eq!(guest.pid(), guest.tid());
            assert_eq!(
                guest.pid().as_raw() as usize,
                word(address, DAEMON).load(Ordering::SeqCst)
            );
            assert_ne!(
                guest.pid().as_raw() as usize,
                word(address, ROOT).load(Ordering::SeqCst)
            );
            // This is the real product subscription and broadcast channel. It
            // precedes clone so the child thread inherits daemon accounting.
            guest.daemonize().await;
            word(address, DAEMONIZED).fetch_add(1, Ordering::SeqCst);
            guest.tail_inject(syscall).await
        }

        async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
            &self,
            tid: Pid,
            global: &G,
            process: i32,
            status: ExitStatus,
        ) -> Result<(), Error> {
            global
                .send_rpc((1, Pid::from_raw(process), tid, Some(status)))
                .await;
            Ok(())
        }

        async fn on_exit_process<G: reverie::GlobalRPC<Self::GlobalState>>(
            self,
            pid: Pid,
            global: &G,
            status: ExitStatus,
        ) -> Result<(), Error> {
            global.send_rpc((2, pid, pid, Some(status))).await;
            Ok(())
        }
    }

    fn left(deadline: u64) -> Duration {
        Duration::from_nanos(deadline.saturating_sub(fatal_monotonic_ns()))
    }

    fn deadline() -> u64 {
        std::env::var(DEADLINE).unwrap().parse().unwrap()
    }

    fn socket_budget(socket: &UnixStream, deadline: u64) {
        let remaining = left(deadline);
        assert!(!remaining.is_zero(), "daemon fixture deadline exhausted");
        socket.set_read_timeout(Some(remaining)).unwrap();
        socket.set_write_timeout(Some(remaining)).unwrap();
    }

    fn command(role: &str, deadline: u64) -> std::process::Command {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(ROLE, role)
            .env(DEADLINE, deadline.to_string());
        command
    }

    fn stat(identity: &TraceeIdentity) -> (char, u32, u64) {
        let text = fatal_proc_read(identity, c"stat").unwrap();
        let tail = &text[text.rfind(')').unwrap() + 1..];
        let fields: Vec<_> = tail.split_ascii_whitespace().collect();
        (
            fields[0].chars().next().unwrap(),
            fields[6].parse().unwrap(),
            fields[19].parse().unwrap(),
        )
    }

    fn pidfd_ready(identity: &TraceeIdentity) -> bool {
        let mut fd = libc::pollfd {
            fd: identity.pidfd.as_ref().unwrap().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut fd, 1, 0) };
        assert!(rc >= 0, "pidfd poll: {}", Errno::last());
        rc == 1 && fd.revents & libc::POLLIN != 0
    }

    fn exact_hooks(events: &Events, root: Pid, daemon: Pid, sibling: Pid) -> bool {
        let killed = ExitStatus::Signaled(Signal::SIGKILL, false);
        let expected = [
            (0, root, root, None),
            (0, daemon, daemon, None),
            (0, daemon, sibling, None),
            (1, root, root, Some(ExitStatus::Exited(23))),
            (2, root, root, Some(ExitStatus::Exited(23))),
            (1, daemon, daemon, Some(killed)),
            (1, daemon, sibling, Some(killed)),
            (2, daemon, daemon, Some(killed)),
        ];
        events.len() == expected.len()
            && expected
                .iter()
                .all(|e| events.iter().filter(|got| *got == e).count() == 1)
    }

    fn notifier_retired(root: Pid, daemon: Pid, sibling: Pid) -> bool {
        FATAL_REAP_OBSERVATIONS.with(|slot| {
            let tasks = slot.borrow();
            let tasks = tasks.as_ref().unwrap();
            tasks.len() == 3
                && [root, daemon, sibling].into_iter().all(|tid| {
                    let matches: Vec<_> = tasks.iter().filter(|task| task.tid == tid).collect();
                    matches.len() == 1
                        && matches[0].terminal.wait(Duration::ZERO)
                        && matches[0].held.lock().unwrap().is_none()
                        && matches[0].terminal.observed_exit_status()
                            == Ok(Some(if tid == root {
                                ExitStatus::Exited(23)
                            } else {
                                ExitStatus::Signaled(Signal::SIGKILL, false)
                            }))
                })
        })
    }

    async fn tracer_role() {
        assert_eq!(
            fatal_subreaper_state(),
            0,
            "tracer is not the natural reaper"
        );
        let deadline = deadline();
        let started = Instant::now();
        let mut channel = unsafe { UnixStream::from_raw_fd(libc::STDIN_FILENO) };
        socket_budget(&channel, deadline);
        let _observations = FatalReapObservationScope::new();
        assert!(IDENTITIES.with(|slot| slot.borrow().is_empty()));
        let _identities = IdentitiesScope;
        let words = FatalWords::new();
        let address = words.0 as usize;
        let sentinel = fork_paused_child(Instant::now() + left(deadline));
        let sentinel_identity = untraced_process_identity(sentinel);
        let tracer = tokio::time::timeout(
            left(deadline),
            spawn_fn_with_config::<DaemonTool, _>(
                move || {
                    word(address, ROOT).store(unsafe { libc::getpid() } as usize, Ordering::SeqCst);
                    match unsafe { unistd::fork() }.unwrap() {
                        ForkResult::Child => {
                            word(address, DAEMON)
                                .store(unsafe { libc::getpid() } as usize, Ordering::SeqCst);
                            assert!(unsafe { libc::syscall(libc::SYS_getpgid, 0) } >= 0);
                            assert_eq!(word(address, DAEMONIZED).load(Ordering::SeqCst), 1);
                            std::thread::spawn(move || {
                                word(address, SIBLING).store(
                                    unsafe { libc::syscall(libc::SYS_gettid) } as usize,
                                    Ordering::SeqCst,
                                );
                                while word(address, COMPLETED).load(Ordering::SeqCst) == 0 {
                                    word(address, HEARTBEAT).fetch_add(1, Ordering::SeqCst);
                                    unsafe {
                                        libc::sched_yield();
                                    }
                                }
                                word(address, CONTINUED).store(1, Ordering::SeqCst);
                                loop {
                                    unsafe {
                                        libc::pause();
                                    }
                                }
                            });
                            while word(address, HEARTBEAT).load(Ordering::SeqCst) == 0 {
                                unsafe {
                                    libc::sched_yield();
                                }
                            }
                            unsafe {
                                libc::syscall(libc::SYS_exit, 7);
                            }
                            word(address, LEADER_RETURNED).store(1, Ordering::SeqCst);
                            unsafe {
                                libc::_exit(127);
                            }
                        }
                        ForkResult::Parent { .. } => {
                            while word(address, ROOT_RELEASE).load(Ordering::SeqCst) == 0 {
                                unsafe {
                                    libc::sched_yield();
                                }
                            }
                            unsafe {
                                libc::syscall(libc::SYS_exit_group, 23);
                            }
                            word(address, ROOT_RETURNED).store(1, Ordering::SeqCst);
                        }
                    }
                },
                address,
                true,
            ),
        )
        .await
        .expect("spawn exceeded original pre-start 3 s")
        .unwrap();
        let root = tracer.guest_pid();
        let root_identity = untraced_process_identity(root);
        let session = tracer.ordinary_session.clone();
        let termination = tracer.termination_handle().unwrap();
        let events = tracer.gref.0.clone();
        let mut completion = Box::pin(tracer.wait_with_output_completion());
        let binding = tokio::time::timeout(left(deadline), async {
            loop {
                tokio::select! {
                    _ = &mut completion => panic!("completed before actual daemon leader exit gate"),
                    () = tokio::task::yield_now() => {}
                }
                let daemon = Pid::from_raw(words.read(DAEMON) as i32);
                let sibling = Pid::from_raw(words.read(SIBLING) as i32);
                if daemon.as_raw() == 0 || sibling.as_raw() == 0 || words.read(HEARTBEAT) == 0 { continue; }
                let observed = IDENTITIES.with(|slot| {
                    let ids = slot.borrow();
                    let leader = ids.iter().find(|id| id.tid == daemon)?;
                    let sibling = ids.iter().find(|id| id.tid == sibling)?;
                    let leader_stat = stat(leader);
                    if leader_stat.0 != 'Z' || leader_stat.1 & 4 == 0 { return None; }
                    let sibling_stat = stat(sibling);
                    assert!(leader.same_process() && sibling.same_process());
                    assert_eq!(leader_stat.2, leader.snapshot.start_time);
                    assert_eq!(sibling_stat.2, sibling.snapshot.start_time);
                    assert_eq!(sibling.snapshot.tgid, daemon);
                    assert!(!matches!(sibling_stat.0, 'Z' | 'X'));
                    assert_eq!(sibling_stat.1 & 4, 0);
                    assert!(!pidfd_ready(leader) && !pidfd_ready(sibling));
                    assert_eq!(sibling.send_raw_signal(0), Ok(()));
                    Some([daemon.as_raw() as u64, leader.snapshot.start_time, leader.proc_inode,
                        root.as_raw() as u64, sibling.tid.as_raw() as u64, sibling.snapshot.start_time,
                        sibling.proc_inode, leader_stat.1 as u64, words.read(HEARTBEAT) as u64])
                });
                if let Some(observed) = observed {
                    let exact = format!("finish getevent: tid={daemon}, result=Ok({}),", 7 << 8);
                    assert!(FATAL_REAP_CHRONOLOGY.with(|slot| slot.borrow().as_ref().unwrap().0.iter().any(|line| line.starts_with(&exact))), "missing actual leader EXIT message7");
                    assert!(!session.ordinary_receipt().backend_signalling);
                    break observed;
                }
            }
        }).await.expect("leader never reached real Z/PF_EXITING before original deadline");
        let daemon = Pid::from_raw(binding[0] as i32);
        let sibling = Pid::from_raw(binding[4] as i32);
        eprintln!(
            "daemon pre-broadcast actual identity: binding={binding:?}, chronology={:?}",
            FATAL_REAP_CHRONOLOGY.with(|slot| slot.borrow().clone())
        );
        fatal_control_write(&mut channel, binding);
        assert_eq!(fatal_control_read::<1>(&mut channel), [1]);
        // Root exit, not the test, now performs the real all-daemons broadcast.
        word(address, ROOT_RELEASE).store(1, Ordering::SeqCst);
        let result = tokio::time::timeout(left(deadline), &mut completion).await;
        let snapshot: Vec<_> = (0..10).map(|i| words.read(i)).collect();
        let observed_events = events.lock().unwrap().clone();
        let receipt = session.ordinary_receipt();
        let retired = notifier_retired(root, daemon, sibling);
        let untouched = sentinel_identity.same_process()
            && unsafe { libc::waitpid(sentinel.as_raw(), std::ptr::null_mut(), libc::WNOHANG) }
                == 0;
        let description = match &result {
            Ok(ToolRunOutcome::Complete(done)) => format!("Complete({:?})", done.result),
            Ok(ToolRunOutcome::CleanupPending(pending)) => {
                format!("Pending({:?})", pending.failure())
            }
            Ok(ToolRunOutcome::UnsupportedBackend(_)) => "Unsupported".into(),
            Err(error) => format!("Timeout({error})"),
        };
        let ready = matches!(&result, Ok(ToolRunOutcome::Complete(done)) if done.result.as_ref().is_ok_and(|output| output.status == ExitStatus::Exited(23) && output.stdout.is_empty() && output.stderr.is_empty()) && done.callback_diagnostics().is_empty())
            && retired
            && untouched
            && !root_identity.same_process()
            && receipt.backend_signalling
            && !receipt.failure_published
            && session.unconfirmed_task_count() == 0
            && exact_hooks(&observed_events, root, daemon, sibling)
            && snapshot[DAEMONIZED] == 1
            && snapshot[CONTINUED] == 0
            && snapshot[LEADER_RETURNED] == 0
            && snapshot[ROOT_RETURNED] == 0
            && fatal_monotonic_ns() < deadline;
        eprintln!(
            "daemon original predicate: ready={ready}, outcome={description}, root={root}, daemon={daemon}, sibling={sibling}, notifier_retired={retired}, sentinel_untouched={untouched}, backend_signalling={}, failure_published={}, shared={snapshot:?}, events={observed_events:?}, elapsed={:?}",
            receipt.backend_signalling,
            receipt.failure_published,
            started.elapsed()
        );
        eprintln!("daemon original owner readback:\n{}", fatal_reap_readback());
        IDENTITIES.with(|slot| {
            for identity in slot.borrow().iter() {
                eprintln!(
                    "daemon original retained identity: tid={}, initial={:?}, inode={}, same_process={}, stat={:?}, pidfd_ready={}",
                    identity.tid,
                    identity.snapshot,
                    identity.proc_inode,
                    identity.same_process(),
                    fatal_proc_read(identity, c"stat"),
                    pidfd_ready(identity)
                );
            }
        });
        // Seal the original outcome before any emergency signal or natural reap.
        let rescue_deadline = (fatal_monotonic_ns() + 2_000_000_000).min(deadline + 2_000_000_000);
        socket_budget(&channel, if ready { deadline } else { rescue_deadline });
        fatal_control_write(&mut channel, [u64::from(ready)]);
        let done = match result {
            Ok(ToolRunOutcome::Complete(done)) => Some(done),
            other => {
                termination.terminate(Error::Tool(anyhow::Error::new(TestDeadline)));
                IDENTITIES.with(|slot| {
                    for id in slot.borrow().iter().filter(|id| id.tid == id.snapshot.tgid) {
                        eprintln!(
                            "daemon rescue-only group pidfd signal tid={}: {:?}",
                            id.tid,
                            id.send_signal(Signal::SIGKILL)
                        );
                    }
                });
                let rescued = match other {
                    Err(_) => tokio::time::timeout(left(rescue_deadline), &mut completion).await,
                    Ok(ToolRunOutcome::CleanupPending(pending)) => {
                        tokio::time::timeout(left(rescue_deadline), pending.resume_cleanup()).await
                    }
                    _ => panic!("ordinary daemon fixture unexpectedly unsupported"),
                };
                match rescued {
                    Ok(ToolRunOutcome::Complete(done)) => Some(done),
                    _ => None,
                }
            }
        };
        let physical_ready = done.is_some()
            && FATAL_REAP_OBSERVATIONS.with(|slot| {
                slot.borrow().as_ref().unwrap().iter().all(|task| {
                    task.terminal.wait(Duration::ZERO) && task.held.lock().unwrap().is_none()
                })
            });
        fatal_control_write(&mut channel, [u64::from(physical_ready)]);
        assert!(
            physical_ready,
            "rescue failed; original failure remains {description}"
        );
        word(address, COMPLETED).store(1, Ordering::SeqCst);
        let heartbeat = words.read(HEARTBEAT);
        tokio::task::yield_now().await;
        assert_eq!(words.read(HEARTBEAT), heartbeat);
        assert_eq!(
            words.read(CONTINUED),
            0,
            "guest continuation after completion"
        );
        assert_eq!(
            fatal_control_read::<1>(&mut channel),
            [1],
            "natural parent did not reap"
        );
        assert_reaped("naturally reaped daemon", daemon);
        assert_reaped("daemon sibling", sibling);
        assert_reaped("natural root", root);
        // The sentinel was observed untouched before this owned teardown.
        sentinel_identity.send_signal(Signal::SIGKILL).unwrap();
        loop {
            let rc =
                unsafe { libc::waitpid(sentinel.as_raw(), std::ptr::null_mut(), libc::WNOHANG) };
            if rc == sentinel.as_raw() {
                break;
            }
            assert_eq!(rc, 0);
            assert!(fatal_monotonic_ns() < if ready { deadline } else { rescue_deadline });
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(
            ready,
            "original daemon broadcast predicate failed: {description}"
        );
        assert!(fatal_monotonic_ns() < deadline);
    }

    fn reaper_role() {
        assert_eq!(fatal_subreaper_state(), 1);
        let deadline = deadline();
        let (mut channel, child_channel) = UnixStream::pair().unwrap();
        socket_budget(&channel, deadline);
        let mut tracer = command("tracer", deadline)
            .stdin(std::process::Stdio::from(OwnedFd::from(child_channel)))
            .spawn()
            .unwrap();
        let tracer_identity = untraced_process_identity(Pid::from_raw(tracer.id() as i32));
        let binding = fatal_control_read::<9>(&mut channel);
        let daemon = Pid::from_raw(binding[0] as i32);
        let identity = untraced_process_identity(daemon);
        assert_eq!(identity.snapshot.start_time, binding[1]);
        assert_eq!(identity.proc_inode, binding[2]);
        assert_eq!(identity.snapshot.ppid.as_raw() as u64, binding[3]);
        assert_eq!(stat(&identity).0, 'Z');
        assert_ne!(stat(&identity).1 & 4, 0);
        assert!(
            !pidfd_ready(&identity),
            "daemon group already dead before broadcast"
        );
        eprintln!("natural reaper retained pre-broadcast daemon: {binding:?}");
        fatal_control_write(&mut channel, [1]);
        // A failed original3s outcome may need its separate2s rescue before the
        // natural parent can receive the notifier's completed terminal handoff.
        socket_budget(&channel, deadline + 2_000_000_000);
        let [original_ready] = fatal_control_read::<1>(&mut channel);
        let [physical_ready] = fatal_control_read::<1>(&mut channel);
        assert_eq!(physical_ready, 1);
        assert!(identity.same_process());
        let snapshot = tracee_snapshot(daemon).unwrap();
        assert_eq!(snapshot.start_time, binding[1]);
        assert_eq!(snapshot.ppid.as_raw(), unsafe { libc::getpid() });
        assert_eq!(
            snapshot.tracer_pid.as_raw(),
            0,
            "ptracer still owns daemon wait"
        );
        assert_eq!(stat(&identity).0, 'Z');
        let fd = identity.pidfd.as_ref().unwrap().as_raw_fd() as u32;
        for flags in [
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            libc::WEXITED | libc::WNOHANG,
        ] {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::waitid(libc::P_PIDFD, fd, &mut info, flags) },
                0
            );
            assert_eq!(unsafe { info.si_pid() }, daemon.as_raw());
            assert_eq!(info.si_code, libc::CLD_KILLED);
            assert_eq!(unsafe { info.si_status() }, libc::SIGKILL);
            eprintln!(
                "natural daemon wait: original_ready={original_ready}, pid={daemon}, flags={flags}, code={}, status={}",
                info.si_code,
                unsafe { info.si_status() }
            );
            assert_eq!(
                Path::new(&format!("/proc/{daemon}")).exists(),
                flags & libc::WNOWAIT != 0
            );
        }
        if original_ready == 1 {
            assert!(fatal_monotonic_ns() < deadline);
        }
        fatal_control_write(&mut channel, [1]);
        let until = if original_ready == 1 {
            deadline
        } else {
            deadline + 2_000_000_000
        };
        while !pidfd_ready(&tracer_identity) {
            assert!(
                fatal_monotonic_ns() < until,
                "isolated tracer did not retire"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let status = tracer.wait().unwrap();
        assert_eq!(
            unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            Errno::last(),
            Errno::ECHILD,
            "natural reaper retained another child"
        );
        assert_eq!(
            original_ready, 1,
            "daemon baseline required rescue; not a passing product"
        );
        assert!(
            status.success(),
            "isolated tracer assertions failed: {status}"
        );
        assert!(fatal_monotonic_ns() < deadline);
    }

    // The outer process owns one unreaped group anchor, used only for failure
    // containment if an isolated role panics before its normal protocol ends.
    struct IsolatedGroup {
        child: std::process::Child,
        reaped: bool,
        rescue_deadline: u64,
    }
    impl Drop for IsolatedGroup {
        fn drop(&mut self) {
            if !self.reaped {
                unsafe {
                    libc::kill(-(self.child.id() as i32), libc::SIGKILL);
                }
                loop {
                    match self.child.try_wait() {
                        Ok(Some(_)) => {
                            self.reaped = true;
                            break;
                        }
                        Ok(None) if fatal_monotonic_ns() < self.rescue_deadline => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        other => {
                            eprintln!("isolated daemon failure cleanup unconfirmed: {other:?}");
                            break;
                        }
                    }
                }
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_daemon_broadcast_kills_sibling_after_leader_sys_exit() {
        if let Ok(role) = std::env::var(ROLE) {
            assert!(std::env::args().any(|arg| arg == TEST));
            assert!(std::env::args().any(|arg| arg == "--exact"));
            match role.as_str() {
                "reaper" => reaper_role(),
                "tracer" => tracer_role().await,
                other => panic!("invalid daemon fixture role: {other}"),
            }
            return;
        }
        let deadline = fatal_monotonic_ns() + 3_000_000_000;
        let mut child = command("reaper", deadline);
        child.process_group(0);
        unsafe {
            child.pre_exec(|| {
                if libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut group = IsolatedGroup {
            child: child.spawn().unwrap(),
            reaped: false,
            rescue_deadline: deadline + 2_000_000_000,
        };
        let identity = untraced_process_identity(Pid::from_raw(group.child.id() as i32));
        let mut original_timeout = false;
        while !pidfd_ready(&identity) {
            if fatal_monotonic_ns() >= deadline {
                original_timeout = true;
            }
            assert!(
                fatal_monotonic_ns() < deadline + 2_000_000_000,
                "isolated daemon fixture exceeded original3s plus rescue2s"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let mut held: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    identity.pidfd.as_ref().unwrap().as_raw_fd() as u32,
                    &mut held,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            },
            0
        );
        assert_eq!(unsafe { held.si_pid() }, group.child.id() as i32);
        if held.si_code != libc::CLD_EXITED || unsafe { held.si_status() } != 0 {
            // Still unreaped: this cannot signal a reused numeric process group.
            unsafe {
                libc::kill(-(group.child.id() as i32), libc::SIGKILL);
            }
        }
        let status = group.child.wait().unwrap();
        group.reaped = true;
        assert!(
            !original_timeout,
            "original daemon fixture deadline failed; rescue is not success"
        );
        assert!(status.success(), "isolated daemon fixture failed: {status}");
        assert!(fatal_monotonic_ns() < deadline);
    }
}
