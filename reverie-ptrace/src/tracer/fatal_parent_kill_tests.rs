/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

pub(super) mod fatal_parent_kill_tests {
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use std::sync::Weak;

    use reverie::syscalls::Addr;
    use reverie::syscalls::MemoryAccess;

    use super::*;

    // 0 magic; 1 child PID; 2 callback releases parent; 3 parent wait complete;
    // 4 raw parent wait status; 5 child continuation; 6 parent is running;
    // 7 actual memory reads; 8 actual errno; 9 parent kill return+1;
    // 19 how the kill spin saw the kill; 20 the kill spin's CPU nanoseconds.
    const MAGIC: usize = 0x315f_4553;
    const PARENT_KILL: u8 = 0;
    const LIVE_ERROR: u8 = 1;
    const SUCCESS: u8 = 2;
    const FORGED_LIVE: u8 = 3;
    const FORGED_KILL: u8 = 4;
    const INDEPENDENT_AFTER_KILL: u8 = 5;
    const TOOL_AFTER_KILL: u8 = 6;
    const IO_AFTER_KILL: u8 = 7;
    const UNRETURNED_ERRNO: u8 = 8;
    const CANCEL_PENDING: u8 = 9;
    const LATE_FAILURE: u8 = 10;
    const OWNED_DAEMON: u8 = 11;
    const TIMER_QUERY_KILL: u8 = 12;
    /// PARENT_KILL with the spin held, before its first read, until the
    /// child is in its PTRACE_EVENT_EXIT stop.
    const EXIT_STOP_KILL: u8 = 13;
    thread_local! {
        static OWNED_DAEMON_SESSION: std::cell::RefCell<Option<Arc<FatalSession>>> = const { std::cell::RefCell::new(None) };
        // While a fixture runs: the tasks its session registered, held weakly
        // so that no task outlives its owners because of this readback.
        static REGISTERED_TASKS: std::cell::RefCell<Option<Vec<Weak<FatalTaskStop>>>> = const { std::cell::RefCell::new(None) };
    }

    // How the kill spin saw the parent's SIGKILL of the child (word 19).
    /// A read of the child failed with ESRCH: the child was between the kill
    /// and its PTRACE_EVENT_EXIT stop.
    const SEEN_BY_READ: usize = 1;
    /// The exit-stop probe found the child dead: in its PTRACE_EVENT_EXIT
    /// stop, where reads succeed again, or out of its stop on the way there.
    const SEEN_BY_PROBE: usize = 2;
    /// Not seen: the spin used up its CPU budget, or the probe could not
    /// observe the child. The spin's stderr line says which.
    const NOT_SEEN: usize = 3;

    /// The livelock cap of one kill spin, in CPU time of the tracer thread
    /// that runs it. It is not wall time, which load stretches, and not a
    /// latency gate. Once the parent's SIGKILL is sent, the child reaches its
    /// exit stop in a few scheduled steps, and the spin ends there. Each
    /// spin's own CPU time is recorded in word 20.
    const KILL_SPIN_CPU_BUDGET_NS: u64 = 5_000_000_000;

    /// The calling thread's CPU time (CLOCK_THREAD_CPUTIME_ID), in
    /// nanoseconds.
    fn thread_cpu_ns() -> u64 {
        let mut now: libc::timespec = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut now) },
            0
        );
        u64::try_from(now.tv_sec).unwrap() * 1_000_000_000 + u64::try_from(now.tv_nsec).unwrap()
    }

    /// Test-only readback of a task the session registered
    /// (`record_fatal_task_for_test`), never a second owner.
    pub(crate) fn record_registered(task: &Arc<FatalTaskStop>) {
        REGISTERED_TASKS.with(|slot| {
            if let Some(tasks) = slot.borrow_mut().as_mut() {
                tasks.push(Arc::downgrade(task));
            }
        });
    }

    /// Collects the registered tasks while it lives.
    struct RegisteredTasksScope;
    impl RegisteredTasksScope {
        fn new() -> Self {
            REGISTERED_TASKS.with(|slot| {
                assert!(slot.borrow().is_none());
                *slot.borrow_mut() = Some(Vec::new());
            });
            Self
        }
    }
    impl Drop for RegisteredTasksScope {
        fn drop(&mut self) {
            REGISTERED_TASKS.with(|slot| *slot.borrow_mut() = None);
        }
    }

    /// The capability for the stop that the callback of `tid` holds, from the
    /// original generation the task's run loop uses (the registered task's
    /// wait owner). A Tool callback is generic over its `Guest`, so it cannot
    /// reach that capability through the guest itself.
    fn held_stop(tid: Pid) -> Stopped {
        REGISTERED_TASKS.with(|slot| {
            slot.borrow()
                .as_ref()
                .expect("the fixture collects registered tasks")
                .iter()
                .rev()
                .filter_map(Weak::upgrade)
                .find(|task| task.tid == tid)
                .expect("the callback's task is registered")
                .waits
                .stopped()
        })
    }

    /// Spins on the tracer thread until it sees `child`, which the guest's
    /// parent SIGKILLs, dead. Records how in word 19 and the CPU time used in
    /// word 20, and returns whether it saw the kill.
    ///
    /// Each turn reads the child's MAGIC word through `read`, then probes the
    /// held stop. Reverie sets PTRACE_O_TRACEEXIT, so a read fails with ESRCH
    /// only in the short window between the kill and the child's arrival at
    /// its PTRACE_EVENT_EXIT stop: once the child is in that stop, reads
    /// succeed again, and a spin that missed the window would never end on
    /// reads alone (see <https://github.com/rrnewton/hermit/issues/3357>).
    /// The probe, [`Stopped::died_into_exit_stop_before_resume`], sees the
    /// death either way, by PF_SIGNALED or by an ESRCH of its own, and it
    /// tells a real exit stop from the forged exit siginfo FORGED_KILL holds.
    ///
    /// The spin never awaits: its callback must return its errno while it
    /// alone holds the stop, before an exit future can claim the exit stop.
    /// Each turn yields the CPU instead, so that the parent and the child
    /// run on a loaded host. The spin is bounded by KILL_SPIN_CPU_BUDGET_NS
    /// alone. When that runs out, or the probe cannot observe, the spin says
    /// so and returns false rather than panicking on the tracer thread, so
    /// that the fixture retires its sentinel before it fails.
    ///
    /// `hold` is the regression seam: before the first read, the spin waits
    /// until the child is in its exit stop ([`in_exit_stop`]), so that the
    /// ESRCH window has passed and only the probe can see the kill.
    fn spin_until_killed(
        child: &Stopped,
        address: usize,
        hold: bool,
        mut read: impl FnMut() -> Result<usize, Errno>,
    ) -> bool {
        let start = thread_cpu_ns();
        let over_budget = || thread_cpu_ns() - start >= KILL_SPIN_CPU_BUDGET_NS;
        let pid = child.pid();
        let seen = 'spin: {
            if hold {
                while !in_exit_stop(pid, pid) {
                    if over_budget() {
                        eprintln!(
                            "kill spin: child {pid} reached no exit stop within the CPU budget"
                        );
                        break 'spin NOT_SEEN;
                    }
                    std::thread::yield_now();
                }
            }
            loop {
                match read() {
                    Ok(value) => {
                        assert_eq!(value, MAGIC);
                        word(address, 7).fetch_add(1, Ordering::SeqCst);
                    }
                    Err(errno) => {
                        assert_eq!(errno, Errno::ESRCH);
                        break 'spin SEEN_BY_READ;
                    }
                }
                match child.died_into_exit_stop_before_resume() {
                    Some(TraceError::Died(_)) => break 'spin SEEN_BY_PROBE,
                    Some(error) => {
                        eprintln!("kill spin: the exit-stop probe of child {pid} failed: {error}");
                        break 'spin NOT_SEEN;
                    }
                    None => {}
                }
                if over_budget() {
                    eprintln!(
                        "kill spin: the kill of child {pid} was not seen within the CPU budget"
                    );
                    break 'spin NOT_SEEN;
                }
                std::thread::yield_now();
            }
        };
        word(address, 20).store((thread_cpu_ns() - start) as usize, Ordering::SeqCst);
        word(address, 19).store(seen, Ordering::SeqCst);
        seen != NOT_SEEN
    }

    fn typed_error(mode: u8) -> bool {
        matches!(mode, TOOL_AFTER_KILL | IO_AFTER_KILL)
    }
    #[derive(Debug, thiserror::Error)]
    #[error("received non-clone cause {0}")]
    struct ReceivedCause(Box<usize>);

    fn kills_child(mode: u8) -> bool {
        matches!(
            mode,
            PARENT_KILL
                | FORGED_KILL
                | INDEPENDENT_AFTER_KILL
                | TOOL_AFTER_KILL
                | IO_AFTER_KILL
                | UNRETURNED_ERRNO
                | CANCEL_PENDING
                | LATE_FAILURE
                | OWNED_DAEMON
                | TIMER_QUERY_KILL
                | EXIT_STOP_KILL
        )
    }
    fn live_error(mode: u8) -> bool {
        matches!(mode, LIVE_ERROR | FORGED_LIVE)
    }

    async fn hold_forged_sigtrap<G: Guest<ParentTool>>(
        guest: &mut G,
        address: usize,
    ) -> Result<(), Errno> {
        use reverie::syscalls::AddrMut;
        use reverie::syscalls::Getpid;
        use reverie::syscalls::RtTgsigqueueinfo;
        // Owned shared mapping, disjoint from the fixture's atomic words. The
        // 64-bit Linux siginfo union starts at byte16. Verify the actual libc
        // accessors before submitting these bytes through the guest syscall.
        let info_address = address + 1024;
        assert_eq!(std::mem::size_of::<libc::siginfo_t>(), 128);
        unsafe {
            let info = info_address as *mut libc::siginfo_t;
            std::ptr::write_bytes(info, 0, 1);
            (*info).si_signo = libc::SIGTRAP;
            (*info).si_code = (libc::PTRACE_EVENT_EXIT << 8) | libc::SIGTRAP;
            info.cast::<i32>().add(4).write(guest.tid().as_raw());
            info.cast::<u32>().add(5).write(libc::getuid());
            assert_eq!((*info).si_pid(), guest.tid().as_raw());
            assert_eq!((*info).si_uid(), libc::getuid());
        }
        let queued = guest
            .inject(
                RtTgsigqueueinfo::new()
                    .with_tgid(guest.pid().as_raw())
                    .with_tid(guest.tid().as_raw())
                    .with_sig(libc::SIGTRAP)
                    .with_siginfo(AddrMut::from_raw(info_address)),
            )
            .await?;
        word(address, 13).store((queued + 1) as usize, Ordering::SeqCst);
        // Only the fields are kept: from libc 0.2.190 a `siginfo_t` is not
        // `Send`, so none may be alive at an `.await`.
        let fields =
            |info: libc::siginfo_t| (info.si_signo, info.si_code, unsafe { info.si_pid() });
        let (mut signo, mut code, mut pid) = nix::sys::ptrace::getsiginfo(guest.tid().into())
            .map(fields)
            .map_err(|error| Errno::new(error as i32))?;
        eprintln!("forged callback first injection: queued={queued}, signo={signo}, code={code}");
        if code != (libc::PTRACE_EVENT_EXIT << 8) | libc::SIGTRAP {
            // At most one additional legal injection; no raw resume, step,
            // SETSIGINFO, second waiter, timing retry or replacement capability.
            let result = guest.inject(Getpid::new()).await?;
            word(address, 14).store(result as usize, Ordering::SeqCst);
            (signo, code, pid) = nix::sys::ptrace::getsiginfo(guest.tid().into())
                .map(fields)
                .map_err(|error| Errno::new(error as i32))?;
            eprintln!(
                "forged callback second injection: result={result}, signo={signo}, code={code}"
            );
        }
        word(address, 11).store(code as usize, Ordering::SeqCst);
        word(address, 12).store(signo as usize, Ordering::SeqCst);
        assert_eq!(queued, 0, "self-queued guest syscall did not succeed");
        assert_eq!(signo, libc::SIGTRAP);
        assert_eq!(
            code,
            (libc::PTRACE_EVENT_EXIT << 8) | libc::SIGTRAP,
            "finite legal Guest injection did not expose the forged stop"
        );
        assert_eq!(pid, guest.tid().as_raw());
        Ok(())
    }
    type Entries = Vec<(u8, Pid, Option<ExitStatus>)>;

    #[derive(Default)]
    struct ParentLog(Arc<StdMutex<Entries>>);

    #[reverie::global_tool]
    impl GlobalTool for ParentLog {
        type Config = (u8, usize, i32);
        type Request = (u8, Pid, Option<ExitStatus>);
        type Response = ();
        async fn receive_rpc(&self, _from: Pid, event: Self::Request) {
            self.0.lock().unwrap().push(event);
        }
    }

    fn word(address: usize, index: usize) -> &'static std::sync::atomic::AtomicUsize {
        // The fixture owns the shared mapping through original completion and
        // any separately reported rescue. No guest-supplied pointer is used.
        unsafe { &*(address as *const std::sync::atomic::AtomicUsize).add(index) }
    }

    #[derive(Default)]
    struct ParentTool;

    #[reverie::tool]
    impl Tool for ParentTool {
        type GlobalState = ParentLog;
        type ThreadState = ();

        fn subscriptions(config: &(u8, usize, i32)) -> Subscription {
            // Parent kill/wait/yield execute natively while this ptracer thread
            // is polling the child's callback. No syscall RPC can serialize
            // the parent behind that same callback.
            if typed_error(config.0) || config.0 == TIMER_QUERY_KILL {
                [Sysno::getpgid].into_iter().collect()
            } else {
                Subscription::none()
            }
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
            Ok(())
        }

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            syscall: Syscall,
        ) -> Result<i64, Error> {
            let (mode, address, _) = *guest.config();
            assert!(matches!(syscall, Syscall::Getpgid(_)));
            if mode == TIMER_QUERY_KILL {
                let result = guest.inject(syscall).await?;
                guest.set_timer_precise(reverie::TimerSchedule::Rcbs(1))?;
                return Ok(result);
            }
            assert!(typed_error(mode));
            let location = Addr::<usize>::from_raw(address).unwrap();
            assert_eq!(guest.memory().read_value(location)?, MAGIC);
            word(address, 7).fetch_add(1, Ordering::SeqCst);
            word(address, 2).store(1, Ordering::SeqCst);
            let seen = spin_until_killed(&held_stop(guest.tid()), address, false, || {
                guest.memory().read_value(location)
            });
            if !seen {
                // Reported to the fixture (word 19); not an observed kill.
                return Err(Errno::ETIMEDOUT.into());
            }
            // Both ways of seeing the death give ESRCH: the failed read's
            // errno, and the errno of safeptrace's `Died`.
            word(address, 8).store(libc::ESRCH as usize, Ordering::SeqCst);
            word(address, 16).store(1, Ordering::SeqCst);
            if mode == TOOL_AFTER_KILL {
                Err(Error::Tool(anyhow::Error::new(ReceivedCause(Box::new(
                    MAGIC,
                )))))
            } else {
                let error = std::fs::File::open("/proc/self/fd/-1")
                    .expect_err("actual invalid proc fd must fail");
                assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
                Err(Error::Io(error))
            }
        }

        async fn handle_signal_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            signal: Signal,
        ) -> Result<Option<Signal>, Errno> {
            if signal != Signal::SIGUSR1 {
                assert_eq!(signal, Signal::SIGCHLD);
                return Ok(None);
            }
            let (mode, address, dead_fd) = *guest.config();
            assert_eq!(
                guest.pid().as_raw() as usize,
                word(address, 1).load(Ordering::SeqCst)
            );
            assert_eq!(word(address, 6).load(Ordering::SeqCst), 1);
            let location = Addr::<usize>::from_raw(address).unwrap();
            assert_eq!(guest.memory().read_value(location)?, MAGIC);
            word(address, 7).fetch_add(1, Ordering::SeqCst);
            if matches!(mode, FORGED_LIVE | FORGED_KILL) {
                hold_forged_sigtrap(guest, address).await?;
            }
            if mode == OWNED_DAEMON {
                guest.daemonize().await;
                // Invoke the real generation-bound daemon signalling primitive
                // directly. This is not a claim to exercise broadcast scheduling.
                OWNED_DAEMON_SESSION
                    .with(|slot| {
                        FATAL_REAP_OBSERVATIONS.with(|owners| {
                            let owners = owners.borrow();
                            let owner = owners
                                .as_ref()
                                .unwrap()
                                .iter()
                                .find(|owner| owner.tid == guest.tid())
                                .expect("original registered callback generation");
                            slot.borrow()
                                .as_ref()
                                .unwrap()
                                .owned_daemon_signal(&owner.terminal)
                        })
                    })
                    .unwrap();
                word(address, 9).store(1, Ordering::SeqCst);
            }
            // No await, second waiter, or callback yield occurs from release
            // through the actual failing operation and returned errno.
            word(address, 2).store(1, Ordering::SeqCst);
            match mode {
                PARENT_KILL
                | FORGED_KILL
                | INDEPENDENT_AFTER_KILL
                | UNRETURNED_ERRNO
                | CANCEL_PENDING
                | LATE_FAILURE
                | OWNED_DAEMON
                | EXIT_STOP_KILL => {
                    // The capability is a temporary: none is held across the
                    // await below.
                    let hold = mode == EXIT_STOP_KILL;
                    let seen = spin_until_killed(&held_stop(guest.tid()), address, hold, || {
                        guest.memory().read_value(location)
                    });
                    if !seen {
                        // Reported to the fixture (word 19); not an observed
                        // kill.
                        return Err(Errno::ETIMEDOUT);
                    }
                    // Both ways of seeing the death give ESRCH: the failed
                    // read's errno, and the errno of safeptrace's `Died`.
                    let errno = Errno::ESRCH;
                    let returned = if mode == INDEPENDENT_AFTER_KILL {
                        let result = unsafe {
                            libc::syscall(
                                libc::SYS_pidfd_send_signal,
                                dead_fd,
                                0,
                                std::ptr::null::<libc::siginfo_t>(),
                                0,
                            )
                        };
                        let independent = Errno::last();
                        assert_eq!(result, -1);
                        assert_eq!(independent, Errno::ESRCH);
                        word(address, 15).store(1, Ordering::SeqCst);
                        independent
                    } else {
                        errno
                    };
                    word(address, 8).store(returned.into_raw() as usize, Ordering::SeqCst);
                    if mode == UNRETURNED_ERRNO {
                        word(address, 16).store(1, Ordering::SeqCst);
                        future::pending::<()>().await;
                        word(address, 17).store(1, Ordering::SeqCst);
                    }
                    Err(returned)
                }
                LIVE_ERROR | FORGED_LIVE => {
                    let ret = unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            dead_fd,
                            0,
                            std::ptr::null::<libc::siginfo_t>(),
                            0,
                        )
                    };
                    let errno = Errno::last();
                    assert_eq!(ret, -1);
                    assert_eq!(errno, Errno::ESRCH);
                    // The stopped child still supports the same memory read:
                    // this ESRCH belongs to the Tool's independent operation.
                    assert_eq!(guest.memory().read_value(location)?, MAGIC);
                    word(address, 7).fetch_add(1, Ordering::SeqCst);
                    word(address, 8).store(errno.into_raw() as usize, Ordering::SeqCst);
                    Err(errno)
                }
                SUCCESS => Ok(None),
                _ => unreachable!(),
            }
        }

        async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
            &self,
            tid: Pid,
            global: &G,
            _: (),
            status: ExitStatus,
        ) -> Result<(), Error> {
            global.send_rpc((1, tid, Some(status))).await;
            Ok(())
        }

        async fn on_exit_process<G: reverie::GlobalRPC<Self::GlobalState>>(
            self,
            pid: Pid,
            global: &G,
            status: ExitStatus,
        ) -> Result<(), Error> {
            global.send_rpc((2, pid, Some(status))).await;
            Ok(())
        }
    }

    async fn control(mode: u8) {
        let started = Instant::now();
        let deadline = fatal_monotonic_ns() + GENEROUS_WALL_BACKSTOP_NS;
        let _registered = RegisteredTasksScope::new();
        let _observations =
            matches!(mode, TIMER_QUERY_KILL | OWNED_DAEMON).then(FatalReapObservationScope::new);
        let helper = fatal_callback_tests::dead_helper(started + GENEROUS_WALL_BACKSTOP).await;
        let words = FatalWords::new();
        let address = words.0 as usize;
        word(address, 0).store(MAGIC, Ordering::SeqCst);
        let sentinel_child = fork_paused_child(Instant::now() + fatal_remaining(deadline));
        let sentinel = sentinel_child.pid();
        let sentinel_identity = untraced_process_identity(sentinel);
        let query_log = Arc::new(StdMutex::new(Vec::new()));
        if mode == TIMER_QUERY_KILL {
            crate::timer::CONTROLLER_QUERY_LOG
                .with(|slot| *slot.borrow_mut() = Some(query_log.clone()));
            crate::timer::CONTROLLER_QUERY_EDGE.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |stopped| {
                    assert_eq!(
                        stopped.pid().as_raw() as usize,
                        word(address, 1).load(Ordering::SeqCst)
                    );
                    let location = address as *mut libc::c_void;
                    assert_eq!(
                        nix::sys::ptrace::read(stopped.pid().into(), location).unwrap() as usize,
                        MAGIC
                    );
                    word(address, 7).fetch_add(1, Ordering::SeqCst);
                    word(address, 2).store(1, Ordering::SeqCst);
                    let read = || {
                        nix::sys::ptrace::read(stopped.pid().into(), location)
                            .map(|value| value as usize)
                            .map_err(|errno| Errno::new(errno as i32))
                    };
                    // On a spin that did not see the kill, word 8 stays 0 and
                    // word 19 says why.
                    if spin_until_killed(stopped, address, false, read) {
                        word(address, 8).store(libc::ESRCH as usize, Ordering::SeqCst);
                    }
                    // No resume or second wait: the next operation is the
                    // actual production namespace metadata query.
                }));
            });
        }
        let tracer = tokio::time::timeout(
            fatal_remaining(deadline),
            spawn_fn_with_config::<ParentTool, _>(
                move || {
                    let child = unsafe { libc::fork() };
                    assert!(child >= 0);
                    if child == 0 {
                        word(address, 1)
                            .store(unsafe { libc::getpid() } as usize, Ordering::SeqCst);
                        while word(address, 6).load(Ordering::SeqCst) == 0 {
                            unsafe {
                                libc::sched_yield();
                            }
                        }
                        if typed_error(mode) || mode == TIMER_QUERY_KILL {
                            unsafe {
                                libc::syscall(libc::SYS_getpgid, 0);
                            }
                        } else {
                            assert_eq!(unsafe { libc::raise(libc::SIGUSR1) }, 0);
                        }
                        word(address, 5).store(1, Ordering::SeqCst);
                        unsafe {
                            libc::_exit(7);
                        }
                    }
                    word(address, 6).store(1, Ordering::SeqCst);
                    while word(address, 2).load(Ordering::SeqCst) == 0 {
                        unsafe {
                            libc::sched_yield();
                        }
                    }
                    if kills_child(mode) && mode != OWNED_DAEMON {
                        let ret = unsafe { libc::kill(child, libc::SIGKILL) };
                        word(address, 9).store((ret + 1) as usize, Ordering::SeqCst);
                        assert_eq!(ret, 0);
                    }
                    let mut status = 0;
                    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
                    word(address, 4).store(status as usize, Ordering::SeqCst);
                    word(address, 3).store(1, Ordering::SeqCst);
                    let bytes = b"parent-survived";
                    assert_eq!(
                        unsafe { libc::write(1, bytes.as_ptr().cast(), bytes.len()) },
                        bytes.len() as isize
                    );
                    if mode == LATE_FAILURE {
                        word(address, 18).store(1, Ordering::SeqCst);
                        loop {
                            unsafe {
                                libc::pause();
                            }
                        }
                    }
                },
                (mode, address, helper.as_raw_fd()),
                true,
            ),
        )
        .await
        .expect("parent-kill spawn exceeded original deadline")
        .unwrap();
        let root = tracer.guest_pid();
        let identity = untraced_process_identity(root);
        let termination = tracer.termination_handle().unwrap();
        let log = tracer.gref.0.clone();
        let session = tracer.ordinary_session.clone();
        OWNED_DAEMON_SESSION
            .with(|slot| *slot.borrow_mut() = (mode == OWNED_DAEMON).then(|| session.clone()));
        let pause = matches!(mode, CANCEL_PENDING | LATE_FAILURE).then(|| {
            Arc::new(CallbackExitPause {
                after_receipt: mode == LATE_FAILURE,
                ..CallbackExitPause::default()
            })
        });
        CALLBACK_EXIT_PAUSE.with(|slot| *slot.borrow_mut() = pause.clone());
        let mut completion = Box::pin(tracer.wait_with_output_completion());
        let result = if let Some(pause) = &pause {
            tokio::time::timeout(fatal_remaining(deadline), async {
                while !pause.entered.load(Ordering::SeqCst) {
                    tokio::select! {
                        outcome = &mut completion => {
                            let kind = match &outcome {
                                ToolRunOutcome::Complete(done) => format!("Complete({:?})", done.result),
                                ToolRunOutcome::CleanupPending(pending) => format!("Pending({:?})", pending.failure()),
                                ToolRunOutcome::UnsupportedBackend(_) => "Unsupported".to_owned(),
                            };
                            panic!("original EXIT owner was not retained: {kind}");
                        },
                        () = pause.changed.notified() => {}
                    }
                }
                if mode == LATE_FAILURE {
                    assert_eq!(*pause.received.lock().unwrap(), Some((Pid::from_raw(words.read(1) as i32), ExitStatus::Signaled(Signal::SIGKILL, false))));
                    // Parent proves actual waitpid delivery and writes its full
                    // prefix before the distinct supervisor failure is published.
                    while words.read(18) == 0 {
                        tokio::select! {
                            _ = &mut completion => panic!("held terminal result falsely completed"),
                            () = tokio::task::yield_now() => {}
                        }
                    }
                    assert_eq!(words.read(3), 1); assert_eq!(words.read(4), libc::SIGKILL as usize);
                    eprintln!("actual terminal result held before late failure: received={:?}, parent_wait={}, parent_prefix_written={}", pause.received.lock().unwrap(), words.read(4), words.read(18));
                }
                let before = session.callback_diagnostics();
                assert_eq!(before.len(), 1);
                assert_eq!(before[0].decision(), crate::PtraceCallbackDecision::AwaitingOwner);
                assert_eq!(before[0].owner_outcome(), None);
                assert_eq!(before[0].errno(), Errno::ESRCH);
                assert!(termination.terminate(Error::Tool(anyhow::Error::new(TestDeadline))));
                let ToolRunOutcome::CleanupPending(pending) = (&mut completion).await else {
                    panic!("held original EXIT capability was falsely completed");
                };
                let retained = pending.callback_diagnostics();
                assert_eq!(retained.len(), 1);
                assert_eq!(retained[0].origin(), before[0].origin());
                assert_eq!(retained[0].errno(), before[0].errno());
                assert_eq!(retained[0].owner_outcome(), None);
                assert!(matches!(pending.failure().primary(), Error::Tool(error) if error.downcast_ref::<TestDeadline>().is_some()));
                assert_eq!(pending.failure().origin().phase, "ptrace supervisor termination");
                eprintln!("callback pending before release: diagnostics={retained:?}, elapsed={:?}", started.elapsed());
                pause.released.store(true, Ordering::SeqCst);
                pause.changed.notify_waiters();
                pending.resume_cleanup().await
            }).await
        } else {
            tokio::time::timeout(fatal_remaining(deadline), &mut completion).await
        };
        CALLBACK_EXIT_PAUSE.with(|slot| *slot.borrow_mut() = None);
        OWNED_DAEMON_SESSION.with(|slot| *slot.borrow_mut() = None);
        crate::timer::CONTROLLER_QUERY_EDGE.with(|slot| *slot.borrow_mut() = None);
        crate::timer::CONTROLLER_QUERY_LOG.with(|slot| *slot.borrow_mut() = None);
        if let Some(pause) = &pause {
            pause.released.store(true, Ordering::SeqCst);
            pause.changed.notify_waiters();
        }
        let child = Pid::from_raw(words.read(1) as i32);
        let events = log.lock().unwrap().clone();
        let root_retired = !identity.same_process();
        let snapshot: Vec<_> = (0..21).map(|index| words.read(index)).collect();
        let description = match &result {
            Ok(ToolRunOutcome::Complete(done)) => format!(
                "Complete({:?}), diagnostics={:?}",
                done.result,
                done.callback_diagnostics()
            ),
            Ok(ToolRunOutcome::CleanupPending(pending)) => {
                format!("Pending({:?})", pending.failure())
            }
            Ok(ToolRunOutcome::UnsupportedBackend(_)) => "Unsupported".to_owned(),
            Err(error) => format!("Timeout({error})"),
        };
        let sentinel_untouched = sentinel_identity.same_process()
            && unsafe { libc::waitpid(sentinel.as_raw(), std::ptr::null_mut(), libc::WNOHANG) }
                == 0;
        let physical_readback = (mode == TIMER_QUERY_KILL).then(fatal_reap_readback);
        eprintln!(
            "parent-kill original predicate: mode={mode}, root={root}, child={child}, root_retired={root_retired}, sentinel_untouched={sentinel_untouched}, shared={snapshot:?}, elapsed={:?}, events={events:?}, outcome={description}",
            started.elapsed()
        );
        if mode == TIMER_QUERY_KILL {
            eprintln!(
                "timer query-edge actual metadata: {:?}",
                query_log.lock().unwrap()
            );
            eprintln!("timer query-edge owner readback: {physical_readback:?}");
        }
        // Retire only our unrelated direct child, after sealing the predicate.
        sentinel_identity.send_signal(Signal::SIGKILL).unwrap();
        let rescue_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let reaped =
                unsafe { libc::waitpid(sentinel.as_raw(), std::ptr::null_mut(), libc::WNOHANG) };
            if reaped == sentinel.as_raw() {
                break;
            }
            assert_eq!(reaped, 0);
            assert!(
                Instant::now() < rescue_deadline,
                "sentinel teardown exceeded separate bound"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let completed = match result {
            Ok(ToolRunOutcome::Complete(done)) => done,
            other => {
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
                    _ => panic!("ordinary fixture entered unsupported route"),
                };
                eprintln!(
                    "parent-kill rescue only: signal={signal:?}, complete={}",
                    matches!(rescued, Ok(ToolRunOutcome::Complete(_)))
                );
                panic!("original parent-kill completion predicate failed: {description}");
            }
        };
        // Every killing mode runs one kill spin, and only those do.
        if kills_child(mode) {
            assert!(
                matches!(snapshot[19], SEEN_BY_READ | SEEN_BY_PROBE),
                "the kill spin did not see the parent's SIGKILL of the child: shared={snapshot:?}"
            );
        } else {
            assert_eq!(snapshot[19], 0);
        }
        if mode == EXIT_STOP_KILL {
            // The hold let the ESRCH window pass: only the probe can see it.
            assert_eq!(
                snapshot[19], SEEN_BY_PROBE,
                "the held spin did not see the kill at the child's exit stop"
            );
        }
        assert!(root_retired && sentinel_untouched);
        assert!(started.elapsed() < GENEROUS_WALL_BACKSTOP);
        assert_eq!(events.iter().filter(|event| event.0 == 0).count(), 2);
        assert_eq!(events.iter().filter(|event| event.0 == 1).count(), 2);
        assert_eq!(events.iter().filter(|event| event.0 == 2).count(), 2);
        if mode == UNRETURNED_ERRNO {
            assert_eq!(snapshot[16], 1);
            assert_eq!(snapshot[17], 0);
        }
        let diagnostics = completed.callback_diagnostics();
        if mode == SUCCESS
            || mode == UNRETURNED_ERRNO
            || mode == TIMER_QUERY_KILL
            || typed_error(mode)
        {
            assert!(diagnostics.is_empty());
        } else {
            assert_eq!(diagnostics.len(), 1);
            let diagnostic = &diagnostics[0];
            assert_eq!(diagnostic.origin().tid, child);
            assert_eq!(diagnostic.origin().pid, child);
            assert_eq!(diagnostic.origin().phase, "ptrace signal callback");
            assert_eq!(diagnostic.errno(), Errno::ESRCH);
            assert_eq!(
                diagnostic.owner_outcome(),
                Some(crate::PtraceCallbackOutcome::Exited(ExitStatus::Signaled(
                    Signal::SIGKILL,
                    false
                )))
            );
            assert_eq!(
                diagnostic.decision(),
                if mode == CANCEL_PENDING {
                    crate::PtraceCallbackDecision::Cancelled
                } else if kills_child(mode) {
                    crate::PtraceCallbackDecision::AwaitingOwner
                } else {
                    crate::PtraceCallbackDecision::Fatal
                }
            );
            assert_eq!(
                diagnostic.failure_published_at_outcome(),
                live_error(mode) || mode == CANCEL_PENDING
            );
            assert_eq!(
                diagnostic.backend_signalling_at_outcome(),
                live_error(mode) || mode == CANCEL_PENDING || mode == OWNED_DAEMON
            );
            assert!(diagnostic.refusal().is_none());
            if matches!(mode, FORGED_LIVE | FORGED_KILL) {
                assert_eq!(snapshot[11], 1541);
                assert_eq!(snapshot[12], libc::SIGTRAP as usize);
                assert_eq!(snapshot[13], 1);
                assert_eq!(
                    diagnostic.held_stop(),
                    Some(crate::PtraceCallbackStop::Signal(libc::SIGTRAP))
                );
                let sample = diagnostic.sample().unwrap();
                if mode == FORGED_LIVE {
                    assert!(sample.siginfo().unwrap().unwrap().has_exit_signature());
                    assert_eq!(*sample.flags().unwrap().as_ref().unwrap() & 0x400, 0);
                    assert_eq!(sample.pidfd_live(), Some(Ok(true)));
                }
            }
            if mode == INDEPENDENT_AFTER_KILL {
                assert_eq!(snapshot[15], 1);
            }
        }
        if typed_error(mode) || matches!(mode, CANCEL_PENDING | LATE_FAILURE) {
            assert_eq!(snapshot[8], libc::ESRCH as usize);
            assert_eq!(snapshot[9], 1);
            assert_eq!(snapshot[3], usize::from(mode == LATE_FAILURE));
            assert_eq!(snapshot[5], 0);
            let failure = completed
                .result
                .expect_err("received typed cause became guest success");
            if mode == TOOL_AFTER_KILL {
                assert!(
                    matches!(failure.primary(), Error::Tool(error) if error.downcast_ref::<ReceivedCause>().is_some_and(|cause| *cause.0 == MAGIC))
                );
            } else if mode == IO_AFTER_KILL {
                assert!(
                    matches!(failure.primary(), Error::Io(error) if error.raw_os_error() == Some(libc::ENOENT))
                );
            } else {
                assert!(
                    matches!(failure.primary(), Error::Tool(error) if error.downcast_ref::<TestDeadline>().is_some())
                );
            }
            assert_eq!(
                failure.origin().phase,
                if matches!(mode, CANCEL_PENDING | LATE_FAILURE) {
                    "ptrace supervisor termination"
                } else {
                    "ptrace syscall callback"
                }
            );
            assert_eq!(
                failure.origin().tid,
                if matches!(mode, CANCEL_PENDING | LATE_FAILURE) {
                    root
                } else {
                    child
                }
            );
            assert_eq!(
                failure.captured_prefix().unwrap().stdout(),
                if mode == LATE_FAILURE {
                    b"parent-survived".as_slice()
                } else {
                    b"".as_slice()
                }
            );
            assert!(
                events
                    .iter()
                    .filter(|event| event.0 == 1)
                    .all(|event| event.2 == Some(ExitStatus::Signaled(Signal::SIGKILL, false)))
            );
            if typed_error(mode) {
                assert_eq!(snapshot[16], 1);
            }
        } else if live_error(mode) {
            assert_eq!(snapshot[8], libc::ESRCH as usize);
            assert_eq!(snapshot[7], 2);
            assert_eq!(snapshot[3], 0);
            assert_eq!(snapshot[5], 0);
            let failure = completed
                .result
                .expect_err("live Tool ESRCH must remain fatal");
            assert!(matches!(failure.primary(), Error::Errno(Errno::ESRCH)));
            assert_eq!(failure.origin().tid, child);
            assert_eq!(failure.origin().phase, "ptrace signal callback");
            assert!(failure.captured_prefix().unwrap().stdout().is_empty());
            assert!(
                events
                    .iter()
                    .filter(|event| event.0 == 1)
                    .all(|event| event.2 == Some(ExitStatus::Signaled(Signal::SIGKILL, false)))
            );
        } else {
            if kills_child(mode) {
                if mode == OWNED_DAEMON {
                    assert_eq!(snapshot[9], 1, "generation-bound daemon signalling failed");
                } else {
                    assert_eq!(
                        snapshot[9], 1,
                        "guest parent did not execute successful kill"
                    );
                }
                assert_eq!(
                    snapshot[8],
                    libc::ESRCH as usize,
                    "child memory operation did not report actual ESRCH"
                );
                assert!(snapshot[7] >= 1);
                assert_eq!(snapshot[5], 0);
                assert_eq!(
                    snapshot[4],
                    libc::SIGKILL as usize,
                    "parent did not observe actual waitpid SIGKILL"
                );
            } else {
                assert_eq!(snapshot[8], 0);
                assert_eq!(snapshot[5], 1);
                assert_eq!(snapshot[4], 7 << 8);
            }
            assert_eq!(
                snapshot[3], 1,
                "guest parent was killed before observing its child's status"
            );
            let output = completed
                .result
                .expect("guest child death must not kill its healthy parent");
            assert_eq!(output.status, ExitStatus::Exited(0));
            assert_eq!(output.stdout, b"parent-survived");
            assert!(output.stderr.is_empty());
            assert!(!Path::new(&format!("/proc/{child}")).exists());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn guest_parent_kill_at_timer_namespace_query_preserves_parent() {
        control(TIMER_QUERY_KILL).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn owned_daemon_signal_preserves_parent_and_marks_diagnostic() {
        control(OWNED_DAEMON).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn later_supervisor_failure_does_not_relabel_an_already_received_child_status() {
        control(LATE_FAILURE).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn received_nonclone_tool_error_after_child_kill_remains_primary() {
        control(TOOL_AFTER_KILL).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn received_real_io_error_after_child_kill_remains_primary() {
        control(IO_AFTER_KILL).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn suspended_callback_errno_is_not_an_observed_return() {
        control(UNRETURNED_ERRNO).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn parked_callback_diagnostic_and_exit_owner_survive_pending_cancellation() {
        control(CANCEL_PENDING).await;
    }

    #[cfg(target_arch = "x86_64")]
    #[tokio::test(flavor = "current_thread")]
    async fn legal_injection_live_forged_exit_siginfo_remains_fatal() {
        control(FORGED_LIVE).await;
    }
    #[cfg(target_arch = "x86_64")]
    #[tokio::test(flavor = "current_thread")]
    async fn legal_injection_forged_stop_parent_kill_preserves_parent() {
        control(FORGED_KILL).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn observed_independent_errno_after_parent_kill_retains_death_precedence() {
        control(INDEPENDENT_AFTER_KILL).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn guest_parent_kill_during_child_memory_callback_preserves_parent() {
        control(PARENT_KILL).await;
    }
    /// The spin reads the child only once it is in its PTRACE_EVENT_EXIT
    /// stop, where reads succeed again: the order a preempted tracer thread
    /// meets by chance. The kill must still be seen, and the parent kept.
    /// See <https://github.com/rrnewton/hermit/issues/3357>.
    #[tokio::test(flavor = "current_thread")]
    async fn guest_parent_kill_seen_at_child_exit_stop_preserves_parent() {
        control(EXIT_STOP_KILL).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn live_child_independent_esrch_remains_fatal() {
        control(LIVE_ERROR).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn normal_child_signal_and_parent_wait_succeed() {
        control(SUCCESS).await;
    }
}
