/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod fatal_callback_tests {
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;
    use std::sync::atomic::AtomicUsize;

    use serde::Deserialize;
    use serde::Serialize;

    use super::*;

    const MARKER: &[u8] = b"callback-resumed\n";
    #[cfg(target_arch = "x86_64")]
    const TSC_VALUE: u64 = 0x1122_3344_5566_7788;
    #[cfg(target_arch = "x86_64")]
    const TSC_AUX: u32 = 0x1234_5678;

    #[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
    enum Callback {
        #[default]
        Signal,
        PostExec,
        #[cfg(target_arch = "x86_64")]
        Cpuid,
        #[cfg(target_arch = "x86_64")]
        Rdtsc,
        #[cfg(target_arch = "x86_64")]
        Rdtscp,
        GuestErrno,
        StartupErrno,
    }

    impl Callback {
        fn phase(self) -> &'static str {
            match self {
                Self::Signal => "ptrace signal callback",
                Self::PostExec => "ptrace post-exec callback",
                #[cfg(target_arch = "x86_64")]
                Self::Cpuid => "ptrace cpuid callback",
                #[cfg(target_arch = "x86_64")]
                Self::Rdtsc | Self::Rdtscp => "ptrace rdtsc callback",
                Self::GuestErrno | Self::StartupErrno => {
                    panic!("legacy errno companions must not produce run failures")
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
    struct Config {
        callback: Callback,
        fail: bool,
        dead_pidfd: i32,
    }

    impl Config {
        fn fatal(self) -> bool {
            self.fail && !matches!(self.callback, Callback::GuestErrno | Callback::StartupErrno)
        }
    }

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    enum Observation {
        Start(Pid),
        Callback {
            callback: Callback,
            tid: Pid,
            ret: i64,
            errno: Option<i32>,
        },
        ExitThread(Pid, ExitStatus),
        CleanupError(Pid, i64, i32),
        ExitProcess(Pid, ExitStatus, usize),
    }

    #[derive(Default)]
    struct Log(Arc<StdMutex<Vec<Observation>>>);

    #[reverie::global_tool]
    impl GlobalTool for Log {
        type Config = Config;
        type Request = Observation;
        type Response = ();

        async fn receive_rpc(&self, _from: Pid, observation: Observation) {
            self.0.lock().unwrap().push(observation);
        }
    }

    #[derive(Default)]
    struct CallbackTool {
        config: Config,
        constructed: AtomicUsize,
    }

    impl CallbackTool {
        async fn operation<G: Guest<Self>>(
            &self,
            guest: &G,
            callback: Callback,
        ) -> Result<(), Errno> {
            assert_eq!(self.config.callback, callback);
            // This descriptor still belongs to this fixture, but its actual
            // child exited and was reaped before the tracee was created. ESRCH
            // here says nothing about the callback's live, stopped tracee.
            let ret = if self.config.fail {
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        self.config.dead_pidfd,
                        0,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                }
            } else {
                unsafe { libc::fcntl(self.config.dead_pidfd, libc::F_GETFD) as libc::c_long }
            };
            let errno = (ret == -1).then(Errno::last);
            guest
                .send_rpc(Observation::Callback {
                    callback,
                    tid: guest.tid(),
                    ret,
                    errno: errno.map(Errno::into_raw),
                })
                .await;
            if self.config.fail {
                assert_eq!(ret, -1, "dead owned pidfd unexpectedly accepted signal 0");
                let errno = errno.expect("raw pidfd errno captured immediately");
                assert_eq!(errno, Errno::ESRCH);
                Err(errno)
            } else {
                assert!(ret >= 0, "owned pidfd F_GETFD failed: {errno:?}");
                Ok(())
            }
        }
    }

    #[reverie::tool]
    impl Tool for CallbackTool {
        type GlobalState = Log;
        type ThreadState = i32;

        fn new(_pid: Pid, config: &Config) -> Self {
            Self {
                config: *config,
                constructed: AtomicUsize::new(0),
            }
        }

        fn init_thread_state(
            &self,
            tid: Pid,
            _parent: Option<(Pid, &Self::ThreadState)>,
        ) -> Self::ThreadState {
            self.constructed.fetch_add(1, Ordering::SeqCst);
            tid.as_raw()
        }

        fn subscriptions(config: &Config) -> Subscription {
            let mut events = Subscription::none();
            match config.callback {
                #[cfg(target_arch = "x86_64")]
                Callback::Cpuid => {
                    events.cpuid();
                }
                #[cfg(target_arch = "x86_64")]
                Callback::Rdtsc | Callback::Rdtscp => {
                    events.rdtsc();
                }
                Callback::GuestErrno => {
                    events.syscall(Sysno::getpgid);
                }
                _ => {}
            }
            events
        }

        async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
            guest.send_rpc(Observation::Start(guest.tid())).await;
            if self.config.callback == Callback::StartupErrno {
                self.operation(guest, Callback::StartupErrno).await?;
            }
            Ok(())
        }

        async fn handle_signal_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            signal: Signal,
        ) -> Result<Option<Signal>, Errno> {
            assert_eq!(signal, Signal::SIGUSR1, "unexpected guest signal");
            self.operation(guest, Callback::Signal).await?;
            Ok(None)
        }

        async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
            self.operation(guest, Callback::PostExec).await
        }

        #[cfg(target_arch = "x86_64")]
        async fn handle_cpuid_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            eax: u32,
            ecx: u32,
        ) -> Result<raw_cpuid::CpuIdResult, Errno> {
            assert_eq!((eax, ecx), (0x4000_00ff, 0x2a));
            self.operation(guest, Callback::Cpuid).await?;
            Ok(raw_cpuid::CpuIdResult {
                eax: 11,
                ebx: 22,
                ecx: 33,
                edx: 44,
            })
        }

        #[cfg(target_arch = "x86_64")]
        async fn handle_rdtsc_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            request: reverie::Rdtsc,
        ) -> Result<reverie::RdtscResult, Errno> {
            let callback = match request {
                reverie::Rdtsc::Tsc => Callback::Rdtsc,
                reverie::Rdtsc::Tscp => Callback::Rdtscp,
            };
            self.operation(guest, callback).await?;
            Ok(reverie::RdtscResult {
                tsc: TSC_VALUE,
                aux: (request == reverie::Rdtsc::Tscp).then_some(TSC_AUX),
            })
        }

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            syscall: Syscall,
        ) -> Result<i64, Error> {
            assert_eq!(self.config.callback, Callback::GuestErrno);
            assert_eq!(syscall.number(), Sysno::getpgid);
            let result = guest.inject(syscall).await;
            guest
                .send_rpc(Observation::Callback {
                    callback: Callback::GuestErrno,
                    tid: guest.tid(),
                    ret: result.unwrap_or(-1),
                    errno: result.err().map(Errno::into_raw),
                })
                .await;
            assert_eq!(result, Err(Errno::ESRCH));
            result.map_err(Error::from)
        }

        async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
            &self,
            tid: Pid,
            global: &G,
            state: Self::ThreadState,
            status: ExitStatus,
        ) -> Result<(), Error> {
            assert_eq!(state, tid.as_raw(), "consume the actual constructed state");
            global.send_rpc(Observation::ExitThread(tid, status)).await;
            if self.config.fatal() {
                let ret = unsafe { libc::fcntl(-1, libc::F_GETFD) };
                let errno = Errno::last();
                global
                    .send_rpc(Observation::CleanupError(tid, ret.into(), errno.into_raw()))
                    .await;
                assert_eq!(ret, -1);
                assert_eq!(errno, Errno::EBADF);
                return Err(errno.into());
            }
            Ok(())
        }

        async fn on_exit_process<G: reverie::GlobalRPC<Self::GlobalState>>(
            self,
            pid: Pid,
            global: &G,
            status: ExitStatus,
        ) -> Result<(), Error> {
            global
                .send_rpc(Observation::ExitProcess(
                    pid,
                    status,
                    self.constructed.load(Ordering::SeqCst),
                ))
                .await;
            Ok(())
        }
    }

    pub(super) async fn dead_helper(deadline: Instant) -> OwnedFd {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "helper fork: {}", Errno::last());
        if pid == 0 {
            unsafe { libc::_exit(7) }
        }
        // The unreaped child identity is still ours even if it already exited.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0, "helper pidfd_open: {}", Errno::last());
        let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let mut status = 0;
        loop {
            let ret = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            let errno = (ret == -1).then(Errno::last);
            if ret == pid {
                eprintln!(
                    "callback helper: pid={pid}, fd={}, wait={ret}, raw_status={status}",
                    fd.as_raw_fd()
                );
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), 7);
                return fd;
            }
            assert_eq!(ret, 0, "helper wait failed: {errno:?}");
            if Instant::now() >= deadline {
                eprintln!(
                    "callback helper deadline: pid={pid}, last_wait={ret}, raw_status={status}"
                );
                let signal = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                };
                let signal_errno = (signal == -1).then(Errno::last);
                let rescue_deadline = Instant::now() + Duration::from_secs(2);
                let rescue = loop {
                    let ret = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                    if ret != 0 || Instant::now() >= rescue_deadline {
                        break ret;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                };
                panic!(
                    "helper exceeded original deadline; rescue only: signal={signal}, errno={signal_errno:?}, wait={rescue}, raw_status={status}"
                );
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    fn guest_body(callback: Callback, address: usize) {
        // Record continuation before validating any returned value. A broken
        // backend must not hide resumption behind a failing guest assertion.
        let resumed = || {
            unsafe { &*(address as *const AtomicUsize) }.store(1, Ordering::SeqCst);
        };
        match callback {
            Callback::Signal => {
                let ret = unsafe {
                    libc::syscall(
                        libc::SYS_tgkill,
                        libc::getpid(),
                        libc::syscall(libc::SYS_gettid),
                        libc::SIGUSR1,
                    )
                };
                resumed();
                assert_eq!(ret, 0);
            }
            Callback::PostExec => unsafe {
                let args = [
                    c"sh".as_ptr(),
                    c"-c".as_ptr(),
                    c"printf 'callback-resumed\n'".as_ptr(),
                    std::ptr::null(),
                ];
                libc::execv(c"/bin/sh".as_ptr(), args.as_ptr());
                libc::_exit(91);
            },
            #[cfg(target_arch = "x86_64")]
            Callback::Cpuid => {
                let result = std::arch::x86_64::__cpuid_count(0x4000_00ff, 0x2a);
                resumed();
                assert_eq!(
                    (result.eax, result.ebx, result.ecx, result.edx),
                    (11, 22, 33, 44)
                );
            }
            #[cfg(target_arch = "x86_64")]
            Callback::Rdtsc => {
                let value = unsafe { std::arch::x86_64::_rdtsc() };
                resumed();
                assert_eq!(value, TSC_VALUE);
            }
            #[cfg(target_arch = "x86_64")]
            Callback::Rdtscp => {
                let mut aux = 0;
                let value = unsafe { std::arch::x86_64::__rdtscp(&mut aux) };
                resumed();
                assert_eq!(value, TSC_VALUE);
                assert_eq!(aux, TSC_AUX);
            }
            Callback::GuestErrno => {
                let ret = unsafe { libc::syscall(libc::SYS_getpgid, -1i32) };
                let errno = Errno::last();
                resumed();
                assert_eq!(ret, -1);
                assert_eq!(errno, Errno::ESRCH);
            }
            Callback::StartupErrno => resumed(),
        }
        // This is actual guest progress after the subscribed operation. For
        // post-exec the replacement image writes MARKER instead, since exec
        // correctly discards this guest mapping.
        assert_eq!(
            unsafe { libc::write(1, MARKER.as_ptr().cast(), MARKER.len()) },
            MARKER.len() as isize
        );
        unsafe { libc::_exit(0) }
    }

    fn describe(outcome: &ToolRunOutcome<Log, reverie::process::Output>) -> String {
        match outcome {
            ToolRunOutcome::Complete(completed) => format!("Complete({:?})", completed.result),
            ToolRunOutcome::CleanupPending(pending) => {
                format!("CleanupPending({:?})", pending.failure())
            }
            ToolRunOutcome::UnsupportedBackend(_) => "UnsupportedBackend".to_owned(),
        }
    }

    async fn check_callback(callback: Callback, fail: bool) {
        let started = Instant::now();
        let deadline = started + Duration::from_secs(3);
        let helper = dead_helper(deadline).await;
        let words = FatalWords::new();
        let address = words.0 as usize;
        let config = Config {
            callback,
            fail,
            dead_pidfd: helper.as_raw_fd(),
        };
        let tracer = tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            spawn_fn_with_config::<CallbackTool, _>(
                move || guest_body(callback, address),
                config,
                true,
            ),
        )
        .await
        .expect("callback spawn exceeded the single pre-spawn deadline")
        .expect("spawn callback fixture");
        let root = tracer.guest_pid();
        let identity = untraced_process_identity(root);
        let termination = tracer
            .termination_handle()
            .expect("ordinary termination owner");
        let log = Arc::clone(&tracer.gref.0);
        let mut completion = Box::pin(tracer.wait_with_output_completion());
        let result = tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            &mut completion,
        )
        .await;
        let elapsed = started.elapsed();
        let root_retired = !identity.same_process();
        let after = words.read(0);
        let events = log.lock().unwrap().clone();
        eprintln!(
            "callback result before rescue: callback={callback:?}, fail={fail}, root={root}, retired={root_retired}, after={after}, elapsed={elapsed:?}, events={events:?}, outcome={}",
            result
                .as_ref()
                .map(describe)
                .unwrap_or_else(|error| format!("Timeout({error})"))
        );
        let completed = match result {
            Ok(ToolRunOutcome::Complete(completed)) => completed,
            other => {
                // Rescue retains the original completion/exit owner. It does
                // not create a second wait owner or turn the earlier failure
                // into a passing observation.
                let rescue_deadline = Instant::now() + Duration::from_secs(2);
                termination.terminate(Error::Tool(anyhow::Error::new(TestDeadline)));
                let signal = identity.send_signal(Signal::SIGKILL);
                let rescue = match other {
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
                    "callback rescue only: signal={signal:?}, outcome={}",
                    rescue
                        .as_ref()
                        .map(describe)
                        .unwrap_or_else(|error| format!("Timeout({error})"))
                );
                panic!("callback fixture did not Complete within the original deadline");
            }
        };
        assert!(
            elapsed <= Duration::from_secs(3),
            "completion exceeded the original deadline"
        );
        assert!(root_retired, "root was not retired before rescue");
        assert_reaped("callback fixture root", root);
        assert_eq!(*completed.global_state.0.lock().unwrap(), events);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Observation::Start(..)))
                .collect::<Vec<_>>(),
            vec![&Observation::Start(root)]
        );
        let callbacks: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Observation::Callback {
                    callback,
                    tid,
                    ret,
                    errno,
                } => Some((*callback, *tid, *ret, *errno)),
                _ => None,
            })
            .collect();
        assert_eq!(callbacks.len(), 1, "zero or repeated callbacks: {events:?}");
        let (actual_callback, tid, ret, errno) = callbacks[0];
        assert_eq!((actual_callback, tid), (callback, root));
        if fail || callback == Callback::GuestErrno {
            assert_eq!((ret, errno), (-1, Some(libc::ESRCH)));
        } else {
            assert!(ret >= 0);
            assert_eq!(errno, None);
        }
        let status = if config.fatal() {
            ExitStatus::Signaled(Signal::SIGKILL, false)
        } else {
            ExitStatus::Exited(0)
        };
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Observation::ExitThread(..)))
                .collect::<Vec<_>>(),
            vec![&Observation::ExitThread(root, status)]
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Observation::ExitProcess(..)))
                .collect::<Vec<_>>(),
            vec![&Observation::ExitProcess(root, status, 1)]
        );
        if config.fatal() {
            let failure = completed
                .result
                .expect_err("callback ESRCH became a guest result");
            assert!(matches!(failure.primary(), Error::Errno(error) if *error == Errno::ESRCH));
            assert_eq!(
                failure.origin(),
                reverie::BackendFailure {
                    pid: root,
                    tid: root,
                    phase: callback.phase()
                }
            );
            assert_eq!(
                failure
                    .secondary()
                    .iter()
                    .filter(|error| error.origin()
                        == reverie::BackendFailure {
                            pid: root,
                            tid: root,
                            phase: "ptrace on_exit_thread"
                        }
                        && matches!(error.error(), Error::Errno(errno) if *errno == Errno::EBADF))
                    .count(),
                1,
                "actual cleanup EBADF lost or duplicated: {failure:?}"
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, Observation::CleanupError(..)))
                    .collect::<Vec<_>>(),
                vec![&Observation::CleanupError(root, -1, libc::EBADF)]
            );
            let prefix = failure
                .captured_prefix()
                .expect("requested capture exists even when empty");
            assert_eq!(prefix.stdout(), b"");
            assert_eq!(prefix.stderr(), b"");
            assert_eq!(after, 0, "failed callback resumed guest code");
        } else {
            let output = completed
                .result
                .expect("successful/legacy-errno callback failed the run");
            assert_eq!(output.status, ExitStatus::Exited(0));
            assert_eq!(output.stdout, MARKER);
            assert_eq!(output.stderr, b"");
            assert_eq!(after, usize::from(callback != Callback::PostExec));
            assert!(
                !events
                    .iter()
                    .any(|event| matches!(event, Observation::CleanupError(..)))
            );
        }
        // The original pidfd stays owned through every callback and assertion.
        assert!(unsafe { libc::fcntl(helper.as_raw_fd(), libc::F_GETFD) } >= 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn signal_success_suppresses_usr1_and_resumes_guest() {
        check_callback(Callback::Signal, false).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn signal_real_esrch_preserves_first_cause_and_retires() {
        check_callback(Callback::Signal, true).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn postexec_success_runs_replacement_image() {
        check_callback(Callback::PostExec, false).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn postexec_real_esrch_preserves_first_cause_and_retires() {
        check_callback(Callback::PostExec, true).await;
    }
    #[cfg(target_arch = "x86_64")]
    #[tokio::test(flavor = "current_thread")]
    async fn cpuid_success_returns_registers_and_resumes_guest() {
        check_callback(Callback::Cpuid, false).await;
    }
    #[cfg(target_arch = "x86_64")]
    #[tokio::test(flavor = "current_thread")]
    async fn cpuid_real_esrch_preserves_first_cause_and_retires() {
        check_callback(Callback::Cpuid, true).await;
    }
    #[cfg(target_arch = "x86_64")]
    #[tokio::test(flavor = "current_thread")]
    async fn rdtsc_success_returns_counter_and_resumes_guest() {
        check_callback(Callback::Rdtsc, false).await;
    }
    #[cfg(target_arch = "x86_64")]
    #[tokio::test(flavor = "current_thread")]
    async fn rdtsc_real_esrch_preserves_first_cause_and_retires() {
        check_callback(Callback::Rdtsc, true).await;
    }
    #[cfg(target_arch = "x86_64")]
    #[tokio::test(flavor = "current_thread")]
    async fn rdtscp_success_returns_counter_aux_and_resumes_guest() {
        check_callback(Callback::Rdtscp, false).await;
    }
    #[cfg(target_arch = "x86_64")]
    #[tokio::test(flavor = "current_thread")]
    async fn rdtscp_real_esrch_preserves_first_cause_and_retires() {
        check_callback(Callback::Rdtscp, true).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn guest_syscall_real_esrch_remains_a_guest_errno() {
        check_callback(Callback::GuestErrno, false).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn startup_real_esrch_preserves_swallowed_legacy_behavior() {
        check_callback(Callback::StartupErrno, true).await;
    }
}
