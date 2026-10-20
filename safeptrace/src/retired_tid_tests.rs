/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[cfg(all(not(sanitized), target_arch = "x86_64"))]
mod retired_tid {
    use super::*;

    const NAME: &str = "notifier::test::retired_tid::explicit_unregistered_retired_target_refuses_numeric_requests";
    const INNER: &str = "SAFEPTRACE_RETIRED_TARGET_INNER";
    const FORCE: &str = "SAFEPTRACE_RETIRED_TARGET_FORCE";
    const KEEP_WARM: &str = "SAFEPTRACE_RETIRED_TARGET_KEEP_AUTH_WARM";
    const MARKER: &str = "ACTUAL_EXPLICIT_UNREGISTERED_RETIRED_TARGET_EXERCISED";

    struct FixtureDirectory(std::path::PathBuf);

    impl Drop for FixtureDirectory {
        fn drop(&mut self) {
            // Only the uniquely created directory owned by this invocation.
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> (FixtureDirectory, std::ffi::CString) {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = env::temp_dir().join(format!("safeptrace-retired-{nonce}"));
        fs::create_dir(&directory).unwrap();
        let directory = FixtureDirectory(directory);
        let source = directory.0.join("fixture.c");
        let program = directory.0.join("fixture");
        fs::write(&source, include_bytes!("retired_tid_fixture.c")).unwrap();
        let output = Command::new("cc")
            .args([
                "-std=gnu11",
                "-O2",
                "-pthread",
                "-Wall",
                "-Wextra",
                "-Werror",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&program)
            .output()
            .expect("compile owned syscall fixture with the Linux build prerequisites");
        assert!(
            output.status.success(),
            "owned fixture compiler: {output:?}"
        );
        let program = std::ffi::CString::new(program.as_os_str().as_encoded_bytes()).unwrap();
        (directory, program)
    }

    fn raw_request(request: libc::c_uint, pid: Pid, data: usize) {
        assert_eq!(
            unsafe {
                libc::ptrace(
                    request,
                    pid.as_raw(),
                    std::ptr::null_mut::<libc::c_void>(),
                    data as *mut libc::c_void,
                )
            },
            0,
            "actual owned ptrace request {request} on {pid}: {}",
            Errno::last()
        );
    }

    fn raw_wait(pid: Pid) -> (Pid, i32) {
        let mut status = 0;
        let mut result = 0;
        legacy_owner_until(|| {
            result = unsafe {
                libc::waitpid(
                    pid.as_raw(),
                    &mut status,
                    libc::__WALL | libc::__WNOTHREAD | libc::WNOHANG,
                )
            };
            assert!(result >= 0, "actual owned wait: {}", Errno::last());
            result != 0
        });
        (Pid::from_raw(result), status)
    }

    #[test]
    fn cached_stop_authentication_refuses_actual_retired_tid_reuse() {
        for forced in [false, true] {
            let output = run_exact_in_pid_namespace_bounded(
                NAME,
                &[
                    (INNER, "1"),
                    (FORCE, if forced { "1" } else { "0" }),
                    (KEEP_WARM, "1"),
                ],
            )
            .expect("start real warm-cache exec/exact-reuse control");
            assert!(output.status.success(), "warm cache reuse: {output:?}");
            assert_eq!(
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .filter(|line| *line == "ACTUAL_WARM_AUTH_CACHE_TID_REUSE_REFUSED")
                    .count(),
                1,
                "warm cache control omitted completed physical reuse proof: {output:?}"
            );
        }
        emit_completion_marker("ACTUAL_WARM_AUTH_CACHE_TID_REUSE_REFUSED");
    }

    #[test]
    fn explicit_unregistered_retired_target_refuses_numeric_requests() {
        if env::var_os(INNER).is_none() {
            for forced in [false, true] {
                let output = run_exact_in_pid_namespace_bounded(
                    NAME,
                    &[(INNER, "1"), (FORCE, if forced { "1" } else { "0" })],
                )
                .expect("start real owned exec/exact-reuse control");
                assert!(
                    output.status.success(),
                    "retired target control: {output:?}"
                );
                let stdout = String::from_utf8_lossy(&output.stdout);
                let rows: Vec<_> = stdout
                    .lines()
                    .filter(|line| line.starts_with("RETIRED_EXPLICIT_TARGET_REFUSAL "))
                    .collect();
                assert_eq!(
                    rows.len(),
                    1,
                    "missing actual retirement/reuse cell: {stdout}"
                );
                assert!(rows[0].contains(&format!("forced={forced}")));
                print!("{stdout}");
                eprint!("{}", String::from_utf8_lossy(&output.stderr));
            }
            emit_completion_marker(MARKER);
            return;
        }
        let forced = env::var(FORCE).as_deref() == Ok("1");
        let (_directory, executable) = fixture();
        let [start, release] = legacy_pipe();
        let start_number = std::ffi::CString::new(start.as_raw_fd().to_string()).unwrap();
        let root = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                assert_eq!(
                    unsafe { libc::fcntl(start.as_raw_fd(), libc::F_SETFD, 0) },
                    0
                );
                unsafe {
                    libc::execl(
                        executable.as_ptr(),
                        executable.as_ptr(),
                        c"--guest".as_ptr(),
                        start_number.as_ptr(),
                        std::ptr::null::<libc::c_char>(),
                    );
                    libc::_exit(127);
                }
            }
        };
        drop(start);
        let mut root_cleanup = TraceeCleanupGuard::new(root).unwrap();
        let _force = forced.then(|| LegacyThreadGroup::new(root));
        // Public SEIZE deliberately omits TRACEEXEC. This fixture does not
        // manufacture a new option requirement for interrupt/ptrace calls.
        let options =
            Options::PTRACE_O_TRACECLONE | Options::PTRACE_O_TRACEEXIT | Options::PTRACE_O_EXITKILL;
        let running = Running::seize_on_ptracer_thread(root.into(), options).unwrap();
        assert_eq!(
            unsafe { libc::write(release.as_raw_fd(), b"s".as_ptr().cast(), 1) },
            1
        );
        drop(release);
        let (parent, event) = running
            .wait_sync_on_ptracer_thread()
            .wait()
            .unwrap()
            .assume_stopped();
        let crate::Event::NewChild(crate::ChildOp::Clone, member) = event else {
            panic!("expected the genuine original CLONE event");
        };
        let former = Pid::from(member.pid());
        let (stopped, event) = member
            .wait_sync_on_ptracer_thread()
            .wait()
            .unwrap()
            .assume_stopped();
        assert_eq!(event, crate::Event::Stop);
        let original = stopped.1.event().clone();
        let generation = stopped.generation();
        let owner = stopped.1.ptracer_owner.clone().unwrap();
        let native = stopped
            .terminal_cleanup_on_ptracer_thread()
            .shared()
            .has_thread_pidfd()
            .unwrap();
        if forced {
            assert!(!native);
        }
        assert!(owner.is_current().unwrap());
        assert_eq!(original.current_tracer_pid(), Ok(owner.tid));
        assert_eq!(original.identity().unwrap().pidfd_is_live(), Ok(true));
        assert_eq!(
            original.event().worker_state.load(Ordering::Acquire),
            WORKER_NOT_STARTED
        );
        assert!(!*original.event().terminal_reaping.read());
        let warm_epoch = env::var_os(KEEP_WARM).map(|_| {
            owner.force_directory_proof.store(true, Ordering::Relaxed);
            original
                .event()
                .numeric_auth_force_directory
                .store(true, Ordering::Relaxed);
            // Warm the positive proof through genuine SDK requests at the
            // original consumed newborn stop. A controlled raw resume below
            // deliberately leaves that epoch valid, so the later refusal
            // must come from the fresh original-target inode lookup.
            stopped.getsiginfo().unwrap();
            stopped.getregs().unwrap();
            let epoch = original.event().numeric_auth_epoch.load(Ordering::Acquire);
            assert_eq!(
                original
                    .event()
                    .numeric_auth_checked_epoch
                    .load(Ordering::Acquire),
                epoch
            );
            epoch
        });
        let old_running = if warm_epoch.is_some() {
            raw_request(libc::PTRACE_CONT, former, 0);
            Running::from_token(stopped.0, stopped.1)
        } else {
            stopped.resume(None).unwrap()
        };
        let parent_running = parent.resume(None).unwrap();
        let mut replacement = Pid::from_raw(0);
        let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
        for _ in 0..12 {
            assert!(Instant::now() < deadline);
            // There are no background wait owners: both SDK waits above
            // consumed their actual stops through the synchronous claim.
            let (pid, status) = raw_wait(Pid::from_raw(-1));
            assert!(libc::WIFSTOPPED(status));
            assert_ne!(status >> 16, libc::PTRACE_EVENT_EXEC);
            if pid == root && status >> 16 == libc::PTRACE_EVENT_CLONE {
                let mut child = 0usize;
                raw_request(
                    libc::PTRACE_GETEVENTMSG,
                    root,
                    (&mut child as *mut usize) as usize,
                );
                replacement = Pid::from_raw(child as i32);
                break;
            }
            raw_request(libc::PTRACE_CONT, pid, 0);
        }
        assert_eq!(
            replacement, former,
            "actual clone3 same-group former TID reuse"
        );
        let (pid, newborn) = raw_wait(replacement);
        assert_eq!(pid, replacement);
        assert!(libc::WIFSTOPPED(newborn));
        assert_eq!(newborn >> 16, libc::PTRACE_EVENT_STOP);
        assert_eq!(original.identity().unwrap().pidfd_is_live(), Ok(false));
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    original.identity().unwrap().pidfd.as_raw_fd(),
                    0,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            },
            -1
        );
        assert_eq!(Errno::last(), Errno::ESRCH);
        assert!(matches!(
            original.current_tracer_pid(),
            Err(Errno::ESRCH | Errno::ENOENT)
        ));
        assert_eq!(
            original.event().worker_state.load(Ordering::Acquire),
            WORKER_NOT_STARTED
        );
        assert!(
            !*original.event().terminal_reaping.read(),
            "no notifier has closed the old gate"
        );
        assert!(owner.is_current().unwrap());
        assert_eq!(old_running.generation(), generation);
        let fresh = Stopped::new_unchecked_on_ptracer_thread(replacement.into()).unwrap();
        assert!(!*original.event().terminal_reaping.read());
        assert_eq!(
            original.event().worker_state.load(Ordering::Acquire),
            WORKER_NOT_STARTED
        );
        let fresh_generation = fresh.generation();
        assert_ne!(fresh_generation, generation);
        assert_eq!(fresh.1.event().current_tracer_pid(), Ok(owner.tid));
        let siginfo = fresh.getsiginfo().unwrap();
        let registers = fresh.getregs().unwrap();
        let old = generation.assume_stopped();
        if let Some(epoch) = warm_epoch {
            assert_eq!(
                original.event().numeric_auth_epoch.load(Ordering::Acquire),
                epoch
            );
            assert_eq!(
                original
                    .event()
                    .numeric_auth_checked_epoch
                    .load(Ordering::Acquire),
                epoch,
                "the old positive authentication must still match its epoch"
            );
        }
        #[cfg(feature = "memory")]
        {
            use std::io::IoSlice;

            use reverie_memory::Addr;
            use reverie_memory::AddrMut;
            use reverie_memory::MemoryAccess;
            use reverie_memory::RemoteIoVec;

            // The replacement is parked on its genuine writable clone stack.
            // The stale token still names the same numeric TID, with its old
            // gate open: only the retained generation guard can refuse this
            // permission-respecting native write before touching these bytes.
            let address = (registers.rsp as usize).checked_sub(16).unwrap();
            let mut before = [0u8; 8];
            fresh
                .read_exact(Addr::from_raw(address).unwrap(), &mut before)
                .unwrap();
            let changed = before.map(|byte| byte ^ 0xff);
            let remote = [RemoteIoVec::new(AddrMut::from_raw(address).unwrap(), 8).unwrap()];
            let mut stale_memory = generation.assume_stopped();
            assert_eq!(
                stale_memory.write_native_user_vectored(
                    former.as_raw(),
                    &[IoSlice::new(&changed)],
                    &remote,
                ),
                Err(Errno::ESRCH)
            );
            assert_eq!(stale_memory.generation(), generation);
            let mut after = [0u8; 8];
            fresh
                .read_exact(Addr::from_raw(address).unwrap(), &mut after)
                .unwrap();
            assert_eq!(after, before, "stale native write changed the replacement");
        }
        for _ in 0..2 {
            assert!(matches!(old.getsiginfo(), Err(Error::Died(_))));
            assert!(matches!(old.getregs(), Err(Error::Died(_))));
            let sample = old.observation().sample(false);
            assert_eq!(sample.siginfo().unwrap().unwrap_err(), Errno::ESRCH);
            assert_eq!(old_running.generation(), generation);
            let after = fresh.getsiginfo().unwrap();
            assert_eq!(after.si_signo, siginfo.si_signo);
            assert_eq!(after.si_code, siginfo.si_code);
            assert_eq!(unsafe { after.si_pid() }, unsafe { siginfo.si_pid() });
            assert_eq!(fresh.getregs().unwrap(), registers);
            let mut pending = 0;
            assert_eq!(
                unsafe {
                    libc::waitpid(
                        replacement.as_raw(),
                        &mut pending,
                        libc::__WALL | libc::__WNOTHREAD | libc::WNOHANG,
                    )
                },
                0
            );
        }
        // The same real retired-generation fixture must refuse syscall resume
        // without losing the old capability or touching its live replacement.
        let (old, error) = old.syscall_retaining(None).unwrap_err();
        assert_eq!(error, Errno::ESRCH);
        assert_eq!(old.generation(), generation);
        assert_eq!(fresh.getregs().unwrap(), registers);
        let (retained, error) = old.resume_retaining(None).unwrap_err();
        assert_eq!(error, Errno::ESRCH);
        assert_eq!(retained.generation(), generation);
        assert_eq!(fresh.getregs().unwrap(), registers);
        let fresh_running = fresh.resume(None).unwrap();
        for _ in 0..2 {
            assert_eq!(old_running.interrupt(), Err(Errno::ESRCH));
            let mut pending = 0;
            assert_eq!(
                unsafe {
                    libc::waitpid(
                        replacement.as_raw(),
                        &mut pending,
                        libc::__WALL | libc::__WNOTHREAD | libc::WNOHANG,
                    )
                },
                0,
                "retired request stopped the replacement"
            );
        }
        // The fresh ORIGINAL replacement capability still produces a real
        // interrupt stop, proving that refusal did not break actual progress.
        fresh_running.interrupt().unwrap();
        let (pid, actual_stop) = raw_wait(replacement);
        assert_eq!(pid, replacement);
        assert!(libc::WIFSTOPPED(actual_stop));
        assert_eq!(actual_stop >> 16, libc::PTRACE_EVENT_STOP);
        let current = fresh_generation.assume_stopped();
        assert_eq!(
            current.getsiginfo().unwrap().si_code,
            libc::SIGTRAP | (libc::PTRACE_EVENT_STOP << 8)
        );
        drop((
            current,
            retained,
            old_running,
            fresh_running,
            parent_running,
        ));
        pidfd_send_signal(&root_cleanup.pidfd, libc::SIGKILL).unwrap();
        let mut root_reaped = false;
        let mut member_reaped = false;
        let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
        while !root_reaped || !member_reaped {
            assert!(Instant::now() < deadline);
            let (pid, status) = raw_wait(Pid::from_raw(-1));
            if libc::WIFSTOPPED(status) {
                raw_request(libc::PTRACE_CONT, pid, 0);
                continue;
            }
            assert!(libc::WIFSIGNALED(status));
            assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
            if pid == root {
                root_reaped = true;
            } else {
                assert_eq!(pid, replacement);
                member_reaped = true;
            }
        }
        root_cleanup.disarm();
        assert!(!std::path::Path::new(&format!("/proc/{root}")).exists());
        assert!(!std::path::Path::new(&format!("/proc/{replacement}")).exists());
        let mut last = 0;
        assert_eq!(
            unsafe {
                libc::waitpid(
                    -1,
                    &mut last,
                    libc::__WALL | libc::__WNOTHREAD | libc::WNOHANG,
                )
            },
            -1
        );
        assert_eq!(Errno::last(), Errno::ECHILD);
        if let Some(epoch) = warm_epoch {
            assert_eq!(
                original.event().numeric_auth_epoch.load(Ordering::Acquire),
                epoch
            );
            assert_eq!(
                original
                    .event()
                    .numeric_auth_checked_epoch
                    .load(Ordering::Acquire),
                epoch
            );
            emit_completion_marker("ACTUAL_WARM_AUTH_CACHE_TID_REUSE_REFUSED");
        }
        emit_completion_marker(&format!(
            "RETIRED_EXPLICIT_TARGET_REFUSAL native={native} forced={forced} former_tid={former} exact_reuse=true same_ptracer=true old_gate_open=true old_worker_unstarted=true actual_original_retired=ESRCH retired_numeric_requests=ESRCH replacement_siginfo_and_registers_preserved=true actual_fresh_interrupt=EVENT_STOP actual_group_kill=SIGKILL root_and_member_reaped=true final_ECHILD=true"
        ));
    }
}
