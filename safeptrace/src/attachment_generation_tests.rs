/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[cfg(not(sanitized))]
mod attachment_generation {
    use super::*;

    const NAME: &str =
        "notifier::test::attachment_generation::initial_seize_refuses_same_owner_exact_tid_reuse";
    const INNER: &str = "SAFEPTRACE_INITIAL_SEIZE_REUSE_INNER";
    const FORCE: &str = "SAFEPTRACE_INITIAL_SEIZE_REUSE_FORCE_LEGACY";
    const MARKER: &str = "ACTUAL_INITIAL_SEIZE_SAME_OWNER_REUSE_EXERCISED";

    fn packet(fd: i32) -> [i32; 2] {
        let mut readiness = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut readiness, 1, TRACEE_WAIT_TIMEOUT.as_millis() as i32) },
            1,
            "owned fixture IPC deadline"
        );
        assert_ne!(
            readiness.revents & libc::POLLIN,
            0,
            "owned fixture IPC closed before receipt"
        );
        let mut value = [0i32; 2];
        assert_eq!(
            unsafe { libc::read(fd, value.as_mut_ptr().cast(), mem::size_of_val(&value)) },
            mem::size_of_val(&value) as isize,
            "complete real identity/status packet"
        );
        value
    }

    fn command(fd: i32, byte: u8) {
        assert_eq!(
            unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) },
            1
        );
    }

    fn child_write(fd: i32, value: [i32; 2]) {
        loop {
            let result =
                unsafe { libc::write(fd, value.as_ptr().cast(), mem::size_of_val(&value)) };
            if result == mem::size_of_val(&value) as isize {
                return;
            }
            if result == -1 && Errno::last() == Errno::EINTR {
                continue;
            }
            unsafe { libc::_exit(126) };
        }
    }

    fn child_command(fd: i32, expected: u8) {
        let mut byte = 0u8;
        loop {
            let result = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
            if result == 1 && byte == expected {
                return;
            }
            if result == -1 && Errno::last() == Errno::EINTR {
                continue;
            }
            unsafe { libc::_exit(126) };
        }
    }

    extern "C" fn exec_member(argument: *mut libc::c_void) -> *mut libc::c_void {
        let descriptors = unsafe { &*argument.cast::<[i32; 2]>() };
        child_write(
            descriptors[0],
            [
                unsafe { libc::getpid() },
                unsafe { libc::syscall(libc::SYS_gettid) } as i32,
            ],
        );
        child_command(descriptors[1], b'X');
        let argv = [c"sleep".as_ptr(), c"30".as_ptr(), std::ptr::null()];
        unsafe {
            libc::execv(c"/bin/sleep".as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }

    fn original_guest(ready: i32, execute: i32) -> ! {
        let mut descriptors = [ready, execute];
        let mut member = mem::MaybeUninit::<libc::pthread_t>::uninit();
        if unsafe {
            libc::pthread_create(
                member.as_mut_ptr(),
                std::ptr::null(),
                exec_member,
                descriptors.as_mut_ptr().cast(),
            )
        } != 0
        {
            unsafe { libc::_exit(127) };
        }
        loop {
            unsafe { libc::pause() };
        }
    }

    fn traced_parent(
        ready: i32,
        create: i32,
        receipt: i32,
        child_receipt: i32,
        requested: i32,
    ) -> ! {
        // This owned child supplies an ordinary, unblocked SIGCHLD delivery.
        // It changes no signal disposition or mask in the Rust test owner.
        let mut mask = mem::MaybeUninit::<libc::sigset_t>::uninit();
        if unsafe { libc::sigemptyset(mask.as_mut_ptr()) } != 0
            || unsafe { libc::sigaddset(mask.as_mut_ptr(), libc::SIGCHLD) } != 0
            || unsafe {
                libc::pthread_sigmask(libc::SIG_UNBLOCK, mask.as_ptr(), std::ptr::null_mut())
            } != 0
            || unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) } == libc::SIG_ERR
        {
            unsafe { libc::_exit(127) };
        }
        child_write(
            ready,
            [
                unsafe { libc::getpid() },
                unsafe { libc::syscall(libc::SYS_gettid) } as i32,
            ],
        );
        child_command(create, b'F');
        #[repr(C)]
        #[derive(Default)]
        struct CloneArgs {
            flags: u64,
            pidfd: u64,
            child_tid: u64,
            parent_tid: u64,
            exit_signal: u64,
            stack: u64,
            stack_size: u64,
            tls: u64,
            set_tid: u64,
            set_tid_size: u64,
            cgroup: u64,
        }
        let args = CloneArgs {
            exit_signal: libc::SIGCHLD as u64,
            set_tid: std::ptr::from_ref(&requested) as u64,
            set_tid_size: 1,
            ..CloneArgs::default()
        };
        let child = unsafe { libc::syscall(libc::SYS_clone3, &args, mem::size_of::<CloneArgs>()) };
        if child == -1 {
            unsafe { libc::_exit(118) };
        }
        if child == 0 {
            let actual = unsafe { libc::getpid() };
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
            if actual != requested || tid != requested {
                unsafe { libc::_exit(119) };
            }
            child_write(child_receipt, [actual, tid]);
            loop {
                unsafe { libc::pause() };
            }
        }
        if child != requested as libc::c_long {
            unsafe { libc::_exit(120) };
        }
        child_write(receipt, [child as i32, 0]);
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(requested, &mut status, 0) };
            if result == -1 && Errno::last() == Errno::EINTR {
                continue;
            }
            if result != requested
                || !libc::WIFSIGNALED(status)
                || libc::WTERMSIG(status) != libc::SIGKILL
            {
                unsafe { libc::_exit(121) };
            }
            break;
        }
        child_write(receipt, [requested, status]);
        unsafe { libc::_exit(0) };
    }

    fn signal(fd: i32, number: i32) -> Result<(), Errno> {
        Errno::result(unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd,
                number,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        })
        .map(drop)
    }

    fn owner_wait(pid: Pid, owner: Pid, label: &str) -> i32 {
        assert_eq!(nix::unistd::gettid(), owner);
        let status =
            waitpid_status_bounded(pid, libc::__WALL | libc::__WNOTHREAD, TRACEE_WAIT_TIMEOUT)
                .unwrap();
        println!(
            "ACTUAL_OWNER_WAIT {label} owner={owner} target={pid} status={status:#x} event={}",
            status >> 16
        );
        status
    }

    fn owner_continue(pid: Pid, owner: Pid, delivered: i32) {
        assert_eq!(nix::unistd::gettid(), owner);
        assert_eq!(
            unsafe { libc::ptrace(libc::PTRACE_CONT, pid.as_raw(), 0usize, delivered as usize) },
            0
        );
    }

    fn event_message(pid: Pid, owner: Pid) -> usize {
        assert_eq!(nix::unistd::gettid(), owner);
        let mut message = 0usize;
        assert_eq!(
            unsafe { libc::ptrace(libc::PTRACE_GETEVENTMSG, pid.as_raw(), 0usize, &mut message) },
            0
        );
        println!("ACTUAL_OWNER_EVENT_MESSAGE owner={owner} target={pid} message={message}");
        message
    }

    struct CapturedReuse {
        original: OwnedFd,
        replacement: OwnedFd,
        replacement_pidfd: OwnedFd,
    }

    #[test]
    fn initial_seize_refuses_same_owner_exact_tid_reuse() {
        if env::var_os(INNER).is_none() {
            for forced in ["0", "1"] {
                let result = run_exact_test_bounded(
                    NAME,
                    &[(INNER, "1"), (FORCE, forced)],
                    true,
                    PID_NAMESPACE_TEST_TIMEOUT,
                )
                .expect("start real bounded initial-SEIZE namespace control");
                assert!(
                    !result.timed_out,
                    "initial-SEIZE control timed out: {result:?}"
                );
                assert!(
                    result.output.status.success(),
                    "initial-SEIZE control failed: {result:?}"
                );
                let stdout = String::from_utf8_lossy(&result.output.stdout);
                assert!(
                    stdout.lines().any(|line| line == MARKER),
                    "actual initial-SEIZE outcome missing: {result:?}"
                );
                assert!(
                    !stdout.contains("SKIP"),
                    "a skipped control cannot prove exact reuse"
                );
                print!("{stdout}");
            }
            return;
        }
        require_aligned_proc_pid_namespace().unwrap();
        let owner = nix::unistd::gettid();
        let owner_identity = LegacyWaitOwner::capture_current().unwrap();
        assert!(owner_identity.is_current().unwrap());
        let forced = match env::var(FORCE).unwrap().as_str() {
            "0" => false,
            "1" => true,
            value => panic!("unknown fixture mode {value}"),
        };

        let [ready, send_ready] = legacy_pipe();
        let [execute, release_execute] = legacy_pipe();
        let root = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => original_guest(send_ready.as_raw_fd(), execute.as_raw_fd()),
        };
        drop((send_ready, execute));
        let [actual_root, actual_tid] = packet(ready.as_raw_fd());
        assert_eq!(actual_root, root.as_raw());
        let target = Pid::from_raw(actual_tid);
        assert_ne!(target, root);
        assert_ne!(target, owner);
        let root_pidfd = pidfd_open_with_flags(root.into(), 0).unwrap();

        let [parent_ready, send_parent_ready] = legacy_pipe();
        let [create, release_create] = legacy_pipe();
        let [parent_receipt, send_parent_receipt] = legacy_pipe();
        let [child_receipt, send_child_receipt] = legacy_pipe();
        let parent = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => traced_parent(
                send_parent_ready.as_raw_fd(),
                create.as_raw_fd(),
                send_parent_receipt.as_raw_fd(),
                send_child_receipt.as_raw_fd(),
                target.as_raw(),
            ),
        };
        drop((
            send_parent_ready,
            create,
            send_parent_receipt,
            send_child_receipt,
        ));
        assert_eq!(
            packet(parent_ready.as_raw_fd()),
            [parent.as_raw(), parent.as_raw()]
        );
        assert_ne!(parent, root);
        assert_ne!(parent, target);
        assert_eq!(
            unsafe {
                libc::ptrace(
                    libc::PTRACE_SEIZE,
                    parent.as_raw(),
                    0usize,
                    (libc::PTRACE_O_TRACEFORK | libc::PTRACE_O_EXITKILL) as usize,
                )
            },
            0
        );
        assert_eq!(
            worker_proc_snapshot(parent.into()).unwrap().tracer_pid,
            owner.into()
        );

        let proc_root = AlignedProcfs::open().unwrap();
        let original = proc_root.open_pid(target.into(), libc::O_RDONLY).unwrap();
        let before = retained_proc_status(original.as_raw_fd()).unwrap();
        assert_eq!(before.pid, target.into());
        assert_eq!(before.tgid, root.into());
        assert_eq!(before.tracer_pid.as_raw(), 0);
        assert_eq!(signal(original.as_raw_fd(), 0), Ok(()));
        let native_reference = match pidfd_open_with_flags(target.into(), libc::O_EXCL) {
            Ok(fd) => {
                assert_eq!(signal(fd.as_raw_fd(), 0), Ok(()));
                Some(fd)
            }
            Err(Errno::EINVAL) => {
                println!("NATIVE_PIDFD_THREAD_REFERENCE_EINVAL expected_on_pre_6_9=true");
                None
            }
            Err(error) => panic!("native reference acquisition error: {error}"),
        };
        println!(
            "DISCOVERED_REAL_IDENTITIES owner={owner} original_root={root} original_member={target} fork_parent={parent} forced={forced}"
        );
        if forced {
            PIDFD_OPEN_ERRORS
                .lock()
                .insert(target.into(), Errno::EINVAL);
        }
        let observed = std::rc::Rc::new(std::cell::RefCell::new(None));
        let callback_observed = std::rc::Rc::clone(&observed);
        ATTACHMENT_CAPTURE_HOOK.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(Box::new(move |requested, anchor| {
                assert_eq!(requested, target.into());
                assert_eq!(anchor.pid, target.into());
                assert_eq!(anchor.inode, fd_inode(&original).unwrap());
                assert!(owner_identity.is_current().unwrap());
                let attached = retained_proc_status(anchor.directory.as_raw_fd()).unwrap();
                assert_eq!(attached.pid, target.into());
                assert_eq!(attached.tgid, root.into());
                assert_eq!(attached.tracer_pid, owner.into());
                assert_eq!(signal(original.as_raw_fd(), 0), Ok(()));
                println!("ALIGNED_LIVE_ORIGINAL_SEIZE_BINDING_POSITIVE owner={owner} root={root} member={target}");
                println!("BEGIN_AFTER_SEIZE_BEFORE_CAPTURE_WINDOW owner_wait=0 owner_resume=0 owner_ptrace=0");
                command(release_execute.as_raw_fd(), b'X');
                legacy_owner_until(|| match retained_proc_status(anchor.directory.as_raw_fd()) {
                    Ok(_) => false,
                    Err(Errno::ESRCH) => true,
                    Err(error) => panic!("original anchor retirement refused: {error}"),
                });
                assert!(matches!(retained_proc_status(original.as_raw_fd()), Err(Errno::ESRCH)));
                assert_eq!(signal(original.as_raw_fd(), 0), Err(Errno::ESRCH));
                if let Some(native) = &native_reference { assert_eq!(signal(native.as_raw_fd(), 0), Err(Errno::ESRCH)); }
                command(release_create.as_raw_fd(), b'F');
                let mut replacement = None;
                legacy_owner_until(|| {
                    let directory = match proc_root.open_pid(target.into(), libc::O_RDONLY) {
                        Ok(directory) => directory,
                        Err(Errno::ENOENT | Errno::ESRCH) => return false,
                        Err(error) => panic!("replacement proc capture refused: {error}"),
                    };
                    let status = retained_proc_status(directory.as_raw_fd()).unwrap();
                    if status.tracer_pid != owner.into() { return false; }
                    assert_eq!(status.pid, target.into());
                    assert_eq!(status.tgid, target.into());
                    assert_ne!(fd_inode(&directory).unwrap(), anchor.inode);
                    replacement = Some(directory);
                    true
                });
                let replacement = replacement.unwrap();
                let replacement_pidfd = pidfd_open_with_flags(target.into(), 0).unwrap();
                assert_eq!(signal(replacement.as_raw_fd(), 0), Ok(()));
                assert_eq!(signal(replacement_pidfd.as_raw_fd(), 0), Ok(()));
                assert!(matches!(retained_proc_status(anchor.directory.as_raw_fd()), Err(Errno::ESRCH)));
                assert!(owner_identity.is_current().unwrap());
                println!("ACTUAL_REPLACEMENT_SAME_OWNER_BEFORE_CAPTURE old_member={target} replacement_leader={target} real_tracer={owner}");
                *callback_observed.borrow_mut() = Some(CapturedReuse { original, replacement, replacement_pidfd });
                println!("END_AFTER_SEIZE_BEFORE_CAPTURE_WINDOW owner_wait=0 owner_resume=0 owner_ptrace=0");
            }));
        });
        let running = Running::seize_on_ptracer_thread(
            target.into(),
            Options::PTRACE_O_TRACEEXEC | Options::PTRACE_O_EXITKILL,
        )
        .unwrap();
        assert!(ATTACHMENT_CAPTURE_HOOK.with(|slot| slot.borrow().is_none()));
        if forced {
            assert!(
                !PIDFD_OPEN_ERRORS.lock().contains_key(&target.into()),
                "the forced legacy capture was not actually attempted"
            );
        }
        let captured = observed
            .borrow_mut()
            .take()
            .expect("actual post-SEIZE callback must execute");
        assert!(
            running.1.event().identity().is_none(),
            "constructor bound a same-owner replacement"
        );
        let original_event = running.1.event().clone();
        let terminal = running.terminal_cleanup();
        assert_eq!(terminal.registration_error(), Some(Errno::ESRCH));
        assert_eq!(terminal.ensure_registered(), Err(Errno::ESRCH));
        let untouched = legacy_owner_observe(target, WaitPidFlag::WSTOPPED);
        assert!(libc::WIFSTOPPED(untouched));
        assert_eq!(untouched >> 16, libc::PTRACE_EVENT_STOP);
        assert_eq!(libc::WSTOPSIG(untouched), libc::SIGTRAP);
        assert_eq!(running.interrupt(), Err(Errno::ESRCH));
        let mut driver = running.wait_owned_on_ptracer_thread().into_driver();
        let waker = futures::task::noop_waker();
        for _ in 0..2 {
            assert!(matches!(
                driver.poll_on_ptracer_thread(&mut Context::from_waker(&waker)),
                Poll::Ready(Err(OwnedWaitError::Errno(Errno::ESRCH)))
            ));
            let input = driver
                .inner
                .inner
                .as_ref()
                .expect("refusal lost original owner");
            assert_eq!(input.pid, target.into());
            assert_eq!(*input.token.event(), original_event);
            assert!(input.token.event().identity().is_none());
            assert_eq!(terminal.request_sigkill(), Err(Errno::ESRCH));
            assert_eq!(terminal.request_sigstop(), Err(Errno::ESRCH));
            assert_eq!(
                legacy_owner_observe(target, WaitPidFlag::WSTOPPED),
                untouched,
                "the refused original wait consumed the replacement's stop"
            );
            assert_eq!(signal(captured.replacement_pidfd.as_raw_fd(), 0), Ok(()));
            assert!(matches!(
                retained_proc_status(captured.original.as_raw_fd()),
                Err(Errno::ESRCH)
            ));
            assert_eq!(
                retained_proc_status(captured.replacement.as_raw_fd())
                    .unwrap()
                    .tracer_pid,
                owner.into()
            );
        }
        let fork_stop = owner_wait(parent, owner, "actual-fork");
        assert!(libc::WIFSTOPPED(fork_stop));
        assert_eq!(fork_stop >> 16, libc::PTRACE_EVENT_FORK);
        assert_eq!(event_message(parent, owner), target.as_raw() as usize);
        assert_eq!(
            owner_wait(target, owner, "actual-replacement-newborn"),
            untouched
        );
        let exec_stop = owner_wait(root, owner, "actual-original-nonleader-exec");
        assert!(libc::WIFSTOPPED(exec_stop));
        assert_eq!(exec_stop >> 16, libc::PTRACE_EVENT_EXEC);
        assert_eq!(event_message(root, owner), target.as_raw() as usize);
        owner_continue(parent, owner, 0);
        owner_continue(target, owner, 0);
        assert_eq!(packet(parent_receipt.as_raw_fd()), [target.as_raw(), 0]);
        assert_eq!(
            packet(child_receipt.as_raw_fd()),
            [target.as_raw(), target.as_raw()]
        );
        assert_eq!(signal(captured.replacement_pidfd.as_raw_fd(), 0), Ok(()));
        assert_eq!(
            signal(captured.replacement_pidfd.as_raw_fd(), libc::SIGKILL),
            Ok(())
        );
        let killed = owner_wait(target, owner, "replacement-terminal-reap");
        assert!(libc::WIFSIGNALED(killed));
        assert_eq!(libc::WTERMSIG(killed), libc::SIGKILL);
        let delivery = owner_wait(parent, owner, "real-parent-SIGCHLD-delivery");
        assert!(libc::WIFSTOPPED(delivery));
        assert_eq!(delivery >> 16, 0);
        assert_eq!(libc::WSTOPSIG(delivery), libc::SIGCHLD);
        let mut info = mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        assert_eq!(
            unsafe {
                libc::ptrace(
                    libc::PTRACE_GETSIGINFO,
                    parent.as_raw(),
                    0usize,
                    info.as_mut_ptr(),
                )
            },
            0
        );
        let info = unsafe { info.assume_init() };
        assert_eq!(info.si_signo, libc::SIGCHLD);
        assert_eq!(info.si_code, libc::CLD_KILLED);
        assert_eq!(unsafe { info.si_pid() }, target.as_raw());
        assert_eq!(unsafe { info.si_status() }, libc::SIGKILL);
        owner_continue(parent, owner, libc::SIGCHLD);
        assert_eq!(
            packet(parent_receipt.as_raw_fd()),
            [target.as_raw(), killed],
            "actual natural-parent terminal receipt"
        );
        let parent_exit = owner_wait(parent, owner, "parent-terminal-reap");
        assert!(libc::WIFEXITED(parent_exit));
        assert_eq!(libc::WEXITSTATUS(parent_exit), 0);
        assert_eq!(signal(root_pidfd.as_raw_fd(), libc::SIGKILL), Ok(()));
        let original_exit = owner_wait(root, owner, "original-exec-terminal-reap");
        assert!(libc::WIFSIGNALED(original_exit));
        assert_eq!(libc::WTERMSIG(original_exit), libc::SIGKILL);
        let mut status = 0;
        assert_eq!(
            unsafe {
                libc::waitpid(
                    -1,
                    &mut status,
                    libc::__WALL | libc::__WNOTHREAD | libc::WNOHANG,
                )
            },
            -1
        );
        assert_eq!(Errno::last(), Errno::ECHILD);
        assert_eq!(
            signal(captured.replacement_pidfd.as_raw_fd(), 0),
            Err(Errno::ESRCH)
        );
        assert_eq!(signal(root_pidfd.as_raw_fd(), 0), Err(Errno::ESRCH));
        assert!(!std::path::Path::new(&format!("/proc/{target}")).exists());
        assert!(!std::path::Path::new(&format!("/proc/{parent}")).exists());
        assert!(!std::path::Path::new(&format!("/proc/{root}")).exists());
        emit_completion_marker(MARKER);
    }
}
