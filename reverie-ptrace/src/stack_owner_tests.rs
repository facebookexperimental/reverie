/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Each cell runs in a new libtest process. A real seccomp filter is confined to
// the forced cell's ptracer thread and descendants; the shared runner stays intact.
#[cfg(target_arch = "x86_64")]
#[test]
fn guest_stack_preserves_ptracer_owner_generation() {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;
    use std::time::Duration;
    use std::time::Instant;

    const CELL_ENV: &str = "REVERIE_GUEST_STACK_OWNER_CELL";
    if let Ok(cell) = std::env::var(CELL_ENV) {
        assert!(cell == "normal" || cell == "forced");
        guest_stack_owner_cell(cell == "forced");
        println!("STACK_OWNER_CELL_PASSED {cell}");
        return;
    }
    let mut all_passed = true;
    for cell in ["normal", "forced"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "stack::tests::guest_stack_preserves_ptracer_owner_generation",
                "--exact",
                "--nocapture",
            ])
            .env(CELL_ENV, cell)
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                // Only this freshly spawned owned process group is signaled.
                assert_eq!(
                    unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) },
                    0
                );
                let status = child.wait().unwrap();
                eprintln!("stack owner cell {cell} exceeded its 15s bound: {status}");
                break status;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        child
            .stdout
            .take()
            .unwrap()
            .take(65537)
            .read_to_end(&mut stdout)
            .unwrap();
        child
            .stderr
            .take()
            .unwrap()
            .take(65537)
            .read_to_end(&mut stderr)
            .unwrap();
        assert!(stdout.len() <= 65536 && stderr.len() <= 65536);
        let stdout = String::from_utf8(stdout).unwrap();
        let stderr = String::from_utf8(stderr).unwrap();
        println!("stack owner cell {cell}, actual status {status}:\n{stdout}");
        eprintln!("{stderr}");
        let passed = status.success()
            && stdout
                .lines()
                .filter(|line| *line == format!("STACK_OWNER_CELL_PASSED {cell}"))
                .count()
                == 1
            && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;");
        all_passed &= passed;
    }
    assert!(
        all_passed,
        "both actual normal and PIDFD_THREAD-EINVAL cells must pass"
    );
    println!("ACTUAL_PTRACER_GUEST_STACK_GENERATION_EXERCISED");
}

#[cfg(target_arch = "x86_64")]
fn guest_stack_owner_cell(force_legacy: bool) {
    use reverie::Guest;
    use reverie::Subscription;
    use tokio::sync::broadcast;
    use tokio::sync::mpsc;

    use crate::task::TracedTask;
    use crate::task::TracedTaskOptions;

    struct Child(libc::pid_t);
    impl Drop for Child {
        fn drop(&mut self) {
            if self.0 > 0 {
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                    loop {
                        let mut status = 0;
                        let actual = libc::waitpid(self.0, &mut status, libc::__WALL);
                        if actual == self.0
                            && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status))
                        {
                            break;
                        }
                        if actual < 0 && *libc::__errno_location() != libc::EINTR {
                            break;
                        }
                    }
                }
            }
        }
    }
    // The alarm is confined to this re-executed owned cell, never the shared runner.
    unsafe { libc::alarm(10) };
    let raw = unsafe { libc::fork() };
    assert!(raw >= 0);
    if raw == 0 {
        unsafe {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0 || libc::raise(libc::SIGSTOP) != 0 {
                libc::_exit(2);
            }
            libc::_exit(0);
        }
    }
    let mut child = Child(raw);
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(raw, &mut status, 0) }, raw);
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
    assert_eq!(
        unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, raw, 0, libc::PTRACE_O_EXITKILL) },
        0
    );
    if force_legacy {
        let insn = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
        let filter = [
            insn(0x20, 0, 0, 4),           // seccomp_data.arch
            insn(0x15, 1, 0, 0xc000_003e), // AUDIT_ARCH_X86_64
            insn(0x06, 0, 0, 0x8000_0000), // kill incompatible architecture
            insn(0x20, 0, 0, 0),           // seccomp_data.nr
            insn(0x15, 0, 3, libc::SYS_pidfd_open as u32),
            insn(0x20, 0, 0, 24),                  // seccomp_data.args[1], flags
            insn(0x15, 0, 1, libc::O_EXCL as u32), // PIDFD_THREAD
            insn(0x06, 0, 0, 0x0005_0000 | libc::EINVAL as u32),
            insn(0x06, 0, 0, 0x7fff_0000), // allow all other calls
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr().cast_mut(),
        };
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0
        );
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program) }, 0);
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_pidfd_open, raw, libc::O_EXCL) },
            -1
        );
        assert_eq!(unsafe { *libc::__errno_location() }, libc::EINVAL);
        let ordinary = unsafe { libc::syscall(libc::SYS_pidfd_open, raw, 0) };
        assert!(ordinary >= 0, "ordinary process pidfd must remain allowed");
        assert_eq!(unsafe { libc::close(ordinary as i32) }, 0);
    }
    let pid = Pid::from_raw(raw);
    let original = Stopped::new_unchecked_on_ptracer_thread(pid).unwrap();
    let generation = original.generation();
    let events = Subscription::none();
    let (orphanage, _orphans) = mpsc::channel(1);
    let (daemon_kill, _) = broadcast::channel(1);
    let mut traced = TracedTask::<()>::new(
        pid,
        (),
        Arc::new(()),
        TracedTaskOptions {
            command_bootstrap: false,
            events: &events,
            injected_syscall_trap: None,
            liteinst_runtime: None,
            liteinst_trap_only: None,
            backend_stats: None,
            final_resume_signal_for_test: None,
            pre_syscall_for_test: None,
            preinit_point_for_test: None,
        },
        orphanage,
        daemon_kill,
        None,
    );
    traced.ptracer_waits.bind_stopped(&original);
    let stack = futures::executor::block_on(traced.stack());
    let flag = stack.token.flag.clone();
    assert!(flag.load(Ordering::SeqCst));
    assert_eq!(
        stack.task.generation(),
        generation,
        "Guest::stack must retain the original Event generation"
    );
    assert!(
        stack
            .task
            .terminal_cleanup()
            .same_generation(&original.terminal_cleanup())
    );
    drop(stack);
    assert!(
        !flag.load(Ordering::SeqCst),
        "uncommitted drop releases the original checkout"
    );

    let mut stack = futures::executor::block_on(traced.stack());
    const PAYLOAD: [u8; 16] = *b"retained-stack!!";
    let address = stack.push(PAYLOAD);
    let guard = stack.commit().unwrap();
    assert!(flag.load(Ordering::SeqCst));
    let mut actual = [0u8; 16];
    original.read_exact(address.cast(), &mut actual).unwrap();
    assert_eq!(actual, PAYLOAD);
    let overlap = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        futures::executor::block_on(traced.stack())
    }));
    assert!(
        overlap.is_err(),
        "a real simultaneous checkout must still be refused"
    );
    assert!(flag.load(Ordering::SeqCst));
    drop(guard);
    assert!(
        !flag.load(Ordering::SeqCst),
        "committed guard drop releases the same checkout"
    );

    let mut stack = futures::executor::block_on(traced.stack());
    let foreign_stop = generation.assume_stopped();
    let foreign_flag = Arc::new(AtomicBool::new(false));
    let foreign_flag_check = foreign_flag.clone();
    let (returned, refused) = std::thread::spawn(move || {
        let mut bytes = [0u8; 16];
        assert_eq!(stack.read(address.cast(), &mut bytes), Err(Errno::EPERM));
        let refused = GuestStack::new_on_ptracer_thread(foreign_stop, foreign_flag);
        assert!(matches!(refused, Err(TraceError::Errno(Errno::EPERM))));
        (stack, foreign_flag_check)
    })
    .join()
    .unwrap();
    stack = returned;
    assert!(
        !refused.load(Ordering::SeqCst),
        "constructor refusal must release its token"
    );
    assert_eq!(stack.task.generation(), generation);
    assert!(
        flag.load(Ordering::SeqCst),
        "foreign refusal must not release the live owner's checkout"
    );
    stack.read_exact(address.cast(), &mut actual).unwrap();
    assert_eq!(actual, PAYLOAD);
    drop(stack);
    assert!(!flag.load(Ordering::SeqCst));
    assert_eq!(original.generation(), generation);
    original.getregs().unwrap();
    let running = original.resume(None).unwrap();
    let mut wait = running.wait_sync_on_ptracer_thread();
    assert_eq!(
        wait.wait().unwrap().assume_exited(),
        (pid, reverie::process::ExitStatus::Exited(0))
    );
    child.0 = 0;
    assert_eq!(
        unsafe { libc::waitpid(raw, &mut status, libc::WNOHANG | libc::__WALL) },
        -1
    );
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ECHILD);
    unsafe { libc::alarm(0) };
}
