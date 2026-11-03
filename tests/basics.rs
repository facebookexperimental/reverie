/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Basic tests that don't fall into some other category.

#[path = "support/basics_commands.rs"]
mod commands;
#[path = "support/basics_rust_guest.rs"]
mod rust_guest;
#[path = "tool_fixtures/basics.rs"]
mod tools;

#[allow(unused_imports)]
use std::ffi::CString;
#[allow(unused_imports)]
use std::io::Write;
#[allow(unused_imports)]
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

#[cfg(all(not(sanitized), test))]
use close_err::Closable;
#[allow(unused_imports)]
use nix::sys::wait;
#[allow(unused_imports)]
use nix::sys::wait::WaitStatus;
#[allow(unused_imports)]
use nix::unistd;
#[allow(unused_imports)]
use nix::unistd::ForkResult;
use reverie::ExitStatus;
#[allow(unused_imports)]
use reverie_ptrace::testing::check_fn;
#[allow(unused_imports)]
use reverie_ptrace::testing::test_fn;
#[allow(unused_imports)]
use reverie_test_support::test_cmd;
use tools::CounterLocal;
use tools::NoopTool;

#[test]
fn noop_tool_test() {
    commands::noop_tool_test(test_cmd::<NoopTool>);
}

#[test]
fn counter_tool_test() {
    commands::counter_tool_test(test_cmd::<CounterLocal>);
}

#[test]
fn error_exit_test() {
    commands::error_exit_test(test_cmd::<CounterLocal>);
}

#[allow(dead_code)]
fn fn_test() {
    let (output, state) = test_fn::<CounterLocal, _>(rust_guest::run_fn_body).unwrap();

    println!(
        " >>> Command complete, stdout len {}, stderr len {}",
        output.stdout.len(),
        output.stderr.len(),
    );
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stderr.len(), 0);
    assert!(AtomicU64::load(&state.num_syscalls, Ordering::SeqCst) > 1);
}

#[cfg(not(sanitized))]
#[test]
fn run_fn_test() {
    fn_test();
    rust_command_test();
}

#[cfg(not(sanitized))]
fn assert_rust_marker(stdout: &[u8]) {
    const MARKER: &[u8] = b"basics-rust-body-complete\n";
    assert_eq!(
        stdout
            .windows(MARKER.len())
            .filter(|part| *part == MARKER)
            .count(),
        1,
    );
}

#[cfg(not(sanitized))]
fn assert_rust_counter(output: &reverie::process::Output, state: &tools::CounterGlobal) {
    // The original fn_test predicates, applied to the actual returned state.
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stderr.len(), 0);
    assert!(AtomicU64::load(&state.num_syscalls, Ordering::SeqCst) > 1);
}

#[cfg(not(sanitized))]
fn record_rust_command(
    label: &str,
    output: &reverie::process::Output,
    state: &tools::CounterGlobal,
) {
    eprintln!(
        "basics Rust command {label}: status={:?} syscalls={} stdout={:02x?} stderr={:02x?}",
        output.status,
        state.num_syscalls.load(Ordering::SeqCst),
        output.stdout,
        output.stderr,
    );
    // The command and controller have completed before this snapshot or output.
    let (count, sequence) = {
        let sequence = state.syscall_sequence.lock().unwrap();
        (state.num_syscalls.load(Ordering::SeqCst), sequence.clone())
    };
    let entries: Vec<_> = sequence
        .iter()
        .enumerate()
        .map(|(ordinal, (sender, sysno))| (ordinal, sender, *sysno as usize, sysno))
        .collect();
    eprintln!("basics Rust syscall sequence {label}: count={count} entries={entries:?}");
    assert_eq!(count, u64::try_from(sequence.len()).unwrap());
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stderr.len(), 0);
    assert_rust_marker(&output.stdout);
}

#[cfg(not(sanitized))]
fn rust_command_test() {
    let program = env!("CARGO_BIN_EXE_basics-rust-command-guest");
    eprintln!("basics Rust command image={program}");
    let output = std::process::Command::new(program).output().unwrap();
    eprintln!(
        "basics Rust command native: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr.len(), 0);
    assert_rust_marker(&output.stdout);

    let (output, state) = test_cmd::<CounterLocal>(program, &[]).unwrap();
    record_rust_command("ptrace", &output, &state);
    assert_rust_counter(&output, &state);

    // The actual Noop Tool has no counter, so its real successful run is
    // paired with an empty counter state. record_rust_command first requires
    // that run's success and marker, so the rejection below can only come from
    // the count predicate: it cannot pass a Tool that intercepts no syscall.
    let (output, ()) = test_cmd::<NoopTool>(program, &[]).unwrap();
    let noop = tools::CounterGlobal::default();
    record_rust_command("noop", &output, &noop);
    assert_eq!(noop.num_syscalls.load(Ordering::SeqCst), 0);
    assert!(std::panic::catch_unwind(|| assert_rust_counter(&output, &noop)).is_err());
}

#[cfg(not(sanitized))]
#[test]
fn run_guest_command_test() {
    commands::run_guest_command_test(test_cmd::<CounterLocal>);
}

#[cfg(not(sanitized))]
#[test]
fn run_guest_command_test_closure() {
    commands::run_guest_command_test_closure(test_cmd::<CounterLocal>);
}

#[cfg(not(sanitized))]
#[test]
fn run_guest_func_write_test() {
    let msg = "abcd";
    let (output, _state) = test_fn::<CounterLocal, _>(move || rust_guest::write_body(msg)).unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stdout.as_slice(), msg.as_bytes());
    rust_output_command_test("write");
}

#[cfg(not(sanitized))]
#[test]
fn run_guest_func_print_test() {
    let msg = "abcd";
    let (output, _state) = test_fn::<CounterLocal, _>(move || rust_guest::print_body(msg)).unwrap();

    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stdout.as_slice(), b"abcd\n");
    rust_output_command_test("print");
}

#[cfg(not(sanitized))]
fn rust_output_matches(mode: &str, exited_zero: bool, stdout: &[u8], stderr: &[u8]) -> bool {
    let expected: &[u8] = match mode {
        "write" => b"abcd",
        "print" => b"abcd\n",
        _ => panic!("unknown Rust output mode: {mode}"),
    };
    exited_zero && stdout == expected && stderr.is_empty()
}

/// The shared write/print bodies as ordinary commands, natively and under
/// ptrace. The opposite selector's real output must pass its own oracle and be
/// rejected by this mode's, so the byte oracle cannot accept either output.
#[cfg(not(sanitized))]
fn rust_output_command_test(mode: &str) {
    let opposite = match mode {
        "write" => "print",
        "print" => "write",
        _ => panic!("unknown Rust output mode: {mode}"),
    };
    let program = env!("CARGO_BIN_EXE_basics-rust-command-guest");
    eprintln!("basics Rust output mode={mode} image={program}");

    let output = std::process::Command::new(program)
        .arg(mode)
        .output()
        .unwrap();
    eprintln!(
        "basics Rust output mode={mode} role=native selector={mode}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert!(rust_output_matches(
        mode,
        output.status.code() == Some(0),
        &output.stdout,
        &output.stderr,
    ));

    let (output, _state) = test_cmd::<CounterLocal>(program, &[mode]).unwrap();
    eprintln!(
        "basics Rust output mode={mode} role=ptrace selector={mode}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert!(rust_output_matches(
        mode,
        output.status == ExitStatus::Exited(0),
        &output.stdout,
        &output.stderr,
    ));

    let (output, _state) = test_cmd::<CounterLocal>(program, &[opposite]).unwrap();
    eprintln!(
        "basics Rust output mode={mode} role=opposite-ptrace selector={opposite}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert!(rust_output_matches(
        opposite,
        output.status == ExitStatus::Exited(0),
        &output.stdout,
        &output.stderr,
    ));
    assert!(!rust_output_matches(
        mode,
        output.status == ExitStatus::Exited(0),
        &output.stdout,
        &output.stderr,
    ));
    eprintln!("basics Rust output mode={mode} opposite={opposite} rejected=true");
}

#[cfg(not(sanitized))]
#[test]
fn orphans() {
    use std::thread;
    use std::time::Duration;

    use nix::unistd::ForkResult;
    use nix::unistd::fork;

    let (output, _state) = test_fn::<CounterLocal, _>(|| {
        // Spawn a child process and make sure the parent exits before the child
        // process.
        match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child: _child } => {
                // Don't wait on the child. Just exit.
            }
            ForkResult::Child => {
                // Sleep for a little while so the parent has time to exit.
                thread::sleep(Duration::from_secs(1));
            }
        }
    })
    .unwrap();

    assert_eq!(output.status, ExitStatus::Exited(0));
}

#[cfg(not(sanitized))]
#[test]
fn rust_execve_noexist_test() {
    use reverie_ptrace::testing::check_fn;
    check_fn::<NoopTool, _>(|| {
        let program = CString::new("I do not exist").unwrap();
        let env = CString::new("foo=bar").unwrap();
        let res = nix::unistd::execve(&program, &[&program], &[&env]);
        assert!(res.is_err());
    });
}

/// Runs `body` natively in a forked child (no tracer) and returns the
/// kernel-reported status. The child inherits this process's limits
/// (including RLIMIT_CORE) unchanged, so its core-dump bit is the native
/// oracle for the same body under the same inherited limits: with a pipe
/// core_pattern and RLIMIT_CORE == 1 the kernel skips the core helper and
/// the bit is false, which a hard-coded `true` cannot express in every
/// environment. A control that cannot run, or whose body does not die by
/// a signal, panics: the control failing IS the test failing.
#[cfg(not(sanitized))]
fn native_signal_status(body: &dyn Fn()) -> ExitStatus {
    use nix::sys::wait::WaitStatus;
    use nix::unistd::ForkResult;
    match unsafe { nix::unistd::fork() } {
        Ok(ForkResult::Child) => {
            body();
            // The body must die by signal; reaching here is a control failure.
            unsafe { libc::_exit(86) }
        }
        Ok(ForkResult::Parent { child }) => loop {
            match nix::sys::wait::waitpid(child, None) {
                Ok(WaitStatus::Signaled(_, signal, core_dumped)) => {
                    assert_eq!(
                        signal,
                        nix::sys::signal::Signal::SIGSEGV,
                        "native segfault control died by the wrong signal"
                    );
                    return ExitStatus::Signaled(signal, core_dumped);
                }
                Ok(other) => {
                    panic!("native segfault control did not die by signal: {other:?}")
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => panic!("native segfault control waitpid failed: {e}"),
            }
        },
        Err(e) => panic!("native segfault control fork failed: {e}"),
    }
}

#[cfg(not(sanitized))]
#[test]
fn i_should_segfault() {
    use reverie_ptrace::testing::test_fn;
    let body = || {
        unsafe {
            let invalid_ptr = std::ptr::dangling_mut::<u64>();
            invalid_ptr.write_volatile(0xdeadbeefu64);
        };
    };
    let (output, _) = test_fn::<NoopTool, _>(body).unwrap();
    assert_eq!(output.status, native_signal_status(&body));
}

#[cfg(not(sanitized))]
#[test]
fn i_should_segfault_2() {
    use reverie_ptrace::testing::test_fn;

    pub fn do_segfault() {
        let invalid_ptr = std::ptr::dangling::<usize>();
        let result = unsafe { invalid_ptr.read_volatile() };
        // Print so the above doesn't get optimized out. We will never get here
        // because the above segfaults.
        println!("{}", result);
    }

    let (output, _) = test_fn::<NoopTool, _>(do_segfault).unwrap();
    assert_eq!(output.status, native_signal_status(&do_segfault));
}

#[cfg(not(sanitized))]
#[test]
fn child_should_inherit_fds() {
    check_fn::<NoopTool, _>(move || {
        let (fdread, fdwrite) = unistd::pipe().unwrap();
        let msg: [u8; 8] = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];
        match unsafe { unistd::fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                fdwrite.close().expect("close failed");
                let mut buf: [u8; 8] = [0; 8];
                assert_eq!(unistd::read(&fdread, &mut buf), Ok(8));
                assert_eq!(buf, msg);
                assert_eq!(wait::waitpid(child, None), Ok(WaitStatus::Exited(child, 0)));
                unsafe { libc::syscall(libc::SYS_exit_group, 0) };
                unreachable!();
            }
            Ok(ForkResult::Child) => {
                fdread.close().expect("close failed");
                assert_eq!(unistd::write(&fdwrite, &msg), Ok(8));
                unsafe { libc::syscall(libc::SYS_exit_group, 0) };
                unreachable!();
            }
            Err(err) => {
                panic!("fork failed: {:?}", err);
            }
        }
    });
}
