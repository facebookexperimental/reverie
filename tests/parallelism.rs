/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(not(sanitized))]

//! Tests for parallelism and concurrency
use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Tid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use tokio::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Default)]
struct GlobalState {}

#[derive(Debug, Default)]
struct TestTool {}

#[reverie::global_tool]
impl GlobalTool for GlobalState {
    type Request = ();
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, _threads: Self::Request) -> Self::Response {
        // TODO: replace this with an ivar read:
        for _i in 0..400_000 {
            tokio::task::yield_now().await;
        }
        sleep(Duration::from_millis(1000)).await;
        // Overkill: spin this async task to make sure there are plenty of turns of the
        // other thread.
        for _i in 0..400_000 {
            tokio::task::yield_now().await;
        }
    }
}

#[reverie::tool]
impl Tool for TestTool {
    type GlobalState = GlobalState;
    type ThreadState = u64;

    fn init_thread_state(
        &self,
        _tid: Tid,
        parent: Option<(Tid, &Self::ThreadState)>,
    ) -> Self::ThreadState {
        match parent {
            None => 0,
            Some((_, n)) => n + 1,
        }
    }

    async fn handle_thread_start<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Error> {
        if guest.is_root_thread() {
            eprintln!("Root thread starting...");
        } else {
            eprintln!("Delaying child thread!");
            guest.send_rpc(()).await;
            eprintln!("Done delaying child thread!");
        }
        Ok(())
    }
}

/// A test to interleave writes on memory.
#[test]
#[cfg(not(sanitized))]
pub fn delay_childprint_test() {
    use std::os::fd::BorrowedFd;

    use reverie::ExitStatus;
    use reverie_ptrace::testing::print_tracee_output;
    use reverie_ptrace::testing::test_fn;

    let fd1 = unsafe { BorrowedFd::borrow_raw(1) };

    let (output, _state) = test_fn::<TestTool, _>(|| {
        let child = std::thread::spawn(move || {
            for _ in 0..2 {
                nix::unistd::write(fd1, b"a").unwrap();
            }
        });
        for _ in 0..100 {
            nix::unistd::write(fd1, b"b").unwrap();
        }
        child.join().unwrap();
        nix::unistd::write(fd1, b"\n").unwrap();
    })
    .unwrap();

    print_tracee_output(&output);
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stdout.len(), 103);
    assert_eq!(output.stderr.len(), 0);
    // Because the child was delayed it must finish last:
    assert_eq!(output.stdout[101] as char, 'a');
}

// A test tool that blocks a handler indefinitely. Its marker is getppid, not
// gettid: Rust's standard library makes a gettid syscall while it starts a
// thread, before the thread's closure runs (to record the thread's id for its
// stack-overflow report), so blocking gettid would stop such a thread before
// it reaches the code under test, as
// `blocking_gettid_stops_a_thread_before_its_closure` shows. A thread made
// with raw pthread_create makes no such call
// (`blocking_gettid_lets_a_raw_pthread_run_its_closure`), but getppid keeps
// the marker independent of how the thread was made.
#[derive(Debug, Default)]
struct TestTool2 {}

#[reverie::tool]
impl Tool for TestTool2 {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        call: Syscall,
    ) -> Result<i64, Error> {
        if let Syscall::Getppid(_) = call {
            // Delay forever. When the main thread is killed, this future should
            // get canceled.
            futures::future::pending::<()>().await;
        }

        guest.tail_inject(call).await
    }
}

/// Exit status of `kill_blocked_child` when its thread did not reach the
/// marker within the bound.
#[cfg(not(sanitized))]
const MARKER_NEVER_REACHED: i32 = 3;

/// Exit status of `kill_blocked_child` when its thread reached the marker but
/// was not seen stopped in it within the bound.
#[cfg(not(sanitized))]
const MARKER_NEVER_STOPPED: i32 = 4;

#[cfg(not(sanitized))]
fn kill_blocked_child() {
    use std::sync::Barrier;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use std::time::Instant;

    struct Shared {
        barrier: Barrier,
        at_marker: AtomicBool,
    }

    // The thread is made with raw pthread_create, not std::thread::spawn: this
    // runs in a fork of the multithreaded test harness, where std's thread
    // start can block forever on a lock another harness thread held at fork
    // time (https://github.com/rrnewton/reverie/issues/1459).
    extern "C" fn blocked_child(shared: *mut libc::c_void) -> *mut libc::c_void {
        // SAFETY: the main thread's `shared` outlives this thread; the main
        // thread ends the process instead of returning.
        let shared = unsafe { &*shared.cast::<Shared>() };
        shared.barrier.wait();
        // No syscall comes between this store and the marker.
        shared.at_marker.store(true, Ordering::Release);
        unsafe { libc::syscall(libc::SYS_getppid) };
        std::ptr::null_mut()
    }

    // Polls `ready` for up to 10 s, and ends the group with `status` if it
    // never holds.
    fn wait_for(status: i32, mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready() {
            if Instant::now() >= deadline {
                unsafe { libc::syscall(libc::SYS_exit_group, status) };
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    let shared = Shared {
        barrier: Barrier::new(2),
        at_marker: AtomicBool::new(false),
    };
    let mut thread = std::mem::MaybeUninit::<libc::pthread_t>::uninit();
    let created = unsafe {
        libc::pthread_create(
            thread.as_mut_ptr(),
            std::ptr::null(),
            blocked_child,
            (&raw const shared).cast_mut().cast(),
        )
    };
    assert_eq!(created, 0, "pthread_create");

    // Wait for the thread to start up.
    shared.barrier.wait();

    // Wait until the thread is stopped in the marker's handler, so the
    // exit_group below has a pending handler to cancel. The process's only
    // other thread is the one created above.
    wait_for(MARKER_NEVER_REACHED, || {
        shared.at_marker.load(Ordering::Acquire)
    });
    let leader = std::process::id().to_string();
    wait_for(MARKER_NEVER_STOPPED, || {
        let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
            return false;
        };
        tasks
            .flatten()
            .filter_map(|task| task.file_name().into_string().ok())
            .filter(|tid| *tid != leader)
            .any(|tid| {
                // The state follows the parenthesized command name.
                std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).is_ok_and(|stat| {
                    stat.rsplit_once(") ")
                        .is_some_and(|(_, rest)| rest.starts_with('t'))
                })
            })
    });

    // This should cause the handler future for the thread to get dropped the
    // next time it is polled.
    unsafe { libc::syscall(libc::SYS_exit_group, 0) };

    unreachable!()
}

/// Test where handle_syscall_event blocks a child thread forever. The
/// expectation is that calling `exit_group` will cancel the
/// `handle_syscall_event` future. The guest calls `exit_group` only once the
/// thread is stopped in that handler, so a pass is never vacuous; exit status
/// `MARKER_NEVER_REACHED` or `MARKER_NEVER_STOPPED` means the thread did not
/// get there within 10 s.
#[cfg(not(sanitized))]
#[test]
pub fn test_kill_blocked_child() {
    use reverie::ExitStatus;
    use reverie_ptrace::testing::test_fn;

    let (output, _state) = test_fn::<TestTool2, _>(kill_blocked_child).unwrap();
    reverie_ptrace::testing::print_tracee_output(&output);
    assert_eq!(output.status, ExitStatus::Exited(0));
}

// A test tool that blocks every gettid, as `TestTool2` once did.
#[derive(Debug, Default)]
struct BlockGettid {}

#[reverie::tool]
impl Tool for BlockGettid {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        call: Syscall,
    ) -> Result<i64, Error> {
        if let Syscall::Gettid(_) = call {
            futures::future::pending::<()>().await;
        }

        guest.tail_inject(call).await
    }
}

/// Exit status of `spawn_and_wait_for_the_closure` and
/// `pthread_and_wait_for_the_closure` when the new thread's closure did not run
/// within its bound.
#[cfg(not(sanitized))]
const CLOSURE_NEVER_RAN: i32 = 42;

/// Spawns a thread whose closure only reports that it ran, waits up to 2 s for
/// that report, and exits the group with 0 if it came and
/// `CLOSURE_NEVER_RAN` if it did not.
#[cfg(not(sanitized))]
fn spawn_and_wait_for_the_closure() {
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Duration;

    let (ran, report) = std::sync::mpsc::channel();
    let _handle = std::thread::spawn(move || {
        let _ = ran.send(());
    });
    let status = match report.recv_timeout(Duration::from_secs(2)) {
        Ok(()) => 0,
        Err(RecvTimeoutError::Timeout) => CLOSURE_NEVER_RAN,
        Err(RecvTimeoutError::Disconnected) => 1,
    };
    unsafe { libc::syscall(libc::SYS_exit_group, status) };

    unreachable!()
}

/// Makes a thread with raw pthread_create whose start routine only reports
/// that it ran, waits up to 2 s for that report, and exits the group with 0 if
/// it came and `CLOSURE_NEVER_RAN` if it did not. The start routine makes no
/// syscall, and the C library's thread start makes no gettid.
#[cfg(not(sanitized))]
fn pthread_and_wait_for_the_closure() {
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use std::time::Instant;

    extern "C" fn report(ran: *mut libc::c_void) -> *mut libc::c_void {
        // SAFETY: the main thread's `ran` outlives this thread; the main
        // thread ends the process instead of returning.
        let ran = unsafe { &*ran.cast::<AtomicBool>() };
        ran.store(true, Ordering::Release);
        std::ptr::null_mut()
    }

    let ran = AtomicBool::new(false);
    let mut thread = std::mem::MaybeUninit::<libc::pthread_t>::uninit();
    let created = unsafe {
        libc::pthread_create(
            thread.as_mut_ptr(),
            std::ptr::null(),
            report,
            (&raw const ran).cast_mut().cast(),
        )
    };
    assert_eq!(created, 0);
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if ran.load(Ordering::Acquire) {
            break 0;
        }
        if Instant::now() >= deadline {
            break CLOSURE_NEVER_RAN;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    unsafe { libc::syscall(libc::SYS_exit_group, status) };

    unreachable!()
}

/// Why `TestTool2` does not use gettid as its marker. With every gettid
/// blocked, a spawned thread stops at the gettid its standard library makes
/// while starting it, so its closure never runs; the exit_group after the 2 s
/// bound then ends that blocked thread.
///
/// This depends on whichever standard library builds the test. In Rust
/// 1.97.1, the pinned toolchain, a spawned thread's start calls
/// `stack_overflow::make_handler`, which calls `set_current_info`, which makes
/// the gettid syscall, whenever std has installed its SIGSEGV handler. If a
/// later std stops making that call, this test fails, and that loud failure is
/// the intended signal: `TestTool2`'s choice of marker should then be looked
/// at again.
///
/// It keeps `std::thread::spawn`, because std's thread start is what it
/// checks. In this fork of the multithreaded test harness, std's thread start
/// can also block on its `thread_info` lock if another harness thread held it
/// at fork time (https://github.com/rrnewton/reverie/issues/1459). That cannot
/// change this test's outcome: `set_current_info` makes the gettid before it
/// takes that lock, so the thread stops at the blocked gettid first, and the
/// 2 s wait bounds the run either way.
#[cfg(not(sanitized))]
#[test]
pub fn blocking_gettid_stops_a_thread_before_its_closure() {
    use reverie::ExitStatus;
    use reverie_ptrace::testing::test_fn;

    let (output, _state) = test_fn::<BlockGettid, _>(spawn_and_wait_for_the_closure).unwrap();
    reverie_ptrace::testing::print_tracee_output(&output);
    assert_eq!(output.status, ExitStatus::Exited(CLOSURE_NEVER_RAN));
}

/// The control for the test above: under the same tool, a thread made with
/// raw pthread_create runs its closure, because neither its start routine nor
/// the C library's thread start makes a gettid. Both tests block every gettid
/// and differ in how the thread is made, so the test above stops at a gettid
/// that std's thread start makes. Raw pthread_create also keeps this control
/// clear of std's `thread_info` lock, which another harness thread can hold
/// at fork time in this fork of the multithreaded test harness
/// (https://github.com/rrnewton/reverie/issues/1459).
#[cfg(not(sanitized))]
#[test]
pub fn blocking_gettid_lets_a_raw_pthread_run_its_closure() {
    use reverie::ExitStatus;
    use reverie_ptrace::testing::test_fn;

    let (output, _state) = test_fn::<BlockGettid, _>(pthread_and_wait_for_the_closure).unwrap();
    reverie_ptrace::testing::print_tracee_output(&output);
    assert_eq!(output.status, ExitStatus::Exited(0));
}
