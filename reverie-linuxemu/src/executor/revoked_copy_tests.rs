/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// A retirement of a shared descriptor entry drops every task's private copy
// of it in the retiring task's call (`PrivateCopies` in fd_table.rs), so a
// pipe's reader sees EOF as soon as the guest's last descriptor of the write
// end goes, whether or not the other threads make a call.

use std::fs::File;

use super::*;

fn run_isolated(test: &str) -> bool {
    const CHILD_ENV: &str = "REVERIE_REVOKED_COPY_TEST";
    let test = format!("executor::revoked_copy_tests::{test}");
    if std::env::var(CHILD_ENV).as_deref() == Ok(test.as_str()) {
        return false;
    }
    // Host forks in neighboring tests can briefly inherit CLOEXEC pipe ends,
    // which would hold a write end open. Make the pipe only in the child that
    // runs this one test.
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "10s"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", &test, "--nocapture"])
        .env(CHILD_ENV, &test)
        .output()
        .expect("failed to run isolated revoked-copy test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "isolated revoked-copy test {test} failed with {}\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

fn nonblocking_pipe() -> (File, File) {
    let mut fds = [-1; 2];
    // SAFETY: fds has room for the two descriptors returned by pipe2.
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) },
        0
    );
    // SAFETY: successful pipe2 returned two distinct owned descriptors.
    unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
}

/// What a nonblocking one-byte read of the pipe's read end finds: `Ok(None)`
/// at EOF, the byte, or the error (`EAGAIN` while a write end is open).
fn read_byte(reader: &File) -> std::io::Result<Option<u8>> {
    let mut byte = 0u8;
    // SAFETY: reader owns a nonblocking pipe and byte is writable for one byte.
    match unsafe { libc::read(reader.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) } {
        0 => Ok(None),
        1 => Ok(Some(byte)),
        -1 => Err(std::io::Error::last_os_error()),
        result => panic!("one-byte pipe read returned {result}"),
    }
}

fn assert_write_end_open(reader: &File, when: &str) {
    assert_eq!(
        read_byte(reader).unwrap_err().raw_os_error(),
        Some(libc::EAGAIN),
        "a write end must still be open {when}"
    );
}

fn call(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    number: libc::c_long,
    args: [u64; 6],
) -> i64 {
    executor.execute(&SyscallRequest::new(number as u64, args), memory)
}

/// A leader whose guest descriptor 3 is the write end of a host pipe, and two
/// threads that copied its table when they were made and have made no call
/// since, as threads parked in a futex wait.
fn leader_and_parked_threads(
    configure: impl FnOnce(&mut LoadedStaticElf),
) -> (File, ElfExecutor, ElfExecutor, ElfExecutor) {
    let (reader, writer) = nonblocking_pipe();
    let mut state = native_loaded_state(&std::env::current_dir().unwrap());
    assert!(state.insert_file(3, writer).is_empty());
    configure(&mut state);
    let leader = ElfExecutor::new(state, false);
    let first = leader.thread_child(2).unwrap();
    let second = leader.thread_child(4).unwrap();
    (reader, leader, first, second)
}

/// One thread closes the write end while the other threads, which hold
/// copies of it, make no call: the reader sees EOF when the close returns.
#[test]
fn a_close_drops_every_parked_threads_copy_in_the_closing_call() {
    if run_isolated("a_close_drops_every_parked_threads_copy_in_the_closing_call") {
        return;
    }
    let (reader, mut leader, mut first, second) = leader_and_parked_threads(|_| {});
    let mut memory = GuestMemory::new(0, 4096).unwrap();
    assert_write_end_open(&reader, "before the close");
    assert_eq!(
        call(&mut leader, &memory, libc::SYS_close, [3, 0, 0, 0, 0, 0]),
        0
    );
    assert_eq!(
        read_byte(&reader).unwrap(),
        None,
        "the reader must see EOF when the guest's last write end closes"
    );
    // A thread's next call finds the descriptor closed, as on Linux.
    memory.write(0x100, b"x").unwrap();
    assert_eq!(
        call(&mut first, &memory, libc::SYS_write, [3, 0x100, 1, 0, 0, 0]),
        negative_errno(libc::EBADF)
    );
    drop(second);
}

/// dup2 over the write end's descriptor retires its entry like a close.
#[test]
fn a_dup2_over_the_descriptor_drops_every_threads_copy_of_the_replaced_entry() {
    if run_isolated("a_dup2_over_the_descriptor_drops_every_threads_copy_of_the_replaced_entry") {
        return;
    }
    let (reader, mut leader, mut first, second) = leader_and_parked_threads(|state| {
        assert!(
            state
                .insert_file(4, File::create("/dev/null").unwrap())
                .is_empty()
        );
    });
    let mut memory = GuestMemory::new(0, 4096).unwrap();
    assert_write_end_open(&reader, "before the dup2");
    assert_eq!(
        call(&mut leader, &memory, libc::SYS_dup2, [4, 3, 0, 0, 0, 0]),
        3
    );
    assert_eq!(
        read_byte(&reader).unwrap(),
        None,
        "the reader must see EOF when dup2 replaces the guest's last write end"
    );
    // A thread's next call finds descriptor 3 on the new description.
    memory.write(0x100, b"x").unwrap();
    assert_eq!(
        call(&mut first, &memory, libc::SYS_write, [3, 0x100, 1, 0, 0, 0]),
        1
    );
    assert_eq!(read_byte(&reader).unwrap(), None);
    drop(second);
}

/// Exec closes the close-on-exec write end in the execing thread's call, and
/// with it every other thread's copy, so the reader sees EOF at the exec.
#[test]
fn close_on_exec_drops_every_threads_copy_at_the_exec() {
    if run_isolated("close_on_exec_drops_every_threads_copy_at_the_exec") {
        return;
    }
    let (reader, mut leader, first, second) = leader_and_parked_threads(|state| {
        state.cloexec_fds.insert(3);
    });
    assert_write_end_open(&reader, "before the exec");
    leader.replace_after_exec(native_loaded_state(&std::env::current_dir().unwrap()));
    assert_eq!(
        read_byte(&reader).unwrap(),
        None,
        "the reader must see EOF when exec closes the guest's last write end"
    );
    drop((first, second));
}

/// A thread's exit gives up its copies' descriptions at once, and a later
/// close by another thread leaves no copy of the exited thread's behind.
#[test]
fn an_exited_threads_copies_hold_nothing_and_a_later_close_still_ends_the_pipe() {
    if run_isolated("an_exited_threads_copies_hold_nothing_and_a_later_close_still_ends_the_pipe") {
        return;
    }
    let (reader, mut leader, mut first, second) = leader_and_parked_threads(|_| {});
    let memory = GuestMemory::new(0, 4096).unwrap();
    first.release_files_on_exit();
    assert_write_end_open(&reader, "while the leader and a thread hold it");
    assert_eq!(
        call(&mut leader, &memory, libc::SYS_close, [3, 0, 0, 0, 0, 0]),
        0
    );
    assert_eq!(read_byte(&reader).unwrap(), None);
    drop((first, second));
}

/// Threads that do make calls keep a working descriptor: the copies revoked
/// are only those of retired entries.
#[test]
fn a_close_of_another_descriptor_leaves_every_threads_copy_working() {
    if run_isolated("a_close_of_another_descriptor_leaves_every_threads_copy_working") {
        return;
    }
    let (reader, mut leader, mut first, second) = leader_and_parked_threads(|state| {
        assert!(
            state
                .insert_file(4, File::create("/dev/null").unwrap())
                .is_empty()
        );
    });
    let mut memory = GuestMemory::new(0, 4096).unwrap();
    assert_eq!(
        call(&mut leader, &memory, libc::SYS_close, [4, 0, 0, 0, 0, 0]),
        0
    );
    assert_write_end_open(&reader, "after a close of another descriptor");
    memory.write(0x100, b"y").unwrap();
    assert_eq!(
        call(&mut first, &memory, libc::SYS_write, [3, 0x100, 1, 0, 0, 0]),
        1
    );
    assert_eq!(read_byte(&reader).unwrap(), Some(b'y'));
    drop(second);
}
