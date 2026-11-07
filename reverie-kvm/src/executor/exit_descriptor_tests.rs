/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::fs::File;
use std::sync::mpsc;
use std::time::Duration;

use super::*;

fn run_isolated(test: &str) -> bool {
    const CHILD_ENV: &str = "REVERIE_EXIT_DESCRIPTOR_LOCK_TEST";
    let test = format!("executor::exit_descriptor_tests::{test}");
    if std::env::var(CHILD_ENV).as_deref() == Ok(test.as_str()) {
        return false;
    }
    // Host forks in neighboring tests can temporarily inherit CLOEXEC pipe
    // endpoints. Create this fixture only after entering its exact-test child.
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "10s"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", &test, "--nocapture"])
        .env(CHILD_ENV, &test)
        .output()
        .expect("failed to run isolated descriptor release control");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "isolated descriptor release control {test} failed with {}\nstdout:\n{stdout}\nstderr:\n{}",
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

#[test]
fn release_files_on_exit_does_not_wait_for_live_sibling_locks() {
    if run_isolated("release_files_on_exit_does_not_wait_for_live_sibling_locks") {
        return;
    }
    let (reader, writer) = nonblocking_pipe();
    let mut state = native_loaded_state(&std::env::current_dir().unwrap());
    assert!(state.insert_file(3, writer).is_empty());
    let mut issuer = ElfExecutor::new(state, false);
    let mut sibling = issuer.thread_child(2).unwrap();
    assert_eq!(
        read_byte(&reader).unwrap_err().raw_os_error(),
        Some(libc::EAGAIN)
    );

    let file_table = sibling.file_table.clone();
    let signal_transaction = sibling.state.signal_transaction.clone();
    let files_guard = file_table.lock().unwrap();
    let signal_guard = signal_transaction.lock().unwrap();
    let (released_sender, released_receiver) = mpsc::channel();
    let releasing = std::thread::spawn(move || {
        issuer.release_files_on_exit();
        released_sender.send(()).unwrap();
        issuer
    });
    let released_while_locked = released_receiver.recv_timeout(Duration::from_secs(3));
    // Always release the locks and join before asserting. The old implementation
    // can then finish its blocked release, so this control fails without leaving
    // a worker stuck behind a lock owned by the panicking test thread.
    drop(signal_guard);
    drop(files_guard);
    drop(signal_transaction);
    drop(file_table);
    let issuer = releasing.join().unwrap();
    assert!(
        released_while_locked.is_ok(),
        "descriptor release waited for live sibling locks: {released_while_locked:?}"
    );
    assert_eq!(
        read_byte(&reader).unwrap_err().raw_os_error(),
        Some(libc::EAGAIN),
        "the live sibling must retain its writer"
    );

    let mut memory = GuestMemory::new(0, 4096).unwrap();
    memory.write(0x100, b"s").unwrap();
    assert_eq!(
        sibling.execute(
            &SyscallRequest::new(libc::SYS_write as u64, [3, 0x100, 1, 0, 0, 0]),
            &memory,
        ),
        1,
        "the live sibling must retain a usable guest descriptor"
    );
    assert_eq!(read_byte(&reader).unwrap(), Some(b's'));
    sibling.release_files_on_exit();
    assert_eq!(
        read_byte(&reader).unwrap(),
        None,
        "the final descriptor owner must release the writer synchronously"
    );
    drop(issuer);
}
