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
    leader
        .replace_after_exec(native_loaded_state(&std::env::current_dir().unwrap()))
        .unwrap();
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

// Calls that use a copy while another thread retires its entry (Codex review
// of the retirement above): a copy a call has reached stays that call's, as
// Linux's fdget holds a file for the call that looked it up, and a call that
// had not reached it finds the descriptor closed. Fork and exec copy the
// table as it is, never a replaced copy. Each race is made deterministic by a
// one-shot hook that runs the other thread's call at the racing point.

use std::cell::RefCell;
use std::rc::Rc;

/// Runs `then` on this thread, once, right after the next call that does not
/// change the table releases the table lock.
fn when_the_table_is_released(then: impl FnOnce() + 'static) {
    TABLE_RELEASED_TEST_HOOK.with(|hook| *hook.borrow_mut() = Some(Box::new(then)));
}

/// Runs `then` on this thread, once, right after the next lookup that
/// reaches a copy.
fn when_a_copy_is_reached(then: impl FnOnce() + 'static) {
    COPY_REACHED_TEST_HOOK.with(|hook| *hook.borrow_mut() = Some(Box::new(then)));
}

fn closer(executor: &Rc<RefCell<ElfExecutor>>, fd: u64) -> impl FnOnce() + 'static {
    let executor = executor.clone();
    move || {
        let memory = GuestMemory::new(0, 4096).unwrap();
        assert_eq!(
            call(
                &mut executor.borrow_mut(),
                &memory,
                libc::SYS_close,
                [fd, 0, 0, 0, 0, 0]
            ),
            0
        );
    }
}

/// A leader whose guest descriptor 3 is the read end of a host pipe holding
/// `bytes`, a thread that copied its table, and a fork child of the leader,
/// which shares descriptor 3's entry but not its table.
fn reader_leader_thread_and_child(
    bytes: &[u8],
) -> (File, Rc<RefCell<ElfExecutor>>, ElfExecutor, ElfExecutor) {
    let (reader, writer) = nonblocking_pipe();
    (&writer).write_all(bytes).unwrap();
    let mut state = native_loaded_state(&std::env::current_dir().unwrap());
    assert!(state.insert_file(3, reader).is_empty());
    let leader = ElfExecutor::new(state, false);
    let thread = leader.thread_child(2).unwrap();
    let child = leader
        .fork_child(leader.state.pid + 30, false, false)
        .unwrap();
    (writer, Rc::new(RefCell::new(leader)), thread, child)
}

/// A call that reached its descriptor keeps the description when another
/// thread closes it meanwhile: its probes see the description, never the
/// placeholder, so they cache nothing false on the entry a fork child shares,
/// and the read completes. The copy is replaced when the call returns.
#[test]
fn a_read_that_reached_its_descriptor_finishes_on_it_when_another_thread_closes_it() {
    if run_isolated(
        "a_read_that_reached_its_descriptor_finishes_on_it_when_another_thread_closes_it",
    ) {
        return;
    }
    let (_writer, leader, mut thread, mut child) = reader_leader_thread_and_child(b"ab");
    let memory = GuestMemory::new(0, 4096).unwrap();
    when_a_copy_is_reached(closer(&leader, 3));
    assert_eq!(
        call(&mut thread, &memory, libc::SYS_read, [3, 0x100, 1, 0, 0, 0]),
        1,
        "the read reached descriptor 3 before the close, so it reads"
    );
    let mut byte = [0];
    memory.read(0x100, &mut byte).unwrap();
    assert_eq!(&byte, b"a");
    // The call has returned: its copy is gone, as the leader's close made it.
    assert_eq!(
        call(&mut thread, &memory, libc::SYS_read, [3, 0x100, 1, 0, 0, 0]),
        negative_errno(libc::EBADF)
    );
    // The fork child's descriptor 3 is its own and still open.
    let child_memory = GuestMemory::new(0, 4096).unwrap();
    assert_eq!(
        call(
            &mut child,
            &child_memory,
            libc::SYS_read,
            [3, 0x100, 1, 0, 0, 0]
        ),
        1,
        "the fork child's inherited descriptor must still read"
    );
    child_memory.read(0x100, &mut byte).unwrap();
    assert_eq!(&byte, b"b");
}

/// A call that had not reached its descriptor when another thread closed it
/// finds it closed, as a Linux call that starts after the close does, and
/// probes nothing: the fork child that shares the entry still reads.
#[test]
fn a_read_that_had_not_reached_its_descriptor_finds_it_closed() {
    if run_isolated("a_read_that_had_not_reached_its_descriptor_finds_it_closed") {
        return;
    }
    let (_writer, leader, mut thread, mut child) = reader_leader_thread_and_child(b"ab");
    let memory = GuestMemory::new(0, 4096).unwrap();
    when_the_table_is_released(closer(&leader, 3));
    assert_eq!(
        call(&mut thread, &memory, libc::SYS_read, [3, 0x100, 1, 0, 0, 0]),
        negative_errno(libc::EBADF),
        "the close came first, so the read finds descriptor 3 closed"
    );
    let child_memory = GuestMemory::new(0, 4096).unwrap();
    assert_eq!(
        call(
            &mut child,
            &child_memory,
            libc::SYS_read,
            [3, 0x100, 1, 0, 0, 0]
        ),
        1,
        "the fork child's inherited descriptor must still read"
    );
    let mut byte = [0];
    child_memory.read(0x100, &mut byte).unwrap();
    assert_eq!(&byte, b"a");
}

/// A write that reached the write end keeps it when another thread closes
/// it, and gives it up when the call returns: the reader gets the byte and
/// then EOF, with no further call of the writing thread.
#[test]
fn a_call_that_reached_a_copy_gives_it_up_when_it_returns() {
    if run_isolated("a_call_that_reached_a_copy_gives_it_up_when_it_returns") {
        return;
    }
    let (reader, leader, mut first, second) = leader_and_parked_threads(|_| {});
    let leader = Rc::new(RefCell::new(leader));
    let mut memory = GuestMemory::new(0, 4096).unwrap();
    memory.write(0x100, b"z").unwrap();
    when_a_copy_is_reached(closer(&leader, 3));
    assert_eq!(
        call(&mut first, &memory, libc::SYS_write, [3, 0x100, 1, 0, 0, 0]),
        1
    );
    assert_eq!(read_byte(&reader).unwrap(), Some(b'z'));
    assert_eq!(
        read_byte(&reader).unwrap(),
        None,
        "the writer's call returned, so its copy must be gone"
    );
    drop(second);
}

/// A lookup outside any call reaches nothing that a call end would release:
/// a later close replaces that copy at once.
#[test]
fn a_lookup_outside_a_call_reaches_nothing() {
    if run_isolated("a_lookup_outside_a_call_reaches_nothing") {
        return;
    }
    let (reader, mut leader, first, mut second) = leader_and_parked_threads(|_| {});
    let memory = GuestMemory::new(0, 4096).unwrap();
    assert!(first.state.files.get(&3).is_some());
    assert!(second.state.files.get_mut(&3).is_some());
    assert_eq!(
        call(&mut leader, &memory, libc::SYS_close, [3, 0, 0, 0, 0, 0]),
        0
    );
    assert_eq!(read_byte(&reader).unwrap(), None);
}

/// A copy lent to a borrower that kept it (as the terminal reader keeps a
/// cancelled read's) is the borrower's to close: another thread's close
/// leaves it alone, and the description goes when the borrower closes it.
#[test]
fn a_copy_its_borrower_kept_is_never_replaced() {
    if run_isolated("a_copy_its_borrower_kept_is_never_replaced") {
        return;
    }
    let (reader, mut leader, mut first, second) = leader_and_parked_threads(|_| {});
    let memory = GuestMemory::new(0, 4096).unwrap();
    let kept = first.state.files.remove(&3).unwrap();
    first.state.files.mark_foreign(kept.as_raw_fd());
    assert_eq!(
        call(&mut leader, &memory, libc::SYS_close, [3, 0, 0, 0, 0, 0]),
        0
    );
    drop(second);
    assert_write_end_open(&reader, "while the borrower holds the lent copy");
    (&kept).write_all(b"k").unwrap();
    assert_eq!(read_byte(&reader).unwrap(), Some(b'k'));
    drop(kept);
    assert_eq!(read_byte(&reader).unwrap(), None);
    drop(first);
}

/// The status of guest `fstat(fd)` in `executor`.
fn fstat_status(executor: &mut ElfExecutor, fd: u64) -> i64 {
    let memory = GuestMemory::new(0, 4096).unwrap();
    call(executor, &memory, libc::SYS_fstat, [fd, 0x200, 0, 0, 0, 0])
}

/// A fork after another thread closed a descriptor copies the table as it
/// is now: the child has no descriptor 3, never the placeholder that the
/// close left on the forking thread's private copy.
#[test]
fn a_fork_after_another_thread_closes_a_descriptor_copies_the_table() {
    if run_isolated("a_fork_after_another_thread_closes_a_descriptor_copies_the_table") {
        return;
    }
    let (reader, leader, mut first, second) = leader_and_parked_threads(|_| {});
    let memory = GuestMemory::new(0, 4096).unwrap();
    assert_eq!(
        call(&mut first, &memory, libc::SYS_close, [3, 0, 0, 0, 0, 0]),
        0
    );
    let mut child = leader
        .fork_child(leader.state.pid + 30, false, false)
        .unwrap();
    assert!(!child.state.files.copies().contains_key(&3));
    assert_eq!(fstat_status(&mut child, 3), negative_errno(libc::EBADF));
    assert_eq!(read_byte(&reader).unwrap(), None);
    drop(second);
}

/// A fork before another thread closes a descriptor gives the child its own
/// copy, which the close leaves open.
#[test]
fn a_fork_before_another_thread_closes_a_descriptor_keeps_the_childs_copy() {
    if run_isolated("a_fork_before_another_thread_closes_a_descriptor_keeps_the_childs_copy") {
        return;
    }
    let (reader, leader, mut first, second) = leader_and_parked_threads(|_| {});
    let mut child = leader
        .fork_child(leader.state.pid + 30, false, false)
        .unwrap();
    let memory = GuestMemory::new(0, 4096).unwrap();
    assert_eq!(
        call(&mut first, &memory, libc::SYS_close, [3, 0, 0, 0, 0, 0]),
        0
    );
    let mut child_memory = GuestMemory::new(0, 4096).unwrap();
    child_memory.write(0x100, b"c").unwrap();
    assert_eq!(
        call(
            &mut child,
            &child_memory,
            libc::SYS_write,
            [3, 0x100, 1, 0, 0, 0]
        ),
        1
    );
    assert_eq!(read_byte(&reader).unwrap(), Some(b'c'));
    drop((leader, second));
}

/// An exec after another thread closed a descriptor inherits the table as it
/// is now, so the new image neither has nor publishes the placeholder.
#[test]
fn an_exec_after_another_thread_closes_a_descriptor_inherits_the_table() {
    if run_isolated("an_exec_after_another_thread_closes_a_descriptor_inherits_the_table") {
        return;
    }
    let (reader, mut leader, mut first, second) = leader_and_parked_threads(|_| {});
    let memory = GuestMemory::new(0, 4096).unwrap();
    assert_eq!(
        call(&mut first, &memory, libc::SYS_close, [3, 0, 0, 0, 0, 0]),
        0
    );
    leader
        .replace_after_exec(native_loaded_state(&std::env::current_dir().unwrap()))
        .unwrap();
    assert!(!leader.state.files.copies().contains_key(&3));
    assert!(!leader.file_table.lock().unwrap().files.contains_key(&3));
    assert_eq!(fstat_status(&mut leader, 3), negative_errno(libc::EBADF));
    assert_eq!(read_byte(&reader).unwrap(), None);
    drop(second);
}

/// Sets RLIMIT_NOFILE, and restores the previous limits when dropped.
struct NofileLimit(libc::rlimit);

impl NofileLimit {
    /// `soft`, and `hard` (or the current hard limit).
    fn set(soft: libc::rlim_t, hard: Option<libc::rlim_t>) -> Self {
        let mut previous = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes only `previous`, and setrlimit reads only
        // the new limits.
        unsafe {
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut previous), 0);
            let limit = libc::rlimit {
                rlim_cur: soft,
                rlim_max: hard.unwrap_or(previous.rlim_max),
            };
            assert_eq!(
                libc::setrlimit(libc::RLIMIT_NOFILE, &limit),
                0,
                "{}",
                std::io::Error::last_os_error()
            );
        }
        Self(previous)
    }

    fn soft() -> libc::rlim_t {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes only `limit`.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        limit.rlim_cur
    }
}

impl Drop for NofileLimit {
    fn drop(&mut self) {
        // SAFETY: setrlimit reads only the saved limits. A lowered hard limit
        // cannot be raised again; the isolated child process just ends.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.0) };
    }
}

/// A retirement opens no descriptor: with this process's descriptor table
/// full, a close still replaces every other thread's copy, and the reader
/// sees EOF.
#[test]
fn a_retirement_opens_no_descriptor() {
    if run_isolated("a_retirement_opens_no_descriptor") {
        return;
    }
    let (reader, mut leader, first, second) = leader_and_parked_threads(|_| {});
    let memory = GuestMemory::new(0, 4096).unwrap();
    let highest = [&first, &second]
        .iter()
        .map(|thread| thread.state.files.copies()[&3].as_raw_fd())
        .max()
        .unwrap();
    let _limit = NofileLimit::set((highest + 16) as libc::rlim_t, None);
    let mut filler = Vec::new();
    loop {
        // SAFETY: dup returns a new owned descriptor or fails.
        let fd = unsafe { libc::dup(0) };
        if fd < 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EMFILE)
            );
            break;
        }
        // SAFETY: fd is a fresh descriptor this test owns.
        filler.push(unsafe { File::from_raw_fd(fd) });
    }
    assert_eq!(
        call(&mut leader, &memory, libc::SYS_close, [3, 0, 0, 0, 0, 0]),
        0
    );
    assert_eq!(read_byte(&reader).unwrap(), None);
    drop((filler, first, second));
}

/// A copy at or above a lowered soft RLIMIT_NOFILE, where dup3 refuses the
/// number, is still replaced, and the soft limit is as it was afterwards.
#[test]
fn a_copy_above_a_lowered_soft_limit_is_replaced() {
    if run_isolated("a_copy_above_a_lowered_soft_limit_is_replaced") {
        return;
    }
    let (reader, mut leader, first, second) = leader_and_parked_threads(|_| {});
    let memory = GuestMemory::new(0, 4096).unwrap();
    let lowest = [&first, &second]
        .iter()
        .map(|thread| thread.state.files.copies()[&3].as_raw_fd())
        .min()
        .unwrap();
    let soft = lowest as libc::rlim_t;
    let _limit = NofileLimit::set(soft, None);
    assert_eq!(
        call(&mut leader, &memory, libc::SYS_close, [3, 0, 0, 0, 0, 0]),
        0
    );
    assert_eq!(read_byte(&reader).unwrap(), None);
    assert_eq!(NofileLimit::soft(), soft, "the soft limit must be restored");
    drop((first, second));
}

fn assert_descriptors_refusal(error: &crate::Error) {
    assert!(
        matches!(
            error,
            crate::Error::HostResources {
                resource: reverie_kvm_core::host_limits::HostResource::Descriptors,
                ..
            }
        ),
        "{error:?}"
    );
}

/// The lowest host descriptor among `threads`' copies of guest descriptor 3.
fn lowest_copy(threads: [&ElfExecutor; 2]) -> RawFd {
    threads
        .iter()
        .map(|thread| thread.state.files.copies()[&3].as_raw_fd())
        .min()
        .unwrap()
}

/// A copy at or above a lowered hard RLIMIT_NOFILE cannot be replaced, and
/// the retirement finds it before it changes anything: the run ends with a
/// named refusal rather than a panic, the table still has the entry, and
/// every copy is still recorded and still holds the description.
#[test]
fn a_copy_above_a_lowered_hard_limit_ends_the_run_before_anything_changes() {
    if run_isolated("a_copy_above_a_lowered_hard_limit_ends_the_run_before_anything_changes") {
        return;
    }
    let (reader, mut leader, first, second) = leader_and_parked_threads(|_| {});
    let memory = GuestMemory::new(0, 4096).unwrap();
    let lowest = lowest_copy([&first, &second]);
    let _limit = NofileLimit::set(lowest as libc::rlim_t, Some(lowest as libc::rlim_t));
    let error = leader
        .execute_checked(
            &SyscallRequest::new(libc::SYS_close as u64, [3, 0, 0, 0, 0, 0]),
            &memory,
        )
        .unwrap_err();
    assert_descriptors_refusal(&error);
    let table = leader.file_table.lock().unwrap();
    assert!(table.files.contains_key(&3), "nothing was published");
    for thread in [&first, &second] {
        assert!(table.records_copy(thread.state.tid, 3));
        let copy = thread.state.files.copies()[&3].as_raw_fd();
        // SAFETY: F_GETFL reads only the descriptor's status flags.
        let flags = unsafe { libc::fcntl(copy, libc::F_GETFL) };
        assert!(
            flags >= 0 && flags & libc::O_PATH == 0,
            "no copy was replaced"
        );
    }
    drop(table);
    assert_write_end_open(&reader, "after a refused retirement");
}

/// A copy whose hard limit falls below it after the retirement checked it
/// (here, through a test hook at that point) cannot be replaced either: the
/// close is published, the run ends with the named refusal rather than a
/// panic, and the copy stays in its thread's record, holding the
/// description. Its thread's next install still closes it.
#[test]
fn a_copy_whose_limit_falls_after_the_check_ends_the_run_and_stays_recorded() {
    if run_isolated("a_copy_whose_limit_falls_after_the_check_ends_the_run_and_stays_recorded") {
        return;
    }
    let (reader, mut leader, mut first, mut second) = leader_and_parked_threads(|_| {});
    let memory = GuestMemory::new(0, 4096).unwrap();
    let lowest = lowest_copy([&first, &second]);
    PUBLICATION_CHECKED_TEST_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            // The isolated child ends with the test; a hard limit cannot be
            // raised again anyway.
            std::mem::forget(NofileLimit::set(
                lowest as libc::rlim_t,
                Some(lowest as libc::rlim_t),
            ));
        }))
    });
    let error = leader
        .execute_checked(
            &SyscallRequest::new(libc::SYS_close as u64, [3, 0, 0, 0, 0, 0]),
            &memory,
        )
        .unwrap_err();
    assert_descriptors_refusal(&error);
    assert!(!leader.file_table.lock().unwrap().files.contains_key(&3));
    let first_tid = first.state.tid;
    let second_tid = second.state.tid;
    let recorded = {
        let table = leader.file_table.lock().unwrap();
        table.records_copy(first_tid, 3) || table.records_copy(second_tid, 3)
    };
    assert!(recorded, "a copy that could not be replaced stays recorded");
    assert_write_end_open(&reader, "while the unreplaced copy holds it");
    for thread in [&mut first, &mut second] {
        assert!(call(thread, &memory, libc::SYS_getpid, [0; 6]) > 0);
    }
    assert_eq!(read_byte(&reader).unwrap(), None);
}
