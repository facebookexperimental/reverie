// Included inside executor::tests; the shared adapter is cfg(test) in lib.rs.
#[test]
fn terminal_cleanup_preserves_live_shared_table_and_does_not_wait_for_its_lock() {
    const TEST: &str = "executor::tests::terminal_cleanup_preserves_live_shared_table_and_does_not_wait_for_its_lock";
    let Some(client) = crate::broker_library_tests::selected_child(TEST) else {
        return;
    };
    terminal_cleanup_preserves_live_shared_table_and_does_not_wait_for_its_lock_body(client);
}

// Compiled inside executor::tests. The ordinary-main launcher supplies the
// authenticated client; these tests exercise actual native workers and their
// service/reaper cleanup without fabricating broker readiness or completion.

fn terminal_cleanup_preserves_live_shared_table_and_does_not_wait_for_its_lock_body(
    client: crate::native_exit_broker::BrokerClient,
) {
    let mut fixture = FdinfoFixture::new(false);
    let guest_fd = fixture.open("a", libc::O_RDWR) as i32;
    assert_eq!(
        fixture.call(
            libc::SYS_socketpair,
            [
                libc::AF_UNIX as u64,
                libc::SOCK_STREAM as u64,
                0,
                0x180,
                0,
                0
            ]
        ),
        0
    );
    let mut pair_bytes = [0u8; 8];
    fixture.memory.read(0x180, &mut pair_bytes).unwrap();
    let pair = [
        i32::from_ne_bytes(pair_bytes[..4].try_into().unwrap()),
        i32::from_ne_bytes(pair_bytes[4..].try_into().unwrap()),
    ];
    assert!(pair[0] >= 3 && pair[1] > pair[0]);
    let runs = Arc::new(Mutex::new(AbandonedRuns::default()));
    let admission = RunAdmission::begin(&runs).unwrap();
    fixture
        .executor
        .configure_terminal_cleanup(
            admission.terminal_factory(client),
            Arc::new(Mutex::new(None)),
        )
        .unwrap();
    futures::executor::block_on(fixture.executor.ready_terminal_cleanup()).unwrap();
    let mut peer = fixture.executor.thread_child(99).unwrap();
    futures::executor::block_on(peer.ready_terminal_cleanup()).unwrap();
    assert!(Arc::ptr_eq(&fixture.executor.file_table, &peer.file_table));
    let old_table = peer.file_table.clone();
    let guard = old_table.lock().unwrap();
    let before: Vec<_> = guard
        .files
        .iter()
        .map(|(fd, file)| (*fd, file.as_raw_fd()))
        .collect();
    let original_entry = peer.state.fd_entry_ids[&guest_fd].clone();
    let (sent, received) = std::sync::mpsc::channel();
    let mut owner = fixture.executor;
    let thread = std::thread::spawn(move || {
        owner.release_files_on_exit();
        sent.send(owner).unwrap();
    });
    // If a regression waits on the live peer's lock, release that lock before
    // asserting failure, so the test diagnoses it without leaking the thread.
    let first = received.recv_timeout(std::time::Duration::from_secs(5));
    let returned_while_locked = first.is_ok();
    assert_eq!(
        guard
            .files
            .iter()
            .map(|(fd, file)| (*fd, file.as_raw_fd()))
            .collect::<Vec<_>>(),
        before
    );
    drop(guard);
    let mut owner = first.unwrap_or_else(|_| {
        received
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
    });
    thread.join().unwrap();
    futures::executor::block_on(owner.finish_terminal_cleanup()).unwrap();
    assert!(owner.state.files.is_empty());
    assert!(owner.file_table.lock().unwrap().files.is_empty());
    assert!(Arc::ptr_eq(
        &peer.state.fd_entry_ids[&guest_fd],
        &original_entry
    ));
    let mut byte = [0u8; 1];
    assert_eq!(
        unsafe {
            libc::pread(
                peer.state.files[&guest_fd].as_raw_fd(),
                byte.as_mut_ptr().cast(),
                1,
                0,
            )
        },
        1
    );
    assert_eq!(byte, [b'x']);
    let marker = [0x63u8];
    assert_eq!(
        unsafe {
            libc::send(
                peer.state.files[&pair[0]].as_raw_fd(),
                marker.as_ptr().cast(),
                1,
                libc::MSG_NOSIGNAL,
            )
        },
        1
    );
    assert_eq!(
        unsafe {
            libc::recv(
                peer.state.files[&pair[1]].as_raw_fd(),
                byte.as_mut_ptr().cast(),
                1,
                libc::MSG_DONTWAIT,
            )
        },
        1
    );
    assert_eq!(
        byte, marker,
        "surviving shared table sockets remain functional"
    );
    assert_eq!(
        old_table
            .lock()
            .unwrap()
            .files
            .iter()
            .map(|(fd, file)| (*fd, file.as_raw_fd()))
            .collect::<Vec<_>>(),
        before
    );
    drop(old_table); // Only this observation pin; the peer still owns its table.
    futures::executor::block_on(peer.finish_terminal_cleanup()).unwrap();
    drop(peer);
    drop(owner);
    admission.finish(&crate::vm::GuestThreadGroup::default());
    assert!(
        returned_while_locked,
        "terminal extraction waited on a surviving CLONE_FILES owner"
    );
}


// Test-only join, compiled inside executor::tests where it can inspect the real
// admission/reaper owner. No production readiness or cleanup rule is bypassed.
impl RunAdmission {
    pub(crate) fn finish_fixture_cleanup(mut self) {
        let workers = Arc::new(crate::vm::GuestThreadGroup::default());
        AbandonedRuns::retire(&self.runs, &workers);
        let reaper = self.reaper.take().expect("fixture admission already finished");
        let observed = reaper.shared.clone();
        drop(reaper);
        self.reaping.take().expect("fixture lost its real reaper join")
            .join().expect("fixture cleanup reaper panicked");
        let state = observed.lock();
        assert_eq!(state.handles, 0, "fixture leaked a cleanup owner");
        assert!(state.adopted.is_empty(), "fixture left retirement work pending");
        assert!(state.retained_panics.is_empty(), "fixture cleanup retained a panic");
    }
}


// A proc-fdinfo observer is not a guest task owner. Freeze exactly the strong
// table upgrade at FdinfoTarget::observe, before its table lock or per-file dup,
// while the last task completes native cleanup. The observed descriptor is an
// unrelated regular file: no native observer owns the tested socket OFD.
#[test]
fn terminal_cleanup_retires_socket_despite_fdinfo_observer_table_pin() {
    const TEST: &str =
        "executor::tests::terminal_cleanup_retires_socket_despite_fdinfo_observer_table_pin";
    let Some(client) = crate::broker_library_tests::selected_child(TEST) else {
        return;
    };
    terminal_cleanup_retires_socket_despite_fdinfo_observer_table_pin_body(client);
}

fn terminal_cleanup_retires_socket_despite_fdinfo_observer_table_pin_body(
    client: crate::native_exit_broker::BrokerClient,
) {
    use std::os::fd::AsRawFd;

    let mut fixture = FdinfoFixture::new(false);
    let regular_fd = fixture.open("a", libc::O_RDWR);
    assert!(regular_fd >= 3);
    assert_eq!(
        fixture.call(
            libc::SYS_socketpair,
            [libc::AF_UNIX as u64, libc::SOCK_STREAM as u64, 0, 0x180, 0, 0],
        ),
        0
    );
    let mut pair_bytes = [0u8; 8];
    fixture.memory.read(0x180, &mut pair_bytes).unwrap();
    let sender_fd = i32::from_ne_bytes(pair_bytes[..4].try_into().unwrap());
    let receiver_fd = i32::from_ne_bytes(pair_bytes[4..].try_into().unwrap());
    assert!(sender_fd >= 3 && receiver_fd > sender_fd);
    // Move the receiver's lifetime outside the guest table by duplicating that
    // endpoint only, then closing its guest descriptor through the dispatcher.
    // No test-owned reference aliases the sender whose last close is checked.
    let receiver = fixture.executor.state.files[&receiver_fd]
        .try_clone()
        .unwrap();
    assert_eq!(
        fixture.call(libc::SYS_close, [receiver_fd as u64, 0, 0, 0, 0, 0]),
        0
    );
    fixture.memory.write(0x220, &[0x53]).unwrap();
    assert_eq!(
        fixture.call(libc::SYS_write, [sender_fd as u64, 0x220, 1, 0, 0, 0]),
        1
    );
    let mut byte = [0u8; 1];
    assert_eq!(
        unsafe {
            libc::recv(
                receiver.as_raw_fd(),
                byte.as_mut_ptr().cast(),
                byte.len(),
                libc::MSG_DONTWAIT,
            )
        },
        1
    );
    assert_eq!(byte, [0x53]);
    let open_result = unsafe {
        libc::recv(
            receiver.as_raw_fd(),
            byte.as_mut_ptr().cast(),
            byte.len(),
            libc::MSG_DONTWAIT,
        )
    };
    let open_errno = std::io::Error::last_os_error().raw_os_error();
    assert_eq!(open_result, -1);
    assert_eq!(open_errno, Some(libc::EAGAIN));

    let info_fd = fixture.info(regular_fd);
    let transient_observer =
        match &fixture.executor.state.fdinfo_files[&(info_fd as i32)].source {
            SeqProcSource::Fdinfo(target) => {
                assert_eq!(target.target_fd, regular_fd as i32);
                target.table.upgrade().expect("live fdinfo target table")
            }
            SeqProcSource::Process { .. } => panic!("expected the real fdinfo target"),
        };
    assert!(Arc::ptr_eq(
        &transient_observer,
        &fixture.executor.file_table
    ));
    assert!(
        transient_observer
            .lock()
            .unwrap()
            .files
            .contains_key(&sender_fd)
    );

    let runs = Arc::new(Mutex::new(AbandonedRuns::default()));
    let admission = RunAdmission::begin(&runs).unwrap();
    fixture
        .executor
        .configure_terminal_cleanup(
            admission.terminal_factory(client),
            Arc::new(Mutex::new(None)),
        )
        .unwrap();
    futures::executor::block_on(fixture.executor.ready_terminal_cleanup()).unwrap();
    // Holding the exact observer Arc is the causal barrier. No sleeps, polling
    // deadline, extra guest task, or mutex is needed to force this interleaving.
    futures::executor::block_on(fixture.executor.finish_terminal_cleanup()).unwrap();
    let (remaining_entries, remaining_stdin) = {
        let table = transient_observer.lock().unwrap();
        (
            table.files.keys().copied().collect::<Vec<_>>(),
            table.stdin.is_some(),
        )
    };
    let before_observer_drop = unsafe {
        libc::recv(
            receiver.as_raw_fd(),
            byte.as_mut_ptr().cast(),
            byte.len(),
            libc::MSG_DONTWAIT,
        )
    };
    let before_observer_drop_errno =
        (before_observer_drop < 0).then(|| std::io::Error::last_os_error().raw_os_error());

    // Cleanup precedes the causal assertions, including on the old production
    // path: release the suspended observer, then reap the task service. A red
    // test must be this observed ownership error, not an outer timeout or a
    // deliberately retained worker. The existing launcher reaps its broker
    // before propagating this exact libtest child's nonzero status.
    drop(transient_observer);
    let after_observer_drop = unsafe {
        libc::recv(
            receiver.as_raw_fd(),
            byte.as_mut_ptr().cast(),
            byte.len(),
            libc::MSG_DONTWAIT,
        )
    };
    let after_observer_drop_errno =
        (after_observer_drop < 0).then(|| std::io::Error::last_os_error().raw_os_error());
    drop(receiver);
    drop(fixture);
    admission.finish_fixture_cleanup();

    eprintln!(
        "FDINFO_TABLE_PIN_CLEANED fixture_reaper_cleanup_complete=true before_drop={before_observer_drop} \
         before_errno={before_observer_drop_errno:?} after_drop={after_observer_drop} \
         after_errno={after_observer_drop_errno:?} remaining_entries={remaining_entries:?} \
         remaining_stdin={remaining_stdin}"
    );
    assert_eq!(
        after_observer_drop, 0,
        "setup leaked a sender reference after observer and task cleanup: {after_observer_drop_errno:?}"
    );
    assert_eq!(
        before_observer_drop, 0,
        "fdinfo table observer diverted terminal socket retirement past native cleanup: {before_observer_drop_errno:?}; retained entries: {remaining_entries:?}"
    );
    assert!(remaining_entries.is_empty());
    assert!(!remaining_stdin);
}
