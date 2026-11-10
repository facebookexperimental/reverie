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
    admission.finish(&crate::executor::EmptyWorkers);
    assert!(
        returned_while_locked,
        "terminal extraction waited on a surviving CLONE_FILES owner"
    );
}
