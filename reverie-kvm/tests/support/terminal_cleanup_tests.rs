// Included inside terminal_cleanup::tests with the authenticated broker adapter.
#[test]
fn dropped_waiter_keeps_native_wait_and_owned_service_alive() {
    const TEST: &str =
        "terminal_cleanup::tests::dropped_waiter_keeps_native_wait_and_owned_service_alive";
    let Some(client) = crate::broker_library_tests::selected_child(TEST) else {
        return;
    };
    dropped_waiter_keeps_native_wait_and_owned_service_alive_body(client);
}

use super::*;

// This body runs inside terminal_cleanup's cfg(test) module and observes its
// private Shared state. Broker identity comes from the authenticated session.
fn dropped_waiter_keeps_native_wait_and_owned_service_alive_body(
    client: crate::native_exit_broker::BrokerClient,
) {
    use std::future::Future;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::IntoRawFd;
    use std::task::Context;
    use std::task::Poll;
    // This exact daemon identity/pidfd arrives with the authenticated session,
    // not from an environment PID or the launcher's SO_PEERPIDFD.
    let identity = client
        .authenticated_broker_identity()
        .expect("complete authenticated broker identity required by STOP control");
    let broker_pid = identity.pid();
    let broker_pidfd = identity.pidfd().try_clone_to_owned().unwrap();
    let runs = Arc::new(Mutex::new(crate::executor::AbandonedRuns::default()));
    let admission = crate::executor::RunAdmission::begin(&runs).unwrap();
    let mut task = admission.terminal_factory(client).spawn().unwrap();
    futures::executor::block_on(task.ready()).unwrap();
    // This is an owned-test daemon stop only. It keeps the worker's actual wait
    // receipt unavailable while we drop the waiter; no test-only product hook.
    fn signal(fd: &std::os::fd::OwnedFd, signal: i32) -> libc::c_long {
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        }
    }
    fn assert_live(fd: &std::os::fd::OwnedFd) {
        let mut interest = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut interest, 1, 0) },
            0,
            "authenticated broker exited or pidfd observation failed"
        );
        assert_eq!(interest.revents, 0);
    }
    struct Resume {
        fd: std::os::fd::OwnedFd,
        armed: bool,
    }
    impl Resume {
        fn resume(mut self) {
            assert_eq!(signal(&self.fd, libc::SIGCONT), 0);
            self.armed = false;
        }
    }
    impl Drop for Resume {
        fn drop(&mut self) {
            if self.armed {
                let _ = signal(&self.fd, libc::SIGCONT);
            }
        }
    }
    let resume = Resume {
        fd: broker_pidfd,
        armed: true,
    };
    assert_live(&resume.fd);
    assert_eq!(signal(&resume.fd, libc::SIGSTOP), 0);
    // The native parent remains the trusted launcher. Inspect the exact
    // retained broker generation until STOP is effective before submission.
    // This observer borrows /proc metadata, never owns a socket reference.
    let stopped_by = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let original_stat = std::fs::read_to_string(format!("/proc/{broker_pid}/stat")).unwrap();
    let original_fields: Vec<_> = original_stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    let generation: u64 = original_fields[19].parse().unwrap();
    loop {
        assert_live(&resume.fd);
        let stat = std::fs::read_to_string(format!("/proc/{broker_pid}/stat")).unwrap();
        let fields: Vec<_> = stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .collect();
        assert_eq!(fields[19].parse::<u64>().unwrap(), generation);
        // Exclude a retired/reused numeric PID on either side of the read.
        assert_live(&resume.fd);
        if fields[0] == "T" {
            break;
        }
        assert!(
            std::time::Instant::now() < stopped_by,
            "owned broker did not acknowledge STOP"
        );
        unsafe {
            libc::poll(std::ptr::null_mut(), 0, 1);
        }
    }
    let (socket, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let shared = task.shared.clone();
    task.submit(vec![crate::native_exit_broker::SocketReference::Owned(
        unsafe { std::fs::File::from_raw_fd(socket.into_raw_fd()) },
    )]);
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    let mut waiter = Box::pin(task.finish());
    assert!(matches!(waiter.as_mut().poll(&mut context), Poll::Pending));
    drop(waiter); // Cancellation must not own or cancel the terminal batch.
    drop(task); // The actual prestarted reaper now owns the join handle.
    assert!(matches!(
        crate::executor::AbandonedRuns::admit(&runs),
        Err(crate::Error::AbandonedRunNotRetired)
    ));
    assert!(
        shared.lock().result.is_none(),
        "stopped broker cannot supply native wait"
    );
    resume.resume();
    futures::executor::block_on(std::future::poll_fn(|cx| {
        shared.waker.register(cx.waker());
        let state = shared.lock();
        if let Some(error) = &state.failure {
            panic!("retained service failure: {error:?}");
        }
        if let Some(result) = &state.result {
            assert!(result.is_ok());
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }));
    let mut byte = [0u8];
    assert_eq!(std::io::Read::read(&mut peer, &mut byte).unwrap(), 0);
    let workers = Arc::new(crate::vm::GuestThreadGroup::default());
    crate::executor::AbandonedRuns::retire(&runs, &workers);
    drop(shared);
    drop(peer);
    admission.finish(&workers);
    // Final process cleanup must use the launcher's actual daemon wait and
    // owned-thread census. State.result alone is NOT a host-join receipt.
}
