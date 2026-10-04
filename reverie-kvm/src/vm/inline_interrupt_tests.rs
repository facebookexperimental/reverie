/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

pub(crate) mod inline_interrupt_tests {
    use std::sync::atomic::AtomicI32;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;
    use std::time::Duration;
    use std::time::Instant;

    use super::*;

    // Only these four tests enroll fresh owned host threads. The signal hook
    // does no allocation, locking, TLS initialization or disposition change.
    static TIDS: [AtomicI32; 8] = [const { AtomicI32::new(0) }; 8];
    static DELIVERIES: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];

    pub(crate) fn observe_delivery() {
        // Linux gettid and native lock-free integer atomics are safe in this
        // Linux x86-64 signal handler. Preserve the interrupted operation's errno.
        unsafe {
            let saved = *libc::__errno_location();
            let tid = libc::syscall(libc::SYS_gettid) as i32;
            for (index, selected) in TIDS.iter().enumerate() {
                if selected.load(Ordering::Relaxed) == tid {
                    DELIVERIES[index].fetch_add(1, Ordering::Relaxed);
                }
            }
            *libc::__errno_location() = saved;
        }
    }

    struct Deliveries(usize);
    impl Deliveries {
        fn new() -> Self {
            let tid = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
            let index = TIDS
                .iter()
                .position(|slot| {
                    slot.compare_exchange(0, tid, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                })
                .expect("finite per-test signal witness slots exhausted");
            DELIVERIES[index].store(0, Ordering::SeqCst);
            Self(index)
        }
        fn count(&self) -> usize {
            DELIVERIES[self.0].load(Ordering::SeqCst)
        }
    }
    impl Drop for Deliveries {
        fn drop(&mut self) {
            TIDS[self.0].store(0, Ordering::SeqCst);
        }
    }

    fn current_mask() -> libc::sigset_t {
        unsafe {
            let mut mask = std::mem::zeroed();
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask),
                0
            );
            mask
        }
    }
    fn mask_bytes(mask: &libc::sigset_t) -> Vec<u8> {
        // Storage was zeroed before libc populated it, including unused bytes.
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(mask).cast::<u8>(),
                std::mem::size_of::<libc::sigset_t>(),
            )
            .to_vec()
        }
    }
    fn pending(signal: i32) -> bool {
        unsafe {
            let mut set = std::mem::zeroed();
            assert_eq!(libc::sigpending(&mut set), 0);
            libc::sigismember(&set, signal) == 1
        }
    }
    struct RestoreMask(libc::sigset_t);
    impl RestoreMask {
        fn new() -> Self {
            let saved = Self(current_mask());
            assert!(!pending(libc::SIGUSR1));
            unsafe {
                let mut set = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGUSR1);
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()),
                    0
                );
                assert_eq!(libc::pthread_kill(libc::pthread_self(), libc::SIGUSR1), 0);
            }
            assert!(pending(libc::SIGUSR1));
            saved
        }
    }
    impl Drop for RestoreMask {
        fn drop(&mut self) {
            // This only removes the test's own known SIGUSR1 before restoring
            // its initial mask. Production and tests never consume SIGURG.
            let taken = unsafe {
                let mut set = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGUSR1);
                let zero = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                libc::sigtimedwait(&set, std::ptr::null_mut(), &zero)
            };
            let restored =
                unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) };
            if !std::thread::panicking() {
                assert_eq!(taken, libc::SIGUSR1);
                assert_eq!(restored, 0);
                assert_eq!(mask_bytes(&current_mask()), mask_bytes(&self.0));
            }
        }
    }
    fn registered(group: &GuestThreadGroup, root: bool) -> bool {
        let pthread = unsafe { libc::pthread_self() };
        if root {
            *group.root.lock().unwrap() == Some(pthread)
        } else {
            group.workers.lock().unwrap().contains(&pthread)
        }
    }
    fn suspend(registration: &GuestThreadRegistration) -> GuestInterruptSuspension<'_> {
        registration
            .suspend_for_inline_fork(
                crate::entry::EntryGate::new(),
                crate::entry::EntryOrigin::default(),
                Arc::new(crate::failure::tool_panics::ToolPanics::default()),
            )
            .unwrap()
    }

    #[test]
    fn pending_parent_and_retiring_child_kicks_are_delivered_at_neutral_boundaries() {
        for root in [true, false] {
            std::thread::spawn(move || {
                install_worker_interrupt_handler().unwrap();
                let _mask = RestoreMask::new();
                let seen = Deliveries::new();
                let parent = Arc::new(GuestThreadGroup::default());
                let child = Arc::new(GuestThreadGroup::default());
                let parent_registration =
                    GuestThreadRegistration::register(parent.clone(), root).unwrap();
                assert!(!set_guest_interrupt_signal_mask(libc::SIG_BLOCK).unwrap());
                let before = mask_bytes(&current_mask());
                let notification = parent.subscribe_cancellation();
                parent.request_exit_group(ExitStatus::Exited(61));
                assert_eq!(notification.now_or_never(), Some(Ok(())));
                assert!(pending(libc::SIGURG));
                assert_eq!(seen.count(), 0);
                let suspended = suspend(&parent_registration);
                assert_eq!(seen.count(), 1, "old parent kick must run the handler");
                assert!(!pending(libc::SIGURG));
                assert!(pending(libc::SIGUSR1));
                assert!(!registered(&parent, root));
                assert_eq!(parent.exit_status(), Some(ExitStatus::Exited(61)));
                assert!(parent.cancelled.load(Ordering::Acquire));
                let child_registration =
                    GuestThreadRegistration::register(child.clone(), true).unwrap();
                assert!(!set_guest_interrupt_signal_mask(libc::SIG_BLOCK).unwrap());
                parent.request_exit_group(ExitStatus::Exited(0));
                assert!(!pending(libc::SIGURG));
                assert_eq!(seen.count(), 1);
                assert_eq!(child.exit_status(), None);
                assert!(!child.cancelled.load(Ordering::Acquire));
                let notification = child.subscribe_cancellation();
                child.request_exit_group(ExitStatus::Exited(73));
                assert_eq!(notification.now_or_never(), Some(Ok(())));
                assert!(pending(libc::SIGURG));
                drop(child_registration);
                suspended.finish(Ok(())).unwrap();
                assert_eq!(seen.count(), 2, "retiring child kick must run the handler");
                assert!(!pending(libc::SIGURG));
                assert!(pending(libc::SIGUSR1));
                assert!(registered(&parent, root));
                assert!(!registered(&child, true));
                assert_eq!(mask_bytes(&current_mask()), before);
                parent.request_exit_group(ExitStatus::Exited(0));
                assert!(pending(libc::SIGURG));
                set_guest_interrupt_signal_mask(libc::SIG_UNBLOCK).unwrap();
                assert_eq!(seen.count(), 3, "restored parent remains interruptible");
                drop(parent_registration);
            })
            .join()
            .unwrap();
        }
    }

    #[test]
    fn nested_inline_interrupt_owners_restore_on_return_error_unwind_and_future_drop() {
        for root in [true, false] {
            for completion in ["return", "error", "unwind", "drop"] {
                std::thread::spawn(move || {
                    install_worker_interrupt_handler().unwrap();
                    let _mask = RestoreMask::new();
                    let seen = Deliveries::new();
                    let parent = Arc::new(GuestThreadGroup::default());
                    let child = Arc::new(GuestThreadGroup::default());
                    let leaf = Arc::new(GuestThreadGroup::default());
                    let registration =
                        GuestThreadRegistration::register(parent.clone(), root).unwrap();
                    let before = mask_bytes(&current_mask());
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let future = async {
                            let parent_guard = suspend(&registration);
                            let result = {
                                let child_registration =
                                    GuestThreadRegistration::register(child.clone(), true).unwrap();
                                let child_guard = suspend(&child_registration);
                                let result = {
                                    let _leaf =
                                        GuestThreadRegistration::register(leaf.clone(), true)
                                            .unwrap();
                                    assert!(
                                        !set_guest_interrupt_signal_mask(libc::SIG_BLOCK).unwrap()
                                    );
                                    assert!(!registered(&parent, root));
                                    assert!(!registered(&child, true));
                                    assert!(registered(&leaf, true));
                                    parent.request_exit_group(ExitStatus::Exited(61));
                                    child.request_exit_group(ExitStatus::Exited(47));
                                    assert!(!pending(libc::SIGURG));
                                    leaf.request_exit_group(ExitStatus::Exited(73));
                                    assert!(pending(libc::SIGURG));
                                    match completion {
                                        "return" => Ok(()),
                                        "error" => Err(Error::RunAborted),
                                        "unwind" => panic!("controlled inline child unwind"),
                                        "drop" => std::future::pending::<Result<()>>().await,
                                        _ => unreachable!(),
                                    }
                                };
                                child_guard.finish(result)
                            };
                            parent_guard.finish(result)
                        };
                        future.now_or_never()
                    }));
                    match (completion, result) {
                        ("return", Ok(Some(Ok(()))))
                        | ("error", Ok(Some(Err(Error::RunAborted))))
                        | ("drop", Ok(None)) => {}
                        ("unwind", Err(payload)) => assert_eq!(
                            payload.downcast_ref::<&str>(),
                            Some(&"controlled inline child unwind")
                        ),
                        _ => panic!("inline owner changed its {completion} outcome"),
                    }
                    assert!(registered(&parent, root));
                    assert!(!registered(&child, true));
                    assert!(!registered(&leaf, true));
                    assert_eq!(parent.exit_status(), Some(ExitStatus::Exited(61)));
                    assert_eq!(child.exit_status(), Some(ExitStatus::Exited(47)));
                    assert_eq!(leaf.exit_status(), Some(ExitStatus::Exited(73)));
                    assert_eq!(seen.count(), 1);
                    assert!(!pending(libc::SIGURG));
                    assert!(pending(libc::SIGUSR1));
                    assert_eq!(mask_bytes(&current_mask()), before);
                    drop(registration);
                })
                .join()
                .unwrap();
            }
        }
    }

    #[test]
    fn restoration_keeps_child_error_and_drop_retains_typed_control_failure() {
        std::thread::spawn(|| {
            install_worker_interrupt_handler().unwrap();
            let _mask = RestoreMask::new();
            let group = Arc::new(GuestThreadGroup::default());
            let registration = GuestThreadRegistration::register(group.clone(), true).unwrap();
            let suspended = suspend(&registration);
            // A real contradictory registry state must refuse restoration,
            // not erase the child error or silently bless ownership replacement.
            *group.root.lock().unwrap() = Some(registration.pthread);
            let original = Arc::new(Error::UnexpectedVcpuExit(
                "original child failure".to_owned(),
            ));
            let error = suspended
                .finish::<()>(Err(Error::SharedFailure(original.clone())))
                .unwrap_err();
            assert!(error.retains_primary(&original));
            let Error::WithCleanup { cleanup, .. } = error else {
                panic!("cleanup cause missing")
            };
            assert_eq!(cleanup.len(), 1);
            assert!(matches!(cleanup[0].primary(), Error::EntryControl { .. }));
            let suspended = suspend(&registration);
            *group.root.lock().unwrap() = Some(registration.pthread);
            let error = suspended.finish::<()>(Err(Error::RunAborted)).unwrap_err();
            assert!(matches!(error.primary(), Error::EntryControl { .. }));
            let Error::WithCleanup { cleanup, .. } = error else {
                panic!("cancellation context missing")
            };
            assert!(
                cleanup
                    .iter()
                    .any(|cause| matches!(cause.primary(), Error::RunAborted))
            );
            let gate = crate::entry::EntryGate::new();
            let panics = Arc::new(crate::failure::tool_panics::ToolPanics::default());
            let suspended = registration
                .suspend_for_inline_fork(
                    gate.clone(),
                    crate::entry::EntryOrigin::default(),
                    panics.clone(),
                )
                .unwrap();
            *group.root.lock().unwrap() = Some(registration.pthread);
            drop(suspended);
            let pending = gate
                .pending_failure()
                .expect("Drop lost its typed restoration error");
            assert!(matches!(
                pending.error().primary(),
                Error::EntryControl { .. }
            ));
            assert!(gate.admit_operation().is_err());
            assert!(panics.take().is_empty());
            drop(registration);
        })
        .join()
        .unwrap();
    }

    fn blocked_read(tid: i32, fd: i32, buffer: usize) -> std::io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let text = std::fs::read_to_string(format!("/proc/self/task/{tid}/syscall"))?;
            let fields: Vec<_> = text.split_whitespace().collect();
            let number = |index: usize| -> Option<u64> {
                fields
                    .get(index)
                    .and_then(|s| s.strip_prefix("0x"))
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
            };
            if fields.first().and_then(|s| s.parse::<i64>().ok()) == Some(libc::SYS_read)
                && number(1) == Some(fd as u64)
                && number(2) == Some(buffer as u64)
                && number(3) == Some(1)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::other(
                    "owned child read was not observed blocked",
                ));
            }
            // Poll cadence only: success requires the exact kernel syscall,
            // descriptor, buffer and length, never elapsed time or a marker.
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn child_group_kick_interrupts_a_kernel_observed_blocked_read() {
        for root in [true, false] {
            let mut fds = [-1; 2];
            assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            let input = unsafe { File::from_raw_fd(fds[0]) };
            let mut release = Some(unsafe { File::from_raw_fd(fds[1]) });
            let parent = Arc::new(GuestThreadGroup::default());
            let child = Arc::new(GuestThreadGroup::default());
            let child_sender = child.clone();
            let (send, receive) = mpsc::channel();
            let (done, completed) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                install_worker_interrupt_handler().unwrap();
                let _mask = RestoreMask::new();
                let seen = Deliveries::new();
                let parent_registration =
                    GuestThreadRegistration::register(parent.clone(), root).unwrap();
                set_guest_interrupt_signal_mask(libc::SIG_BLOCK).unwrap();
                parent.request_exit_group(ExitStatus::Exited(61));
                assert!(pending(libc::SIGURG));
                let suspended = suspend(&parent_registration);
                assert_eq!(seen.count(), 1);
                let child_registration =
                    GuestThreadRegistration::register(child.clone(), true).unwrap();
                let mut byte = [0u8; 1];
                let fd = input.as_raw_fd();
                let address = byte.as_mut_ptr() as usize;
                let tid = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
                send.send((tid, fd, address)).unwrap();
                // No write occurs on the successful observer path. Only the
                // genuine child-group SIGURG can complete this blocking read.
                let count = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
                let errno = std::io::Error::last_os_error().raw_os_error();
                done.send((count, errno)).unwrap();
                drop(child_registration);
                suspended.finish(Ok(())).unwrap();
                assert_eq!(parent.exit_status(), Some(ExitStatus::Exited(61)));
                assert_eq!(child.exit_status(), Some(ExitStatus::Exited(73)));
                assert_eq!(seen.count(), 2);
                assert!(!pending(libc::SIGURG));
                drop(parent_registration);
                (count, errno)
            });
            let observed = receive
                .recv_timeout(Duration::from_secs(5))
                .map_err(|e| std::io::Error::other(e.to_string()))
                .and_then(|(tid, fd, address)| blocked_read(tid, fd, address));
            if observed.is_ok() {
                child_sender.request_exit_group(ExitStatus::Exited(73));
            } else {
                // EOF unblocks the reader without SIGPIPE or accepting success.
                drop(release.take());
            }
            let interruption = completed.recv_timeout(Duration::from_secs(5));
            if interruption.is_err() {
                // A missing child kick must fail finitely, not hang in join.
                drop(release.take());
            }
            let returned = worker.join();
            assert!(observed.is_ok(), "{observed:?}; child={returned:?}");
            assert_eq!(interruption.unwrap(), (-1, Some(libc::EINTR)));
            assert_eq!(returned.unwrap(), (-1, Some(libc::EINTR)));
        }
    }
}
