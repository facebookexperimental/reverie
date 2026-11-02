/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Actual common-entry controls, not a native loader or scheduler proof.

use super::super::native_state::DeferredNative;
use super::*;

#[derive(Default)]
pub(super) struct DropOrder {
    pub(super) parent_drops: AtomicUsize,
    pub(super) child_start_completed: std::sync::atomic::AtomicBool,
    retired_after_start: std::sync::atomic::AtomicBool,
}

#[derive(Clone)]
pub(super) struct ParentDrop(Arc<DropOrder>);

impl Drop for ParentDrop {
    fn drop(&mut self) {
        self.0.retired_after_start.store(
            self.0.child_start_completed.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
        self.0.parent_drops.fetch_add(1, Ordering::SeqCst);
    }
}

fn prepare_copy<'owner>(
    host: &'owner ToolHost<Probe, Runtime>,
    callback: &Callback,
    rpc: &NativeRpc<Remote>,
) -> DeferredNative<'owner, Probe> {
    let services = callback.services(None);
    let handle = unsafe {
        host.register_native_image_thread(callback.identity(), State::seeded())
            .unwrap()
    };
    let lease = unsafe {
        host.enter_native_callback(handle, callback.identity())
            .unwrap()
    };
    let mut call = event(0);
    call.number = libc::SYS_fork;
    let result = unsafe {
        host.with_native_guest(lease, &services, rpc, &mut call, |tool, guest, _| {
            let mut stack = crate::tool_host::drive_native_ready(guest.stack());
            let saved = stack.push(0x7197_u64).as_raw();
            tool.saved_stack.store(saved, Ordering::SeqCst);
            drop(stack.commit().unwrap());
            NativeCallbackOutcome::<Result<(), Error>>::Deferred {
                number: libc::SYS_fork,
                args: [0; 6],
            }
        })
        .unwrap()
    };
    match result {
        NativeCallResult::Deferred(owner) => owner,
        NativeCallResult::Return(()) => panic!("copy operation lost its original continuation"),
    }
}

#[test]
fn native_copy_refuses_same_process_without_consuming_the_original() {
    let server = Server::new();
    let (host, _peer) = make_host();
    let callback = Callback::new(91);
    let config = host.rpc.shared_config();
    let rpc = NativeRpc::new(server.path.clone(), Arc::clone(&config)).unwrap();
    let mut original = Some(prepare_copy(&host, &callback, &rpc));
    let error = unsafe {
        host.rebind_copied_native_process(&mut original, &callback.services(None), &rpc, Runtime)
    }
    .err()
    .expect("the current parent is not its copied child");
    assert_eq!(error.raw_os_error(), Some(libc::ESTALE));
    assert_eq!(
        original.as_ref().unwrap().operation(),
        (libc::SYS_fork, [0; 6])
    );
    let tool = host.tool.lock();
    let probe = tool.as_deref().unwrap().as_ref().unwrap();
    assert_eq!(probe.initializer_entries.load(Ordering::SeqCst), 0);
    assert_eq!(
        unsafe { *(probe.saved_stack.load(Ordering::SeqCst) as *const u64) },
        0x7197
    );
    drop(tool);
    unsafe {
        original
            .take()
            .unwrap()
            .complete(callback.invocation())
            .unwrap();
    }
    fixture::close_test_primary(&rpc, &callback);
}

#[test]
fn native_copy_actual_child_keeps_tool_scratch_rpc_and_lifecycle() {
    const CHILD: &str = "REVERIE_NATIVE_COPIED_ENTRY_CONTROL";
    if std::env::var_os(CHILD).is_none() {
        // One isolated case owns the actual fork; no unrelated unit test can
        // hold a Rust lock in this subprocess at the copy boundary.
        let path = module_path!()
            .split_once("::")
            .expect("crate-qualified test module")
            .1;
        let name = format!("{path}::native_copy_actual_child_keeps_tool_scratch_rpc_and_lifecycle");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated copied-entry control failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
            "isolated control did not actually select and run its one test"
        );
        return;
    }

    let server = Server::new();
    let (host, _peer) = make_host();
    let callback = Callback::new(91);
    let config = host.rpc.shared_config();
    let rpc = NativeRpc::new(server.path.clone(), Arc::clone(&config)).unwrap();
    let mut original = Some(prepare_copy(&host, &callback, &rpc));
    // This lock remains held in the child copy. Its only Tool pin comes from
    // the original DeferredNative, never a reacquisition of this Tool slot.
    let drop_order = Arc::new(DropOrder::default());
    original
        .as_mut()
        .unwrap()
        .callback_mut()
        .parts()
        .1
        .copied_parent_drop = Some(ParentDrop(Arc::clone(&drop_order)));
    let inherited_fd = rpc.descriptor(callback.identity().physical_pid()).unwrap();
    let mut inherited_metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    assert_eq!(
        unsafe { libc::fstat(inherited_fd, inherited_metadata.as_mut_ptr()) },
        0
    );
    let inherited_metadata = unsafe { inherited_metadata.assume_init() };
    // The child must not reacquire even an inherited leased primary. Its
    // original published number is the actual owner fact, not a requested FD.
    let mut inherited_primary = rpc
        .borrow_mapping_capture_primary(callback.identity().physical_pid())
        .unwrap();
    let inherited_slot = host.tool.lock();
    let original_tool = Arc::as_ptr(inherited_slot.as_ref().unwrap()) as usize;
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe {
            libc::alarm(10);
        }
        let passed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let callback = Callback::new(91);
            let services = callback.services(None);
            // An actual child with the wrong image must not consume its real
            // copied continuation or initialize anything.
            let stale = Callback::new(92);
            let refused = unsafe {
                host.rebind_copied_native_process(
                    &mut original,
                    &stale.services(None),
                    &rpc,
                    Runtime,
                )
            }
            .err()
            .expect("a different image reused the copied continuation");
            assert_eq!(refused.raw_os_error(), Some(libc::ESTALE));
            assert!(original.is_some());
            let local = NativeRpc::local(Arc::new(Remote::default()), Arc::clone(&config));
            assert_eq!(
                unsafe {
                    host.rebind_copied_native_process(&mut original, &services, &local, Runtime)
                }
                .err()
                .expect("copied local route acquired a fake coordinator")
                .kind(),
                io::ErrorKind::Unsupported
            );
            assert!(original.is_some());
            let copied = unsafe {
                host.rebind_copied_native_process(&mut original, &services, &rpc, Runtime)
                    .unwrap()
            };
            let child_host = copied.host;
            let child_rpc = copied.rpc;
            let parent = copied.parent;
            assert!(original.is_none());
            assert_eq!(
                child_rpc.descriptor(callback.identity().physical_pid()),
                None
            );
            assert_eq!(
                child_rpc
                    .borrow_mapping_capture_primary(callback.identity().physical_pid())
                    .err()
                    .unwrap(),
                reverie::MappingCaptureError::Connection
            );
            let (handle, mut pending) = unsafe {
                child_host
                    .initialize_copied_native_thread(
                        &services,
                        &child_rpc,
                        parent,
                        |parent| {
                            assert_eq!((parent.starts, parent.posts, parent.seed), (1, 1, 71));
                            parent.seed = 79;
                            Ok(())
                        },
                        |state, parent| {
                            assert_eq!(parent.seed, 79);
                            assert_eq!(state.parent_seed, Some(79));
                            assert_eq!(state.initialized_for, callback.identity().tid().as_raw());
                            assert_eq!(drop_order.parent_drops.load(Ordering::SeqCst), 0);
                            state.copied_child_order = Some(Arc::clone(&drop_order));
                            Ok(())
                        },
                    )
                    .unwrap()
            };
            assert_eq!(
                child_rpc.descriptor(callback.identity().physical_pid()),
                Some(inherited_fd)
            );
            assert_eq!(
                rpc.descriptor(callback.identity().physical_pid()),
                None,
                "the inherited owner was relabelled as a child connection"
            );
            assert_eq!(callback.count(libc::SYS_dup3), 1);
            assert_eq!(callback.count(libc::SYS_socket), 1);
            let mut child_metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
            assert_eq!(
                unsafe { libc::fstat(inherited_fd, child_metadata.as_mut_ptr()) },
                0
            );
            let child_metadata = unsafe { child_metadata.assume_init() };
            assert_ne!(
                (child_metadata.st_dev, child_metadata.st_ino),
                (inherited_metadata.st_dev, inherited_metadata.st_ino),
                "child retained the parent's actual socket instead of replacing it"
            );
            assert_eq!(
                unsafe { libc::fcntl(inherited_fd, libc::F_GETFD) },
                libc::FD_CLOEXEC
            );
            assert_eq!(
                child_rpc.protect_operation(
                    callback.invocation(),
                    libc::SYS_close,
                    &[inherited_fd as u64, 0, 0, 0, 0, 0],
                    false
                ),
                Some(-i64::from(libc::EBADF))
            );
            assert_eq!(pending.operation(), (libc::SYS_fork, [0; 6]));
            assert_eq!(drop_order.parent_drops.load(Ordering::SeqCst), 0);
            assert!(!drop_order.child_start_completed.load(Ordering::SeqCst));
            let mut post = event(0);
            unsafe {
                child_host
                    .with_native_post_step(
                        &mut pending,
                        &services,
                        &child_rpc,
                        &mut post,
                        |tool, guest, _| {
                            let slot = child_host
                                .tool
                                .try_lock()
                                .expect("fresh Tool slot is unlocked");
                            assert_eq!(Arc::as_ptr(slot.as_ref().unwrap()) as usize, original_tool);
                            drop(slot);
                            assert_eq!(tool.initializer_entries.load(Ordering::SeqCst), 1);
                            assert_eq!(guest.thread_state().order, [1]);
                            assert_eq!(
                                (guest.thread_state().starts, guest.thread_state().posts),
                                (1, 0)
                            );
                            assert_eq!(drop_order.parent_drops.load(Ordering::SeqCst), 1);
                            assert!(drop_order.retired_after_start.load(Ordering::SeqCst));
                            assert_eq!(
                                *(tool.saved_stack.load(Ordering::SeqCst) as *const u64),
                                0x7197
                            );
                            assert_eq!(
                                crate::tool_host::drive_native_ready(guest.send_rpc(Request(312))),
                                Reply(callback.identity().tid().as_raw(), 312)
                            );
                            NativeCallbackOutcome::Ready(Ok(()))
                        },
                    )
                    .unwrap();
            }
            assert_eq!(
                unsafe { child_host.enter_native_callback(handle, callback.identity()) }
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            // This is the final native post-event boundary, after all real
            // child-side bookkeeping and scratch use above.
            unsafe {
                pending.complete(callback.invocation()).unwrap();
            }
            let next = unsafe {
                child_host
                    .enter_native_callback(handle, callback.identity())
                    .unwrap()
            };
            unsafe {
                child_host
                    .with_native_guest(next, &services, &child_rpc, &mut post, |_tool, guest, _| {
                        assert_eq!(
                            (guest.thread_state().starts, guest.thread_state().posts),
                            (1, 0)
                        );
                        NativeCallbackOutcome::Ready(Ok(()))
                    })
                    .unwrap();
            }
        }))
        .is_ok();
        // Inherited guards/registries are intentionally not dropped through
        // their parent owner in this actual child.
        unsafe {
            libc::_exit(if passed { 0 } else { 101 });
        }
    }
    drop(inherited_slot);
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if waited == child {
            break;
        }
        assert_eq!(waited, 0);
        if std::time::Instant::now() >= deadline {
            unsafe {
                libc::kill(child, libc::SIGKILL);
                libc::waitpid(child, &mut status, 0);
            }
            panic!("copied entry locked an inherited owner or failed to complete");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    inherited_primary.release(true);
    assert_eq!(
        rpc.descriptor(callback.identity().physical_pid()),
        Some(inherited_fd)
    );
    let mut parent_metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    assert_eq!(
        unsafe { libc::fstat(inherited_fd, parent_metadata.as_mut_ptr()) },
        0
    );
    let parent_metadata = unsafe { parent_metadata.assume_init() };
    assert_eq!(
        (parent_metadata.st_dev, parent_metadata.st_ino),
        (inherited_metadata.st_dev, inherited_metadata.st_ino)
    );
    assert_eq!(
        rpc.application(callback.invocation())
            .exchange(Request(313))
            .unwrap(),
        Reply(callback.identity().tid().as_raw(), 313)
    );
    assert_eq!(
        host.tool
            .lock()
            .as_deref()
            .unwrap()
            .as_ref()
            .unwrap()
            .initializer_entries
            .load(Ordering::SeqCst),
        0
    );
    // The parent's own COW continuation is still genuine and independently
    // completed; the child's fresh registry never modified it.
    unsafe {
        original
            .take()
            .unwrap()
            .complete(callback.invocation())
            .unwrap();
    }
    fixture::close_test_primary(&rpc, &callback);
}

#[test]
fn native_copy_real_post_precedes_later_initializer_and_thread_start() {
    const CHILD: &str = "REVERIE_NATIVE_COPIED_POST_BEFORE_INIT_CONTROL";
    if std::env::var_os(CHILD).is_none() {
        let path = module_path!()
            .split_once("::")
            .expect("crate-qualified test module")
            .1;
        let name =
            format!("{path}::native_copy_real_post_precedes_later_initializer_and_thread_start");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated delayed initializer failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
            "isolated delayed initializer did not run its one actual test"
        );
        return;
    }

    let server = Server::new();
    let (host, _peer) = make_host();
    let callback = Callback::new(91);
    let rpc = NativeRpc::new(server.path.clone(), host.rpc.shared_config()).unwrap();
    let mut original = Some(prepare_copy(&host, &callback, &rpc));
    let drop_order = Arc::new(DropOrder::default());
    original
        .as_mut()
        .unwrap()
        .callback_mut()
        .parts()
        .1
        .copied_parent_drop = Some(ParentDrop(Arc::clone(&drop_order)));
    // Both actual inherited locks remain held in the COW child. Neither the
    // transfer nor its early post-completion may reacquire them.
    let mut inherited_primary = rpc
        .borrow_mapping_capture_primary(callback.identity().physical_pid())
        .unwrap();
    let inherited_slot = host.tool.lock();
    let original_tool = Arc::as_ptr(inherited_slot.as_ref().unwrap()) as usize;
    let saved = inherited_slot
        .as_deref()
        .unwrap()
        .as_ref()
        .unwrap()
        .saved_stack
        .load(Ordering::SeqCst);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe {
            libc::alarm(10);
        }
        let passed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let callback = Callback::new(91);
            let services = callback.services(None);
            let copied = unsafe {
                host.rebind_copied_native_process(&mut original, &services, &rpc, Runtime)
                    .unwrap()
            };
            let child_host = copied.host;
            let child_rpc = copied.rpc;
            let mut parent = Some(copied.parent);
            assert!(original.is_none());
            assert_eq!(unsafe { *(saved as *const u64) }, 0x7197);
            let stale = Callback::new(92);
            assert_eq!(
                unsafe {
                    child_host.complete_copied_native_post(
                        &stale.services(None),
                        &child_rpc,
                        &mut parent,
                    )
                }
                .err()
                .expect("wrong image consumed copied post owner")
                .raw_os_error(),
                Some(libc::ESTALE)
            );
            assert!(parent.is_some(), "refusal consumed original copied record");
            // This is the actual child's final post boundary. A later API
            // call cannot authorize it by supplying a serialized bool.
            let completed = unsafe {
                child_host
                    .complete_copied_native_post(&services, &child_rpc, &mut parent)
                    .unwrap()
            };
            assert!(parent.is_none());
            assert_eq!(
                unsafe {
                    child_host.complete_copied_native_post(&services, &child_rpc, &mut parent)
                }
                .err()
                .expect("copied post owner completed twice")
                .raw_os_error(),
                Some(libc::ESTALE)
            );
            assert_eq!(callback.count(libc::SYS_socket), 0);
            assert_eq!(callback.count(libc::SYS_dup3), 0);
            assert_eq!(
                child_rpc.descriptor(callback.identity().physical_pid()),
                None
            );
            assert_eq!(drop_order.parent_drops.load(Ordering::SeqCst), 0);
            assert!(!drop_order.child_start_completed.load(Ordering::SeqCst));
            assert_eq!(unsafe { *(saved as *const u64) }, 0x7197);
            {
                let slot = child_host
                    .tool
                    .try_lock()
                    .expect("fresh Tool slot unlocked at post");
                assert_eq!(Arc::as_ptr(slot.as_ref().unwrap()) as usize, original_tool);
                assert_eq!(
                    slot.as_deref()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .initializer_entries
                        .load(Ordering::SeqCst),
                    0
                );
            }
            // The native owner now reaches the maintained later initializer.
            // It still has the same Tool, original parent and live scratch.
            let handle = unsafe {
                child_host
                    .initialize_postcompleted_copied_native_thread(
                        &services,
                        &child_rpc,
                        completed,
                        |parent| {
                            assert_eq!((parent.starts, parent.posts, parent.seed), (1, 1, 71));
                            parent.seed = 79;
                            Ok(())
                        },
                        |state, parent| {
                            assert_eq!(parent.seed, 79);
                            assert_eq!(state.parent_seed, Some(79));
                            assert_eq!(state.initialized_for, callback.identity().tid().as_raw());
                            assert_eq!(drop_order.parent_drops.load(Ordering::SeqCst), 0);
                            state.copied_child_order = Some(Arc::clone(&drop_order));
                            Ok(())
                        },
                    )
                    .unwrap()
            };
            assert_eq!(callback.count(libc::SYS_socket), 1);
            assert_eq!(callback.count(libc::SYS_dup3), 1);
            assert_eq!(drop_order.parent_drops.load(Ordering::SeqCst), 0);
            assert!(!drop_order.child_start_completed.load(Ordering::SeqCst));
            assert_eq!(unsafe { *(saved as *const u64) }, 0x7197);
            // Real common entry must run the child's actual thread-start once
            // before dropping its original parent, without a synthetic exec.
            let lease = unsafe {
                child_host
                    .enter_native_callback(handle, callback.identity())
                    .unwrap()
            };
            let mut first = event(0);
            unsafe {
                child_host
                    .with_native_guest(
                        lease,
                        &services,
                        &child_rpc,
                        &mut first,
                        |tool, guest, _| {
                            assert_eq!(tool.initializer_entries.load(Ordering::SeqCst), 1);
                            assert_eq!(
                                (guest.thread_state().starts, guest.thread_state().posts),
                                (1, 0)
                            );
                            assert_eq!(guest.thread_state().order, [1]);
                            assert_eq!(drop_order.parent_drops.load(Ordering::SeqCst), 1);
                            assert!(drop_order.retired_after_start.load(Ordering::SeqCst));
                            assert_eq!(
                                crate::tool_host::drive_native_ready(guest.send_rpc(Request(314))),
                                Reply(callback.identity().tid().as_raw(), 314)
                            );
                            NativeCallbackOutcome::Ready(Ok(()))
                        },
                    )
                    .unwrap();
            }
            let lease = unsafe {
                child_host
                    .enter_native_callback(handle, callback.identity())
                    .unwrap()
            };
            unsafe {
                child_host
                    .with_native_guest(
                        lease,
                        &services,
                        &child_rpc,
                        &mut first,
                        |tool, guest, _| {
                            assert_eq!(tool.initializer_entries.load(Ordering::SeqCst), 1);
                            assert_eq!(
                                (guest.thread_state().starts, guest.thread_state().posts),
                                (1, 0)
                            );
                            assert_eq!(drop_order.parent_drops.load(Ordering::SeqCst), 1);
                            NativeCallbackOutcome::Ready(Ok(()))
                        },
                    )
                    .unwrap();
            }
        }))
        .is_ok();
        // Never run inherited guards/registries' parent cleanup in the child.
        unsafe {
            libc::_exit(if passed { 0 } else { 101 });
        }
    }
    drop(inherited_slot);
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if waited == child {
            break;
        }
        assert_eq!(waited, 0);
        if std::time::Instant::now() >= deadline {
            unsafe {
                libc::kill(child, libc::SIGKILL);
                libc::waitpid(child, &mut status, 0);
            }
            panic!("delayed copied initializer locked an inherited owner or failed to complete");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    inherited_primary.release(true);
    assert_eq!(
        rpc.application(callback.invocation())
            .exchange(Request(315))
            .unwrap(),
        Reply(callback.identity().tid().as_raw(), 315)
    );
    assert_eq!(
        host.tool
            .lock()
            .as_deref()
            .unwrap()
            .as_ref()
            .unwrap()
            .initializer_entries
            .load(Ordering::SeqCst),
        0
    );
    unsafe {
        original
            .take()
            .unwrap()
            .complete(callback.invocation())
            .unwrap();
    }
    fixture::close_test_primary(&rpc, &callback);
}
