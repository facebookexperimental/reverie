/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Real shared-wire socket and exclusive-owner controls. Mapping-capture tests
//! below exercise the ownership/release interface, not a kernel MM transaction.

use std::sync::Arc;

use super::super::native_test_support as fixture;
use super::super::native_test_support::Callback;
use super::super::native_test_support::Remote;
use super::super::native_test_support::Reply;
use super::super::native_test_support::Request;
use super::super::native_test_support::Server;
use super::*;

fn owner(server: &Server) -> NativeRpc<Remote> {
    NativeRpc::new(server.path.clone(), Arc::new(71)).unwrap()
}

#[test]
fn native_rpc_real_socket_keeps_context_config_short_io_and_primary_fd_protected() {
    let server = Server::new();
    let owner = owner(&server);
    let first = Callback::new(1);
    let second = Callback::new(1);
    assert_eq!(
        owner
            .application(first.invocation())
            .exchange(Request(1))
            .unwrap(),
        Reply(first.identity().tid().as_raw(), 1)
    );
    let first_calls = first.calls.lock().unwrap().len();
    let fd = owner.descriptor(first.identity().physical_pid()).unwrap();
    assert!(fd >= 1024);
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, libc::FD_CLOEXEC);
    assert_eq!(
        owner
            .application(second.invocation())
            .exchange(Request(2))
            .unwrap(),
        Reply(second.identity().tid().as_raw(), 2)
    );
    assert_eq!(
        first.calls.lock().unwrap().len(),
        first_calls,
        "cached a prior callback context"
    );
    assert_eq!(first.count(libc::SYS_socket), 1);
    assert_eq!(second.count(libc::SYS_socket), 0);
    assert!(first.count(libc::SYS_read) > 1 && first.count(libc::SYS_write) > 1);
    assert!(second.count(libc::SYS_read) > 1 && second.count(libc::SYS_write) > 1);
    assert_eq!(owner.application(second.invocation()).config(), &71);
    let args = [fd as u64, 0, 0, 0, 0, 0];
    assert_eq!(
        owner.protect_operation(second.invocation(), libc::SYS_close, &args, true),
        None
    );
    assert_eq!(
        owner.protect_operation(second.invocation(), libc::SYS_close, &args, false),
        Some(-i64::from(libc::EBADF))
    );
    assert_eq!(
        owner.protect_operation(second.invocation(), libc::SYS_fstat, &args, true),
        Some(-i64::from(libc::EBADF))
    );
    assert_eq!(owner.descriptor(first.identity().physical_pid()), Some(fd));
    assert_eq!(server.global.seen.lock().unwrap().len(), 2);
    fixture::close_test_primary(&owner, &second);
}

#[test]
fn native_capture_release_is_once_non_io_and_unusable_primary_stays_reserved() {
    let server = Server::new();
    let owner = owner(&server);
    let callback = Callback::new(1);
    let contender = Callback::new(1);
    owner.prepare(callback.invocation()).unwrap();
    let pid = callback.identity().physical_pid();
    let fd = owner.descriptor(pid).unwrap();
    let mut capture = owner.borrow_mapping_capture_primary(pid).unwrap();
    assert_eq!(capture.fd(), fd);
    assert_eq!(
        owner.borrow_mapping_capture_primary(pid).err().unwrap(),
        reverie::MappingCaptureError::Connection
    );
    // A real exchange while capture owns the exact primary uses an independent
    // connection, never waits for capture or borrows its native context.
    assert_eq!(
        owner
            .application(contender.invocation())
            .exchange(Request(17))
            .unwrap(),
        Reply(contender.identity().tid().as_raw(), 17)
    );
    assert_eq!(contender.count(libc::SYS_socket), 1);
    fixture::assert_independent_connection_retired(&contender, fd);
    let before_release = callback.calls.lock().unwrap().len();
    let cookie = &mut capture as *mut MappingCapturePrimary<'_, Remote> as usize;
    unsafe { release_mapping_capture_primary::<Remote>(cookie, 0) };
    assert!(capture.is_released());
    // A duplicate release is inert; it cannot publish another generation or
    // close/allocate/decode/reconnect from the native transaction boundary.
    unsafe { release_mapping_capture_primary::<Remote>(cookie, 1) };
    assert_eq!(callback.calls.lock().unwrap().len(), before_release);
    assert_eq!(owner.descriptor(pid), Some(fd));
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, libc::FD_CLOEXEC);
    assert!(
        owner
            .application(callback.invocation())
            .exchange(Request(18))
            .is_err()
    );
    assert!(owner.prepare(callback.invocation()).is_err());
    assert_eq!(
        callback.calls.lock().unwrap().len(),
        before_release,
        "unusable framing was replaced"
    );
    assert_eq!(
        server
            .global
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|(_, n)| *n)
            .collect::<Vec<_>>(),
        [17]
    );
    assert_eq!(
        owner.protect_operation(
            callback.invocation(),
            libc::SYS_close,
            &[fd as u64, 0, 0, 0, 0, 0],
            false
        ),
        Some(-i64::from(libc::EBADF))
    );
    fixture::close_test_primary(&owner, &callback);
}

#[test]
fn native_rpc_serialization_and_decode_panics_leave_no_primary_io_guard() {
    let server = Server::new();
    let owner = owner(&server);
    let callback = Callback::new(1);
    let application = owner.application(callback.invocation());
    owner.prepare(callback.invocation()).unwrap();
    let fd = owner
        .descriptor(callback.identity().physical_pid())
        .unwrap();
    let before = callback.calls.lock().unwrap().len();
    let encoding = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        application.exchange(Request(u64::MAX))
    }));
    assert!(encoding.is_err());
    assert_eq!(
        callback.calls.lock().unwrap().len(),
        before,
        "serialization ran inside socket ownership"
    );
    assert_eq!(
        application.exchange(Request(3)).unwrap(),
        Reply(callback.identity().tid().as_raw(), 3)
    );
    let decoding = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        application.exchange(Request(99))
    }));
    assert!(decoding.is_err());
    assert_eq!(
        application.exchange(Request(4)).unwrap(),
        Reply(callback.identity().tid().as_raw(), 4)
    );
    assert_eq!(
        owner.descriptor(callback.identity().physical_pid()),
        Some(fd)
    );
    assert_eq!(
        callback.count(libc::SYS_socket),
        1,
        "response decoding poisoned an already released exchange"
    );
    assert_eq!(
        server
            .global
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|(_, n)| *n)
            .collect::<Vec<_>>(),
        [3, 99, 4]
    );
    fixture::close_test_primary(&owner, &callback);
}

#[test]
fn native_capture_unprepared_borrow_refuses_without_connect_or_recovery() {
    let server = Server::new();
    let owner = owner(&server);
    let callback = Callback::new(1);
    let pid = callback.identity().physical_pid();
    assert_eq!(
        owner.borrow_mapping_capture_primary(pid).err().unwrap(),
        reverie::MappingCaptureError::Connection
    );
    assert!(callback.calls.lock().unwrap().is_empty());
    assert!(server.global.seen.lock().unwrap().is_empty());
    owner.prepare(callback.invocation()).unwrap();
    assert_eq!(callback.count(libc::SYS_socket), 1);
    let mut capture = owner.borrow_mapping_capture_primary(pid).unwrap();
    capture.release(true);
    assert_eq!(
        owner
            .application(callback.invocation())
            .exchange(Request(7))
            .unwrap(),
        Reply(callback.identity().tid().as_raw(), 7)
    );
    assert_eq!(
        callback.count(libc::SYS_socket),
        1,
        "refused borrow or usable release fabricated recovery"
    );
    fixture::close_test_primary(&owner, &callback);
}

#[test]
fn native_rpc_wrong_current_owner_refuses_before_descriptor_or_request() {
    let server = Server::new();
    let owner = owner(&server);
    let callback = Callback::new(1);
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let error = owner
                    .application(callback.invocation())
                    .exchange(Request(1))
                    .unwrap_err();
                assert!(
                    matches!(error, RpcError::Io(ref e) if e.raw_os_error() == Some(libc::ESTALE))
                );
            })
            .join()
            .unwrap();
    });
    assert!(callback.calls.lock().unwrap().is_empty());
    assert!(
        owner
            .descriptor(callback.identity().physical_pid())
            .is_none()
    );
    assert!(server.global.seen.lock().unwrap().is_empty());
}

#[test]
fn native_local_rpc_awaits_the_real_global_without_socket_or_sync_fallback() {
    let global = Arc::new(Remote::default());
    let (entered, receiving) = std::sync::mpsc::channel();
    *global.first_pending.lock().unwrap() = Some(entered);
    let config = Arc::new(71);
    let owner = Arc::new(NativeRpc::local(Arc::clone(&global), Arc::clone(&config)));
    let worker_owner = Arc::clone(&owner);
    let worker = std::thread::spawn(move || {
        let callback = Callback::new(1);
        worker_owner.prepare(callback.invocation()).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let answer = runtime.block_on(
            worker_owner
                .application(callback.invocation())
                .send_rpc(Request(100)),
        );
        assert_eq!(answer, Reply(callback.identity().tid().as_raw(), 100));
        assert!(callback.calls.lock().unwrap().is_empty());
    });
    receiving
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let callback = Callback::new(1);
    let application = owner.application(callback.invocation());
    assert!(matches!(
        application.try_send_rpc_sync(Request(17)),
        Err(Request(17))
    ));
    assert!(application.exchange(Request(18)).is_err());
    assert_eq!(
        crate::tool_host::drive_native_ready(application.send_rpc(Request(101))),
        Reply(callback.identity().tid().as_raw(), 101)
    );
    worker.join().unwrap();
    assert!(Arc::ptr_eq(owner.shared_config(), &config));
    assert_eq!(owner.descriptor(callback.identity().physical_pid()), None);
    assert!(
        owner
            .borrow_mapping_capture_primary(callback.identity().physical_pid())
            .is_err()
    );
    assert!(callback.calls.lock().unwrap().is_empty());
    assert_eq!(
        global
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|(_, n)| *n)
            .collect::<Vec<_>>(),
        [100, 101]
    );
    let background =
        unsafe { NativeBackgroundRpc::local_from_admitted(Arc::clone(&global), config) };
    let view = background.for_thread(callback.identity().tid()).unwrap();
    assert!(matches!(
        view.try_send_rpc_sync(Request(19)),
        Err(Request(19))
    ));
    assert!(view.exchange(Request(20)).is_err());
    assert_eq!(
        crate::tool_host::drive_native_ready(view.send_rpc(Request(21))),
        Reply(callback.identity().tid().as_raw(), 21)
    );
}

/// `ACTIVE_ROUTE` must stay zero-initialized (.tbss): `None` takes the zero
/// value of `RouteKind`'s niche. A nonzero initializer moves the thread-local
/// into .tdata, ahead of the allocator cell the native artifact qualifier reads
/// at a fixed TLS offset. Only the niche byte of a `None` is defined, so only
/// that byte is read.
#[test]
fn an_empty_active_route_is_all_zero_in_its_niche() {
    assert_eq!(
        std::mem::size_of::<Option<ErasedRoute>>(),
        std::mem::size_of::<ErasedRoute>(),
        "None must use RouteKind's niche",
    );
    // Read the declared thread-local's initial value, on a thread that has
    // never installed a route.
    let (tag, initial_none) = std::thread::spawn(|| {
        ACTIVE_ROUTE.with(|active| {
            let tag = unsafe {
                active
                    .as_ptr()
                    .cast::<u8>()
                    .add(std::mem::offset_of!(ErasedRoute, kind))
                    .read()
            };
            (tag, active.get().is_none())
        })
    })
    .join()
    .unwrap();
    assert!(initial_none);
    assert_eq!(tag, 0);
}
