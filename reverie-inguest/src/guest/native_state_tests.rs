/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */
//! Controls for the actual native state-entry API. These do not qualify a
//! native loader, callback services, Tool lifecycle or a physical guest.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::time::Duration;

use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::codec::encode;

use super::super::rpc::GuestRpcStream;
use super::native_state::NativeThreadIdentity;
use super::*;

#[derive(Default)]
struct Probe;

struct Remote;
impl Default for Remote {
    fn default() -> Self {
        panic!("the test coordinator owns this state")
    }
}

#[reverie::global_tool]
impl GlobalTool for Remote {
    type Config = u64;
    type Request = ();
    type Response = ();
    async fn receive_rpc(&self, _: Pid, _: ()) {
        panic!("state entry must not manufacture a Tool RPC")
    }
}

#[reverie::tool]
impl Tool for Probe {
    type GlobalState = Remote;
    type ThreadState = u64;
}

struct Runtime;
impl HostRuntime for Runtime {
    fn fork_child_rebind(&self) {
        panic!("no fork in this storage control")
    }
    fn emit_stage(&self, _: &[u8]) {}
    fn fork_child_reset(&self, _: &SyscallEvent) {
        panic!("no fork in this storage control")
    }
    fn cpuid_interception_enabled(&self) -> bool {
        false
    }
    fn exit_process_stats(&self, _: Pid) -> io::Result<()> {
        panic!("no process exit in this storage control")
    }
    fn read_clock(&self) -> io::Result<u64> {
        panic!("no branch clock in this storage control")
    }
    fn signal_action_supported(&self, _: i64, _: [u64; 6]) -> bool {
        false
    }
    fn reserved_signal_mask(&self) -> u64 {
        0
    }
}

fn make_host(native: bool) -> (ToolHost<Probe, Runtime>, UnixStream) {
    let (client, mut peer) = UnixStream::pair().unwrap();
    let config = encode(&71_u64).unwrap();
    peer.write_all(&(config.len() as u32).to_be_bytes())
        .unwrap();
    peer.write_all(&config).unwrap();
    let tid = raw_pid(libc::SYS_gettid);
    let client =
        BlockingRpcClient::from_connected_stream(GuestRpcStream::from(client), tid).unwrap();
    let rpc = CoordinatorRpc::from_live_client("unused-native-state-test", client, |_, _| {
        panic!("state entry must not reconnect")
    })
    .unwrap();
    let host = if native {
        // This fixture is the owner of the test process/thread and genuine
        // connected config. No physical native Guest is invoked.
        unsafe { ToolHost::new_native(Probe, rpc, tid, HashSet::new(), false, Runtime) }
    } else {
        ToolHost::new(Probe, rpc, tid, HashSet::new(), false, Runtime)
    };
    (host, peer)
}

fn identity(image: u64) -> NativeThreadIdentity {
    let pid = raw_pid(libc::SYS_getpid);
    let tid = raw_pid(libc::SYS_gettid);
    // Model only the native image owner; the kernel IDs are this actual
    // callback-entry thread. This grants no loader or private-phase credit.
    unsafe { NativeThreadIdentity::from_admitted(pid, tid, pid, tid, image).unwrap() }
}

#[test]
fn native_callback_entry_allows_a_sibling_and_retains_its_own_scratch() {
    // Native state storage must not require an extra ordinary connection.
    // This nonexistent path is retained as a fact, never opened here.
    let config = Arc::new(71_u64);
    let config_owner = CoordinatorRpc::<Remote>::from_native_configuration(
        "/unused-native-config-owner-test",
        Arc::clone(&config),
    )
    .unwrap();
    assert!(Arc::ptr_eq(&config, &config_owner.shared_config()));
    assert_eq!(config_owner.raw_fd(), -1);
    assert!(config_owner.send_blocking_unless_in_flight(()).is_err());
    let native_host = unsafe {
        ToolHost::new_native(
            Probe,
            config_owner,
            raw_pid(libc::SYS_getpid),
            HashSet::new(),
            false,
            Runtime,
        )
    };
    let id = identity(1);
    let handle = unsafe { native_host.register_native_thread(id, 71).unwrap() };
    let callback = unsafe { native_host.enter_native_callback(handle, id).unwrap() };
    unsafe { callback.complete(id).unwrap() };
    assert_eq!(
        unsafe { native_host.retire_native_thread(handle, id).unwrap() },
        71
    );

    let (host, _peer) = make_host(true);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let host_ref = &host;
        let first = scope.spawn(move || {
            let id = identity(1);
            let handle = unsafe { host_ref.register_native_thread(id, 71).unwrap() };
            let mut callback = unsafe { host_ref.enter_native_callback(handle, id).unwrap() };
            {
                let tool = host_ref
                    .tool
                    .try_lock()
                    .expect("Tool guard released at entry");
                assert!(std::ptr::eq(
                    callback.parts().0,
                    tool.as_deref().unwrap().as_ref().unwrap()
                ));
            }
            assert!(host_ref.states.try_lock().is_some());
            assert_eq!(*callback.parts().1, 71);
            *callback.parts().1 = 97;
            let mut stack = callback.stack();
            let saved = stack.push(0x7197_u64).as_raw();
            drop(stack.commit().unwrap());
            entered_tx.send(()).unwrap();
            // A real blocking operation while the actual callback-entry
            // lease is live. If it retained a process registry/Tool guard,
            // the sibling entry below could not complete.
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(unsafe { (saved as *const u64).read() }, 0x7197);
            assert_eq!(*callback.parts().1, 97);
            unsafe { callback.complete(id).unwrap() };
            assert_eq!(
                unsafe { host_ref.retire_native_thread(handle, id).unwrap() },
                97
            );
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let id = identity(1);
        let handle = unsafe { host.register_native_thread(id, 83).unwrap() };
        let mut callback = unsafe { host.enter_native_callback(handle, id).unwrap() };
        assert_eq!(*callback.parts().1, 83);
        let mut stack = callback.stack();
        stack.push(0x8383_u64);
        drop(stack.commit().unwrap());
        unsafe { callback.complete(id).unwrap() };
        assert_eq!(
            unsafe { host.retire_native_thread(handle, id).unwrap() },
            83
        );
        release_tx.send(()).unwrap();
        first.join().unwrap();
    });
}

#[test]
fn native_callback_identity_reentry_and_retirement_refuse() {
    let (host, _peer) = make_host(true);
    let id = identity(1);
    let handle = unsafe { host.register_native_thread(id, 71).unwrap() };
    assert_eq!(
        unsafe { host.register_native_thread(id, 0) }
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        unsafe { host.enter_native_callback(handle, identity(2)) }
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ESTALE)
    );
    let callback = unsafe { host.enter_native_callback(handle, id).unwrap() };
    assert_eq!(
        unsafe { host.enter_native_callback(handle, id) }
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        unsafe { host.retire_native_thread(handle, id) }
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    let (other, _other_peer) = make_host(true);
    assert_eq!(
        unsafe { other.enter_native_callback(handle, id) }
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ESTALE)
    );
    unsafe { callback.complete(id).unwrap() };
    assert_eq!(
        unsafe { host.retire_native_thread(handle, id).unwrap() },
        71
    );
    assert_eq!(
        unsafe { host.enter_native_callback(handle, id) }
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ESTALE)
    );
}

#[test]
fn abandoned_native_callback_cannot_be_reentered_or_retired_as_success() {
    let (host, _peer) = make_host(true);
    let id = identity(1);
    let handle = unsafe { host.register_native_thread(id, 71).unwrap() };
    let mut callback = unsafe { host.enter_native_callback(handle, id).unwrap() };
    *callback.parts().1 = 97;
    drop(callback);
    assert_eq!(
        unsafe { host.enter_native_callback(handle, id) }
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::EIO)
    );
    assert_eq!(
        unsafe { host.retire_native_thread(handle, id) }
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::EIO)
    );
}

#[test]
fn native_callback_completion_requires_original_image_identity() {
    let (host, _peer) = make_host(true);
    let id = identity(1);
    let handle = unsafe { host.register_native_thread(id, 71).unwrap() };
    let callback = unsafe { host.enter_native_callback(handle, id).unwrap() };
    assert_eq!(
        unsafe { callback.complete(identity(2)) }
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ESTALE)
    );
    assert_eq!(
        unsafe { host.enter_native_callback(handle, id) }
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::EIO)
    );
}

#[test]
fn local_host_cannot_register_native_callback_state() {
    let (host, _peer) = make_host(false);
    assert_eq!(
        unsafe { host.register_native_thread(identity(1), 71) }
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Unsupported
    );
}
