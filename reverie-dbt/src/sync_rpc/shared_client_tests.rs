/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use serde::Deserialize;

use super::*;

const CHILD: &str = "REVERIE_DBT_SHARED_RPC_TEST_CHILD";

#[derive(Deserialize)]
struct Request(u64);

impl Serialize for Request {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        assert_ne!(self.0, u64::MAX, "intentional request serialization panic");
        serializer.serialize_u64(self.0)
    }
}

#[derive(Debug, PartialEq, Serialize)]
struct Response(i32, u64);

impl<'de> Deserialize<'de> for Response {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (from, value) = <(i32, u64)>::deserialize(deserializer)?;
        assert_ne!(value, 99, "intentional response deserialization panic");
        Ok(Self(from, value))
    }
}

#[derive(Default)]
struct Global {
    requests: Mutex<Vec<(i32, u64)>>,
    released: AtomicBool,
    release: tokio::sync::Notify,
}

#[reverie::global_tool]
impl GlobalTool for Global {
    type Request = Request;
    type Response = Response;
    type Config = u64;

    async fn receive_rpc(&self, from: Tid, request: Request) -> Response {
        self.requests
            .lock()
            .unwrap()
            .push((from.as_raw(), request.0));
        if request.0 == 100 && !self.released.load(Ordering::SeqCst) {
            self.release.notified().await;
        } else if request.0 == 101 {
            self.released.store(true, Ordering::SeqCst);
            self.release.notify_one();
        }
        Response(from.as_raw(), request.0)
    }
}

#[derive(Default)]
struct Callback {
    calls: Vec<(i64, i32)>,
    interrupted_read: bool,
    interrupted_write: bool,
    wrote: bool,
    awaiting_response: Option<std::sync::mpsc::Sender<()>>,
    fail_dup3: bool,
}

impl Callback {
    fn send(&mut self, tid: i32, value: u64) -> Response {
        send_rpc_from_guest::<Global>(
            self as *mut Self as usize,
            invoke_callback,
            Tid::from_raw(tid),
            &83,
            Request(value),
        )
    }

    fn count(&self, number: i64) -> usize {
        self.calls
            .iter()
            .filter(|(call, _)| *call == number)
            .count()
    }
}

// Real Linux socket I/O, reached only through the supplied callback context.
// Force short I/O and EINTR without substituting a transport or a mock response.
unsafe extern "C" fn invoke_callback(context: usize, number: i64, args: *const u64) -> i64 {
    let state = unsafe { &mut *(context as *mut Callback) };
    let mut args = unsafe { args.cast::<[u64; 6]>().read() };
    state.calls.push((number, args[0] as i32));
    if number == libc::SYS_dup3 && state.fail_dup3 {
        return -i64::from(libc::EBUSY);
    }
    if number == libc::SYS_read {
        if !std::mem::replace(&mut state.interrupted_read, true) {
            return -i64::from(libc::EINTR);
        }
        if state.wrote
            && let Some(sender) = state.awaiting_response.take()
        {
            sender.send(()).unwrap();
        }
        args[2] = args[2].min(2);
    } else if number == libc::SYS_write {
        if !std::mem::replace(&mut state.interrupted_write, true) {
            return -i64::from(libc::EINTR);
        }
        args[2] = args[2].min(2);
        state.wrote = true;
    }
    let result =
        unsafe { libc::syscall(number, args[0], args[1], args[2], args[3], args[4], args[5]) };
    if result == -1 {
        -i64::from(io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        result
    }
}

fn exercise_both_paths() {
    assert_eq!(
        send_rpc::<Global>(Tid::from_raw(11), &83, Request(1)),
        Response(11, 1)
    );
    assert_eq!(
        send_rpc::<Global>(Tid::from_raw(12), &83, Request(2)),
        Response(12, 2)
    );
    std::thread::spawn(|| {
        assert_eq!(
            send_rpc::<Global>(Tid::from_raw(21), &83, Request(3)),
            Response(21, 3)
        );
    })
    .join()
    .unwrap();

    let mut first = Callback::default();
    let mut second = Callback::default();
    assert_eq!(first.send(31, 4), Response(31, 4));
    let first_calls = first.calls.len();
    assert_eq!(second.send(32, 5), Response(32, 5));
    assert_eq!(
        first.calls.len(),
        first_calls,
        "a stale callback context was reused"
    );
    assert_eq!(first.count(libc::SYS_socket), 1);
    assert_eq!(
        second.count(libc::SYS_socket),
        0,
        "the configured connection was not reused"
    );
    assert!(second.count(libc::SYS_read) > 1 && second.count(libc::SYS_write) > 1);

    // The primary's NUMBER remains owned through real same-process path
    // replacement. No old owner may drop the newly installed socket.
    let pid = std::process::id();
    let primary = GUEST_CLIENT.descriptor(pid).unwrap();
    assert!(primary >= 1024);
    assert_eq!(
        unsafe { libc::fcntl(primary, libc::F_GETFD) },
        libc::FD_CLOEXEC
    );
    let path = PathBuf::from(std::env::var_os(RPC_SOCKET_ENV).unwrap());
    let alias = path.with_file_name("rpc-alias");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    {
        let mut slot = GUEST_CLIENT.connection.lock().unwrap();
        GUEST_CLIENT
            .replace(
                &mut slot,
                &mut second as *mut Callback as usize,
                invoke_callback,
                &alias,
                pid,
            )
            .unwrap();
        assert_eq!(slot.as_ref().unwrap().path, alias);
        assert_eq!(slot.as_ref().unwrap().fd, primary);
    }
    assert_eq!(GUEST_CLIENT.descriptor(pid), Some(primary));
    // send_rpc uses the original configured path and reconnects back without
    // freeing the published number; the actual host still answers correctly.
    assert_eq!(second.send(32, 7), Response(32, 7));
    assert_eq!(GUEST_CLIENT.descriptor(pid), Some(primary));
    for fail_dup3 in [false, true] {
        let mut probe = Callback {
            fail_dup3,
            ..Callback::default()
        };
        let mut slot = GUEST_CLIENT.connection.lock().unwrap();
        let destination = if fail_dup3 {
            alias.clone()
        } else {
            path.with_file_name("missing")
        };
        let error = GUEST_CLIENT
            .replace(
                &mut slot,
                &mut probe as *mut Callback as usize,
                invoke_callback,
                &destination,
                pid,
            )
            .unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(if fail_dup3 { libc::EBUSY } else { libc::ENOENT })
        );
        assert_eq!(slot.as_ref().unwrap().fd, primary);
        assert_eq!(slot.as_ref().unwrap().path, path);
        assert_eq!(GUEST_CLIENT.descriptor(pid), Some(primary));
        assert_eq!(
            unsafe { libc::fcntl(primary, libc::F_GETFD) },
            libc::FD_CLOEXEC
        );
    }
    assert_eq!(second.send(32, 8), Response(32, 8));

    // A4 facts remain readable while the real primary exchange lease is held.
    // Before-Tool close is left for model accounting; physical forwarding
    // refuses it, and the connection remains usable afterward.
    {
        let _held = GUEST_CLIENT.connection.lock().unwrap();
        let args = [primary as u64, 0, 0, 0, 0, 0];
        assert_eq!(
            protect_guest_operation(0, invoke_callback, pid, libc::SYS_close, &args, true),
            None
        );
        assert_eq!(
            protect_guest_operation(0, invoke_callback, pid, libc::SYS_close, &args, false),
            Some(-i64::from(libc::EBADF))
        );
        assert_eq!(
            protect_guest_operation(0, invoke_callback, pid, libc::SYS_read, &args, true),
            Some(-i64::from(libc::EBADF))
        );
        assert_eq!(GUEST_CLIENT.descriptor(pid.wrapping_add(1)), None);
    }
    assert_eq!(second.send(32, 9), Response(32, 9));

    // User codecs run at their old boundaries: before the cached lease and
    // after it. A codec panic must not poison that cache.
    for value in [u64::MAX, 99] {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| second.send(33, value)));
        assert!(result.is_err());
        assert!(!GUEST_CLIENT.connection.is_poisoned());
        assert!(GUEST_CLIENT.connection.try_lock().is_ok());
    }
    let mut uncached = Callback::default();
    {
        let _held = GUEST_CLIENT.connection.lock().unwrap();
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| uncached.send(34, 99)));
        assert!(result.is_err());
        let closed: Vec<_> = uncached
            .calls
            .iter()
            .filter(|(call, _)| *call == libc::SYS_close)
            .collect();
        assert_eq!(
            closed.len(),
            2,
            "temporary socket must close before decode can panic"
        );
        assert_eq!(
            unsafe { libc::fcntl(closed.last().unwrap().1, libc::F_GETFD) },
            -1
        );
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }

    // A genuinely pending cached request can be released by an independent
    // callback. The second callback must use its own uncached connection.
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let waiting = std::thread::spawn(move || {
        let mut callback = Callback {
            awaiting_response: Some(started_tx),
            ..Callback::default()
        };
        assert_eq!(callback.send(41, 100), Response(41, 100));
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut release = Callback::default();
    assert_eq!(release.send(42, 101), Response(42, 101));
    assert_eq!(release.count(libc::SYS_socket), 1);
    assert_eq!(release.count(libc::SYS_close), 2);
    waiting.join().unwrap();

    // Exercise the existing owner-PID mismatch branch without doing unsafe
    // Rust work in a fork child. Real native fork/exec fixtures remain required.
    GUEST_CLIENT
        .connection
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .pid = 0;
    let mut reconnected = Callback::default();
    assert_eq!(reconnected.send(51, 6), Response(51, 6));
    assert_eq!(reconnected.count(libc::SYS_dup3), 1);
    assert_eq!(reconnected.count(libc::SYS_socket), 1);
    assert_eq!(GUEST_CLIENT.descriptor(pid), Some(primary));
    assert_eq!(
        GUEST_CLIENT
            .connection
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .pid,
        pid
    );
    GUEST_CLIENT.primary.store(0, Ordering::Release);
    let fd = GUEST_CLIENT.connection.lock().unwrap().take().unwrap().fd;
    close_guest(
        &mut reconnected as *mut Callback as usize,
        invoke_callback,
        fd,
    );
    CLIENT.with(|slot| {
        slot.borrow_mut().take();
    });
}

#[test]
fn actual_dbt_clients_share_transport_and_keep_callback_and_pending_request_boundaries() {
    if std::env::var_os(CHILD).is_some() {
        exercise_both_paths();
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let dirfd = std::fs::File::open(directory.path()).unwrap();
    // A held parent dirfd keeps this real filesystem socket's short spelling
    // valid in both processes, regardless of a deeply nested harness TMPDIR.
    let path = PathBuf::from(format!(
        "/proc/{}/fd/{}/rpc",
        std::process::id(),
        dirfd.as_raw_fd()
    ));
    let global = Arc::new(Global::default());
    let server_global = global.clone();
    let server_path = path.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let server = reverie_rpc_transport::RpcServer::bind(&server_path, server_global, 83).unwrap();
            ready_tx.send(()).unwrap();
            tokio::select! {
                result = server.serve() => panic!("RPC server ended before the test client: {result:?}"),
                _ = stop_rx => {},
            }
        });
    });
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "sync_rpc::shared_client_tests::actual_dbt_clients_share_transport_and_keep_callback_and_pending_request_boundaries", "--nocapture"])
        .env(CHILD, "1").env(RPC_SOCKET_ENV, &path)
        // Three caught codec panics are intentional; bound their diagnostics
        // while the parent retains the child's full stdout/stderr.
        .env("RUST_BACKTRACE", "0")
        .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn();
    let result = (|| {
        let mut child = child?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut exceeded = false;
        while child.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                exceeded = true;
                child.kill()?;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok::<_, io::Error>((exceeded, child.wait_with_output()?))
    })();
    let _ = stop_tx.send(());
    server.join().unwrap();
    let (exceeded, output) = result.unwrap();
    assert!(
        !exceeded,
        "DBT client blocked behind another pending request"
    );
    assert!(output.status.success(), "{output:?}");
    let mut actual = global.requests.lock().unwrap().clone();
    actual.sort_unstable();
    assert_eq!(
        actual,
        [
            (11, 1),
            (12, 2),
            (21, 3),
            (31, 4),
            (32, 5),
            (32, 7),
            (32, 8),
            (32, 9),
            (33, 99),
            (34, 99),
            (41, 100),
            (42, 101),
            (51, 6)
        ]
    );
}
