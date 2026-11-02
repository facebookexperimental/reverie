/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Owned real-socket fixtures for common native mechanism controls. These use
//! normal test threads and syscalls; they do not qualify a native loader/TLS.

use std::io;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use reverie::GlobalTool;
use reverie::Pid;
use serde::Deserialize;
use serde::Serialize;

use super::host::HostRuntime;
use super::host::native_state::NativeThreadIdentity;
use super::native_rpc::NativeInvocation;
use super::native_rpc::NativeRpc;
use super::native_services::NativeEventFacts;
use super::native_services::NativeServiceTable;
use super::native_services::NativeServices;
use super::rpc::CoordinatorRpc;
use super::rpc::GuestRpcStream;

#[derive(Debug, Deserialize)]
pub(crate) struct Request(pub u64);
impl Serialize for Request {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        assert_ne!(self.0, u64::MAX, "intentional request serialization panic");
        serializer.serialize_u64(self.0)
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Reply(pub i32, pub u64);
impl<'de> Deserialize<'de> for Reply {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (from, value) = <(i32, u64)>::deserialize(deserializer)?;
        assert_ne!(value, 99, "intentional response deserialization panic");
        if value == 500 {
            // The actual global entry reenters the same selected owner during
            // decode. It must find the primary released, not a held I/O owner.
            let result = super::native_rpc::dispatch_global::<Remote>(Request(501));
            assert!(matches!(
                result,
                super::native_rpc::NativeGlobalDispatch::Handled(Ok(Reply(_, 501)))
            ));
        }
        Ok(Self(from, value))
    }
}

#[derive(Default)]
pub(crate) struct Remote {
    pub(crate) seen: Mutex<Vec<(i32, u64)>>,
    pub(crate) first_pending: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    released: AtomicBool,
    release: tokio::sync::Notify,
}

#[reverie::global_tool]
impl GlobalTool for Remote {
    type Config = u64;
    type Request = Request;
    type Response = Reply;
    async fn receive_rpc(&self, from: Pid, request: Request) -> Reply {
        self.seen.lock().unwrap().push((from.as_raw(), request.0));
        if request.0 == 100 {
            if let Some(entered) = self.first_pending.lock().unwrap().take() {
                entered.send(()).unwrap();
            }
            if !self.released.load(Ordering::SeqCst) {
                tokio::time::timeout(Duration::from_secs(5), self.release.notified())
                    .await
                    .expect("second real RPC did not release the first");
            }
        } else if request.0 == 101 {
            self.released.store(true, Ordering::SeqCst);
            self.release.notify_one();
        }
        Reply(from.as_raw(), request.0)
    }
}

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

pub(crate) struct Server {
    pub(crate) path: PathBuf,
    pub(crate) global: Arc<Remote>,
    root: PathBuf,
    _directory: std::fs::File,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    pub(crate) fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "reverie-native-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let directory = std::fs::File::open(&root).unwrap();
        // Keep long harness TMPDIR names outside sockaddr_un without losing
        // custody of the actual private parent directory.
        let path = PathBuf::from(format!(
            "/proc/{}/fd/{}/rpc",
            std::process::id(),
            directory.as_raw_fd()
        ));
        let global = Arc::new(Remote::default());
        let server_global = Arc::clone(&global);
        let server_path = path.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let server = reverie_rpc_transport::RpcServer::bind_exclusive(
                        &server_path,
                        server_global,
                        71,
                    )
                    .unwrap();
                    ready_tx.send(()).unwrap();
                    server
                        .serve_until(async {
                            let _ = stop_rx.await;
                        })
                        .await
                        .unwrap();
                });
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        Self {
            path,
            global,
            root,
            _directory: directory,
            stop: Some(stop_tx),
            thread: Some(thread),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        std::fs::remove_dir(&self.root).unwrap();
    }
}

pub(crate) fn configured_rpc() -> (CoordinatorRpc<Remote>, UnixStream) {
    let (client, mut peer) = UnixStream::pair().unwrap();
    let config = reverie_rpc_transport::codec::encode(&71_u64).unwrap();
    peer.write_all(&(config.len() as u32).to_be_bytes())
        .unwrap();
    peer.write_all(&config).unwrap();
    let client = reverie_rpc_transport::BlockingRpcClient::from_connected_stream(
        GuestRpcStream::from(client),
        actual_pid(libc::SYS_gettid),
    )
    .unwrap();
    let rpc = CoordinatorRpc::from_live_client("unused-native-entry-test", client, |_, _| {
        panic!("native tests must not reconnect through the local client")
    })
    .unwrap();
    (rpc, peer)
}

pub(crate) fn actual_pid(number: i64) -> Pid {
    Pid::from_raw(unsafe { libc::syscall(number) } as i32)
}

pub(crate) struct Callback {
    thread: std::thread::ThreadId,
    identity: NativeThreadIdentity,
    pub(crate) calls: Mutex<Vec<(i64, [u64; 6])>>,
    pub(crate) regs: Mutex<libc::user_regs_struct>,
    interrupted_read: AtomicBool,
    interrupted_write: AtomicBool,
    pub(crate) admitted: AtomicU64,
}
impl Callback {
    pub(crate) fn new(image: u64) -> Self {
        let pid = actual_pid(libc::SYS_getpid);
        let tid = actual_pid(libc::SYS_gettid);
        Self::with_tool_identity(image, pid, tid)
    }
    pub(crate) fn with_tool_identity(image: u64, tool_pid: Pid, tool_tid: Pid) -> Self {
        let pid = actual_pid(libc::SYS_getpid);
        let tid = actual_pid(libc::SYS_gettid);
        let identity = unsafe {
            NativeThreadIdentity::from_admitted(pid, tid, tool_pid, tool_tid, image).unwrap()
        };
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.rip = 0x1234;
        Self {
            thread: std::thread::current().id(),
            identity,
            calls: Mutex::new(Vec::new()),
            regs: Mutex::new(regs),
            interrupted_read: AtomicBool::new(false),
            interrupted_write: AtomicBool::new(false),
            admitted: AtomicU64::new(0),
        }
    }
    pub(crate) fn identity(&self) -> NativeThreadIdentity {
        self.identity
    }
    pub(crate) fn invocation(&self) -> NativeInvocation<'_> {
        unsafe {
            NativeInvocation::from_admitted(
                self as *const Self as usize,
                invoke,
                current,
                self.identity,
            )
        }
    }
    pub(crate) fn services(
        &self,
        signal_info: Option<[u8; reverie::SIGNAL_INFO_SIZE]>,
    ) -> NativeServices<'_> {
        unsafe {
            NativeServices::from_admitted(
                self.invocation(),
                &TABLE,
                NativeEventFacts {
                    parent: None,
                    branches: 17,
                    cpuid_interception: true,
                    pidfd_self_spelling: reverie::PidfdSelfSpelling::Unknown,
                    auxv: &[(libc::AT_PAGESZ, 4096), (libc::AT_NULL, 0)],
                    initial_stack: None,
                    signal_info,
                },
            )
            .unwrap()
        }
    }
    pub(crate) fn count(&self, number: i64) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| *n == number)
            .count()
    }
}

unsafe extern "C" fn current(context: usize) -> i32 {
    let callback = unsafe { &*(context as *const Callback) };
    i32::from(
        callback.thread == std::thread::current().id()
            && callback.identity.physical_pid() == actual_pid(libc::SYS_getpid)
            && callback.identity.physical_tid() == actual_pid(libc::SYS_gettid),
    )
}
unsafe extern "C" fn invoke(context: usize, number: i64, args: *const u64, purpose: u32) -> i64 {
    assert_eq!(unsafe { current(context) }, 1);
    assert!(
        purpose == reverie::InjectionPurpose::Application as u32
            || purpose == reverie::InjectionPurpose::Pselect6WrapperValidation as u32
    );
    let callback = unsafe { &*(context as *const Callback) };
    let mut args = unsafe { args.cast::<[u64; 6]>().read() };
    callback.calls.lock().unwrap().push((number, args));
    if number == libc::SYS_read {
        if !callback.interrupted_read.swap(true, Ordering::SeqCst) {
            return -i64::from(libc::EINTR);
        }
        args[2] = args[2].min(2);
    } else if number == libc::SYS_write {
        if !callback.interrupted_write.swap(true, Ordering::SeqCst) {
            return -i64::from(libc::EINTR);
        }
        args[2] = args[2].min(2);
    }
    let result =
        unsafe { libc::syscall(number, args[0], args[1], args[2], args[3], args[4], args[5]) };
    if result == -1 {
        -i64::from(io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        result
    }
}
unsafe extern "C" fn read_regs(context: usize, output: *mut libc::user_regs_struct) -> i32 {
    let callback = unsafe { &*(context as *const Callback) };
    unsafe { output.write(*callback.regs.lock().unwrap()) };
    1
}
unsafe extern "C" fn write_regs(context: usize, input: *const libc::user_regs_struct) -> i32 {
    let callback = unsafe { &*(context as *const Callback) };
    *callback.regs.lock().unwrap() = unsafe { input.read() };
    1
}
unsafe extern "C" fn acknowledge(
    context: usize,
    operation: u32,
    output: *mut super::native_services::NativeControllerCaptureFact,
) -> i32 {
    let callback = unsafe { &*(context as *const Callback) };
    unsafe { output.write(Default::default()) };
    if operation == 1 {
        callback.admitted.fetch_add(1, Ordering::SeqCst);
    }
    0 // Acknowledgement observation grants no controller-capture authority.
}
static TABLE: NativeServiceTable = NativeServiceTable {
    read_registers: read_regs,
    write_registers: write_regs,
    compare_exchange_u32: None,
    controller_capture: Some(acknowledge),
    private_memory: None,
    mapping_capture: None,
    read_memory: None,
};

pub(crate) struct Runtime;
impl HostRuntime for Runtime {
    fn fork_child_rebind(&self) {
        panic!("no local fork in native controls")
    }
    fn emit_stage(&self, _: &[u8]) {}
    fn fork_child_reset(&self, _: &super::event::SyscallEvent) {
        panic!("no local fork")
    }
    fn cpuid_interception_enabled(&self) -> bool {
        true
    }
    fn exit_process_stats(&self, _: Pid) -> io::Result<()> {
        panic!("native exit owner is separate")
    }
    fn read_clock(&self) -> io::Result<u64> {
        panic!("must use actual native branch fact")
    }
    fn signal_action_supported(&self, _: i64, _: [u64; 6]) -> bool {
        false
    }
    fn reserved_signal_mask(&self) -> u64 {
        0
    }
}

/// Test-only final process-owner action: no callback survives this close. The
/// production primary remains occupied until its actual native image retires.
pub(crate) fn close_test_primary(rpc: &NativeRpc<Remote>, callback: &Callback) {
    if let Some(fd) = rpc.descriptor(callback.identity.physical_pid()) {
        assert_eq!(unsafe { libc::close(fd) }, 0);
    }
}

/// Check both distinct closes in the real independent path: its low socket
/// after F_DUPFD_CLOEXEC relocation, then its high connection after framing.
/// Neither close may name the simultaneously occupied primary descriptor.
pub(crate) fn assert_independent_connection_retired(callback: &Callback, primary: i32) {
    let calls = callback.calls.lock().unwrap();
    let connects = calls
        .iter()
        .filter(|(number, _)| *number == libc::SYS_connect)
        .map(|(_, args)| args[0] as i32)
        .collect::<Vec<_>>();
    assert_eq!(connects.len(), 1);
    let independent = connects[0];
    assert!(independent >= 1024);
    assert_ne!(independent, primary);
    let closes = calls
        .iter()
        .filter(|(number, _)| *number == libc::SYS_close)
        .map(|(_, args)| args[0] as i32)
        .collect::<Vec<_>>();
    let relocations = calls
        .iter()
        .filter(|(number, args)| {
            *number == libc::SYS_fcntl && args[1] == libc::F_DUPFD_CLOEXEC as u64
        })
        .map(|(_, args)| args[0] as i32)
        .collect::<Vec<_>>();
    if let Some(&low) = relocations.first() {
        assert_eq!(relocations.len(), 1);
        assert!(low < 1024);
        assert_eq!(
            closes,
            [low, independent],
            "relocated low socket then completed connection"
        );
    } else {
        assert_eq!(
            closes,
            [independent],
            "already-high connection closes exactly once"
        );
    }
    assert!(!closes.contains(&primary));
    assert_eq!(unsafe { libc::fcntl(independent, libc::F_GETFD) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
}
