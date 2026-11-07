/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! CallerRuntime with the real RPC server, codec and sockets. Native contexts,
//! filter admission and terminal reservations below are explicit unit fixtures,
//! not DynamoRIO execution or evidence of actual application exit.

use std::cell::Cell;
use std::cell::RefCell;
use std::os::unix::net::UnixListener;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::thread::ThreadId;
use std::time::Duration;
use std::time::Instant;

use reverie::ExitStatus;
use reverie::Guest;
use reverie::InjectionPurpose;
use reverie::Subscription;
use reverie::syscalls::Errno;
use reverie_rpc_transport::ConnectionMonitor;
use reverie_rpc_transport::RpcIssueMonitor;
use reverie_rpc_transport::RpcServer;
use reverie_rpc_transport::tool_activation::ActivationRun;
use serde::Deserialize;
use serde::Serialize;

use super::*;

const CHILD_CASE: &str = "REVERIE_DBT_CALLER_RUNTIME_UNIT_CASE";
const TEST_NAME: &str = "caller_runtime::tests::caller_runtime_protocol";
const WITNESS: &str = "CALLER_RUNTIME_UNIT_COMPLETED";
const SEED: u64 = 73;
const FINAL_ARGS: [u64; 6] = [0x12f, 2, 3, 4, 5, 6];
static EVENTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
static DIAGNOSTICS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static SELECTIONS: AtomicUsize = AtomicUsize::new(0);
static CONSTRUCTORS: AtomicUsize = AtomicUsize::new(0);
static CONFIG_ADDRESS: AtomicUsize = AtomicUsize::new(0);

fn event(name: &'static str) {
    EVENTS.lock().unwrap().push(name);
}
fn events() -> Vec<&'static str> {
    EVENTS.lock().unwrap().clone()
}
fn pid() -> Pid {
    Pid::from_raw(std::process::id() as i32)
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Config {
    seed: u64,
    label: String,
    instructions: u8,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Request {
    Start,
    PostExec,
    ThreadExit,
    ProcessExit,
    AfterFinished,
}

impl Request {
    fn response(self) -> u64 {
        SEED + self as u64
    }
    fn event(self) -> &'static str {
        match self {
            Self::Start => "remote-start",
            Self::PostExec => "remote-post",
            Self::ThreadExit => "remote-thread-exit",
            Self::ProcessExit => "remote-process-exit",
            Self::AfterFinished => panic!("RPC escaped the finished primary"),
        }
    }
}

struct RemoteGlobal {
    owner: ThreadId,
    calls: AtomicUsize,
}
impl Default for RemoteGlobal {
    fn default() -> Self {
        panic!("caller must never create a local default GlobalTool")
    }
}

#[reverie::global_tool]
impl GlobalTool for RemoteGlobal {
    type Config = Config;
    type Request = Request;
    type Response = u64;

    async fn receive_rpc(&self, from: Pid, request: Request) -> u64 {
        assert_eq!(
            std::thread::current().id(),
            self.owner,
            "local GlobalTool fallback"
        );
        assert_eq!(from, pid());
        self.calls.fetch_add(1, Ordering::SeqCst);
        event(request.event());
        request.response()
    }
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    tid: i32,
    stamp: u64,
}
impl Drop for State {
    fn drop(&mut self) {
        if self.tid != 0 {
            event("state-drop");
        }
    }
}

struct Probe {
    process: Pid,
    config: usize,
}
impl Default for Probe {
    fn default() -> Self {
        panic!("actual Tool::new must construct the caller")
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        event("tool-drop");
    }
}

fn check_config(config: &Config) {
    assert_eq!(config.seed, SEED);
    assert_eq!(config.label, "received-config");
    assert_eq!(
        config as *const Config as usize,
        CONFIG_ADDRESS.load(Ordering::SeqCst)
    );
}

#[reverie::tool]
impl Tool for Probe {
    type GlobalState = RemoteGlobal;
    type ThreadState = State;

    fn subscriptions(config: &Config) -> Subscription {
        assert_eq!(config.seed, SEED);
        assert_eq!(config.label, "received-config");
        assert_eq!(SELECTIONS.fetch_add(1, Ordering::SeqCst), 0);
        assert_eq!(CONSTRUCTORS.load(Ordering::SeqCst), 0);
        CONFIG_ADDRESS.store(config as *const Config as usize, Ordering::SeqCst);
        event("select");
        let mut selected = Subscription::none();
        selected.syscall(Sysno::getpid);
        if config.instructions & 1 != 0 {
            selected.cpuid();
        }
        if config.instructions & 2 != 0 {
            selected.rdtsc();
        }
        selected
    }

    fn new(process: Pid, config: &Config) -> Self {
        check_config(config);
        assert_eq!(process, pid());
        assert_eq!(SELECTIONS.load(Ordering::SeqCst), 1);
        assert_eq!(CONSTRUCTORS.fetch_add(1, Ordering::SeqCst), 0);
        event("new");
        Self {
            process,
            config: config as *const Config as usize,
        }
    }

    fn init_thread_state(&self, tid: Pid, parent: Option<(Pid, &State)>) -> State {
        assert_eq!(tid, self.process);
        assert!(parent.is_none());
        event("state");
        State {
            tid: tid.as_raw(),
            stamp: SEED,
        }
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        check_config(guest.config());
        assert_eq!(guest.config() as *const Config as usize, self.config);
        assert_eq!(guest.pid(), self.process);
        assert_eq!(guest.tid(), self.process);
        assert_eq!(guest.ppid(), None);
        assert_eq!(guest.thread_state().stamp, SEED);
        event("start");
        assert_eq!(
            guest.send_rpc(Request::Start).await,
            Request::Start.response()
        );
        guest.thread_state_mut().stamp += 1;
        Ok(())
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        check_config(guest.config());
        assert_eq!(guest.thread_state().stamp, SEED + 1);
        event("post");
        assert_eq!(
            guest.send_rpc(Request::PostExec).await,
            Request::PostExec.response()
        );
        guest.thread_state_mut().stamp += 2;
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        check_config(guest.config());
        assert_eq!(guest.thread_state().stamp, SEED + 3);
        event("syscall");
        guest.thread_state_mut().stamp += 4;
        guest
            .tail_inject(Syscall::from_raw(
                Sysno::exit_group,
                SyscallArgs::new(FINAL_ARGS[0] as usize, 2, 3, 4, 5, 6),
            ))
            .await
    }

    async fn on_exit_thread<G: GlobalRPC<RemoteGlobal>>(
        &self,
        tid: Pid,
        rpc: &G,
        state: State,
        status: ExitStatus,
    ) -> Result<(), Error> {
        assert_eq!(tid, self.process);
        assert_eq!(state.tid, tid.as_raw());
        assert!(state.stamp == SEED + 3 || state.stamp == SEED + 7);
        assert_eq!(status, reverie::exit_status_from_raw(FINAL_ARGS[0]));
        check_config(rpc.config());
        event("thread-exit");
        assert_eq!(
            rpc.send_rpc(Request::ThreadExit).await,
            Request::ThreadExit.response()
        );
        drop(state);
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<RemoteGlobal>>(
        self,
        process: Pid,
        rpc: &G,
        status: ExitStatus,
    ) -> Result<(), Error> {
        assert_eq!(process, self.process);
        assert_eq!(status, reverie::exit_status_from_raw(FINAL_ARGS[0]));
        check_config(rpc.config());
        event("process-exit");
        assert_eq!(
            rpc.send_rpc(Request::ProcessExit).await,
            Request::ProcessExit.response()
        );
        Ok(())
    }
}

/// Passive frame-order witness. All framing, validation and acknowledgements
/// still execute in the existing shared client/server; this never sends an ack.
#[derive(Default)]
struct Frames(Vec<u8>);
impl Frames {
    fn observe(&mut self, bytes: &[u8], incoming: bool) {
        self.0.extend_from_slice(bytes);
        while self.0.len() >= 4 {
            let length = u32::from_be_bytes(self.0[..4].try_into().unwrap()) as usize;
            assert!(length <= reverie_rpc_transport::codec::DEFAULT_MAX_FRAME_LEN);
            if self.0.len() < 4 + length {
                break;
            }
            let frame = &self.0[4..4 + length];
            if frame.starts_with(&[0xff; 4]) {
                assert_eq!(length, reverie_rpc_transport::tool_activation::FRAME_LEN);
                assert_eq!(&frame[4..7], b"TA\x02");
                event(match (incoming, frame[7]) {
                    (false, 1) => "claim",
                    (true, 2) => "claim-ack",
                    (false, 3) => "started",
                    (true, 4) => "started-ack",
                    (false, 5) => "finished",
                    (true, 6) => "finished-ack",
                    _ => panic!("unexpected actual control frame"),
                });
            }
            self.0.drain(..4 + length);
        }
    }
}

/// Only this context/filter/reservation is synthetic. Transport calls below
/// execute real Linux socket I/O. No exit or lifecycle syscall is executed.
#[derive(Default)]
struct NativeFixture {
    primary: Cell<Option<i32>>,
    calls: Cell<usize>,
    reservation: Cell<Option<TerminalFact>>,
    sent: RefCell<Frames>,
    received: RefCell<Frames>,
}
impl NativeFixture {
    fn context(&self) -> usize {
        self as *const Self as usize
    }
    fn shutdown(&self) {
        if let Some(fd) = self.primary.take() {
            // The production connection owner retains its FD until process
            // exit. Shutdown supplies EOF for a joined server drain here.
            unsafe {
                libc::shutdown(fd, libc::SHUT_RDWR);
            }
        }
    }
}
impl Drop for NativeFixture {
    fn drop(&mut self) {
        self.shutdown();
    }
}

unsafe extern "C" fn invoke(context: usize, number: i64, args: *const u64, purpose: u32) -> i64 {
    let fixture = unsafe { &*(context as *const NativeFixture) };
    let args = unsafe { args.cast::<[u64; 6]>().read() };
    assert_eq!(purpose, InjectionPurpose::Application as u32);
    fixture.calls.set(fixture.calls.get() + 1);
    if number == libc::SYS_prctl {
        assert_eq!(args, [libc::PR_GET_SECCOMP as u64, 0, 0, 0, 0, 0]);
        event("unit-filter-probe");
        return 0; // Unit native-admission fixture, never a host filter claim.
    }
    assert!(matches!(
        number,
        libc::SYS_socket
            | libc::SYS_fcntl
            | libc::SYS_close
            | libc::SYS_connect
            | libc::SYS_read
            | libc::SYS_write
    ));
    let result =
        unsafe { libc::syscall(number, args[0], args[1], args[2], args[3], args[4], args[5]) };
    if result == -1 {
        return -i64::from(std::io::Error::last_os_error().raw_os_error().unwrap());
    }
    if number == libc::SYS_connect {
        fixture.primary.set(Some(args[0] as i32));
    }
    if matches!(number, libc::SYS_read | libc::SYS_write) && result > 0 {
        let bytes = unsafe { std::slice::from_raw_parts(args[1] as *const u8, result as usize) };
        if number == libc::SYS_read {
            fixture.received.borrow_mut().observe(bytes, true);
        } else {
            fixture.sent.borrow_mut().observe(bytes, false);
        }
    }
    result
}

unsafe extern "C" fn admit(
    context: usize,
    number: i64,
    args: *const u64,
    out: *mut TerminalFact,
) -> i32 {
    let fixture = unsafe { &*(context as *const NativeFixture) };
    assert!(fixture.reservation.get().is_none());
    assert_eq!(number, libc::SYS_exit_group);
    let fact = TerminalFact {
        size: std::mem::size_of::<TerminalFact>() as u32,
        kind: 1,
        image: 1,
        context: context as u64,
        pid: pid().as_raw(),
        tid: pid().as_raw(),
        sysno: number,
        args: unsafe { args.cast::<[u64; 6]>().read() },
        cookie: 91,
        origin: 2,
        reserved: 0,
    };
    assert_eq!(fact.args, FINAL_ARGS);
    fixture.reservation.set(Some(fact));
    event("unit-reservation");
    unsafe {
        out.write(fact);
    }
    1
}

unsafe extern "C" fn emit(bytes: *const u8, length: usize) {
    let bytes = unsafe { std::slice::from_raw_parts(bytes, length) };
    DIAGNOSTICS
        .lock()
        .unwrap()
        .push(String::from_utf8_lossy(bytes).into_owned());
}
unsafe extern "C" fn idle() {
    std::thread::yield_now();
}
unsafe extern "C" fn read_registers(_: usize, output: *mut libc::user_regs_struct) -> i32 {
    unsafe {
        output.write(std::mem::zeroed());
    }
    1
}
unsafe extern "C" fn write_registers(_: usize, _: *const libc::user_regs_struct) -> i32 {
    panic!("unexpected register write")
}
unsafe extern "C" fn read_memory(_: usize, _: *mut u8, _: usize) -> i32 {
    panic!("unexpected memory read")
}
unsafe extern "C" fn compare_exchange(_: usize, _: u32, _: u32, _: *mut u32) -> i32 {
    panic!("unexpected atomic memory effect")
}
unsafe extern "C" fn capture(
    _: usize,
    operation: u32,
    out: *mut crate::NativeControllerCaptureFact,
) -> i32 {
    assert_eq!(operation, 1);
    event("native-ack-call");
    unsafe {
        out.write(Default::default());
    }
    0
}
unsafe extern "C" fn private_memory(
    _: usize,
    _: *const crate::NativePrivateMemorySnapshot,
    out: *mut crate::NativePrivateMemorySnapshot,
) -> i32 {
    unsafe {
        out.write(Default::default());
    }
    0
}
unsafe extern "C" fn branch(_: usize, out: *mut crate::NativeBranchFact) -> i32 {
    unsafe {
        out.write(Default::default());
    }
    0
}
unsafe extern "C" fn mapping(_: usize, _: u32, _: *mut crate::NativeMappingCapture) -> i32 {
    panic!("unexpected mapping capture")
}

fn callbacks() -> DbtRuntimeCallbacks {
    DbtRuntimeCallbacks {
        emit,
        idle,
        panic_on_unsupported_syscalls: 0,
        unsupported_report_fd: -1,
        emit_stdout: emit,
        emit_evidence: emit,
        evidence_log_level: 0,
        compare_exchange_u32: compare_exchange,
        controller_capture_control: capture,
        runtime_private_memory: private_memory,
        branch_fact: branch,
        mapping_capture: mapping,
        admit_terminal: admit,
        rpc_transport_fatal: Some(unexpected_rpc_transport_failure),
    }
}

// Positive unit fixtures never disconnect. Actual native failure/cleanup is
// exercised by the separately produced caller artifact, not this callback.
unsafe extern "C" fn unexpected_rpc_transport_failure(_: usize) -> ! {
    std::process::abort()
}

struct Server {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    monitor: ConnectionMonitor,
    issues: RpcIssueMonitor,
    global: Arc<RemoteGlobal>,
}
impl Server {
    fn start(config: Config, run: ActivationRun) -> Self {
        let path = std::env::var_os(crate::sync_rpc::RPC_SOCKET_ENV).unwrap();
        let listener = UnixListener::bind(path).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let global = Arc::new(RemoteGlobal {
                    owner: std::thread::current().id(),
                    calls: AtomicUsize::new(0),
                });
                let mut server = RpcServer::from_prebound(listener, global.clone(), config)
                    .unwrap()
                    .tool_activation(run);
                let monitor = server.connection_monitor();
                let issues = server.retain_connection_issues();
                send.send((monitor.clone(), issues, global)).unwrap();
                server
                    .serve_until(async move {
                        let _ = stopped.await;
                        tokio::time::timeout(Duration::from_secs(2), monitor.wait_for_idle())
                            .await
                            .expect("RPC connections did not drain");
                    })
                    .await
                    .unwrap();
            });
        });
        let (monitor, issues, global) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        Self {
            stop: Some(stop),
            thread: Some(thread),
            monitor,
            issues,
            global,
        }
    }
    fn finish(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        assert_eq!(self.monitor.active_connections(), 0);
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.finish();
    }
}

fn init(
    runtime: &CallerRuntime<Probe>,
    counters: &mut CallerCounters,
    fixture: &NativeFixture,
    defer: i32,
) -> i32 {
    unsafe {
        runtime.thread_init(
            counters,
            fixture.context(),
            pid().as_raw(),
            pid().as_raw(),
            -1,
            37,
            defer,
            invoke,
            read_registers,
            write_registers,
        )
    }
}

fn sentinel() -> ReadySnapshot {
    ReadySnapshot {
        size: 123,
        selected_event_bits: 456,
        raw_config_digest: [0xa5; 32],
        owner_generation: 789,
    }
}

fn exercise(case: &str) {
    let runtime = CallerRuntime::<Probe>::new([0x6b; 32]);
    let image = runtime.image_init();
    assert!(image.is_valid());
    assert_eq!(image.runtime_input_identity, [0x6b; 32]);
    let mut counters = CallerCounters {
        branches: 0,
        observed_syscalls: 0,
        rewritten_syscalls: 0,
        runtime_state: std::ptr::null_mut(),
    };
    let fixture = NativeFixture::default();
    let mut snapshot = sentinel();
    assert_eq!(unsafe { runtime.ready(1, &mut snapshot) }, 0);
    assert_eq!(snapshot, sentinel());
    assert_eq!(init(&runtime, &mut counters, &fixture, 1), 0);
    assert_eq!(init(&runtime, &mut counters, &fixture, 0), 1);
    assert!(events().is_empty());
    assert_eq!(fixture.calls.get(), 0);
    assert!(counters.runtime_state.is_null());
    if case == "missing-fatal" {
        let mut callbacks = callbacks();
        callbacks.rpc_transport_fatal = None;
        assert_eq!(
            unsafe {
                runtime.background_init(
                    (&mut callbacks as *mut DbtRuntimeCallbacks).cast(),
                    crate::DbtStartupMode::Coordinated as u32,
                )
            },
            -1
        );
        assert_eq!(unsafe { runtime.ready(1, &mut snapshot) }, -1);
        assert_eq!(snapshot, sentinel());
        assert_eq!(init(&runtime, &mut counters, &fixture, 0), -1);
        assert_eq!(CONSTRUCTORS.load(Ordering::SeqCst), 0);
        assert_eq!(SELECTIONS.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.calls.get(), 0);
        assert!(counters.runtime_state.is_null());
        assert!(events().is_empty());
        assert_eq!(
            DIAGNOSTICS.lock().unwrap().as_slice(),
            ["reverie-dbt: caller RPC failure owner missing\n"]
        );
        runtime.process_exit();
        assert_eq!(
            DIAGNOSTICS.lock().unwrap().as_slice(),
            ["reverie-dbt: caller RPC failure owner missing\n"]
        );
        assert!(events().is_empty());
        assert_eq!(fixture.calls.get(), 0);
        return;
    }
    if case == "failed" {
        assert_eq!(
            unsafe {
                runtime.background_init(
                    std::ptr::null_mut(),
                    crate::DbtStartupMode::Coordinated as u32,
                )
            },
            -1
        );
        assert_eq!(unsafe { runtime.ready(1, &mut snapshot) }, -1);
        assert_eq!(snapshot, sentinel());
        assert_eq!(init(&runtime, &mut counters, &fixture, 0), -1);
        assert_eq!(CONSTRUCTORS.load(Ordering::SeqCst), 0);
        assert_eq!(SELECTIONS.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.calls.get(), 0);
        assert!(counters.runtime_state.is_null());
        assert!(events().is_empty());
        return;
    }

    let config = Config {
        seed: SEED,
        label: "received-config".into(),
        instructions: match case {
            "cpuid" => 1,
            "rdtsc" => 2,
            _ => 0,
        },
    };
    let run = ActivationRun::new();
    run.bind_root(pid().as_raw()).unwrap();
    let mut server = Server::start(config.clone(), run.clone());
    // Fix the unit context's address before admission and drop it before Server
    // on panic, so the cached primary has EOF before the serving owner joins.
    // Pending/defer1 retained no context or application state above.
    let fixture = Box::new(fixture);
    let mut callbacks = callbacks();
    assert_eq!(
        unsafe {
            runtime.background_init(
                (&mut callbacks as *mut DbtRuntimeCallbacks).cast(),
                crate::DbtStartupMode::Coordinated as u32,
            )
        },
        0
    );
    assert_eq!(events(), ["select"]);
    assert_eq!(CONSTRUCTORS.load(Ordering::SeqCst), 0);
    assert!(counters.runtime_state.is_null());
    assert_eq!(unsafe { runtime.ready(1, &mut snapshot) }, 1);
    assert_eq!(snapshot.size as usize, std::mem::size_of::<ReadySnapshot>());
    assert_eq!(snapshot.owner_generation, 1);
    assert_eq!(snapshot.selected_event_bits, u32::from(config.instructions));
    assert_eq!(
        snapshot.raw_config_digest,
        reverie_rpc_transport::initial_image::config_digest(
            &reverie_rpc_transport::codec::encode(&config).unwrap()
        )
    );
    let untouched = sentinel();
    let mut wrong_image = untouched;
    assert_eq!(unsafe { runtime.ready(2, &mut wrong_image) }, -1);
    assert_eq!(wrong_image, untouched);
    assert_eq!(init(&runtime, &mut counters, &fixture, 1), 0);
    assert_eq!(CONSTRUCTORS.load(Ordering::SeqCst), 0);
    if config.instructions != 0 {
        assert_eq!(init(&runtime, &mut counters, &fixture, 0), -1);
        assert_eq!(events(), ["select"]);
        assert_eq!(fixture.calls.get(), 0);
        assert_eq!(CONSTRUCTORS.load(Ordering::SeqCst), 0);
        assert!(counters.runtime_state.is_null());
        snapshot = sentinel();
        assert_eq!(unsafe { runtime.ready(1, &mut snapshot) }, -1);
        assert_eq!(snapshot, sentinel());
        assert!(run.completed().is_err());
        assert_eq!(server.global.calls.load(Ordering::SeqCst), 0);
        assert!(
            DIAGNOSTICS
                .lock()
                .unwrap()
                .iter()
                .any(|message| message.contains("caller-instruction-subscription-unsupported"))
        );
        server.finish();
        assert!(server.issues.snapshot().is_empty());
        return;
    }

    assert_eq!(init(&runtime, &mut counters, &fixture, 0), 0);
    assert_eq!(
        events(),
        [
            "select",
            "unit-filter-probe",
            "claim",
            "claim-ack",
            "new",
            "state",
            "start",
            "remote-start",
            "post",
            "remote-post",
            "started",
            "started-ack",
            "native-ack-call"
        ]
    );
    assert!(run.completed().is_err());
    if case == "missing-finished" {
        // Real construction and startup RPC have completed, but this unit
        // notification establishes neither a native ending nor a receipt.
        let before = events();
        assert!(DIAGNOSTICS.lock().unwrap().is_empty());
        runtime.process_exit();
        assert_eq!(
            DIAGNOSTICS.lock().unwrap().as_slice(),
            ["reverie-dbt: caller process ended without acknowledged consuming lifecycle\n"]
        );
        assert_eq!(runtime.ready.load(Ordering::Acquire), -1);
        runtime.process_exit();
        assert_eq!(
            DIAGNOSTICS.lock().unwrap().as_slice(),
            ["reverie-dbt: caller process ended without acknowledged consuming lifecycle\n"]
        );
        assert_eq!(events(), before);
        assert!(run.completed().is_err());
        // The unit fixture owns the attachment allocation; no exit hook is
        // called to dispose of a process whose ending was never admitted.
        unsafe {
            drop(Box::from_raw(
                counters.runtime_state.cast::<RootAttachment<Probe>>(),
            ));
        }
        fixture.shutdown();
        server.finish();
        return;
    }
    let selected = runtime
        .configuration
        .get()
        .unwrap()
        .selected
        .shared_config();
    let attachment = unsafe {
        runtime
            .attachment(
                &mut counters,
                fixture.context(),
                pid().as_raw(),
                pid().as_raw(),
                1,
            )
            .unwrap()
    };
    assert!(Arc::ptr_eq(
        &selected,
        &attachment
            .process
            .selected_configuration()
            .unwrap()
            .shared_config()
    ));
    assert_eq!(attachment.state.as_ref().unwrap().stamp, SEED + 3);
    assert!(attachment.phase == Phase::Running);

    let mut result = -1234;
    let mut deferred_number = -4321;
    let mut deferred_args = [0xa5; 6];
    let number = if case == "original" {
        libc::SYS_exit_group
    } else {
        libc::SYS_getpid
    };
    let action = unsafe {
        runtime.pre_syscall(
            fixture.context(),
            &mut counters,
            pid().as_raw(),
            pid().as_raw(),
            1,
            number,
            FINAL_ARGS.as_ptr(),
            41,
            &mut result,
            &mut deferred_number,
            deferred_args.as_mut_ptr(),
            invoke,
            read_registers,
            write_registers,
            read_memory,
        )
    };
    let fact = if case == "original" {
        assert_eq!(action, 0);
        assert_eq!(deferred_number, -4321);
        assert_eq!(deferred_args, [0xa5; 6]);
        assert!(fixture.reservation.get().is_none());
        TerminalFact {
            size: std::mem::size_of::<TerminalFact>() as u32,
            kind: 1,
            image: 1,
            context: fixture.context() as u64,
            pid: pid().as_raw(),
            tid: pid().as_raw(),
            sysno: libc::SYS_exit_group,
            args: FINAL_ARGS,
            cookie: 92,
            origin: 1,
            reserved: 0,
        }
    } else {
        assert_eq!(action, 2);
        assert_eq!(deferred_number, libc::SYS_exit_group);
        assert_eq!(deferred_args, FINAL_ARGS);
        fixture.reservation.get().unwrap()
    };
    assert_eq!(result, -1234);
    assert!(!events().contains(&"thread-exit"));
    assert!(!events().contains(&"finished"));
    assert!(run.completed().is_err());
    let attachment = unsafe {
        runtime
            .attachment(
                &mut counters,
                fixture.context(),
                pid().as_raw(),
                pid().as_raw(),
                1,
            )
            .unwrap()
    };
    assert_eq!(
        attachment.state.as_ref().unwrap().stamp,
        if case == "original" {
            SEED + 3
        } else {
            SEED + 7
        }
    );

    if case == "mismatch" {
        for field in 0..4 {
            let mut changed = fact;
            match field {
                0 => changed.cookie += 1,
                1 => changed.args[0] += 1,
                2 => changed.context += 1,
                _ => changed.origin = 1,
            }
            assert_eq!(
                unsafe {
                    runtime.thread_exit(
                        &mut counters,
                        fixture.context(),
                        pid().as_raw(),
                        invoke,
                        &changed,
                    )
                },
                -1
            );
            let attachment = unsafe {
                runtime
                    .attachment(
                        &mut counters,
                        fixture.context(),
                        pid().as_raw(),
                        pid().as_raw(),
                        1,
                    )
                    .unwrap()
            };
            assert!(attachment.phase == Phase::Running);
            assert!(attachment.state.is_some());
            assert!(attachment.process.as_ref().is_some());
            assert_eq!(attachment.effects.ending(), Some(fact));
        }
        assert!(!events().contains(&"thread-exit"));
        assert!(!events().contains(&"finished"));
        assert_eq!(server.global.calls.load(Ordering::SeqCst), 2);
        assert!(run.completed().is_err());
        snapshot = sentinel();
        assert_eq!(unsafe { runtime.ready(1, &mut snapshot) }, -1);
        assert_eq!(snapshot, sentinel());
    } else {
        assert_eq!(
            unsafe {
                runtime.thread_exit(
                    &mut counters,
                    fixture.context(),
                    pid().as_raw(),
                    invoke,
                    &fact,
                )
            },
            0
        );
        let before = events();
        assert_eq!(
            &before[before.len() - 8..],
            [
                "thread-exit",
                "remote-thread-exit",
                "state-drop",
                "process-exit",
                "remote-process-exit",
                "tool-drop",
                "finished",
                "finished-ack"
            ]
        );
        let calls = fixture.calls.get();
        let attachment = unsafe {
            runtime
                .attachment(
                    &mut counters,
                    fixture.context(),
                    pid().as_raw(),
                    pid().as_raw(),
                    1,
                )
                .unwrap()
        };
        assert!(attachment.phase == Phase::Finished);
        assert!(attachment.state.is_none());
        assert!(attachment.process.as_ref().is_none());
        assert_eq!(attachment.effects.check_memory(), Err(Errno::ESRCH));
        assert!(
            attachment
                .primary
                .send::<RemoteGlobal>(
                    fixture.context(),
                    invoke,
                    pid(),
                    &selected,
                    Request::AfterFinished
                )
                .is_err()
        );
        assert!(
            attachment
                .primary
                .control(
                    fixture.context(),
                    invoke,
                    &ToolControl::Started {
                        digest: snapshot.raw_config_digest
                    }
                )
                .is_err()
        );
        assert_eq!(
            unsafe {
                runtime.thread_exit(
                    &mut counters,
                    fixture.context(),
                    pid().as_raw(),
                    invoke,
                    &fact,
                )
            },
            0
        );
        runtime.process_exit();
        runtime.process_exit();
        assert_eq!(events(), before);
        assert_eq!(fixture.calls.get(), calls);
        assert_eq!(server.global.calls.load(Ordering::SeqCst), 4);
        assert_eq!(
            before.iter().filter(|event| **event == "finished").count(),
            1
        );
    }
    assert_eq!(SELECTIONS.load(Ordering::SeqCst), 1);
    assert_eq!(CONSTRUCTORS.load(Ordering::SeqCst), 1);
    // Retire the test-owned attachment only after all runtime operations; its
    // production lifetime ends with the application process, not a second hook.
    unsafe {
        drop(Box::from_raw(
            counters.runtime_state.cast::<RootAttachment<Probe>>(),
        ));
    }
    counters.runtime_state = std::ptr::null_mut();
    assert!(counters.runtime_state.is_null());
    fixture.shutdown();
    server.finish();
    if case != "mismatch" {
        let receipt = run.completed().unwrap();
        assert_eq!(receipt.exit_code(), 47);
        assert_eq!(receipt.syscall(), libc::SYS_exit_group);
        assert_eq!(
            receipt.origin(),
            if case == "original" {
                ExitOrigin::Original
            } else {
                ExitOrigin::Deferred
            }
        );
        assert!(server.issues.snapshot().is_empty());
        assert!(DIAGNOSTICS.lock().unwrap().is_empty());
    }
}

struct ChildGuard(Option<Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn caller_runtime_protocol() {
    if let Some(case) = std::env::var_os(CHILD_CASE) {
        let case = case.to_str().unwrap();
        assert!(matches!(
            case,
            "deferred"
                | "original"
                | "mismatch"
                | "cpuid"
                | "rdtsc"
                | "failed"
                | "missing-fatal"
                | "missing-finished"
        ));
        exercise(case);
        println!("{WITNESS}:{case}");
        return;
    }
    // Installers and the cached primary are process globals. Exec starts a
    // fresh libtest process; no Rust allocator/async work follows a raw fork of
    // the multithreaded harness. Every timeout/panic kills and reaps the child.
    for case in [
        "deferred",
        "original",
        "mismatch",
        "cpuid",
        "rdtsc",
        "failed",
        "missing-fatal",
        "missing-finished",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--test-threads=1", "--nocapture"])
            .env(CHILD_CASE, case)
            .env(
                crate::sync_rpc::RPC_SOCKET_ENV,
                directory.path().join("caller.sock"),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut child = ChildGuard(Some(child));
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "CallerRuntime {case} child timed out"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        assert!(output.status.success(), "CallerRuntime {case}: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("test result: ok. 1 passed;"),
            "wrong libtest selection: {stdout}"
        );
        assert_eq!(stdout.matches(&format!("{WITNESS}:{case}")).count(), 1);
    }
}
