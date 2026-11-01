//! Real typed configuration transport and CallerRuntime entrypoints. The
//! NativeFixture's application context/filter probe remains synthetic; this is
//! not a DynamoRIO run or a stock binary-stream Tool execution claim.

use super::*;

const CASE_ENV: &str = "REVERIE_DBT_FACILITY_ADMISSION_CASE";
const TEST: &str = "caller_runtime::tests::facility_admission::typed_admission_precedes_readiness_and_construction";
const REFUSAL: &str = "fixture non-plain stream refused";
static ADMISSIONS: AtomicUsize = AtomicUsize::new(0);
static NEWS: AtomicUsize = AtomicUsize::new(0);
static STARTS: AtomicUsize = AtomicUsize::new(0);
static SELECTS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct AdmissionConfig {
    record_mode: bool,
    replay_mode: bool,
    marker: u64,
}

#[derive(Default)]
struct AdmissionGlobal;

#[reverie::global_tool]
impl GlobalTool for AdmissionGlobal {
    type Config = AdmissionConfig;
    type Request = ();
    type Response = ();

    async fn receive_rpc(&self, _from: Pid, _request: ()) {
        panic!("admission controls do not send Tool RPCs");
    }
}

fn check(config: &AdmissionConfig) {
    assert!(!config.record_mode);
    assert!(!config.replay_mode);
    assert_eq!(config.marker, 0x63ad_1198);
}

#[derive(Default)]
struct AdmissionProbe<const ROLE: u8>;

#[reverie::tool]
impl<const ROLE: u8> Tool for AdmissionProbe<ROLE> {
    type GlobalState = AdmissionGlobal;
    type ThreadState = ();

    fn stream_role() -> reverie::ToolStreamRole {
        match ROLE {
            0 => reverie::ToolStreamRole::Unknown,
            1 => reverie::ToolStreamRole::Plain,
            2 => reverie::ToolStreamRole::BinaryRecord,
            3 => reverie::ToolStreamRole::BinaryReplay,
            _ => panic!("unexpected fixture role"),
        }
    }

    fn facility_admission(config: &AdmissionConfig) -> Result<(), Error> {
        check(config);
        assert_eq!(ADMISSIONS.fetch_add(1, Ordering::SeqCst), 0);
        assert_eq!(SELECTS.load(Ordering::SeqCst), 0);
        assert_eq!(NEWS.load(Ordering::SeqCst), 0);
        assert_eq!(STARTS.load(Ordering::SeqCst), 0);
        if Self::stream_role() != reverie::ToolStreamRole::Plain {
            return Err(std::io::Error::other(REFUSAL).into());
        }
        Ok(())
    }

    fn subscriptions(_config: &AdmissionConfig) -> Subscription {
        // The fixture observes selection for the ordering assertion, but makes
        // no operational admission decision in this query.
        SELECTS.fetch_add(1, Ordering::SeqCst);
        [Sysno::getpid].into_iter().collect()
    }

    fn new(_pid: Pid, config: &AdmissionConfig) -> Self {
        check(config);
        assert_eq!(ADMISSIONS.load(Ordering::SeqCst), 1);
        assert_eq!(NEWS.fetch_add(1, Ordering::SeqCst), 0);
        Self
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        check(guest.config());
        assert_eq!(NEWS.load(Ordering::SeqCst), 1);
        assert_eq!(STARTS.fetch_add(1, Ordering::SeqCst), 0);
        Ok(())
    }
}

struct AdmissionServer {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    monitor: ConnectionMonitor,
}

impl AdmissionServer {
    fn start() -> Self {
        let path = std::env::var_os(crate::sync_rpc::RPC_SOCKET_ENV).unwrap();
        let listener = UnixListener::bind(path).unwrap();
        let run = ActivationRun::new();
        run.bind_root(pid().as_raw()).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let config = AdmissionConfig {
                    record_mode: false,
                    replay_mode: false,
                    marker: 0x63ad_1198,
                };
                let server = RpcServer::from_prebound(listener, Arc::new(AdmissionGlobal), config)
                    .unwrap()
                    .tool_activation(run);
                let monitor = server.connection_monitor();
                send.send(monitor.clone()).unwrap();
                server
                    .serve_until(async move {
                        let _ = stopped.await;
                        tokio::time::timeout(Duration::from_secs(2), monitor.wait_for_idle())
                            .await
                            .expect("admission RPC connection did not drain");
                    })
                    .await
                    .unwrap();
            });
        });
        Self {
            stop: Some(stop),
            thread: Some(thread),
            monitor: receive.recv_timeout(Duration::from_secs(2)).unwrap(),
        }
    }
}

impl Drop for AdmissionServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        assert_eq!(self.monitor.active_connections(), 0);
    }
}

fn exercise_admission<const ROLE: u8>() {
    let runtime = CallerRuntime::<AdmissionProbe<ROLE>>::new([0x4c; 32]);
    assert!(runtime.image_init().is_valid());
    let _server = AdmissionServer::start();
    // This guard closes native fixture sockets before the server is joined on
    // either normal return or an assertion failure, like the existing controls.
    let fixture = Box::new(NativeFixture::default());
    let mut callbacks = callbacks();
    let mut counters = CallerCounters {
        branches: 0,
        observed_syscalls: 0,
        rewritten_syscalls: 0,
        runtime_state: std::ptr::null_mut(),
    };
    let result = unsafe {
        runtime.background_init(
            (&mut callbacks as *mut DbtRuntimeCallbacks).cast(),
            crate::DbtStartupMode::Coordinated as u32,
        )
    };
    assert_eq!(ADMISSIONS.load(Ordering::SeqCst), 1);
    assert_eq!(NEWS.load(Ordering::SeqCst), 0);
    assert_eq!(STARTS.load(Ordering::SeqCst), 0);
    assert!(counters.runtime_state.is_null());
    let mut snapshot = sentinel();
    let ready = unsafe { runtime.ready(1, &mut snapshot) };
    if ROLE != 1 {
        assert_eq!(result, -1);
        assert_eq!(ready, -1);
        assert_eq!(snapshot, sentinel());
        assert!(runtime.configuration.get().is_none());
        assert_eq!(SELECTS.load(Ordering::SeqCst), 0);
        assert_eq!(
            DIAGNOSTICS.lock().unwrap().as_slice(),
            [format!("reverie-dbt: {REFUSAL}\n")]
        );
    } else {
        assert_eq!(result, 0);
        assert_eq!(ready, 1);
        assert_eq!(snapshot.selected_event_bits, 0);
        assert_eq!(snapshot.owner_generation, 1);
        assert_eq!(SELECTS.load(Ordering::SeqCst), 1);
        assert!(DIAGNOSTICS.lock().unwrap().is_empty());
    }
    let started = unsafe {
        runtime.thread_init(
            &mut counters,
            fixture.context(),
            pid().as_raw(),
            pid().as_raw(),
            -1,
            0,
            0,
            invoke,
            read_registers,
            write_registers,
        )
    };
    if ROLE != 1 {
        assert_eq!(started, -1);
        assert!(counters.runtime_state.is_null());
        assert_eq!(NEWS.load(Ordering::SeqCst), 0);
        assert_eq!(STARTS.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.calls.get(), 0);
        assert!(events().is_empty());
    } else {
        assert_eq!(started, 0);
        assert!(!counters.runtime_state.is_null());
        assert_eq!(NEWS.load(Ordering::SeqCst), 1);
        assert_eq!(STARTS.load(Ordering::SeqCst), 1);
        assert_eq!(
            events(),
            [
                "unit-filter-probe",
                "claim",
                "claim-ack",
                "started",
                "started-ack",
                "native-ack-call"
            ]
        );
        // The test owns this synthetic attachment. No native exit or consuming
        // lifecycle is claimed; dispose it before the real socket server stops.
        unsafe {
            drop(Box::from_raw(
                counters
                    .runtime_state
                    .cast::<RootAttachment<AdmissionProbe<ROLE>>>(),
            ));
        }
        counters.runtime_state = std::ptr::null_mut();
        assert!(counters.runtime_state.is_null());
        fixture.shutdown();
    }
}

#[test]
fn typed_admission_precedes_readiness_and_construction() {
    if let Ok(case) = std::env::var(CASE_ENV) {
        match case.as_str() {
            "unknown" => exercise_admission::<0>(),
            "plain" => exercise_admission::<1>(),
            "record" => exercise_admission::<2>(),
            "replay" => exercise_admission::<3>(),
            _ => panic!("unexpected admission case"),
        }
        println!("FACILITY_ADMISSION_COMPLETED:{case}");
        return;
    }
    for case in ["unknown", "record", "replay", "plain"] {
        let directory = tempfile::tempdir().unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CASE_ENV, case)
            .env(
                crate::sync_rpc::RPC_SOCKET_ENV,
                directory.path().join("admission.sock"),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut child = ChildGuard(Some(child));
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "admission {case} timed out");
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        assert!(output.status.success(), "admission {case}: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("test result: ok. 1 passed;"), "{stdout}");
        assert_eq!(
            stdout
                .matches(&format!("FACILITY_ADMISSION_COMPLETED:{case}"))
                .count(),
            1
        );
    }
}
