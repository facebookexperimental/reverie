//! Ordinary main-thread fixture; the discovered integration tests own its bound.
#![cfg(target_os = "linux")]

use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::time::Duration;

mod owned_lifecycle;

use reverie_rpc_transport::guest_log::Options;
use reverie_rpc_transport::guest_log::Phase;
use reverie_rpc_transport::guest_log::PublishError;
use reverie_rpc_transport::guest_log::SharedBuffer;
use reverie_rpc_transport::guest_log::channel_pair;
use reverie_rpc_transport::guest_log::retained_log;

fn wait(mapping: &SharedBuffer, _: u32) -> Result<(), PublishError> {
    if mapping.stopped() {
        return Err(PublishError::Stopped);
    }
    std::thread::sleep(Duration::from_millis(1));
    Ok(())
}

fn producer(mode: &str, fd: i32) {
    // SAFETY: the fixture owns both peers, layout and all producer incarnations.
    let mapping = unsafe { SharedBuffer::receive(fd) }.unwrap();
    assert_eq!(
        unsafe { libc::getpid() },
        unsafe { libc::syscall(libc::SYS_gettid) } as i32
    );
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    let mut parent = unsafe { mapping.activate(0, i64::from(libc::getpid())) }.unwrap();
    parent
        .write_record(&mapping, b"parent\0record", wait)
        .unwrap();
    let slot = mapping.reserve_child(0).unwrap();
    let result = if mode == "failed-fork" {
        unsafe { libc::syscall(libc::SYS_clone, libc::CLONE_THREAD, 0, 0, 0, 0) }
    } else {
        i64::from(unsafe { libc::fork() })
    };
    if result == 0 {
        if mode == "death-before-attach" {
            unsafe {
                libc::_exit(0);
            }
        }
        let mut child = unsafe { mapping.activate(slot, i64::from(libc::getpid())) }.unwrap();
        if mode == "parent-first-exit" {
            std::thread::sleep(Duration::from_millis(50));
        }
        child
            .write_record(&mapping, b"child\xffrecord", wait)
            .unwrap();
        child.finish(&mapping, wait).unwrap();
        unsafe {
            libc::_exit(0);
        }
    }
    if mode == "failed-fork" {
        assert_eq!(result, -1);
    } else {
        assert!(result > 0);
    }
    mapping.resolve_fork(slot, result).unwrap();
    if mode == "wait-error" {
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(i32::MAX, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
    parent.finish(&mapping, wait).unwrap();
    if mode != "parent-first-exit" && result > 0 {
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(result as i32, &mut status, 0) },
            result as i32
        );
        assert_eq!(status, 0);
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.get(1).map(String::as_str) == Some("--split-startup-failure") {
        split_startup_failure(&arguments[2]);
        return;
    }
    if arguments.get(1).map(String::as_str) == Some("--split-lifecycle") {
        split_lifecycle(&arguments[2]);
        return;
    }
    if arguments.get(1).map(String::as_str) == Some("--split-ordered-guest") {
        split_ordered_guest(
            arguments[2].parse().unwrap(),
            &arguments[3],
            arguments[4].parse().unwrap(),
        );
        return;
    }
    if arguments.get(1).map(String::as_str) == Some("--split-rpc-shutdown") {
        split_rpc_shutdown(&arguments[2]);
        return;
    }
    if arguments.get(1).map(String::as_str) == Some("--ownership-control") {
        ownership_control(&arguments[2]);
        return;
    }
    if arguments.get(1).map(String::as_str) == Some("--ownership-leader") {
        ownership_leader();
    }
    if arguments.get(1).map(String::as_str) == Some("--ownership-holder") {
        use std::io::Write;
        println!("holder keeps stdout open");
        eprintln!("holder keeps stderr open");
        std::io::stdout().flush().unwrap();
        let fd: i32 = arguments[2].parse().unwrap();
        assert_eq!(unsafe { libc::write(fd, b"R".as_ptr().cast(), 1) }, 1);
        assert_eq!(unsafe { libc::close(fd) }, 0);
        loop {
            unsafe { libc::pause() };
        }
    }
    if arguments.get(1).map(String::as_str) == Some("--producer") {
        producer(&arguments[2], arguments[3].parse().unwrap());
        return;
    }
    let mode = arguments
        .get(1)
        .map(String::as_str)
        .expect("one lifecycle mode");
    assert!(
        [
            "fork",
            "wait-error",
            "failed-fork",
            "death-before-attach",
            "parent-first-exit"
        ]
        .contains(&mode)
    );
    // Own the orphaned descendant in parent-first-exit, without changing that case.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    {
        let options = Options {
            byte_limit: 4096,
            producers: 4,
            slots: 1,
        };
        let (host, guest) = unsafe { channel_pair(options) }.unwrap();
        let (sink, handle) = retained_log(options);
        let reader = unsafe { sink.reader(host) }.unwrap();
        let descriptor = guest.as_raw_fd();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--producer", mode, &descriptor.to_string()]);
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(descriptor, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        drop(guest);
        let collect = std::thread::spawn(move || reader.run());
        assert!(child.wait().unwrap().success());
        handle.root_reaped();
        let collected = collect.join().unwrap();
        // Collection can finish before wait() returns, particularly for failed
        // fork. Read retained reap state after actual wait, preserving the
        // collector's phase, closure and exact bytes as independent evidence.
        let report = handle.snapshot();
        assert_eq!(report.phase, collected.phase);
        assert_eq!(report.peer_closed, collected.peer_closed);
        assert_eq!(report.streams, collected.streams);
        assert!(
            report.peer_closed && report.root_reaped,
            "{mode}: {report:?}"
        );
        assert_eq!(report.streams[0].bytes, b"parent\0record", "{mode}");
        if mode == "death-before-attach" {
            assert_eq!(report.phase, Phase::Incomplete);
        } else {
            assert_eq!(report.phase, Phase::Complete, "{mode}: {report:?}");
            if mode != "failed-fork" {
                assert_eq!(report.streams[1].bytes, b"child\xffrecord");
            }
        }
        if mode == "parent-first-exit" {
            let mut status = 0;
            assert!(unsafe { libc::waitpid(-1, &mut status, 0) } > 0);
            assert_eq!(status, 0);
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        println!(
            "lifecycle {mode}: expected phase={:?}, streams={}, root_reaped={}, peer_closed={}",
            report.phase,
            report.streams.len(),
            report.root_reaped,
            report.peer_closed
        );
    }
    println!("ordinary lifecycle case completed and descendants reaped: {mode}");
}

fn ownership_leader() -> ! {
    use std::io::Read;
    use std::io::Write;
    let (mut ready, child_ready) = std::os::unix::net::UnixStream::pair().unwrap();
    let fd = child_ready.as_raw_fd();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--ownership-holder", &fd.to_string()]);
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(child_ready);
    let mut byte = [0];
    ready.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"R");
    println!("leader={} holder={}", std::process::id(), child.id());
    std::io::stdout().flush().unwrap();
    std::process::exit(17);
}

fn ownership_control(mode: &str) {
    assert_eq!(
        unsafe { libc::getpid() },
        unsafe { libc::syscall(libc::SYS_gettid) } as i32
    );
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    assert!(["early-exit", "single-signal"].contains(&mode));
    let start = std::time::Instant::now();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.arg("--ownership-leader");
    let (output, signals) = owned_lifecycle::run(command, Duration::from_secs(2)).unwrap();
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(output.status.code(), Some(17));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("holder keeps stdout open\n"), "{stdout}");
    assert_eq!(stderr, "holder keeps stderr open\n");
    let identity = stdout
        .lines()
        .find(|line| line.starts_with("leader="))
        .unwrap();
    let (leader, holder) = identity.split_once(' ').unwrap();
    let leader: i32 = leader.strip_prefix("leader=").unwrap().parse().unwrap();
    let holder: i32 = holder.strip_prefix("holder=").unwrap().parse().unwrap();
    // run() has already dropped its guard. Count actual syscalls, including
    // any unsuccessful attempt made by Drop after the leader was reaped.
    assert_eq!(signals, vec![(-leader, 0, None)]);
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(leader, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    // This fresh control process is the orphan's actual subreaper. No global
    // libtest reaper or unowned sleep process is left behind by this regression.
    loop {
        let reaped = unsafe { libc::waitpid(holder, &mut status, libc::WNOHANG) };
        if reaped == holder {
            break;
        }
        assert_eq!(reaped, 0);
        assert!(start.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
    assert_eq!(unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    println!("actual cleanup signals: {signals:?}; leader and holder reaped");
    println!("ownership control completed: {mode}");
}

// The split lifecycle needs completed runtime teardown, not merely an idle count.
struct SplitRpcProbe {
    open: std::sync::atomic::AtomicBool,
    entered: std::sync::atomic::AtomicBool,
    request_drops: std::sync::atomic::AtomicUsize,
    global_drops: std::sync::atomic::AtomicUsize,
    events: std::sync::Mutex<Vec<&'static str>>,
    emitter: Option<reverie_rpc_transport::guest_log::CoordinatorEmitter>,
}

impl SplitRpcProbe {
    fn new() -> Self {
        Self {
            open: std::sync::atomic::AtomicBool::new(true),
            entered: std::sync::atomic::AtomicBool::new(false),
            request_drops: std::sync::atomic::AtomicUsize::new(0),
            global_drops: std::sync::atomic::AtomicUsize::new(0),
            events: std::sync::Mutex::new(Vec::new()),
            emitter: None,
        }
    }

    fn emit(&self, event: &'static str) {
        assert!(self.open.load(std::sync::atomic::Ordering::Acquire));
        self.events.lock().unwrap().push(event);
        if let Some(emitter) = &self.emitter {
            emitter
                .write_record(format!("{event}\n").as_bytes())
                .unwrap();
        }
    }
}

struct SplitRpcGlobal(std::sync::Arc<SplitRpcProbe>);

impl Default for SplitRpcGlobal {
    fn default() -> Self {
        Self(std::sync::Arc::new(SplitRpcProbe::new()))
    }
}

impl Drop for SplitRpcGlobal {
    fn drop(&mut self) {
        self.0.emit("global-drop");
        self.0
            .global_drops
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    }
}

struct SplitRpcRequestDrop(std::sync::Arc<SplitRpcProbe>);

impl Drop for SplitRpcRequestDrop {
    fn drop(&mut self) {
        self.0.emit("request-drop");
        self.0
            .request_drops
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    }
}

// This is owned by the actual connection future. Its destructor runs when
// that future is destroyed, including after a normal Closed poll result.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct SplitRpcConfig {
    enabled: bool,
    connection_copy: bool,
}
impl Clone for SplitRpcConfig {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            connection_copy: true,
        }
    }
}
impl Drop for SplitRpcConfig {
    fn drop(&mut self) {
        if self.enabled && self.connection_copy {
            eprintln!("actual RPC connection configuration Drop panics");
            panic!("split RPC teardown destructor panic");
        }
    }
}

#[async_trait::async_trait]
impl reverie::GlobalTool for SplitRpcGlobal {
    type Config = SplitRpcConfig;
    type Request = u8;
    type Response = u32;

    async fn receive_rpc(&self, _: reverie::Tid, request: u8) -> u32 {
        let _drop = SplitRpcRequestDrop(self.0.clone());
        self.0.emit("request-entered");
        self.0
            .entered
            .store(true, std::sync::atomic::Ordering::Release);
        match request {
            0 => 37,
            1 => std::future::pending().await,
            2 => panic!("split RPC original panic"),
            _ => panic!("invalid fixture request"),
        }
    }
}

fn split_rpc_shutdown(mode: &str) {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use reverie_rpc_transport::ConnectionFailure;
    use reverie_rpc_transport::RpcServer;
    use tokio::io::AsyncWriteExt;

    assert!(
        [
            "clean",
            "planned",
            "unplanned",
            "panic",
            "decode",
            "drop-panic",
            "planned-drop-panic"
        ]
        .contains(&mode)
    );
    assert_eq!(
        unsafe { libc::getpid() },
        unsafe { libc::syscall(libc::SYS_gettid) } as i32
    );
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    let probe = Arc::new(SplitRpcProbe::new());
    let global = Arc::new(SplitRpcGlobal(probe.clone()));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let path = format!("/tmp/sa3-rpc-{}.sock", std::process::id());
    assert!(!std::path::Path::new(&path).exists());
    let (issues, connections, at_server_join) = runtime.block_on(async {
        let mut server = RpcServer::bind(
            &path,
            global.clone(),
            SplitRpcConfig {
                enabled: mode == "drop-panic" || mode == "planned-drop-panic",
                connection_copy: false,
            },
        )
        .unwrap();
        let issues = server.retain_connection_issues();
        let connections = server.connection_monitor();
        let serving = tokio::spawn(server.serve());
        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        reverie_rpc_transport::codec::read_message(&mut stream, 1024)
            .await
            .unwrap();
        if mode == "decode" {
            stream.write_all(&[5, 0]).await.unwrap();
            drop(stream);
            tokio::time::timeout(Duration::from_secs(2), issues.failed())
                .await
                .unwrap();
        } else {
            let request = reverie_rpc_transport::RequestEnvelope {
                from: reverie::Tid::from_raw(1),
                request: match mode {
                    "clean" | "drop-panic" => 0u8,
                    "panic" => 2,
                    _ => 1,
                },
            };
            let bytes = reverie_rpc_transport::codec::encode(&request).unwrap();
            reverie_rpc_transport::codec::write_message(&mut stream, &bytes)
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while !probe.entered.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            if mode == "clean" || mode == "drop-panic" {
                let bytes = reverie_rpc_transport::codec::read_message(&mut stream, 1024)
                    .await
                    .unwrap();
                let value: u32 = reverie_rpc_transport::codec::decode(&bytes).unwrap();
                assert_eq!(value, 37);
                drop(stream);
                connections.wait_for_idle().await;
            } else if mode == "panic" {
                tokio::time::timeout(Duration::from_secs(2), issues.failed())
                    .await
                    .unwrap();
                drop(stream);
            } else {
                assert_eq!(probe.request_drops.load(Ordering::Acquire), 0);
                assert!(issues.snapshot().is_empty());
                // Keep the actual pending connection alive until cancellation.
                if mode == "planned" || mode == "planned-drop-panic" {
                    issues.planned_shutdown();
                }
                serving.abort();
                assert!(serving.await.unwrap_err().is_cancelled());
                let at_join = probe.request_drops.load(Ordering::Acquire);
                probe.emit("serving-task-joined");
                drop(stream);
                return (issues, connections, at_join);
            }
        }
        issues.planned_shutdown();
        serving.abort();
        assert!(serving.await.unwrap_err().is_cancelled());
        let at_join = probe.request_drops.load(Ordering::Acquire);
        probe.emit("serving-task-joined");
        (issues, connections, at_join)
    });
    // Outside async execution, with logging still admitted. No shutdown_timeout,
    // detached runtime, or claim that Drop can preempt arbitrary user code.
    drop(runtime);
    probe.emit("runtime-dropped");
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    assert_eq!(
        Arc::strong_count(&global),
        1,
        "RPC task retained global state"
    );
    assert_eq!(connections.active_connections(), 0);
    let final_issues = issues.snapshot();
    match mode {
        "clean" | "planned" => assert!(final_issues.is_empty(), "{final_issues:?}"),
        "drop-panic" | "planned-drop-panic" => {
            println!("actual destructor-panic final monitor: {final_issues:?}");
            assert!(
                !final_issues.is_empty(),
                "RPC teardown panic was lost despite completed runtime teardown"
            );
        }
        "unplanned" => {
            assert_eq!(final_issues.len(), 1);
            assert!(matches!(
                final_issues[0].failure,
                ConnectionFailure::Interrupted
            ));
        }
        "panic" => {
            assert_eq!(final_issues.len(), 1);
            let ConnectionFailure::Panicked(payload) = &final_issues[0].failure else {
                panic!("{final_issues:?}");
            };
            assert_eq!(
                payload.0.lock().unwrap().downcast_ref::<&str>(),
                Some(&"split RPC original panic")
            );
        }
        "decode" => {
            assert_eq!(final_issues.len(), 1);
            let ConnectionFailure::Transport(error) = &final_issues[0].failure else {
                panic!("{final_issues:?}");
            };
            assert!(
                matches!(&**error, reverie_rpc_transport::RpcError::Io(error) if error.kind() == std::io::ErrorKind::UnexpectedEof)
            );
        }
        _ => unreachable!(),
    }
    if let Some(issue) = final_issues.first() {
        assert_eq!(issue.connection, 1);
    }
    assert_eq!(
        probe.request_drops.load(Ordering::Acquire),
        usize::from(mode != "decode")
    );
    drop(global);
    assert_eq!(probe.global_drops.load(Ordering::Acquire), 1);
    probe.emit("final-snapshot-and-global-teardown");
    probe.open.store(false, Ordering::Release);
    assert!(!std::path::Path::new(&path).exists());
    println!(
        "split RPC teardown {mode}: request_drops_at_server_join={at_server_join}; final_request_drops={}; global_drops=1; issues={final_issues:?}; events={:?}",
        probe.request_drops.load(Ordering::Acquire),
        probe.events.lock().unwrap()
    );
    println!("split RPC shutdown completed with actual runtime teardown: {mode}");
}

struct SplitOutput {
    file: std::fs::File,
    bytes: u64,
    gate: Option<std::os::unix::net::UnixStream>,
    drop_marker: Option<std::path::PathBuf>,
    flush_failure: bool,
    output_ceiling: bool,
    discarded: u64,
}
impl Drop for SplitOutput {
    fn drop(&mut self) {
        if let Some(path) = &self.drop_marker {
            assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
            std::fs::write(path, b"D-drop after actual joins").unwrap();
        }
    }
}
impl std::io::Write for SplitOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Some(mut gate) = self.gate.take() {
            let mut byte = [0];
            std::io::Read::read_exact(&mut gate, &mut byte)?;
            assert_eq!(byte, [b'R']);
        }
        if self.output_ceiling {
            let retained = bytes.len().min(12usize.saturating_sub(self.bytes as usize));
            self.file.write_all(&bytes[..retained])?;
            self.bytes += retained as u64;
            self.discarded += (bytes.len() - retained) as u64;
            return Ok(bytes.len());
        }
        let count = self.file.write(bytes)?;
        self.bytes += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if self.flush_failure {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        self.file.flush()
    }
}
impl reverie_rpc_transport::guest_log::CaptureDestination for SplitOutput {
    fn progress(&self) -> reverie_rpc_transport::guest_log::DestinationProgress {
        reverie_rpc_transport::guest_log::DestinationProgress {
            acknowledged_data_bytes: self.bytes,
            output_ceiling: self.discarded != 0,
            discarded_bytes: self.discarded,
            ..Default::default()
        }
    }
}
struct SplitFactoryDrop {
    file: std::fs::File,
    owner_pid: u32,
    panic_after_cleanup: bool,
}
impl Drop for SplitFactoryDrop {
    fn drop(&mut self) {
        use std::io::Write;
        assert_eq!(
            std::process::id(),
            self.owner_pid,
            "borrowed O factory was dropped in C"
        );
        assert_eq!(
            std::fs::read_dir("/proc/self/task").unwrap().count(),
            1,
            "factory freed before actual O joins"
        );
        self.file.write_all(b"factory-drop\n").unwrap();
        assert!(
            !self.panic_after_cleanup,
            "actual O factory Drop panic after joins"
        );
    }
}
struct SplitLoggedValue {
    value: Vec<u8>,
    emitter: Option<reverie_rpc_transport::guest_log::CoordinatorEmitter>,
    behavior: String,
    field: Option<SplitRecordDrop>,
}
impl<'de> serde::Deserialize<'de> for SplitLoggedValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Vec::<u8>::deserialize(deserializer)?;
        if value == [255] {
            return Err(serde::de::Error::custom("actual result decoder refusal"));
        }
        Ok(Self {
            value,
            emitter: None,
            behavior: String::new(),
            field: None,
        })
    }
}
impl serde::Serialize for SplitLoggedValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let Some(emitter) = &self.emitter {
            emitter.write_record(b"serialize\n").unwrap();
        }
        if self.behavior == "serialize-error" {
            return Err(serde::ser::Error::custom("actual serializer refusal"));
        }
        assert_ne!(self.behavior, "serialize-panic", "actual serializer panic");
        if self.behavior == "stalled-serializer" {
            std::fs::write(
                std::env::var_os("SPLIT_STALL_MARKER").expect("owned outer marker"),
                b"actual serializer entered",
            )
            .unwrap();
            loop {
                std::thread::park();
            }
        }
        serde::Serialize::serialize(&self.value, serializer)
    }
}
impl Drop for SplitLoggedValue {
    fn drop(&mut self) {
        if let Some(emitter) = &self.emitter {
            emitter.write_record(b"T-drop\n").unwrap();
        }
        assert_ne!(self.behavior, "T-panic", "actual result destructor panic");
        drop(self.field.take());
    }
}
struct SplitRecordDrop(
    Option<(
        reverie_rpc_transport::guest_log::CoordinatorEmitter,
        &'static [u8],
    )>,
    bool,
);
impl SplitRecordDrop {
    fn attach(&mut self, emitter: reverie_rpc_transport::guest_log::CoordinatorEmitter) {
        self.0 = Some((emitter, b"W-drop\n"));
    }
}
impl Drop for SplitRecordDrop {
    fn drop(&mut self) {
        if let Some((emitter, record)) = &self.0 {
            emitter.write_record(record).unwrap();
        }
        assert!(!self.1, "actual C-created capture/field destructor panic");
    }
}
struct SplitDeferredDrop {
    emitter: reverie_rpc_transport::guest_log::CoordinatorEmitter,
    hold: Option<std::os::unix::net::UnixStream>,
    marker: std::path::PathBuf,
    panic_on_drop: bool,
}
impl Drop for SplitDeferredDrop {
    fn drop(&mut self) {
        self.emitter.write_record(b"U-drop\n").unwrap();
        assert!(!self.panic_on_drop, "actual deferred destructor panic");
        if let Some(hold) = &mut self.hold {
            std::fs::write(
                &self.marker,
                b"actual C deferred Drop entered after result EOF",
            )
            .unwrap();
            let mut byte = [0];
            std::io::Read::read_exact(hold, &mut byte).unwrap();
            panic!("held deferred cleanup must be cancelled, never released");
        }
    }
}
fn split_ordered_guest(fd: i32, mode: &str, expected_parent: i32) {
    let guest7 = mode.ends_with("-guest7");
    let mode = mode.strip_suffix("-guest7").unwrap_or(mode);
    assert_eq!(unsafe { libc::getppid() }, expected_parent);
    assert_eq!(
        unsafe { libc::getpid() },
        unsafe { libc::syscall(libc::SYS_gettid) } as i32
    );
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    println!(
        "actual G pid={} ppid={} tid={}",
        std::process::id(),
        unsafe { libc::getppid() },
        unsafe { libc::syscall(libc::SYS_gettid) }
    );
    use reverie_rpc_transport::guest_log::ordered;
    if mode.starts_with("rpc-") {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            use reverie_rpc_transport::codec;
            use tokio::io::AsyncWriteExt;
            let path = format!("/tmp/sa3-composed-rpc-{expected_parent}.sock");
            let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
            codec::read_message(&mut stream, 1024).await.unwrap();
            if mode == "rpc-truncated-header" {
                stream.write_all(&[5, 0]).await.unwrap();
                return;
            }
            let request = reverie_rpc_transport::RequestEnvelope {
                from: reverie::Tid::from_raw(std::process::id() as i32),
                request: if mode == "rpc-panic" { 2u8 } else { 0u8 },
            };
            let bytes = codec::encode(&request).unwrap();
            codec::write_message(&mut stream, &bytes).await.unwrap();
            let response = codec::read_message(&mut stream, 1024).await;
            if mode == "rpc-panic" {
                assert!(response.is_err());
            } else {
                assert_eq!(codec::decode::<u32>(&response.unwrap()).unwrap(), 37);
            }
        });
        drop(runtime);
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    }
    let endpoint =
        unsafe { <std::os::unix::net::UnixStream as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    let buffer = unsafe { ordered::Buffer::receive(endpoint.as_raw_fd()) }.unwrap();
    let mut writer = unsafe { buffer.activate(1, i64::from(std::process::id())) }.unwrap();
    writer.write_record(b"guest\n", wait).unwrap();
    if mode != "missing-finish" {
        writer.finish(wait).unwrap();
    }
    drop(writer);
    drop(buffer);
    drop(endpoint);
    if mode == "guest-nonzero" || guest7 {
        std::process::exit(7);
    }
}

fn split_composed_rpc_guest(
    command: &mut std::process::Command,
    emitter: &reverie_rpc_transport::guest_log::CoordinatorEmitter,
    mode: &str,
) -> (
    u32,
    std::process::ExitStatus,
    Vec<reverie_rpc_transport::ConnectionIssue>,
) {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use reverie_rpc_transport::RpcServer;

    let mut probe = SplitRpcProbe::new();
    probe.emitter = Some(emitter.clone());
    let probe = Arc::new(probe);
    let global = Arc::new(SplitRpcGlobal(probe.clone()));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let path = format!("/tmp/sa3-composed-rpc-{}.sock", std::process::id());
    assert!(!std::path::Path::new(&path).exists());
    let mut server = {
        let _entered = runtime.enter();
        RpcServer::bind(
            &path,
            global.clone(),
            SplitRpcConfig {
                enabled: mode == "rpc-drop-panic",
                connection_copy: false,
            },
        )
        .unwrap()
    };
    let issues = server.retain_connection_issues();
    let connections = server.connection_monitor();
    // A current-thread runtime has not introduced a helper before G's clone.
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    let mut guest = command.spawn().unwrap();
    let guest_pid = guest.id();
    let status = runtime.block_on(async {
        let serving = tokio::spawn(server.serve());
        let status = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(status) = guest.try_wait().unwrap() {
                    break status;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), connections.wait_for_idle())
            .await
            .unwrap();
        issues.planned_shutdown();
        serving.abort();
        assert!(serving.await.unwrap_err().is_cancelled());
        probe.emit("serving-task-joined");
        status
    });
    drop(runtime); // Outside async, emission still open through task destruction.
    probe.emit("runtime-dropped");
    assert_eq!(Arc::strong_count(&global), 1);
    assert_eq!(connections.active_connections(), 0);
    let final_issues = issues.snapshot();
    assert_eq!(final_issues.is_empty(), mode == "rpc-complete");
    assert_eq!(
        probe.request_drops.load(Ordering::Acquire),
        usize::from(mode != "rpc-truncated-header")
    );
    drop(global);
    assert_eq!(probe.global_drops.load(Ordering::Acquire), 1);
    probe.open.store(false, Ordering::Release);
    assert!(!std::path::Path::new(&path).exists());
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    println!(
        "actual composed RPC {mode}: G{guest_pid} status={status:?}, final issues={final_issues:?}"
    );
    (guest_pid, status, final_issues)
}
// A real O-held alias, transferred by C, keeps the transport endpoint open
// after C and G have both exited. No helper process or guessed PID is needed.
fn send_endpoint_alias(socket: &std::os::unix::net::UnixDatagram, fd: i32) {
    unsafe {
        let mut byte = b'A';
        let mut vector = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        let mut control = [0usize; 4];
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<i32>() as _) as usize;
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as _) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), fd);
        assert_eq!(libc::sendmsg(socket.as_raw_fd(), &message, 0), 1);
    }
}
fn receive_endpoint_alias(socket: &std::os::unix::net::UnixDatagram) -> std::os::fd::OwnedFd {
    use std::os::fd::FromRawFd;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    unsafe {
        let mut byte = 0u8;
        let mut vector = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        let mut control = [0usize; 4];
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        assert_eq!(
            libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC),
            1
        );
        assert_eq!(byte, b'A');
        assert_eq!(message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC), 0);
        let header = libc::CMSG_FIRSTHDR(&message);
        assert!(!header.is_null());
        assert_eq!((*header).cmsg_level, libc::SOL_SOCKET);
        assert_eq!((*header).cmsg_type, libc::SCM_RIGHTS);
        assert_eq!(
            (*header).cmsg_len,
            libc::CMSG_LEN(std::mem::size_of::<i32>() as _) as usize
        );
        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>());
        assert!(fd >= 0);
        assert!(libc::CMSG_NXTHDR(&message, header).is_null());
        std::os::fd::OwnedFd::from_raw_fd(fd)
    }
}
// Keep setup failure non-core-producing: a refused prctl must not panic
// through the raw-clone extern-C callback while C is still dumpable.
fn split_dumpability_refused(stage: &[u8], result: i32, errno: i32) -> ! {
    fn write(bytes: &[u8]) {
        unsafe {
            libc::write(libc::STDERR_FILENO, bytes.as_ptr().cast(), bytes.len());
        }
    }
    fn number(value: i32) {
        let mut bytes = [0u8; 12];
        let mut at = bytes.len();
        let mut magnitude = i64::from(value).unsigned_abs();
        loop {
            at -= 1;
            bytes[at] = b'0' + (magnitude % 10) as u8;
            magnitude /= 10;
            if magnitude == 0 {
                break;
            }
        }
        if value < 0 {
            at -= 1;
            bytes[at] = b'-';
        }
        write(&bytes[at..]);
    }
    write(b"split-fixture dumpability-setup-refused stage=");
    write(stage);
    write(b" raw_result=");
    number(result);
    write(b" errno=");
    number(errno);
    write(b" noncore_exit=90 intended-abort-not-entered\n");
    unsafe { libc::_exit(90) }
}

fn split_contain_intentional_abort() {
    let result = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if result != 0 {
        let errno = unsafe { *libc::__errno_location() };
        split_dumpability_refused(b"SET", result, errno);
    }
    let result = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    if result != 0 {
        let errno = if result < 0 {
            unsafe { *libc::__errno_location() }
        } else {
            0
        };
        split_dumpability_refused(b"GET", result, errno);
    }
}

fn split_lifecycle(case: &str) {
    let guest7 = case.ends_with("-guest7");
    let mode = case.strip_suffix("-guest7").unwrap_or(case);
    let intentional_abort = matches!(
        mode,
        "serialize-error" | "serialize-panic" | "T-panic" | "field-panic" | "U-panic" | "W-panic"
    );
    use std::os::unix::process::ExitStatusExt;
    use std::time::Instant;

    use reverie::process::Container;
    use reverie::process::ExitStatus;
    use reverie_rpc_transport::guest_log as g;
    assert!(
        [
            "complete",
            "guest-nonzero",
            "caught-panic",
            "coordinator-error",
            "policy-refusal",
            "run-timeout",
            "missing-finish",
            "large",
            "second-clone",
            "held-publication",
            "serialize-error",
            "coordinator-exit",
            "coordinator-sigpipe",
            "stalled-serializer",
            "namespace",
            "namespace-helper",
            "namespace-double-reservation",
            "cancel-pending",
            "drop-pending",
            "rpc-complete",
            "rpc-panic",
            "rpc-drop-panic",
            "rpc-truncated-header",
            "drop-publication",
            "factory-drop-panic",
            "serialize-panic",
            "T-panic",
            "field-panic",
            "U-panic",
            "W-panic",
            "flush-eio",
            "output-ceiling",
            "decode-error",
            "held-endpoint"
        ]
        .contains(&mode)
    );
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    let root = std::path::PathBuf::from(format!("/tmp/sa3-life-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let repetitions = if mode == "second-clone" { 2 } else { 1 };
    let original_fds = std::fs::read_dir("/proc/self/fd").unwrap().count();
    for turn in 0..repetitions {
        assert_eq!(
            std::fs::read_dir("/proc/self/fd").unwrap().count(),
            original_fds
        );
        let output_path = root.join(format!("output-{turn}"));
        let factory_path = root.join(format!("factory-{turn}"));
        let factory = SplitFactoryDrop {
            file: std::fs::File::create(&factory_path).unwrap(),
            owner_pid: std::process::id(),
            panic_after_cleanup: mode == "factory-drop-panic",
        };
        let settings = g::CaptureOptions {
            limits: g::CaptureLimits {
                producers: 4,
                slots_per_producer: 8,
                max_record_bytes: 4096,
                host_pending_bytes: 8192,
                guest_pending_bytes: 8192,
                pending_records: 16,
                diagnostic_bytes: 4096,
            },
            timeouts: g::CaptureTimeouts {
                startup: Duration::from_secs(2),
                blocked_publication: Duration::from_secs(2),
                final_drain: Duration::from_secs(2),
            },
        };
        let plan = unsafe { g::SplitCapturePlan::new(settings) }.unwrap();
        let destination_path = output_path.clone();
        let selected = mode.to_string();
        let large = mode == "large";
        let (gate_reader, mut gate_writer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut gate_reader = if mode == "drop-publication" {
            let fd = std::env::var("SPLIT_DISPOSE_FD")
                .unwrap()
                .parse::<i32>()
                .unwrap();
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                0
            );
            Some(unsafe {
                <std::os::unix::net::UnixStream as std::os::fd::FromRawFd>::from_raw_fd(fd)
            })
        } else {
            (mode == "held-publication").then_some(gate_reader)
        };
        let destination_drop = root.join(format!("D-drop-{turn}"));
        let destination_marker = matches!(mode, "drop-publication" | "factory-drop-panic")
            .then(|| destination_drop.clone());
        let mut container = Container::new();
        if mode.starts_with("namespace") {
            container.unshare(reverie::process::Namespace::USER | reverie::process::Namespace::PID);
        }
        let original_parent = std::process::id();
        let (child_hold, _hold_writer) = std::os::unix::net::UnixStream::pair().unwrap();
        let child_hold = matches!(mode, "cancel-pending" | "drop-pending").then_some(child_hold);
        let marker = root.join(format!("C-deferred-{turn}"));
        let child_marker = marker.clone();
        let (alias_receiver, alias_sender) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let actual_pid = std::cell::Cell::new(0i32);
        let observer = std::cell::Cell::<Option<std::os::fd::OwnedFd>>::new(None);
        let actual_pid_ref = &actual_pid;
        let observer_ref = &observer;
        let run = unsafe {
            g::run_split_capture(
                &mut container,
                plan,
                move |context| {
                    actual_pid_ref.set(context.child_pid().as_raw());
                    let duplicate =
                        libc::fcntl(context.child_pidfd().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0);
                    assert!(duplicate >= 0);
                    observer_ref.set(Some(
                        <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(duplicate),
                    ));
                    // Include the actual A2 result reader among ALL live parent pipe FDs.
                    // No guess about default pipe capacity supports the large-result case.
                    if large {
                        let capacities: Vec<_> = std::fs::read_dir("/proc/self/fd")
                            .unwrap()
                            .filter_map(Result::ok)
                            .filter_map(|entry| {
                                entry
                                    .file_name()
                                    .to_str()
                                    .and_then(|name| name.parse::<i32>().ok())
                            })
                            .filter_map(|fd| {
                                let size = libc::fcntl(fd, libc::F_GETPIPE_SZ);
                                (size > 0).then_some((fd, size))
                            })
                            .collect();
                        assert!(!capacities.is_empty());
                        assert!(capacities.iter().all(|(_, size)| *size < 10 * 1024 * 1024));
                        println!(
                            "actual live pipe FD capacities at parent startup: {capacities:?}"
                        );
                    }
                    Ok(SplitOutput {
                        file: std::fs::File::create(&destination_path).unwrap(),
                        bytes: 0,
                        gate: gate_reader.take(),
                        drop_marker: destination_marker.clone(),
                        flush_failure: mode == "flush-eio",
                        output_ceiling: mode == "output-ceiling",
                        discarded: 0,
                    })
                },
                move |_| {
                    let _borrowed_factory = &factory;
                    let selected = selected.clone();
                    let mut work_drop = SplitRecordDrop(None, selected == "W-panic"); // Newly C-created W capture.
                    let child_hold = child_hold.as_ref().map(|fd| fd.try_clone().unwrap());
                    let child_marker = child_marker.clone();
                    let alias_sender = alias_sender.try_clone().unwrap();
                    Ok(move |mut context: g::CoordinatorContext| {
                        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
                        assert_eq!(libc::getpid(), libc::syscall(libc::SYS_gettid) as i32);
                        if selected.starts_with("namespace") {
                            assert_eq!(libc::getpid(), 1);
                            assert_eq!(libc::getppid(), 0);
                        } else {
                            assert_eq!(libc::getppid(), original_parent as i32);
                        }
                        println!(
                            "actual C pid={} ppid={} tid={} original_O={original_parent}",
                            libc::getpid(),
                            libc::getppid(),
                            libc::syscall(libc::SYS_gettid)
                        );
                        let emitter = context.emitter();
                        work_drop.attach(emitter.clone());
                        emitter.write_record(b"work\n").unwrap();
                        if selected.starts_with("namespace") {
                            let reserve = libc::fork();
                            assert!(reserve >= 0);
                            if reserve == 0 {
                                libc::_exit(0);
                            }
                            assert_eq!(reserve, 2);
                            let mut status = 0;
                            assert_eq!(libc::waitpid(reserve, &mut status, 0), reserve);
                            assert_eq!(status, 0);
                            if selected == "namespace-helper" {
                                assert_eq!(
                                    std::thread::spawn(|| libc::syscall(libc::SYS_gettid))
                                        .join()
                                        .unwrap(),
                                    3
                                );
                            }
                            if selected == "namespace-double-reservation" {
                                let extra = libc::fork();
                                if extra == 0 {
                                    libc::_exit(0);
                                }
                                assert_eq!(extra, 3);
                                assert_eq!(libc::waitpid(extra, &mut status, 0), extra);
                                assert_eq!(status, 0);
                            }
                        }
                        let endpoint = context.guest_endpoint().unwrap();
                        let fd = endpoint.as_raw_fd();
                        if selected == "held-endpoint" {
                            send_endpoint_alias(&alias_sender, fd);
                        }
                        let mut command =
                            std::process::Command::new(std::env::current_exe().unwrap());
                        command.args([
                            "--split-ordered-guest",
                            &fd.to_string(),
                            &if guest7 {
                                format!("{selected}-guest7")
                            } else {
                                selected.clone()
                            },
                            &libc::getpid().to_string(),
                        ]);
                        command.pre_exec(move || {
                            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                                return Err(std::io::Error::last_os_error());
                            }
                            Ok(())
                        });
                        let (guest_pid, status, rpc_issues) = if selected.starts_with("rpc-") {
                            split_composed_rpc_guest(&mut command, &emitter, &selected)
                        } else {
                            let mut guest = command.spawn().unwrap();
                            let guest_pid = guest.id();
                            (guest_pid, guest.wait().unwrap(), Vec::new()) // Actual G wait before facts.
                        };
                        if selected.starts_with("namespace") {
                            let later_tid = std::thread::spawn(|| libc::syscall(libc::SYS_gettid))
                                .join()
                                .unwrap();
                            let observed = (libc::getpid(), 2, guest_pid, later_tid);
                            if selected == "namespace" {
                                assert_eq!(observed, (1, 2, 3, 4));
                            } else {
                                assert_eq!(observed, (1, 2, 4, 5));
                                assert_ne!(observed, (1, 2, 3, 4));
                            }
                            println!(
                                "actual namespace population: {observed:?}; original identity predicate={}",
                                observed == (1, 2, 3, 4)
                            );
                        }
                        drop(endpoint);
                        if intentional_abort {
                            // G has been reaped. Contain only C's intentional abort, before
                            // W is dropped or serialization/value/deferred teardown begins.
                            // A host core helper must not participate in the join deadline.
                            split_contain_intentional_abort();
                        }
                        let disposition = if selected == "caught-panic" {
                            let caught = std::panic::catch_unwind(|| {
                                panic!("caught coordinator fixture panic")
                            });
                            assert!(caught.is_err());
                            g::CoordinatorDisposition::CaughtPanic
                        } else {
                            match selected.as_str() {
                                "coordinator-error" => g::CoordinatorDisposition::CoordinatorError,
                                "policy-refusal" => g::CoordinatorDisposition::PolicyRefusal,
                                "run-timeout" => g::CoordinatorDisposition::RunTimeout,
                                _ => g::CoordinatorDisposition::Completed,
                            }
                        };
                        if selected == "coordinator-exit" {
                            libc::_exit(23);
                        }
                        if selected == "coordinator-sigpipe" {
                            assert_ne!(libc::signal(libc::SIGPIPE, libc::SIG_DFL), libc::SIG_ERR);
                            let mut fds = [0; 2];
                            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
                            assert_eq!(libc::close(fds[0]), 0);
                            libc::write(fds[1], b"X".as_ptr().cast(), 1);
                            panic!("default SIGPIPE did not terminate C");
                        }
                        emitter.write_record(b"work-return\n").unwrap();
                        let value = SplitLoggedValue {
                            value: vec![
                                if selected == "decode-error" { 255 } else { 37 };
                                if selected == "large" {
                                    10 * 1024 * 1024
                                } else {
                                    1
                                }
                            ],
                            emitter: Some(emitter.clone()),
                            behavior: selected.clone(),
                            field: Some(SplitRecordDrop(
                                Some((emitter.clone(), b"field-drop\n")),
                                selected == "field-panic",
                            )),
                        };
                        (
                            context.after_teardown(
                                value,
                                disposition,
                                ExitStatus::from_raw(status.into_raw()),
                                &rpc_issues,
                            ),
                            SplitDeferredDrop {
                                emitter,
                                hold: child_hold,
                                marker: child_marker,
                                panic_on_drop: selected == "U-panic",
                            },
                        )
                    })
                },
            )
        };
        if matches!(mode, "cancel-pending" | "drop-pending") {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !marker.exists() {
                assert!(Instant::now() < deadline);
                std::thread::yield_now();
            }
            assert!(std::fs::read(&factory_path).unwrap().is_empty());
            if mode == "drop-pending" {
                drop(run);
            } else {
                let g::SplitCaptureOutcome::Joined(joined) =
                    run.cancel_until(Instant::now() + Duration::from_secs(2))
                else {
                    panic!("bounded cancellation did not join");
                };
                assert!(!joined.report.qualifies());
                assert!(matches!(
                    joined.integrity,
                    g::TerminalCaptureIntegrity::Incomplete { .. }
                ));
                assert!(
                    joined
                        .report
                        .failure
                        .as_ref()
                        .unwrap()
                        .contains("cancelled")
                );
                assert_eq!(
                    joined.actual_coordinator_status.unwrap().signal(),
                    Some(libc::SIGKILL)
                );
                assert_eq!(joined.actual_joins, (true, true));
            }
            let observer = observer.take().unwrap();
            let mut poll = libc::pollfd {
                fd: observer.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut poll, 1, 0) }, 1);
            assert_ne!(poll.revents & libc::POLLIN, 0);
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(actual_pid.get(), &mut status, libc::WNOHANG) },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
            assert_eq!(std::fs::read(&factory_path).unwrap(), b"factory-drop\n");
            println!(
                "actual {mode}: C{} pidfd exited and wait ECHILD; factory retained until all cleanup",
                actual_pid.get()
            );
            continue;
        }
        if mode == "factory-drop-panic" {
            let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run.settle_until(Instant::now() + Duration::from_secs(2))
            }));
            assert!(
                failure.is_err(),
                "factory panic escaped as a returned capture"
            );
            assert_eq!(std::fs::read(&factory_path).unwrap(), b"factory-drop\n");
            assert_eq!(
                std::fs::read(&destination_drop).unwrap(),
                b"D-drop after actual joins"
            );
            let observer = observer.take().unwrap();
            let mut poll = libc::pollfd {
                fd: observer.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut poll, 1, 0) }, 1);
            assert_ne!(poll.revents & libc::POLLIN, 0);
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(actual_pid.get(), &mut status, libc::WNOHANG) },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
            assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
            println!(
                "actual factory panic propagated only after pidfd exit, reap, D and worker cleanup"
            );
            continue;
        }
        let alias = (mode == "held-endpoint").then(|| receive_endpoint_alias(&alias_receiver));
        let outcome = run.settle_until(Instant::now() + Duration::from_secs(2));
        drop(alias);
        let outcome = if mode == "held-endpoint" {
            match outcome {
                g::SplitCaptureOutcome::Unjoined(run) => {
                    run.settle_until(Instant::now() + Duration::from_secs(2))
                }
                joined => joined,
            }
        } else {
            outcome
        };
        if mode == "drop-publication" {
            let g::SplitCaptureOutcome::Unjoined(run) = outcome else {
                panic!("held output was declared joined before implicit disposal");
            };
            assert!(std::fs::read(&factory_path).unwrap().is_empty());
            assert!(!destination_drop.exists());
            let marker =
                std::path::PathBuf::from(std::env::var_os("SPLIT_DISPOSE_MARKER").unwrap());
            let pending_marker = marker.with_extension("pending");
            assert!(!pending_marker.exists());
            std::fs::write(
                &pending_marker,
                b"entering owned disposal with held publication",
            )
            .unwrap();
            std::fs::rename(pending_marker, marker).unwrap();
            drop(run); // External integration controller releases the actual Write.
            assert_eq!(std::fs::read(&factory_path).unwrap(), b"factory-drop\n");
            assert_eq!(
                std::fs::read(&destination_drop).unwrap(),
                b"D-drop after actual joins"
            );
            assert_eq!(std::fs::read(&output_path).unwrap(), b"work\n");
            assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
            println!(
                "actual implicit disposal retained D/factory until held publication was released and joined"
            );
            continue;
        }
        let outcome = if mode == "held-publication" {
            let g::SplitCaptureOutcome::Unjoined(run) = outcome else {
                panic!("blocked output was declared joined");
            };
            assert!(
                std::fs::read(&factory_path).unwrap().is_empty(),
                "factory released before output join"
            );
            std::io::Write::write_all(&mut gate_writer, b"R").unwrap();
            run.settle_until(Instant::now() + Duration::from_secs(2))
        } else {
            outcome
        };
        let joined = match outcome {
            g::SplitCaptureOutcome::Joined(joined) => joined,
            g::SplitCaptureOutcome::Unjoined(_) => panic!("split fixture did not actually join"),
        };
        let expected = !guest7
            && matches!(
                mode,
                "complete"
                    | "large"
                    | "second-clone"
                    | "namespace"
                    | "namespace-helper"
                    | "namespace-double-reservation"
                    | "rpc-complete"
            );
        assert_eq!(joined.report.qualifies(), expected, "{:?}", joined.report);
        let intact = expected || mode == "guest-nonzero" || (guest7 && mode == "complete");
        if intact {
            assert_eq!(
                joined.integrity,
                g::TerminalCaptureIntegrity::Complete {
                    guest_status: std::process::ExitStatus::from(ExitStatus::Exited(
                        if guest7 || mode == "guest-nonzero" {
                            7
                        } else {
                            0
                        }
                    )),
                },
                "{case}: {:?}",
                joined.report
            );
        } else {
            let g::TerminalCaptureIntegrity::Incomplete { faults } = joined.integrity else {
                panic!(
                    "{case}: faulted capture declared complete: {:?}",
                    joined.report
                );
            };
            assert!(!faults.is_empty());
            if matches!(mode, "flush-eio" | "output-ceiling" | "held-publication") {
                assert!(
                    faults.contains(g::IntegrityFault::Publication),
                    "{faults:?}"
                );
            }
            if mode.starts_with("rpc-") && mode != "rpc-complete" {
                assert!(faults.contains(g::IntegrityFault::Rpc), "{faults:?}");
            }
            if matches!(mode, "held-endpoint" | "missing-finish") {
                assert!(faults.contains(g::IntegrityFault::Collector), "{faults:?}");
            }
            if mode == "decode-error" {
                assert!(
                    faults.contains(g::IntegrityFault::DecodeBinding),
                    "{faults:?}"
                );
                assert!(joined.facts.is_none());
                assert!(joined.value.is_none());
                assert_eq!(joined.actual_joins, (true, true));
                assert_eq!(joined.actual_coordinator_status, Some(ExitStatus::SUCCESS));
                assert!(!joined.encoded_bytes.is_empty());
                println!(
                    "actual split {case}: decoder refusal retained: {:?}",
                    joined.report
                );
                continue;
            }
        }
        if guest7 || mode == "guest-nonzero" {
            assert_eq!(
                joined.facts.as_ref().unwrap().guest_wait_status,
                ExitStatus::Exited(7).into_raw()
            );
            assert_eq!(
                joined.report.capture.as_ref().unwrap().guest.run,
                g::RunState::Failed
            );
            assert!(joined.report.capture.as_ref().unwrap().error.is_some());
        }
        if matches!(
            mode,
            "serialize-error"
                | "coordinator-exit"
                | "coordinator-sigpipe"
                | "serialize-panic"
                | "T-panic"
                | "field-panic"
                | "U-panic"
                | "W-panic"
        ) {
            assert!(joined.value.is_none());
            assert!(
                joined
                    .actual_coordinator_status
                    .is_some_and(|status| !status.success())
            );
            assert_eq!(joined.actual_joins, (true, true));
            if intentional_abort {
                assert_eq!(
                    joined.actual_coordinator_status.unwrap().signal(),
                    Some(libc::SIGABRT),
                    "{mode}: setup refusal must not qualify as the intended abort"
                );
            }
            if mode == "coordinator-exit" {
                assert_eq!(
                    joined.actual_coordinator_status,
                    Some(ExitStatus::Exited(23))
                );
            }
            if mode == "coordinator-sigpipe" {
                assert_eq!(
                    joined.actual_coordinator_status.unwrap().signal(),
                    Some(libc::SIGPIPE)
                );
            }
            assert_eq!(std::fs::read(&factory_path).unwrap(), b"factory-drop\n");
            println!(
                "actual failed coordinator {mode}: {:?}; status={:?}; retained_encoded_bytes={}",
                joined.report,
                joined.actual_coordinator_status,
                joined.encoded_bytes.len()
            );
            continue;
        }
        assert_eq!(joined.report.coordinator_status, Some(ExitStatus::SUCCESS));
        assert_eq!(joined.actual_joins, (true, true));
        if !matches!(mode, "held-publication" | "held-endpoint") {
            assert_eq!(joined.report.collector_join, Some(true));
            assert_eq!(joined.report.publication_join, Some(true));
        } else if mode == "held-endpoint" {
            assert!(!joined.report.capture.as_ref().unwrap().guest.peer_closed);
        } else {
            assert_eq!(
                joined
                    .report
                    .capture
                    .as_ref()
                    .unwrap()
                    .publication
                    .stability,
                g::ArtifactStability::MayAppend
            );
        }
        assert_eq!(std::fs::read(&factory_path).unwrap(), b"factory-drop\n");
        let value = joined.value.as_ref().unwrap();
        assert_eq!(value.value[0], 37);
        if mode == "large" {
            assert_eq!(value.value.len(), 10 * 1024 * 1024);
        }
        if mode == "held-publication" {
            assert_eq!(std::fs::read(&output_path).unwrap(), b"work\n");
        } else if mode == "output-ceiling" {
            assert_eq!(std::fs::read(&output_path).unwrap(), b"work\nguest\nw");
            assert!(
                joined
                    .report
                    .capture
                    .as_ref()
                    .unwrap()
                    .publication
                    .progress
                    .discarded_bytes
                    > 0
            );
        } else if mode.starts_with("rpc-") {
            let expected = if mode == "rpc-truncated-header" {
                b"work\nguest\nserving-task-joined\nruntime-dropped\nglobal-drop\nwork-return\nW-drop\nserialize\nU-drop\nT-drop\nfield-drop\n".as_slice()
            } else {
                b"work\nrequest-entered\nrequest-drop\nguest\nserving-task-joined\nruntime-dropped\nglobal-drop\nwork-return\nW-drop\nserialize\nU-drop\nT-drop\nfield-drop\n".as_slice()
            };
            assert_eq!(std::fs::read(&output_path).unwrap(), expected);
            let issues = &joined.facts.as_ref().unwrap().rpc_issues;
            if mode == "rpc-complete" {
                assert!(issues.is_empty());
            } else {
                assert_eq!(issues.len(), 1);
                assert_eq!(issues[0].connection, 1);
                assert_eq!(
                    issues[0].failure,
                    if mode == "rpc-truncated-header" {
                        g::SplitRpcFailure::Transport
                    } else {
                        g::SplitRpcFailure::Panicked
                    }
                );
                assert_eq!(joined.actual_coordinator_status, Some(ExitStatus::SUCCESS));
                assert_eq!(
                    joined.facts.as_ref().unwrap().guest_wait_status,
                    ExitStatus::Exited(if guest7 { 7 } else { 0 }).into_raw()
                );
            }
        } else {
            assert_eq!(
                std::fs::read(&output_path).unwrap(),
                b"work\nguest\nwork-return\nW-drop\nserialize\nU-drop\nT-drop\nfield-drop\n"
            );
        }
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
        println!(
            "actual split {mode}/{turn}: {:?}; facts={:?}",
            joined.report, joined.facts
        );
    }
    // The external disposal controller transfers one inherited descriptor to
    // this fixture; reclaim it too. All other modes restore their whole entry
    // descriptor population, including between the two actual clone runs.
    let final_fds = original_fds - usize::from(mode == "drop-publication");
    assert_eq!(
        std::fs::read_dir("/proc/self/fd").unwrap().count(),
        final_fds
    );
    println!(
        "actual O descriptor population: before={original_fds}, after={final_fds}; runs={repetitions}"
    );
    std::fs::remove_dir_all(root).unwrap();
    println!("split lifecycle completed: {case}");
}

fn split_startup_failure(mode: &str) {
    use std::time::Instant;

    use reverie::process::Container;
    use reverie::process::StartupError;
    use reverie_rpc_transport::guest_log as g;
    assert!(["child-refusal", "parent-refusal", "parent-panic"].contains(&mode));
    let root = std::path::PathBuf::from(format!("/tmp/sa3-start-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let parent_path = root.join("parent-factory");
    let child_path = root.join("child-factory");
    let pid_path = root.join("real-child-pid");
    let parent_factory = SplitFactoryDrop {
        file: std::fs::File::create(&parent_path).unwrap(),
        owner_pid: std::process::id(),
        panic_after_cleanup: false,
    };
    let child_factory = SplitFactoryDrop {
        file: std::fs::File::create(&child_path).unwrap(),
        owner_pid: std::process::id(),
        panic_after_cleanup: false,
    };
    let options = g::CaptureOptions {
        limits: g::CaptureLimits {
            producers: 4,
            slots_per_producer: 8,
            max_record_bytes: 4096,
            host_pending_bytes: 8192,
            guest_pending_bytes: 8192,
            pending_records: 16,
            diagnostic_bytes: 4096,
        },
        timeouts: g::CaptureTimeouts {
            startup: Duration::from_secs(2),
            blocked_publication: Duration::from_secs(2),
            final_drain: Duration::from_secs(2),
        },
    };
    let plan = unsafe { g::SplitCapturePlan::new(options) }.unwrap();
    let child_pid_path = pid_path.clone();
    let observer = std::cell::Cell::<Option<std::os::fd::OwnedFd>>::new(None);
    let observer_ref = &observer;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        g::run_split_capture(
            &mut Container::new(),
            plan,
            move |context| -> Result<SplitOutput, StartupError> {
                let _keep_factory = &parent_factory;
                let duplicate =
                    libc::fcntl(context.child_pidfd().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0);
                assert!(duplicate >= 0);
                observer_ref.set(Some(
                    <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(duplicate),
                ));
                assert_eq!(
                    std::fs::read_to_string(&pid_path)
                        .unwrap()
                        .parse::<i32>()
                        .unwrap(),
                    context.child_pid().as_raw()
                );
                if mode == "parent-panic" {
                    panic!("actual borrowed parent callback panic");
                }
                Err(StartupError::Refused)
            },
            move |_| {
                let _keep_factory = &child_factory;
                std::fs::write(&child_pid_path, std::process::id().to_string()).unwrap();
                if mode == "child-refusal" {
                    return Err(StartupError::Refused);
                }
                Ok(
                    |_: g::CoordinatorContext| -> (g::SplitChildResult<u32>, ()) {
                        panic!("workload must not start after startup refusal")
                    },
                )
            },
        )
    }));
    if mode == "parent-panic" {
        assert!(outcome.is_err());
    } else {
        let run = outcome.unwrap_or_else(|_| panic!("unexpected parent unwind"));
        let g::SplitCaptureOutcome::Joined(joined) =
            run.settle_until(Instant::now() + Duration::from_secs(2))
        else {
            panic!("startup child not settled");
        };
        assert!(!joined.report.qualifies());
        assert!(matches!(
            joined.integrity,
            g::TerminalCaptureIntegrity::Incomplete { .. }
        ));
        assert!(joined.report.failure.is_some());
        assert!(joined.value.is_none());
        assert!(joined.actual_coordinator_status.is_some());
        assert_eq!(joined.actual_joins, (true, true));
        println!("actual startup refusal {mode}: {:?}", joined.report);
    }
    for path in [parent_path, child_path] {
        assert_eq!(std::fs::read(path).unwrap(), b"factory-drop\n");
    }
    let pid: i32 = std::fs::read_to_string(root.join("real-child-pid"))
        .unwrap()
        .parse()
        .unwrap();
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    // A reaped numeric PID may be reused. Observe the original pidfd when the
    // parent callback ran; early child refusal is bound to the actual wait
    // status retained above instead of reopening that numeric identity.
    if mode != "child-refusal" {
        let observer = observer.take().unwrap();
        let mut poll = libc::pollfd {
            fd: observer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 0) }, 1);
        assert_ne!(poll.revents & libc::POLLIN, 0);
    }
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    std::fs::remove_dir_all(root).unwrap();
    println!(
        "split startup cleanup completed: {mode}; actual child {pid} reaped; both factories once"
    );
}
