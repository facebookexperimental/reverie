//! Controlled test-harness setup, not universal guest/preinit bootstrap.
use std::future::Future;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicU64;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use super::*;

mod native;

static CALLER_TID: AtomicI64 = AtomicI64::new(0);
static MAPPING_DEV: AtomicU64 = AtomicU64::new(0);
static MAPPING_INO: AtomicU64 = AtomicU64::new(0);
static SERIALIZE_CALLS: AtomicUsize = AtomicUsize::new(0);
static DESERIALIZE_CALLS: AtomicUsize = AtomicUsize::new(0);
static CONFIG_CALLS: AtomicUsize = AtomicUsize::new(0);

fn tid() -> i64 {
    unsafe { libc::syscall(libc::SYS_gettid) }
}
fn admitted_callback() {
    assert_eq!(
        tid(),
        CALLER_TID.load(Ordering::SeqCst),
        "callback moved off the originating thread"
    );
    let identity = (
        MAPPING_DEV.load(Ordering::SeqCst),
        MAPPING_INO.load(Ordering::SeqCst),
    );
    assert_ne!(identity.1, 0);
    for entry in std::fs::read_dir("/proc/self/fd").unwrap() {
        let path = entry.unwrap().path();
        if let Ok(metadata) = std::fs::metadata(&path) {
            assert_ne!(
                (metadata.dev(), metadata.ino()),
                identity,
                "private mapped transport descriptor remained at admitted callback: {}",
                path.display()
            );
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
struct Config(Vec<u8>);
impl<'de> Deserialize<'de> for Config {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        admitted_callback();
        CONFIG_CALLS.fetch_add(1, Ordering::SeqCst);
        Vec::<u8>::deserialize(decoder).map(Self)
    }
}
#[derive(Debug, Deserialize)]
struct SourceRequest {
    value: u8,
    bytes: Vec<u8>,
}
impl Serialize for SourceRequest {
    fn serialize<S: Serializer>(&self, encoder: S) -> Result<S::Ok, S::Error> {
        admitted_callback();
        SERIALIZE_CALLS.fetch_add(1, Ordering::SeqCst);
        assert_ne!(self.value, 255, "intentional source Serialize panic");
        if self.value == 254 {
            return Err(serde::ser::Error::custom(
                "intentional source Serialize error",
            ));
        }
        (&self.value, &self.bytes).serialize(encoder)
    }
}
#[derive(Debug, Serialize)]
struct SourceResponse {
    value: u8,
    bytes: Vec<u8>,
}
impl<'de> Deserialize<'de> for SourceResponse {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        admitted_callback();
        DESERIALIZE_CALLS.fetch_add(1, Ordering::SeqCst);
        let (value, bytes) = <(u8, Vec<u8>)>::deserialize(decoder)?;
        assert_ne!(value, 255, "intentional source Deserialize panic");
        if value == 254 {
            return Err(serde::de::Error::custom(
                "intentional source Deserialize error",
            ));
        }
        Ok(Self { value, bytes })
    }
}
#[derive(Default)]
struct CallbackGlobal {
    host_tid: i64,
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
}
#[async_trait]
impl GlobalTool for CallbackGlobal {
    type Request = SourceRequest;
    type Response = SourceResponse;
    type Config = Config;
    async fn receive_rpc(&self, from: Tid, request: SourceRequest) -> SourceResponse {
        assert_eq!(
            tid(),
            self.host_tid,
            "GlobalTool callback left its host task thread"
        );
        assert_ne!(i64::from(from.as_raw()), self.host_tid);
        self.calls.fetch_add(1, Ordering::SeqCst);
        if request.value == 42 {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        SourceResponse {
            value: match request.value {
                200 => 254,
                201 => 255,
                n => n,
            },
            bytes: request.bytes,
        }
    }
}
fn request(value: u8, bytes: Vec<u8>) -> SourceRequest {
    SourceRequest { value, bytes }
}

#[test]
fn controlled_setup_child() {
    let Ok(mode) = std::env::var("MAPPED_RPC_CHILD_MODE") else {
        return;
    };
    let fd: i32 = std::env::var("MAPPED_RPC_SETUP_FD")
        .unwrap()
        .parse()
        .unwrap();
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(fd, &mut stat) }, 0);
    MAPPING_DEV.store(stat.st_dev, Ordering::SeqCst);
    MAPPING_INO.store(stat.st_ino, Ordering::SeqCst);
    CALLER_TID.store(tid(), Ordering::SeqCst);
    // The test's admission boundary follows import/closure. The Rust test
    // harness and loader already ran; they are explicitly outside this claim.
    let guest = unsafe { MappedStream::from_owned_fd(OwnedFd::from_raw_fd(fd)) }.unwrap();
    admitted_callback();
    let client = BlockingRpcClient::<CallbackGlobal, _>::from_connected_stream(
        guest,
        Tid::from_raw(tid() as i32),
    )
    .unwrap();
    assert_eq!(client.config().0, vec![0x36; 8193]);
    if mode == "killed" {
        client.try_send_rpc(request(42, vec![])).unwrap();
        panic!("killed child unexpectedly returned from its blocked RPC");
    }
    assert_eq!(mode, "callbacks");
    assert!(matches!(
        client.try_send_rpc(request(254, vec![])),
        Err(RpcError::Encode(_))
    ));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || client.try_send_rpc(request(255, vec![]))
        ))
        .is_err()
    );
    let payload: Vec<u8> = (0..65_537).map(|i| (i * 17) as u8).collect();
    let response = {
        let mut future = std::pin::pin!(client.send_rpc(request(7, payload.clone())));
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(response) => response,
            Poll::Pending => panic!("blocking RPC first poll returned Pending"),
        }
    };
    assert_eq!(response.value, 7);
    assert_eq!(response.bytes, payload);
    // Reproduce only the previously established ordinary SEND and UPDATE
    // prefix operations, while the mapped RPC remains live and descriptor-free.
    native::run();
    admitted_callback();
    assert!(matches!(
        client.try_send_rpc(request(200, vec![])),
        Err(RpcError::Decode(_))
    ));
    assert_eq!(
        client
            .try_send_rpc(request(8, b"after decode error".to_vec()))
            .unwrap()
            .bytes,
        b"after decode error"
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || client.try_send_rpc(request(201, vec![]))
        ))
        .is_err()
    );
    assert!(
        matches!(client.try_send_rpc(request(9, vec![])), Err(RpcError::Io(ref e)) if e.to_string() == "reverie-rpc-transport: blocking client mutex poisoned")
    );
    assert_eq!(CONFIG_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(SERIALIZE_CALLS.load(Ordering::SeqCst), 7);
    assert_eq!(DESERIALIZE_CALLS.load(Ordering::SeqCst), 4);
    drop(client);
    println!("mapped child callbacks complete; waiting on ordinary stdin before actual exit");
    let mut release = [0];
    std::io::stdin().read_exact(&mut release).unwrap();
    assert_eq!(release, *b"x");
}

struct OwnedChild {
    child: Option<Child>,
    pidfd: OwnedFd,
    mode: String,
}
impl OwnedChild {
    fn spawn(fd: &OwnedFd, mode: &str) -> Self {
        let number = fd.as_raw_fd();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "process::controlled_setup_child", "--nocapture"])
            .env("MAPPED_RPC_CHILD_MODE", mode)
            .env("MAPPED_RPC_SETUP_FD", number.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(number, libc::F_GETFD);
                if flags < 0 || libc::fcntl(number, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        // The parent owns this unreaped direct child. It cannot reuse the PID
        // before wait; normal child execution is also blocked on our handshake.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0u32) };
        if raw < 0 {
            let error = io::Error::last_os_error();
            let _ = child.kill();
            let _ = child.wait();
            panic!("owned child pidfd unavailable: {error}");
        }
        Self {
            child: Some(child),
            pidfd: unsafe { OwnedFd::from_raw_fd(raw as i32) },
            mode: mode.to_owned(),
        }
    }
    fn exited(&self, timeout_ms: i32) -> bool {
        let mut poll = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, timeout_ms) };
        assert!(result >= 0, "pidfd poll: {}", io::Error::last_os_error());
        assert_eq!(poll.revents & (libc::POLLERR | libc::POLLNVAL), 0);
        result == 1 && poll.revents & libc::POLLIN != 0
    }
    fn finish(&mut self, mode: &str) -> std::process::Output {
        assert!(self.exited(5000), "owned child did not actually exit");
        let child = self.child.take().unwrap();
        let id = child.id();
        let output = child.wait_with_output().unwrap();
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/mapped-rpc-implementation/children");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{mode}-{id}.stdout")), &output.stdout).unwrap();
        std::fs::write(dir.join(format!("{mode}-{id}.stderr")), &output.stderr).unwrap();
        println!(
            "child mode={mode} pid={id} status={}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout)
        );
        if !output.status.success() {
            eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        }
        output
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            let id = child.id();
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    0usize,
                    0u32,
                );
            }
            if let Ok(output) = child.wait_with_output() {
                let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../target/mapped-rpc-implementation/children");
                let _ = std::fs::create_dir_all(&dir);
                let _ = std::fs::write(
                    dir.join(format!("{}-{id}-cleanup.stdout", self.mode)),
                    &output.stdout,
                );
                let _ = std::fs::write(
                    dir.join(format!("{}-{id}-cleanup.stderr", self.mode)),
                    &output.stderr,
                );
                eprintln!(
                    "child cleanup mode={} pid={id} status={}\n{}\n{}",
                    self.mode,
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}

#[test]
fn subprocess_closes_descriptors_before_callbacks_and_retains_native_io() {
    runtime().block_on(async {
        // Only the controlled child imports this backing storage; neither
        // process writes through the descriptor or creates an extra endpoint.
        let (host, fd) = unsafe { MappedStream::create(31) }.unwrap();
        let mut child = OwnedChild::spawn(&fd, "callbacks");
        drop(fd);
        let global = Arc::new(CallbackGlobal {
            host_tid: tid(),
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
        });
        let server = tokio::spawn(serve_stream(
            global.clone(),
            Config(vec![0x36; 8193]),
            host.into_async().unwrap(),
        ));
        tokio::time::timeout(LIMIT, server)
            .await
            .expect("controlled callback server stalled")
            .unwrap()
            .unwrap();
        assert_eq!(
            global.calls.load(Ordering::SeqCst),
            4,
            "failed serializer unexpectedly sent a request"
        );
        assert!(
            !child.exited(0),
            "logical connection close was confused with actual child exit"
        );
        child
            .child
            .as_mut()
            .unwrap()
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let output = child.finish("callbacks");
        assert!(output.status.success(), "controlled child callbacks failed");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("running 1 test"));
        assert!(stdout.contains("test result: ok. 1 passed"));
    });
}

#[test]
fn actual_child_death_requires_owned_cancellation_and_is_not_clean_eof() {
    runtime().block_on(async {
        // Only the controlled child imports this backing storage; neither
        // process writes through the descriptor or creates an extra endpoint.
        let (host, fd) = unsafe { MappedStream::create(13) }.unwrap();
        let abort = host.abort_handle();
        let mut child = OwnedChild::spawn(&fd, "killed");
        drop(fd);
        let global = Arc::new(CallbackGlobal {
            host_tid: tid(),
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
        });
        let server = tokio::spawn(serve_stream(
            global.clone(),
            Config(vec![0x36; 8193]),
            host.into_async().unwrap(),
        ));
        tokio::time::timeout(LIMIT, global.entered.notified())
            .await
            .unwrap();
        assert!(!child.exited(0));
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    child.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    0usize,
                    0u32,
                )
            },
            0
        );
        let output = child.finish("killed");
        assert_eq!(output.status.signal(), Some(libc::SIGKILL));
        // Shared-memory queues have no kernel EOF. The lifecycle owner observes
        // the pidfd, fails the stream, and cancels its pending GlobalTool future.
        assert!(
            !server.is_finished(),
            "queue fabricated socket EOF from process death"
        );
        abort.abort(MappedFailure::PeerFailed);
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        assert_eq!(global.calls.load(Ordering::SeqCst), 1);
    });
}
