//! Controlled single-main-thread fork fixture, not a runtime bootstrap.
use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileExt;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Tid;
use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::mapped::InheritedMappingReleaseFailure;
use reverie_rpc_transport::mapped::MappedStream;
use reverie_rpc_transport::serve_stream;
use serde::Deserialize;
use serde::Serialize;

const LIMIT: Duration = Duration::from_secs(5);
static TRACK_NEXT: AtomicBool = AtomicBool::new(false);
static TRACKED: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicUsize = AtomicUsize::new(0);
static CONFIG_DROPS: AtomicUsize = AtomicUsize::new(0);
static CONFIG_CLONES: AtomicUsize = AtomicUsize::new(0);

// Fixture-only libc interposition. Only the explicitly selected child VMA is
// affected; all other calls reach the real syscall. This is a labelled injected
// error, not a claim that the kernel rejected a valid munmap.
static UNMAP_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static UNMAP_MODE: AtomicUsize = AtomicUsize::new(0);
static UNMAP_CALLS: AtomicUsize = AtomicUsize::new(0);
static UNMAP_LENGTH: AtomicUsize = AtomicUsize::new(0);
static REPLACEMENT_READY: AtomicBool = AtomicBool::new(false);
#[unsafe(no_mangle)]
unsafe extern "C" fn munmap(address: *mut libc::c_void, len: usize) -> libc::c_int {
    let selected = UNMAP_ADDRESS.load(Ordering::SeqCst) == address as usize;
    let call = if selected {
        UNMAP_LENGTH.store(len, Ordering::SeqCst);
        UNMAP_CALLS.fetch_add(1, Ordering::SeqCst) + 1
    } else {
        0
    };
    if selected && UNMAP_MODE.load(Ordering::SeqCst) == 1 && call == 1 {
        unsafe { *libc::__errno_location() = libc::EPERM };
        return -1;
    }
    let result = unsafe { libc::syscall(libc::SYS_munmap, address, len) } as libc::c_int;
    if selected && UNMAP_MODE.load(Ordering::SeqCst) == 2 && call == 1 && result == 0 {
        // The original VMA has actually ceased to exist. A new independent
        // mapping now occupies the free range, making a redundant unmap visible.
        let replacement = unsafe {
            libc::mmap(
                address,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        REPLACEMENT_READY.store(replacement == address, Ordering::SeqCst);
    }
    result
}

struct Allocator;
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if TRACK_NEXT.swap(false, Ordering::SeqCst) {
            TRACKED.store(pointer as usize, Ordering::SeqCst);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if TRACKED
            .compare_exchange(pointer as usize, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            FREED.fetch_add(1, Ordering::SeqCst);
        }
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Config(u64);
impl Clone for Config {
    fn clone(&self) -> Self {
        CONFIG_CLONES.fetch_add(1, Ordering::SeqCst);
        Self(self.0)
    }
}
impl Drop for Config {
    fn drop(&mut self) {
        CONFIG_DROPS.fetch_add(1, Ordering::SeqCst);
    }
}
#[derive(Default)]
struct Global {
    expected_tid: i32,
    calls: AtomicUsize,
}
#[async_trait]
impl GlobalTool for Global {
    type Request = u64;
    type Response = (i32, u64, usize);
    type Config = Config;
    async fn receive_rpc(&self, from: Tid, request: u64) -> Self::Response {
        assert_eq!(
            from.as_raw(),
            self.expected_tid,
            "request reached the wrong inherited endpoint"
        );
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        (from.as_raw(), request ^ 0xabcd, call)
    }
}
fn tid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}
fn no_setup_descriptor() {
    for entry in std::fs::read_dir("/proc/self/fd").unwrap() {
        if let Ok(target) = std::fs::read_link(entry.unwrap().path()) {
            assert!(
                !target.to_string_lossy().contains("memfd:reverie-rpc"),
                "setup descriptor remains open"
            );
        }
    }
}
fn peer(expected_tid: i32) {
    let stream = unsafe { MappedStream::from_owned_fd(OwnedFd::from_raw_fd(0)) }.unwrap();
    no_setup_descriptor();
    let global = Arc::new(Global {
        expected_tid,
        calls: AtomicUsize::new(0),
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(serve_stream(
            global.clone(),
            Config(0x1298),
            stream.into_async().unwrap(),
        ))
        .unwrap();
    println!(
        "PEER_COMPLETE calls={}",
        global.calls.load(Ordering::SeqCst)
    );
}
struct Peer(Option<Child>);
impl Peer {
    fn finish(mut self) -> (bool, String) {
        let mut child = self.0.take().unwrap();
        let deadline = Instant::now() + LIMIT;
        let mut expired = false;
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                expired = true;
                child.kill().unwrap();
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            !expired,
            "peer failed to exit within original five-second bound; reaped {:?}",
            output.status
        );
        (
            output.status.success(),
            String::from_utf8(output.stdout).unwrap(),
        )
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
struct ForkChild(libc::pid_t);
impl ForkChild {
    fn wait(mut self) -> (bool, i32) {
        let deadline = Instant::now() + LIMIT;
        let mut status = 0;
        let mut expired = false;
        loop {
            let rc = unsafe { libc::waitpid(self.0, &mut status, libc::WNOHANG) };
            if rc == self.0 {
                break;
            }
            assert_eq!(rc, 0);
            if Instant::now() >= deadline {
                expired = true;
                assert_eq!(unsafe { libc::kill(self.0, libc::SIGKILL) }, 0);
                assert_eq!(unsafe { libc::waitpid(self.0, &mut status, 0) }, self.0);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        self.0 = 0;
        (
            !expired && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            status,
        )
    }
}
impl Drop for ForkChild {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                libc::kill(self.0, libc::SIGKILL);
                libc::waitpid(self.0, std::ptr::null_mut(), 0);
            }
        }
    }
}
fn mapping() -> (usize, usize) {
    let rows: Vec<_> = std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .filter(|line| line.contains("memfd:reverie-rpc"))
        .map(|line| {
            let (a, b) = line
                .split_whitespace()
                .next()
                .unwrap()
                .split_once('-')
                .unwrap();
            (
                usize::from_str_radix(a, 16).unwrap(),
                usize::from_str_radix(b, 16).unwrap(),
            )
        })
        .collect();
    assert_eq!(rows.len(), 1);
    rows[0]
}
fn bytes(range: (usize, usize)) -> Vec<u8> {
    let mut bytes = vec![0; range.1 - range.0];
    std::fs::File::open("/proc/self/mem")
        .unwrap()
        .read_exact_at(&mut bytes, range.0 as u64)
        .unwrap();
    bytes
}
fn child_release(
    client: BlockingRpcClient<Global, MappedStream>,
    alias: Option<reverie_rpc_transport::mapped::MappedAbort>,
    address: usize,
    parent_tid: i32,
    mode: &str,
    mapped_len: usize,
) {
    assert_ne!(tid(), parent_tid);
    assert_eq!(unsafe { libc::getpid() }, tid());
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    let (stored_tid, config, stream) = client.into_parts();
    assert_eq!(stored_tid.as_raw(), parent_tid);
    assert_eq!(config.0, 0x1298);
    assert_eq!(CONFIG_CLONES.load(Ordering::SeqCst), 0);
    assert_eq!(CONFIG_DROPS.load(Ordering::SeqCst), 0);
    UNMAP_ADDRESS.store(address, Ordering::SeqCst);
    UNMAP_MODE.store(
        match mode {
            "unmap-failure" => 1,
            "single-unmap" => 2,
            _ => 0,
        },
        Ordering::SeqCst,
    );
    let result = unsafe { stream.discard_inherited_after_fork() };
    if let Some(alias) = alias {
        let error = result.expect_err("extra alias must retain a disarmed error owner");
        assert!(matches!(
            error.failure(),
            InheritedMappingReleaseFailure::Nonexclusive
        ));
        let error = unsafe { error.retry() }.expect_err("alias retry must remain pending");
        assert!(matches!(
            error.failure(),
            InheritedMappingReleaseFailure::Nonexclusive
        ));
        assert_eq!(FREED.load(Ordering::SeqCst), 0);
        drop(alias);
        unsafe { error.retry() }.unwrap();
    } else if mode == "unmap-failure" {
        let error = result.expect_err("injected unmap failure was reported as success");
        assert!(
            matches!(error.failure(), InheritedMappingReleaseFailure::Unmap(e) if e.raw_os_error() == Some(libc::EPERM))
        );
        let mut resident = 0u8;
        assert_eq!(
            unsafe { libc::mincore(address as *mut libc::c_void, 1, &mut resident) },
            0,
            "failed unmap lost the owned VMA before retry"
        );
        assert_eq!(UNMAP_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(UNMAP_LENGTH.load(Ordering::SeqCst), mapped_len);
        unsafe { error.retry() }.unwrap();
    } else {
        result.unwrap();
    }
    let calls = UNMAP_CALLS.load(Ordering::SeqCst);
    let mut replacement_present = 0;
    if mode == "single-unmap" {
        let mut resident = 0u8;
        replacement_present =
            unsafe { libc::mincore(address as *mut libc::c_void, 1, &mut resident) };
        // Always release the fixture's replacement, including on a mutant's
        // redundant-unmap failure, before making the final assertion.
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_munmap, address, mapped_len) },
            0
        );
    }
    // This raw observation is immediate: no allocation, logging or new mapping
    // occurs between release returning and mincore on the original VMA.
    let mut resident = 0u8;
    let rc = unsafe { libc::mincore(address as *mut libc::c_void, 1, &mut resident) };
    let errno = std::io::Error::last_os_error().raw_os_error();
    assert_eq!(
        rc, -1,
        "child inherited VMA remains mapped after reported release"
    );
    assert_eq!(errno, Some(libc::ENOMEM));
    assert_eq!(UNMAP_LENGTH.load(Ordering::SeqCst), mapped_len);
    assert_eq!(
        calls,
        if mode == "unmap-failure" { 2 } else { 1 },
        "inherited release performed a redundant unmap"
    );
    if mode == "single-unmap" {
        assert!(REPLACEMENT_READY.load(Ordering::SeqCst));
        assert_eq!(
            replacement_present, 0,
            "successful release unmapped the independent replacement VMA"
        );
    }
    assert_eq!(
        FREED.load(Ordering::SeqCst),
        1,
        "controlled System Arc metadata was not deallocated"
    );
    assert_eq!(CONFIG_DROPS.load(Ordering::SeqCst), 0);
    drop(config);
    assert_eq!(CONFIG_DROPS.load(Ordering::SeqCst), 1);
    println!(
        "CHILD_RELEASED pid={} inherited_tid={} vma_absent=true arc_deallocated=1 config_drops=1",
        tid(),
        stored_tid.as_raw()
    );
}
fn parent(mode: &str) {
    let extra_alias = mode == "alias";
    assert_eq!(unsafe { libc::getpid() }, tid());
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    TRACK_NEXT.store(true, Ordering::SeqCst);
    let (stream, fd) = unsafe { MappedStream::create(97) }.unwrap();
    assert!(!TRACK_NEXT.load(Ordering::SeqCst));
    assert_ne!(TRACKED.load(Ordering::SeqCst), 0);
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::fstat(std::os::fd::AsRawFd::as_raw_fd(&fd), &mut stat) },
        0
    );
    let mapped_len = stat.st_size as usize;
    let alias = extra_alias.then(|| stream.abort_handle());
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["peer", &tid().to_string()])
        .stdin(Stdio::from(fd))
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let peer_pid = child.id() as i32;
    let peer = Peer(Some(child));
    no_setup_descriptor();
    let client =
        BlockingRpcClient::<Global, _>::from_connected_stream(stream, Tid::from_raw(tid()))
            .unwrap();
    assert_eq!(client.config().0, 0x1298);
    assert_eq!(
        client.try_send_rpc(0x11).unwrap(),
        (tid(), 0x11 ^ 0xabcd, 1)
    );
    assert_eq!(unsafe { libc::kill(peer_pid, libc::SIGSTOP) }, 0);
    let mut stopped = 0;
    assert_eq!(
        unsafe { libc::waitpid(peer_pid, &mut stopped, libc::WUNTRACED) },
        peer_pid
    );
    assert!(libc::WIFSTOPPED(stopped));
    let range = mapping();
    let before = bytes(range);
    let parent_tid = tid();
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            child_release(client, alias, range.0, parent_tid, mode, mapped_len)
        }));
        unsafe { libc::_exit(if outcome.is_ok() { 0 } else { 101 }) };
    }
    let (child_ok, status) = ForkChild(pid).wait();
    let after = bytes(range);
    let shared_unchanged = before == after;
    let parent_metadata_retained = FREED.load(Ordering::SeqCst) == 0;
    assert_eq!(unsafe { libc::kill(peer_pid, libc::SIGCONT) }, 0);
    let response = client.try_send_rpc(0x29);
    let parent_config_unchanged =
        client.config().0 == 0x1298 && CONFIG_DROPS.load(Ordering::SeqCst) == 0;
    drop(alias);
    drop(client);
    let (peer_ok, peer_output) = peer.finish();
    // All owned children have been reaped before the final semantic assertions.
    assert!(child_ok, "fork child failed; actual wait status={status}");
    assert!(
        shared_unchanged,
        "child disposal changed shared header, cursors, flags, progress or payload bytes"
    );
    assert!(
        parent_metadata_retained,
        "child deallocation changed parent COW ownership"
    );
    assert_eq!(
        response.unwrap(),
        (parent_tid, 0x29 ^ 0xabcd, 2),
        "parent RPC continuity failed"
    );
    assert!(parent_config_unchanged);
    assert!(peer_ok, "peer failed: {peer_output}");
    assert_eq!(peer_output, "PEER_COMPLETE calls=2\n");
    assert_eq!(CONFIG_CLONES.load(Ordering::SeqCst), 0);
    assert_eq!(CONFIG_DROPS.load(Ordering::SeqCst), 1);
    assert_eq!(FREED.load(Ordering::SeqCst), 1);
    println!(
        "PARENT_CONTINUED child_status={status} shared_bytes={} extra_alias={extra_alias}",
        before.len()
    );
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("peer") => peer(args[2].parse().unwrap()),
        Some(mode @ ("sole" | "alias" | "unmap-failure" | "single-unmap")) => parent(mode),
        _ => panic!("expected peer, sole or alias fixture mode"),
    }
}
