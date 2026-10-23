/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Exercises the real execute guard and installed callback slot. The managed
//! probe stops at operation zero with Unavailable; it establishes dispatch
//! reachability, not native capture, ownership, or controller authorization.
//! Each invocation isolates the global callback slot in a child test process.

use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use reverie::Error;
use reverie::Guest;
use reverie::MappingCaptureError;
use reverie::MappingCaptureIdentity;
use reverie::MappingCaptureToken;
use reverie::NativeMmOwnership;
use reverie::PreparedMappingCapture;
use reverie::RuntimePrivateMemoryRegion;
use reverie::RuntimePrivateMemorySnapshot;
use reverie::Tid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use serde::Deserialize;
use serde::Serialize;

use super::CAPTURE;
use super::NativeMappingCapture;
use super::execute;
use super::install_mapping_capture;

const CHILD: &str = "REVERIE_DBT_MAPPING_CAPTURE_EXECUTE_TEST_CHILD";
const CONTEXT: usize = 0x45;
const NONCE: u64 = 19;
static CALLS: AtomicUsize = AtomicUsize::new(0);
static OPERATION: AtomicU32 = AtomicU32::new(u32::MAX);
static OBSERVED_CONTEXT: AtomicUsize = AtomicUsize::new(0);
static OBSERVED_NONCE: AtomicU64 = AtomicU64::new(0);
static OBSERVED_ROOT: AtomicI32 = AtomicI32::new(0);
static SPAWN_CALLBACKS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Default, Serialize, Deserialize)]
struct Untrusted;

#[reverie::tool]
impl Tool for Untrusted {
    type GlobalState = ();
    type ThreadState = ();
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct UntrustedNativeSpawn;

#[reverie::tool]
impl Tool for UntrustedNativeSpawn {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        // Real unrestricted native work if invoked. The test never invokes
        // this method; the default declaration must guard execute itself.
        SPAWN_CALLBACKS.fetch_add(1, Ordering::SeqCst);
        std::thread::spawn(|| ())
            .join()
            .expect("native-spawn test callback worker");
        Ok(guest.inject(call).await?)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ManagedProbe;

#[reverie::tool]
impl Tool for ManagedProbe {
    type GlobalState = ();
    type ThreadState = ();

    fn native_mm_ownership(_config: &()) -> NativeMmOwnership {
        NativeMmOwnership::ManagedRuntimeOnly
    }
}

unsafe extern "C" fn capture_probe(
    context: usize,
    operation: u32,
    args: *mut NativeMappingCapture,
) -> i32 {
    CALLS.fetch_add(1, Ordering::SeqCst);
    OPERATION.store(operation, Ordering::SeqCst);
    OBSERVED_CONTEXT.store(context, Ordering::SeqCst);
    if !args.is_null() {
        // SAFETY: execute supplies its live fixed ABI record to operation zero.
        let args = unsafe { &*args };
        OBSERVED_NONCE.store(args.nonce, Ordering::SeqCst);
        OBSERVED_ROOT.store(args.root_pid, Ordering::SeqCst);
    }
    // No buffer, lease, transport or native park is supplied. A guard-removal
    // mutant still returns Unavailable, so CALLS is the decisive negative.
    0
}

fn prepared(root: i32) -> PreparedMappingCapture<()> {
    let private = RuntimePrivateMemorySnapshot {
        owner: [11, 12, 13, 14],
        version: 7,
        regions: vec![RuntimePrivateMemoryRegion {
            start: 0x1000,
            end: 0x2000,
        }],
    };
    let token = MappingCaptureToken {
        nonce: NONCE,
        identity: MappingCaptureIdentity {
            process: root,
            thread: root,
            address_space: [1, 2],
            private_owner: private.owner,
            private_version: private.version,
        },
    };
    // This is accepted by the real constructor and passes execute's region
    // and serialization prerequisites. These equality fields confer no actual
    // controller grant/private ownership, and the probe never claims one.
    PreparedMappingCapture::new(token, private, ()).expect("valid prepared equality bindings")
}

fn exercise() {
    assert!(
        CAPTURE.get().is_none(),
        "child reused an installed callback"
    );
    install_mapping_capture(capture_probe);
    assert!(CAPTURE.get().is_some(), "probe was not installed");
    let root = i32::try_from(std::process::id()).expect("native process id");
    let tid = Tid::from_raw(root);
    assert_eq!(
        execute::<Untrusted>(CONTEXT, tid, &(), prepared(root)),
        Err(MappingCaptureError::Unavailable)
    );
    assert_eq!(
        CALLS.load(Ordering::SeqCst),
        0,
        "untrusted Tool reached native capture"
    );
    assert_eq!(
        execute::<UntrustedNativeSpawn>(CONTEXT, tid, &(), prepared(root)),
        Err(MappingCaptureError::Unavailable)
    );
    assert_eq!(
        CALLS.load(Ordering::SeqCst),
        0,
        "native-spawn Tool reached native capture"
    );
    assert_eq!(SPAWN_CALLBACKS.load(Ordering::SeqCst), 0);

    assert_eq!(
        execute::<ManagedProbe>(CONTEXT, tid, &(), prepared(root)),
        Err(MappingCaptureError::Unavailable),
        "the dispatch probe must not fake a successful capture"
    );
    assert_eq!(CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(OPERATION.load(Ordering::SeqCst), 0);
    assert_eq!(OBSERVED_CONTEXT.load(Ordering::SeqCst), CONTEXT);
    assert_eq!(OBSERVED_NONCE.load(Ordering::SeqCst), NONCE);
    assert_eq!(OBSERVED_ROOT.load(Ordering::SeqCst), root);
    assert_eq!(SPAWN_CALLBACKS.load(Ordering::SeqCst), 0);
}

#[test]
fn execute_refuses_untrusted_tools_before_native_dispatch() {
    const NAME: &str = "execute_refuses_untrusted_tools_before_native_dispatch";
    const COMPLETE: &str = "mapping-capture-execute-guard-complete";
    if let Some(child) = std::env::var_os(CHILD) {
        assert_eq!(child, NAME);
        exercise();
        println!("{COMPLETE}");
        return;
    }
    // libtest omits the crate-name prefix from module_path!. This works when
    // the author registers this child module as tests or another local name.
    let (_, module) = module_path!().split_once("::").expect("child test module");
    let full_name = format!("{module}::{NAME}");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &full_name, "--nocapture", "--test-threads=1"])
        .env(CHILD, NAME)
        .env("RUST_BACKTRACE", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn isolated execute guard test");
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut exceeded = false;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            exceeded = true;
            child.kill().unwrap();
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!exceeded, "execute guard test blocked: {output:?}");
    assert!(
        output.status.success(),
        "execute guard child failed: {output:?}"
    );
    assert!(
        output
            .stdout
            .windows(COMPLETE.len())
            .any(|bytes| bytes == COMPLETE.as_bytes()),
        "exact child identity did not finish its assertions: {output:?}"
    );
}
