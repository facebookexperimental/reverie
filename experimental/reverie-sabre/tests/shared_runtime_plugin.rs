#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! The shared in-guest runtime as the SaBRe plugin (SaBRe switch, step 5c,
//! R1): the example library examples/shared_runtime_plugin.rs is loaded by
//! the real SaBRe loader, installs the shared runtime from `post_load`, and
//! receives the client's rewritten syscalls through
//! `reverie_sabre_routed_syscall_v1` and the shared entry.
//!
//! The client is launched as Hermit launches a guest, through a sealed
//! launch specification, here with the test's own setting that leaves short
//! syscall sites raw (they trap to the armed filter), as H1's launch will.
//!
//! The example's Tool answers each `getpid` by its path, read from the
//! call's own site (4,000,000 plus the count through the routed entry,
//! 5,000,000 plus the count through the filter), checks that its own
//! allocation is in the runtime's private Tool heap, answers RDTSC with a
//! fixed value, and fails a `clock_gettime` from the vDSO's trapping stub
//! with EOWNERDEAD (any other with ENOTRECOVERABLE).
//!
//! The example is a cdylib, which Cargo builds with the package's examples:
//! run this test through `cargo test -p reverie-sabre --features
//! shared-runtime`, not with `--test` alone (Cargo cannot make a test depend
//! on an example).

use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use reverie::GlobalTool;
use reverie::Tid;
use reverie_rpc_transport::RpcServer;

/// The coordinator side of the example's Tool, with the same RPC types.
#[derive(Default)]
struct CountGlobal {
    calls: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for CountGlobal {
    type Request = u64;
    type Response = u64;
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, amount: u64) -> u64 {
        self.calls.fetch_add(amount, Ordering::Relaxed) + amount
    }
}

fn example_plugin() -> PathBuf {
    let deps = std::env::current_exe().unwrap();
    let profile = deps.parent().unwrap().parent().unwrap();
    let plugin = profile.join("examples/libshared_runtime_plugin.so");
    assert!(
        plugin.is_file(),
        "{} is missing: build the package's examples (cargo test --features shared-runtime)",
        plugin.display()
    );
    plugin
}

/// The example's answer to RDTSC (examples/shared_runtime_plugin.rs).
const TSC: u64 = 0x0005_AB1E_0000_0001;

/// Runs `command` to completion, killing it after `limit`, and drains its
/// output while it runs.
fn bounded_output(command: &mut Command, limit: Duration) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let drain = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes).unwrap();
            bytes
        })
    };
    let stdout = drain(Box::new(child.stdout.take().unwrap()));
    let stderr = drain(Box::new(child.stderr.take().unwrap()));
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "the client did not finish within {limit:?}; stderr: {}",
                String::from_utf8_lossy(&stderr.join().unwrap())
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output {
        status,
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    }
}

/// Runs `client` under the loader through a launch specification carrying
/// `settings`, as Hermit launches a guest.
fn launched(plugin: &Path, client: &Path, settings: &[Vec<u8>]) -> Output {
    let settings: Vec<&[u8]> = settings.iter().map(Vec::as_slice).collect();
    let spec = reverie_sabre::launch::spec_bytes(
        plugin.as_os_str().as_bytes(),
        client.as_os_str().as_bytes(),
        &settings,
    )
    .unwrap();
    // Inherited (no close-on-exec) and open until the child has finished.
    let spec = reverie_sabre::launch::spec_fd(&spec).unwrap();
    let output = bounded_output(
        &mut Command::new(reverie_sabre::bundled_sabre_path()),
        Duration::from_secs(30),
    );
    drop(spec);
    output
}

#[test]
fn the_shared_runtime_as_the_sabre_plugin_handles_rewritten_syscalls() {
    let out = tempfile::tempdir().unwrap();
    let client = out.path().join("client");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/shared_runtime_plugin/client.c");
    let compiled = cc::Build::new()
        .cargo_metadata(false)
        .opt_level(1)
        .host("x86_64-unknown-linux-gnu")
        .target("x86_64-unknown-linux-gnu")
        .get_compiler()
        .to_command()
        .arg(&source)
        .arg("-o")
        .arg(&client)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");

    let socket = out.path().join("coordinator.sock");
    let global = Arc::new(CountGlobal::default());
    let server = {
        let socket = socket.clone();
        let global = global.clone();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let bound = runtime.block_on(async { RpcServer::bind(&socket, global, ()).unwrap() });
        std::thread::spawn(move || {
            runtime.block_on(async move {
                let _ = bound.serve().await;
            })
        })
    };
    let _ = server;

    let mut coordinator = b"SHARED_RUNTIME_PLUGIN_COORDINATOR=".to_vec();
    coordinator.extend_from_slice(socket.as_os_str().as_bytes());
    let output = launched(
        &example_plugin(),
        &client,
        &[
            // Consumed by the loader: short sites stay unrewritten and trap
            // to the armed filter, as H1's launch will select.
            b"REVERIE_SABRE_SHORT_SYSCALL_SITES=raw".to_vec(),
            // The plugin's setting: libc's environment is not set up yet
            // when the loader runs its install body.
            coordinator,
        ],
    );
    assert!(output.status.success(), "{output:?}");
    // Two calls from rewritten sites through the routed entry, one from the
    // site the loader could not rewrite through the filter; 2 in place of an
    // answer is a Tool allocation outside the Tool heap. libc's
    // clock_gettime goes through the vDSO, whose trapping stub reaches the
    // Tool (EOWNERDEAD; a libc syscall fallback would give ENOTRECOVERABLE).
    // On a host whose clocksource has no vDSO fast path, the original vDSO
    // function's own fallback syscall would also trap from inside the vDSO,
    // so there this does not prove the stub; on a TSC host a native vDSO
    // call would print "0 0".
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("4000001 4000002 5000003 {TSC:#x} -1 {}\n", libc::EOWNERDEAD),
        "{output:?}"
    );
    assert_eq!(global.calls.load(Ordering::Relaxed), 3);
}
