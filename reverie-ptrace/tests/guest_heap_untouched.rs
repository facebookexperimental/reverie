/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Plain reverie-ptrace must leave the guest heap exactly as a native run
//! does at `main`: the tracer injects nothing that moves the program break or
//! initialises glibc's malloc before the guest's first statement.

#![cfg(target_arch = "x86_64")]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::LazyLock;
use std::time::Duration;

use reverie::Error;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tool;
use reverie::process::Command;
use reverie::process::Stdio;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_ptrace::TracerBuilder;

/// What every correct run of `guest_heap_untouched.c` prints: the program
/// break has not moved and glibc's main arena and mmap accounting are empty.
const UNTOUCHED_HEAP: &str = "brk_delta=0 arena=0 mmapped=0\n";

/// Subscribes to brk and getpid, and injects them unchanged.
#[derive(Default)]
struct InjectHeapSyscalls;

#[reverie::tool]
impl Tool for InjectHeapSyscalls {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::brk, Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::brk | Sysno::getpid => {}
            other => panic!("subscribed only to brk and getpid, got {other:?}"),
        }
        Ok(guest.inject(syscall).await?)
    }
}

/// Compiles `tests/fixtures/guest_heap_untouched.c` once, beside the test
/// binary.
fn guest() -> &'static PathBuf {
    static GUEST: LazyLock<PathBuf> = LazyLock::new(|| {
        // Prefer the run-time CARGO_MANIFEST_DIR, which Cargo and the fbsource
        // BUCK rule set. The compile-time value is a directory on the build
        // host and is missing on the test host when the binary was built
        // remotely.
        let source = std::env::var_os("CARGO_MANIFEST_DIR")
            .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
            .join("tests/fixtures/guest_heap_untouched.c");
        // One guest beside the test binary, compiled by each process and
        // renamed into place.
        let directory = std::env::current_exe()
            .expect("locate the test binary")
            .parent()
            .expect("the test binary has a directory")
            .to_path_buf();
        let path = directory.join("reverie-guest-heap-untouched");
        let staging = directory.join(format!(
            "reverie-guest-heap-untouched.{}.tmp",
            std::process::id()
        ));
        let compiler = std::env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
        let result = ProcessCommand::new(&compiler)
            .args(["-std=gnu11", "-O0", "-fno-pie", "-no-pie"])
            .arg(&source)
            .arg("-o")
            .arg(&staging)
            .output()
            .unwrap_or_else(|error| panic!("invoke {compiler:?}: {error}"));
        assert!(
            result.status.success(),
            "compile {} failed:\n{}",
            source.display(),
            String::from_utf8_lossy(&result.stderr)
        );
        std::fs::rename(&staging, &path)
            .unwrap_or_else(|error| panic!("publish {}: {error}", path.display()));
        path
    });
    &GUEST
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Natively, nothing allocates before main; under plain reverie-ptrace, with
/// a Tool that intercepts and injects brk, the guest sees the same untouched
/// heap.
#[tokio::test(flavor = "current_thread")]
async fn tracer_leaves_guest_heap_uninitialised() {
    // Admission control: natively, nothing allocates before main. If this
    // fails, the fixture or the host's C runtime is wrong, not the tracer.
    let native = ProcessCommand::new(guest()).output().unwrap();
    assert!(native.status.success(), "native fixture failed: {native:?}");
    assert_eq!(
        text(&native.stdout),
        UNTOUCHED_HEAP,
        "admission control failed: the fixture does not see an untouched heap natively"
    );

    // Plain reverie-ptrace injects nothing into the guest's heap.
    let mut command = Command::new(guest());
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let (output, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        TracerBuilder::<InjectHeapSyscalls>::new(command)
            .spawn()
            .await?
            .wait_with_output()
            .await
    })
    .await
    .expect("plain ptrace run timed out")
    .expect("plain ptrace run failed");
    assert!(
        output.status.success(),
        "plain ptrace fixture failed: {output:?}"
    );
    assert_eq!(
        text(&output.stdout),
        UNTOUCHED_HEAP,
        "the fixture does not see an untouched heap under plain ptrace: {output:?}"
    );
}
