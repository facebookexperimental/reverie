/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Backend;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use reverie::process::Command;
use reverie::process::Stdio;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_e9patch::BuiltinTool;
use reverie_e9patch::E9patchBackend;
use reverie_e9patch::E9patchRewriter;
use reverie_e9patch::configure_guest_builtin;

#[derive(Default)]
struct EventCounter {
    delivered: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for EventCounter {
    type Request = u64;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, increment: u64) {
        self.delivered.fetch_add(increment, Ordering::SeqCst);
    }
}

fn subscriptions() -> Subscription {
    [Sysno::getpid].into_iter().collect()
}

fn direct_syscall_guest() -> OsString {
    std::env::var_os("REVERIE_E9PATCH_REAL_GUEST")
        .expect("set REVERIE_E9PATCH_REAL_GUEST to a direct getpid-syscall ELF")
}

fn compile_fixture(name: &str) -> (tempfile::TempDir, PathBuf) {
    compile_fixture_with_flags(name, &["-fno-pie", "-no-pie"])
}

fn compile_pie_fixture(name: &str) -> (tempfile::TempDir, PathBuf) {
    compile_fixture_with_flags(name, &["-fpie", "-pie"])
}

fn compile_fixture_with_flags(name: &str, flags: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let output = directory.path().join(name.trim_end_matches(".c"));
    let compiler = std::env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let result = ProcessCommand::new(compiler)
        .args(["-std=gnu11", "-O0", "-fno-stack-protector"])
        .args(flags)
        .arg(&source)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "failed to compile {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    (directory, output)
}

fn materialize_prepared_fixture(name: &str) -> (tempfile::TempDir, PathBuf) {
    let (directory, guest) = compile_fixture(name);
    let prepared = E9patchRewriter::from_env().unwrap().prepare(guest).unwrap();
    let executable = directory.path().join("rewritten-guest");
    let mut artifact = prepared.artifact().unwrap();
    let mut output = File::create(&executable).unwrap();
    std::io::copy(&mut artifact, &mut output).unwrap();
    let mut permissions = fs::metadata(&executable).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&executable, permissions).unwrap();
    (directory, executable)
}

#[derive(Default)]
struct EmulateGetpid;

#[reverie::tool]
impl Tool for EmulateGetpid {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        subscriptions()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        assert_eq!(guest.regs().await.rip, 0x401111);
        guest.send_rpc(1).await;
        Ok(1234)
    }
}

#[derive(Default)]
struct InjectGetpid;

#[reverie::tool]
impl Tool for InjectGetpid {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        subscriptions()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        guest.send_rpc(1).await;
        let result = guest.inject(syscall).await?;
        assert!(result > 0);
        Ok(result)
    }
}

#[derive(Default)]
struct CountRead;

#[reverie::tool]
impl Tool for CountRead {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::read].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::read);
        if guest.regs().await.rip == 0x401002 {
            guest.send_rpc(1).await;
            Ok(0)
        } else {
            Ok(guest.inject(syscall).await?)
        }
    }
}

#[derive(Default)]
struct CountGetpid;

#[reverie::tool]
impl Tool for CountGetpid {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        subscriptions()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        guest.send_rpc(1).await;
        Ok(424242)
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair and direct-syscall guest"]
async fn rewritten_syscall_is_delivered_and_emulated() {
    let mut command = Command::new(direct_syscall_guest());
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let (output, global) = E9patchBackend::run_with_output::<EmulateGetpid>(command, ())
        .await
        .unwrap();
    assert_eq!(global.delivered.load(Ordering::SeqCst), 1);
    assert_eq!(output.status, ExitStatus::Exited(0));
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair and direct-syscall guest"]
async fn rewritten_syscall_supports_guest_injection() {
    let (status, global) =
        E9patchBackend::run::<InjectGetpid>(Command::new(direct_syscall_guest()), ())
            .await
            .unwrap();
    assert_eq!(global.delivered.load(Ordering::SeqCst), 1);
    assert_eq!(status, ExitStatus::Exited(0));
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair and direct-syscall guest"]
async fn unsubscribed_rewritten_syscall_is_not_delivered_to_the_tool() {
    let (status, ()) = E9patchBackend::run::<()>(Command::new(direct_syscall_guest()), ())
        .await
        .unwrap();
    assert_eq!(status, ExitStatus::Exited(0));
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair and a C compiler"]
async fn rewritten_clone_restores_parent_and_child_contexts() {
    let (_directory, guest) = compile_fixture("direct_clone.c");
    let (status, ()) = E9patchBackend::run::<()>(Command::new(guest), ())
        .await
        .unwrap();
    assert_eq!(status, ExitStatus::Exited(0));
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair and a C compiler"]
async fn rewritten_rt_sigreturn_uses_the_original_signal_frame() {
    let (_directory, guest) = compile_fixture("direct_rt_sigreturn.c");
    let (status, ()) = E9patchBackend::run::<()>(Command::new(guest), ())
        .await
        .unwrap();
    assert_eq!(status, ExitStatus::Exited(0));
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair and a C compiler"]
async fn direct_builtin_passthrough_handles_far_rt_sigreturn_site() {
    let (_directory, guest) = materialize_prepared_fixture("direct_rt_sigreturn.c");
    let mut command = Command::new(guest);
    configure_guest_builtin(&mut command, BuiltinTool::Passthrough).unwrap();
    let output = command.output().await.unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair and a C compiler"]
async fn direct_builtin_spoof_mutates_rewritten_getpid_result() {
    let (_directory, guest) = materialize_prepared_fixture("direct_spoof_getpid.c");
    let mut command = Command::new(guest);
    configure_guest_builtin(&mut command, BuiltinTool::SpoofGetpid).unwrap();
    let output = command.output().await.unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
}

#[test]
#[ignore = "requires a built e9tool/e9patch pair and a C compiler"]
fn standalone_configuration_selects_direct_passthrough() {
    let (_directory, guest) = materialize_prepared_fixture("direct_rt_sigreturn.c");
    let mut command = std::process::Command::new(guest);
    reverie_e9patch::configure_command(&mut command).unwrap();
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair and a C compiler"]
async fn marker_collision_at_another_rip_is_not_a_syscall_event() {
    let (_directory, guest) = compile_fixture("marker_collision.c");
    let (status, global) = E9patchBackend::run::<CountRead>(Command::new(guest), ())
        .await
        .unwrap();
    assert_eq!(global.delivered.load(Ordering::SeqCst), 0);
    assert_eq!(status, ExitStatus::Exited(0));
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair and a C compiler"]
async fn exact_trap_with_unpatched_site_is_not_a_syscall_event() {
    let (_directory, guest) = compile_fixture("exact_trap_spoof.c");
    let (status, global) = E9patchBackend::run::<CountGetpid>(Command::new(guest), ())
        .await
        .unwrap();
    assert_eq!(global.delivered.load(Ordering::SeqCst), 0);
    assert_eq!(status.signal(), Some(libc::SIGTRAP));
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair and a C compiler"]
async fn exact_trap_with_patched_site_documents_collision_filter_limit() {
    let (_directory, guest) = compile_fixture_with_flags(
        "exact_trap_spoof.c",
        &["-fno-pie", "-no-pie", "-DSPOOF_PATCHED_SITE"],
    );
    let (_status, global) = E9patchBackend::run::<CountGetpid>(Command::new(guest), ())
        .await
        .unwrap();
    assert_eq!(global.delivered.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair and a C compiler"]
async fn pie_rewritten_site_validates_with_runtime_load_bias() {
    let (_directory, guest) = compile_pie_fixture("direct_spoof_getpid.c");
    let (status, global) = E9patchBackend::run::<CountGetpid>(Command::new(guest), ())
        .await
        .unwrap();
    assert_eq!(global.delivered.load(Ordering::SeqCst), 1);
    assert_eq!(status, ExitStatus::Exited(0));
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a ptrace-capable host"]
async fn non_elf_script_uses_ptrace_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let guest = directory.path().join("guest.sh");
    fs::write(&guest, "#!/bin/sh\nexit 0\n").unwrap();
    let mut permissions = fs::metadata(&guest).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&guest, permissions).unwrap();

    let (status, ()) = E9patchBackend::run::<()>(Command::new(guest), ())
        .await
        .unwrap();
    assert_eq!(status, ExitStatus::Exited(0));
}
