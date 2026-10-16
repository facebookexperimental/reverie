/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Live regressions for DBT task identity and thread admission.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

use reverie_dbt::DbtRunner;

fn compile_fixture(directory: &Path, name: &str) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.c"));
    let output = directory.join(name);
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let status = Command::new(compiler)
        .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-pthread")
        .arg("-o")
        .arg(&output)
        .status()
        .unwrap_or_else(|error| panic!("compile {}: {error}", source.display()));
    assert!(status.success(), "fixture compilation failed");
    output
}

fn run_fixture(name: &str, client_argument: &str) -> Output {
    run_fixture_with_env(name, client_argument, &[])
}

fn run_fixture_with_env(name: &str, client_argument: &str, env: &[(&str, &str)]) -> Output {
    run_fixture_under(name, client_argument, env, "")
}

/// [`run_fixture_with_env`] in a fresh user and PID namespace, including a
/// process whose actual kernel PID is one.
fn run_fixture_in_pid_namespace(name: &str, client_argument: &str, env: &[(&str, &str)]) -> Output {
    run_fixture_under(
        name,
        client_argument,
        env,
        "unshare --user --map-root-user --pid --fork --mount-proc ",
    )
}

fn run_fixture_under(
    name: &str,
    client_argument: &str,
    env: &[(&str, &str)],
    launcher_prefix: &str,
) -> Output {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = compile_fixture(directory.path(), name);
    // A broken startup gate can prevent the guest from handling even SIGALRM.
    // Bound the native launcher outside DynamoRIO and terminate its process
    // group, so the test reports a failed status instead of hanging forever.
    let launcher = directory.path().join("bounded-drrun");
    std::fs::write(
        &launcher,
        format!(
            "#!/bin/sh\nexec timeout --signal=TERM --kill-after=2s 10s {launcher_prefix}\"$REVERIE_DBT_TEST_DRRUN\" \"$@\"\n"
        ),
    )
    .expect("write bounded launcher");
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))
        .expect("make bounded launcher executable");
    let client = std::env::var_os("REVERIE_DBT_CLIENT")
        .expect("REVERIE_DBT_CLIENT must point to the built native client");
    let mut guest = Command::new(fixture);
    guest.env("REVERIE_DBT_TEST_DRRUN", reverie_dbt::bundled_drrun_path());
    guest.envs(env.iter().copied());
    DbtRunner::new(launcher, client)
        .expect("create bounded native runner")
        .client_argument(client_argument)
        .output(&guest)
        .unwrap_or_else(|error| panic!("run {name}: {error}"))
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn reused_host_tid_waits_for_the_clone_parents_virtual_identity() {
    let output = run_fixture("reused_tid_start", "-test-reused-tid");
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"reused-tid-start=ok\n");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("REUSED_TID_TEST exercised=1"),
        "the stale host-TID mapping was not exercised: {output:?}"
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn an_exiting_process_does_not_block_another_process_thread_start() {
    let output = run_fixture(
        "thread_clone_process_exit",
        "-test-thread-clone-process-exit",
    );
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"thread-clone-process-exit=ok\n");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("THREAD_CLONE_PROCESS_EXIT_TEST exercised=1"),
        "the exiting process path was not exercised: {output:?}"
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn a_failed_thread_clone_does_not_block_the_next_thread_start() {
    let output = run_fixture("failed_thread_clone", "-test-wait-for-background");
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"failed-thread-clone=ok\n");
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn a_new_thread_cannot_write_memory_before_admission() {
    let output = run_fixture("thread_start_write", "-test-thread-start-write");
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"thread-start-write=ok\n");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("THREAD_START_WRITE_TEST blocked=1"),
        "the pre-admission write check was not exercised: {output:?}"
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn a_copied_process_thread_uses_its_parents_published_identity() {
    let output = run_fixture("copied_thread_identity", "-test-reused-tid");
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"copied-thread-identity=ok\n");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("REUSED_TID_TEST exercised=1"),
        "the copied thread's stale host-TID mapping was not exercised: {output:?}"
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn a_precompiled_entry_cannot_bypass_thread_admission() {
    let output = run_fixture("thread_start_write_precompiled", "-test-thread-start-write");
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"precompiled-thread-start-write=ok\n");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("THREAD_START_WRITE_TEST blocked=1"),
        "the pre-admission write check was not exercised: {output:?}"
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn a_stalled_clone_fails_with_an_admission_diagnostic() {
    let output = run_fixture("reused_tid_start", "-test-stalled-thread-start");
    assert_eq!(output.status.code(), Some(96), "guest result: {output:?}");
    assert!(output.stdout.is_empty(), "unadmitted guest ran: {output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("STALLED_THREAD_START_TEST exercised=1"),
        "the stalled clone was not exercised: {output:?}"
    );
    let diagnostic = stderr
        .lines()
        .find(|line| line.starts_with("reverie-dbt: thread admission timed out:"))
        .unwrap_or_else(|| panic!("missing admission diagnostic: {output:?}"));
    assert!(diagnostic.contains("pending_clones=1 "), "{diagnostic}");
    assert!(diagnostic.contains("pending_start=2 "), "{diagnostic}");
    assert!(diagnostic.ends_with("timeout_ms=100"), "{diagnostic}");
    let host_tid = diagnostic
        .split_whitespace()
        .find_map(|field| field.strip_prefix("host_tid="))
        .expect("diagnostic host TID")
        .parse::<u32>()
        .expect("positive numeric host TID");
    let kernel_pid = diagnostic
        .split_whitespace()
        .find_map(|field| field.strip_prefix("kernel_pid="))
        .expect("diagnostic kernel PID")
        .parse::<u32>()
        .expect("positive numeric kernel PID");
    assert!(
        host_tid > 0 && kernel_pid > 0 && host_tid != kernel_pid,
        "{diagnostic}"
    );
}

/// The TID words Linux stores for CLONE_PARENT_SETTID (a process clone, and a
/// thread clone as pthread_create makes) and CLONE_CHILD_SETTID (a process
/// clone, as fork makes), and both words of a clone3 given distinct ones, hold
/// the virtual TID that clone returned and that the child's gettid or getpid
/// reports, not the host TID the kernel wrote
/// (https://github.com/rrnewton/hermit/issues/3147).
#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn clone_settid_words_hold_the_virtual_tid() {
    let output = run_fixture("settid_virtual_identity", "-test-wait-for-background");
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(
        output.stdout,
        b"settid parent=1 thread=1 child=1 clone3=1\n"
    );
}

/// NoopTool tail-injects (native action 2). The test above leaves the
/// observation Tool unset (native action 0). Both run the complete SETTID and
/// clear-TID matrix, including copied children, against procfs kernel witnesses.
#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn clone_settid_words_match_kernel_identity_with_tail_injection() {
    let output = run_fixture_with_env(
        "settid_virtual_identity",
        "-test-wait-for-background",
        &[("HERMIT_DBT_NOOP", "1")],
    );
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(
        output.stdout,
        b"settid parent=1 thread=1 child=1 clone3=1\n"
    );
}

/// Returning gettid and tail-injected clone must retain the same identity
/// relation. This catches a partial native getter cut that leaves clone/SETTID
/// words in a different identity domain; the full kernel witness remains too.
#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn clone_settid_words_match_kernel_identity_with_returning_gettid() {
    let output = run_fixture_with_env(
        "settid_virtual_identity",
        "-test-wait-for-background",
        &[("HERMIT_DBT_TEST_SET_REG", "returning-gettid")],
    );
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(
        output.stdout,
        b"settid parent=1 thread=1 child=1 clone3=1\n"
    );
}

/// A robust mutex whose owner dies returns EOWNERDEAD to the next locker, when
/// the owner was a forked child's main thread, an exiting thread, a thread that
/// exit_group killed, a process that exec'd, or a thread that a sibling's exec
/// killed, and a locker already asleep on it is woken. A failed exec leaves
/// the held mutexes unlockable, and the walk stops at a misaligned owner word
/// as Linux's does. The owner words retain kernel TIDs, including when an
/// owner is killed by SIGKILL and cannot execute client cleanup. Linux also
/// handles nonleader exec: de_thread transfers the process ID before walking
/// the caller's list. Failed exec must leave the original word unchanged.
/// The SIGKILL assertion covers the former translated-owner gap in
/// https://github.com/rrnewton/hermit/issues/4239.
#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn a_dead_robust_mutex_owner_is_marked_owner_dead() {
    let output = run_fixture("robust_owner_death", "-test-wait-for-background");
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, ROBUST_OWNER_DEATH_OUTPUT);
    for (first, expected) in [
        (
            "failed-exec",
            &b"robust first_failed_exec=1 id_overlap=0\n"[..],
        ),
        ("exec", &b"robust first_exec=ETIMEDOUT id_overlap=0\n"[..]),
    ] {
        let output = run_fixture_with_env(
            "robust_owner_death",
            "-test-wait-for-background",
            &[("ROBUST_OWNER_DEATH_FIRST", first)],
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(expected),
            "{first}"
        );
        assert!(output.status.success(), "{first}: guest failed: {output:?}");
    }
}

const ROBUST_OWNER_DEATH_OUTPUT: &[u8] =
    b"robust fork_child=1 thread=1 exit_group_thread=1 waited_thread=1 \
      exec_child=1 exec_killed_thread=1 failed_exec=1 sigkill=EOWNERDEAD \
      walk_stop=1 tgid_exec=1 tgid_failed_exec=1\n";

/// Repeat the complete owner-death and exec checks in a fresh PID namespace.
/// Raw worker TIDs remain distinct from their process ID (`id_overlap=0`).
/// Failed exec must leave the owner word unchanged and unlockable; successful
/// nonleader exec must not mark or rewrite a word naming the old worker TID.
#[test]
#[ignore = "requires a built DynamoRIO, the reverie-dbt native client and unprivileged user namespaces; run explicitly with --ignored"]
fn a_dead_robust_mutex_owner_is_marked_owner_dead_in_a_pid_namespace() {
    let all = run_fixture_in_pid_namespace("robust_owner_death", "-test-wait-for-background", &[]);
    assert!(all.status.success(), "guest failed: {all:?}");
    assert_eq!(all.stdout, ROBUST_OWNER_DEATH_OUTPUT);
    for (first, expected) in [
        (
            "failed-exec",
            &b"robust first_failed_exec=1 id_overlap=0\n"[..],
        ),
        ("exec", &b"robust first_exec=ETIMEDOUT id_overlap=0\n"[..]),
    ] {
        let output = run_fixture_in_pid_namespace(
            "robust_owner_death",
            "-test-wait-for-background",
            &[("ROBUST_OWNER_DEATH_FIRST", first)],
        );
        assert!(output.status.success(), "{first}: guest failed: {output:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(expected),
            "{first}"
        );
    }
}

/// The native client's atomic guest-word compare-and-exchange, which Detcore
/// uses to mark a dead robust-mutex owner's word under DBT
/// (https://github.com/rrnewton/hermit/issues/4238), replaces a matching word,
/// leaves a mismatching one alone and reports what it held, refuses a
/// misaligned address with EINVAL, turns faults on an unmapped or read-only
/// word into EFAULT without storing, and keeps every increment when a client
/// thread and the calling thread each make 200000 retry-loop increments of one
/// word at the same time (Claude review of
/// https://github.com/rrnewton/reverie/pull/1023).
#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn the_native_compare_exchange_reports_each_outcome() {
    let output = run_fixture("settid_virtual_identity", "-test-compare-exchange");
    assert!(output.status.success(), "guest failed: {output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "reverie-dbt: compare-exchange self-test matched=1 mismatched=1 \
             core=1 misaligned=1 unmapped=1 unwritable=1 contended=1"
        ),
        "{stderr}"
    );
}

/// The compare-and-exchange reaches the guest's own pages through
/// `Guest::memory()` and the callback the runtime installed: it succeeds on a
/// word whose page holds code the guest has run, which DynamoRIO has made
/// read-only for its code cache while the guest still sees it writable, the
/// code still runs afterwards, and genuinely read-only and unmapped words, and
/// a word in a shared mapping past the end of its file, give EFAULT without a
/// store (Codex review of
/// https://github.com/rrnewton/reverie/pull/1023). The same exchange made
/// from a DynamoRIO client thread, outside any system-call event, is refused
/// with EFAULT, says so on stderr, and leaves the word alone (Claude re-check
/// of the same pull request).
#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn the_guest_compare_exchange_writes_a_page_dynamorio_protects() {
    let output = run_fixture_with_env(
        "compare_exchange_guest",
        "-test-compare-exchange",
        &[("HERMIT_DBT_TEST_COMPARE_EXCHANGE", "1")],
    );
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(
        output.stdout,
        b"cas_guest gated=1 code_page=1 refused=1 code_ok=1 read_only=1 unmapped=1 \
          past_eof=1\n"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "reverie-dbt: compare-exchange refused outside a system-call event \
             on a page DynamoRIO made read-only"
        ),
        "the exchange outside a system-call event was not refused by the gate: {stderr}"
    );
    assert!(
        stderr.contains("reverie-dbt: compare-exchange on a page DynamoRIO made read-only"),
        "the code page was not one DynamoRIO protects, so this case did not run: {stderr}"
    );
}

/// Active namespace observation covers both clone forms and a later clone
/// whose PID namespace was selected by unshare, without rejecting invalid calls.
#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn nested_pid_namespace_children_are_refused_before_child_syscall_dispatch() {
    for mode in [
        "separate-vm",
        "shared-vm",
        "shared-vm-vfork",
        "pid-for-children",
        "pid-for-children-vfork",
    ] {
        let output = run_fixture_in_pid_namespace(
            "pid_namespace_admission",
            "-test-wait-for-background",
            &[
                ("HERMIT_DBT_NOOP", "1"),
                ("REVERIE_DBT_TEST_PID_NAMESPACE_CASE", mode),
            ],
        );
        assert!(output.status.success(), "{mode}: {output:?}");
        assert_eq!(
            output.stdout, b"nested-pid-child-refused-before-application\n",
            "{mode}: child application must not run: {output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(
                "refusing nested PID namespace task admission: container-observed child identity transport is not implemented"
            ),
            "{mode}: named transport refusal must be retained: {output:?}"
        );
    }
}
