// The launcher cases of the library-test adapter (broker_library_tests.rs).
// They run in reverie-linuxemu's unit tests only; reverie-kvm includes the
// adapter but not these cases.
use crate::broker_library_tests::launcher_path;

/// These cases enter the existing helper before its ordinary bootstrap. They
/// exercise actual host calls; no libtest thread asserts StartupAuthority.
fn bootstrap_case(case: &str, expected: &str, accepted: bool) {
    let executable = std::env::current_exe().expect("library test executable");
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "30s"])
        .arg(launcher_path(&executable))
        .args(["--bootstrap-case", case])
        .output()
        .expect("start existing ordinary-main bootstrap helper");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{case}: status={:?} stdout={stdout} stderr={stderr}",
        output.status
    );
    assert!(stderr.is_empty(), "{case}: unexpected stderr={stderr}");
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(
        lines.first().copied(),
        Some(format!("BROKER_BOOTSTRAP_QUERY_READY case={case}").as_str())
    );
    assert_eq!(lines.last().copied(), Some(format!("BROKER_BOOTSTRAP_CASE_PASS case={case} expected={expected} mask_restored=true original_live=true").as_str()));
    assert_eq!(
        lines.len(),
        if accepted { 3 } else { 2 },
        "exact executed case receipts"
    );
    if accepted {
        let fields: Vec<_> = lines[1].split_whitespace().collect();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0], "NATIVE_CASE_BROKER_WAIT");
        let pid = fields[1]
            .strip_prefix("native_pid=")
            .expect("actual broker PID")
            .parse::<i32>()
            .unwrap();
        assert!(pid > 0);
        assert_eq!(fields[2], "raw_wait_status=0");
        assert_eq!(fields[3], "actual_wait=true");
    }
}

#[test]
fn bootstrap_unknown_filesystem_rejects_before_getattr() {
    bootstrap_case("procfs-reject", "rejected-eopnotsupp", false);
}

#[test]
fn bootstrap_audited_regular_and_null_classes_preserve_originals() {
    bootstrap_case("memfd-accept", "accepted-tmpfs", true);
    bootstrap_case("null-accept", "accepted-null", true);
}

#[test]
fn bootstrap_path_only_does_not_query_inode_attributes() {
    bootstrap_case("opath-procfs-accept", "accepted-path-only", true);
}

/// Only the ordinary-main child owns startup authority. The waited status is
/// case-specific: 125 records failed invocation termination, never cleanup.
fn fatal_abort_case(case: &str, expected_status: i32) -> String {
    let executable = std::env::current_exe().expect("library test executable");
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "30s"])
        .arg(launcher_path(&executable))
        .args(["--fatal-abort-case", case])
        .output()
        .expect("start ordinary-main fatal invocation helper");
    let stdout = String::from_utf8(output.stdout).expect("native case stdout");
    let stderr = String::from_utf8(output.stderr).expect("native case stderr");
    assert_eq!(
        output.status.code(),
        Some(expected_status),
        "{case}: actual waited status={:?} stdout={stdout} stderr={stderr}",
        output.status
    );
    assert!(stderr.is_empty(), "{case}: unexpected stderr={stderr}");
    stdout
}

fn fatal_case_pid(field: &str, prefix: &str) -> i32 {
    let pid = field.strip_prefix(prefix).unwrap().parse::<i32>().unwrap();
    assert!(pid > 0, "native identity must be positive: {field}");
    pid
}

#[test]
fn fatal_invocation_original_creator_exits_without_rust_drop_or_park() {
    let stdout = fatal_abort_case("original-creator", 125);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "exact executed fatal case receipts");
    let fields: Vec<_> = lines[0].split_whitespace().collect();
    assert_eq!(fields.len(), 6);
    assert_eq!(fields[0], "FATAL_ABORT_CASE_READY");
    assert_eq!(fields[1], "case=original-creator");
    let creator = fatal_case_pid(fields[2], "creator_pid=");
    let thread = fatal_case_pid(fields[3], "creator_tid=");
    let broker = fatal_case_pid(fields[4], "broker_pid=");
    assert_eq!(creator, thread, "ordinary single-threaded launcher");
    assert_ne!(creator, broker);
    assert_eq!(fields[5], "native_wait=false");
    assert_eq!(lines[1], "FATAL_ABORT_FILTER_ARMED futex_and_pause=true");
    // No broker wait or surviving-client settlement is inferred from exit125.
}

#[test]
fn fatal_invocation_wrong_process_returns_owner_before_two_native_waits() {
    let stdout = fatal_abort_case("wrong-process", 0);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "exact refused-owner cleanup receipts");
    assert_eq!(
        lines[0],
        "FATAL_ABORT_WRONG_PROCESS_REFUSED same_owner=true inherited_client_refused=true"
    );
    let wait: Vec<_> = lines[1].split_whitespace().collect();
    assert_eq!(wait.len(), 4);
    assert_eq!(wait[0], "NATIVE_CASE_BROKER_WAIT");
    let broker = fatal_case_pid(wait[1], "native_pid=");
    assert_eq!(wait[2], "raw_wait_status=0");
    assert_eq!(wait[3], "actual_wait=true");
    let cleanup: Vec<_> = lines[2].split_whitespace().collect();
    assert_eq!(cleanup.len(), 6);
    assert_eq!(cleanup[0], "FATAL_ABORT_WRONG_PROCESS_CLEANUP");
    let child = fatal_case_pid(cleanup[1], "child_pid=");
    assert_ne!(child, broker);
    assert_eq!(cleanup[2], "child_wait_status=0");
    assert_eq!(fatal_case_pid(cleanup[3], "broker_pid="), broker);
    assert_eq!(cleanup[4], "broker_wait_status=0");
    assert_eq!(cleanup[5], "actual_waits=2");
}
