// The launcher cases of the library-test adapter (broker_library_tests.rs).
// They run in reverie-linuxemu's unit tests only; reverie-kvm includes the
// adapter but not these cases.
use crate::broker_library_tests::launcher_path;
use crate::broker_library_tests::report_skip;

/// The named-skip reason when the launcher refused setup over a host
/// capability it names itself: no ambient mount in its bootstrap
/// mountinfo.
fn broker_host_skip(stderr: &str) -> Option<&'static str> {
    if stderr.contains("ambient mount absent from bootstrap mountinfo") {
        Some(
            "broker ambient mount absent from bootstrap mountinfo on this host (https://github.com/facebookexperimental/reverie/issues/96)",
        )
    } else {
        None
    }
}

/// The bootstrap ambient census classifies the broker's own socket
/// descriptors too; when a fresh socketpair's mount is absent from
/// mountinfo on this host, accepted-class cases cannot classify here.
fn ambient_mount_visible() -> bool {
    use std::os::fd::AsRawFd;
    let Ok((probe, _peer)) = std::os::unix::net::UnixStream::pair() else {
        return false;
    };
    let Ok(fdinfo) = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", probe.as_raw_fd()))
    else {
        return false;
    };
    let Some(mnt_id) = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .map(str::trim)
    else {
        return false;
    };
    let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    mountinfo
        .lines()
        .any(|line| line.split_whitespace().next() == Some(mnt_id))
}

/// These cases enter the existing helper before its ordinary bootstrap. They
/// exercise actual host calls; no libtest thread asserts StartupAuthority.
fn bootstrap_case(test: &str, case: &str, expected: &str, accepted: bool) {
    if accepted && !ambient_mount_visible() {
        report_skip(
            test,
            "broker ambient mount absent from bootstrap mountinfo on this host (https://github.com/facebookexperimental/reverie/issues/96)",
        );
        return;
    }
    let executable = std::env::current_exe().expect("library test executable");
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "30s"])
        .arg(launcher_path(&executable))
        .args(["--bootstrap-case", case])
        .output()
        .expect("start existing ordinary-main bootstrap helper");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Only the ambient-absent refusal skips here. The metadata-query
    // (EOPNOTSUPP) signature deliberately does NOT: the procfs-reject
    // case's expected outcome is itself an EOPNOTSUPP rejection, so
    // skipping on that signature would mask its regression.
    if !output.status.success() && stderr.contains("ambient mount absent from bootstrap mountinfo")
    {
        report_skip(
            test,
            "broker ambient mount absent from bootstrap mountinfo on this host (https://github.com/facebookexperimental/reverie/issues/96)",
        );
        return;
    }
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
    bootstrap_case(
        "broker_library_selftests::bootstrap_unknown_filesystem_rejects_before_getattr",
        "procfs-reject",
        "rejected-eopnotsupp",
        false,
    );
}

#[test]
fn bootstrap_audited_regular_and_null_classes_preserve_originals() {
    bootstrap_case(
        "broker_library_selftests::bootstrap_audited_regular_and_null_classes_preserve_originals",
        "memfd-accept",
        "accepted-tmpfs",
        true,
    );
    bootstrap_case(
        "broker_library_selftests::bootstrap_audited_regular_and_null_classes_preserve_originals",
        "null-accept",
        "accepted-null",
        true,
    );
}

#[test]
fn bootstrap_path_only_does_not_query_inode_attributes() {
    bootstrap_case(
        "broker_library_selftests::bootstrap_path_only_does_not_query_inode_attributes",
        "opath-procfs-accept",
        "accepted-path-only",
        true,
    );
}

/// Only the ordinary-main child owns startup authority. The waited status is
/// case-specific: 125 records failed invocation termination, never cleanup.
fn fatal_abort_case(test: &str, case: &str, expected_status: i32) -> Option<String> {
    fatal_abort_case_inheriting(test, case, expected_status, None)
}

/// [`fatal_abort_case`], with the launcher also inheriting `leaked`, a
/// descriptor this test process holds with close-on-exec set: it is cleared
/// in the forked child alone, so only the launcher's process tree (through
/// `timeout`) inherits the descriptor, as a spawner's leak would hand it on.
/// No other test's child sees it.
fn fatal_abort_case_inheriting(
    test: &str,
    case: &str,
    expected_status: i32,
    leaked: Option<std::os::fd::BorrowedFd<'_>>,
) -> Option<String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let executable = std::env::current_exe().expect("library test executable");
    let mut command = std::process::Command::new("timeout");
    command
        .args(["--kill-after=2s", "30s"])
        .arg(launcher_path(&executable))
        .args(["--fatal-abort-case", case]);
    if let Some(leaked) = leaked {
        let fd = leaked.as_raw_fd();
        // SAFETY: runs in the forked child before exec, and calls only fcntl,
        // which is async-signal-safe, on a descriptor the parent keeps open
        // until the child has been waited for.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }
    let output = command
        .output()
        .expect("start ordinary-main fatal invocation helper");
    let stdout = String::from_utf8(output.stdout).expect("native case stdout");
    let stderr = String::from_utf8(output.stderr).expect("native case stderr");
    if let Some(reason) = broker_host_skip(&stderr) {
        report_skip(test, reason);
        return None;
    }
    assert_eq!(
        output.status.code(),
        Some(expected_status),
        "{case}: actual waited status={:?} stdout={stdout} stderr={stderr}",
        output.status
    );
    assert!(stderr.is_empty(), "{case}: unexpected stderr={stderr}");
    Some(stdout)
}

fn fatal_case_pid(field: &str, prefix: &str) -> i32 {
    let pid = field.strip_prefix(prefix).unwrap().parse::<i32>().unwrap();
    assert!(pid > 0, "native identity must be positive: {field}");
    pid
}

#[test]
fn fatal_invocation_original_creator_exits_without_rust_drop_or_park() {
    let Some(stdout) = fatal_abort_case(
        "broker_library_selftests::fatal_invocation_original_creator_exits_without_rust_drop_or_park",
        "original-creator",
        125,
    ) else {
        return;
    };
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
    let Some(stdout) = fatal_abort_case(
        "broker_library_selftests::fatal_invocation_wrong_process_returns_owner_before_two_native_waits",
        "wrong-process",
        0,
    ) else {
        return;
    };
    assert_wrong_process_receipts(&stdout);
}

/// A spawner, such as a test runner or a shell, can leave descriptors open
/// without close-on-exec; every program it starts inherits them. The broker
/// would classify each as one of the launcher's held originals, and one on a
/// filesystem whose class it cannot prove (a FUSE file on an Eden checkout,
/// or here a procfs file, which every host has and the broker refuses the same
/// way: "unproved ambient filesystem metadata-query class") would refuse the
/// launch. The launcher closes what it inherited above stderr before its
/// census, so the wrong-process case runs to its exact receipts while the
/// launcher inherits such a descriptor.
#[test]
fn a_launcher_ignores_descriptors_its_spawner_leaked() {
    use std::os::fd::AsFd;
    let leaked = std::fs::File::open("/proc/self/status").expect("open a procfs descriptor");
    let Some(stdout) = fatal_abort_case_inheriting(
        "broker_library_selftests::a_launcher_ignores_descriptors_its_spawner_leaked",
        "wrong-process",
        0,
        Some(leaked.as_fd()),
    ) else {
        return;
    };
    assert_wrong_process_receipts(&stdout);
}

/// The exact receipts of the fatal-abort wrong-process case: the refused
/// owner, then both native waits.
fn assert_wrong_process_receipts(stdout: &str) {
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
