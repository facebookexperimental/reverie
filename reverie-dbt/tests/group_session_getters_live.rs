/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Read-only group/session/policy/priority queries can name live tasks outside the DBT client.

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;

use reverie_dbt::DbtRunner;

struct HeldChild(Child);

impl Drop for HeldChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        self.0.wait().expect("reap held ordinary child");
    }
}

#[test]
#[ignore = "requires a built DynamoRIO and native client; run explicitly with --ignored"]
fn original_group_queries_reach_a_live_unregistered_process() {
    compare_with_linux("original");
}

#[test]
#[ignore = "requires a built DynamoRIO and native client; run explicitly with --ignored"]
fn tail_group_queries_reach_a_live_unregistered_process() {
    compare_with_linux("tail");
}

#[test]
#[ignore = "requires a built DynamoRIO and native client; run explicitly with --ignored"]
fn returning_group_queries_reach_a_live_unregistered_process() {
    compare_with_linux("returning");
}

fn raw_priority(which: libc::c_long, who: libc::c_long) -> i64 {
    // syscall returns the kernel's 20-minus-nice value, not libc getpriority's
    // converted nice value. Normalize only the syscall wrapper's errno case.
    let result = unsafe { libc::syscall(libc::SYS_getpriority, which, who) };
    if result == -1 {
        -i64::from(std::io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        result
    }
}

fn compare_with_linux(mode: &str) {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = directory.path().join("group-session-getters");
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/group_session_getters.c");
    let status = Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()))
        .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .arg("-o")
        .arg(&fixture)
        .status()
        .expect("compile group/session getter fixture");
    assert!(status.success(), "fixture compilation failed");

    // This is the test parent's ordinary child, never instrumented or entered
    // in the DBT client's membership. EOF is withheld until all queries finish.
    // Its separate group, session and policy make target-to-self substitutions observable.
    let mut holder = Command::new("/bin/cat");
    holder
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid and the raw scheduler syscall are async-signal-safe; the child
    // calls no Rust code that
    // allocates or acquires locks between fork and exec.
    unsafe {
        holder.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let parameter = libc::sched_param { sched_priority: 0 };
            if libc::syscall(
                libc::SYS_sched_setscheduler,
                0,
                libc::SCHED_BATCH,
                &parameter,
            ) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = HeldChild(holder.spawn().expect("hold ordinary unregistered child"));
    let pid = child.0.id() as libc::pid_t;
    // SAFETY: these read-only queries name our live child.
    let pgid = unsafe { libc::getpgid(pid) };
    let sid = unsafe { libc::getsid(pid) };
    let policy = unsafe { libc::sched_getscheduler(pid) };
    assert_eq!(pgid, pid, "held child must lead its own group");
    assert_eq!(sid, pid, "held child must lead its own session");
    assert_eq!(policy, libc::SCHED_BATCH, "held child must use SCHED_BATCH");
    let process = libc::PRIO_PROCESS as libc::c_long;
    let own_pid = unsafe { libc::getpid() } as libc::c_long;
    let priority_cases = [
        (process, 0),
        (process, own_pid),
        (process, i64::from(pid)),
        (process, i64::from(i32::MAX)),
        (process, -1),
        (-1, 0),
        (3, i64::from(pid)),
        (999, i64::from(i32::MAX)),
    ];
    let priority_values: Vec<_> = priority_cases
        .iter()
        .map(|&(which, who)| raw_priority(which, who))
        .collect();
    assert!((1..=40).contains(&priority_values[0]));
    assert_eq!(priority_values[1], priority_values[0]);
    assert!((1..=40).contains(&priority_values[2]));
    assert_eq!(
        &priority_values[3..],
        &[
            -i64::from(libc::ESRCH),
            -i64::from(libc::ESRCH),
            -i64::from(libc::EINVAL),
            -i64::from(libc::EINVAL),
            -i64::from(libc::EINVAL),
        ],
        "native target/selector controls changed"
    );
    // nice19 can make self and target equal. Do not require value-based target
    // discrimination: the live target and exact raw arguments are the witness.
    let arguments = [
        pid.to_string(),
        pgid.to_string(),
        sid.to_string(),
        policy.to_string(),
        priority_values[2].to_string(),
        priority_values[0].to_string(),
    ];
    let mut expected = format!(
        "getpgid live={pgid} errno=0\ngetpgid zero-is-self=1\n\
         getpgid negative rc=-1 errno={}\ngetpgid absent rc=-1 errno={}\n\
         getsid live={sid} errno=0\ngetsid zero-is-self=1\n\
         getsid negative rc=-1 errno={}\ngetsid absent rc=-1 errno={}\n\
         sched_getscheduler live={policy} errno=0\nsched_getscheduler zero-is-self=1\n\
         sched_getscheduler negative rc=-1 errno={}\n\
         sched_getscheduler absent rc=-1 errno={}\n",
        libc::ESRCH,
        libc::ESRCH,
        libc::ESRCH,
        libc::ESRCH,
        libc::EINVAL,
        libc::ESRCH,
    );
    let priority_labels = [
        "zero",
        "self",
        "live",
        "absent",
        "negative",
        "invalid-negative-zero",
        "invalid-three-live",
        "invalid-999-absent",
    ];
    for (label, &value) in priority_labels.iter().zip(&priority_values) {
        let (rc, error) = if value < 0 { (-1, -value) } else { (value, 0) };
        expected.push_str(&format!("getpriority {label} rc={rc} errno={error}\n"));
    }
    expected.push_str("group-session-getters=ok\n");
    let native = Command::new(&fixture)
        .arg("original")
        .args(&arguments)
        .output()
        .expect("run Linux oracle");
    eprintln!("{mode} native: {native:?}");
    assert!(native.status.success(), "native oracle failed: {native:?}");
    assert_eq!(native.stdout, expected.as_bytes());

    let runner = DbtRunner::from_env()
        .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must be set")
        .client_argument("-test-wait-for-background");
    let mut guest = Command::new(&fixture);
    guest
        .arg(mode)
        .args(&arguments)
        .env_remove(reverie_dbt::TOOL_ENV);
    // The named registry selector takes precedence over the legacy selectors.
    // Select exactly the route whose native injection contract this test checks.
    for selector in [
        "HERMIT_DBT_TEST_REWRITE_EXIT",
        "HERMIT_DBT_TEST_INJECT_INVALID_CLONE",
        "HERMIT_DBT_TEST_SET_REG",
        "HERMIT_DBT_TEST_COMPARE_EXCHANGE",
        "HERMIT_DBT_TEST_PPID",
        "HERMIT_DBT_TEST_BACKTRACE",
        "HERMIT_DBT_STRACE",
        "HERMIT_DBT_SYSCALL_HISTOGRAM",
        "HERMIT_DBT_COUNTER1",
        "HERMIT_DBT_COUNTER2",
        "HERMIT_DBT_CHUNKY_PRINT",
        "HERMIT_DBT_CHROME_TRACE",
        "HERMIT_DBT_CHAOS",
        "HERMIT_DBT_NOOP",
        "HERMIT_DBT_COUNTER1_EXACT",
        "HERMIT_DBT_COUNTER2_EXACT",
    ] {
        guest.env_remove(selector);
    }
    match mode {
        "tail" => {
            guest.env("HERMIT_DBT_NOOP", "1");
        }
        "returning" => {
            guest.env("HERMIT_DBT_TEST_SET_REG", "1");
        }
        "original" => {}
        _ => unreachable!(),
    }
    let output = runner.output(&guest).expect("run DBT getter fixture");
    assert!(
        child.0.try_wait().expect("inspect held child").is_none(),
        "the independent target must stay live through every query"
    );
    eprintln!("{mode}: {output:?}");
    assert!(output.status.success(), "{mode} fixture failed: {output:?}");
    assert_eq!(output.stdout, native.stdout, "{mode} differs from Linux");
    if mode == "returning" {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let rows: Vec<_> = stderr
            .lines()
            .filter_map(|line| line.strip_prefix("reverie-dbt-test: kernel-group-query "))
            .collect();
        assert_eq!(rows.len(), 15, "missing returning observations: {output:?}");
        for row in rows {
            let fields: Vec<_> = row.split_whitespace().collect();
            assert_eq!(fields.len(), 4, "malformed kernel observation: {row}");
            let kernel = fields[2].strip_prefix("kernel=").unwrap();
            let injected = fields[3].strip_prefix("injected=").unwrap();
            assert_eq!(injected, kernel, "native membership altered a query: {row}");
        }
        let identity_prefix = format!(
            "reverie-dbt-test: kernel-identity sysnum={} ",
            libc::SYS_getpid
        );
        let identities: Vec<_> = stderr
            .lines()
            .filter_map(|line| line.strip_prefix(&identity_prefix))
            .collect();
        assert_eq!(identities.len(), 1, "missing own-PID witness: {output:?}");
        let guest_pid: i64 = identities[0]
            .split_whitespace()
            .find_map(|field| field.strip_prefix("kernel="))
            .unwrap()
            .parse()
            .unwrap();
        assert!(guest_pid > 0 && guest_pid != i64::from(pid));
        let mut guest_cases = priority_cases;
        guest_cases[1].1 = guest_pid;
        let priority_rows: Vec<_> = stderr
            .lines()
            .filter_map(|line| line.strip_prefix("reverie-dbt-test: kernel-priority-query "))
            .collect();
        assert_eq!(
            priority_rows.len(),
            8,
            "missing priority observations: {output:?}"
        );
        for (index, row) in priority_rows.iter().enumerate() {
            let fields: Vec<_> = row.split_whitespace().collect();
            assert_eq!(fields.len(), 5, "malformed priority observation: {row}");
            assert_eq!(fields[0], format!("sysnum={}", libc::SYS_getpriority));
            assert_eq!(fields[1], format!("which={}", guest_cases[index].0));
            assert_eq!(fields[2], format!("who={}", guest_cases[index].1));
            assert_eq!(fields[3], format!("kernel={}", priority_values[index]));
            assert_eq!(fields[4], format!("injected={}", priority_values[index]));
        }
    }
}
