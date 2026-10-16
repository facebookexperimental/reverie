/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Read-only group/session queries can name live tasks outside the DBT client.

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
    // Its separate group and session make target-to-self substitutions observable.
    let mut holder = Command::new("/bin/cat");
    holder
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid is async-signal-safe; the child calls no Rust code that
    // allocates or acquires locks between fork and exec.
    unsafe {
        holder.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = HeldChild(holder.spawn().expect("hold ordinary unregistered child"));
    let pid = child.0.id() as libc::pid_t;
    // SAFETY: these read-only queries name our live child.
    let pgid = unsafe { libc::getpgid(pid) };
    let sid = unsafe { libc::getsid(pid) };
    assert_eq!(pgid, pid, "held child must lead its own group");
    assert_eq!(sid, pid, "held child must lead its own session");
    let arguments = [pid.to_string(), pgid.to_string(), sid.to_string()];
    let expected = format!(
        "getpgid live={pgid} errno=0\ngetpgid zero-is-self=1\n\
         getpgid negative rc=-1 errno={}\ngetpgid absent rc=-1 errno={}\n\
         getsid live={sid} errno=0\ngetsid zero-is-self=1\n\
         getsid negative rc=-1 errno={}\ngetsid absent rc=-1 errno={}\n\
         group-session-getters=ok\n",
        libc::ESRCH,
        libc::ESRCH,
        libc::ESRCH,
        libc::ESRCH,
    );
    let native = Command::new(&fixture)
        .arg("original")
        .args(&arguments)
        .output()
        .expect("run Linux oracle");
    assert!(native.status.success(), "native oracle failed: {native:?}");
    assert_eq!(native.stdout, expected.as_bytes());

    let runner = DbtRunner::from_env()
        .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must be set")
        .client_argument("-test-wait-for-background");
    let mut guest = Command::new(&fixture);
    guest
        .arg(mode)
        .args(&arguments)
        .env_remove("HERMIT_DBT_NOOP")
        .env_remove("HERMIT_DBT_TEST_SET_REG");
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
        assert_eq!(rows.len(), 10, "missing returning observations: {output:?}");
        for row in rows {
            let fields: Vec<_> = row.split_whitespace().collect();
            assert_eq!(fields.len(), 4, "malformed kernel observation: {row}");
            let kernel = fields[2].strip_prefix("kernel=").unwrap();
            let injected = fields[3].strip_prefix("injected=").unwrap();
            assert_eq!(injected, kernel, "native membership altered a query: {row}");
        }
    }
}
