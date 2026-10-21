/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Compare fcntl and socket-ioctl asynchronous-I/O owners with Linux and require
//! that each owner the guest names by its own ID is the task Linux signals.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use reverie_dbt::DbtRunner;

/// How the launcher places the program in a process group.
#[derive(Clone, Copy)]
enum Group {
    /// The program leads its own session and group, so the guest sees its own
    /// group under its own virtual ID.
    Leads,
    /// A shell leads the session and runs the program as a member, so the
    /// group is led from outside the guest and the guest sees its raw host ID.
    /// The shell ignores SIGUSR1, so group-directed signals reach only it and
    /// the program.
    Inherited,
}

#[test]
#[ignore = "requires a built DynamoRIO native client and python3; run explicitly with --ignored"]
fn fcntl_owners_name_the_guest_task_and_keep_kernel_validation_order() {
    compare_with_linux(Group::Leads);
}

#[test]
#[ignore = "requires a built DynamoRIO native client and python3; run explicitly with --ignored"]
fn fcntl_owners_reach_a_process_group_led_from_outside_the_guest() {
    compare_with_linux(Group::Inherited);
}

fn compare_with_linux(group: Group) {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = directory.path().join("fcntl-owner-identity");
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fcntl_owner_identity.c");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let status = Command::new(compiler)
        .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .arg("-o")
        .arg(&fixture)
        .status()
        .expect("compile fcntl owner identity fixture");
    assert!(status.success(), "fixture compilation failed");

    // The supervisor stays outside the program's session and, when the program
    // exits or hangs, kills every remaining member of that session. The fixture
    // creates process groups of its own inside the session, so killing only
    // the launched group could leave a member holding the output pipes open.
    let launcher = directory.path().join("bounded-launcher");
    std::fs::write(
        &launcher,
        r#"#!/usr/bin/env python3
import os, signal, subprocess, sys
command = [os.environ["REVERIE_DBT_TEST_PROGRAM"], *sys.argv[1:]]
if os.environ.get("REVERIE_DBT_TEST_GROUP") == "inherited":
    command = ["/bin/sh", "-c", 'trap "" USR1; "$@"; exit $?', "sh", *command]
child = subprocess.Popen(command, start_new_session=True)

def kill_session(session, sig):
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat", "rb") as stream:
                data = stream.read()
        except OSError:
            continue
        fields = data[data.rfind(b")") + 2:].split()
        if len(fields) > 3 and int(fields[3]) == session:
            try:
                os.kill(int(name), sig)
            except (ProcessLookupError, PermissionError):
                pass

try:
    try:
        result = child.wait(timeout=15)
    except subprocess.TimeoutExpired:
        kill_session(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        result = 124
finally:
    kill_session(child.pid, signal.SIGKILL)
    child.wait()
sys.exit(result)
"#,
    )
    .expect("write bounded launcher");
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))
        .expect("make bounded launcher executable");
    let group_mode = match group {
        Group::Leads => "leads",
        Group::Inherited => "inherited",
    };

    let native = Command::new(&launcher)
        .env("REVERIE_DBT_TEST_PROGRAM", &fixture)
        .env("REVERIE_DBT_TEST_GROUP", group_mode)
        .output()
        .expect("run Linux oracle");
    assert!(native.status.success(), "native fixture failed: {native:?}");
    let native_stdout = String::from_utf8_lossy(&native.stdout);
    // The oracle itself must show every owner receiving its signal; otherwise
    // the comparison below would accept a DBT run that delivers nothing.
    let group_is_self = match group {
        Group::Leads => "group-is-self=1\n",
        Group::Inherited => "group-is-self=0\n",
    };
    for line in [
        group_is_self,
        "setown-self delivered=1\n",
        "setown-ex-tid delivered=1\n",
        "setown-ex-pid delivered=1\n",
        "getown-is-group=1\n",
        "getown-raw-is-group=1\n",
        "setown-group delivered=1\n",
        "setown-ex-pgrp delivered=1\n",
        "setown-raw rc=0 registers-preserved=1\n",
        "setown-ex-raw rc=0 registers-preserved=1\n",
        "fiosetown-raw rc=0 registers-preserved=1\n",
        "fiosetown-self delivered=1\n",
        "siocspgrp-group delivered=1\n",
        "fiosetown-unknown rc=-1 errno-is-esrch=1\n",
        "setown-nonleader-group rc=0 getown-raw-is-zero=1\n",
        "setown-child parent-received=0\n",
        "setown-child child-received=1\n",
        "setown-exited-leader-group rc=0\n",
        "setown-exited-leader-group parent-received=0\n",
        "setown-exited-leader-group member-received=1\n",
        "setown-unknown rc=-1 errno-is-esrch=1\n",
        "setown-badfd rc=-1 errno-is-ebadf=1\n",
    ] {
        assert!(
            native_stdout.contains(line),
            "Linux oracle lacks {line:?}:\n{native_stdout}"
        );
    }
    assert_eq!(native.stdout.split(|byte| *byte == b'\n').count(), 48);
    assert!(native.stdout.ends_with(b"fcntl-owner-identity=ok\n"));

    let client = std::env::var_os("REVERIE_DBT_CLIENT")
        .expect("REVERIE_DBT_CLIENT must point to the built native client");
    let mut guest = Command::new(&fixture);
    guest
        .env("HERMIT_DBT_NOOP", "1")
        .env(
            "REVERIE_DBT_TEST_PROGRAM",
            reverie_dbt::bundled_drrun_path(),
        )
        .env("REVERIE_DBT_TEST_GROUP", group_mode);
    let output = DbtRunner::new(launcher, client)
        .expect("create bounded native runner")
        .client_argument("-test-wait-for-background")
        .output(&guest)
        .expect("run DBT fcntl owner fixture");
    assert!(output.status.success(), "DBT fixture failed: {output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        native_stdout,
        "DBT must match the Linux oracle"
    );
}
