/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Witnesses for the grouped-admission protocol model (see the
//! `reverie-liteinst-grouped-admission-spike` binary). Each mode runs as
//! its own process because the refusal modes exit from the fault handler.

use std::process::Command;
use std::process::Output;

fn run(mode: &str) -> Output {
    Command::new(env!(
        "CARGO_BIN_EXE_reverie-liteinst-grouped-admission-spike"
    ))
    .arg(mode)
    .output()
    .expect("run grouped admission spike")
}

#[test]
fn one_fault_admits_the_whole_group() {
    let out = run("admit");
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ADMIT-OK faults=1 admissions=1"),
        "{stdout}"
    );
}

#[test]
fn uncertified_interior_entry_refuses() {
    let out = run("interior");
    assert_eq!(out.status.code(), Some(4), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("R-CODE interior-entry"),
        "{out:?}"
    );
}

#[test]
fn stale_certificate_refuses_after_revocation() {
    let out = run("revoke");
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("R-CODE stale-generation"),
        "{out:?}"
    );
}

#[test]
fn fresh_certificate_readmits_the_new_generation() {
    let out = run("readmit");
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("READMIT-OK") && stdout.contains("admissions=2"),
        "{stdout}"
    );
}

#[test]
fn racing_first_faults_admit_exactly_once() {
    let out = run("concurrent");
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("CONCURRENT-OK") && stdout.contains("admissions=1"),
        "{stdout}"
    );
}
