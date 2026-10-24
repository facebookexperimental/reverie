/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(all(
    feature = "exec-private-init",
    target_arch = "x86_64",
    target_os = "linux"
))]

//! Actual exec + real kernel TSC/capture/restore component evidence. The C
//! fixture uses direct raw syscalls, not an authenticated fixed-page/filter
//! context. Its selected C-boundary mode is manual: production Rust selection
//! and its initial/successor ownership checks have separate unit coverage.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[path = "../../reverie-rpc-transport/tests/fixtures/owned_lifecycle.rs"]
mod owned_lifecycle;

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
impl Fixture {
    fn build() -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "reverie-native-kernel-tsc-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let fixture = Self(directory);
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut command = Command::new("cc");
        command.args([
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-stack-protector",
            "-fno-builtin",
            "-fno-pie",
            "-ffunction-sections",
            "-fdata-sections",
            "-nostdlib",
            "-static",
            "-no-pie",
            "-Wl,--gc-sections",
            "-Wl,-e,_start",
            "-I",
        ]);
        command.arg(manifest.join("native_exec"));
        command.arg(manifest.join("tests/fixtures/native_kernel_tsc.S"));
        command.arg(manifest.join("tests/fixtures/native_kernel_tsc.c"));
        command.arg(manifest.join("native_exec/private-kernel-state.c"));
        command.arg("-o").arg(fixture.0.join("fixture"));
        println!("actual fixture compile: {command:?}");
        let (output, _) = owned_lifecycle::run(command, Duration::from_secs(30)).unwrap();
        assert!(output.status.success(), "fixture compile: {output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        fixture
    }

    fn run(&self, inherited: u64, selected: u64, installed: u64, denial: u64) -> Observation {
        let mut command = Command::new(self.0.join("fixture"));
        command.env_clear().arg("parent");
        for value in [inherited, selected, installed, denial] {
            command.arg(value.to_string());
        }
        // SAFETY: child-local scalar resource setting, no allocation or shared
        // parent state. Fatal-opcode controls must not generate core artifacts.
        unsafe {
            command.pre_exec(|| {
                let core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &core) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let (output, _) = owned_lifecycle::run(command, Duration::from_secs(10)).unwrap();
        assert_eq!(output.stdout.len() % 72, 0, "partial witness: {output:?}");
        let records = output
            .stdout
            .as_chunks::<72>()
            .0
            .iter()
            .map(|record| {
                let words: Vec<u64> = record
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .map(|word| u64::from_le_bytes(*word))
                    .collect();
                assert_eq!(words[0], 0x3153_4354_5445_5354);
                assert_eq!(words[2], inherited);
                Witness {
                    stage: words[1] as u8,
                    observed: words[3],
                    query_rc: words[4] as i64,
                    captured: words[5],
                    selected: words[6],
                    native_state: words[7],
                    tid: words[8],
                }
            })
            .collect::<Vec<_>>();
        println!(
            "inherited={inherited} selected={selected} installed={installed} denial={denial}; status={:?}; witnesses={records:?}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(records.len() >= 2, "no real-exec witnesses: {output:?}");
        for record in &records[..2] {
            assert_eq!(record.query_rc, 0);
            assert_eq!(record.observed, inherited);
            assert_eq!(record.native_state, 0);
            assert_eq!(record.tid, 0);
        }
        assert_eq!(records[0].stage, b'P');
        assert_eq!(records[1].stage, b'E');
        Observation {
            status: output.status,
            records,
            stderr: output.stderr,
        }
    }
}
#[derive(Debug)]
struct Witness {
    stage: u8,
    observed: u64,
    query_rc: i64,
    captured: u64,
    selected: u64,
    native_state: u64,
    tid: u64,
}
struct Observation {
    status: std::process::ExitStatus,
    records: Vec<Witness>,
    stderr: Vec<u8>,
}
impl Observation {
    fn stages(&self) -> Vec<u8> {
        self.records.iter().map(|record| record.stage).collect()
    }
    fn capture(&self, inherited: u64) {
        let record = &self.records[2];
        assert_eq!(record.stage, b'C');
        assert_eq!(record.query_rc, 0);
        assert_eq!(record.observed, 1);
        assert_eq!(record.captured, inherited);
        assert_eq!(record.selected, 0);
        assert_eq!(record.native_state, 1);
        assert_ne!(record.tid, 0);
        assert!(
            self.records[2..]
                .iter()
                .all(|later| later.tid == record.tid)
        );
    }
}

#[test]
fn native_capture_normalizes_real_inherited_tsc_before_private_rdtsc() {
    let fixture = Fixture::build();
    for inherited in [1, 2] {
        let actual = fixture.run(inherited, 0, 0, 0);
        assert_eq!(actual.status.code(), Some(0));
        assert_eq!(actual.stages(), b"PECL");
        actual.capture(inherited);
        assert!(actual.stderr.is_empty());
        assert_eq!(actual.records[3].observed, 1);
        assert_eq!(actual.records[3].query_rc, 0);
    }
}

#[test]
fn native_kernel_restore_applies_manually_selected_tsc_boundary() {
    let fixture = Fixture::build();
    // Explicit C-boundary cases, not a duplicated subscription selector.
    // Last two differ in whether the common installer's real setter effect
    // has occurred. Rust owner tests cover actual subscription selection.
    for (inherited, selected, installed) in [(1, 1, 0), (1, 2, 2), (2, 2, 0), (2, 2, 2)] {
        let actual = fixture.run(inherited, selected, installed, 0);
        actual.capture(inherited);
        assert!(actual.stderr.is_empty());
        assert_eq!(actual.records[4].stage, b'I');
        assert_eq!(
            actual.records[4].observed,
            if installed == 0 { 1 } else { 2 }
        );
        assert_eq!(actual.records[4].query_rc, 0);
        let restored = &actual.records[5];
        assert_eq!(restored.stage, b'F');
        assert_eq!(restored.query_rc, 0);
        assert_eq!(restored.observed, selected);
        assert_eq!(restored.captured, inherited);
        assert_eq!(restored.selected, selected);
        assert_eq!(restored.native_state, 3);
        if selected == 1 {
            assert_eq!(actual.status.code(), Some(0));
            assert_eq!(actual.stages(), b"PECLIFR");
        } else {
            assert_eq!(actual.status.signal(), Some(libc::SIGSEGV));
            assert_eq!(actual.stages(), b"PECLIF");
        }
    }
}

#[test]
fn native_capture_refuses_real_tsc_get_and_set_denial() {
    let fixture = Fixture::build();
    for denial in [1, 2] {
        let actual = fixture.run(2, 0, 0, denial);
        assert_eq!(actual.status.code(), Some(0));
        assert_eq!(actual.stages(), b"PED");
        let refused = &actual.records[2];
        assert_eq!(refused.native_state, 0);
        assert_eq!(refused.selected, 0);
        if denial == 1 {
            assert_eq!(refused.query_rc, -i64::from(libc::EPERM));
        } else {
            assert_eq!(refused.query_rc, 0);
            assert_eq!(refused.observed, 2);
        }
        assert!(String::from_utf8_lossy(&actual.stderr).contains("exec-private capture refused"));
    }
}

#[test]
fn native_restore_refuses_real_tsc_get_and_set_denial() {
    let fixture = Fixture::build();
    for denial in [3, 4] {
        let actual = fixture.run(2, 2, 2, denial);
        actual.capture(2);
        assert_eq!(actual.status.code(), Some(0));
        assert_eq!(actual.stages(), b"PECLID");
        let refused = &actual.records[5];
        assert_eq!(refused.native_state, 1);
        assert_eq!(refused.selected, 2);
        if denial == 3 {
            assert_eq!(refused.query_rc, -i64::from(libc::EPERM));
        } else {
            assert_eq!(refused.query_rc, 0);
            assert_eq!(refused.observed, 2);
        }
        assert!(actual.stderr.is_empty());
    }
}

#[test]
fn native_restore_refuses_unset_and_unknown_tsc_modes() {
    let fixture = Fixture::build();
    // Deliberate control mutations AFTER genuine exec/capture; these do not
    // claim that a real PR_GET_TSC returned an unknown mode.
    for mutation in [5, 6, 7, 8] {
        let actual = fixture.run(2, 1, 0, mutation);
        actual.capture(2);
        assert_eq!(actual.status.code(), Some(0));
        assert_eq!(actual.stages(), b"PECLID");
        let refused = &actual.records[5];
        assert_eq!(refused.native_state, 1);
        assert_eq!(refused.query_rc, 0);
        assert_eq!(refused.observed, 1);
        assert_eq!(
            refused.captured,
            match mutation {
                5 => 0,
                6 => 3,
                _ => 2,
            }
        );
        assert_eq!(
            refused.selected,
            match mutation {
                7 => 0,
                8 => 3,
                _ => 1,
            }
        );
        assert!(actual.stderr.is_empty());
    }
}
