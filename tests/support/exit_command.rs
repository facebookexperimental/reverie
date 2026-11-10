/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

const SOURCE: &str = include_str!("../fixtures/exit-command.S");

pub(super) struct GuestBinary {
    _directory: tempfile::TempDir,
    compiler: OsString,
    source: PathBuf,
    guest: PathBuf,
}

impl GuestBinary {
    pub(super) fn compile() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("inject-exit-guest-")
            .tempdir()
            .unwrap();
        let source = directory.path().join("guest.S");
        let guest = directory.path().join("guest");
        std::fs::write(&source, SOURCE.as_bytes()).unwrap();
        let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
        let output = Command::new(&compiler)
            .args([
                "-nostdlib",
                "-static",
                "-no-pie",
                "-Wl,-e,_start",
                "-Wl,--build-id=none",
                "-o",
            ])
            .arg(&guest)
            .arg(&source)
            .output()
            .expect("compile injected-exit assembly with CC or cc");
        assert!(output.status.success(), "guest compiler failed: {output:?}");
        Self {
            _directory: directory,
            compiler,
            source,
            guest,
        }
    }

    pub(super) fn program(&self) -> &str {
        self.guest.to_str().expect("guest path must be UTF-8")
    }

    pub(super) fn record_before_launch(&self, label: &str) {
        let source = std::fs::read(&self.source).unwrap();
        assert_eq!(source, SOURCE.as_bytes());
        eprintln!(
            "exit fixture {label}: compiler={:?} source={} guest={} source_bytes={:02x?} image={:02x?}",
            self.compiler,
            self.source.display(),
            self.guest.display(),
            source,
            std::fs::read(&self.guest).unwrap(),
        );
    }

    pub(super) fn assert_native(&self) {
        self.record_before_launch("native");
        let output = Command::new(&self.guest)
            .output()
            .expect("run native getpid/exit_group guest");
        eprintln!(
            "injected exit native: status={:?} stdout={:02x?} stderr={:02x?}",
            output.status, output.stdout, output.stderr,
        );
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}
