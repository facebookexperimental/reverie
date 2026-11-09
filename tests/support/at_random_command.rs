/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

const SOURCE: &str = include_str!("../fixtures/at-random-command.c");

pub(super) struct GuestBinary {
    _directory: tempfile::TempDir,
    compiler: OsString,
    source: PathBuf,
    guest: PathBuf,
}

impl GuestBinary {
    pub(super) fn compile() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("at-random-command-guest-")
            .tempdir()
            .unwrap();
        let source = directory.path().join("guest.c");
        let guest = directory.path().join("guest");
        std::fs::write(&source, SOURCE.as_bytes()).unwrap();
        let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
        let mut command = Command::new(&compiler);
        command
            .args([
                "-std=c11",
                "-D_GNU_SOURCE",
                "-UNDEBUG",
                "-O0",
                "-g0",
                "-fno-pie",
                "-no-pie",
                "-Wl,--build-id=none",
                "-o",
            ])
            .arg(&guest)
            .arg(&source);
        eprintln!(
            "at-random compiler: program={compiler:?} argv={:?}",
            command.get_args().collect::<Vec<_>>(),
        );
        let output = command
            .output()
            .expect("compile at-random C fixture with CC or cc");
        eprintln!(
            "at-random compiler output: status={:?} stdout={:02x?} stderr={:02x?}",
            output.status, output.stdout, output.stderr,
        );
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

    pub(super) fn record_before_launch(&self, backend: &str) {
        let source = std::fs::read(&self.source).unwrap();
        assert_eq!(source, SOURCE.as_bytes());
        eprintln!(
            "at-random fixture/{backend}: compiler={:?} source={} guest={} source_bytes={:02x?} image={:02x?}",
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
            .expect("run native at-random fixture");
        eprintln!(
            "at-random command native: status={:?} stdout={:02x?} stderr={:02x?}",
            output.status, output.stdout, output.stderr,
        );
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout.len(), 16);
        assert!(output.stderr.is_empty());
    }
}
