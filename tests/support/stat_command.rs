/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

pub(super) enum Operation {
    Stat,
    Statx,
}

pub(super) struct GuestBinary {
    _directory: tempfile::TempDir,
    name: &'static str,
    source_text: &'static str,
    compiler: OsString,
    source: PathBuf,
    guest: PathBuf,
}

impl GuestBinary {
    pub(super) fn compile(operation: Operation) -> Self {
        let (name, source_text) = match operation {
            Operation::Stat => ("stat", include_str!("../fixtures/stat-command.c")),
            Operation::Statx => ("statx", include_str!("../fixtures/statx-command.c")),
        };
        let directory = tempfile::Builder::new()
            .prefix("stat-command-guest-")
            .tempdir()
            .unwrap();
        let source = directory.path().join("guest.c");
        let guest = directory.path().join("guest");
        std::fs::write(&source, source_text.as_bytes()).unwrap();
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
            "stat compiler {name}: program={compiler:?} argv={:?}",
            command.get_args().collect::<Vec<_>>(),
        );
        let output = command
            .output()
            .expect("compile stat C fixture with CC or cc");
        assert!(output.status.success(), "guest compiler failed: {output:?}");
        Self {
            _directory: directory,
            name,
            source_text,
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
        assert_eq!(source, self.source_text.as_bytes());
        eprintln!(
            "stat fixture {}/{backend}: compiler={:?} source={} guest={} source_bytes={:02x?} image={:02x?}",
            self.name,
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
            .expect("run native stat fixture");
        eprintln!(
            "stat command {}/native: status={:?} stdout={:02x?} stderr={:02x?}",
            self.name, output.status, output.stdout, output.stderr,
        );
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}
