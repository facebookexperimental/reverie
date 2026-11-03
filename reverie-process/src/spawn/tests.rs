/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::fs;
use std::fs::File;
use std::io::Seek;
use std::io::Write;
use std::os::unix::fs::MetadataExt;

use crate::Command;
use crate::ExitStatus;
use crate::Stdio;

const STDOUT_PREFIX: &[u8] = b"initial stdout\n";
const STDERR_PREFIX: &[u8] = b"initial stderr\n";
const STDOUT_BYTES: &[u8] = b"stdout:\0\xff\n";
const STDERR_BYTES: &[u8] = b"stderr:\0\xfe\n";
// POSIX shell builtin printf writes distinct binary payloads to both real
// descriptors. The first failure stops the script; the second is its status.
const SCRIPT: &str = "printf 'stdout:\\000\\377\\n' && printf 'stderr:\\000\\376\\n' >&2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    File,
    Pipe,
    Null,
}

impl Mode {
    fn configure(self, file: &File) -> Stdio {
        match self {
            Self::File => file.try_clone().unwrap().into(),
            Self::Pipe => Stdio::piped(),
            Self::Null => Stdio::null(),
        }
    }

    fn file_contents(self, prefix: &[u8], bytes: &[u8]) -> Vec<u8> {
        let mut expected = prefix.to_vec();
        if self == Self::File {
            expected.extend_from_slice(bytes);
        }
        expected
    }

    fn captured(self, bytes: &[u8]) -> Vec<u8> {
        if self == Self::Pipe {
            bytes.to_vec()
        } else {
            Vec::new()
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Entry {
    Spawn,
    SpawnWith,
}

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    status: ExitStatus,
    stdout_pipe: bool,
    stderr_pipe: bool,
    captured_stdout: Vec<u8>,
    captured_stderr: Vec<u8>,
    stdout_file: Vec<u8>,
    stderr_file: Vec<u8>,
    stdout_offset: u64,
    stderr_offset: u64,
}

async fn check_routes(stdout: Mode, stderr: Mode, entry: Entry) {
    let directory = tempfile::tempdir().unwrap();
    let stdout_path = directory.path().join("stdout");
    let stderr_path = directory.path().join("stderr");
    let mut stdout_file = File::create(&stdout_path).unwrap();
    let mut stderr_file = File::create(&stderr_path).unwrap();
    stdout_file.write_all(STDOUT_PREFIX).unwrap();
    stderr_file.write_all(STDERR_PREFIX).unwrap();
    let out_meta = stdout_file.metadata().unwrap();
    let err_meta = stderr_file.metadata().unwrap();
    assert_ne!((out_meta.dev(), out_meta.ino()), (err_meta.dev(), err_meta.ino()));

    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", SCRIPT])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(stdout.configure(&stdout_file))
        .stderr(stderr.configure(&stderr_file));
    // Command::output() would overwrite both requested modes with Pipe and
    // hide this defect. Use the actual public spawn paths instead.
    let child = match entry {
        Entry::Spawn => command.spawn(),
        // A setup/exec failure has a distinct nonzero status. This closure
        // executes in the child and does not allocate or inspect shared state.
        Entry::SpawnWith => command.spawn_with(|_| 93),
    }
    .expect("spawn the controlled stdio command");
    let stdout_pipe = child.stdout.is_some();
    let stderr_pipe = child.stderr.is_some();
    // Reap and drain before asserting the route, including on the buggy
    // baseline. A failed assertion must not abandon a live child or pipe.
    let output = child.wait_with_output().await.unwrap();
    drop(command);
    let actual = Observation {
        status: output.status,
        stdout_pipe,
        stderr_pipe,
        captured_stdout: output.stdout,
        captured_stderr: output.stderr,
        stdout_file: fs::read(&stdout_path).unwrap(),
        stderr_file: fs::read(&stderr_path).unwrap(),
        stdout_offset: stdout_file.stream_position().unwrap(),
        stderr_offset: stderr_file.stream_position().unwrap(),
    };
    let expected_stdout = stdout.file_contents(STDOUT_PREFIX, STDOUT_BYTES);
    let expected_stderr = stderr.file_contents(STDERR_PREFIX, STDERR_BYTES);
    let expected = Observation {
        status: ExitStatus::Exited(0),
        stdout_pipe: stdout == Mode::Pipe,
        stderr_pipe: stderr == Mode::Pipe,
        captured_stdout: stdout.captured(STDOUT_BYTES),
        captured_stderr: stderr.captured(STDERR_BYTES),
        stdout_offset: expected_stdout.len() as u64,
        stderr_offset: expected_stderr.len() as u64,
        stdout_file: expected_stdout,
        stderr_file: expected_stderr,
    };
    assert_eq!(actual, expected, "entry={entry:?}, stdout={stdout:?}, stderr={stderr:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn spawn_routes_distinct_files() {
    if crate::test_runs_in_own_process() {
        return;
    }
    check_routes(Mode::File, Mode::File, Entry::Spawn).await;
}

#[tokio::test(flavor = "current_thread")]
async fn spawn_routes_file_stdout_and_piped_stderr() {
    if crate::test_runs_in_own_process() {
        return;
    }
    check_routes(Mode::File, Mode::Pipe, Entry::Spawn).await;
}

#[tokio::test(flavor = "current_thread")]
async fn spawn_routes_piped_stdout_and_file_stderr() {
    if crate::test_runs_in_own_process() {
        return;
    }
    check_routes(Mode::Pipe, Mode::File, Entry::Spawn).await;
}

#[tokio::test(flavor = "current_thread")]
async fn spawn_routes_null_stdout_and_piped_stderr() {
    if crate::test_runs_in_own_process() {
        return;
    }
    check_routes(Mode::Null, Mode::Pipe, Entry::Spawn).await;
}

#[tokio::test(flavor = "current_thread")]
async fn spawn_routes_piped_stdout_and_null_stderr() {
    if crate::test_runs_in_own_process() {
        return;
    }
    check_routes(Mode::Pipe, Mode::Null, Entry::Spawn).await;
}

#[tokio::test(flavor = "current_thread")]
async fn spawn_routes_null_stdout_and_file_stderr() {
    if crate::test_runs_in_own_process() {
        return;
    }
    check_routes(Mode::Null, Mode::File, Entry::Spawn).await;
}

#[tokio::test(flavor = "current_thread")]
async fn spawn_routes_file_stdout_and_null_stderr() {
    if crate::test_runs_in_own_process() {
        return;
    }
    check_routes(Mode::File, Mode::Null, Entry::Spawn).await;
}

// This qualifying control passes before and after the one-line fix: two
// separate pipes already work, so it cannot replace the asymmetric cases.
#[tokio::test(flavor = "current_thread")]
async fn spawn_routes_two_pipes() {
    if crate::test_runs_in_own_process() {
        return;
    }
    check_routes(Mode::Pipe, Mode::Pipe, Entry::Spawn).await;
}

#[tokio::test(flavor = "current_thread")]
async fn spawn_with_routes_distinct_files() {
    if crate::test_runs_in_own_process() {
        return;
    }
    check_routes(Mode::File, Mode::File, Entry::SpawnWith).await;
}
