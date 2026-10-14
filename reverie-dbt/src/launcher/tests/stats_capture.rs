/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::io::Cursor;

use super::*;
use crate::Counter2Global;
use crate::backend_stats::DbtProcessRecord;
use crate::backend_stats::DbtStatsCapture;
use crate::backend_stats::encode_process_record;

#[test]
fn stats_capture_distinguishes_missing_and_empty_and_cleans_its_directory() {
    let prefix = "hermit-dbt-verify-stats-";
    let unused = DbtStatsSink::with_prefix(prefix).unwrap();
    let directory = unused.directory().to_owned();
    assert_eq!(unused.path.parent(), Some(directory.as_path()));
    assert!(
        directory
            .file_name()
            .unwrap()
            .as_encoded_bytes()
            .starts_with(prefix.as_bytes())
    );
    assert!(directory.is_dir());
    let configured = unused.configure(runner().client_argument("existing-argument"));
    assert_eq!(
        configured.client_arguments,
        vec![
            OsString::from("existing-argument"),
            OsString::from("-stats_path"),
            unused.path.clone().into_os_string(),
        ]
    );
    drop(unused);
    assert!(!directory.exists());

    let missing = DbtStatsSink::new().unwrap();
    let directory = missing.path.parent().unwrap().to_owned();
    assert!(directory.is_dir());
    assert!(!missing.path.exists());
    let missing = missing.capture();
    assert!(matches!(&missing, DbtStatsCapture::Missing));
    assert_eq!(
        missing.records().unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(
        missing.snapshot().unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert!(!directory.exists());

    let empty = DbtStatsSink::new().unwrap();
    let directory = empty.path.parent().unwrap().to_owned();
    std::fs::write(&empty.path, []).unwrap();
    let empty = empty.capture();
    assert!(matches!(&empty, DbtStatsCapture::Records(bytes) if bytes.is_empty()));
    assert_eq!(empty.records().unwrap(), b"");
    assert_eq!(empty.snapshot().unwrap().process_images(), 0);
    assert!(!directory.exists());

    // The legacy optional instrumentation API still projects missing records
    // to an empty snapshot. Strict callers use capture's presence instead.
    let legacy = DbtStatsSink::new().unwrap();
    let directory = legacy.directory().to_owned();
    assert!(!legacy.path.exists());
    assert_eq!(legacy.drain().unwrap().snapshot().process_images(), 0);
    assert!(!directory.exists());
}

#[test]
fn stats_capture_retains_exact_record_order_after_decoding_and_cleanup() {
    let sink = DbtStatsSink::new().unwrap();
    let directory = sink.path.parent().unwrap().to_owned();
    let first = DbtProcessRecord {
        branches: 19,
        syscalls: 7,
        rewritten: 2,
        image_generation: 3,
        process_identity: 41,
        ..Default::default()
    };
    let second = DbtProcessRecord {
        branches: 11,
        syscalls: 3,
        rewritten: 1,
        image_generation: 1,
        process_identity: 17,
        ..Default::default()
    };
    let records = [
        encode_process_record(&first),
        encode_process_record(&second),
    ]
    .concat();
    std::fs::write(&sink.path, &records).unwrap();
    assert!(sink.path.is_file());

    let captured = sink.capture();
    assert!(!directory.exists());
    assert_eq!(captured.records().unwrap(), records);
    let snapshot = captured.snapshot().unwrap();
    assert_eq!(snapshot.process_images(), 2);
    assert_eq!(snapshot.counted_branches(), 30);
    assert_eq!(snapshot.intercepted_syscalls(), 10);
    assert_eq!(snapshot.rewritten_syscalls(), 3);
    // Commutative totals alone would not catch sorting or rewriting the saved
    // native stream. Decoding must leave its unequal records byte-for-byte.
    assert_eq!(captured.records().unwrap(), records);
}

#[test]
fn stats_capture_keeps_read_failure_distinct_from_malformed_records() {
    let unreadable = DbtStatsSink::new().unwrap();
    let directory = unreadable.path.parent().unwrap().to_owned();
    // A directory gives a real, deterministic read failure on Linux, without
    // relying on permissions that a privileged test process could bypass.
    std::fs::create_dir(&unreadable.path).unwrap();
    let unreadable = unreadable.capture();
    assert!(matches!(
        &unreadable,
        DbtStatsCapture::Unreadable { message, raw_os_error: Some(code) }
            if !message.is_empty() && *code == libc::EISDIR
    ));
    assert_eq!(
        unreadable.records().unwrap_err().raw_os_error(),
        Some(libc::EISDIR)
    );
    assert_eq!(
        unreadable.snapshot().unwrap_err().raw_os_error(),
        Some(libc::EISDIR)
    );
    assert!(!directory.exists());

    let malformed = DbtStatsSink::new().unwrap();
    let directory = malformed.path.parent().unwrap().to_owned();
    let records = b"a truncated native record";
    std::fs::write(&malformed.path, records).unwrap();
    let malformed = malformed.capture();
    assert!(matches!(&malformed, DbtStatsCapture::Records(_)));
    assert_eq!(malformed.records().unwrap(), records);
    assert!(malformed.snapshot().is_err());
    assert_eq!(malformed.records().unwrap(), records);
    assert!(!directory.exists());
}

// These fake-drrun tests execute the real physical launcher and coordinator
// ownership path, not native DR or an RPC client. Exit 7 is deliberate: it
// preserves the existing refusal of a successful guest that sent no RPC.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reader_capture_keeps_output_and_global_when_stats_are_malformed() {
    let directory = tempfile::tempdir().unwrap();
    let runner = DbtRunner::new(fake_drrun(directory.path()), fake_client()).unwrap();
    let sink = DbtStatsSink::new().unwrap();
    let stats_directory = sink.path.parent().unwrap().to_owned();
    let mut guest = Command::new("/bin/sh");
    guest
        .args([
            "-c",
            "/bin/cat; printf guest-diagnostic >&2; printf malformed > \"$1\"; exit 7",
            "stats-reader-test",
        ])
        .arg(&sink.path);
    let input = b"reader\0input\n".to_vec();
    let (output, global) = sink
        .configure(runner)
        .output_with_detached_reader_and_global::<Counter2Global, _>(
            &guest,
            Cursor::new(input.clone()),
            (),
        )
        .await
        .expect("malformed statistics must not discard physical completion");

    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, input);
    assert_eq!(output.stderr, b"guest-diagnostic");
    assert_eq!(global.snapshot(), (0, 0, 0));
    assert!(
        stats_directory.is_dir(),
        "the caller must still own the sink"
    );
    let capture = sink.capture();
    assert_eq!(capture.records().unwrap(), b"malformed");
    assert!(capture.snapshot().is_err());
    assert_eq!(capture.records().unwrap(), b"malformed");
    assert!(!stats_directory.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inherited_input_capture_keeps_output_and_global_when_stats_are_missing() {
    let directory = tempfile::tempdir().unwrap();
    let runner = DbtRunner::new(fake_drrun(directory.path()), fake_client()).unwrap();
    let sink = DbtStatsSink::new().unwrap();
    let stats_directory = sink.path.parent().unwrap().to_owned();
    let mut guest = Command::new("/bin/sh");
    // Do not read inherited stdin: the contract under test is completion and
    // capture ownership, independent of the harness's own input source.
    guest.args([
        "-c",
        "printf guest-output; printf guest-diagnostic >&2; exit 7",
    ]);
    let (output, global) = sink
        .configure(runner)
        .output_with_inherited_stdin_and_global::<Counter2Global>(&guest, ())
        .await
        .expect("missing statistics must not discard physical completion");

    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, b"guest-output");
    assert_eq!(output.stderr, b"guest-diagnostic");
    assert_eq!(global.snapshot(), (0, 0, 0));
    assert!(
        stats_directory.is_dir(),
        "the caller must still own the sink"
    );
    assert!(matches!(sink.capture(), DbtStatsCapture::Missing));
    assert!(!stats_directory.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_capture_keeps_read_failure_after_physical_completion() {
    let directory = tempfile::tempdir().unwrap();
    let runner = DbtRunner::new(fake_drrun(directory.path()), fake_client()).unwrap();
    let sink = DbtStatsSink::new().unwrap();
    let stats_directory = sink.path.parent().unwrap().to_owned();
    let mut guest = Command::new("/bin/sh");
    guest
        .args(["-c", "mkdir \"$1\"; exit 7", "stats-status-test"])
        .arg(&sink.path);
    let (status, global) = sink
        .configure(runner)
        .status_with_global::<Counter2Global>(&guest, ())
        .await
        .expect("a statistics read error must not discard status and global");
    assert_eq!(status.code(), Some(7));
    assert_eq!(global.snapshot(), (0, 0, 0));
    assert!(
        stats_directory.is_dir(),
        "the caller must still own the sink"
    );
    assert!(matches!(
        sink.capture(),
        DbtStatsCapture::Unreadable {
            raw_os_error: Some(libc::EISDIR),
            ..
        }
    ));
    assert!(!stats_directory.exists());
}
