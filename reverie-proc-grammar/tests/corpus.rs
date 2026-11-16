/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// The scanner rules govern the library, not these tests (which must
// read fixtures and /proc).
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

//! Corpus replay plus hand-written goldens.
//!
//! Every fixture under `tests/fixtures/<format>/` is produced by
//! this crate's renderer after anonymization of a live kernel
//! snapshot collected by `examples/collect-corpus.rs` (process names
//! are replaced before writing, so fixtures are renderer output,
//! not literal kernel bytes; the live-byte evidence is the kernel
//! oracle's render-equality inventory). The contract is
//! `render(parse(bytes)) == bytes` exactly. The goldens pin the edge
//! shapes a live snapshot cannot be relied on to contain (non-UTF-8
//! comms, the 53-vs-52 naive-split line, refusal shapes).

use std::fs;
use std::path::PathBuf;

use reverie_proc_grammar::*;

fn fixture_files(format: &str) -> Vec<Vec<u8>> {
    // Prefer the run-time CARGO_MANIFEST_DIR: the compile-time value is a
    // directory on the build host, missing on a test host the binary was
    // copied to (fbcode test runners rewrite the run-time value to the
    // staged resources path).
    let dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
        .join("tests/fixtures")
        .join(format);
    let mut files: Vec<Vec<u8>> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read fixture dir {dir:?}: {e} (run the collector)"))
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension()?.to_str()? == "bytes") // Raw kernel bytes; not .txt, whose lints would mangle tabs.
                .then(|| fs::read(&path).expect("read fixture"))
        })
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no {format} fixtures: run examples/collect-corpus.rs"
    );
    files
}

macro_rules! replay {
    ($name:ident, $format:literal, $parse:ident, $render:ident) => {
        #[test]
        fn $name() {
            for bytes in fixture_files($format) {
                let parsed = $parse(&bytes).unwrap_or_else(|e| {
                    panic!("fixture refused: {e}\n{}", String::from_utf8_lossy(&bytes))
                });
                assert_eq!(
                    $render(&parsed),
                    bytes,
                    "render(parse(bytes)) must reproduce kernel bytes"
                );
            }
        }
    };
}

replay!(replay_stat, "stat", parse_stat, render_stat);
replay!(replay_status, "status", parse_status, render_status);
replay!(replay_statm, "statm", parse_statm, render_statm);
replay!(replay_io, "io", parse_process_io, render_process_io);
replay!(replay_sched, "sched", parse_sched, render_sched);
replay!(replay_fdinfo, "fdinfo", parse_fdinfo, render_fdinfo);

#[test]
fn replay_comm() {
    for bytes in fixture_files("comm") {
        let name = parse_comm_file(&bytes).expect("comm fixture refused");
        assert_eq!(render_comm_file(&name), bytes);
    }
}

/// A stat line whose comm holds the bytes that break naive parsers:
/// a space (the live `tmux: client` shape, 53 fields under a naive
/// split), parens, a newline, and non-UTF-8 bytes.
fn stat_line(comm: &[u8]) -> Vec<u8> {
    let mut line = b"1234 (".to_vec();
    line.extend_from_slice(comm);
    line.extend_from_slice(
        b") S 1 1234 1234 0 -1 4194560 100 0 0 0 10 5 0 0 20 0 3 0 999 \
          1000000 200 18446744073709551615 4194304 4200000 0 0 0 0 0 0 0 0 0 0 \
          17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
    );
    line
}

#[test]
fn stat_comm_edge_cases_parse_and_round_trip() {
    for comm in [
        &b"tmux: client"[..],
        b"(sd-pam)",
        b"a)b (c",
        b"a\nb",
        b"\xff\xfe binary",
        b"trailing ",
        b"",
        b"123456789012345", // the 15-byte truncation limit
    ] {
        let line = stat_line(comm);
        let stat = parse_stat(&line).unwrap_or_else(|e| panic!("comm {comm:?} refused: {e}"));
        assert_eq!(stat.comm, comm);
        assert_eq!(stat.pid, 1234);
        assert_eq!(stat.state, b'S');
        assert_eq!(stat.starttime, 999, "field 22 must not shift");
        assert_eq!(stat.exit_code, 0);
        assert_eq!(render_stat(&stat), line);
    }
}

#[test]
fn stat_refuses_wrong_field_counts_and_bad_numbers() {
    let good = stat_line(b"a b");
    // 51 fields: drop the last token.
    let short = {
        let text = String::from_utf8(good.clone()).unwrap();
        let (head, _) = text.rsplit_once(' ').unwrap();
        format!("{head}\n").into_bytes()
    };
    assert!(matches!(
        parse_stat(&short),
        Err(ProcParseError::WrongFieldCount { expected: 52, .. })
    ));
    // 53 fields: append a token (a future kernel field is refused,
    // never silently republished).
    let long = {
        let mut v = good.clone();
        v.pop(); // newline
        v.extend_from_slice(b" 7\n");
        v
    };
    assert!(matches!(
        parse_stat(&long),
        Err(ProcParseError::WrongFieldCount { expected: 52, .. })
    ));
    // A non-number in starttime names the field.
    let bad = String::from_utf8(good)
        .unwrap()
        .replace(" 999 ", " noon ")
        .into_bytes();
    assert!(matches!(
        parse_stat(&bad),
        Err(ProcParseError::BadNumber {
            field: "starttime",
            ..
        })
    ));
    assert!(parse_stat(b"").is_err());
    assert!(parse_stat(b"no parens at all").is_err());
}

#[test]
fn comm_refuses_unprintable_shapes() {
    assert!(parse_comm_file(b"").is_err());
    assert!(parse_comm_file(b"no newline").is_err());
    assert!(parse_comm_file(b"has\0nul\n").is_err());
    // Kernel-thread full names exceed 15 bytes and must parse.
    assert_eq!(
        parse_comm_file(b"pool_workqueue_release\n").unwrap(),
        b"pool_workqueue_release"
    );
    // A newline inside the name is content; only the final one ends it.
    assert_eq!(parse_comm_file(b"a\nb\n").unwrap(), b"a\nb");
}

#[test]
fn status_preserves_unknown_labels_and_refuses_bad_masks() {
    // The default parser stays strict: an unknown label refuses.
    let unknown = b"Name:\tx\nPid:\t7\nNewKernelField:\t1\n";
    assert!(matches!(
        parse_status(unknown),
        Err(ProcParseError::UnknownLabel {
            format: Format::Status,
            ..
        })
    ));
    // The preserving opt-in keeps it verbatim, reported by
    // unknown_labels, and droppable by a guest-visible consumer —
    // never a reason to blank the whole file.
    let mut status = parse_status_preserving_unknown(unknown).unwrap();
    assert_eq!(
        status.unknown_labels().collect::<Vec<_>>(),
        [b"NewKernelField".as_slice()]
    );
    assert_eq!(render_status(&status), unknown);
    assert_eq!(status.drop_unknown(), [b"NewKernelField".to_vec()]);
    assert_eq!(render_status(&status), b"Name:\tx\nPid:\t7\n");

    let bad_mask = b"Name:\tx\nSigBlk:\tZZZZ\n";
    assert!(matches!(
        parse_status(bad_mask),
        Err(ProcParseError::BadNumber {
            field: "SigBlk",
            ..
        })
    ));
    // Uppercase hex is a spelling the kernel never prints.
    assert!(parse_status(b"Name:\tx\nSigBlk:\tFFFFFFFFFFFFFFFF\n").is_err());
    // Duplicated or out-of-order known labels are refused.
    assert!(parse_status(b"Pid:\t7\nPid:\t8\n").is_err());
    assert!(parse_status(b"Pid:\t7\nName:\tx\n").is_err());

    // Nested-namespace id lists are lists, not one decimal.
    let nested = b"Name:\tx\nNStgid:\t4240\t5\nNSpid:\t4242\t7\n";
    let status = parse_status(nested).unwrap();
    assert_eq!(
        status.get(StatusLabel::NSpid),
        Some(&StatusValue::PidList(vec![4242, 7]))
    );
    assert_eq!(render_status(&status), nested);
}

#[test]
fn parsers_refuse_truncated_and_noncanonical_reads() {
    // Exactly the reported failure: a final field cut short parsed
    // as a shorter number because the newline was optional.
    let mut truncated = stat_line(b"x");
    truncated.truncate(truncated.len() - 2); // last digits + newline
    assert!(parse_stat(&truncated).is_err());
    // Every format refuses a missing final newline.
    assert!(parse_statm(b"1 2 3 4 5 6 7").is_err());
    assert!(parse_process_io(
        b"rchar: 1\nwchar: 2\nsyscr: 3\nsyscw: 4\nread_bytes: 5\nwrite_bytes: 6\ncancelled_write_bytes: 7"
    )
    .is_err());
    assert!(parse_status(b"Name:\tx").is_err());
    assert!(parse_fdinfo(b"pos:\t0\nflags:\t02\nmnt_id:\t1\nino:\t2").is_err());
    // Non-canonical spellings the kernel never prints.
    assert!(parse_statm(b"01 2 3 4 5 6 7\n").is_err(), "leading zero");
    assert!(
        parse_status(b"Name:\tx\nVmRSS:\t0 kB\n").is_err(),
        "kB width"
    );
}

#[test]
fn status_x86_thread_features() {
    let input = b"Name:\tx\nvoluntary_ctxt_switches:\t1\nnonvoluntary_ctxt_switches:\t2\nx86_Thread_features:\tshstk wrss \nx86_Thread_features_locked:\tshstk \n";
    let status = parse_status(input).unwrap();
    assert_eq!(
        status.get(StatusLabel::X86ThreadFeatures),
        Some(&StatusValue::ThreadFeatures {
            shstk: true,
            wrss: true
        })
    );
    assert_eq!(
        status.get(StatusLabel::X86ThreadFeaturesLocked),
        Some(&StatusValue::ThreadFeatures {
            shstk: true,
            wrss: false
        })
    );
    assert_eq!(render_status(&status), input);
    // An empty feature set prints an empty value.
    assert!(parse_status(b"x86_Thread_features:\t\nx86_Thread_features_locked:\t\n").is_ok());
    assert!(parse_status(b"x86_Thread_features:\twrss shstk \n").is_err());
}

#[test]
fn io_and_statm_refuse_shape_changes() {
    assert!(matches!(
        parse_process_io(b"rchar: 1\nsurprise: 2\n"),
        Err(ProcParseError::WrongFieldCount {
            format: Format::ProcessIo,
            ..
        })
    ));
    assert!(parse_statm(b"1 2 3\n").is_err());
    assert!(parse_statm(b"1 2 3 4 5 6 7 8\n").is_err());
}

#[test]
fn fdinfo_eventfd_shapes_and_lock_canonicality() {
    let header = b"pos:\t0\nflags:\t02\nmnt_id:\t18\nino:\t1\n";
    // Pre-6.5 two-line eventfd form (fs/eventfd.c in v6.4).
    let mut old = header.to_vec();
    old.extend_from_slice(b"eventfd-count:                5\neventfd-id: 7\n");
    let parsed = parse_fdinfo(&old).unwrap();
    assert!(matches!(
        parsed.kind,
        FdinfoKind::Eventfd {
            count: 5,
            id: 7,
            semaphore: None
        }
    ));
    assert_eq!(render_fdinfo(&parsed), old);
    // Over-wide hex for a 32-bit field is refused, never truncated.
    let mut wide = header.to_vec();
    wide.extend_from_slice(
        b"tfd:        4 events: 1ffffffff data:                4  pos:0 ino:2f sdev:f\n",
    );
    assert!(parse_fdinfo(&wide).is_err(), "1ffffffff must not truncate");
    // Lock combinations the kernel never prints are refused, not
    // normalized (FLOCK is always ADVISORY:0 EOF in lock_get_status).
    let mut flock_mandatory = header.to_vec();
    flock_mandatory.extend_from_slice(b"lock:\t1: FLOCK  MANDATORY  WRITE 7 00:2f:99 0 EOF\n");
    assert!(parse_fdinfo(&flock_mandatory).is_err());
    let mut flock_range = header.to_vec();
    flock_range.extend_from_slice(b"lock:\t1: FLOCK  ADVISORY  WRITE 7 00:2f:99 10 20\n");
    assert!(parse_fdinfo(&flock_range).is_err());
    // A canonical mandatory POSIX range lock round-trips.
    let mut posix = header.to_vec();
    posix.extend_from_slice(b"lock:\t1: POSIX  MANDATORY WRITE 7 00:2f:99 10 20\n");
    let parsed = parse_fdinfo(&posix).unwrap();
    assert_eq!(parsed.locks[0].mode, LockMode::Mandatory);
    assert_eq!(render_fdinfo(&parsed), posix);
}

#[test]
fn fdinfo_refuses_unmodelled_kinds() {
    let header = b"pos:\t0\nflags:\t02\nmnt_id:\t18\nino:\t1\n";
    let mut epoll_unknown = header.to_vec();
    epoll_unknown.extend_from_slice(b"fanotify mark: 1\n");
    assert!(matches!(
        parse_fdinfo(&epoll_unknown),
        Err(ProcParseError::UnknownLabel {
            format: Format::Fdinfo,
            ..
        })
    ));
    // io_uring is deliberately unmodelled (see fdinfo module docs).
    let mut uring = header.to_vec();
    uring.extend_from_slice(b"SqMask:\t0xff\n");
    assert!(parse_fdinfo(&uring).is_err());
}

/// One canonical kernel sched field line (`%-45s:` + `%21Ld` or
/// `%14Ld.%06ld`).
fn sched_int(label: &str, value: i64) -> String {
    format!("{label:<45}:{value:>21}\n")
}

fn sched_fixed(label: &str, whole: i64, frac: u32) -> String {
    format!("{label:<45}:{whole:>14}.{frac:06}\n")
}

#[test]
fn sched_header_with_spaced_and_newline_comm() {
    let separator = "-".repeat(67);
    let bytes = format!(
        "my thread (4242, #threads: 2)\n{separator}\n{}{}",
        sched_fixed("se.exec_start", 1000, 1),
        sched_int("nr_switches", 7)
    )
    .into_bytes();
    let mut sched = parse_sched(&bytes).unwrap();
    assert_eq!(sched.comm, b"my thread");
    assert_eq!(sched.pid, 4242);
    assert_eq!(sched.get(b"nr_switches"), Some(SchedValue::Int(7)));
    assert_eq!(render_sched(&sched), bytes);
    // A rewritten value renders at the canonical width, not at the
    // width the host value occupied.
    assert!(sched.set(b"se.exec_start", SchedValue::Fixed6(0)));
    let expected = format!(
        "my thread (4242, #threads: 2)\n{separator}\n{}{}",
        sched_fixed("se.exec_start", 0, 0),
        sched_int("nr_switches", 7)
    )
    .into_bytes();
    assert_eq!(render_sched(&sched), expected);

    let bytes_nl = format!(
        "a\nb (99, #threads: 1)\n{separator}\n{}",
        sched_int("clock-delta", 36)
    )
    .into_bytes();
    let sched_nl = parse_sched(&bytes_nl).unwrap();
    assert_eq!(sched_nl.comm, b"a\nb");
    assert_eq!(render_sched(&sched_nl), bytes_nl);
    assert!(parse_sched(b"garbage\n").is_err());
    // The single-space test shorthand the old text surgery accepted
    // is not a kernel spelling.
    assert!(parse_sched(b"x (1, #threads: 1)\nse.exec_start : 1.000000\n").is_err());
    // A tab where the kernel prints a space parses token-wise but
    // renders back with a space: the render-equality gate refuses it.
    let mut tabbed = bytes.clone();
    let colon = tabbed
        .windows(2)
        .rposition(|w| w == b": ")
        .expect("field colon");
    tabbed[colon + 1] = b'\t';
    assert!(
        parse_sched(&tabbed).is_err(),
        "tab must not parse and re-render as space"
    );
}

#[test]
fn sched_fixed6_submillisecond_negative_round_trips_via_kernel_spelling() {
    // The kernel's SPLIT_NS split loses the sign below one
    // millisecond, so a setter-constructed sub-millisecond negative
    // must render in the kernel spelling and re-parse.
    assert_eq!(SchedValue::Fixed6(-500_000).render(), b"0.500000");
    let separator = "-".repeat(67);
    let bytes = format!(
        "x (1, #threads: 1)\n{separator}\n{}{}",
        sched_fixed("se.exec_start", 0, 500_000),
        sched_int("clock-delta", 36)
    )
    .into_bytes();
    let mut sched = parse_sched(&bytes).unwrap();
    assert!(sched.set(b"se.exec_start", SchedValue::Fixed6(-500_000)));
    let rendered = render_sched(&sched);
    assert!(
        String::from_utf8_lossy(&rendered).contains("0.500000"),
        "kernel spelling expected, got {:?}",
        String::from_utf8_lossy(&rendered)
    );
    let reparsed = parse_sched(&rendered).expect("rendered sched must re-parse");
    assert_eq!(render_sched(&reparsed), rendered);
    assert_eq!(SchedValue::Fixed6(-1_500_000).render(), b"-1.500000");
}

#[test]
fn bitmap_width_invariant_holds_for_constructed_values() {
    // A first group needing more digits than the declared width
    // is not a kernel spelling and cannot be constructed; with
    // public fields it rendered at the wider width and re-parsed
    // as a different value.
    assert_eq!(Bitmap::new(1, vec![0x1ff_u32]), None);
    assert_eq!(Bitmap::new(0, vec![1]), None);
    assert_eq!(Bitmap::new(9, vec![1]), None);
    assert_eq!(Bitmap::new(1, vec![]), None);
    let bitmap = Bitmap::new(3, vec![0x1ff_u32]).expect("0x1ff fits three digits");
    assert_eq!(bitmap.first_digits(), 3);
    assert_eq!(bitmap.groups(), [0x1ff_u32].as_slice());
    let mut status = fixture_files("status")
        .into_iter()
        .find_map(|bytes| {
            parse_status_preserving_unknown(&bytes)
                .ok()
                .filter(|status| status.get(StatusLabel::CpusAllowed).is_some())
        })
        .expect("status fixture with CpusAllowed");
    assert!(status.set(StatusLabel::CpusAllowed, StatusValue::Bitmap(bitmap)));
    let rendered = render_status(&status);
    let reparsed = parse_status(&rendered).expect("rendered status must re-parse");
    let expected = match reparsed.get(StatusLabel::CpusAllowed) {
        Some(StatusValue::Bitmap(bitmap)) => bitmap.clone(),
        other => panic!("bitmap lost: {other:?}"),
    };
    let original = match status.get(StatusLabel::CpusAllowed) {
        Some(StatusValue::Bitmap(bitmap)) => bitmap.clone(),
        other => panic!("bitmap missing: {other:?}"),
    };
    assert_eq!(render_status(&reparsed), rendered);
    assert_eq!(
        expected, original,
        "constructed Bitmap changed across render/parse"
    );
}
