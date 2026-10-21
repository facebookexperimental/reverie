/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A tool that answers the guest's `brk(2)` itself
//! ([`DbtRunner::tool_answers_brk`]) finds the guest's start of the break as
//! the kernel leaves it: no page mapped after the guest image, and the
//! kernel's break where the kernel put it.
//!
//! Without the option, DynamoRIO's early injection reserves for the break.
//! It maps an inaccessible page after the guest image (its separate-.bss
//! page), maps a region of its own to emulate `brk` in, and with emulation
//! off nudges the kernel's break by a byte. A tool that keeps its own model
//! of the break, starting after the image as Linux's does, would find that
//! page in the way.
//!
//! [`tests/fixtures/tool_answers_brk.c`] reports, before anything has
//! allocated, whether the page after its image is mapped, whether `brk(0)`
//! is the kernel's start_brk, and whether the break lies in a mapping. With
//! the option, its output under DynamoRIO equals its native output. Without
//! it, the page is mapped, which is the control.
//!
//! The fixture's procfs parsers must refuse what they cannot read whole, or
//! a cut-short record would read as an observation. The negative controls
//! below feed them malformed records through standard input and need only a
//! C compiler, so they run by default.
//!
//! The live test is `#[ignore]`d like the other live tests; run it with:
//!
//! ```text
//! REVERIE_DBT_CLIENT=<...>/libreverie_dbt_client.so \
//!   cargo test -p reverie-dbt --test tool_answers_brk_live -- --ignored --nocapture
//! ```

use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;

use reverie_dbt::DbtRunner;

fn compile_fixture(directory: &Path) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tool_answers_brk.c");
    let binary = directory.join("tool_answers_brk");
    let compile = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
        .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap_or_else(|error| panic!("failed to start the C compiler: {error}"));
    assert!(
        compile.status.success(),
        "failed to compile {}: {}",
        source.display(),
        String::from_utf8_lossy(&compile.stderr)
    );
    binary
}

fn under_dynamorio(fixture: &Path, tool_answers_brk: bool) -> Output {
    let client = std::env::var_os("REVERIE_DBT_CLIENT")
        .expect("REVERIE_DBT_CLIENT must point to the built native client");
    DbtRunner::new(reverie_dbt::bundled_drrun_path(), client)
        .expect("create the native runner")
        .tool_answers_brk(tool_answers_brk)
        .output(&Command::new(fixture))
        .unwrap_or_else(|error| panic!("run the fixture: {error}"))
}

fn stdout_of(label: &str, output: &Output) -> String {
    assert!(output.status.success(), "{label} failed: {output:?}");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn a_tool_that_answers_brk_finds_the_break_as_the_kernel_leaves_it() {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = compile_fixture(directory.path());
    let native = stdout_of(
        "native",
        &Command::new(&fixture)
            .output()
            .expect("run the fixture natively"),
    );
    assert_eq!(
        native,
        "page after the image mapped: no\nbrk(0) is the kernel's start_brk: yes\nbreak in a mapping: no\n"
    );
    assert_eq!(
        stdout_of(
            "DynamoRIO, tool answers brk",
            &under_dynamorio(&fixture, true)
        ),
        native
    );
    let reserved = stdout_of("DynamoRIO", &under_dynamorio(&fixture, false));
    assert!(
        reserved.contains("page after the image mapped: yes"),
        "without the option DynamoRIO reserves the page after the image: {reserved}"
    );
}

/// The fixture's `mode` parser alone, on `input`.
fn parse(fixture: &Path, mode: &str, input: &[u8]) -> Output {
    let mut child = Command::new(fixture)
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("run the fixture {mode}: {error}"));
    child
        .stdin
        .take()
        .expect("fixture stdin")
        .write_all(input)
        .expect("write the fixture's input");
    child.wait_with_output().expect("wait for the fixture")
}

/// The parser refused `input`, naming `why`, and printed nothing.
fn assert_refused(fixture: &Path, mode: &str, input: &[u8], why: &str) {
    let output = parse(fixture, mode, input);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{mode} accepted {input:?}: {output:?}"
    );
    assert!(
        output.stdout.is_empty(),
        "{mode} printed on refusing {input:?}: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(why),
        "{mode} refused {input:?} for another reason: {stderr}"
    );
}

#[test]
fn the_stat_parser_takes_only_a_whole_record_and_a_whole_field_47() {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = compile_fixture(directory.path());
    let stat = std::fs::read("/proc/self/stat").expect("read /proc/self/stat");
    let accepted = parse(&fixture, "--stat-from-stdin", &stat);
    assert_eq!(
        String::from_utf8_lossy(&accepted.stdout),
        "stat parsed: yes\n",
        "the control: a whole record parses: {accepted:?}"
    );

    // The byte offsets of field 47: fields 3 onward follow the last ')',
    // one space before each.
    let command_end = stat
        .iter()
        .rposition(|&byte| byte == b')')
        .expect("a command");
    let mut spaces = stat[command_end..]
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b' ')
        .map(|(offset, _)| command_end + offset);
    let field_47 = spaces.nth(44).expect("field 47") + 1;
    let field_47_end = field_47
        + stat[field_47..]
            .iter()
            .position(|&byte| byte == b' ')
            .expect("field 48");

    assert_refused(
        &fixture,
        "--stat-from-stdin",
        &stat[..field_47_end],
        "ends without a newline",
    );
    assert_refused(
        &fixture,
        "--stat-from-stdin",
        &stat[..field_47_end - 1],
        "ends without a newline",
    );
    assert_refused(
        &fixture,
        "--stat-from-stdin",
        &[&stat[..field_47_end], b"\n"].concat(),
        "fewer than 52 fields",
    );
    assert_refused(
        &fixture,
        "--stat-from-stdin",
        &[&stat[..field_47_end], b"junk", &stat[field_47_end..]].concat(),
        "field 47 is not a whole number",
    );
    assert_refused(
        &fixture,
        "--stat-from-stdin",
        &[&stat[..field_47], b"+", &stat[field_47..]].concat(),
        "field 47 is not a whole number",
    );
    assert_refused(
        &fixture,
        "--stat-from-stdin",
        &[
            &stat[..field_47],
            b"99999999999999999999",
            &stat[field_47_end..],
        ]
        .concat(),
        "field 47 is not a whole number",
    );
    assert_refused(&fixture, "--stat-from-stdin", b"", "is empty");
    // Two whole records are not one: the last ')' is the second record's.
    assert_refused(
        &fixture,
        "--stat-from-stdin",
        &[&stat[..], &stat[..]].concat(),
        "not one complete line",
    );
    // Cut after field 47, then five spaces: 52 separators, but fields 48 to
    // 52 are empty.
    assert_refused(
        &fixture,
        "--stat-from-stdin",
        &[&stat[..field_47_end], b"     \n"].concat(),
        "an empty field",
    );
}

#[test]
fn the_maps_parser_takes_only_whole_increasing_ranges() {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = compile_fixture(directory.path());
    let maps = std::fs::read("/proc/self/maps").expect("read /proc/self/maps");
    let accepted = parse(&fixture, "--maps-from-stdin", &maps);
    assert_eq!(
        String::from_utf8_lossy(&accepted.stdout),
        "maps parsed: yes\n",
        "the control: whole maps parse: {accepted:?}"
    );

    let line = |range: &str| format!("{range} r--p 00000000 00:00 0\n").into_bytes();
    assert_refused(
        &fixture,
        "--maps-from-stdin",
        &[&maps[..], &line("2000-1000")].concat(),
        "does not increase",
    );
    assert_refused(
        &fixture,
        "--maps-from-stdin",
        &[&maps[..], &line("1000-1000")].concat(),
        "does not increase",
    );
    assert_refused(
        &fixture,
        "--maps-from-stdin",
        &[&maps[..], &line("1000-10000000000000000")].concat(),
        "no well-formed end",
    );
    assert_refused(
        &fixture,
        "--maps-from-stdin",
        &[&maps[..], &line("+1000-2000")].concat(),
        "does not start with a range",
    );
    assert_refused(
        &fixture,
        "--maps-from-stdin",
        &maps[..maps.len() - 1],
        "ends without a newline",
    );
    assert_refused(&fixture, "--maps-from-stdin", b"", "is empty");
}
