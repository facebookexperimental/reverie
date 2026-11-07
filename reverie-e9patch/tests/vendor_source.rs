/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Guards on the vendored e9patch source tree that `build.rs` compiles.
//!
//! These tests interrogate the artifacts that actually decide the outcome
//! rather than a stand-in for them: the parallel-build guard reads GNU make's
//! own parsed dependency database, and the payload guards walk the real
//! vendored files. Grepping the `Makefile` text, or trusting a review note that
//! says the tree is clean, would prove neither.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

/// Bytes above which a *text* file needs explicit coordinator approval.
const LARGE_TEXT_LIMIT: u64 = 2 * 1024 * 1024;

/// Text files over [`LARGE_TEXT_LIMIT`] that are knowingly retained.
///
/// Zydis commits `src/Generated/*.inc` as ordinary tracked source: they are
/// produced out of band by the separate `zydis-db` tooling, no generator exists
/// anywhere in this tree, and `contrib/zydis/.gitignore` does not list them.
/// `InstructionDefinitions.inc` is `#include`d by `src/SharedData.c`, which is
/// in the `contrib/zydis` object list, so the decoder cannot be built without
/// it. The encoder-side companion (`EncoderTables.inc`, 2.6 MB) *was* droppable
/// and has been removed along with the rest of the encoder.
///
/// Anything not on this list is a regression: keep the list short, and never
/// extend it to silence a newly added blob.
const LARGE_TEXT_ALLOWLIST: &[&str] = &["contrib/zydis/src/Generated/InstructionDefinitions.inc"];

fn vendored_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor/e9patch")
}

/// The `e9tool:` dependency line from `make --dry-run --print-data-base`.
///
/// This is make's own parse of the makefile, so it reports the graph make will
/// actually schedule against, including the `|` order-only section.
fn e9tool_dependency_line(goal: &str) -> String {
    let output = Command::new("make")
        .arg("-C")
        .arg(vendored_source())
        .args(["--dry-run", "--print-data-base", goal])
        .output()
        .expect("failed to run make against the vendored e9patch source");
    // `--dry-run` may still report a nonzero status on an up-to-date-check
    // detail; the database is printed either way, so parse it rather than
    // gating on the exit code.
    let database = String::from_utf8_lossy(&output.stdout);
    let mut lines = database
        .lines()
        .filter(|line| line.starts_with("e9tool:") && !line.contains(":="))
        // Target-specific variable assignments (`e9tool: CXXFLAGS += ...`) are
        // printed with the same prefix; the dependency line is the one naming
        // the object files.
        .filter(|line| line.contains("src/e9tool/e9tool.o"));
    let line = lines
        .next()
        .unwrap_or_else(|| {
            panic!("make's database for goal `{goal}` has no e9tool dependency line")
        })
        .to_owned();
    assert!(
        lines.next().is_none(),
        "make's database for goal `{goal}` has more than one e9tool dependency line"
    );
    line
}

fn order_only_section(dependency_line: &str) -> Option<&str> {
    dependency_line.split_once(" | ").map(|(_, order)| order)
}

/// Positive control: on the goals that build the contrib archives, the e9tool
/// link must not be schedulable before both archives exist.
///
/// Without this edge `make -j` links e9tool while `contrib/zydis/libZydis.a`
/// and `contrib/libdw/libdw.a` are still being built, and the build fails with
/// missing archives or undefined `Zydis*` / libdw references.
#[test]
fn contrib_archives_are_ordered_before_the_e9tool_link() {
    for goal in ["dev", "release", "debug", "sanitize"] {
        let line = e9tool_dependency_line(goal);
        let order = order_only_section(&line).unwrap_or_else(|| {
            panic!("goal `{goal}`: e9tool has no order-only prerequisites: {line}")
        });
        for archive in ["contrib/zydis/libZydis.a", "contrib/libdw/libdw.a"] {
            assert!(
                order.split_whitespace().any(|token| token == archive),
                "goal `{goal}`: {archive} is not an order-only prerequisite of e9tool: {line}"
            );
        }
    }
}

/// Negative control: the guard must not be permanently on.
///
/// `all` and `check` link the system `-lZydis` / `-ldw` and must keep upstream
/// behaviour — building the contrib archives there would be wasted work and
/// would hide a genuinely missing edge on the goals that need one.
#[test]
fn the_system_library_goals_do_not_build_the_contrib_archives() {
    for goal in ["all", "check"] {
        let line = e9tool_dependency_line(goal);
        assert!(
            order_only_section(&line).is_none(),
            "goal `{goal}`: e9tool must not gain contrib order-only prerequisites: {line}"
        );
        for archive in ["libZydis.a", "libdw.a"] {
            assert!(
                !line.contains(archive),
                "goal `{goal}`: e9tool must not depend on {archive}: {line}"
            );
        }
    }
}

/// The encoder half of Zydis is compiled out, so its sources must be gone.
///
/// `contrib/zydis/Makefile` never listed `Encoder.o` / `EncoderData.o`, and the
/// build now passes `-DZYDIS_DISABLE_ENCODER`, which is the upstream switch
/// that also stops `<Zydis/Zydis.h>` from pulling in `<Zydis/Encoder.h>`.
#[test]
fn the_zydis_encoder_is_disabled_and_its_sources_are_absent() {
    let zydis = vendored_source().join("contrib/zydis");
    for removed in [
        "src/Encoder.c",
        "src/EncoderData.c",
        "src/Generated/EncoderTables.inc",
        "include/Zydis/Encoder.h",
        "include/Zydis/Internal/EncoderData.h",
    ] {
        assert!(
            !zydis.join(removed).exists(),
            "contrib/zydis/{removed} is back; the encoder is meant to be pruned"
        );
    }
    let zydis_makefile = std::fs::read_to_string(zydis.join("Makefile"))
        .expect("failed to read the vendored contrib/zydis makefile");
    assert!(
        zydis_makefile.contains("-DZYDIS_DISABLE_ENCODER"),
        "contrib/zydis/Makefile must build libZydis.a with -DZYDIS_DISABLE_ENCODER"
    );
    let e9patch_makefile = std::fs::read_to_string(vendored_source().join("Makefile"))
        .expect("failed to read the vendored e9patch makefile");
    assert!(
        e9patch_makefile.contains("-DZYDIS_DISABLE_ENCODER"),
        "the e9tool compile must define ZYDIS_DISABLE_ENCODER to match libZydis.a"
    );
}

fn vendored_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("failed to walk the vendored e9patch source") {
            let entry = entry.expect("failed to read a vendored e9patch directory entry");
            let path = entry.path();
            let kind = entry.file_type().expect("failed to stat a vendored path");
            if kind.is_dir() {
                walk(&path, found);
            } else if kind.is_file() {
                found.push(path);
            }
        }
    }
    let root = vendored_source();
    let mut found = Vec::new();
    walk(&root, &mut found);
    assert!(
        found.len() > 100,
        "the vendored e9patch walk found only {} files",
        found.len()
    );
    found
}

/// No binary payload may be vendored: the repository policy is source only.
///
/// Detection is a NUL-byte scan over the real bytes rather than an extension
/// list, so a renamed blob is still caught.
#[test]
fn the_vendored_source_contains_no_binary_files() {
    let root = vendored_source();
    let mut offenders = Vec::new();
    for path in vendored_files() {
        let bytes = std::fs::read(&path).expect("failed to read a vendored e9patch file");
        if bytes.contains(&0) {
            let relative = path.strip_prefix(&root).unwrap_or(&path);
            offenders.push(format!("{} ({} bytes)", relative.display(), bytes.len()));
        }
    }
    assert!(
        offenders.is_empty(),
        "the vendored e9patch source must not contain binary files: {}",
        offenders.join(", ")
    );
}

/// Text files above the 2 MiB approval ceiling must stay on the short,
/// justified allowlist.
#[test]
fn oversized_text_files_stay_on_the_allowlist() {
    let root = vendored_source();
    let mut offenders = Vec::new();
    let mut seen = Vec::new();
    for path in vendored_files() {
        let size = path
            .metadata()
            .expect("failed to stat a vendored e9patch file")
            .len();
        if size <= LARGE_TEXT_LIMIT {
            continue;
        }
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        if LARGE_TEXT_ALLOWLIST.contains(&relative.as_str()) {
            seen.push(relative);
        } else {
            offenders.push(format!("{relative} ({size} bytes)"));
        }
    }
    assert!(
        offenders.is_empty(),
        "vendored text files over {LARGE_TEXT_LIMIT} bytes need coordinator approval: {}",
        offenders.join(", ")
    );
    // Fire the positive side too: an allowlist entry that no longer matches a
    // real file would let the guard pass while describing a tree that is gone.
    for allowed in LARGE_TEXT_ALLOWLIST {
        assert!(
            seen.iter().any(|found| found == allowed),
            "allowlisted path {allowed} is no longer an oversized vendored file; drop the entry"
        );
    }
}
