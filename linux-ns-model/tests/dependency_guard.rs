/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// The guard itself must read the manifest and sources it checks
// (and locate them via CARGO_MANIFEST_DIR); the clippy.toml purity
// bans govern the library, not this test. `allow`, not `expect`:
// Buck test targets do not load this crate's clippy.toml, so the
// bans never fire there and an expectation would go unfulfilled
// (a land-blocking RUSTFIX warning); under cargo they do fire.
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "the guard reads the manifest and sources it checks and locates them via CARGO_MANIFEST_DIR"
)]

//! Dependency and independence guards, executed by `cargo test`
//! (and by the matching Buck test target). This scan is the
//! secondary check: the authoritative manifest check is
//! `scripts/check-linux-ns-model-deps.py`, which parses with
//! `tomllib` and judges effective packages, and the configured
//! Buck graph queries it quotes in fbsource. A cargo invocation
//! does not fit this test's Buck target (its resources are only
//! this crate's sources, not the workspace), and adding a direct
//! `toml` dev-dependency here (0.8.23 is present transitively in
//! fbsource) would expand the very test closure this guard keeps
//! minimal, so this line scanner stays as defense in depth where
//! Python does not run — any discrepancy is settled in the
//! authoritative checks' favor.
//!
//! 1. Forward closure at the manifest level: the library declares
//!    no normal or build dependencies at all, and dev-dependencies
//!    are exactly the allowlist below. The bridge to the full
//!    transitive closure (`cargo tree`, Buck `cquery deps`) is
//!    `scripts/check-linux-ns-model-deps.py` in this repository.
//! 2. Source independence: the library sources, manifest, and
//!    README never name a consumer. The forbidden names are
//!    assembled from fragments so this guard file does not contain
//!    them either, and the planted-control tests below prove both
//!    checkers fire on synthetic violations (a guard that cannot
//!    fail is not a guard).
//!
//! Incoming edges (who may depend on this crate) are checked by
//! the same script over the whole workspace.

use std::path::PathBuf;

/// The complete dev-dependency allowlist. `libc` serves only the
/// kernel differential test. A dev-dependency on any workspace
/// crate — a backend included — is a violation even though tests
/// never ship: test roots are part of the dependency guard.
const DEV_ALLOWLIST: &[&str] = &["libc"];

/// Classify a manifest section header: `Some((is_dev, None))`
/// for a dependency section whose entries name their packages,
/// `Some((is_dev, Some(name)))` for the table form
/// (`[dependencies.foo]`), where the header itself names the
/// package and the lines under it are its fields. Table form
/// matters: a scanner that only knows the entry form silently
/// admits a dependency declared as a table (found in review).
/// A `target.'cfg(...)'.` prefix is skipped over; quoted tokens
/// are unquoted first.
fn dep_section(section: &str) -> Option<(bool, Option<String>)> {
    let clean = section.trim().replace(['"', '\''], "");
    let tokens: Vec<&str> = clean.split('.').map(str::trim).collect();
    let start = usize::from(tokens.first() == Some(&"target"));
    for (i, tok) in tokens.iter().enumerate().skip(start) {
        let is_dev = match *tok {
            "dependencies" | "build-dependencies" => false,
            "dev-dependencies" => true,
            _ => continue,
        };
        let table_name = tokens.get(i + 1).map(|s| (*s).to_string());
        return Some((is_dev, table_name));
    }
    None
}

fn judge(name: &str, is_dev: bool, violations: &mut Vec<String>) {
    if is_dev {
        if !DEV_ALLOWLIST.contains(&name) {
            violations.push(format!("dev-dependency not on the allowlist: {name}"));
        }
    } else {
        violations.push(format!("library dependency is forbidden: {name}"));
    }
}

fn starts_triple(chars: &[char], at: usize) -> Option<&'static str> {
    let rest: String = chars.iter().skip(at).take(3).collect();
    match rest.as_str() {
        "\"\"\"" => Some("\"\"\""),
        "'''" => Some("'''"),
        _ => None,
    }
}

/// Manifest text as logical lines: comments outside quoted
/// strings removed, and triple-quoted strings kept intact as
/// single logical-line tokens (internal newlines preserved, so
/// TOML first-newline trim and line-ending-backslash joining
/// are applied by `quoted_field`, mirroring `tomllib`).
fn logical_lines(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut lines = Vec::new();
    let mut buf = String::new();
    let mut quote: Option<char> = None;
    let mut triple: Option<&'static str> = None;
    let mut escaped = false;
    let mut in_comment = false;
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if in_comment {
            if c == '\n' {
                lines.push(core::mem::take(&mut buf));
                in_comment = false;
            }
            i += 1;
            continue;
        }
        if let Some(delim) = triple {
            if starts_triple(&chars, i) == Some(delim) {
                buf.push_str(delim);
                i += 3;
                triple = None;
                escaped = false;
                continue;
            }
            if c == '\n' {
                buf.push('\n');
                escaped = false;
            } else {
                buf.push(c);
                if delim == "\"\"\"" {
                    if escaped {
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    }
                }
            }
            i += 1;
            continue;
        }
        match quote {
            Some('"') => {
                buf.push(c);
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' || c == '\n' {
                    quote = None;
                    if c == '\n' {
                        lines.push(core::mem::take(&mut buf));
                    }
                }
                i += 1;
            }
            Some('\'') => {
                buf.push(c);
                if c == '\'' || c == '\n' {
                    quote = None;
                    if c == '\n' {
                        lines.push(core::mem::take(&mut buf));
                    }
                }
                i += 1;
            }
            Some(_) => unreachable!(),
            None => {
                if let Some(delim) = starts_triple(&chars, i) {
                    triple = Some(delim);
                    buf.push_str(delim);
                    i += 3;
                } else if c == '"' || c == '\'' {
                    quote = Some(c);
                    buf.push(c);
                    i += 1;
                } else if c == '#' {
                    in_comment = true;
                    i += 1;
                } else if c == '\n' {
                    lines.push(core::mem::take(&mut buf));
                    i += 1;
                } else {
                    buf.push(c);
                    i += 1;
                }
            }
        }
    }
    if !buf.is_empty() {
        lines.push(buf);
    }
    lines
}

/// The string a triple-quoted value denotes, for the forms a
/// package/path name can take: the newline after the opening
/// delimiter is trimmed, and in a basic (`"""`) string a
/// line-ending backslash joins the following line (all
/// whitespace up to the next non-whitespace is dropped), as
/// TOML specifies. Other escapes are left untouched, which
/// fails closed for names (they cannot contain escapes).
fn triple_value(inner: &str, basic: bool) -> String {
    let inner = inner
        .strip_prefix("\r\n")
        .or_else(|| inner.strip_prefix('\n'))
        .unwrap_or(inner);
    if !basic {
        return inner.to_string();
    }
    let mut out = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let mut lookahead = chars.clone();
            while matches!(lookahead.peek(), Some(' ' | '\t' | '\r')) {
                lookahead.next();
            }
            if lookahead.peek() == Some(&'\n') {
                chars = lookahead;
                chars.next();
                while matches!(chars.peek(), Some(' ' | '\t' | '\r' | '\n')) {
                    chars.next();
                }
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// The quoted value of `field = "..."` (basic, literal `'...'`,
/// or triple-quoted) in a declaration's value text (an inline
/// table or a table-form body), if present. The field name may
/// itself be quoted.
fn quoted_field(value: &str, field: &str) -> Option<String> {
    for (at, _) in value.match_indices(field) {
        let before_ok = value[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'));
        if !before_ok {
            continue;
        }
        let rest = value[at + field.len()..].trim_start();
        // A quoted key's closing quote sits between name and `=`.
        let rest = rest
            .strip_prefix('"')
            .or_else(|| rest.strip_prefix('\''))
            .unwrap_or(rest)
            .trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let rest = rest.trim_start();
        for delim in ["\"\"\"", "'''"] {
            if let Some(inner) = rest.strip_prefix(delim)
                && let Some(end) = inner.find(delim)
            {
                return Some(triple_value(&inner[..end], delim == "\"\"\""));
            }
        }
        for quote in ['"', '\''] {
            if let Some(inner) = rest.strip_prefix(quote)
                && let Some(end) = inner.find(quote)
            {
                return Some(inner[..end].to_string());
            }
        }
    }
    None
}

/// Split a TOML dotted key into unquoted segments.
fn split_key(key: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut buf = String::new();
    let mut quote: Option<char> = None;
    for c in key.trim().chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => buf.push(c),
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '.' => {
                parts.push(buf.trim().to_string());
                buf.clear();
            }
            None => buf.push(c),
        }
    }
    parts.push(buf.trim().to_string());
    parts
}

/// Net bracket/brace depth delta outside quoted strings.
/// Triple-quoted spans are opaque, so braces inside them (or in
/// single-line strings) never change depth.
fn depth_delta(line: &str) -> i32 {
    let chars: Vec<char> = line.chars().collect();
    let mut delta = 0i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Some('"') => {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    quote = None;
                }
                i += 1;
            }
            Some('\'') => {
                if c == '\'' {
                    quote = None;
                }
                i += 1;
            }
            Some(_) => unreachable!(),
            None => {
                if let Some(delim) = starts_triple(&chars, i) {
                    // Skip the whole triple-quoted span.
                    i += 3;
                    let mut inner_escaped = false;
                    while i < chars.len() {
                        if !inner_escaped && starts_triple(&chars, i) == Some(delim) {
                            i += 3;
                            break;
                        }
                        inner_escaped = delim == "\"\"\"" && !inner_escaped && chars[i] == '\\';
                        i += 1;
                    }
                } else if c == '"' || c == '\'' {
                    quote = Some(c);
                    i += 1;
                } else if c == '[' || c == '{' {
                    delta += 1;
                    i += 1;
                } else if c == ']' || c == '}' {
                    delta -= 1;
                    i += 1;
                } else {
                    i += 1;
                }
            }
        }
    }
    delta
}

fn flush_groups(
    groups: &mut Vec<(String, Vec<String>, i32)>,
    is_dev: bool,
    violations: &mut Vec<String>,
) {
    for (name, body, _) in groups.drain(..) {
        judge(
            &effective_package(&name, &body.join("\n")),
            is_dev,
            violations,
        );
    }
}

/// Final component of a declaration's `path` or `git` source,
/// with a trailing `.git` removed, if either is present.
fn source_basename(value: &str) -> Option<String> {
    for field in ["path", "git"] {
        let Some(raw) = quoted_field(value, field) else {
            continue;
        };
        let trimmed = raw.trim_end_matches('/');
        let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
        if let Some(last) = trimmed
            .split('/')
            .rfind(|part| !part.is_empty() && *part != ".")
        {
            return Some(last.to_string());
        }
    }
    None
}

/// The package a declaration actually names: its
/// `package = "..."` rename when present, else the basename of
/// its `path`/`git` source, else its local key. A renamed
/// dependency must not hide behind an allowlisted alias.
fn effective_package(name: &str, value: &str) -> String {
    quoted_field(value, "package")
        .or_else(|| source_basename(value))
        .unwrap_or_else(|| name.to_string())
}

/// Dependency violations in one manifest text. Deliberately a
/// small line scanner, not a TOML parser: it recognizes
/// `[section]` headers (entry and table forms) and `name = ...` /
/// `name.version = ...` entries, judges each declaration by its
/// effective package, and fails closed on shapes it does not
/// recognize inside a dependency section. A table-form
/// declaration is judged when its body ends, so a `package =`
/// rename in the body counts.
fn manifest_violations(text: &str) -> Vec<String> {
    let mut violations = Vec::new();
    // (is_dev) for an entry-form section; table forms are buffered
    // in `pending` as (is_dev, local name, body lines). Entry-form
    // dotted keys are buffered per local name in `groups`.
    let mut current: Option<bool> = None;
    let mut pending: Option<(bool, String, Vec<String>)> = None;
    let mut groups: Vec<(String, Vec<String>, i32)> = Vec::new();
    let mut last_group: Option<usize> = None;
    let mut section = String::new();
    let flush = |pending: &mut Option<(bool, String, Vec<String>)>,
                 violations: &mut Vec<String>| {
        if let Some((is_dev, name, body)) = pending.take() {
            judge(
                &effective_package(&name, &body.join("\n")),
                is_dev,
                violations,
            );
        }
    };
    for line in logical_lines(text) {
        let line = line.trim();
        if let Some(idx) = last_group
            && groups[idx].2 > 0
        {
            groups[idx].1.push(line.to_string());
            groups[idx].2 += depth_delta(line);
            continue;
        }
        if line.starts_with('[') {
            flush(&mut pending, &mut violations);
            if let Some(is_dev) = current {
                flush_groups(&mut groups, is_dev, &mut violations);
            }
            last_group = None;
            section = line.trim_matches(|c| c == '[' || c == ']').to_string();
            current = None;
            if let Some((is_dev, table)) = dep_section(&section) {
                match table {
                    Some(name) => pending = Some((is_dev, name, Vec::new())),
                    None => current = Some(is_dev),
                }
            }
            continue;
        }
        if let Some((_, _, body)) = &mut pending {
            if !line.is_empty() && !line.starts_with('#') {
                body.push(line.to_string());
            }
            continue;
        }
        let Some(_is_dev) = current else {
            continue;
        };
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            violations.push(format!("unrecognized line in [{section}]: {line}"));
            continue;
        };
        let segments = split_key(key);
        let Some(name) = segments.first().filter(|n| !n.is_empty()) else {
            violations.push(format!("unrecognized line in [{section}]: {line}"));
            continue;
        };
        let idx = match groups.iter().position(|(n, _, _)| n == name) {
            Some(idx) => idx,
            None => {
                groups.push((name.clone(), Vec::new(), 0));
                groups.len() - 1
            }
        };
        last_group = Some(idx);
        if segments.len() == 1 {
            groups[idx].1.push(format!("{name} ={value}"));
        } else {
            groups[idx].1.push(format!("{} ={value}", segments[1]));
        }
        groups[idx].2 += depth_delta(value);
    }
    flush(&mut pending, &mut violations);
    if let Some(is_dev) = current {
        flush_groups(&mut groups, is_dev, &mut violations);
    }
    violations
}

/// Forbidden consumer names, assembled so this file — which the
/// scan does not cover, being a test — still never contains them.
fn forbidden_tokens() -> Vec<String> {
    vec![
        ["her", "mit"].concat(),
        ["det", "core"].concat(),
        ["HER", "MIT"].concat(),
        ["DET", "CORE"].concat(),
        ["Her", "mit"].concat(),
        ["Det", "core"].concat(),
    ]
}

fn source_violations(text: &str) -> Vec<String> {
    forbidden_tokens()
        .into_iter()
        .filter(|tok| text.contains(tok.as_str()))
        .map(|tok| format!("names a consumer: {tok}"))
        .collect()
}

fn crate_root() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

#[test]
fn manifest_declares_only_allowlisted_dev_dependencies() {
    let text = std::fs::read_to_string(crate_root().join("Cargo.toml")).expect("read Cargo.toml");
    assert_eq!(manifest_violations(&text), Vec::<String>::new());
}

#[test]
fn library_sources_manifest_and_readme_name_no_consumer() {
    let root = crate_root();
    let mut checked = 0usize;
    let mut stack = vec![root.join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("read source");
                assert_eq!(
                    source_violations(&text),
                    Vec::<String>::new(),
                    "{}",
                    path.display()
                );
                checked += 1;
            }
        }
    }
    assert!(checked >= 5, "scanned only {checked} sources");
    for extra in ["Cargo.toml", "README.md"] {
        let text = std::fs::read_to_string(root.join(extra)).expect("read file");
        assert_eq!(source_violations(&text), Vec::<String>::new(), "{extra}");
    }
}

/// Planted controls: synthetic violations must be caught, and the
/// shapes this crate legitimately uses must not be.
#[test]
fn planted_violations_are_caught() {
    // A normal dependency on a backend crate.
    let planted = "[dependencies]\nreverie-ptrace = { path = \"../reverie-ptrace\" }\n";
    assert!(!manifest_violations(planted).is_empty());
    // The same planted as a dev-dependency still fails.
    let planted = "[dev-dependencies]\nreverie-ptrace = \"0.5\"\n";
    assert!(!manifest_violations(planted).is_empty());
    // A build dependency fails.
    let planted = "[build-dependencies]\ncc = \"1\"\n";
    assert!(!manifest_violations(planted).is_empty());
    // A target-specific dependency fails.
    let planted = "[target.'cfg(unix)'.dependencies]\nnix = \"1\"\n";
    assert!(!manifest_violations(planted).is_empty());
    // Table form declares the package in the header (review F3:
    // an entry-only scanner silently admits these).
    let planted = "[dependencies.reverie-ptrace]\npath = \"../reverie-ptrace\"\n";
    assert!(!manifest_violations(planted).is_empty());
    let planted = "[target.'cfg(unix)'.dev-dependencies.reverie-ptrace]\nversion = \"0.5\"\n";
    assert!(!manifest_violations(planted).is_empty());
    let clean = "[dev-dependencies.libc]\nversion = \"0.2\"\n";
    assert!(manifest_violations(clean).is_empty());
    // Renames are judged by the package they name, not the alias.
    let planted = "[dev-dependencies.libc]\npackage = \"reverie-ptrace\"\nversion = \"0.5\"\n";
    assert!(!manifest_violations(planted).is_empty());
    let planted =
        "[dev-dependencies]\nlibc = { package = \"reverie-ptrace\", version = \"0.5\" }\n";
    assert!(!manifest_violations(planted).is_empty());
    let clean = "[dev-dependencies]\nmy-libc = { package = \"libc\", version = \"0.2\" }\n";
    assert!(manifest_violations(clean).is_empty());
    // Dotted keys name fields of one declaration across lines,
    // and literal (single-quoted) strings are still renames.
    let planted = "[dev-dependencies]\nlibc.package = \"reverie-ptrace\"\nlibc.version = \"0.5\"\n";
    assert!(!manifest_violations(planted).is_empty());
    let planted = "[dev-dependencies.libc]\npackage = 'reverie-ptrace'\nversion = '0.5'\n";
    assert!(!manifest_violations(planted).is_empty());
    let planted = "[dev-dependencies]\nlibc = { package = 'reverie-ptrace', version = '0.5' }\n";
    assert!(!manifest_violations(planted).is_empty());
    let clean = "[dev-dependencies]\nmy-libc.package = 'libc'\nmy-libc.version = '0.2'\n";
    assert!(manifest_violations(clean).is_empty());
    let planted = "[ dev-dependencies ]\nlibc.package = \"reverie-ptrace\"\n";
    assert!(!manifest_violations(planted).is_empty());
    let planted =
        "[dev-dependencies]\nlibc = {\n  package = \"reverie-ptrace\",\n  version = \"0.5\",\n}\n";
    assert!(!manifest_violations(planted).is_empty());
    let planted = "[dev-dependencies]\nlibc = { path = \"../reverie-ptrace\" }\n";
    assert!(!manifest_violations(planted).is_empty());
    let planted =
        "[dev-dependencies]\nlibc = { git = \"https://example.invalid/reverie-ptrace.git\" }\n";
    assert!(!manifest_violations(planted).is_empty());
    // TOML trims the newline after an opening triple quote; a
    // rename split with a line-ending backslash joins the same way.
    let planted = "[dev-dependencies.libc]\npackage = \"\"\"\nreverie-ptrace\"\"\"\n";
    assert!(!manifest_violations(planted).is_empty());
    let planted = "[dev-dependencies.libc]\npackage = '''\nreverie-ptrace'''\n";
    assert!(!manifest_violations(planted).is_empty());
    let planted = "[dev-dependencies.libc]\npackage = \"\"\"reverie-\\\n    ptrace\"\"\"\n";
    assert!(!manifest_violations(planted).is_empty());
    let clean = "[dev-dependencies.libc] # don't { break\npackage = \"\"\"\nlibc\"\"\"\n";
    assert!(manifest_violations(clean).is_empty());
    let clean = "[dev-dependencies.libc]\npackage = \"\"\"lib\\\n    c\"\"\"\n";
    assert!(manifest_violations(clean).is_empty());
    // A trailing comment must not make the scanner skip the
    // section, and a brace inside a comment must not swallow the
    // next declaration into the previous group.
    let planted = "[dev-dependencies] # dev-only\nlibc.package = \"reverie-ptrace\"\n";
    assert!(!manifest_violations(planted).is_empty());
    let planted = "[dev-dependencies]\nlibc = { package = \"libc\", version = \"0.2\" } # {\nevil.package = \"reverie-ptrace\"\n";
    assert!(!manifest_violations(planted).is_empty());
    // Triple-quoted (multiline-style) strings are still renames.
    let planted = "[dev-dependencies.libc]\npackage = \"\"\"reverie-ptrace\"\"\"\n";
    assert!(!manifest_violations(planted).is_empty());
    let planted = "[dev-dependencies]\nlibc = { package = '''reverie-ptrace''' }\n";
    assert!(!manifest_violations(planted).is_empty());
    // The allowlisted shape passes.
    let clean = "[package]\nname = \"x\"\n[dev-dependencies]\nlibc = \"0.2\"\n";
    assert!(manifest_violations(clean).is_empty());
    // A non-dependency section mentioning names is not a violation.
    let clean = "[package.metadata]\nfoo = \"reverie-ptrace\"\n";
    assert!(manifest_violations(clean).is_empty());

    // Source-level planted controls, tokens built the same way as
    // the scanner's.
    let bad = format!("// glue for {}\n", ["Her", "mit"].concat());
    assert!(!source_violations(&bad).is_empty());
    let bad = format!("fn {}_policy() {{}}\n", ["det", "core"].concat());
    assert!(!source_violations(&bad).is_empty());
    let clean = "// Semantics live with the consumer.\n";
    assert!(source_violations(clean).is_empty());
}
