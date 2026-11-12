/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// The scanner itself must read the library sources it checks; the
// disallowed-* rules in clippy.toml govern the library, not this test.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

//! Purity guard: this crate formats bytes from caller-supplied values
//! only. Reading a clock, the filesystem, the environment, or a
//! randomness source would make its output depend on the host or the
//! moment, which is exactly what sharing it exists to prevent.
//!
//! Two layers enforce it. `clippy.toml` bans the resolved paths at
//! compile time (the `-D warnings` clippy gate). This test is the
//! second layer: it parses every library source with `syn` and refuses
//! forbidden paths however they are spelled — grouped imports
//! (`use std::{fs};`), whitespace variants (`std :: fs :: read`), and
//! impure `libc::` entry points (`libc::time(..)`) — none of which a
//! substring scan can see. Deliberate obfuscation (renamed `std`
//! aliases, macro-built paths) is out of scope: this guard is against
//! forgetfulness, and the forgetful spellings are the grouped ones.

use syn::visit::Visit;

const STD_MODULES: &[&str] = &["fs", "time", "env", "process", "net", "thread"];
const TYPE_NAMES: &[&str] = &["SystemTime", "Instant"];
const LIBC_BANNED: &[&str] = &[
    "time",
    "clock_gettime",
    "gettimeofday",
    "localtime",
    "gmtime",
    "getenv",
    "setenv",
    "unsetenv",
    "open",
    "openat",
    "openat2",
    "creat",
    "fopen",
    "syscall",
    "rand",
    "srand",
    "random",
    "fork",
    "vfork",
    "clone",
    "pthread_create",
    "system",
    "popen",
];

fn segments(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect()
}

fn check_segments(segs: &[String], violations: &mut Vec<String>) {
    if segs.len() >= 2 && segs[0] == "std" && STD_MODULES.contains(&segs[1].as_str()) {
        violations.push(format!("forbidden std module path {}", segs.join("::")));
    }
    if segs.len() >= 2 && segs[0] == "libc" && LIBC_BANNED.contains(&segs[1].as_str()) {
        violations.push(format!("forbidden libc entry point {}", segs.join("::")));
    }
    if let Some(last) = segs.last()
        && TYPE_NAMES.contains(&last.as_str())
        && segs.first().is_some_and(|f| f == "std" || f == "core")
    {
        violations.push(format!("forbidden clock type {}", segs.join("::")));
    }
}

fn check_use_tree(prefix: &mut Vec<String>, tree: &syn::UseTree, violations: &mut Vec<String>) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            check_use_tree(prefix, &path.tree, violations);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let mut full = prefix.clone();
            full.push(name.ident.to_string());
            check_segments(&full, violations);
        }
        syn::UseTree::Rename(rename) => {
            let mut full = prefix.clone();
            full.push(rename.ident.to_string());
            check_segments(&full, violations);
        }
        syn::UseTree::Glob(_) => {
            // A glob under std (or a forbidden std module) can name any
            // of the refused APIs without spelling them.
            if prefix.first().is_some_and(|f| f == "std") {
                violations.push(format!("forbidden glob import {}::*", prefix.join("::")));
            }
            if prefix.first().is_some_and(|f| f == "libc") {
                violations.push("forbidden glob import libc::*".to_owned());
            }
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                check_use_tree(prefix, item, violations);
            }
        }
    }
}

#[derive(Default)]
struct Scanner {
    violations: Vec<String>,
}

impl<'ast> Visit<'ast> for Scanner {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        check_segments(&segments(path), &mut self.violations);
        syn::visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        check_use_tree(&mut Vec::new(), &item.tree, &mut self.violations);
        syn::visit::visit_item_use(self, item);
    }
}

/// The forbidden paths in one source text, empty when it is pure.
fn check_source(text: &str) -> Vec<String> {
    let file = syn::parse_file(text).expect("library source parses");
    let mut scanner = Scanner::default();
    scanner.visit_file(&file);
    scanner.violations
}

#[test]
fn library_sources_use_no_host_or_clock_apis() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src];
    let mut checked = 0;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src dir") {
            let path = entry.expect("src entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let text = std::fs::read_to_string(&path).expect("read src file");
                checked += 1;
                assert!(
                    check_source(&text).is_empty(),
                    "{}: {:?}",
                    path.display(),
                    check_source(&text)
                );
            }
        }
    }
    assert!(
        checked >= 3,
        "expected to scan the crate sources, got {checked}"
    );
}

#[test]
fn scanner_refuses_the_forgetful_spellings() {
    // Canonical spelling.
    assert!(!check_source("fn f() { let _ = std::time::SystemTime::now(); }").is_empty());
    // Grouped import, then the short path.
    assert!(
        !check_source("use std::{fs}; fn f() { let _ = fs::read(\"/etc/hostname\"); }").is_empty()
    );
    // Grouped import naming a forbidden module among allowed ones.
    assert!(!check_source("use std::{fmt, fs};").is_empty());
    // Whitespace variant.
    assert!(!check_source("fn f() { let _ = std :: fs :: read(\"/etc/hostname\"); }").is_empty());
    // Through the libc dependency.
    assert!(!check_source("fn f() { unsafe { libc::time(std::ptr::null_mut()) }; }").is_empty());
    assert!(
        !check_source("fn f() { unsafe { libc::getenv(b\"X\\0\".as_ptr().cast()) }; }").is_empty()
    );
    // Glob over std.
    assert!(!check_source("use std::*;").is_empty());
}

#[test]
fn scanner_admits_the_pure_spellings_this_crate_uses() {
    assert!(
        check_source(
            "use std::fmt::Write as _; fn f(s: &mut String) { let _ = write!(s, \"x\"); }"
        )
        .is_empty()
    );
    assert!(check_source("fn f() -> libc::stat { unsafe { std::mem::zeroed() } }").is_empty());
    assert!(check_source("fn f(d: u64) -> u64 { libc::major(d) }").is_empty());
    assert!(check_source("use std::collections::BTreeSet;").is_empty());
}
