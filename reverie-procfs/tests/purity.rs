/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Purity guard: this crate formats bytes from caller-supplied values
//! only. Reading a clock, the filesystem, the environment, or a
//! randomness source would make its output depend on the host or the
//! moment, which is exactly what sharing it exists to prevent. Scan
//! every library source file for those APIs and refuse them by name.

#[test]
fn library_sources_use_no_host_or_clock_apis() {
    let forbidden: Vec<String> = [
        ("std", "::fs"),
        ("std", "::time"),
        ("std", "::env"),
        ("std", "::process"),
        ("std", "::net"),
        ("std", "::thread"),
        ("get", "random"),
        ("System", "Time"),
        ("Inst", "ant"),
    ]
    .iter()
    .map(|(a, b)| format!("{a}{b}"))
    .collect();
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
                for token in &forbidden {
                    assert!(
                        !text.contains(token.as_str()),
                        "{} uses forbidden host/clock API token {token:?}",
                        path.display()
                    );
                }
            }
        }
    }
    assert!(
        checked >= 3,
        "expected to scan the crate sources, got {checked}"
    );
}
