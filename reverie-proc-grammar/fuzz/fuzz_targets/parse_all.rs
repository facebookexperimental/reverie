/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The crate's one fuzz target: every parser over arbitrary bytes.
//!
//! Failure is a panic, or an accepted value that is not stable under
//! render+reparse (a field-shift or lossy-render bug). Seed with the
//! checked-in corpus:
//!   cargo fuzz run parse_all ../tests/fixtures
//! (cargo-fuzz seeds from files under the given directories; the
//! corpus-replay of the same fixtures also runs as an ordinary test,
//! so CI needs no nightly toolchain.)

#![no_main]

use libfuzzer_sys::fuzz_target;
use reverie_proc_grammar::*;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = parse_stat(data) {
        assert_eq!(parse_stat(&render_stat(&parsed)), Ok(parsed));
    }
    if let Ok(parsed) = parse_status(data) {
        assert_eq!(parse_status(&render_status(&parsed)), Ok(parsed));
    }
    if let Ok(parsed) = parse_fdinfo(data) {
        assert_eq!(parse_fdinfo(&render_fdinfo(&parsed)), Ok(parsed));
    }
    if let Ok(parsed) = parse_sched(data) {
        assert_eq!(parse_sched(&render_sched(&parsed)), Ok(parsed));
    }
    if let Ok(parsed) = parse_process_io(data) {
        assert_eq!(parse_process_io(&render_process_io(&parsed)), Ok(parsed));
    }
    if let Ok(parsed) = parse_statm(data) {
        assert_eq!(parse_statm(&render_statm(&parsed)), Ok(parsed));
    }
    if let Ok(parsed) = parse_comm_file(data) {
        assert_eq!(parse_comm_file(&render_comm_file(&parsed)), Ok(parsed));
    }
});
