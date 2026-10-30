/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[path = "../support/vdso_rust_guest.rs"]
mod rust_guest;

fn main() -> std::process::ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match arguments.as_slice() {
        [] => rust_guest::clock_getres(),
        [selector] if selector == "gettimeofday" => gettimeofday_command(),
        _ => {
            eprintln!("usage: vdso-rust-command-guest [gettimeofday]");
            return std::process::ExitCode::from(2);
        }
    }
    std::process::ExitCode::SUCCESS
}

fn gettimeofday_command() {
    use std::io::Write;

    rust_guest::gettimeofday();
    std::io::stdout()
        .write_all(b"vdso-rust-gettimeofday-complete\n")
        .unwrap();
}
