/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Runs the exact shared counter1 tool through the Reverie KVM guest.

mod counter1_tool;

use std::error::Error;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::PathBuf;

use counter1_tool::CounterLocal;
use reverie_kvm::KvmBackend;

const GUEST_MEMORY_BYTES: usize = 1024 * 1024 * 1024;

async fn run() -> Result<i32, Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let first = args
        .next()
        .ok_or("usage: reverie-kvm-counter1 [--] PROGRAM [ARG ...]")?;
    let executable = if first == OsStr::new("--") {
        PathBuf::from(
            args.next()
                .ok_or("usage: reverie-kvm-counter1 [--] PROGRAM [ARG ...]")?,
        )
    } else {
        PathBuf::from(first)
    };
    let tail: Vec<OsString> = args.collect();
    let argv: Vec<String> = std::iter::once(executable.as_os_str().to_owned())
        .chain(tail)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| "KVM counter1 arguments must be valid UTF-8")
        })
        .collect::<Result<_, _>>()?;
    let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let image = std::fs::read(&executable)?;
    let cwd = std::env::current_dir()?;

    let mut backend = KvmBackend::new(GUEST_MEMORY_BYTES)?;
    backend.install_static_elf_with_context(
        &image,
        &argv_refs,
        &["LC_ALL=C", "LANG=C", "RUST_LOG=off"],
        &cwd,
    )?;
    let (global, status, _, _) = backend
        .run_static_elf_with_tool::<CounterLocal>((), false)
        .await?;
    eprintln!("counter1-global syscalls={}", global.total());
    Ok(status)
}

fn main() {
    let status = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .and_then(|runtime| {
            runtime
                .block_on(run())
                .map_err(|error| std::io::Error::other(error.to_string()))
        }) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("reverie-kvm-counter1: {error}");
            1
        }
    };
    std::process::exit(status);
}
