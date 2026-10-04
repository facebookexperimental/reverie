/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Runs the exact shared counter2 tool through e9patch's direct AOT path.

use std::ffi::OsString;
use std::io;
use std::io::Write;
use std::path::PathBuf;

use reverie::process::Command;
use reverie_examples::run_e9patch_counter2_with_preload;

fn example_preload() -> io::Result<PathBuf> {
    let executable = std::env::current_exe()?;
    let parent = executable.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "launcher executable has no parent")
    })?;
    [
        parent.join("libreverie_examples.so"),
        parent.join("deps/libreverie_examples.so"),
        parent
            .parent()
            .unwrap_or(parent)
            .join("libreverie_examples.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "cannot find libreverie_examples.so beside {}",
                executable.display()
            ),
        )
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let mut arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.first().is_some_and(|argument| argument == "--") {
        arguments.remove(0);
    }
    let Some(program) = arguments.first().cloned() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: reverie-e9patch-counter2 -- PROGRAM [ARG ...]",
        )
        .into());
    };
    let guest_arguments: Vec<OsString> = arguments.into_iter().skip(1).collect();
    let mut command = Command::new(program);
    command.args(guest_arguments);

    let (output, (syscalls, processes, threads)) =
        run_e9patch_counter2_with_preload(command, example_preload()?).await?;
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;
    eprintln!(
        " [counter tool] Total system calls in process tree: {syscalls}, from {processes} processes, {threads} thread(s)."
    );
    output.status.raise_or_exit()
}
