/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ffi::OsString;
use std::io;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use reverie_dbt::Counter2Global;
use reverie_dbt::DbtRunner;

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let mut arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.first().is_some_and(|argument| argument == "--") {
        arguments.remove(0);
    }
    let Some(program) = arguments.first().cloned() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: reverie-dbt-counter2 -- PROGRAM [ARG ...]",
        ));
    };
    let guest_arguments: Vec<OsString> = arguments.into_iter().skip(1).collect();

    let runner = DbtRunner::from_env()?;
    let mut guest = Command::new(program);
    guest.args(guest_arguments).env("HERMIT_DBT_COUNTER2", "1");
    let (output, global) = runner
        .output_with_global::<Counter2Global>(&guest, ())
        .await?;

    io::stdout().write_all(&output.stdout)?;
    io::stderr().write_all(&output.stderr)?;
    let (syscalls, processes, threads) = global.snapshot();
    eprintln!(
        "reverie-dbt: counter2 global system calls: {syscalls}, from {processes} processes, {threads} thread(s)"
    );

    let code = output
        .status
        .code()
        .or_else(|| output.status.signal().map(|signal| 128 + signal))
        .unwrap_or(1);
    std::process::exit(code);
}
