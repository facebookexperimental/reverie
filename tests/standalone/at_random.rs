/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::env;

use reverie::Error;
use reverie::ExitStatus;

#[path = "../tool_fixtures/at_random.rs"]
mod at_random_tool;

use at_random_tool::TestTool;

#[path = "../support/at_random_rust_guest.rs"]
mod at_random_rust_guest;

use at_random_rust_guest::guest_mode;

async fn host_mode() -> Result<ExitStatus, Error> {
    println!("Running in HOST mode (ReverieTool)");

    let at_random = unsafe { libc::getauxval(libc::AT_RANDOM) as *const u8 };
    let slice = unsafe { std::slice::from_raw_parts(at_random, 16) };

    println!("Entropy (non-intercepted) at at_random {:02x?}", slice);

    let mut command = reverie::process::Command::new(std::env::current_exe().unwrap());
    command.arg("guest");

    let tracer = reverie_ptrace::TracerBuilder::<TestTool>::new(command)
        .spawn()
        .await?;
    let (status, _) = tracer.wait().await?;

    Ok(status)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    match &args[..] {
        [_] => host_mode().await?.raise_or_exit(),
        [_, s] if s == "guest" => guest_mode(),
        _ => panic!(
            "Expected 'guest' or no CLI argument. Got unexpected command line args ({}): {:?}",
            args.len(),
            args
        ),
    }

    Ok(())
}
