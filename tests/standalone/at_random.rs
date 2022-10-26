/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::env;

use reverie::syscalls::MemoryAccess;
use reverie::Errno;
use reverie::Error;
use reverie::ExitStatus;
use reverie::Guest;
use reverie::Tool;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct TestTool {}

const PRNG_SEED: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xca, 0xfe, 0x87, 0x65, 0x43, 0x21,
];

#[reverie::tool]
impl Tool for TestTool {
    async fn handle_post_exec<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Errno> {
        if let Some(ptr) = guest.auxv().at_random() {
            // It is safe to mutate this address since libc has not yet had a
            // chance to modify or copy the auxv table.
            let ptr = unsafe { ptr.into_mut() };
            guest.memory().write_value(ptr, &PRNG_SEED)?;
        }

        Ok(())
    }
}

fn guest_mode() {
    println!("Running in guest mode (actual test).");

    let at_random = unsafe { libc::getauxval(libc::AT_RANDOM) as *const u8 };
    let slice = unsafe { std::slice::from_raw_parts(at_random, 16) };

    println!("Entropy (intercepted) at at_random {:02x?}", slice);

    assert_eq!(slice, PRNG_SEED);
}

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
