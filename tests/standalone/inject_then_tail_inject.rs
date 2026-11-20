/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::env;
use std::io;
use std::io::Write;

use nix::unistd;
use reverie::Error;
use reverie::process::Stdio;

#[path = "../tool_fixtures/inject_then_tail.rs"]
mod inject_then_tail_tool;

use inject_then_tail_tool::NUM_REPS;
use inject_then_tail_tool::TestTool;

#[path = "../support/inject_then_tail_rust_guest.rs"]
mod rust_guest;

use rust_guest::guest_mode;

/// The IDs the guest prints, in its `Read IDs:` line order.
#[derive(Debug, PartialEq, Eq)]
struct Ids {
    tid: i64,
    pid: i64,
    gid: i64,
    ppid: i64,
    pgid: i64,
    sid: i64,
}

impl Ids {
    /// What the guest must read, from the tracer's side: the guest is this
    /// process's child, in its process group and session, with its group ID,
    /// and it reads its thread ID on its main thread.
    fn expected(guest_pid: i64) -> Result<Self, Error> {
        let pgid = unistd::getpgid(None).map_err(io::Error::from)?;
        let sid = unistd::getsid(None).map_err(io::Error::from)?;
        Ok(Self {
            tid: guest_pid,
            pid: guest_pid,
            gid: unistd::getgid().as_raw().into(),
            ppid: unistd::getpid().as_raw().into(),
            pgid: pgid.as_raw().into(),
            sid: sid.as_raw().into(),
        })
    }

    /// Parses the guest's whole stdout: its start line, its
    /// `Read IDs: t {}, p {}, g {}, pp {}, pg {}, s{}` line and the random number
    /// it prints last. A guest that stopped early has no IDs.
    fn printed(stdout: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(stdout).ok()?;
        let lines: Vec<&str> = text.lines().collect();
        let ["Running in guest mode (actual test).", ids, random] = lines.as_slice() else {
            return None;
        };
        random
            .strip_prefix("Generated random number: ")?
            .parse::<u64>()
            .ok()?;
        let fields: Vec<&str> = ids.strip_prefix("Read IDs: ")?.split(", ").collect();
        let [t, p, g, pp, pg, s] = fields.as_slice() else {
            return None;
        };
        let value = |field: &str, prefix: &str| field.strip_prefix(prefix)?.parse::<i64>().ok();
        Some(Self {
            tid: value(t, "t ")?,
            pid: value(p, "p ")?,
            gid: value(g, "g ")?,
            ppid: value(pp, "pp ")?,
            pgid: value(pg, "pg ")?,
            sid: value(s, "s")?,
        })
    }
}

async fn host_mode(thisprog: &str) -> Result<i32, Error> {
    println!("Running in HOST mode (ReverieTool)");

    let mut command = reverie::process::Command::new(thisprog);
    command.arg("guest").stdout(Stdio::piped());

    let tracer = reverie_ptrace::TracerBuilder::<TestTool>::new(command)
        .config(NUM_REPS)
        .spawn()
        .await?;
    let guest_pid = tracer.guest_pid().as_raw().into();
    let (output, _) = tracer.wait_with_output().await?;
    io::stdout().write_all(&output.stdout)?;

    let status = output.status.code().unwrap_or(1);
    if status != 0 {
        return Ok(status);
    }

    let expected = Ids::expected(guest_pid)?;
    match Ids::printed(&output.stdout) {
        Some(printed) if printed == expected => Ok(0),
        Some(printed) => {
            eprintln!("The guest read {printed:?}; the tracer expected {expected:?}");
            Ok(1)
        }
        None => {
            eprintln!("The guest did not print its three lines to the end");
            Ok(1)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    match &args[..] {
        [p] => std::process::exit(host_mode(p).await?),
        [_, s] if s == "guest" => guest_mode(),
        _ => panic!(
            "Expected 'guest' or no CLI argument. Got unexpected command line args ({}): {:?}",
            args.len(),
            args
        ),
    }

    Ok(())
}
