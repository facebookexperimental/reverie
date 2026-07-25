/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::fs;
use std::io;
use std::io::Write;
use std::sync::Mutex;

use colored::Colorize;
use reverie_process::Pid;
use riptrace_rpc::Config;
use riptrace_rpc::MyService;
use syscalls::Errno;

pub struct GlobalState {
    /// The configuration.
    pub config: Config,

    /// The number of syscalls we've seen so far.
    pub count: AtomicUsize,

    output: Output,
}

pub enum Output {
    Stderr(io::Stderr),
    File(Mutex<io::BufWriter<fs::File>>),
}

#[async_trait::async_trait]
impl MyService for GlobalState {
    async fn config(&self) -> Config {
        self.config.clone()
    }

    async fn count(&self, count: usize) {
        self.count.fetch_add(count, Ordering::Relaxed);
    }

    async fn pretty_print(
        &self,
        thread_id: u32,
        pretty: &str,
        result: Option<Result<usize, Errno>>,
    ) {
        let thread_id = Pid::from_raw(thread_id as i32);

        match &self.output {
            Output::Stderr(stderr) => {
                let mut stderr = stderr.lock();

                match result {
                    Some(Ok(value)) => {
                        writeln!(
                            stderr,
                            "[{}] {} {} {}",
                            thread_id.colored(),
                            pretty,
                            "->".bold(),
                            value.to_string().green()
                        )
                        .unwrap();
                    }
                    Some(Err(errno)) => {
                        writeln!(
                            stderr,
                            "[{}] {} {} {}",
                            thread_id.colored(),
                            pretty,
                            "->".bold(),
                            errno.to_string().bold().red()
                        )
                        .unwrap();
                    }
                    None => {
                        writeln!(stderr, "[{}] {}", thread_id.colored(), pretty).unwrap();
                    }
                }
            }
            Output::File(file) => {
                let mut f = file.lock().unwrap();

                match result {
                    Some(Ok(value)) => {
                        writeln!(f, "[{}] {} -> {}", thread_id, pretty, value).unwrap();
                    }
                    Some(Err(errno)) => {
                        writeln!(f, "[{}] {} -> {}", thread_id, pretty, errno).unwrap();
                    }
                    None => {
                        writeln!(f, "[{}] {}", thread_id, pretty).unwrap();
                    }
                }
            }
        }
    }
}

impl GlobalState {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            count: AtomicUsize::new(0),
            output: Output::Stderr(io::stderr()),
        }
    }

    pub fn with_output(&mut self, f: fs::File) -> &mut Self {
        self.output = Output::File(Mutex::new(io::BufWriter::new(f)));

        self
    }
}
