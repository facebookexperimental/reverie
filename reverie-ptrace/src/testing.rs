/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Utilities that support constructing tests for Reverie Tools.

use futures::Future;
use reverie::process::Command;
use reverie::process::Output;
use reverie::process::Stdio;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Tool;

pub use crate::perf::do_branches;
use crate::spawn_fn_with_config;
use crate::TracerBuilder;

/// For some tests, its nice to show what was printed.
pub fn print_tracee_output(output: &Output) {
    println!(
        " >>> Tracee completed, {:?}, stdout len {}, stderr len {}",
        output.status,
        output.stdout.len(),
        output.stderr.len(),
    );
    if !output.stdout.is_empty() {
        println!(
            " >>> stdout:\n{}",
            &std::str::from_utf8(&output.stdout).unwrap()
        );
    }
    if !output.stderr.is_empty() {
        println!(
            " >>> stderr:\n{}",
            &std::str::from_utf8(&output.stderr).unwrap()
        );
    }
}

/// Configure tokio and tracing in the way that we like, and run the future.
pub fn run_tokio_test<F: Future>(fut: F) -> F::Output {
    let collector = tracing_subscriber::fmt()
        .with_env_filter("reverie=trace")
        .finish();

    // For reentrancy during testing we need to set up logging early because mio
    // will actually do some log chatter.

    // Here we ignore errors, because tests may be running in parallel, and we don't care who "wins".
    tracing::subscriber::set_global_default(collector).unwrap_or(());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .worker_threads(2)
        .build()
        .unwrap();
    rt.block_on(async move {
        let local_set = tokio::task::LocalSet::new();
        local_set.run_until(fut).await
    })
}

/// Runs a command as a guest and returns its collected output and global state.
pub fn test_cmd_with_config<T>(
    program: &str,
    args: &[&str],
    config: <T::GlobalState as GlobalTool>::Config,
) -> Result<(Output, T::GlobalState), Error>
where
    T: Tool + 'static,
{
    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    run_tokio_test(async move {
        let tracer = TracerBuilder::<T>::new(cmd).config(config).spawn().await?;
        tracer.wait_with_output().await
    })
}

/// Runs a command as a guest and returns its collected output and global state.
pub fn test_cmd<T>(program: &str, args: &[&str]) -> Result<(Output, T::GlobalState), Error>
where
    T: Tool + 'static,
{
    test_cmd_with_config::<T>(program, args, Default::default())
}

/// Runs a function as a guest and returns its collected (stdout/err) output and global state.
pub fn test_fn_with_config<T, F>(
    f: F,
    config: <T::GlobalState as GlobalTool>::Config,
    capture_output: bool,
) -> Result<(Output, T::GlobalState), Error>
where
    T: Tool + 'static,
    F: FnOnce(),
{
    run_tokio_test(async move {
        let tracee = spawn_fn_with_config::<T, _>(f, config, capture_output).await?;
        tracee.wait_with_output().await
    })
}

/// Runs a function as a guest and returns its collected output and global state.
pub fn test_fn<T, F>(f: F) -> Result<(Output, T::GlobalState), Error>
where
    T: Tool + 'static,
    F: FnOnce(),
{
    test_fn_with_config::<T, F>(f, Default::default(), true)
}

/// Runs a function as a guest and returns its global state. Also checks that the
/// tracee exit code is 0.
pub fn check_fn_with_config<T, F>(
    f: F,
    config: <T::GlobalState as GlobalTool>::Config,
    capture_output: bool,
) -> T::GlobalState
where
    T: Tool + 'static,
    F: FnOnce(),
{
    let (output, state) = test_fn_with_config::<T, F>(f, config, capture_output).unwrap();

    if output.status != ExitStatus::Exited(0) {
        print_tracee_output(&output);
        panic!("Got exit status {:?}", output.status);
    }

    state
}

/// Runs a function as a guest and returns its global state. Also checks that the
/// tracee exit code is 0.
pub fn check_fn<T, F>(f: F) -> T::GlobalState
where
    T: Tool + 'static,
    F: FnOnce(),
{
    check_fn_with_config::<T, F>(f, Default::default(), true)
}
