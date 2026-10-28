/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Command helpers for generic Reverie conformance tests.
//!
//! The current implementation uses ptrace and returns the caller's actual
//! global Tool state. Other backends need an adapter that installs that same
//! caller-owned Tool; there is no backend selector or implicit fallback here.
//! Inherited function guests continue to use `reverie_ptrace::testing` directly.

use reverie::Error;
use reverie::GlobalTool;
use reverie::Tool;
use reverie::process::Output;

/// Runs a ptrace command with the existing output capture and runtime setup.
pub fn test_cmd_with_config<T>(
    program: &str,
    args: &[&str],
    config: <T::GlobalState as GlobalTool>::Config,
) -> Result<(Output, T::GlobalState), Error>
where
    T: Tool + 'static,
{
    reverie_ptrace::testing::test_cmd_with_config::<T>(program, args, config)
}

/// Runs a ptrace command with the caller's default Tool configuration.
pub fn test_cmd<T>(program: &str, args: &[&str]) -> Result<(Output, T::GlobalState), Error>
where
    T: Tool + 'static,
{
    test_cmd_with_config::<T>(program, args, Default::default())
}
