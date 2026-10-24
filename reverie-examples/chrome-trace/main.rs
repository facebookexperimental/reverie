/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Runs a process, gathering metadata about all of the processes that were ran
//! and displays it as a tree using Graphviz.

mod event;
mod global_state;
mod tool;

// TODO-HUMAN-REVIEW(PR-159): Review crate-local reuse of the production ChromeTrace tool.
pub(crate) use tool::ChromeTrace;
