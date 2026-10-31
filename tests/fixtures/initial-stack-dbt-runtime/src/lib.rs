/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Caller runtime for the shared initial-stack observation Tool.

#[path = "../../../tool_fixtures/initial_stack_pointer.rs"]
pub mod initial_stack_tool;

include!(concat!(env!("OUT_DIR"), "/caller_identity.rs"));

reverie_dbt::export_caller_tool!(initial_stack_tool::StackTool, CALLER_INPUT_IDENTITY);
