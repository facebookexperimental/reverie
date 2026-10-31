/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[path = "../../../tool_fixtures/thread_start_tail.rs"]
pub mod thread_start_tail_tool;
include!(concat!(env!("OUT_DIR"), "/caller_identity.rs"));

reverie_dbt::export_caller_tool!(thread_start_tail_tool::TestTool, CALLER_INPUT_IDENTITY);
