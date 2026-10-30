/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[path = "../../../tool_fixtures/suppression.rs"]
pub mod suppression_tool;
include!(concat!(env!("OUT_DIR"), "/caller_identity.rs"));

reverie_dbt::export_caller_tool!(suppression_tool::TestTool, CALLER_INPUT_IDENTITY);
