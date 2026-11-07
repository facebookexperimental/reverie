/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! The shared Counter1 Tool hosted by the caller-selected DBT runtime.

#[path = "../../counter1_tool.rs"]
mod counter1_tool;

include!(concat!(env!("OUT_DIR"), "/caller_identity.rs"));

reverie_dbt::export_caller_tool!(counter1_tool::CounterLocal, CALLER_INPUT_IDENTITY);
