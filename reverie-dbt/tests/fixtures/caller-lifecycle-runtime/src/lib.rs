/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! One typed native test Tool over the ordinary caller export contract.

mod lifecycle;
pub mod protocol;
pub mod tool;

include!(concat!(env!("OUT_DIR"), "/caller_identity.rs"));

reverie_dbt::export_caller_tool!(tool::LifecycleTool, CALLER_INPUT_IDENTITY);
