/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[path = "pkey_nested_support.rs"]
mod support;

extern "C" fn initialize() {
    if let Some(path) = std::env::var_os(reverie_e9patch::COORDINATOR_ENV) {
        unsafe { reverie_e9patch::install_tool::<support::NestedTool>(path) }.unwrap();
    }
}

#[used]
#[unsafe(link_section = ".init_array")]
static INITIALIZE: extern "C" fn() = initialize;
