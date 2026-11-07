/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! The original Strace Tool compiled as an explicit external DBT caller.
//!
//! No example preload or in-guest constructor is linked into this artifact.

#[path = "../../strace/config.rs"]
mod config;
#[path = "../../strace/filter.rs"]
mod filter;
#[path = "../../strace/global_state.rs"]
mod global_state;
#[path = "../../strace/tool.rs"]
mod tool;

include!(concat!(env!("OUT_DIR"), "/caller_identity.rs"));

reverie_dbt::export_caller_tool!(tool::Strace, CALLER_INPUT_IDENTITY);

#[cfg(test)]
mod tests {
    #[test]
    fn exported_image_declares_the_generated_caller_without_dispatch() {
        assert_eq!(super::tool::take_handled_syscalls(), 0);
        let image = super::reverie_dbt_runtime_image_init();
        assert_eq!(image.runtime_input_identity, super::CALLER_INPUT_IDENTITY);
        assert_eq!(image.abi, 16);
        assert_eq!(image.capabilities, 7);
        assert_eq!(super::tool::take_handled_syscalls(), 0);
    }
}
