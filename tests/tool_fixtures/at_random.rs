/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use reverie::Errno;
use reverie::Guest;
use reverie::Tool;
use reverie::syscalls::MemoryAccess;

#[derive(Debug, Default, Clone)]
pub struct TestTool {}

#[path = "at_random_constants.rs"]
mod at_random_constants;

pub use at_random_constants::PRNG_SEED;

#[reverie::tool]
impl Tool for TestTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_post_exec<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Errno> {
        if let Some(ptr) = guest.auxv().at_random() {
            // It is safe to mutate this address since libc has not yet had a
            // chance to modify or copy the auxv table.
            let ptr = unsafe { ptr.into_mut() };
            guest.memory().write_value(ptr, &PRNG_SEED)?;
        }

        Ok(())
    }
}
