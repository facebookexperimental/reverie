/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The actual default-forwarding Tool shared by the stat conformance tests.

use reverie::Tool;

#[derive(Debug, Default, Clone)]
pub struct LocalState;

#[reverie::tool]
impl Tool for LocalState {
    type GlobalState = ();
    type ThreadState = ();
}
