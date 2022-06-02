/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use thiserror::Error;

use crate::trace;

/// A reverie-ptrace error. This error type isn't meant to be exposed to the
/// user.
#[derive(Error, Debug)]
pub enum Error {
    /// An internal error that is only ever meant to be used as a reverie-ptrace
    /// implementation detail. None of these errors should make it through to the
    /// user.
    #[error(transparent)]
    Internal(#[from] trace::Error),

    /// A public error.
    #[error(transparent)]
    External(#[from] reverie::Error),
}
