/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The register context a hook or the fallback continuation saves for
//! one guest event. The layout is the native architecture's own (see
//! [`super::isa::Isa::RegisterContext`]); generic code reads and
//! writes it only through that trait.

use super::isa::Isa;
use super::isa::NativeIsa;

/// The native architecture's saved register block.
pub type RegisterContext = <NativeIsa as Isa>::RegisterContext;
