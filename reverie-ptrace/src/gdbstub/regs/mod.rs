/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::CoreRegs;
#[cfg(target_arch = "x86_64")]
pub use x86_64::CoreRegs;
#[cfg(target_arch = "x86_64")]
pub use x86_64::ExtraRegs;
