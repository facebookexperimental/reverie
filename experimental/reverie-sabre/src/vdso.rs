/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use super::ffi;

#[allow(non_upper_case_globals)]
pub static mut clock_gettime: ffi::vdso_clock_gettime_fn = ffi::vdso_clock_gettime_stub;

#[allow(non_upper_case_globals)]
pub static mut getcpu: ffi::vdso_getcpu_fn = ffi::vdso_getcpu_stub;

#[allow(non_upper_case_globals)]
pub static mut gettimeofday: ffi::vdso_gettimeofday_fn = ffi::vdso_gettimeofday_stub;

#[allow(non_upper_case_globals)]
pub static mut time: ffi::vdso_time_fn = ffi::vdso_time_stub;
