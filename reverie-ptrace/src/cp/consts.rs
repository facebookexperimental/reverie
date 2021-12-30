/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 * Copyright (c) 2020-, Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/// A page that is reserved by Reverie in every guest process.
pub const PRIVATE_PAGE_OFFSET: u64 = 0x7000_0000;

/// trampoline data from private pages
pub const TRAMPOLINE_BASE: u64 = PRIVATE_PAGE_OFFSET;
pub const TRAMPOLINE_SIZE: usize = 0x1000;

/// total private page size
pub const PRIVATE_PAGE_SIZE: usize = TRAMPOLINE_SIZE;
