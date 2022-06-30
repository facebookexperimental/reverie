/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! rdtsc/rdtscp helpers

use core::arch::x86_64::__rdtscp;
use core::arch::x86_64::_rdtsc;
use core::mem::MaybeUninit;
use serde::Deserialize;
use serde::Serialize;

/// Rdtsc/Rdtscp request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rdtsc {
    /// Rdtsc
    Tsc,
    /// Rdtscp
    Tscp,
}

/// Result returned by [`Tool::handle_rdtsc_event`].
///
/// [`Tool::handle_rdtsc_event`]: crate::Tool::handle_rdtsc_event
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdtscResult {
    /// tsc counter returned from rdtsc/rdtscp
    pub tsc: u64,
    /// aux (TSC_AUX) returned from rdtscp
    /// for rdtsc this should be None.
    pub aux: Option<u32>,
}

impl RdtscResult {
    /// read current tsc/tscp value
    pub fn new(request: Rdtsc) -> RdtscResult {
        match request {
            Rdtsc::Tsc => RdtscResult {
                tsc: unsafe { _rdtsc() },
                aux: None,
            },
            Rdtsc::Tscp => {
                let mut aux_val = MaybeUninit::uninit();
                let tsc = unsafe { __rdtscp(aux_val.as_mut_ptr()) };
                RdtscResult {
                    tsc,
                    aux: Some(unsafe { aux_val.assume_init() }),
                }
            }
        }
    }
}
