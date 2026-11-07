/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! rdtsc/rdtscp helpers. x86_64 is the only architecture where we
//! can intercept these instructions; the request/result vocabulary
//! itself is plain data shared by every architecture, so Tools can
//! name it unconditionally. Other architectures never receive these
//! events (admission refuses the subscription).

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::__rdtscp;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_rdtsc;
#[cfg(target_arch = "x86_64")]
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
    /// Read the current tsc/tscp value. Off x86_64 there is no
    /// counter to read and no event is ever delivered, so this
    /// returns zeros; it exists so the vocabulary compiles.
    pub fn new(request: Rdtsc) -> RdtscResult {
        #[cfg(target_arch = "x86_64")]
        {
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
        #[cfg(not(target_arch = "x86_64"))]
        {
            RdtscResult {
                tsc: 0,
                aux: (request == Rdtsc::Tscp).then_some(0),
            }
        }
    }
}
