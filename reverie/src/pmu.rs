/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Processor-specific PMU event settings shared by execution backends.
//!
//! This module contains the x86 family/model table. It does not inspect the
//! host CPU, open a counter, or apply timer-policy overrides.

const AMD_RCB_EVENT: u64 = 0x5100d1;
const AMD_DEFAULT_SKID_MARGIN: u64 = 10_000;
const AMD_EPYC_9D85_SKID_MARGIN: u64 = 1_000;

/// A raw retired conditional branch event and its default ptrace timer margin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PmuProfile {
    rcb_event: u64,
    skid_margin: u64,
}

impl PmuProfile {
    /// Looks up the existing x86 PMU profile for a CPUID family and model.
    ///
    /// Returns `None` when the family/model pair is not in the profile table.
    /// This lookup does not validate the CPU vendor or counter availability;
    /// callers must establish those before using the raw event.
    pub fn for_family_model(family_id: u8, model_id: u8) -> Option<Self> {
        // based on rr's PerfCounters_x86.h and PerfCounters.cc
        let (rcb_event, skid_margin) = match family_id {
            // Intel
            0x06 => match model_id {
                0x1A | 0x1E | 0x2E => (0x5101c4, 100),        // Intel Nehalem
                0x25 | 0x2C | 0x2F => (0x5101c4, 100),        // Intel Westmere
                0x2A | 0x2D | 0x3E => (0x5101c4, 100),        // Intel Sandy Bridge
                0x3A => (0x5101c4, 100),                      // Intel Ivy Bridge
                0x3C | 0x3F | 0x45 | 0x46 => (0x5101c4, 100), // Intel Haswell
                0x3D | 0x47 | 0x4F | 0x56 => (0x5101c4, 100), // Intel Broadwell
                0x4E | 0x55 | 0x5E => (0x5101c4, 100),        // Intel Skylake
                0x8E | 0x9E => (0x5101c4, 100),               // Intel Kabylake
                0xA5 | 0xA6 => (0x5101c4, 100),               // Intel Cometlake
                0x8D => (0x5101c4, 100),                      // Intel Tiger Lake
                0x9A => (0x5101c4, 125),                      // Intel Alder Lake
                0x8F => (0x5101c4, 125),                      // Intel Sapphire Rapids
                0x86 => (0x5101c4, 100),                      // Intel Icelake
                _ => return None,
            },
            // Turin EPYC family 1Ah model 11h has p99 skid of 384 RCBs. A 1K
            // performance margin avoids excessive single stepping. Rare larger
            // overshoots are reported and delivered at the observed counter.
            0x1A if model_id == 0x11 => (AMD_RCB_EVENT, AMD_EPYC_9D85_SKID_MARGIN),
            // Other Zen CPUs keep rr's 10K guard because they have exhibited rare large skid.
            0x17 | 0x19 | 0x1A => (AMD_RCB_EVENT, AMD_DEFAULT_SKID_MARGIN),
            _ => return None,
        };

        Some(Self {
            rcb_event,
            skid_margin,
        })
    }

    /// Returns the raw retired conditional branch event selector.
    pub fn raw_rcb_event(&self) -> u64 {
        self.rcb_event
    }

    /// Returns the processor's default ptrace timer skid margin in branch events.
    ///
    /// This value excludes environment and programmatic timer-policy overrides.
    pub fn default_skid_margin(&self) -> u64 {
        self.skid_margin
    }
}
