/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use kvm_bindings::CpuId;

/// Controls which host-supported CPU features are exposed to a KVM guest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuidPolicy {
    /// Hide hardware random-number instructions (`RDRAND` and `RDSEED`).
    pub mask_hardware_random: bool,
    /// Hide Intel transactional-memory extensions.
    pub mask_tsx: bool,
    /// Hide AVX-512 instructions and their extended register state.
    pub mask_avx512: bool,
}

impl CpuidPolicy {
    /// A conservative policy for deterministic execution.
    pub const fn deterministic() -> Self {
        Self {
            mask_hardware_random: true,
            mask_tsx: true,
            mask_avx512: true,
        }
    }

    /// Exposes KVM's full host-supported CPUID table.
    pub const fn host_supported() -> Self {
        Self {
            mask_hardware_random: false,
            mask_tsx: false,
            mask_avx512: false,
        }
    }

    pub(crate) fn apply(self, cpuid: &mut CpuId) {
        for entry in cpuid.as_mut_slice() {
            match (entry.function, entry.index) {
                (1, 0) if self.mask_hardware_random => {
                    entry.ecx &= !bit(30); // RDRAND
                }
                (7, 0) => {
                    if self.mask_hardware_random {
                        entry.ebx &= !bit(18); // RDSEED
                    }
                    if self.mask_tsx {
                        entry.ebx &= !(bit(4) | bit(11)); // HLE, RTM
                        entry.edx &= !(bit(11) | bit(13) | bit(16));
                    }
                    if self.mask_avx512 {
                        entry.ebx &= !(bit(16)
                            | bit(17)
                            | bit(21)
                            | bit(26)
                            | bit(27)
                            | bit(28)
                            | bit(30)
                            | bit(31));
                        entry.ecx &= !(bit(1) | bit(6) | bit(11) | bit(12) | bit(14));
                        entry.edx &= !(bit(2) | bit(3) | bit(8) | bit(23));
                    }
                }
                (7, 1) if self.mask_avx512 => {
                    entry.eax &= !bit(5); // AVX512_BF16
                }
                (0xd, 0) if self.mask_avx512 => {
                    // Opmask, ZMM_Hi256, and Hi16_ZMM user-state components.
                    entry.eax &= !(bit(5) | bit(6) | bit(7));
                }
                _ => {}
            }
        }
    }
}

impl Default for CpuidPolicy {
    fn default() -> Self {
        Self::deterministic()
    }
}

const fn bit(index: u32) -> u32 {
    1_u32 << index
}

#[cfg(test)]
mod tests {
    use kvm_bindings::CpuId;
    use kvm_bindings::kvm_cpuid_entry2;

    use super::*;

    fn entry(function: u32, index: u32) -> kvm_cpuid_entry2 {
        kvm_cpuid_entry2 {
            function,
            index,
            eax: u32::MAX,
            ebx: u32::MAX,
            ecx: u32::MAX,
            edx: u32::MAX,
            ..Default::default()
        }
    }

    #[test]
    fn deterministic_policy_masks_nondeterministic_features() {
        let mut cpuid =
            CpuId::from_entries(&[entry(1, 0), entry(7, 0), entry(7, 1), entry(0xd, 0)]).unwrap();

        CpuidPolicy::deterministic().apply(&mut cpuid);

        let entries = cpuid.as_slice();
        assert_eq!(entries[0].ecx & bit(30), 0);
        assert_eq!(entries[1].ebx & bit(18), 0);
        assert_eq!(entries[1].ebx & (bit(4) | bit(11)), 0);
        assert_eq!(entries[1].edx & (bit(11) | bit(13) | bit(16)), 0);
        assert_eq!(entries[1].ebx & bit(16), 0);
        assert_eq!(entries[1].ecx & bit(1), 0);
        assert_eq!(entries[1].edx & bit(23), 0);
        assert_eq!(entries[2].eax & bit(5), 0);
        assert_eq!(entries[3].eax & (bit(5) | bit(6) | bit(7)), 0);
    }

    #[test]
    fn host_supported_policy_preserves_entries() {
        let entries = [entry(1, 0), entry(7, 0), entry(7, 1), entry(0xd, 0)];
        let mut cpuid = CpuId::from_entries(&entries).unwrap();

        CpuidPolicy::host_supported().apply(&mut cpuid);

        assert_eq!(cpuid.as_slice(), entries);
    }
}
