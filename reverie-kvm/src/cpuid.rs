/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use kvm_bindings::CpuId;
use kvm_bindings::kvm_cpuid_entry2;

use crate::Error;
use crate::Result;

/// Controls the CPU identity and features exposed to a KVM guest.
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
    /// A fixed x86-64-v2 baseline for deterministic execution.
    // TODO-HUMAN-REVIEW(PR-129): Review the fixed KVM CPUID profile API.
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

    pub(crate) fn apply(self, cpuid: &mut CpuId) -> Result<()> {
        if self == Self::deterministic() {
            let fixed = deterministic_cpuid_table();
            validate_required_features(cpuid, &fixed)?;
            *cpuid = fixed;
        }
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
        Ok(())
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

fn deterministic_cpuid_table() -> CpuId {
    let entries = DETERMINISTIC_STANDARD_CPUIDS
        .iter()
        .enumerate()
        .filter(|(_, registers)| **registers != [0; 4])
        .map(|(function, registers)| cpuid_entry(function as u32, *registers))
        .chain(
            DETERMINISTIC_EXTENDED_CPUIDS
                .iter()
                .enumerate()
                .filter(|(_, registers)| **registers != [0; 4])
                .map(|(offset, registers)| cpuid_entry(0x8000_0000 + offset as u32, *registers)),
        )
        .collect::<Vec<_>>();
    CpuId::from_entries(&entries).expect("fixed CPUID profile must fit in KVM's table")
}

#[derive(Clone, Copy)]
enum FeatureRegister {
    Ebx,
    Ecx,
    Edx,
}

impl FeatureRegister {
    fn value(self, entry: &kvm_cpuid_entry2) -> u32 {
        match self {
            Self::Ebx => entry.ebx,
            Self::Ecx => entry.ecx,
            Self::Edx => entry.edx,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Ebx => "ebx",
            Self::Ecx => "ecx",
            Self::Edx => "edx",
        }
    }
}

fn validate_required_features(host: &CpuId, fixed: &CpuId) -> Result<()> {
    for (function, index, register) in [
        (1, 0, FeatureRegister::Ecx),
        (1, 0, FeatureRegister::Edx),
        (7, 0, FeatureRegister::Ebx),
        (7, 0, FeatureRegister::Ecx),
        (7, 0, FeatureRegister::Edx),
        (0x8000_0001, 0, FeatureRegister::Ecx),
        (0x8000_0001, 0, FeatureRegister::Edx),
    ] {
        let required = fixed
            .as_slice()
            .iter()
            .find(|entry| entry.function == function && entry.index == index)
            .map_or(0, |entry| register.value(entry));
        if required == 0 {
            continue;
        }
        let supported = host
            .as_slice()
            .iter()
            .find(|entry| entry.function == function && entry.index == index)
            .map_or(0, |entry| register.value(entry));
        let missing = required & !supported;
        if missing != 0 {
            return Err(Error::UnsupportedCpuidProfile(format!(
                "leaf {function:#x}, {}, missing bits {missing:#010x}",
                register.name()
            )));
        }
    }
    Ok(())
}

fn cpuid_entry(function: u32, [eax, ebx, ecx, edx]: [u32; 4]) -> kvm_cpuid_entry2 {
    kvm_cpuid_entry2 {
        function,
        eax,
        ebx,
        ecx,
        edx,
        ..Default::default()
    }
}

// This starts from Detcore's fixed profile and narrows it to x86-64-v2 and
// backend-safe features. KVM additionally applies the selected masks after
// installing the table.
const DETERMINISTIC_STANDARD_CPUIDS: &[[u32; 4]] = &[
    [0x0000_000d, 0x756e_6547, 0x6c65_746e, 0x4965_6e69],
    [
        0x0000_0663,
        0x0000_0800,
        bit(0) | bit(9) | bit(13) | bit(19) | bit(20) | bit(23),
        0x078b_fbfd,
    ],
    [0x0000_0001, 0x0000_0000, 0x0000_004d, 0x002c_307d],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0120, 0x01c0_003f, 0x0000_003f, 0x0000_0001],
    [0x0000_0000, 0x0000_0000, 0x0000_0003, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0001, 0x0000_0100, 0x0000_0001],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
];

const DETERMINISTIC_EXTENDED_CPUIDS: &[[u32; 4]] = &[
    [0x8000_000a, 0x756e_6547, 0x6c65_746e, 0x4965_6e69],
    [0x0000_0663, 0x0000_0000, 0x0000_0001, 0x2010_0800],
    [0x554d_4551, 0x7269_5620, 0x6c61_7574, 0x5543_5020],
    [0x7265_7620, 0x6e6f_6973, 0x352e_3220, 0x0000_002b],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x01ff_01ff, 0x01ff_01ff, 0x4002_0140, 0x4002_0140],
    [0x0000_0000, 0x4200_4200, 0x0200_8140, 0x0080_8140],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_3028, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
    [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000],
];
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
    fn deterministic_policy_replaces_host_identity_and_features() {
        let mut minimum_host_entries = [
            entry(0, 0),
            entry(1, 0),
            entry(7, 0),
            entry(7, 1),
            entry(0xd, 0),
            entry(0x8000_0000, 0),
            entry(0x8000_0001, 0),
        ];
        minimum_host_entries[1].ecx = DETERMINISTIC_STANDARD_CPUIDS[1][2];
        minimum_host_entries[1].edx = DETERMINISTIC_STANDARD_CPUIDS[1][3];
        minimum_host_entries[2].ebx = 0;
        minimum_host_entries[2].ecx = 0;
        minimum_host_entries[2].edx = 0;
        minimum_host_entries[6].ecx = DETERMINISTIC_EXTENDED_CPUIDS[1][2];
        minimum_host_entries[6].edx = DETERMINISTIC_EXTENDED_CPUIDS[1][3];
        let mut first_host = CpuId::from_entries(&minimum_host_entries).unwrap();
        let mut superset_host_entries = minimum_host_entries;
        for entry in &mut superset_host_entries {
            entry.ecx |= bit(31);
            entry.edx |= bit(31);
        }
        let mut second_host = CpuId::from_entries(&superset_host_entries).unwrap();

        CpuidPolicy::deterministic().apply(&mut first_host).unwrap();
        CpuidPolicy::deterministic()
            .apply(&mut second_host)
            .unwrap();

        assert_eq!(first_host, second_host);
        let entries = first_host.as_slice();
        assert_eq!(
            entries.len(),
            DETERMINISTIC_STANDARD_CPUIDS
                .iter()
                .chain(DETERMINISTIC_EXTENDED_CPUIDS)
                .filter(|registers| **registers != [0; 4])
                .count()
        );
        let leaf = |function| {
            entries
                .iter()
                .find(|entry| entry.function == function)
                .unwrap()
        };
        assert_eq!(leaf(0).eax, 0x0000_000d);
        assert_eq!(leaf(0).ebx, u32::from_le_bytes(*b"Genu"));
        assert_eq!(leaf(0).ecx, u32::from_le_bytes(*b"ntel"));
        assert_eq!(leaf(0).edx, u32::from_le_bytes(*b"ineI"));
        assert_eq!(leaf(1).eax, 0x0000_0663);
        assert_eq!(leaf(1).ecx & bit(30), 0);
        assert!(entries.iter().all(|entry| entry.function != 7));
        assert!(entries.iter().all(|entry| entry.function != 0xd));
        assert_eq!(leaf(0x8000_0000).eax, 0x8000_000a);
        assert_eq!(leaf(0x8000_0000).ebx, u32::from_le_bytes(*b"Genu"));
        assert_eq!(leaf(0x8000_0000).ecx, u32::from_le_bytes(*b"ntel"));
        assert_eq!(leaf(0x8000_0000).edx, u32::from_le_bytes(*b"ineI"));
    }

    #[test]
    fn deterministic_policy_rejects_missing_required_features() {
        let mut unsupported = CpuId::from_entries(&[
            kvm_cpuid_entry2 {
                function: 1,
                ..Default::default()
            },
            kvm_cpuid_entry2 {
                function: 0x8000_0001,
                ..Default::default()
            },
        ])
        .unwrap();

        let error = CpuidPolicy::deterministic()
            .apply(&mut unsupported)
            .unwrap_err();

        assert!(matches!(error, Error::UnsupportedCpuidProfile(_)));
    }

    #[test]
    fn host_supported_policy_preserves_entries() {
        let entries = [
            entry(0, 0),
            entry(1, 0),
            entry(7, 0),
            entry(7, 1),
            entry(0xd, 0),
        ];
        let mut cpuid = CpuId::from_entries(&entries).unwrap();

        CpuidPolicy::host_supported().apply(&mut cpuid).unwrap();

        assert_eq!(cpuid.as_slice(), entries);
    }
}
