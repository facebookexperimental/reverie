/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! CPL3 CPUID fault admission and instruction retirement. The existing Tool
//! callback owns the result and any logical-time charge; this module adds none.

use kvm_bindings::Msrs;
use kvm_bindings::kvm_msr_entry;
use kvm_bindings::kvm_regs;
use kvm_ioctls::Kvm;
use kvm_ioctls::VcpuFd;
use reverie::CpuIdResult;

use crate::Error;
use crate::Result;

const PLATFORM_INFO: u32 = 0xce;
const MISC_FEATURES_ENABLES: u32 = 0x140;
const SUPPORT: u64 = 1 << 31;
const ENABLE: u64 = 1;

#[derive(Clone, Copy)]
struct MsrState {
    platform: u64,
    features: u64,
}

/// State belongs to one real vCPU, never to a process snapshot or a Tool type.
/// Retain the original before the first write, including after a failed rollback.
#[derive(Default)]
pub(crate) struct Interception {
    original: Option<MsrState>,
    enabled: bool,
}

fn entry(index: u32, data: u64) -> kvm_msr_entry {
    kvm_msr_entry {
        index,
        data,
        ..Default::default()
    }
}

fn exact_count(operation: &str, expected: usize, actual: usize) -> Result<()> {
    if actual != expected {
        return Err(Error::UnexpectedVcpuExit(format!(
            "CPUID interception {operation}: transferred {actual} of {expected} MSRs"
        )));
    }
    Ok(())
}

fn read_state(vcpu: &VcpuFd) -> Result<MsrState> {
    let mut values =
        Msrs::from_entries(&[entry(PLATFORM_INFO, 0), entry(MISC_FEATURES_ENABLES, 0)])
            .expect("fixed CPUID MSR read fits");
    exact_count("read", 2, vcpu.get_msrs(&mut values)?)?;
    Ok(MsrState {
        platform: values.as_slice()[0].data,
        features: values.as_slice()[1].data,
    })
}

fn write_one(vcpu: &VcpuFd, index: u32, value: u64) -> Result<()> {
    let values = Msrs::from_entries(&[entry(index, value)]).expect("one CPUID MSR write fits");
    exact_count(&format!("write {index:#x}"), 1, vcpu.set_msrs(&values)?)
}

impl Interception {
    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn configure(&mut self, vcpu: &VcpuFd, enabled: bool) -> Result<()> {
        if !enabled {
            // A fresh tool-less backend never requests this optional feature.
            return self.restore(vcpu);
        }
        if self.enabled {
            return self.verify(vcpu);
        }
        if self.original.is_some() {
            return Err(Error::UnexpectedVcpuExit(
                "CPUID interception has unresolved MSR restoration".to_owned(),
            ));
        }
        let kvm = Kvm::new()?;
        if !kvm
            .get_msr_feature_index_list()?
            .as_slice()
            .contains(&PLATFORM_INFO)
        {
            return Err(Error::UnexpectedVcpuExit(
                "CPUID interception unsupported: PLATFORM_INFO feature MSR absent".to_owned(),
            ));
        }
        let mut feature =
            Msrs::from_entries(&[entry(PLATFORM_INFO, 0)]).expect("one feature MSR fits");
        exact_count("feature read", 1, kvm.get_msrs(&mut feature)?)?;
        if feature.as_slice()[0].data & SUPPORT == 0 {
            return Err(Error::UnexpectedVcpuExit(
                "CPUID interception unsupported: fault support bit absent".to_owned(),
            ));
        }
        let original = read_state(vcpu)?;
        if original.features & ENABLE != 0 {
            return Err(Error::UnexpectedVcpuExit(
                "CPUID interception was armed without an owning Tool consumer".to_owned(),
            ));
        }
        self.original = Some(original);
        let admission: Result<()> = (|| {
            write_one(vcpu, PLATFORM_INFO, original.platform | SUPPORT)?;
            write_one(vcpu, MISC_FEATURES_ENABLES, original.features | ENABLE)?;
            let actual = read_state(vcpu)?;
            if actual.platform != (original.platform | SUPPORT)
                || actual.features != (original.features | ENABLE)
            {
                return Err(Error::UnexpectedVcpuExit(
                    "CPUID interception admission readback differs".to_owned(),
                ));
            }
            Ok(())
        })();
        if let Err(error) = admission {
            let restored = self.restore(vcpu);
            return Err(error.with_cleanup(restored.err().into_iter().collect()));
        }
        self.enabled = true;
        Ok(())
    }

    pub(crate) fn verify(&self, vcpu: &VcpuFd) -> Result<()> {
        let original = self.original.ok_or_else(|| {
            Error::UnexpectedVcpuExit("CPUID interception has no admitted MSR owner".to_owned())
        })?;
        let actual = read_state(vcpu)?;
        if !self.enabled
            || actual.platform != (original.platform | SUPPORT)
            || actual.features != (original.features | ENABLE)
        {
            return Err(Error::UnexpectedVcpuExit(
                "CPUID interception state changed after admission".to_owned(),
            ));
        }
        Ok(())
    }

    fn restore(&mut self, vcpu: &VcpuFd) -> Result<()> {
        let Some(original) = self.original else {
            return Ok(());
        };
        self.enabled = false;
        let mut errors = Vec::new();
        // No guest may resume after any failure. Still attempt both original
        // values and readback, retaining every error instead of overwriting one.
        for (index, value) in [
            (MISC_FEATURES_ENABLES, original.features),
            (PLATFORM_INFO, original.platform),
        ] {
            if let Err(error) = write_one(vcpu, index, value) {
                errors.push(error);
            }
        }
        match read_state(vcpu) {
            Ok(actual)
                if actual.platform == original.platform && actual.features == original.features => {
            }
            Ok(_) => errors.push(Error::UnexpectedVcpuExit(
                "CPUID interception restoration readback differs".to_owned(),
            )),
            Err(error) => errors.push(error),
        }
        if errors.is_empty() {
            self.original = None;
        }
        Error::combine(errors)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Instruction {
    pub(crate) length: u8,
}

/// CPUID ignores ordinary legacy/REX prefixes. LOCK is invalid. Fetch no
/// sixteenth byte and no byte after the completed two-byte opcode.
pub(crate) fn decode(mut fetch: impl FnMut(u8) -> Option<u8>) -> Option<Instruction> {
    let mut length = 0;
    let mut next = || {
        if length == 15 {
            return None;
        }
        let byte = fetch(length)?;
        length += 1;
        Some(byte)
    };
    loop {
        match next()? {
            0x66 | 0x67 | 0xf2 | 0xf3 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x40..=0x4f => {
                continue;
            }
            0x0f if next()? == 0xa2 => break,
            _ => return None,
        }
    }
    Some(Instruction { length })
}

pub(crate) fn result_registers(
    mut original: kvm_regs,
    instruction: Instruction,
    result: CpuIdResult,
) -> Option<kvm_regs> {
    original.rip = original.rip.checked_add(u64::from(instruction.length))?;
    original.rflags &= !(1 << 16); // Retirement clears the exception frame's RF.
    original.rax = u64::from(result.eax);
    original.rbx = u64::from(result.ebx);
    original.rcx = u64::from(result.ecx);
    original.rdx = u64::from(result.edx);
    Some(original)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpuid_decoder_fetches_exact_legal_instruction_and_refuses_invalid_forms() {
        for prefix in [
            0x66, 0x67, 0xf2, 0xf3, 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x40, 0x4f,
        ] {
            let bytes = [prefix, 0x0f, 0xa2];
            assert_eq!(
                decode(|i| bytes.get(usize::from(i)).copied()),
                Some(Instruction { length: 3 })
            );
        }
        let mut visits = Vec::new();
        assert_eq!(
            decode(|i| {
                visits.push(i);
                [0x0f, 0xa2].get(usize::from(i)).copied()
            }),
            Some(Instruction { length: 2 })
        );
        assert_eq!(visits, [0, 1]);
        let mut longest = vec![0x66; 13];
        longest.extend_from_slice(&[0x0f, 0xa2]);
        assert_eq!(
            decode(|i| longest.get(usize::from(i)).copied()),
            Some(Instruction { length: 15 })
        );
        longest.insert(0, 0x66);
        assert_eq!(decode(|i| longest.get(usize::from(i)).copied()), None);
        for bytes in [
            &[0xf0, 0x0f, 0xa2][..],
            &[0x0f, 0x31],
            &[0x0f, 0x01, 0xf9],
            &[0x0f],
            &[0xed],
        ] {
            assert_eq!(decode(|i| bytes.get(usize::from(i)).copied()), None);
        }
    }

    #[test]
    fn cpuid_result_zero_extends_all_outputs_and_preserves_other_user_state() {
        let original = kvm_regs {
            rax: u64::MAX,
            rbx: u64::MAX,
            rcx: u64::MAX,
            rdx: u64::MAX,
            rsi: 5,
            rdi: 6,
            rsp: 7,
            rbp: 8,
            r8: 9,
            r9: 10,
            r10: 11,
            r11: 12,
            r12: 13,
            r13: 14,
            r14: 15,
            r15: 16,
            rip: 0x200000,
            rflags: 0x1_02d7,
        };
        let mut expected = original;
        expected.rax = 0xf1234567;
        expected.rbx = 0xe2345678;
        expected.rcx = 0xd3456789;
        expected.rdx = 0xc456789a;
        expected.rip += 15;
        expected.rflags &= !(1 << 16);
        let result = CpuIdResult {
            eax: 0xf1234567,
            ebx: 0xe2345678,
            ecx: 0xd3456789,
            edx: 0xc456789a,
        };
        assert_eq!(
            result_registers(original, Instruction { length: 15 }, result),
            Some(expected)
        );
        assert!(
            result_registers(
                kvm_regs {
                    rip: u64::MAX,
                    ..original
                },
                Instruction { length: 2 },
                result
            )
            .is_none()
        );
    }

    #[test]
    fn actual_partial_msr_transfers_are_refused_with_exact_counts() {
        let backend = crate::KvmBackend::new(16 * 1024 * 1024).expect("actual KVM is mandatory");
        let mut entries =
            Msrs::from_entries(&[entry(PLATFORM_INFO, 0), entry(u32::MAX, 0)]).unwrap();
        let actual = backend.vcpu.get_msrs(&mut entries).unwrap();
        assert_eq!(
            actual, 1,
            "the real second unsupported MSR must stop this read"
        );
        let error = exact_count("read", 2, actual).unwrap_err();
        assert!(
            matches!(error,Error::UnexpectedVcpuExit(ref message) if message=="CPUID interception read: transferred 1 of 2 MSRs")
        );
        let error = write_one(&backend.vcpu, u32::MAX, 0).unwrap_err();
        assert!(
            matches!(error,Error::UnexpectedVcpuExit(ref message) if message=="CPUID interception write 0xffffffff: transferred 0 of 1 MSRs")
        );
        eprintln!("actual rejected MSR transfers: read 1/2; write 0/1");
    }

    #[test]
    fn actual_cpuid_interception_is_owned_and_restores_original_msr_state() {
        let backend = crate::KvmBackend::new(16 * 1024 * 1024).expect("actual KVM is mandatory");
        let before = read_state(&backend.vcpu).unwrap();
        let mut owner = Interception::default();
        owner.configure(&backend.vcpu, true).unwrap();
        assert!(owner.enabled());
        owner.verify(&backend.vcpu).unwrap();
        let mut stranger = Interception::default();
        let error = stranger.configure(&backend.vcpu, true).unwrap_err();
        assert!(matches!(error, Error::UnexpectedVcpuExit(ref message)
            if message == "CPUID interception was armed without an owning Tool consumer"));
        assert!(!stranger.enabled());
        assert!(stranger.original.is_none());
        owner.verify(&backend.vcpu).unwrap();
        let independent = crate::KvmBackend::new(16 * 1024 * 1024).unwrap();
        assert_eq!(read_state(&independent.vcpu).unwrap().features & ENABLE, 0);
        owner.verify(&backend.vcpu).unwrap();
        // Change the real vCPU behind its owner: a stale admission must fail,
        // retain its original state, and still support explicit restoration.
        write_one(&backend.vcpu, MISC_FEATURES_ENABLES, before.features).unwrap();
        let error = owner.configure(&backend.vcpu, true).unwrap_err();
        assert!(matches!(error, Error::UnexpectedVcpuExit(ref message)
            if message == "CPUID interception state changed after admission"));
        assert!(owner.original.is_some());
        owner.configure(&backend.vcpu, false).unwrap();
        assert!(!owner.enabled());
        assert!(owner.original.is_none());
        let after = read_state(&backend.vcpu).unwrap();
        assert_eq!(
            (after.platform, after.features),
            (before.platform, before.features)
        );
        owner.configure(&backend.vcpu, false).unwrap();
    }
}
