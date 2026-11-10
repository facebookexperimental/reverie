/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The vCPU's IA32_XSS, set once to the host's value.
//!
//! While a vCPU's IA32_XSS differs from the host's, KVM writes the MSR twice
//! around every guest entry: the vCPU's value before entering the guest and
//! the host's after the exit (`kvm_load_xfeatures`, Linux
//! arch/x86/kvm/x86.c). On AMD this happens even when the vCPU's CPUID table
//! hides XSAVES: SVM cannot disable XSAVES alone, so KVM treats it as enabled
//! whenever the host has it and the vCPU has XSAVE
//! (`svm_vcpu_after_set_cpuid`, arch/x86/kvm/svm/svm.c). A vCPU starts with
//! IA32_XSS = 0 and a host with CET state components does not, so every entry
//! paid for both writes. [`match_host_xss`] gives the vCPU the host's value
//! once, before its first entry, and KVM then skips both.
//!
//! User space cannot read the host's IA32_XSS, so the value is shown equal to
//! it from two rows user space can read:
//! - `hardware`: CPUID.(EAX=0DH,ECX=1):ECX:EDX on the host, the IA32_XSS bits
//!   the processor supports. The kernel builds its IA32_XSS from a subset of
//!   them (`fpu__init_system_xstate` and `fpu__init_cpu_xstate`,
//!   arch/x86/kernel/fpu/xstate.c).
//! - `kvm`: the same subleaf of KVM_GET_SUPPORTED_CPUID. KVM reports the
//!   processor's bits ANDed with its supported XSS, which is the host's
//!   IA32_XSS (read when KVM loaded) ANDed with the bits KVM can virtualize
//!   (`kvm_x86_vendor_init` in x86.c, `__do_cpuid_func` in cpuid.c).
//!
//! So `kvm` is a subset of the host's value, which is a subset of `hardware`:
//! when `kvm` equals `hardware`, all three are equal. Otherwise the vCPU keeps
//! IA32_XSS = 0, and KVM keeps switching it as before.
//!
//! The value is exactly both CET state components, IA32_XSS bits 11 and 12
//! (CET_U | CET_S), or nothing is set. These are the only bits KVM lets a
//! vCPU's IA32_XSS hold (KVM_SUPPORTED_XSS) and the only ones whose effect on a
//! guest was reviewed. KVM v7.1.3 drops partial CET support itself
//! (`kvm_setup_xss_caps`, arch/x86/kvm/x86.c), so a host that qualifies always
//! has both; [`decide`] requires both rather than relying on that, so a row
//! with one of them alone keeps 0. KVM's guest FPU state always carries both
//! components when the host supports them (`guest_default_cfg`,
//! arch/x86/kernel/fpu/xstate.c), and KVM loads it before entering the guest
//! and saves it before returning to user space (`fpu_swap_kvm_fpstate`,
//! arch/x86/kernel/fpu/core.c), so an XSAVES or XRSTORS that guest code runs on
//! them reaches only the vCPU's own copy. A KVM that accepts further bits keeps
//! the old behaviour here until those are reviewed as well.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use kvm_bindings::CpuId;
use kvm_bindings::Msrs;
use kvm_bindings::kvm_msr_entry;
use kvm_ioctls::VcpuFd;

use crate::Error;
use crate::Result;

const MSR_IA32_XSS: u32 = 0xda0;
/// CPUID.(EAX=0DH,ECX=1):EAX bit 3, XSAVES/XRSTORS and IA32_XSS.
const XSAVES: u32 = 1 << 3;
/// IA32_XSS bit 11, the CET user state component (IA32_U_CET, IA32_PL3_SSP).
const CET_USER: u64 = 1 << 11;
/// IA32_XSS bit 12, the CET supervisor state component (IA32_PL0_SSP through
/// IA32_PL2_SSP).
const CET_SUPERVISOR: u64 = 1 << 12;
/// The one IA32_XSS value [`decide`] gives a vCPU: both CET components and
/// nothing else.
const REVIEWED_COMPONENTS: u64 = CET_USER | CET_SUPERVISOR;

/// The registers of CPUID.(EAX=0DH,ECX=1) that [`decide`] reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct XsaveSubleaf {
    eax: u32,
    ecx: u32,
    edx: u32,
}

impl XsaveSubleaf {
    /// The subleaf's row in a CPUID table, if it has one.
    pub(crate) fn of_table(table: &CpuId) -> Option<Self> {
        table
            .as_slice()
            .iter()
            .find(|entry| entry.function == 0xd && entry.index == 1)
            .map(|entry| Self {
                eax: entry.eax,
                ecx: entry.ecx,
                edx: entry.edx,
            })
    }

    /// The subleaf as the host processor reports it.
    fn of_host() -> Self {
        let row = core::arch::x86_64::__cpuid_count(0xd, 1);
        Self {
            eax: row.eax,
            ecx: row.ecx,
            edx: row.edx,
        }
    }

    /// The IA32_XSS state components the row lists.
    fn components(self) -> u64 {
        u64::from(self.ecx) | (u64::from(self.edx) << 32)
    }
}

/// Why a vCPU keeps IA32_XSS = 0.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Keep {
    /// The processor supports no IA32_XSS component, so the host's IA32_XSS
    /// is 0 as well and KVM never writes it.
    NoHostComponents,
    /// KVM_GET_SUPPORTED_CPUID has no CPUID.(EAX=0DH,ECX=1) row.
    NoKvmRow,
    /// KVM does not report every component the processor supports, so the
    /// host's IA32_XSS cannot be shown equal to KVM's value.
    Unproven { hardware: u64, kvm: u64 },
    /// KVM's row, which equals the processor's, is not exactly the two reviewed
    /// components (bits 11 and 12): it has another component, or it has only one
    /// of the two.
    Unreviewed { kvm: u64 },
    /// The vCPU's CPUID table lacks XSAVES or one of the components, so KVM
    /// would refuse the value.
    VcpuTable,
}

/// The IA32_XSS a new vCPU should have.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Decision {
    /// Both CET components, CET_U | CET_S, which is then exactly the host's
    /// IA32_XSS.
    Set(u64),
    /// Leave the vCPU's reset value, 0.
    Keep(Keep),
}

/// Decides from the host's CPUID.(EAX=0DH,ECX=1) row (`hardware`), KVM's
/// supported row (`kvm`) and the vCPU's own CPUID table row (`vcpu`). The
/// result is [`Decision::Set`] only when the processor's row and KVM's row are
/// equal and are exactly the two CET components, and the vCPU's table lists
/// XSAVES and both of them; anything else, one component alone included, keeps
/// 0.
pub(crate) fn decide(
    hardware: XsaveSubleaf,
    kvm: Option<XsaveSubleaf>,
    vcpu: Option<XsaveSubleaf>,
) -> Decision {
    let hardware = hardware.components();
    if hardware == 0 {
        return Decision::Keep(Keep::NoHostComponents);
    }
    let Some(kvm) = kvm else {
        return Decision::Keep(Keep::NoKvmRow);
    };
    let kvm = kvm.components();
    // KVM's value is a subset of the host's, which is a subset of the
    // processor's, so equality with the processor's proves it the host's.
    if kvm != hardware {
        return Decision::Keep(Keep::Unproven { hardware, kvm });
    }
    // Exactly the reviewed pair. KVM v7.1.3 drops partial CET support itself,
    // so a qualifying host reports both, but the pair is what was reviewed: a
    // row with one component alone, like one with another component, is refused.
    if kvm != REVIEWED_COMPONENTS {
        return Decision::Keep(Keep::Unreviewed { kvm });
    }
    // KVM accepts a host-initiated IA32_XSS write only if the vCPU's table
    // lists XSAVES and every component of the value (`kvm_set_msr_common`).
    match vcpu {
        Some(row) if row.eax & XSAVES != 0 && kvm & !row.components() == 0 => Decision::Set(kvm),
        _ => Decision::Keep(Keep::VcpuTable),
    }
}

/// What [`match_host_xss`] left in the vCPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    /// The vCPU holds the host's IA32_XSS.
    Set(u64),
    /// The vCPU keeps IA32_XSS = 0 because the decision said so.
    Kept(Keep),
    /// Setting the host's value failed and was reported, and the vCPU was then
    /// confirmed to hold IA32_XSS = 0, as it would without this module.
    Failed,
}

/// Whether this process has reported a failed IA32_XSS write.
static FAILURE_REPORTED: AtomicBool = AtomicBool::new(false);

/// Gives a new vCPU the host's IA32_XSS when [`decide`] shows it, before the
/// vCPU's first KVM_RUN and after its CPUID table is set (KVM checks the value
/// against that table). `kvm` is CPUID.(EAX=0DH,ECX=1) of
/// KVM_GET_SUPPORTED_CPUID and `vcpu_table` the table given to the vCPU.
///
/// If setting the value fails (the ioctl fails or writes short, or the register
/// reads back another value), the first such failure in a process is reported
/// on standard error, and the register is then read back and, if it is not 0,
/// written with 0, KVM's reset value. When 0 is confirmed the vCPU is as it
/// would be without this function and [`Outcome::Failed`] is returned. When 0
/// cannot be confirmed an error is returned, which stops the construction of
/// the backend before the vCPU can enter the guest.
pub(crate) fn match_host_xss(
    vcpu: &VcpuFd,
    kvm: Option<XsaveSubleaf>,
    vcpu_table: &CpuId,
) -> Result<Outcome> {
    let value = match decide(
        XsaveSubleaf::of_host(),
        kvm,
        XsaveSubleaf::of_table(vcpu_table),
    ) {
        Decision::Set(value) => value,
        Decision::Keep(reason) => return Ok(Outcome::Kept(reason)),
    };
    let failure = match write_xss(vcpu, value).and_then(|()| read_xss(vcpu)) {
        Ok(read) if read == value => return Ok(Outcome::Set(value)),
        Ok(read) => format!("KVM reads back {read:#x}"),
        Err(error) => error.to_string(),
    };
    if !FAILURE_REPORTED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "reverie-kvm: setting the vCPU's IA32_XSS to the host's value {value:#x} failed \
             ({failure}); falling back to 0, with which KVM switches IA32_XSS on every guest \
             entry (an error follows if 0 cannot be confirmed)"
        );
    }
    let restored = match read_xss(vcpu) {
        Ok(0) => Ok(()),
        _ => write_xss(vcpu, 0).and_then(|()| match read_xss(vcpu)? {
            0 => Ok(()),
            read => Err(Error::UnexpectedVcpuExit(format!(
                "IA32_XSS reads back {read:#x} after restoring 0"
            ))),
        }),
    };
    restored.map(|()| Outcome::Failed).map_err(|error| {
        Error::UnexpectedVcpuExit(format!(
            "IA32_XSS {value:#x} failed ({failure}) and 0 could not be confirmed: {error}"
        ))
    })
}

fn write_xss(vcpu: &VcpuFd, value: u64) -> Result<()> {
    let entries = Msrs::from_entries(&[kvm_msr_entry {
        index: MSR_IA32_XSS,
        data: value,
        ..Default::default()
    }])
    .expect("one MSR fits");
    match vcpu.set_msrs(&entries)? {
        1 => Ok(()),
        written => Err(Error::UnexpectedVcpuExit(format!(
            "KVM_SET_MSRS accepted {written} of 1 IA32_XSS writes"
        ))),
    }
}

fn read_xss(vcpu: &VcpuFd) -> Result<u64> {
    let mut entries = Msrs::from_entries(&[kvm_msr_entry {
        index: MSR_IA32_XSS,
        ..Default::default()
    }])
    .expect("one MSR fits");
    match vcpu.get_msrs(&mut entries)? {
        1 => Ok(entries.as_slice()[0].data),
        read => Err(Error::UnexpectedVcpuExit(format!(
            "KVM_GET_MSRS returned {read} of 1 IA32_XSS reads"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CET: u32 = (CET_USER | CET_SUPERVISOR) as u32;
    /// XSAVEOPT, XSAVEC, XGETBV with ECX=1 and XSAVES, as this subleaf's EAX
    /// reports them on current x86-64 processors.
    const EAX: u32 = 0xf;

    fn row(eax: u32, ecx: u32, edx: u32) -> XsaveSubleaf {
        XsaveSubleaf { eax, ecx, edx }
    }

    #[test]
    fn equal_cet_rows_give_the_host_value() {
        let host = row(EAX, CET, 0);
        assert_eq!(
            decide(host, Some(host), Some(host)),
            Decision::Set(CET_USER | CET_SUPERVISOR)
        );
        // KVM's EAX does not matter; only its components are compared.
        assert_eq!(
            decide(host, Some(row(0, CET, 0)), Some(host)),
            Decision::Set(CET_USER | CET_SUPERVISOR)
        );
    }

    #[test]
    fn a_processor_without_components_keeps_zero() {
        assert_eq!(
            decide(row(EAX, 0, 0), Some(row(EAX, 0, 0)), Some(row(EAX, 0, 0))),
            Decision::Keep(Keep::NoHostComponents)
        );
    }

    #[test]
    fn a_component_kvm_does_not_report_leaves_the_host_value_unproven() {
        // PASID (bit 10) or an architectural-LBR component (bit 15) may be in
        // the host's IA32_XSS without being in KVM's, and so may CET when KVM
        // cannot virtualize it.
        for (hardware, kvm) in [(CET | 1 << 10, CET), (CET | 1 << 15, CET), (CET, 0)] {
            assert_eq!(
                decide(
                    row(EAX, hardware, 0),
                    Some(row(EAX, kvm, 0)),
                    Some(row(EAX, hardware, 0))
                ),
                Decision::Keep(Keep::Unproven {
                    hardware: u64::from(hardware),
                    kvm: u64::from(kvm),
                })
            );
        }
        // A high component (EDX) counts the same way.
        assert_eq!(
            decide(
                row(EAX, CET, 1),
                Some(row(EAX, CET, 0)),
                Some(row(EAX, CET, 1))
            ),
            Decision::Keep(Keep::Unproven {
                hardware: u64::from(CET) | 1 << 32,
                kvm: u64::from(CET),
            })
        );
        assert_eq!(
            decide(row(EAX, CET, 0), None, Some(row(EAX, CET, 0))),
            Decision::Keep(Keep::NoKvmRow)
        );
    }

    #[test]
    fn components_outside_cet_are_not_given_even_when_proven() {
        for components in [1 << 10, CET | 1 << 8, 1 << 15] {
            let host = row(EAX, components, 0);
            assert_eq!(
                decide(host, Some(host), Some(host)),
                Decision::Keep(Keep::Unreviewed {
                    kvm: u64::from(components)
                })
            );
        }
        let high = row(EAX, CET, 1);
        assert_eq!(
            decide(high, Some(high), Some(high)),
            Decision::Keep(Keep::Unreviewed {
                kvm: u64::from(CET) | 1 << 32
            })
        );
    }

    /// KVM v7.1.3 drops partial CET support itself, so a real host never
    /// reports one CET component alone; `decide` still requires the reviewed
    /// pair and refuses a row with only CET_U or only CET_S.
    #[test]
    fn one_cet_component_alone_is_not_given_even_when_proven() {
        for component in [CET_USER, CET_SUPERVISOR] {
            let host = row(EAX, component as u32, 0);
            assert_eq!(
                decide(host, Some(host), Some(host)),
                Decision::Keep(Keep::Unreviewed { kvm: component }),
                "only bit {}",
                component.trailing_zeros()
            );
        }
    }

    #[test]
    fn a_vcpu_table_kvm_would_refuse_keeps_zero() {
        let host = row(EAX, CET, 0);
        for vcpu in [
            None,
            Some(row(EAX & !XSAVES, CET, 0)),
            Some(row(EAX, CET_USER as u32, 0)),
            Some(row(EAX, 0, 0)),
        ] {
            assert_eq!(
                decide(host, Some(host), vcpu),
                Decision::Keep(Keep::VcpuTable),
                "{vcpu:?}"
            );
        }
    }

    /// A new backend's vCPU holds what `decide` gives for this host: the host's
    /// IA32_XSS or the reset value 0. The test prints the decision and the value
    /// read back, so that a log shows the assertion ran. Without KVM it returns
    /// early only while REVERIE_REQUIRE_KVM is unset; with it set, a backend that
    /// cannot be created fails the test.
    #[test]
    fn a_new_vcpu_holds_the_decided_ia32_xss() {
        let backend = match crate::vm::KvmBackend::new(0x20_0000) {
            Ok(backend) => backend,
            Err(error) => {
                assert!(
                    std::env::var_os("REVERIE_REQUIRE_KVM").is_none(),
                    "KVM required: {error}"
                );
                eprintln!("skipping IA32_XSS KVM test: {error}");
                return;
            }
        };
        let kvm = kvm_ioctls::Kvm::new().unwrap();
        let supported = kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .unwrap();
        let table = backend
            .vcpu
            .get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .unwrap();
        let decision = decide(
            XsaveSubleaf::of_host(),
            XsaveSubleaf::of_table(&supported),
            XsaveSubleaf::of_table(&table),
        );
        let expected = match decision {
            Decision::Set(value) => value,
            Decision::Keep(_) => 0,
        };
        let read = read_xss(&backend.vcpu).unwrap();
        eprintln!(
            "IA32_XSS decision on this host: {decision:?}; the new vCPU reads back {read:#x}, expected {expected:#x}"
        );
        assert_eq!(read, expected);
    }
}
