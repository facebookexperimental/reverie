/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A signal handler starts with Linux's initial FPU state,
//! `XsaveImage::initialized_kvm`, which must cover every user state component
//! the guest enables: x87 and SSE state from the image, YMM state by
//! initialization.

use super::*;

/// The MXCSR_MASK field of an FXSAVE image taken on this CPU.
fn fxsave_mxcsr_mask() -> u32 {
    #[repr(C, align(16))]
    struct FxsaveArea([u8; 512]);
    let mut area = FxsaveArea([0; 512]);
    // SAFETY: FXSAVE writes exactly this 512-byte, 16-byte-aligned area.
    unsafe { std::arch::x86_64::_fxsave64(area.0.as_mut_ptr()) };
    u32::from_le_bytes(area.0[28..32].try_into().unwrap())
}

#[test]
fn the_initial_fpu_image_covers_every_component_the_guest_enables() {
    let mut backend =
        KvmBackend::new(16 * 1024 * 1024).expect("the initial FPU image test requires /dev/kvm");
    backend
        .install_static_elf(&minimal_test_elf(&[0xf4]), "/initial-fpu-state")
        .unwrap();
    // The guest enables x87, SSE and YMM state, the components signal frames
    // carry, and its CPUID table offers no other.
    let xcrs = backend.vcpu.get_xcrs().unwrap();
    let xcr0 = xcrs.xcrs[..xcrs.nr_xcrs as usize]
        .iter()
        .find(|xcr| xcr.xcr == 0)
        .unwrap()
        .value;
    assert_eq!(xcr0, crate::signal::FIXED_XFEATURES);
    let cpuid = backend.vcpu.get_cpuid2(KVM_MAX_CPUID_ENTRIES).unwrap();
    let extended = cpuid
        .as_slice()
        .iter()
        .find(|entry| entry.function == 0xd && entry.index == 0)
        .unwrap();
    assert_eq!(
        u64::from(extended.eax) | u64::from(extended.edx) << 32,
        crate::signal::FIXED_XFEATURES
    );
    // CR4.PKE is clear and XCR0 has no PKRU bit: the guest has no PKRU, so
    // nothing stands for Linux's pkru_write_default.
    assert_eq!(
        kvm_ioctls::VcpuFd::get_sregs(&backend.vcpu).unwrap().cr4 & (1 << 22),
        0
    );
    // The image marks x87 and SSE state present and leaves YMM state initial,
    // as the frame Linux builds after its reset says, in the standard format
    // KVM_SET_XSAVE requires (XCOMP_BV zero). Its MXCSR_MASK is the CPU's.
    let image = XsaveImage::initialized_kvm();
    assert_eq!(xstate_bv(&image), X87_AND_SSE);
    assert_eq!((image.region[130], image.region[131]), (0, 0));
    assert_eq!(image.region[7], fxsave_mxcsr_mask());
    // A vCPU state unlike the initial one in every part: x87 control word
    // 0x027f, TOP 6 and two valid registers, MXCSR 0x7f80 with the constant
    // mask 0xffbf, and a nonzero XMM5 and upper YMM5.
    let mut dirty = kvm_xsave::default();
    dirty.region[0] = 0x027f | 0x3000 << 16;
    dirty.region[1] = 0xc0;
    dirty.region[6] = 0x7f80;
    dirty.region[7] = 0xffbf;
    dirty.region[XMM5] = 0x1111_1111;
    dirty.region[UPPER_YMM5] = 0x3333_3333;
    dirty.region[128] = crate::signal::FIXED_XFEATURES as u32;
    // SAFETY: both images hold only the components the guest enables.
    unsafe { backend.vcpu.set_xsave(&dirty).unwrap() };
    let before = backend.vcpu.get_xsave().unwrap();
    assert_eq!(
        (before.region[6], before.region[UPPER_YMM5]),
        (0x7f80, 0x3333_3333)
    );
    // KVM_SET_XSAVE of the image installs all of it: copying x87 and SSE
    // state carries MXCSR and the mask, and YMM state, whose bit is clear,
    // is initialized, so KVM reports it absent and zero, and the frame of
    // a signal delivered next says the same.
    unsafe { backend.vcpu.set_xsave(&image).unwrap() };
    let installed = backend.vcpu.get_xsave().unwrap();
    assert_eq!(xstate_bv(&installed), X87_AND_SSE);
    assert_eq!(
        (installed.region[0], installed.region[1] & 0xff),
        (0x037f, 0),
        "x87 control and status words, abridged tag word"
    );
    assert_eq!(
        (installed.region[6], installed.region[7]),
        (0x1f80, fxsave_mxcsr_mask())
    );
    assert!(installed.region[40..104].iter().all(|word| *word == 0));
    assert!(installed.region[144..208].iter().all(|word| *word == 0));
    let frame = XsaveImage::from_kvm(&installed);
    assert_eq!(
        u64::from_le_bytes(frame.bytes()[512..520].try_into().unwrap()),
        X87_AND_SSE
    );
}

/// The x87 and SSE bits of XSTATE_BV.
const X87_AND_SSE: u64 = 0b011;
/// The words of `kvm_xsave::region` holding XMM5's low half and the low half
/// of YMM5's upper 128 bits.
const XMM5: usize = (160 + 5 * 16) / 4;
const UPPER_YMM5: usize = (576 + 5 * 16) / 4;

fn xstate_bv(xsave: &kvm_xsave) -> u64 {
    u64::from(xsave.region[128]) | u64::from(xsave.region[129]) << 32
}
