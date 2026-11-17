/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use super::*;

/// Kernel name size for descriptors (`KVM_STATS_NAME_SIZE`).
const NAME_SIZE: usize = 48;

/// A stats file as the kernel lays it out: header, id string, descriptors,
/// then the data block. `descriptors` are (name, flags, size, offset into the
/// data block in bytes); `data` is the data block as `__u64` words.
fn stats_file(header_flags: u32, descriptors: &[(&str, u32, u16, u32)], data: &[u64]) -> Vec<u8> {
    let stride = STATS_DESC_FIXED_SIZE + NAME_SIZE;
    let id_offset = STATS_HEADER_SIZE;
    let desc_offset = id_offset + NAME_SIZE;
    let data_offset = desc_offset + stride * descriptors.len();
    let mut file = Vec::new();
    for word in [
        header_flags,
        NAME_SIZE as u32,
        descriptors.len() as u32,
        id_offset as u32,
        desc_offset as u32,
        data_offset as u32,
    ] {
        file.extend_from_slice(&word.to_ne_bytes());
    }
    let mut id = b"kvm-1234/vcpu-0".to_vec();
    id.resize(NAME_SIZE, 0);
    file.extend_from_slice(&id);
    for (name, flags, size, offset) in descriptors {
        file.extend_from_slice(&flags.to_ne_bytes());
        file.extend_from_slice(&0_i16.to_ne_bytes());
        file.extend_from_slice(&size.to_ne_bytes());
        file.extend_from_slice(&offset.to_ne_bytes());
        file.extend_from_slice(&0_u32.to_ne_bytes());
        let mut bytes = name.as_bytes().to_vec();
        bytes.resize(NAME_SIZE, 0);
        file.extend_from_slice(&bytes);
    }
    assert_eq!(file.len(), data_offset);
    for value in data {
        file.extend_from_slice(&value.to_ne_bytes());
    }
    file
}

fn reader(file: &[u8]) -> impl Fn(&mut [u8], u64) -> io::Result<()> + '_ {
    move |buffer, offset| {
        let start = usize::try_from(offset).unwrap();
        let end = start + buffer.len();
        let source = file
            .get(start..end)
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        buffer.copy_from_slice(source);
        Ok(())
    }
}

/// The seven names, each a cumulative one-item counter, interleaved with
/// other statistics and in an order unlike [`STAT_NAMES`], so the parser must
/// find each by name and use its own offset.
fn layout_descriptors() -> Vec<(&'static str, u32, u16, u32)> {
    vec![
        ("pf_taken", 0, 1, 0),
        ("preemption_other", 0, 1, 8),
        ("exits", 0, 1, 16),
        ("guest_mode", 0x11, 1, 24),
        ("fpu_reload", 0, 1, 32),
        ("halt_exits", 0, 1, 40),
        ("signal_exits", 0, 1, 48),
        ("hypercalls", 0, 1, 56),
        ("preemption_reported", 0, 1, 64),
    ]
}

#[test]
fn the_stats_layout_finds_each_counter_by_name_at_its_own_offset() {
    let data = [100, 7, 1001, 1, 1002, 1003, 1004, 1005, 1006];
    let file = stats_file(0, &layout_descriptors(), &data);
    let layout = StatsLayout::parse(reader(&file)).unwrap();
    let snapshot = layout.read(reader(&file)).unwrap();
    assert_eq!(
        snapshot,
        VcpuStatsSnapshot {
            exits: 1001,
            signal_exits: 1004,
            halt_exits: 1003,
            hypercalls: 1005,
            fpu_reload: 1002,
            preemption_reported: 1006,
            preemption_other: 7,
        }
    );
}

#[test]
fn the_stats_layout_refuses_a_missing_counter_by_name() {
    let descriptors: Vec<_> = layout_descriptors()
        .into_iter()
        .filter(|(name, ..)| *name != "fpu_reload")
        .collect();
    let file = stats_file(0, &descriptors, &[0; 8]);
    let error = StatsLayout::parse(reader(&file)).unwrap_err().to_string();
    assert!(error.contains("no fpu_reload descriptor"), "{error}");
}

#[test]
fn the_stats_layout_refuses_a_counter_that_is_not_one_cumulative_item() {
    for (name, flags, size, want) in [
        ("hypercalls", 0x1, 1, "hypercalls has flags 0x1"),
        ("exits", 0, 2, "exits has 2 items"),
    ] {
        let descriptors: Vec<_> = layout_descriptors()
            .into_iter()
            .map(|entry| {
                if entry.0 == name {
                    (entry.0, flags, size, entry.3)
                } else {
                    entry
                }
            })
            .collect();
        let file = stats_file(0, &descriptors, &[0; 10]);
        let error = StatsLayout::parse(reader(&file)).unwrap_err().to_string();
        assert!(error.contains(want), "{name}: {error}");
    }
}

#[test]
fn the_stats_layout_refuses_a_duplicate_counter_and_nonzero_header_flags() {
    let mut descriptors = layout_descriptors();
    descriptors.push(("exits", 0, 1, 72));
    let file = stats_file(0, &descriptors, &[0; 10]);
    let error = StatsLayout::parse(reader(&file)).unwrap_err().to_string();
    assert!(error.contains("exits is described twice"), "{error}");

    let file = stats_file(1, &layout_descriptors(), &[0; 9]);
    let error = StatsLayout::parse(reader(&file)).unwrap_err().to_string();
    assert!(error.contains("header flags 0x1"), "{error}");
}

#[test]
fn a_snapshot_delta_refuses_a_counter_that_went_backwards() {
    let before = VcpuStatsSnapshot {
        exits: 10,
        fpu_reload: 4,
        ..Default::default()
    };
    let after = VcpuStatsSnapshot {
        exits: 12,
        fpu_reload: 5,
        ..Default::default()
    };
    let delta = before.delta_to(&after).unwrap();
    assert_eq!((delta.exits, delta.fpu_reload, delta.hypercalls), (2, 1, 0));
    let error = after.delta_to(&before).unwrap_err().to_string();
    assert!(
        error.contains("exits went backwards: 12 then 10"),
        "{error}"
    );
}

/// The real vCPU's statistics file has every counter the probe certifies
/// with. Actual KVM is mandatory here, as in the crate's other vCPU tests.
#[test]
fn a_real_vcpu_exposes_every_counter_the_probe_reads() {
    let backend = crate::KvmBackend::new(16 << 20).expect("actual KVM is mandatory");
    let stats = VcpuStats::open(&backend.vcpu).expect("KVM_GET_STATS_FD");
    let first = stats.snapshot().unwrap();
    let second = stats.snapshot().unwrap();
    // No KVM_RUN ran in between, so nothing moved.
    assert_eq!(
        first.delta_to(&second).unwrap(),
        VcpuStatsSnapshot::default()
    );
}

/// A blob with a FORCE `syscall` ending at offset 4 and a DONE one at 9.
const SITE_BLOB: [u8; 10] = [0xb8, 0x0f, 0x05, 0x90, 0x90, 0x90, 0x90, 0x0f, 0x05, 0xf4];

fn sites() -> [ExitSite; 2] {
    [
        ExitSite {
            marker: PROBE_MARKER_FORCE,
            return_offset: 3,
        },
        ExitSite {
            marker: PROBE_MARKER_DONE,
            return_offset: 9,
        },
    ]
}

#[test]
fn the_exit_site_table_accepts_sites_that_follow_a_syscall() {
    check_exit_sites(&SITE_BLOB, &sites()).unwrap();
}

#[test]
fn the_exit_site_table_refuses_a_bad_marker_a_duplicate_or_a_site_after_no_syscall() {
    let cases: [(Vec<ExitSite>, &str); 5] = [
        (
            vec![ExitSite {
                marker: 0x3c,
                return_offset: 3,
            }],
            "0x3c is not a probe marker",
        ),
        (vec![sites()[0], sites()[0]], "is declared twice"),
        (
            vec![ExitSite {
                marker: PROBE_MARKER_DONE,
                return_offset: 4,
            }],
            "offset 0x4 does not follow a syscall",
        ),
        (
            vec![ExitSite {
                marker: PROBE_MARKER_DONE,
                return_offset: 1,
            }],
            "offset 0x1 does not follow a syscall",
        ),
        (
            vec![ExitSite {
                marker: PROBE_MARKER_DONE,
                return_offset: 11,
            }],
            "offset 0xb does not follow a syscall",
        ),
    ];
    for (table, want) in cases {
        let error = check_exit_sites(&SITE_BLOB, &table)
            .unwrap_err()
            .to_string();
        assert!(error.contains("exit-site table"), "{error}");
        assert!(error.contains(want), "{want}: {error}");
    }
}

#[test]
fn the_two_pinned_trampolines_differ_only_in_the_hypercall_instruction() {
    let differing: Vec<usize> = (0..PINNED_TRAMPOLINE_VMMCALL.len())
        .filter(|&byte| PINNED_TRAMPOLINE_VMMCALL[byte] != PINNED_TRAMPOLINE_VMCALL[byte])
        .collect();
    assert!(
        differing.iter().all(
            |byte| (TRAMPOLINE_HYPERCALL_OFFSET..TRAMPOLINE_HYPERCALL_OFFSET + 3).contains(byte)
        ),
        "{differing:?}"
    );
    let at = TRAMPOLINE_HYPERCALL_OFFSET..TRAMPOLINE_HYPERCALL_OFFSET + 3;
    assert_eq!(PINNED_TRAMPOLINE_VMMCALL[at.clone()], VMMCALL);
    assert_eq!(PINNED_TRAMPOLINE_VMCALL[at], VMCALL);
}

fn pinned_check(installed: &[u8]) -> TrampolineCheck {
    check_trampoline(
        PINNED_TRAMPOLINE_ADDRESS,
        0xd01,
        PINNED_TRAMPOLINE_ADDRESS,
        PINNED_FRAME_ADDRESS,
        VMMCALL,
        installed,
    )
}

#[test]
fn the_trampoline_check_passes_the_pinned_entry_and_refuses_each_difference() {
    assert_eq!(
        pinned_check(&PINNED_TRAMPOLINE_VMMCALL),
        TrampolineCheck::Pinned
    );

    // One changed byte, and a short read, name the first differing byte.
    let mut changed = PINNED_TRAMPOLINE_VMMCALL;
    changed[200] ^= 0x01;
    assert_eq!(pinned_check(&changed), TrampolineCheck::Bytes(200));
    assert_eq!(
        pinned_check(&PINNED_TRAMPOLINE_VMMCALL[..241]),
        TrampolineCheck::Bytes(241)
    );
    // The other vendor's bytes do not pass for this backend's instruction.
    assert_eq!(
        pinned_check(&PINNED_TRAMPOLINE_VMCALL),
        TrampolineCheck::Bytes(TRAMPOLINE_HYPERCALL_OFFSET + 2)
    );

    let entry = |lstar, efer, trampoline, frame, instruction| {
        check_trampoline(
            lstar,
            efer,
            trampoline,
            frame,
            instruction,
            &PINNED_TRAMPOLINE_VMMCALL,
        )
    };
    assert_eq!(
        entry(0x7000, 0xd01, 0x5000, 0x6000, VMMCALL),
        TrampolineCheck::Lstar(0x7000)
    );
    assert_eq!(
        entry(0x5000, 0xd00, 0x5000, 0x6000, VMMCALL),
        TrampolineCheck::SyscallDisabled
    );
    assert_eq!(
        entry(0x5000, 0xd01, 0xf000, 0x10000, VMMCALL),
        TrampolineCheck::Layout {
            trampoline: 0xf000,
            frame: 0x10000
        }
    );
    assert_eq!(
        entry(0x5000, 0xd01, 0x5000, 0x6000, [0x0f, 0x01, 0xca]),
        TrampolineCheck::Bytes(TRAMPOLINE_HYPERCALL_OFFSET)
    );
}

const LOAD: u64 = 0x20_0000;

fn hypercall() -> HypercallExit {
    HypercallExit {
        nr: 12,
        args: [0x6000, 1, 0],
        flags: 1,
    }
}

fn frame(marker: u64, return_rip: u64) -> [u64; FRAME_IDENTITY_WORDS] {
    let mut frame = [0; FRAME_IDENTITY_WORDS];
    frame[0] = marker;
    frame[8] = return_rip;
    frame
}

fn identify(
    exit: HypercallExit,
    frame: &[u64; FRAME_IDENTITY_WORDS],
    expected: u32,
) -> std::result::Result<TrampolineExit, IdentityMismatch> {
    identify_trampoline_exit(exit, 0x6000, frame, expected, LOAD, &sites())
}

#[test]
fn a_trampoline_exit_is_identified_by_marker_and_return_site() {
    let force = u64::from(PROBE_MARKER_FORCE);
    assert_eq!(
        identify(hypercall(), &frame(force, LOAD + 3), PROBE_MARKER_FORCE),
        Ok(TrampolineExit {
            marker: force,
            return_rip: LOAD + 3
        })
    );
}

#[test]
fn every_item_of_the_exit_identity_is_checked() {
    let force = u64::from(PROBE_MARKER_FORCE);
    let done = u64::from(PROBE_MARKER_DONE);
    let good = frame(force, LOAD + 3);
    let with = |change: fn(&mut HypercallExit)| {
        let mut exit = hypercall();
        change(&mut exit);
        identify(exit, &good, PROBE_MARKER_FORCE)
    };
    assert_eq!(with(|exit| exit.nr = 1), Err(IdentityMismatch::Number(1)));
    assert_eq!(
        with(|exit| exit.args[0] = 0x10000),
        Err(IdentityMismatch::Frame(0x10000))
    );
    assert_eq!(
        with(|exit| exit.args[1] = 2),
        Err(IdentityMismatch::Arguments(2, 0))
    );
    assert_eq!(
        with(|exit| exit.args[2] = 1),
        Err(IdentityMismatch::Arguments(1, 1))
    );
    assert_eq!(
        with(|exit| exit.flags = 0),
        Err(IdentityMismatch::NotLongMode)
    );

    // A blob without its FORCE reaches DONE first: both the marker and, with
    // the marker forged, the return site differ.
    assert_eq!(
        identify(hypercall(), &frame(done, LOAD + 9), PROBE_MARKER_FORCE),
        Err(IdentityMismatch::Marker {
            expected: PROBE_MARKER_FORCE,
            observed: done
        })
    );
    assert_eq!(
        identify(hypercall(), &frame(force, LOAD + 9), PROBE_MARKER_FORCE),
        Err(IdentityMismatch::ReturnRip {
            expected: LOAD + 3,
            observed: LOAD + 9
        })
    );
    // All 64 bits of word 0 count.
    assert_eq!(
        identify(
            hypercall(),
            &frame(force | (1 << 32), LOAD + 3),
            PROBE_MARKER_FORCE
        ),
        Err(IdentityMismatch::Marker {
            expected: PROBE_MARKER_FORCE,
            observed: force | (1 << 32)
        })
    );
    assert_eq!(
        identify(
            hypercall(),
            &frame(u64::from(PROBE_MARKER_SIG), LOAD + 3),
            PROBE_MARKER_SIG
        ),
        Err(IdentityMismatch::NoSite(PROBE_MARKER_SIG))
    );
    let mut full = good;
    full[11] = 1;
    assert_eq!(
        identify(hypercall(), &full, PROBE_MARKER_FORCE),
        Err(IdentityMismatch::FullReturn(1))
    );
}

#[test]
fn no_probe_marker_is_a_linux_syscall_number() {
    for marker in PROBE_MARKERS {
        assert!(PROBE_MARKER_RANGE.contains(&marker), "{marker:#x}");
        assert_eq!(crate::Sysno::new(marker as usize), None, "{marker:#x}");
    }
}

#[test]
fn thread_switches_are_read_once_each_from_the_status_file() {
    let status = "Name:\tprobe\nvoluntary_ctxt_switches:\t12\nnonvoluntary_ctxt_switches:\t3\n";
    assert_eq!(
        parse_switches(status).unwrap(),
        ThreadSwitches {
            voluntary: 12,
            nonvoluntary: 3
        }
    );
    let missing = "voluntary_ctxt_switches:\t12\n";
    let error = parse_switches(missing).unwrap_err().to_string();
    assert!(error.contains("no nonvoluntary_ctxt_switches"), "{error}");
    let twice = format!("{status}voluntary_ctxt_switches:\t13\n");
    let error = parse_switches(&twice).unwrap_err().to_string();
    assert!(
        error.contains("voluntary_ctxt_switches appears twice"),
        "{error}"
    );
    let garbled = "voluntary_ctxt_switches:\tx\nnonvoluntary_ctxt_switches:\t3\n";
    let error = parse_switches(garbled).unwrap_err().to_string();
    assert!(
        error.contains("voluntary_ctxt_switches is \"x\""),
        "{error}"
    );
}

#[test]
fn this_thread_has_readable_switches_and_a_cpu() {
    read_switches(current_tid()).unwrap();
    current_cpu().unwrap();
}

fn xss_kept() -> XssOutcome {
    XssOutcome {
        kind: XssOutcomeKind::Kept(XssKeepReason::NoHostComponents),
        read_back: 0,
    }
}

#[test]
fn runner_facts_decode_vendor_family_model_stepping_and_the_named_words() {
    // AMD family 0x1a model 0x11: base family 0xf plus extended family 0xb.
    let amd = |leaf: u32, subleaf: u32| match (leaf, subleaf) {
        (0, 0) => CpuidWords {
            eax: 0x10,
            ebx: 0x6874_7541,
            ecx: 0x444d_4163,
            edx: 0x6974_6e65,
        },
        (1, 0) => CpuidWords {
            eax: 0x00b1_0f11,
            ecx: 0x7ef8_3203,
            ..Default::default()
        },
        (7, 0) => CpuidWords {
            ebx: 0x2000,
            ..Default::default()
        },
        (0xd, 1) => CpuidWords {
            eax: 0xf,
            ..Default::default()
        },
        (0x8000_0000, 0) => CpuidWords {
            eax: 0x8000_0021,
            ..Default::default()
        },
        (0x8000_0008, 0) => CpuidWords {
            ebx: 0x4,
            ..Default::default()
        },
        _ => CpuidWords::default(),
    };
    let facts = RunnerFacts::from_cpuid(amd, 0x2e7, VMMCALL, xss_kept(), SchedExt::Disabled);
    assert_eq!(&facts.vendor, b"AuthenticAMD");
    assert_eq!((facts.family, facts.model, facts.stepping), (0x1a, 0x11, 1));
    assert_eq!(facts.host_xcr0, 0x2e7);
    assert_eq!(facts.hypercall_instruction, VMMCALL);
    assert_eq!(facts.xss, xss_kept());
    assert_eq!(
        (
            facts.cpuid_1_ecx,
            facts.cpuid_d_1_eax,
            facts.cpuid_7_0_ebx,
            facts.cpuid_8000_0008_ebx
        ),
        (0x7ef8_3203, 0xf, 0x2000, 0x4)
    );
    assert!(!facts.hypervisor);
    assert_eq!(facts.sched_ext, SchedExt::Disabled);

    // Intel family 6 model 0x8f; the hypervisor bit; leaves above the
    // reported maxima read as zero.
    let intel = |leaf: u32, subleaf: u32| match (leaf, subleaf) {
        (0, 0) => CpuidWords {
            eax: 0x6,
            ..Default::default()
        },
        (1, 0) => CpuidWords {
            eax: 0x0008_06f8,
            ecx: 1 << 31,
            ..Default::default()
        },
        (0x8000_0000, 0) => CpuidWords {
            eax: 0x8000_0001,
            ..Default::default()
        },
        _ => CpuidWords {
            eax: 0xdead,
            ebx: 0xdead,
            ..Default::default()
        },
    };
    let facts = RunnerFacts::from_cpuid(intel, 0x7, VMCALL, xss_kept(), SchedExt::Absent);
    assert_eq!(
        (facts.family, facts.model, facts.stepping),
        (0x6, 0x8f, 0x8)
    );
    assert!(facts.hypervisor);
    assert_eq!(
        (
            facts.cpuid_d_1_eax,
            facts.cpuid_7_0_ebx,
            facts.cpuid_8000_0008_ebx
        ),
        (0, 0, 0)
    );
}

/// A blob that exits once with DONE: `mov eax, DONE; syscall; jmp $`.
const DONE_BLOB: [u8; 9] = [0xb8, 0x03, 0x58, 0x50, 0x00, 0x0f, 0x05, 0xeb, 0xfe];

/// On actual KVM, the runner's setup finds the syscall entry in its pinned
/// form and the blob at CPL3 before the first run (r7-1a §2 (a) and §3), and
/// the blob's DONE reaches user space with its full identity.
#[test]
fn a_real_probe_vm_has_the_pinned_syscall_entry_and_reaches_done() {
    let sites = [ExitSite {
        marker: PROBE_MARKER_DONE,
        return_offset: 7,
    }];
    let context = [0xa5; 0x80];
    let mut vm =
        ProbeVm::new(&DONE_BLOB, 0, &context, 0x3f_f000, &sites).expect("actual KVM is mandatory");
    assert_eq!(vm.backend.vcpu.get_regs().unwrap().rdi, CONTEXT_ADDRESS);
    assert_eq!(vm.trampoline, TrampolineCheck::Pinned);
    assert_eq!((vm.initial_cs_selector & 3, vm.initial_ss_dpl), (3, 3));
    assert_eq!(
        vm.facts.hypercall_instruction,
        vm.backend.hypercall_instruction()
    );
    let record = vm.step(current_tid(), Some(PROBE_MARKER_DONE)).unwrap();
    assert_eq!(
        record.end,
        RunEnd::Trampoline(TrampolineExit {
            marker: u64::from(PROBE_MARKER_DONE),
            return_rip: DEFAULT_LOAD_ADDRESS + 7
        })
    );
    let delta = record.before.stats.delta_to(&record.after.stats).unwrap();
    assert_eq!((delta.hypercalls, delta.fpu_reload), (1, 1));
    // The control words start zeroed; the caller's data is untouched.
    let context_back = vm.read_context().unwrap();
    assert_eq!(context_back[..0x40], [0; 0x40]);
    assert_eq!(context_back[0x40..], context[0x40..]);
}

#[test]
fn a_one_cpu_set_holds_exactly_that_cpu() {
    let allowed = cpus_in(&thread_affinity().unwrap());
    assert!(!allowed.is_empty());
    let cpu = allowed[allowed.len() - 1];
    assert_eq!(cpus_in(&only_cpu(cpu)), vec![cpu]);
}

#[test]
fn the_affinity_guard_restores_the_thread_affinity() {
    let before = cpus_in(&thread_affinity().unwrap());
    {
        let _guard = AffinityGuard::save().unwrap();
        set_thread_affinity(&only_cpu(before[0])).unwrap();
        assert_eq!(current_cpu().unwrap(), before[0]);
    }
    assert_eq!(cpus_in(&thread_affinity().unwrap()), before);
}

/// The peer's self-check passes exactly where AVX and XSAVE exist, and its
/// x87 stack and upper YMM halves are left clean: a second check passes too.
#[test]
fn the_peer_fpu_self_check_sees_its_own_values() {
    let available =
        std::arch::is_x86_feature_detected!("avx") && std::arch::is_x86_feature_detected!("xsave");
    assert_eq!(peer_fpu_self_check(), available);
    assert_eq!(peer_fpu_self_check(), available);
}

/// `mov eax, FORCE; syscall; mov eax, DONE; syscall; jmp $` (P1, P6).
const FORCE_DONE_BLOB: [u8; 16] = [
    0xb8, 0x01, 0x58, 0x50, 0x00, 0x0f, 0x05, 0xb8, 0x03, 0x58, 0x50, 0x00, 0x0f, 0x05, 0xeb, 0xfe,
];
/// `xor eax, eax; cpuid; mov eax, DONE; syscall; jmp $` (P2, P3).
const CPUID_DONE_BLOB: [u8; 13] = [
    0x31, 0xc0, 0x0f, 0xa2, 0xb8, 0x03, 0x58, 0x50, 0x00, 0x0f, 0x05, 0xeb, 0xfe,
];
/// `rdtsc; mov eax, DONE; syscall; jmp $` (P4).
const RDTSC_DONE_BLOB: [u8; 11] = [
    0x0f, 0x31, 0xb8, 0x03, 0x58, 0x50, 0x00, 0x0f, 0x05, 0xeb, 0xfe,
];
/// `mov qword [rdi], 1; spin: inc qword [rdi+0x10]; cmp qword [rdi+8], 0;
/// je spin; mov eax, DONE; syscall; jmp $` (P5, P7).
const SPIN_DONE_BLOB: [u8; 27] = [
    0x48, 0xc7, 0x07, 0x01, 0x00, 0x00, 0x00, 0x48, 0xff, 0x47, 0x10, 0x48, 0x83, 0x7f, 0x08, 0x00,
    0x74, 0xf5, 0xb8, 0x03, 0x58, 0x50, 0x00, 0x0f, 0x05, 0xeb, 0xfe,
];

fn done_at(offset: u64) -> ExitSite {
    ExitSite {
        marker: PROBE_MARKER_DONE,
        return_offset: offset,
    }
}

fn force_done_sites() -> [ExitSite; 2] {
    [
        ExitSite {
            marker: PROBE_MARKER_FORCE,
            return_offset: 7,
        },
        done_at(14),
    ]
}

fn at(marker: u32, offset: u64) -> RunEnd {
    RunEnd::Trampoline(TrampolineExit {
        marker: u64::from(marker),
        return_rip: DEFAULT_LOAD_ADDRESS + offset,
    })
}

fn trial(blob: &[u8], sites: &[ExitSite], path: ProbeExitPath, action: HostAction) -> TrialRecord {
    trial_until(
        blob,
        sites,
        path,
        action,
        std::time::Duration::from_secs(60),
    )
}

fn trial_until(
    blob: &[u8],
    sites: &[ExitSite],
    path: ProbeExitPath,
    action: HostAction,
    within: std::time::Duration,
) -> TrialRecord {
    let runner = GuestProbeRunner::new(blob, 0, &[0; 0x80], 0x3f_f000, sites)
        .expect("actual KVM is mandatory");
    runner
        .run_trial(path, &action, None, std::time::Instant::now() + within)
        .unwrap()
}

fn ends(record: &TrialRecord) -> Vec<RunEnd> {
    record.runs.iter().map(|run| run.end).collect()
}

fn delta(run: &RunRecord) -> VcpuStatsSnapshot {
    run.before.stats.delta_to(&run.after.stats).unwrap()
}

/// Writes a named skip past libtest output capture (fd 2
/// directly), so the counted runner and per-crate scorecard
/// report it as skipped rather than as a silent pass.
fn report_skip(test: &str, reason: &str) {
    let line = format!("\nREVERIE_SKIP: {test}: {reason}\n");
    let mut rest = line.as_bytes();
    while !rest.is_empty() {
        // SAFETY: writes only the buffer above to this process's stderr.
        let written =
            unsafe { libc::write(libc::STDERR_FILENO, rest.as_ptr().cast(), rest.len()) };
        assert!(
            written > 0,
            "write the named skip for {test}: {}",
            std::io::Error::last_os_error()
        );
        rest = &rest[written as usize..];
    }
}

/// The exact CI signature tracked by issue 307: the host kept an
/// unproven IA32_XSS and only the XSAVE image first differed, at
/// the header's first byte (offset 512).
fn is_issue_307_unstable_signature(
    qualification: &crate::guest_probe::FixedXstateQualification,
) -> bool {
    qualification.unstable > 0
        && matches!(
            qualification.xss.kind,
            crate::guest_probe::XssOutcomeKind::Kept(
                crate::guest_probe::XssKeepReason::Unproven { .. }
            )
        )
        && qualification.first_image_difference == Some(512)
}

#[test]
fn only_the_issue_307_signature_skips_the_stable_xstate_test() {
    use crate::guest_probe::FixedXstateQualification;
    use crate::guest_probe::XssKeepReason;
    use crate::guest_probe::XssOutcome;
    use crate::guest_probe::XssOutcomeKind;

    let report = |kind, unstable, first_image_difference| FixedXstateQualification {
        guest_xcr0: crate::bootstrap::FIXED_GUEST_XCR0,
        xss: XssOutcome {
            kind,
            read_back: 0,
        },
        host_cpuid_d_1_eax: 15,
        comparisons: 6,
        unstable,
        first_image_difference,
    };
    let ci_report = report(
        XssOutcomeKind::Kept(XssKeepReason::Unproven {
            hardware: 256,
            kvm: 0,
        }),
        2,
        Some(512),
    );
    assert!(is_issue_307_unstable_signature(&ci_report));

    let stable = report(
        XssOutcomeKind::Kept(XssKeepReason::NoHostComponents),
        0,
        None,
    );
    assert!(!is_issue_307_unstable_signature(&stable));

    let different_xss = report(XssOutcomeKind::Set(256), 2, Some(512));
    assert!(!is_issue_307_unstable_signature(&different_xss));

    let different_offset = report(
        XssOutcomeKind::Kept(XssKeepReason::Unproven {
            hardware: 256,
            kvm: 0,
        }),
        2,
        Some(513),
    );
    assert!(!is_issue_307_unstable_signature(&different_offset));
}

#[test]
fn the_fixed_xstate_qualification_is_stable_on_this_host() {
    let qualification = qualify_fixed_guest_xstate().unwrap();
    assert_eq!(qualification.guest_xcr0, crate::bootstrap::FIXED_GUEST_XCR0);
    assert!(qualification.comparisons >= 6, "{qualification:?}");
    if is_issue_307_unstable_signature(&qualification) {
        report_skip(
            "the_fixed_xstate_qualification_is_stable_on_this_host",
            &format!(
                "UnsupportedHost: fixed-guest xstate unstable on this host: \
                 {qualification:?}; \
                 matches the known unstable signature (is_issue_307_unstable_signature)"
            ),
        );
        return;
    }
    assert_eq!(
        qualification.unstable, 0,
        "guest xstate answers changed across a VM exit: {qualification:?}"
    );
    assert_eq!(qualification.first_image_difference, None);
}

#[test]
fn a_real_p1_trial_exits_at_force_then_done() {
    let record = trial(
        &FORCE_DONE_BLOB,
        &force_done_sites(),
        ProbeExitPath::P1,
        HostAction::None,
    );
    assert_eq!(record.trampoline, TrampolineCheck::Pinned);
    assert_eq!((record.initial_cpl.0 & 3, record.initial_cpl.1), (3, 3));
    assert_eq!(
        ends(&record),
        [at(PROBE_MARKER_FORCE, 7), at(PROBE_MARKER_DONE, 14)]
    );
    for run in &record.runs {
        assert_eq!((delta(run).hypercalls, delta(run).fpu_reload), (1, 1));
    }
    assert!(!record.watchdog_kicked);
}

#[test]
fn a_real_p1_frame_consumer_trial_reinstalls_the_image() {
    let record = trial(
        &FORCE_DONE_BLOB,
        &force_done_sites(),
        ProbeExitPath::P1,
        HostAction::FrameConsumer(FrameEdit::default()),
    );
    assert_eq!(
        ends(&record),
        [at(PROBE_MARKER_FORCE, 7), at(PROBE_MARKER_DONE, 14)]
    );
    let frame = record.frame.expect("the consumer ran");
    assert_eq!(frame.raw_get.len(), frame.restored.len());
    assert!(!frame.frame.is_empty());
}

#[test]
fn a_real_p1_migrate_trial_runs_run_2_on_another_cpu() {
    let record = trial(
        &FORCE_DONE_BLOB,
        &force_done_sites(),
        ProbeExitPath::P1,
        HostAction::Migrate,
    );
    let Some(target) = record.migrate_target else {
        assert_eq!(cpus_in(&thread_affinity().unwrap()).len(), 1);
        return;
    };
    assert_eq!(
        ends(&record),
        [at(PROBE_MARKER_FORCE, 7), at(PROBE_MARKER_DONE, 14)]
    );
    assert_eq!(
        (record.runs[1].before.cpu, record.runs[1].after.cpu),
        (target, target)
    );
    assert_ne!(record.runs[0].after.cpu, target);
}

#[test]
fn a_real_p2_trial_takes_the_in_kernel_cpuid_exit_then_done() {
    let record = trial(
        &CPUID_DONE_BLOB,
        &[done_at(11)],
        ProbeExitPath::P2,
        HostAction::None,
    );
    assert_eq!(ends(&record), [at(PROBE_MARKER_DONE, 11)]);
    let run = delta(&record.runs[0]);
    assert!(run.exits >= 2, "{run:?}");
    assert_eq!(run.hypercalls, 1);
}

#[test]
fn a_real_p3_trial_emulates_the_faulting_cpuid() {
    let record = trial(
        &CPUID_DONE_BLOB,
        &[done_at(11)],
        ProbeExitPath::P3,
        HostAction::None,
    );
    assert!(matches!(record.runs[0].end, RunEnd::Halt(_)), "{record:?}");
    assert_eq!(record.runs[1].end, at(PROBE_MARKER_DONE, 11));
    assert_eq!(record.emulated_rip, Some(DEFAULT_LOAD_ADDRESS + 2));
    assert_eq!(delta(&record.runs[0]).hypercalls, 0);
}

#[test]
fn a_real_p4_trial_emulates_the_faulting_rdtsc() {
    let record = trial(
        &RDTSC_DONE_BLOB,
        &[done_at(9)],
        ProbeExitPath::P4,
        HostAction::None,
    );
    assert!(matches!(record.runs[0].end, RunEnd::Halt(_)), "{record:?}");
    assert_eq!(record.runs[1].end, at(PROBE_MARKER_DONE, 9));
    assert_eq!(record.emulated_rip, Some(DEFAULT_LOAD_ADDRESS));
}

#[test]
fn a_real_p5_trial_is_kicked_after_the_marker_then_reaches_done() {
    let record = trial(
        &SPIN_DONE_BLOB,
        &[done_at(25)],
        ProbeExitPath::P5,
        HostAction::None,
    );
    assert_eq!(
        ends(&record),
        [RunEnd::Failed(libc::EINTR), at(PROBE_MARKER_DONE, 25)]
    );
    assert!(record.kick.expect("the kicker ran").marker_seen);
    assert!(record.spin_after_run1.expect("run 1 returned") > 0);
    let (cs, ss_dpl) = record.cpl_at_kick.expect("sampled at the kick");
    assert_eq!((cs & 3, ss_dpl), (3, 3));
    let run1 = delta(&record.runs[0]);
    assert_eq!((run1.signal_exits, run1.hypercalls), (1, 0));
}

#[test]
fn a_real_p6_trial_completes_the_pending_exit_without_entering() {
    let record = trial(
        &FORCE_DONE_BLOB,
        &force_done_sites(),
        ProbeExitPath::P6,
        HostAction::None,
    );
    assert_eq!(
        ends(&record),
        [
            at(PROBE_MARKER_FORCE, 7),
            RunEnd::Failed(libc::EINTR),
            at(PROBE_MARKER_DONE, 14)
        ]
    );
    let immediate = delta(&record.runs[1]);
    assert_eq!(
        (
            immediate.exits,
            immediate.signal_exits,
            immediate.hypercalls,
            immediate.fpu_reload
        ),
        (0, 0, 0, 1)
    );
}

/// The real P7 run. It never accepts a caller refusal as a pass: at a caller
/// nice above 14 it fails visibly, because P7 itself would be untested. It is
/// ignored in routine runs and run once, explicitly, at a caller nice of 14.
#[test]
#[ignore = "needs a caller nice of at most 14 under SCHED_OTHER; run explicitly"]
fn a_real_p7_trial_brackets_the_peer() {
    let caller = thread_nice().unwrap();
    // Stricter than the admission rule on purpose: the explicit run
    // certifies plain SCHED_OTHER, without SCHED_RESET_ON_FORK.
    let policy = thread_policy().unwrap();
    assert_eq!(
        policy.policy,
        libc::SCHED_OTHER,
        "P7's explicit run needs plain SCHED_OTHER: {policy:?}"
    );
    assert!(
        caller <= P7_MAX_CALLER_NICE,
        "P7 needs a caller nice of at most {P7_MAX_CALLER_NICE}; this test runs at nice {caller}, \
         where P7 refuses (reason 17) and its run would go untested"
    );
    let record = trial(
        &SPIN_DONE_BLOB,
        &[done_at(25)],
        ProbeExitPath::P7,
        HostAction::None,
    );
    let p7 = record.p7.expect("P7 recorded");
    assert_eq!(p7.refusal, None);
    assert!(p7.nice_established, "{p7:?}");
    assert_eq!(
        (p7.observed_vcpu_nice, p7.observed_peer_nice),
        (Some(p7.vcpu_nice), Some(caller))
    );
    let (x, _) = p7.cpus.expect("P7 needs two allowed CPUs");
    assert_eq!(
        p7.run.expect("the run ended").end,
        at(PROBE_MARKER_DONE, 25)
    );
    assert!(p7.marker_seen);
    let peer = p7.peer.expect("the peer reported");
    assert_eq!(peer.cpu, x);
    assert_eq!(peer.nice, caller);
    assert_eq!(
        peer.fpu_ok,
        std::arch::is_x86_feature_detected!("avx") && std::arch::is_x86_feature_detected!("xsave")
    );
    assert!(!p7.kicked);
    // The bracket (r7 l.397, P7 step 4): a counted preemption and a nonvoluntary
    // switch of the vCPU thread between S0/T0 and S1/T1.
    let bracket = p7.s0.delta_to(&p7.s1).unwrap();
    let preemptions = bracket.preemption_reported + bracket.preemption_other;
    let nonvoluntary = p7
        .t1
        .nonvoluntary
        .checked_sub(p7.t0.nonvoluntary)
        .expect("nonvoluntary switches only grow");
    assert!(preemptions >= 1, "{p7:?}");
    assert!(nonvoluntary >= 1, "{p7:?}");
    // The evidence line, printed only after every assertion has held. It
    // starts with a newline: run serially, libtest has already printed
    // "test <name> ... " without one.
    println!(
        "\nP7 PASS: caller nice {caller}, intended vCPU {} peer {}, observed vCPU {:?} peer {:?}, \
         preemptions {preemptions}, nonvoluntary switches {nonvoluntary}, cpu {x}",
        p7.vcpu_nice, p7.peer_nice, p7.observed_vcpu_nice, p7.observed_peer_nice
    );
}

/// R-h's mechanism: a blob that never exits is kicked by the watchdog at the
/// deadline, the trial ends, and every helper thread has been joined.
#[test]
fn a_real_trial_that_never_exits_is_kicked_at_the_deadline() {
    let started = std::time::Instant::now();
    let record = trial_until(
        &[0xeb, 0xfe],
        &[],
        ProbeExitPath::P1,
        HostAction::None,
        std::time::Duration::from_secs(2),
    );
    assert!(record.watchdog_kicked);
    assert_eq!(ends(&record), [RunEnd::Failed(libc::EINTR)]);
    assert!(started.elapsed() < std::time::Duration::from_secs(30));
}

#[test]
fn p7_refuses_a_caller_nice_that_leaves_less_than_the_five_level_gap() {
    assert_eq!(p7_nice(-5), (0, None));
    assert_eq!(p7_nice(0), (5, None));
    assert_eq!(p7_nice(14), (19, None));
    for caller in [15, 19] {
        assert_eq!(
            p7_nice(caller),
            (19, Some(P7Refusal::CallerNiceTooHigh { caller, vcpu: 19 }))
        );
    }
}

/// R-p7-nice: a caller at nice 15 or above gets the named refusal before
/// the whole P7 trial. Even with a SIG preamble requested, the record has no
/// preamble and no run, the watchdog never started, and this thread spawned
/// no helper and wrote no affinity. A check placed any later would run the
/// preamble (this blob has no SIG site, so it would spin to the 5 s deadline)
/// or start the watchdog, and fail these assertions.
#[test]
fn a_real_p7_trial_at_a_high_caller_nice_refuses_before_any_activity() {
    let nice = thread_nice().unwrap().max(15);
    set_thread_nice(nice).unwrap();
    let affinity = cpus_in(&thread_affinity().unwrap());
    let runner = GuestProbeRunner::new(&SPIN_DONE_BLOB, 0, &[0; 0x80], 0x3f_f000, &[done_at(25)])
        .expect("actual KVM is mandatory");
    let spawns = HELPER_SPAWNS.with(|count| count.get());
    let writes = AFFINITY_WRITES.with(|count| count.get());
    let record = runner
        .run_trial(
            ProbeExitPath::P7,
            &HostAction::None,
            Some(&FrameEdit::default()),
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .unwrap();
    assert_eq!(HELPER_SPAWNS.with(|count| count.get()), spawns);
    assert_eq!(AFFINITY_WRITES.with(|count| count.get()), writes);
    assert!(!record.watchdog_started);
    assert!(record.preamble.is_none());
    assert!(record.runs.is_empty());
    let p7 = record.p7.expect("P7 recorded");
    assert_eq!(
        p7.refusal,
        Some(P7Refusal::CallerNiceTooHigh {
            caller: nice,
            vcpu: 19
        })
    );
    assert_eq!((p7.vcpu_nice, p7.peer_nice), (19, nice));
    assert_eq!((p7.run, p7.cpus, p7.peer), (None, None, None));
    assert_eq!(cpus_in(&thread_affinity().unwrap()), affinity);
}

#[test]
fn thread_nice_reads_a_valid_nice_value() {
    let nice = thread_nice().unwrap();
    assert!((-20..=19).contains(&nice), "{nice}");
}

#[test]
fn p7_admits_only_the_sched_other_class_and_refuses_every_other_by_name() {
    let of = |policy, priority| ThreadPolicy { policy, priority };
    assert_eq!(p7_admission(of(libc::SCHED_OTHER, 0), 14), (19, None));
    assert_eq!(
        p7_admission(of(libc::SCHED_OTHER, 0), 15).1,
        Some(P7Refusal::CallerNiceTooHigh {
            caller: 15,
            vcpu: 19
        })
    );
    // Every other policy, with and without SCHED_RESET_ON_FORK, and an
    // unknown value, is refused by name before the nice value is considered.
    let refused = [
        (libc::SCHED_FIFO, 10),
        (libc::SCHED_RR, 10),
        (libc::SCHED_BATCH, 0),
        (libc::SCHED_IDLE, 0),
        (libc::SCHED_DEADLINE, 0),
        // SCHED_EXT; libc names no constant for it.
        (7, 0),
        (0x7f, 0),
    ];
    for (base, priority) in refused {
        for policy in [base, base | libc::SCHED_RESET_ON_FORK] {
            for caller in [0, 19] {
                assert_eq!(
                    p7_admission(of(policy, priority), caller).1,
                    Some(P7Refusal::CallerPolicy { policy, priority }),
                    "{policy:#x}"
                );
            }
        }
    }
    // coord7's ruling, by name: SCHED_OTHER with SCHED_RESET_ON_FORK is the
    // SCHED_OTHER class and is admitted; SCHED_BATCH with it is refused.
    let other_reset = libc::SCHED_OTHER | libc::SCHED_RESET_ON_FORK;
    assert_eq!(p7_admission(of(other_reset, 0), 14), (19, None));
    assert_eq!(
        p7_admission(of(other_reset, 0), 15).1,
        Some(P7Refusal::CallerNiceTooHigh {
            caller: 15,
            vcpu: 19
        })
    );
    let batch_reset = libc::SCHED_BATCH | libc::SCHED_RESET_ON_FORK;
    assert_eq!(
        p7_admission(of(batch_reset, 0), 0),
        (
            5,
            Some(P7Refusal::CallerPolicy {
                policy: batch_reset,
                priority: 0
            })
        )
    );
}

/// R-p7-policy: a caller under SCHED_BATCH gets the named policy refusal
/// before the whole P7 trial, with the same witnesses as R-p7-nice.
#[test]
fn a_real_p7_trial_under_a_batch_policy_refuses_before_any_activity() {
    let param = libc::sched_param { sched_priority: 0 };
    // SAFETY: `param` is a valid sched_param; pid 0 is this test's thread,
    // and moving to SCHED_BATCH needs no privilege.
    assert_eq!(
        unsafe { libc::sched_setscheduler(0, libc::SCHED_BATCH, &param) },
        0
    );
    let policy = thread_policy().unwrap();
    let affinity = cpus_in(&thread_affinity().unwrap());
    let runner = GuestProbeRunner::new(&SPIN_DONE_BLOB, 0, &[0; 0x80], 0x3f_f000, &[done_at(25)])
        .expect("actual KVM is mandatory");
    let spawns = HELPER_SPAWNS.with(|count| count.get());
    let writes = AFFINITY_WRITES.with(|count| count.get());
    let record = runner
        .run_trial(
            ProbeExitPath::P7,
            &HostAction::None,
            Some(&FrameEdit::default()),
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .unwrap();
    assert_eq!(HELPER_SPAWNS.with(|count| count.get()), spawns);
    assert_eq!(AFFINITY_WRITES.with(|count| count.get()), writes);
    assert!(!record.watchdog_started);
    assert!(record.preamble.is_none());
    assert!(record.runs.is_empty());
    let p7 = record.p7.expect("P7 recorded");
    assert_eq!(
        p7.refusal,
        Some(P7Refusal::CallerPolicy {
            policy: policy.policy,
            priority: policy.priority
        })
    );
    assert_eq!(policy.policy, libc::SCHED_BATCH);
    assert_eq!((p7.run, p7.cpus, p7.peer), (None, None, None));
    assert_eq!(cpus_in(&thread_affinity().unwrap()), affinity);
}

/// F4's witness: any failure of the vCPU thread's nice setter, on a raise, is
/// not an error. EACCES and EPERM stand for an LSM denial. The setup reports
/// what it reads back, which then differs from the intended value, so the run
/// is not started ("P7 nice not established").
#[test]
fn a_failed_vcpu_nice_setter_leaves_the_p7_run_unstarted() {
    fn eacces(_: i32) -> Result<()> {
        Err(Error::HostIo(io::Error::from_raw_os_error(libc::EACCES)))
    }
    fn eperm(_: i32) -> Result<()> {
        Err(Error::HostIo(io::Error::from_raw_os_error(libc::EPERM)))
    }
    let affinity = AffinityGuard::save().unwrap();
    let x = cpus_in(affinity.saved())[0];
    let caller = thread_nice().unwrap();
    // A raise, so the setter is called; it fails, so nothing is set. At 19
    // the value is past the cap, which only the failing setter ever sees.
    let intended = caller + 1;
    type Setter = fn(i32) -> Result<()>;
    let setters: [(Setter, i32); 2] = [(eacces, libc::EACCES), (eperm, libc::EPERM)];
    for (setter, errno) in setters {
        let (observed, refused) = p7_vcpu_setup(x, intended, setter).unwrap();
        assert_eq!(observed, caller);
        assert_eq!(
            refused,
            Some(Error::HostIo(io::Error::from_raw_os_error(errno)).to_string())
        );
        assert!(!p7_nice_established(
            Some(observed),
            Some(caller),
            intended,
            caller,
            refused.is_some()
        ));
        assert_eq!(cpus_in(&thread_affinity().unwrap()), [x]);
    }
    drop(affinity);
    assert!(p7_nice_established(
        Some(intended),
        Some(caller),
        intended,
        caller,
        false
    ));
    assert!(!p7_nice_established(
        Some(intended),
        Some(caller),
        intended,
        caller,
        true
    ));
    assert!(!p7_nice_established(
        None,
        Some(caller),
        intended,
        caller,
        false
    ));
    assert!(!p7_nice_established(
        Some(intended),
        None,
        intended,
        caller,
        false
    ));
    assert!(!p7_nice_established(
        Some(intended),
        Some(caller + 1),
        intended,
        caller,
        false
    ));
}

#[test]
fn the_sched_ext_state_decodes_absent_disabled_and_anything_else() {
    assert_eq!(SchedExt::from_state(None), SchedExt::Absent);
    assert_eq!(SchedExt::from_state(Some("disabled\n")), SchedExt::Disabled);
    assert_eq!(
        SchedExt::from_state(Some("enabled\n")),
        SchedExt::NotDisabled
    );
    assert_eq!(
        SchedExt::from_state(Some("enabling")),
        SchedExt::NotDisabled
    );
}

/// cx F4's end-to-end witness on actual KVM. The vCPU thread's nice setter
/// fails with EACCES on a raise; the real P7 threads then run their
/// handshake, the run is not started, the VM comes back with no `KVM_RUN` on
/// it, and every thread is joined long before the deadline.
/// The intended vCPU nice is a raise the failing setter leaves unreached, so
/// this runs at any caller nice, the scopes' 19 included.
#[test]
fn a_real_p7_run_with_a_failed_vcpu_nice_setter_is_not_started() {
    fn eacces(_: i32) -> Result<()> {
        Err(Error::HostIo(io::Error::from_raw_os_error(libc::EACCES)))
    }
    let caller = thread_nice().unwrap();
    // A raise, so the setter is called (past the cap at 19; see above).
    let intended = caller + 1;
    let affinity = cpus_in(&thread_affinity().unwrap());
    let vm = ProbeVm::new(&SPIN_DONE_BLOB, 0, &[0; 0x80], 0x3f_f000, &[done_at(25)])
        .expect("actual KVM is mandatory");
    let before = vm.stats.snapshot().unwrap();
    let bound = std::time::Duration::from_secs(30);
    let start = std::time::Instant::now();
    let (vm, p7) = run_p7_admitted(vm, start + bound, intended, caller, eacces).unwrap();
    // The handshake, not the deadline, ended it.
    assert!(start.elapsed() < bound, "{p7:?}");
    assert_eq!(
        before.delta_to(&vm.stats.snapshot().unwrap()).unwrap(),
        VcpuStatsSnapshot::default(),
        "no KVM_RUN"
    );
    assert_eq!(p7.refusal, None);
    assert!(p7.cpus.is_some(), "P7 needs two allowed CPUs");
    assert_eq!(
        (p7.observed_vcpu_nice, p7.observed_peer_nice),
        (Some(caller), Some(caller))
    );
    assert_eq!(
        p7.vcpu_nice_refused,
        Some(Error::HostIo(io::Error::from_raw_os_error(libc::EACCES)).to_string())
    );
    assert!(!p7.nice_established);
    assert_eq!((p7.run, p7.peer), (None, None));
    assert!(!p7.marker_seen);
    assert!(!p7.kicked);
    assert_eq!(cpus_in(&thread_affinity().unwrap()), affinity);
}

/// cx F5's corners of SCHED_OTHER with SCHED_RESET_ON_FORK at a negative
/// caller nice c: the threads start at 0, so the peer reads back 0, not c,
/// and the run is not started. At c = -3 the vCPU thread's raise to 2
/// succeeds; at c = -8 the target -3 would be a lowering, which the thread
/// skips, so it stays at 0.
#[test]
fn reset_on_fork_at_a_negative_caller_nice_leaves_p7_unestablished() {
    let reset = ThreadPolicy {
        policy: libc::SCHED_OTHER | libc::SCHED_RESET_ON_FORK,
        priority: 0,
    };
    assert_eq!(p7_admission(reset, -3), (2, None));
    assert!(!p7_nice_established(Some(2), Some(0), 2, -3, false));
    assert_eq!(p7_admission(reset, -8), (-3, None));
    assert!(!p7_nice_established(Some(0), Some(0), -3, -8, true));
}

/// No thread's nice is ever lowered (r7 l.715). The synthetic case is the
/// SCHED_RESET_ON_FORK corner at caller nice -8: the vCPU thread inherits 0
/// and P7 intends -3, and the setter is never called, so the case needs no
/// privileged run. The setter is called once for a raise, not at all for an
/// equal value, and its failure on a raise is reported.
#[test]
fn p7_never_lowers_the_vcpu_nice_and_calls_the_setter_only_to_raise() {
    thread_local! {
        static SETTER_CALLS: std::cell::RefCell<Vec<i32>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }
    fn recording(nice: i32) -> Result<()> {
        SETTER_CALLS.with(|calls| calls.borrow_mut().push(nice));
        Ok(())
    }
    fn eacces(_: i32) -> Result<()> {
        Err(Error::HostIo(io::Error::from_raw_os_error(libc::EACCES)))
    }
    let calls = || SETTER_CALLS.with(|cell| cell.take());
    assert_eq!(
        p7_raise_nice(0, -3, recording),
        Some("not lowered: inherited nice 0, intended -3".to_string())
    );
    assert!(calls().is_empty());
    assert_eq!(p7_raise_nice(0, 2, recording), None);
    assert_eq!(calls(), [2]);
    assert_eq!(p7_raise_nice(14, 14, recording), None);
    assert!(calls().is_empty());
    assert_eq!(
        p7_raise_nice(14, 19, eacces),
        Some(Error::HostIo(io::Error::from_raw_os_error(libc::EACCES)).to_string())
    );
    // The setup reads the thread's own inherited value: a lower target is
    // skipped without a call, and the read-back is unchanged.
    let affinity = AffinityGuard::save().unwrap();
    let x = cpus_in(affinity.saved())[0];
    let caller = thread_nice().unwrap();
    let (observed, refused) = p7_vcpu_setup(x, caller - 1, recording).unwrap();
    assert!(calls().is_empty());
    assert_eq!(observed, caller);
    assert_eq!(
        refused,
        Some(format!(
            "not lowered: inherited nice {caller}, intended {}",
            caller - 1
        ))
    );
    assert!(!p7_nice_established(
        Some(observed),
        Some(caller),
        caller - 1,
        caller,
        refused.is_some()
    ));
}
