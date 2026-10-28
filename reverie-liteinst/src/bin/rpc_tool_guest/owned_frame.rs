/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * Licensed under the BSD-style license in the repository root LICENSE.
 */

use core::sync::atomic::AtomicU64;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::path::Path;

use reverie::Error;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_inguest::trap::raw_syscall6;

const STACK_BYTES: usize = 1024 * 1024;
const XSTATE_OFFSET: usize = 512;
static GUEST_STACK: AtomicUsize = AtomicUsize::new(0);
static GUEST_STACK_END: AtomicUsize = AtomicUsize::new(0);
static AVX: AtomicUsize = AtomicUsize::new(0);
static AVX512: AtomicUsize = AtomicUsize::new(0);
static CALLBACKS: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
struct State {
    fields: [u64; 56],
    seed: [u8; 64],
}

#[derive(Default)]
struct FrameTool;

#[reverie::tool]
impl Tool for FrameTool {
    type GlobalState = super::CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_: &()) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        // Async locals can reside in the allocated future. Observe the live
        // hardware stack pointer, rather than mistaking future storage for it.
        let address: usize;
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) address, options(nostack, nomem, preserves_flags))
        };
        assert!(unsafe { reverie_liteinst_on_owned_fallback_stack(address) });
        assert!(
            !(GUEST_STACK.load(Ordering::Relaxed)..GUEST_STACK_END.load(Ordering::Relaxed))
                .contains(&address)
        );
        let registers = guest.regs().await;
        assert_eq!(
            registers.rip,
            core::ptr::addr_of!(owned_frame_guest_syscall) as u64
        );
        assert_eq!(
            registers.rsp,
            GUEST_STACK_END.load(Ordering::Relaxed) as u64 - 256
        );
        let mut control = 0u16;
        let mut mxcsr = 0u32;
        unsafe {
            core::arch::asm!("fnstcw [{control}]", "stmxcsr [{mxcsr}]", control = in(reg) &mut control, mxcsr = in(reg) &mut mxcsr, options(nostack, preserves_flags));
        }
        assert_eq!(control, 0x037f);
        assert_eq!(mxcsr, 0x1f80);
        assert_eq!(read_pkru(), 0);
        let _ = guest.send_rpc(1).await;
        CALLBACKS.fetch_add(1, Ordering::Relaxed);
        let result = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
        unsafe {
            owned_frame_clobber_guest_fp(
                AVX.load(Ordering::Relaxed) as i32,
                AVX512.load(Ordering::Relaxed) as i32,
            )
        };
        Ok(result)
    }
}

#[derive(Clone, Debug)]
struct Observation {
    registers: [u64; 19],
    pkru: u32,
    xstate: Vec<u8>,
}

fn read_pkru() -> u32 {
    let value;
    unsafe {
        core::arch::asm!("rdpkru", in("ecx") 0u32, out("eax") value, out("edx") _, options(nostack, preserves_flags))
    };
    value
}

fn map(bytes: usize) -> *mut u8 {
    let value = unsafe {
        raw_syscall6(
            libc::SYS_mmap,
            [
                0,
                bytes as u64,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                u64::MAX,
                0,
            ],
        )
    };
    assert!(value > 0, "mmap: {value}");
    value as *mut u8
}

fn protect(address: *mut u8, bytes: usize, protection: i32) {
    assert_eq!(
        unsafe {
            raw_syscall6(
                libc::SYS_mprotect,
                [address as u64, bytes as u64, protection as u64, 0, 0, 0],
            )
        },
        0
    );
}

fn unregister_rseq() -> Option<usize> {
    let offset = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__rseq_offset".as_ptr()) };
    let size = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__rseq_size".as_ptr()) };
    assert!(!offset.is_null() && !size.is_null());
    let size = unsafe { *size.cast::<u32>() };
    if size == 0 {
        return None;
    }
    assert!(size <= 32, "unsupported rseq layout {size}");
    let mut fs = 0usize;
    assert_eq!(
        unsafe {
            raw_syscall6(
                libc::SYS_arch_prctl,
                [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
            )
        },
        0
    );
    let area = fs
        .checked_add_signed(unsafe { *offset.cast::<isize>() })
        .unwrap();
    assert_eq!(
        unsafe { raw_syscall6(libc::SYS_rseq, [area as u64, 32, 1, 0x5305_3053, 0, 0]) },
        0
    );
    Some(area)
}

fn observe(
    pointer: *mut u8,
    bytes: usize,
    number: i64,
    args: [u64; 6],
    pkru: u32,
    mediated: bool,
    partial_hole: Option<(usize, usize)>,
) -> Observation {
    let state = unsafe { &mut *pointer.cast::<State>() };
    state.fields[8] = number as u64;
    state.fields[9..15].copy_from_slice(&args);
    state.fields[17] = u64::from(pkru);
    state.fields[43] = u64::MAX;
    state.fields[44] = 0;
    state.fields[46] = 0x3f80;
    state.fields[47] = 0x077f;
    let image = unsafe { pointer.add(XSTATE_OFFSET) };
    unsafe { image.write_bytes(0, bytes) };
    let before = core::array::from_fn::<_, 3, _>(|i| unsafe {
        reverie_liteinst_owned_fallback_observation(i as u32)
    });
    if let Some((address, length)) = partial_hole {
        // Keep this fixture-owned page reserved through runtime initialization.
        // Expose the hole only across the operation; no allocation precedes it.
        assert_eq!(
            unsafe {
                raw_syscall6(
                    libc::SYS_munmap,
                    [address as u64, length as u64, 0, 0, 0, 0],
                )
            },
            0
        );
    }
    unsafe { owned_frame_enter_guest(pointer.cast()) };
    if let Some((address, length)) = partial_hole {
        // Assembly already captured actual return registers/PKRU/XSAVE before
        // restoring harness access. Reserve the hole before result allocation;
        // NOREPLACE refuses to overwrite any unexpected mapping.
        assert_eq!(
            unsafe {
                raw_syscall6(
                    libc::SYS_mmap,
                    [
                        address as u64,
                        length as u64,
                        libc::PROT_NONE as u64,
                        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE)
                            as u64,
                        u64::MAX,
                        0,
                    ],
                )
            },
            address as i64
        );
    }
    let state = unsafe { &*pointer.cast::<State>() };
    let after = core::array::from_fn::<_, 3, _>(|i| unsafe {
        reverie_liteinst_owned_fallback_observation(i as u32)
    });
    assert_eq!(state.fields[44], 1, "guest continuation was not reached");
    for i in 0..3 {
        assert_eq!(after[i] - before[i], u64::from(mediated), "observation {i}");
    }
    let registers = state.fields[24..43].try_into().unwrap();
    Observation {
        registers,
        pkru: state.fields[43] as u32,
        xstate: unsafe { core::slice::from_raw_parts(image, bytes) }.to_vec(),
    }
}

pub(super) fn run(path: &Path) {
    if core::arch::x86_64::__cpuid_count(7, 0).ecx & (1 << 4) == 0 {
        println!("owned frame: OSPKE unavailable");
        std::process::exit(77);
    }
    let rseq = unregister_rseq();
    let original_harness_pkru = read_pkru();
    unsafe {
        core::arch::asm!("wrpkru", "lfence", in("eax") 0u32, in("ecx") 0u32, in("edx") 0u32, options(nostack, preserves_flags))
    };
    let mask = unsafe { core::arch::x86_64::_xgetbv(0) };
    let bytes = core::arch::x86_64::__cpuid_count(0xd, 0).ebx as usize;
    assert!(bytes >= 576);
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let observation_bytes = (XSTATE_OFFSET + bytes).div_ceil(page) * page + STACK_BYTES;
    let observation = map(observation_bytes);
    let guest_stack = map(STACK_BYTES);
    let partial = map(page * 2);
    let key = unsafe { raw_syscall6(libc::SYS_pkey_alloc, [0; 6]) };
    assert!(key > 0);
    assert_eq!(
        unsafe {
            raw_syscall6(
                libc::SYS_pkey_mprotect,
                [
                    observation as u64,
                    observation_bytes as u64,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    key as u64,
                    0,
                    0,
                ],
            )
        },
        0
    );
    let alt_stack = reverie_liteinst::alt_stack_from_env_value(
        std::env::var_os(reverie_liteinst::ALT_STACK_ENV).as_deref(),
    )
    .unwrap();
    if !alt_stack {
        // Genuine first delivery needs a usable stack. The existing no-alt
        // control keeps this stack on the accessible observation key.
        assert_eq!(
            unsafe {
                raw_syscall6(
                    libc::SYS_pkey_mprotect,
                    [
                        guest_stack as u64,
                        STACK_BYTES as u64,
                        (libc::PROT_READ | libc::PROT_WRITE) as u64,
                        key as u64,
                        0,
                        0,
                    ],
                )
            },
            0
        );
    }
    let guest_sp = guest_stack as u64 + STACK_BYTES as u64 - 256;
    let state = unsafe { &mut *observation.cast::<State>() };
    state.fields.fill(0);
    state.seed = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(0x31));
    state.fields[7] = mask;
    state.fields[15] = guest_sp;
    state.fields[16] = observation as u64 + observation_bytes as u64 - 256;
    state.fields[18] = u64::from(read_pkru());
    assert_eq!(
        state.fields[18], 0,
        "fixture requires explicit open harness rights"
    );
    state.fields[19] = u64::from(mask & 6 == 6);
    state.fields[20] = u64::from(mask & 0xe0 == 0xe0);
    AVX.store(state.fields[19] as usize, Ordering::Relaxed);
    AVX512.store(state.fields[20] as usize, Ordering::Relaxed);
    GUEST_STACK.store(guest_stack as usize, Ordering::Relaxed);
    GUEST_STACK_END.store(guest_stack as usize + STACK_BYTES, Ordering::Relaxed);
    let site = core::ptr::addr_of!(owned_frame_guest_syscall) as usize;
    assert_eq!(site % 64, 63);
    let site_bytes = unsafe { core::slice::from_raw_parts(site as *const u8, 2) }.to_vec();
    assert_eq!(site_bytes, [0x0f, 0x05]);
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let cases = [
        ("getpid-open", libc::SYS_getpid, [0; 6], 0),
        ("getpid-denied", libc::SYS_getpid, [0; 6], 3),
        (
            "stack-prot-none",
            libc::SYS_mprotect,
            [
                guest_stack as u64,
                STACK_BYTES as u64,
                libc::PROT_NONE as u64,
                0,
                0,
                0,
            ],
            0,
        ),
        (
            "partial-exec-error",
            libc::SYS_mprotect,
            [
                partial as u64,
                (page * 2) as u64,
                libc::PROT_EXEC as u64,
                0,
                0,
                0,
            ],
            0,
        ),
    ];
    let mut native = Vec::new();
    for mediated in [false, true] {
        if mediated {
            unsafe { reverie_liteinst::install_tool::<FrameTool>(path) }.unwrap();
        }
        for (index, (name, number, args, pkru)) in cases.iter().copied().enumerate() {
            let observed = observe(
                observation,
                bytes,
                number,
                args,
                pkru,
                mediated,
                (index == 3).then_some((partial as usize + page, page)),
            );
            assert_eq!(observed.registers[15], guest_sp);
            assert_eq!(observed.registers[7], observation as u64);
            assert_eq!(
                observed.registers[16],
                core::ptr::addr_of!(owned_frame_guest_resume) as u64
            );
            assert_eq!(
                observed.registers[13] as i64,
                if number == libc::SYS_getpid {
                    pid
                } else if index == 3 {
                    -i64::from(libc::ENOMEM)
                } else {
                    0
                }
            );
            if index == 3 {
                assert_ne!(
                    observed.pkru, 0,
                    "negative mprotect must retain its actual permission effect"
                );
            } else {
                assert_eq!(observed.pkru, pkru);
            }
            let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
            let address = if index == 3 {
                partial as usize
            } else {
                guest_stack as usize
            };
            let permissions = maps
                .lines()
                .find_map(|line| {
                    let mut parts = line.split_whitespace();
                    let (start, end) = parts.next()?.split_once('-')?;
                    let start = usize::from_str_radix(start, 16).ok()?;
                    let end = usize::from_str_radix(end, 16).ok()?;
                    (start <= address && address < end).then(|| parts.next().unwrap())
                })
                .unwrap();
            if index == 2 {
                assert_eq!(permissions, "---p");
            }
            if index == 3 {
                assert_eq!(permissions, "--xp");
            }
            println!(
                "owned frame observation: mode={} case={name} pid={pid} original-rsp={guest_sp:#x} state={:#x} mapping={permissions} pkru={} registers={:x?} xstate={:02x?}",
                if mediated { "Tool" } else { "native" },
                observation as usize,
                observed.pkru,
                observed.registers,
                observed.xstate
            );
            if mediated {
                let expected: &Observation = &native[index];
                assert_eq!(observed.registers, expected.registers, "{name} registers");
                assert_eq!(observed.pkru, expected.pkru, "{name} PKRU");
                assert_eq!(observed.xstate, expected.xstate, "{name} complete XSTATE");
            } else {
                native.push(observed);
            }
            if index == 2 {
                protect(guest_stack, STACK_BYTES, libc::PROT_READ | libc::PROT_WRITE);
            }
            if index == 3 {
                protect(partial, page, libc::PROT_READ | libc::PROT_WRITE);
            }
        }
    }
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 2);
    assert_eq!(
        unsafe { core::slice::from_raw_parts(site as *const u8, 2) },
        site_bytes
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_hook_count(site as u64),
        0
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_trap_count(site as u64),
        4
    );
    println!(
        "owned frame: rseq=unregistered native=4 Tool=4 registers=equal xstate-bytes={bytes} callback-stack=owned guest-stack-revoked=preserved negative-pkru=preserved hooks=0 traps=4"
    );
    if let Some(area) = rseq {
        assert_eq!(
            unsafe { raw_syscall6(libc::SYS_rseq, [area as u64, 32, 0, 0x5305_3053, 0, 0]) },
            0
        );
    }
    unsafe {
        core::arch::asm!("wrpkru", "lfence", in("eax") original_harness_pkru, in("ecx") 0u32, in("edx") 0u32, options(nostack, preserves_flags))
    };
}

unsafe extern "C" {
    fn owned_frame_enter_guest(state: *mut State);
    fn owned_frame_clobber_guest_fp(avx: i32, avx512: i32);
    static owned_frame_guest_syscall: u8;
    static owned_frame_guest_resume: u8;
    fn reverie_liteinst_on_owned_fallback_stack(address: usize) -> bool;
    fn reverie_liteinst_owned_fallback_observation(selector: u32) -> u64;
}

core::arch::global_asm!(include_str!("owned_frame.S"), options(att_syntax));
