/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The preemption timer against real KVM and the real PMU: the kick lands,
//! every decision follows the clock, a late arrival is recorded (exactly at
//! the target too), the clock is the same with and without the timer, an
//! unarmed thread's entries issue no syscall for the timer, a request
//! re-armed after the timer stopped counting is programmed afresh, and a
//! request found due outside user mode is delivered once back in it.
//!
//! Placement: tests whose names say pinned force pinned placement and run on
//! every host. Tests that need following placement print NOT EXECUTED and
//! return on a host whose default placement pins each entry. The rest use the
//! host's default placement and hold on either placement.

use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use super::*;
use crate::preemption_timer::KICK_SIGNAL;
use crate::preemption_timer::KICKS_DRAINED;
use crate::preemption_timer::KICKS_TAKEN;
use crate::preemption_timer::MAX_PERIOD;
use crate::preemption_timer::TIMER_SYSCALLS;
use crate::preemption_timer::reserve_kick_signal;
// The witness count is process-global: every test that reads it, here and in
// the timer's own unit tests, takes this one turn.
use crate::preemption_timer::witness_turn;

const MEMORY: usize = 16 * 1024 * 1024;

/// Timer syscalls that open the timer event at an entry, once this process
/// has installed the kick handler: query the kick signal's handler and block
/// the signal (which reads the thread's mask), `perf_event_open`, three
/// `fcntl`s, one `PERF_EVENT_IOC_PERIOD`, one `PERF_EVENT_IOC_ENABLE` and one
/// `KVM_SET_SIGNAL_MASK`. A pinned entry also disables its CPU-bound event
/// when it ends, one more, and an entry that a kick ends takes the kick, one
/// more.
const OPEN_SYSCALLS: u64 = 9;

fn margin() -> u64 {
    reverie::pmu_config::try_get_pmu_config()
        .expect("the preemption timer requires this CPU's PMU profile")
        .skid_margin()
}

fn timer_syscalls() -> u64 {
    TIMER_SYSCALLS.with(|count| count.get())
}

fn kicks_taken() -> u64 {
    KICKS_TAKEN.with(|kicks| kicks.load(Ordering::Relaxed))
}

fn kicks_drained() -> u64 {
    KICKS_DRAINED.with(|kicks| kicks.get())
}

/// A CPL3 loop, forever: exactly `branches` conditional branches (`dec ecx;
/// jnz`), then a getpid transport exit. The k-th exit is at clock k *
/// `branches`, and no branch retires between a block's last branch and its
/// exit, so an overflow at a block's end is followed by an exit at the same
/// count whether the kick or the syscall comes first.
fn block_loop(branches: u32) -> Vec<u8> {
    assert!(branches > 0);
    let mut code = vec![0xb9]; // start: mov ecx, branches
    code.extend_from_slice(&branches.to_le_bytes());
    code.extend_from_slice(&[
        0xff, 0xc9, 0x75, 0xfc, // loop: dec ecx; jnz loop
        0xb8, 39, 0, 0, 0, // mov eax, SYS_getpid
        0x0f, 0x05, // syscall
        0xeb, 0xee, // jmp start
    ]);
    code
}

/// A CPL3 loop with no exit at all: one taken JZ per iteration, forever.
const SPINNER: [u8; 6] = [
    0x31, 0xc0, // xor eax, eax
    0x85, 0xc0, // loop: test eax, eax
    0x74, 0xfc, // jz loop
];

/// Pins this thread to the CPU it is on until dropped, so that pinned entries
/// keep one counter identity and never reopen their events.
struct PinThread(libc::cpu_set_t);

impl PinThread {
    fn here() -> Self {
        let saved = affinity().unwrap();
        let cpu = current_cpu().expect("sched_getcpu");
        // SAFETY: an all-zero cpu_set_t is the empty set; `cpu` is below
        // CPU_SETSIZE because the kernel reported it.
        let mut one: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe { libc::CPU_SET(cpu, &mut one) };
        set_affinity(&one).unwrap();
        Self(saved)
    }
}

impl Drop for PinThread {
    fn drop(&mut self) {
        let _ = set_affinity(&self.0);
    }
}

fn counted_backend(code: &[u8], placement: CounterPlacement) -> crate::KvmBackend {
    let mut backend =
        crate::KvmBackend::new(MEMORY).expect("the preemption timer controls require /dev/kvm");
    backend
        .install_static_elf(&crate::vm::minimal_test_elf(code), "/bin/preemption-timer")
        .unwrap();
    assert_eq!(backend.vcpu.get_sregs().unwrap().cs.dpl, 3);
    backend.vcpu.clock.placement = placement;
    backend.vcpu.track_clock().unwrap();
    backend
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Exit {
    Syscall,
    Kick,
}

fn next_exit(vcpu: &mut CountedVcpu) -> Exit {
    match vcpu.run() {
        Ok(Some(VcpuExit::Hypercall(exit))) => {
            assert_eq!(exit.nr, crate::vm::VMCALL_SYSCALL_TRANSPORT);
            Exit::Syscall
        }
        Ok(Some(exit)) => panic!("unexpected exit {exit:?}"),
        Ok(None) => panic!("entry admission was closed"),
        Err(Error::Kvm(error)) if error.errno() == libc::EINTR => Exit::Kick,
        Err(error) => panic!("entry failed: {error}"),
    }
}

fn timer_event(vcpu: &CountedVcpu) -> Option<&TimerEvent> {
    vcpu.clock.binding.as_ref().and_then(|b| b.timer.as_ref())
}

/// The timer event's own count and the clock's advance since the entry that
/// opened that event, read once at the end of a test. The two are equal when
/// the timer counted exactly the branches its clock counted. An event
/// reopened with its binding (another host thread or CPU) counts from zero.
fn timer_and_clock_advance(vcpu: &CountedVcpu) -> (u64, u64) {
    let timer = timer_event(vcpu).expect("an armed thread has a timer event");
    let advance = vcpu.read_clock().unwrap() - timer.opened_clock;
    (timer_count(vcpu), advance)
}

/// The timer event's own count since it was opened.
fn timer_count(vcpu: &CountedVcpu) -> u64 {
    let timer = timer_event(vcpu).expect("an armed thread has a timer event");
    let mut value = 0_u64;
    // SAFETY: a sampling event with no read_format reads one native u64.
    let read = unsafe {
        libc::read(
            timer.fd().as_raw_fd(),
            std::ptr::from_mut(&mut value).cast(),
            std::mem::size_of::<u64>(),
        )
    };
    assert_eq!(read, std::mem::size_of::<u64>() as isize);
    value
}

/// A request found due. These tests take no single steps, so a precise
/// request is always late, and an on-time one is imprecise.
fn due(target: u64, clock: u64, late: bool) -> Option<TimerDue> {
    Some(TimerDue {
        target,
        clock,
        late,
        kind: if late {
            TimerKind::Precise
        } else {
            TimerKind::Imprecise
        },
    })
}

/// A request's phases at exits that land on exact counts, under `placement`:
/// the first programming one skid margin short of the target, the second at
/// the target, and the exit at exactly the target recorded as late.
fn exits_follow_the_clock(placement: CounterPlacement) {
    let _turn = witness_turn();
    let margin = margin();
    if margin < 2 || margin > u64::from(u32::MAX) / 8 {
        println!("timer phases: NOT EXECUTED; skid margin {margin} is overridden out of range");
        return;
    }
    // One block per skid margin puts every programmed overflow at a block's
    // end, so each exit's clock is exact however late its kick is.
    let block = margin;
    let mut backend = counted_backend(&block_loop(block as u32), placement);
    backend
        .vcpu
        .request_timer(3 * block, TimerKind::Precise)
        .unwrap();
    assert_eq!(backend.vcpu.timer_target(), Some(3 * block));
    let mut exits = Vec::new();
    while backend.vcpu.read_clock().unwrap() < 3 * block {
        let exit = next_exit(&mut backend.vcpu);
        let clock = backend.vcpu.read_clock().unwrap();
        let overflow = timer_event(&backend.vcpu).unwrap().overflow_at();
        exits.push((exit, clock, overflow));
        if clock < 3 * block {
            assert_eq!(backend.vcpu.timer_due(), None, "{exits:?}");
        }
        // A kick whose interrupt came very late can land anywhere; a
        // syscall exit is always at a block's end.
        if exit == Exit::Syscall {
            assert_eq!(clock % block, 0, "{exits:?}");
            match clock / block {
                // The first programming overflows one margin short of the
                // target.
                1 => assert_eq!(overflow, Some(2 * block), "{exits:?}"),
                // Its overflow is reached and forgotten; an entry after a
                // kick at the block's end programs the target before the
                // block's exit.
                2 => assert!(overflow.is_none_or(|at| at == 3 * block), "{exits:?}"),
                _ => {}
            }
        }
    }
    // The first exit at or past the target is at exactly the target: no
    // branch retires between the block's last branch and its syscall exit.
    assert_eq!(backend.vcpu.read_clock().unwrap(), 3 * block, "{exits:?}");
    // Exactly at the target, and still late: the exit is asynchronous.
    assert_eq!(
        backend.vcpu.timer_due(),
        due(3 * block, 3 * block, true),
        "{exits:?}"
    );
    assert_eq!(reverie::take_skid_overshoot_count(), 1);
    // Later exits find it already due and record nothing more.
    while backend.vcpu.read_clock().unwrap() < 4 * block {
        next_exit(&mut backend.vcpu);
        assert_eq!(backend.vcpu.timer_due(), due(3 * block, 3 * block, true));
    }
    assert_eq!(reverie::take_skid_overshoot_count(), 0);

    // Past the target: the kick or the block's exit, whichever comes first,
    // finds the clock at or past it, but never past the block's end.
    backend
        .vcpu
        .request_timer(block / 2, TimerKind::Precise)
        .unwrap();
    let target = 4 * block + block / 2;
    while backend.vcpu.timer_due().is_none() {
        next_exit(&mut backend.vcpu);
    }
    let late = backend.vcpu.timer_due().unwrap();
    assert_eq!(late.target, target);
    assert!(late.late);
    assert!((target..=5 * block).contains(&late.clock), "{late:?}");
    assert_eq!(reverie::take_skid_overshoot_count(), 1);
    while backend.vcpu.read_clock().unwrap() < 5 * block {
        next_exit(&mut backend.vcpu);
    }

    // An imprecise request reached at its target is on time: nothing recorded.
    backend
        .vcpu
        .request_timer(block, TimerKind::Imprecise)
        .unwrap();
    while backend.vcpu.timer_due().is_none() {
        next_exit(&mut backend.vcpu);
    }
    assert_eq!(backend.vcpu.timer_due(), due(6 * block, 6 * block, false));
    assert_eq!(reverie::take_skid_overshoot_count(), 0);

    // A replaced request is forgotten; a cancelled one never comes due.
    backend
        .vcpu
        .request_timer(9 * block, TimerKind::Precise)
        .unwrap();
    backend
        .vcpu
        .request_timer(2 * block, TimerKind::Precise)
        .unwrap();
    assert_eq!(backend.vcpu.timer_target(), Some(8 * block));
    while backend.vcpu.timer_due().is_none() {
        next_exit(&mut backend.vcpu);
    }
    assert_eq!(backend.vcpu.timer_due(), due(8 * block, 8 * block, true));
    assert_eq!(reverie::take_skid_overshoot_count(), 1);
    backend
        .vcpu
        .request_timer(2 * block, TimerKind::Precise)
        .unwrap();
    backend.vcpu.cancel_timer();
    assert_eq!(backend.vcpu.timer_target(), None);
    while backend.vcpu.read_clock().unwrap() < 12 * block {
        next_exit(&mut backend.vcpu);
        assert_eq!(backend.vcpu.timer_due(), None);
    }
    assert_eq!(reverie::take_skid_overshoot_count(), 0);
    println!(
        "timer phases ({placement:?}, margin {margin}): {} exits to the first target: {exits:?}",
        exits.len()
    );
}

#[test]
fn exits_follow_the_clock_with_following_events() {
    if CounterPlacement::default() != CounterPlacement::FollowTask {
        println!("timer phases: FollowTask NOT EXECUTED; this host pins each entry");
        return;
    }
    exits_follow_the_clock(CounterPlacement::FollowTask);
}

#[test]
fn exits_follow_the_clock_with_pinned_entries() {
    let _pin = PinThread::here();
    exits_follow_the_clock(CounterPlacement::PinEachEntry);
}

/// Runs `rounds` requests on a guest that never exits by itself, so every
/// exit is a kick: a lost kick would leave `KVM_RUN` running until the
/// watchdog sends one, which fails the test.
fn every_kick_lands(placement: CounterPlacement, rounds: u64) {
    let _turn = witness_turn();
    let margin = margin();
    let mut backend = counted_backend(&SPINNER, placement);
    let steps = [
        1,
        2,
        3,
        5,
        6,
        margin.saturating_sub(1).max(1),
        margin.max(1),
        margin + 5,
        margin + 6,
        2 * margin + 1,
        10_005,
        10_006,
        100_000,
        1_000_000,
    ];
    let progress = AtomicU64::new(0);
    let done = AtomicBool::new(false);
    let rescued = AtomicU64::new(0);
    // SAFETY: the identity of this thread, which outlives the watchdog.
    let vcpu_thread = unsafe { libc::pthread_self() };
    let taken_before = kicks_taken();
    let drained_before = kicks_drained();
    let mut exits = 0_u64;
    let mut precise = 0_u64;
    let mut most_late = 0_u64;
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut last = 0;
            let mut since = Instant::now();
            while !done.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
                let now = progress.load(Ordering::SeqCst);
                if now != last {
                    last = now;
                    since = Instant::now();
                } else if since.elapsed() > Duration::from_secs(10) {
                    rescued.fetch_add(1, Ordering::SeqCst);
                    // SAFETY: the vCPU thread is alive until `done` is set.
                    unsafe { libc::pthread_kill(vcpu_thread, KICK_SIGNAL) };
                    since = Instant::now();
                }
            }
        });
        struct Done<'a>(&'a AtomicBool);
        impl Drop for Done<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let _done = Done(&done);
        for round in 0..rounds {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let ticks = if round % 2 == 0 {
                steps[(round / 2) as usize % steps.len()]
            } else {
                1 + (seed >> 33) % 200_000
            };
            let kind = if round % 3 == 0 {
                TimerKind::Imprecise
            } else {
                TimerKind::Precise
            };
            let start = backend.vcpu.read_clock().unwrap();
            backend.vcpu.request_timer(ticks, kind).unwrap();
            while backend.vcpu.timer_due().is_none() {
                assert_eq!(next_exit(&mut backend.vcpu), Exit::Kick);
                exits += 1;
            }
            let reached = backend.vcpu.timer_due().unwrap();
            assert_eq!(reached.target, start + ticks, "round {round}");
            assert!(
                reached.clock >= reached.target,
                "round {round}: {reached:?}"
            );
            assert_eq!(reached.late, kind == TimerKind::Precise, "round {round}");
            precise += u64::from(reached.late);
            most_late = most_late.max(reached.clock - reached.target);
            progress.fetch_add(1, Ordering::SeqCst);
        }
    });
    assert_eq!(rescued.load(Ordering::SeqCst), 0, "a kick was lost");
    assert_eq!(reverie::take_skid_overshoot_count(), precise);
    assert!(exits >= rounds, "every round needs a kick");
    // Every EINTR exit took the kick that ended it, from the thread's
    // pending signals, and no kick reached the handler: none landed in host
    // code unblocked.
    let drained = kicks_drained() - drained_before;
    assert_eq!(drained, exits, "one kick taken at each EINTR exit");
    assert_eq!(kicks_taken() - taken_before, 0, "a kick ran the handler");
    // The timer counted exactly what the clock counted from the entry that
    // opened it: neither lost a branch to the other's kicks.
    let clock = backend.vcpu.read_clock().unwrap();
    let (timer, advance) = timer_and_clock_advance(&backend.vcpu);
    assert_eq!(timer, advance);
    println!(
        "timer kicks ({placement:?}, margin {margin}): {rounds} requests, {exits} EINTR exits, \
         {drained} kicks taken at those exits, 0 by the handler, 0 lost; clock {clock}; timer \
         count {timer} = clock advance since it opened; largest overshoot {most_late} RCBs"
    );
}

#[test]
fn every_kick_lands_with_following_events() {
    if CounterPlacement::default() != CounterPlacement::FollowTask {
        println!("timer kicks: FollowTask NOT EXECUTED; this host pins each entry");
        return;
    }
    every_kick_lands(CounterPlacement::FollowTask, 2_000);
}

#[test]
fn every_kick_lands_with_pinned_entries() {
    // One CPU for the whole test: a pinned event opened on another CPU would
    // count only from its own opening.
    let _pin = PinThread::here();
    every_kick_lands(CounterPlacement::PinEachEntry, 500);
}

/// The clocks at a deterministic guest's syscall exits, with no timer or
/// with a precise request renewed at every exit `ticks` RCBs ahead, and how
/// many kicks the timer caused. After `moved_at` syscall exits the guest
/// moves to another host thread, which reopens its binding: its clock and,
/// when armed, its timer. With a timer, also returns the clock value at the
/// entry that opened the current timer event.
fn clocks_at_syscalls(
    blocks: usize,
    branches: u32,
    ticks: Option<u64>,
    moved_at: usize,
) -> (Vec<u64>, u64, Option<u64>) {
    let mut backend = counted_backend(&block_loop(branches), CounterPlacement::default());
    let mut clocks = Vec::new();
    let mut kicks = 0;
    let mut run = |backend: &mut crate::KvmBackend, until: usize| {
        while clocks.len() < until {
            if let Some(ticks) = ticks {
                backend
                    .vcpu
                    .request_timer(ticks, TimerKind::Precise)
                    .unwrap();
            }
            match next_exit(&mut backend.vcpu) {
                Exit::Syscall => clocks.push(backend.vcpu.read_clock().unwrap()),
                Exit::Kick => kicks += 1,
            }
        }
    };
    run(&mut backend, moved_at);
    let first_tid = backend.vcpu.clock.binding.as_ref().unwrap().identity.tid;
    std::thread::scope(|scope| scope.spawn(|| run(&mut backend, blocks)).join().unwrap());
    assert_ne!(
        backend.vcpu.clock.binding.as_ref().unwrap().identity.tid,
        first_tid,
        "the guest must really move to another host task"
    );
    let opened = ticks.map(|_| {
        let (timer, advance) = timer_and_clock_advance(&backend.vcpu);
        assert_eq!(timer, advance, "the timer and its clock disagree");
        timer_event(&backend.vcpu).unwrap().opened_clock
    });
    if ticks.is_none() {
        assert!(timer_event(&backend.vcpu).is_none());
    }
    (clocks, kicks, opened)
}

#[test]
fn the_clock_is_bit_exact_with_and_without_the_timer() {
    let _turn = witness_turn();
    const BLOCKS: usize = 30;
    const MOVED_AT: usize = 10;
    const BRANCHES: u32 = 100_003;
    let (without, no_kicks, _) = clocks_at_syscalls(BLOCKS, BRANCHES, None, MOVED_AT);
    let (with, kicks, opened) = clocks_at_syscalls(BLOCKS, BRANCHES, Some(997), MOVED_AT);
    let expected: Vec<u64> = (1..=BLOCKS as u64)
        .map(|block| block * u64::from(BRANCHES))
        .collect();
    assert_eq!(without, expected);
    assert_eq!(with, without, "the timer changed the clock");
    assert_eq!(no_kicks, 0);
    assert!(
        kicks > BLOCKS as u64,
        "the timer must kick within blocks: {kicks}"
    );
    // The move reopened the timer partway, so its own count restarted there:
    // compared with the whole clock, it would fall short by `opened`.
    let opened = opened.unwrap();
    assert!(opened >= MOVED_AT as u64 * u64::from(BRANCHES), "{opened}");
    let _ = reverie::take_skid_overshoot_count();
    println!(
        "timer clock parity: {BLOCKS} syscall clocks equal with and without the timer; \
         {kicks} kicks with a request renewed 997 RCBs ahead; the guest moved host threads \
         after {MOVED_AT} exits and its timer reopened at clock {opened}"
    );
}

#[test]
fn unarmed_entries_issue_no_timer_syscalls_and_armed_ones_only_on_change() {
    let _turn = witness_turn();
    if CounterPlacement::default() != CounterPlacement::FollowTask {
        println!("timer syscalls: FollowTask NOT EXECUTED; this host pins each entry");
        return;
    }
    const BRANCHES: u32 = 10;
    const EXITS: u64 = 1_000;
    let mut backend = counted_backend(&block_loop(BRANCHES), CounterPlacement::FollowTask);
    let run = |backend: &mut crate::KvmBackend, exits: u64| -> u64 {
        let before = timer_syscalls();
        for _ in 0..exits {
            assert_eq!(next_exit(&mut backend.vcpu), Exit::Syscall);
        }
        timer_syscalls() - before
    };
    // Never armed: no event, no syscall.
    assert_eq!(run(&mut backend, EXITS), 0);
    assert!(timer_event(&backend.vcpu).is_none());
    // Armed far ahead: the first entry opens and programs the event, and no
    // later entry touches it while the target is unchanged. The kick handler
    // is installed first, so that the count does not depend on whether
    // another test in this process installed it already.
    reserve_kick_signal().unwrap();
    backend
        .vcpu
        .request_timer(1 << 40, TimerKind::Precise)
        .unwrap();
    let target = backend.vcpu.timer_target().unwrap();
    let opened = run(&mut backend, 1);
    assert_eq!(opened, OPEN_SYSCALLS);
    assert_eq!(run(&mut backend, EXITS), 0);
    // The same target requested again: nothing to change.
    let clock = backend.vcpu.read_clock().unwrap();
    backend
        .vcpu
        .request_timer(target - clock, TimerKind::Precise)
        .unwrap();
    assert_eq!(run(&mut backend, EXITS), 0);
    // An earlier target: one reprogramming.
    backend
        .vcpu
        .request_timer(1 << 39, TimerKind::Precise)
        .unwrap();
    assert_eq!(run(&mut backend, EXITS), 1);
    // A later target keeps the earlier overflow, which only kicks sooner.
    backend
        .vcpu
        .request_timer(1 << 41, TimerKind::Precise)
        .unwrap();
    assert_eq!(run(&mut backend, EXITS), 0);
    // Cancelled: one quieting programming, then nothing.
    backend.vcpu.cancel_timer();
    assert_eq!(run(&mut backend, 1), 1);
    assert_eq!(run(&mut backend, EXITS), 0);
    assert_eq!(reverie::take_skid_overshoot_count(), 0);
    println!(
        "timer syscalls: 0 per entry unarmed and while a target is unchanged ({EXITS} entries each); \
         {opened} to open, 1 per earlier target, 1 to quiet"
    );
}

#[test]
fn pinned_entries_enable_the_timer_only_while_armed() {
    let _turn = witness_turn();
    // One CPU, so that every entry keeps the same counter identity.
    let _pin = PinThread::here();
    const EXITS: u64 = 200;
    let mut backend = counted_backend(&block_loop(10), CounterPlacement::PinEachEntry);
    let run = |backend: &mut crate::KvmBackend, exits: u64| -> u64 {
        let before = timer_syscalls();
        for _ in 0..exits {
            assert_eq!(next_exit(&mut backend.vcpu), Exit::Syscall);
        }
        timer_syscalls() - before
    };
    assert_eq!(run(&mut backend, EXITS), 0);
    assert!(timer_event(&backend.vcpu).is_none());
    backend
        .vcpu
        .request_timer(1 << 40, TimerKind::Precise)
        .unwrap();
    run(&mut backend, 1);
    // A CPU-bound event is enabled for each armed entry and disabled after.
    assert_eq!(run(&mut backend, EXITS), 2 * EXITS);
    assert!(!timer_event(&backend.vcpu).unwrap().enabled());
    // Cancelled: a disabled event cannot overflow, so it is left alone.
    backend.vcpu.cancel_timer();
    assert_eq!(run(&mut backend, EXITS), 0);
    assert_eq!(reverie::take_skid_overshoot_count(), 0);
}

#[test]
fn another_guest_on_the_host_task_does_not_advance_the_timer() {
    let _turn = witness_turn();
    if CounterPlacement::default() != CounterPlacement::FollowTask {
        println!("timer displacement: NOT EXECUTED; this host pins each entry");
        return;
    }
    const BRANCHES: u32 = 1_000;
    let mut armed = counted_backend(&block_loop(BRANCHES), CounterPlacement::FollowTask);
    armed
        .vcpu
        .request_timer(1 << 40, TimerKind::Precise)
        .unwrap();
    for _ in 0..3 {
        assert_eq!(next_exit(&mut armed.vcpu), Exit::Syscall);
    }
    assert!(timer_event(&armed.vcpu).unwrap().enabled());
    // Another counted guest on this host task enables its own clock, which
    // disables the armed thread's clock and timer while it runs.
    let mut other = counted_backend(&block_loop(100_000), CounterPlacement::FollowTask);
    for _ in 0..5 {
        assert_eq!(next_exit(&mut other.vcpu), Exit::Syscall);
    }
    assert_eq!(other.vcpu.read_clock().unwrap(), 500_000);
    assert!(
        armed
            .vcpu
            .clock
            .binding
            .as_ref()
            .unwrap()
            .displaced
            .load(Ordering::Relaxed)
    );
    for _ in 0..3 {
        assert_eq!(next_exit(&mut armed.vcpu), Exit::Syscall);
    }
    assert!(timer_event(&armed.vcpu).unwrap().enabled());
    assert_eq!(armed.vcpu.read_clock().unwrap(), 6 * u64::from(BRANCHES));
    let (timer, advance) = timer_and_clock_advance(&armed.vcpu);
    assert_eq!(
        (timer, advance),
        (6 * u64::from(BRANCHES), 6 * u64::from(BRANCHES)),
        "the armed timer counted the other guest's branches"
    );
    assert_eq!(reverie::take_skid_overshoot_count(), 0);
}

#[test]
fn the_timer_follows_a_guest_to_another_host_thread() {
    let _turn = witness_turn();
    let margin = margin();
    let mut backend = counted_backend(&SPINNER, CounterPlacement::default());
    let placement = backend.vcpu.clock.placement;
    let ticks = 100 * margin.max(1_000);
    backend
        .vcpu
        .request_timer(ticks, TimerKind::Precise)
        .unwrap();
    // The first kick, normally one margin short of the target, comes on this
    // thread and leaves a timer event bound to it.
    assert_eq!(next_exit(&mut backend.vcpu), Exit::Kick);
    let mut late = u64::from(backend.vcpu.timer_due().is_some());
    let first_tid = backend.vcpu.clock.binding.as_ref().unwrap().identity.tid;
    let (opened, tid, start) = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let start = backend.vcpu.read_clock().unwrap();
                backend
                    .vcpu
                    .request_timer(ticks, TimerKind::Precise)
                    .unwrap();
                // The first entry on this thread opens its own timer event.
                let before = timer_syscalls();
                assert_eq!(next_exit(&mut backend.vcpu), Exit::Kick);
                let opened = timer_syscalls() - before;
                while backend.vcpu.timer_due().is_none() {
                    assert_eq!(next_exit(&mut backend.vcpu), Exit::Kick);
                }
                (opened, host_tid(), start)
            })
            .join()
            .unwrap()
    });
    late += 1;
    assert_ne!(tid, first_tid, "the test must really change host tasks");
    assert_eq!(
        backend.vcpu.clock.binding.as_ref().unwrap().identity.tid,
        tid
    );
    // The first thread's timer installed the kick handler, so the new
    // thread pays only the query and the block. The measured entry ends with
    // a kick, which it takes, and on pinned placement also with the disable
    // of its CPU-bound timer.
    let expected = OPEN_SYSCALLS + 1 + u64::from(placement == CounterPlacement::PinEachEntry);
    assert_eq!(
        opened, expected,
        "the new host task opens its own timer ({placement:?})"
    );
    let reached = backend.vcpu.timer_due().unwrap();
    assert_eq!(reached.target, start + ticks);
    assert!(
        reached.late && reached.clock >= reached.target,
        "{reached:?}"
    );
    assert_eq!(reverie::take_skid_overshoot_count(), late);
}

/// The re-arm tests' guest: blocks of `RE_ARM_BLOCK` branches, each ended by a
/// syscall exit, and a target in the middle of the third block. A request
/// programmed correctly comes due through a kick inside the third block; one
/// whose programming went stale is caught only by that block's syscall exit,
/// 2,000,000 RCBs late. That slack is about 0.7 ms of guest time, far above
/// the longest interrupt latency measured for these kicks.
const RE_ARM_BLOCK: u32 = 4_000_000;
const RE_ARM_TARGET: u64 = 10_000_000;

/// A precise request armed at clock 0 for [`RE_ARM_TARGET`], one block, then
/// `interlude` (which may cancel the request or run another guest on this
/// host task), then one block with no request, then the same absolute target
/// requested again at clock 8,000,000. Returns the timer event's pending
/// overflow just before that request, and the exits until it came due.
fn re_arm_after(
    placement: CounterPlacement,
    interlude: impl FnOnce(&mut crate::KvmBackend),
) -> (Option<u64>, Vec<(Exit, u64)>, TimerDue) {
    let block = u64::from(RE_ARM_BLOCK);
    // The request is staged: its first stage is programmed one first stage
    // margin short of the target.
    let config = reverie::pmu_config::try_get_pmu_config().unwrap();
    let margin = if config.stages(RE_ARM_TARGET) {
        config.first_stage_margin()
    } else {
        config.skid_margin()
    };
    let mut backend = counted_backend(&block_loop(RE_ARM_BLOCK), placement);
    backend
        .vcpu
        .request_timer(RE_ARM_TARGET, TimerKind::Precise)
        .unwrap();
    assert_eq!(next_exit(&mut backend.vcpu), Exit::Syscall);
    assert_eq!(backend.vcpu.read_clock().unwrap(), block);
    assert_eq!(
        timer_event(&backend.vcpu).unwrap().overflow_at(),
        Some(RE_ARM_TARGET - margin)
    );
    interlude(&mut backend);
    backend.vcpu.cancel_timer();
    while backend.vcpu.read_clock().unwrap() < 2 * block {
        next_exit(&mut backend.vcpu);
    }
    assert_eq!(backend.vcpu.read_clock().unwrap(), 2 * block);
    let before = timer_event(&backend.vcpu).unwrap().overflow_at();
    backend
        .vcpu
        .request_timer(RE_ARM_TARGET - 2 * block, TimerKind::Precise)
        .unwrap();
    let mut exits = Vec::new();
    while backend.vcpu.timer_due().is_none() {
        let exit = next_exit(&mut backend.vcpu);
        exits.push((exit, backend.vcpu.read_clock().unwrap()));
    }
    (before, exits, backend.vcpu.timer_due().unwrap())
}

/// The request came due through a kick inside the third block, at or past
/// its target, rather than at that block's syscall exit.
fn assert_due_by_kick(due: TimerDue, exits: &[(Exit, u64)]) {
    let third_exit = 3 * u64::from(RE_ARM_BLOCK);
    assert_eq!(due.target, RE_ARM_TARGET, "{exits:?}");
    assert!(due.late, "{exits:?}");
    assert!(
        (RE_ARM_TARGET..third_exit).contains(&due.clock),
        "the re-armed request came due at {}, not through a kick before the \
         block's syscall exit at {third_exit}: {exits:?}",
        due.clock
    );
    assert_eq!(
        exits.last().map(|exit| exit.0),
        Some(Exit::Kick),
        "{exits:?}"
    );
}

#[test]
fn a_request_re_armed_after_a_cancel_is_programmed_afresh_with_pinned_entries() {
    let _turn = witness_turn();
    // One CPU, so that every entry keeps the same counter identity: the event
    // that missed the unarmed block is the one re-armed.
    let _pin = PinThread::here();
    let (before, exits, due) = re_arm_after(CounterPlacement::PinEachEntry, |_| {});
    // The unarmed block ran the clock with the event disabled, so its old
    // overflow named no clock value any more and was forgotten.
    assert_eq!(before, None, "{exits:?}");
    assert_due_by_kick(due, &exits);
    assert_eq!(reverie::take_skid_overshoot_count(), 1);
    println!("timer re-arm after cancel (PinEachEntry): exits {exits:?}, due {due:?}");
}

#[test]
fn a_request_re_armed_after_a_cancel_is_programmed_afresh_with_following_events() {
    let _turn = witness_turn();
    if CounterPlacement::default() != CounterPlacement::FollowTask {
        println!("timer re-arm after cancel: FollowTask NOT EXECUTED; this host pins each entry");
        return;
    }
    let (before, exits, due) = re_arm_after(CounterPlacement::FollowTask, |_| {});
    // A following event stays enabled: the cancel quieted it.
    assert_eq!(before, None, "{exits:?}");
    assert_due_by_kick(due, &exits);
    assert_eq!(reverie::take_skid_overshoot_count(), 1);
    println!("timer re-arm after cancel (FollowTask): exits {exits:?}, due {due:?}");
}

#[test]
fn a_request_re_armed_after_a_displacement_is_programmed_afresh() {
    let _turn = witness_turn();
    if CounterPlacement::default() != CounterPlacement::FollowTask {
        println!("timer re-arm after displacement: NOT EXECUTED; this host pins each entry");
        return;
    }
    let mut other = None;
    let (before, exits, due) = re_arm_after(CounterPlacement::FollowTask, |armed| {
        // Another counted guest on this host task disables the armed
        // thread's clock and timer while it runs.
        let mut guest = counted_backend(&block_loop(1_000), CounterPlacement::FollowTask);
        assert_eq!(next_exit(&mut guest.vcpu), Exit::Syscall);
        let binding = armed.vcpu.clock.binding.as_ref().unwrap();
        assert!(binding.displaced.load(Ordering::Relaxed));
        other = Some(guest);
    });
    assert_eq!(before, None, "{exits:?}");
    assert_due_by_kick(due, &exits);
    assert_eq!(reverie::take_skid_overshoot_count(), 1);
    drop(other);
    println!("timer re-arm after displacement: exits {exits:?}, due {due:?}");
}

#[test]
fn a_timer_that_cannot_be_displaced_refuses_the_displacing_entry() {
    let _turn = witness_turn();
    if CounterPlacement::default() != CounterPlacement::FollowTask {
        println!("timer displacement refusal: NOT EXECUTED; this host pins each entry");
        return;
    }
    let mut backend = counted_backend(&block_loop(1_000), CounterPlacement::FollowTask);
    // Another binding's timer that cannot be disabled: a pipe, on which the
    // perf disable ioctl fails with ENOTTY, as a denied ioctl would.
    let mut fds = [-1; 2];
    // SAFETY: pipe2 writes two new descriptors into the array.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: both descriptors are new and owned only here.
    let (timer, _writer) = unsafe {
        (
            std::sync::Arc::new(OwnedFd::from_raw_fd(fds[0])),
            OwnedFd::from_raw_fd(fds[1]),
        )
    };
    let other_displaced = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    ENABLED_FOLLOWING_EVENT.with(|slot| {
        *slot.borrow_mut() = Some(FollowingEvents {
            clock: std::sync::Weak::new(),
            timer: Some(std::sync::Arc::downgrade(&timer)),
            displaced: other_displaced.clone(),
        });
    });
    // That binding displaced this one, which must displace it back to run.
    let binding = backend.vcpu.clock.binding.as_ref().unwrap();
    binding.displaced.store(true, Ordering::Relaxed);
    let rip = backend.vcpu.get_regs().unwrap().rip;
    let error = match backend.vcpu.run() {
        Err(error) => error,
        Ok(exit) => panic!(
            "the entry ran although another guest's timer stayed enabled: {:?}",
            exit.map(|exit| format!("{exit:?}"))
        ),
    };
    assert!(
        matches!(error.primary(), Error::GuestClock(message)
            if message.contains("disable another guest's preemption timer")),
        "{error}"
    );
    // No guest instruction ran, and the refusal is final for this clock.
    assert_eq!(backend.vcpu.get_regs().unwrap().rip, rip);
    assert!(backend.vcpu.read_clock().is_err());
    // The other binding keeps both of its events, still recorded as enabled.
    assert!(!other_displaced.load(Ordering::Relaxed));
    let recorded = ENABLED_FOLLOWING_EVENT.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|events| std::sync::Arc::ptr_eq(&events.displaced, &other_displaced))
    });
    assert!(recorded);
    ENABLED_FOLLOWING_EVENT.with(|slot| slot.borrow_mut().take());
    assert_eq!(reverie::take_skid_overshoot_count(), 0);
    println!("timer displacement refusal: {error}");
}

/// A named limit, not a guarantee: only counted entries displace another
/// binding's events. An uncounted vCPU on the armed thread's host task
/// leaves its timer enabled, the timer counts that vCPU's branches and
/// overflows inside its run, and reloads a whole period. The kick does not
/// end that vCPU's run, which has no timer and so runs under the thread's
/// own mask, where the kick signal is blocked: it stays pending and ends the
/// armed vCPU's next entry at once, before any guest instruction. This pins
/// down the consequence: the request comes due only at the block's syscall
/// exit, recorded late.
#[test]
fn an_uncounted_vcpu_on_the_host_task_makes_the_armed_kick_late() {
    let _turn = witness_turn();
    if CounterPlacement::default() != CounterPlacement::FollowTask {
        println!("timer uncounted vCPU: NOT EXECUTED; this host pins each entry");
        return;
    }
    let block = u64::from(RE_ARM_BLOCK);
    let mut armed = counted_backend(&block_loop(RE_ARM_BLOCK), CounterPlacement::FollowTask);
    armed
        .vcpu
        .request_timer(RE_ARM_TARGET, TimerKind::Precise)
        .unwrap();
    assert_eq!(next_exit(&mut armed.vcpu), Exit::Syscall);
    assert_eq!(armed.vcpu.read_clock().unwrap(), block);
    // An uncounted guest (its clock never tracked) runs 7,000,000 branches
    // on this host task: past the armed timer's remaining 5,998,000.
    let mut uncounted =
        crate::KvmBackend::new(MEMORY).expect("the preemption timer controls require /dev/kvm");
    uncounted
        .install_static_elf(
            &crate::vm::minimal_test_elf(&block_loop(7_000_000)),
            "/bin/uncounted",
        )
        .unwrap();
    let mut uncounted_exits = Vec::new();
    while uncounted_exits.last() != Some(&Exit::Syscall) {
        uncounted_exits.push(next_exit(&mut uncounted.vcpu));
    }
    assert_eq!(
        uncounted_exits,
        [Exit::Syscall],
        "a kick ended a run that has no timer"
    );
    assert!(
        signal_pending(KICK_SIGNAL),
        "the armed timer did not count the uncounted guest"
    );
    let mut exits = Vec::new();
    while armed.vcpu.timer_due().is_none() {
        let exit = next_exit(&mut armed.vcpu);
        exits.push((exit, armed.vcpu.read_clock().unwrap()));
    }
    assert_eq!(
        exits,
        [
            (Exit::Kick, block),
            (Exit::Syscall, 2 * block),
            (Exit::Syscall, 3 * block)
        ]
    );
    assert_eq!(
        armed.vcpu.timer_due(),
        due(RE_ARM_TARGET, 3 * block, true),
        "{exits:?}"
    );
    assert_eq!(reverie::take_skid_overshoot_count(), 1);
    println!(
        "timer uncounted vCPU (named limit): uncounted exits {uncounted_exits:?}; armed exits \
         {exits:?}; due {:?}",
        armed.vcpu.timer_due()
    );
}

#[test]
fn requests_beyond_the_longest_period_are_programmed_in_pieces() {
    let _turn = witness_turn();
    // One CPU, so that a pinned binding never reopens its timer at a later
    // clock and every overflow point below is counted from clock 0.
    let _pin = PinThread::here();
    let mut backend = counted_backend(&block_loop(1_000), CounterPlacement::default());
    // Linux refuses a period with bit 63 set. The request is accepted, and
    // the event is programmed with the longest period instead.
    backend
        .vcpu
        .request_timer(1 << 63, TimerKind::Imprecise)
        .unwrap();
    for _ in 0..3 {
        assert_eq!(next_exit(&mut backend.vcpu), Exit::Syscall);
    }
    assert_eq!(backend.vcpu.read_clock().unwrap(), 3_000);
    assert_eq!(
        timer_event(&backend.vcpu).unwrap().overflow_at(),
        Some(MAX_PERIOD)
    );
    // The farthest target the clock can name is accepted; one more RCB, or
    // none at all, is refused and leaves the request in place.
    let clock = backend.vcpu.read_clock().unwrap();
    backend
        .vcpu
        .request_timer(u64::MAX - clock, TimerKind::Precise)
        .unwrap();
    assert_eq!(backend.vcpu.timer_target(), Some(u64::MAX));
    for refused in [u64::MAX - clock + 1, 0] {
        let error = backend
            .vcpu
            .request_timer(refused, TimerKind::Precise)
            .unwrap_err();
        assert!(matches!(error, Error::GuestClock(_)), "{error}");
        assert_eq!(backend.vcpu.timer_target(), Some(u64::MAX));
    }
    assert_eq!(next_exit(&mut backend.vcpu), Exit::Syscall);
    assert_eq!(
        timer_event(&backend.vcpu).unwrap().overflow_at(),
        Some(MAX_PERIOD)
    );
    assert!(backend.vcpu.read_clock().is_ok());
    assert_eq!(reverie::take_skid_overshoot_count(), 0);
}

/// A request found due where the vCPU is not in user mode, here the
/// trampoline at its VMCALL (as a kick in the trampoline finds it: a syscall's
/// exit delivers at the syscall's return), is not delivered there. It is
/// armed again at its target, and the kick that follows finds the guest back
/// in user mode, where the request is taken once, with the live registers.
/// So is a late precise one, which records nothing more.
fn a_request_due_outside_user_mode_is_delivered_back_in_it(placement: CounterPlacement) {
    let _turn = witness_turn();
    for kind in [TimerKind::Imprecise, TimerKind::Precise] {
        a_found_request_is_delivered_back_in_user_mode(placement, kind);
    }
    assert_eq!(reverie::take_skid_overshoot_count(), 0);
}

fn a_found_request_is_delivered_back_in_user_mode(placement: CounterPlacement, kind: TimerKind) {
    let block = 1_000_u64;
    let mut backend = counted_backend(&block_loop(block as u32), placement);
    assert_eq!(next_exit(&mut backend.vcpu), Exit::Syscall);
    assert_eq!(backend.vcpu.read_clock().unwrap(), block);
    assert_eq!(
        backend.vcpu.get_sregs().unwrap().cs.dpl,
        0,
        "in the trampoline"
    );
    // As if this exit had found the request due: a precise one, late.
    let found = TimerDue {
        target: block,
        clock: block,
        late: kind == TimerKind::Precise,
        kind,
    };
    backend.vcpu.clock.timer = TimerState::Due(found);
    assert!(backend.timer_instruction_boundary().unwrap().is_none());
    assert_eq!(
        backend.vcpu.clock.timer,
        TimerState::Armed {
            target: block,
            kind: TimerKind::Imprecise,
            margin: 0,
            first_stage: None,
        }
    );
    // A syscall exit before the kick finds it due in ring 0 again.
    let mut exits = Vec::new();
    let boundary = loop {
        let exit = next_exit(&mut backend.vcpu);
        exits.push((exit, backend.vcpu.read_clock().unwrap()));
        assert!(exits.len() < 100, "{exits:?}");
        if let Some(boundary) = backend.timer_instruction_boundary().unwrap() {
            break boundary;
        }
        assert!(backend.vcpu.timer_due().is_none(), "{exits:?}");
    };
    let crate::vm::ToolInstructionBoundary::Timer(boundary) = boundary else {
        panic!("not a timer boundary");
    };
    let (exit, clock) = *exits.last().unwrap();
    assert_eq!(exit, Exit::Kick, "{exits:?}");
    // Programmed two RCBs past the clock at the deferral, the earliest
    // overflow Linux allows.
    assert!(clock >= block + 2, "{exits:?}");
    assert_eq!(
        boundary.instruction,
        TimerDue {
            target: block,
            clock,
            late: false,
            kind: TimerKind::Imprecise,
        }
    );
    let user = boundary.user_registers();
    assert_eq!(user.cs & 3, 3);
    assert_eq!(user.rip, backend.vcpu.get_regs().unwrap().rip);
    // Taken once.
    assert_eq!(backend.vcpu.clock.timer, TimerState::Idle);
    assert!(backend.timer_instruction_boundary().unwrap().is_none());
    println!(
        "timer deferral ({placement:?}): due at {block}, delivered at {clock} after {exits:?}"
    );
}

#[test]
fn a_request_due_outside_user_mode_is_delivered_back_in_it_with_following_events() {
    if CounterPlacement::default() != CounterPlacement::FollowTask {
        println!("timer deferral: FollowTask NOT EXECUTED; this host pins each entry");
        return;
    }
    a_request_due_outside_user_mode_is_delivered_back_in_it(CounterPlacement::FollowTask);
}

#[test]
fn a_request_due_outside_user_mode_is_delivered_back_in_it_with_pinned_entries() {
    let _pin = PinThread::here();
    a_request_due_outside_user_mode_is_delivered_back_in_it(CounterPlacement::PinEachEntry);
}

/// A host interrupt that stops the syscall trampoline on its way back to
/// user mode, within a precise request's stepping window, keeps the run to
/// the breakpoint at the user instruction it returns to. Two single steps in
/// ring 0, which complete the VMCALL and run one more instruction, stop the
/// trampoline here where such an interrupt could.
#[test]
fn an_interrupted_trampoline_keeps_its_run_to_the_user_return() {
    let _pin = PinThread::here();
    let mut backend = counted_backend(&EXIT_THEN_SPIN, CounterPlacement::default());
    backend.vcpu.request_timer(100, TimerKind::Precise).unwrap();
    assert_eq!(next_exit(&mut backend.vcpu), Exit::Syscall);
    backend.prepare_timer_steps().unwrap();
    let StepMode::RunTo(user_return) = backend.vcpu.next_step_mode else {
        panic!("{:?}", backend.vcpu.next_step_mode);
    };
    for _ in 0..2 {
        backend.vcpu.step_next_entry(StepMode::Step);
        assert!(matches!(backend.vcpu.run(), Ok(Some(VcpuExit::Debug(_)))));
    }
    assert_eq!(backend.vcpu.get_sregs().unwrap().cs.dpl, 0);
    let stopped = backend.vcpu.get_regs().unwrap().rip;
    backend.prepare_timer_steps().unwrap();
    assert_eq!(
        backend.vcpu.next_step_mode,
        StepMode::RunTo(user_return),
        "stopped at {stopped:#x}"
    );
    let Ok(Some(VcpuExit::Debug(debug))) = backend.vcpu.run() else {
        panic!("no breakpoint at {user_return:#x}");
    };
    backend.finish_timer_step(debug).unwrap();
    assert_eq!(backend.vcpu.get_regs().unwrap().rip, user_return);
    assert_eq!(backend.vcpu.get_sregs().unwrap().cs.dpl, 3);
}

/// The guest's own trap flag during a run to a breakpoint is refused by
/// name: loaded by the instruction run there (POPF), the breakpoint finds it;
/// set when the run starts (here through the registers, after the entry
/// that checks for it), the trap it raises comes first.
#[test]
fn a_guest_trap_flag_during_a_run_to_a_breakpoint_is_refused_by_name() {
    // push 0x302 (TF, IF and the reserved bit); popfq; jmp .
    let popf = [0x68, 0x02, 0x03, 0x00, 0x00, 0x9d, 0xeb, 0xfe];
    // rdtsc; jmp .
    let rdtsc = [0x0f, 0x31, 0xeb, 0xfe];
    for (code, entries) in [(&popf[..], 2), (&rdtsc[..], 1)] {
        let mut backend = counted_backend(code, CounterPlacement::default());
        backend.vcpu.request_timer(100, TimerKind::Precise).unwrap();
        let mut refusal = None;
        for entry in 1..=entries {
            backend.prepare_timer_steps().unwrap();
            if entries == 1 {
                let mut registers = backend.vcpu.get_regs().unwrap();
                registers.rflags |= 1 << 8;
                backend.vcpu.set_regs(&registers).unwrap();
            }
            let Ok(Some(VcpuExit::Debug(debug))) = backend.vcpu.run() else {
                panic!("no debug exit");
            };
            let finished = backend.finish_timer_step(debug);
            if entry == entries {
                refusal = Some(finished.unwrap_err().to_string());
            } else {
                finished.unwrap();
            }
        }
        let refusal = refusal.unwrap();
        assert!(refusal.contains("sets its own trap flag"), "{refusal}");
    }
}

/// A host interrupt can end a POPF's run before its breakpoint, after the
/// POPF loaded the guest's own trap flag. The next entry refuses it by name
/// whatever runs there, here UD2 or SYSCALL, both unstepped, and runs them
/// when TF is clear. The breakpoint's exit stands in for the interrupt: it
/// leaves the vCPU in the same state, and finishing it is skipped.
#[test]
fn an_interrupted_popf_cannot_carry_its_trap_flag_past_the_next_entry() {
    for (next, exit) in [([0x0f, 0x0b], "Hlt"), ([0x0f, 0x05], "Hypercall")] {
        for flags in [0x302_u32, 0x202] {
            // push flags; popfq; ud2 or syscall; jmp .
            let [a, b, c, d] = flags.to_le_bytes();
            let code = [0x68, a, b, c, d, 0x9d, next[0], next[1], 0xeb, 0xfe];
            let mut backend = counted_backend(&code, CounterPlacement::default());
            backend.vcpu.request_timer(100, TimerKind::Precise).unwrap();
            for _ in 0..2 {
                backend.prepare_timer_steps().unwrap();
                assert!(matches!(backend.vcpu.run(), Ok(Some(VcpuExit::Debug(_)))));
            }
            match backend.prepare_timer_steps() {
                Err(refusal) => {
                    assert_ne!(flags & 0x100, 0, "{refusal}");
                    assert!(refusal.to_string().contains("sets its own trap flag"));
                }
                Ok(()) => {
                    assert_eq!(flags & 0x100, 0);
                    assert_eq!(backend.vcpu.next_step_mode, StepMode::Off);
                    let ran = format!("{:?}", backend.vcpu.run().unwrap());
                    assert!(ran.contains(exit), "{ran}");
                }
            }
        }
    }
}

// The kick signal outside KVM_RUN (see the module documentation of
// `preemption_timer.rs`): blocked on the vCPU thread in host code, unblocked
// only inside KVM_RUN through the vCPU signal mask, and taken at EINTR exits.

/// A getpid exit, then a CPL3 loop with no exit at all.
const EXIT_THEN_SPIN: [u8; 13] = [
    0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, SYS_getpid
    0x0f, 0x05, // syscall
    0x31, 0xc0, // xor eax, eax
    0x85, 0xc0, // loop: test eax, eax
    0x74, 0xfc, // jz loop
];

/// nanosleep({0, 300 ms}, &remainder), then exit_group(-result): 0 when the
/// sleep completed, EINTR when a signal interrupted it.
const SLEEP_GUEST: [u8; 47] = [
    0x48, 0x83, 0xec, 0x20, // sub rsp, 32
    0x48, 0xc7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00, // mov qword [rsp], 0
    0x48, 0xc7, 0x44, 0x24, 0x08, 0x00, 0xa3, 0xe1, 0x11, // mov qword [rsp+8], 300000000
    0x48, 0x89, 0xe7, // mov rdi, rsp
    0x48, 0x8d, 0x74, 0x24, 0x10, // lea rsi, [rsp+16]
    0xb8, 0x23, 0x00, 0x00, 0x00, // mov eax, SYS_nanosleep
    0x0f, 0x05, // syscall
    0xf7, 0xd8, // neg eax
    0x89, 0xc7, // mov edi, eax
    0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
    0x0f, 0x05, // syscall
];

/// pipe2(fds, 0), then ppoll of its empty read end for POLLIN with a 300 ms
/// timeout and no signal mask, then exit_group(-result): 0 when the poll
/// timed out, EINTR when a signal interrupted it, pipe2's errno if that
/// failed.
const PPOLL_GUEST: [u8; 95] = [
    0x48, 0x83, 0xec, 0x40, // sub rsp, 64
    0x48, 0x89, 0xe7, // mov rdi, rsp
    0x31, 0xf6, // xor esi, esi
    0xb8, 0x25, 0x01, 0x00, 0x00, // mov eax, SYS_pipe2
    0x0f, 0x05, // syscall
    0x85, 0xc0, // test eax, eax
    0x75, 0x40, // jnz exit
    0x8b, 0x04, 0x24, // mov eax, [rsp]
    0x89, 0x44, 0x24, 0x10, // mov [rsp+16], eax: pollfd.fd
    0xc7, 0x44, 0x24, 0x14, 0x01, 0x00, 0x00, 0x00, // pollfd.events = POLLIN
    0x48, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, // mov qword [rsp+32], 0
    0x48, 0xc7, 0x44, 0x24, 0x28, 0x00, 0xa3, 0xe1, 0x11, // mov qword [rsp+40], 300000000
    0x48, 0x8d, 0x7c, 0x24, 0x10, // lea rdi, [rsp+16]
    0xbe, 0x01, 0x00, 0x00, 0x00, // mov esi, 1
    0x48, 0x8d, 0x54, 0x24, 0x20, // lea rdx, [rsp+32]
    0x45, 0x31, 0xd2, // xor r10d, r10d
    0x41, 0xb8, 0x08, 0x00, 0x00, 0x00, // mov r8d, 8
    0xb8, 0x0f, 0x01, 0x00, 0x00, // mov eax, SYS_ppoll
    0x0f, 0x05, // syscall
    0xf7, 0xd8, // exit: neg eax
    0x89, 0xc7, // mov edi, eax
    0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
    0x0f, 0x05, // syscall
];

fn signal_bit(signal: libc::c_int) -> u64 {
    1 << (signal - 1)
}

/// The calling thread's whole kernel signal mask, one bit per signal as
/// above (glibc's own query hides the two signals it reserves).
fn thread_mask() -> u64 {
    let mut mask = 0_u64;
    // SAFETY: a query into an initialized kernel sigset of the size passed.
    let queried = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_BLOCK,
            std::ptr::null::<u64>(),
            std::ptr::from_mut(&mut mask),
            std::mem::size_of::<u64>(),
        )
    };
    assert_eq!(queried, 0);
    mask
}

fn change_mask(how: libc::c_int, signal: libc::c_int) {
    // SAFETY: valid set storage; the change affects only this thread.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signal);
        assert_eq!(libc::pthread_sigmask(how, &set, std::ptr::null_mut()), 0);
    }
}

fn signal_pending(signal: libc::c_int) -> bool {
    // SAFETY: a query into initialized storage.
    unsafe {
        let mut pending: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigpending(&mut pending), 0);
        libc::sigismember(&pending, signal) == 1
    }
}

fn tgkill(tid: libc::pid_t, signal: libc::c_int) {
    // SAFETY: a thread-directed signal to a live thread of this process.
    let sent = unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), tid, signal) };
    assert_eq!(sent, 0, "{}", std::io::Error::last_os_error());
}

/// Restores the calling thread's whole signal mask when dropped.
struct RestoreMask(libc::sigset_t);

impl RestoreMask {
    fn here() -> Self {
        // SAFETY: a query into initialized storage.
        unsafe {
            let mut mask: libc::sigset_t = std::mem::zeroed();
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask),
                0
            );
            Self(mask)
        }
    }
}

impl Drop for RestoreMask {
    fn drop(&mut self) {
        // SAFETY: restores a mask this thread had.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) };
    }
}

/// Host thread `tid`'s blocked signals as `/proc` reports them: the vCPU
/// signal mask while that thread is inside KVM_RUN.
fn proc_blocked(tid: libc::pid_t) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/self/task/{tid}/status")).unwrap();
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix("SigBlk:"))
        .expect("a SigBlk line");
    u64::from_str_radix(line.trim(), 16).unwrap()
}

/// The host syscall that thread `tid` is blocked in, if any.
fn proc_syscall(tid: libc::pid_t) -> Option<i64> {
    std::fs::read_to_string(format!("/proc/self/task/{tid}/syscall"))
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Runs this thread's next entry, of a guest that never exits by itself,
/// while another thread, on the CPUs `allowed`, reads this thread's blocked
/// signals from `/proc` until they show KVM_RUN's mask (the kick signal
/// unblocked, which this thread blocks in host code) and then ends the entry
/// with a kick. Returns that mask.
fn mask_inside_kvm_run(backend: &mut crate::KvmBackend, allowed: &libc::cpu_set_t) -> u64 {
    let tid = host_tid();
    let kick = signal_bit(KICK_SIGNAL);
    assert_ne!(thread_mask() & kick, 0, "host code blocks the kick signal");
    let seen = AtomicU64::new(0);
    let late = AtomicBool::new(false);
    let exit = std::thread::scope(|scope| {
        scope.spawn(|| {
            // Not on the vCPU thread's one CPU, where it would wait for it.
            set_affinity(allowed).unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                let blocked = proc_blocked(tid);
                if blocked & kick == 0 {
                    seen.store(blocked, Ordering::SeqCst);
                    break;
                }
                if Instant::now() > deadline {
                    // End the entry anyway so that the test fails rather
                    // than hangs.
                    late.store(true, Ordering::SeqCst);
                    break;
                }
                std::thread::yield_now();
            }
            tgkill(tid, KICK_SIGNAL);
        });
        next_exit(&mut backend.vcpu)
    });
    assert!(
        !late.load(Ordering::SeqCst),
        "KVM_RUN's mask was never seen"
    );
    assert_eq!(exit, Exit::Kick);
    seen.load(Ordering::SeqCst)
}

/// KVM_RUN runs under the vCPU thread's own mask with only the kick signal
/// unblocked: signal 64, the entry signal, and SIGURG, the worker interrupt,
/// keep the thread's state, and so does any other signal. When reverie-kvm
/// changes this thread's SIGURG state, the next armed entry composes the mask
/// again, for two more syscalls; an unchanged mask costs nothing.
#[test]
fn kvm_run_runs_under_the_thread_mask_with_only_the_kick_signal_unblocked() {
    let _turn = witness_turn();
    let allowed = affinity().unwrap();
    let _pin = PinThread::here();
    let _restore = RestoreMask::here();
    let kick = signal_bit(KICK_SIGNAL);
    let urg = signal_bit(libc::SIGURG);
    let winch = signal_bit(libc::SIGWINCH);
    // A marker in the thread's own mask, and SIGURG unblocked, as on a
    // registered guest thread.
    change_mask(libc::SIG_BLOCK, libc::SIGWINCH);
    change_mask(libc::SIG_UNBLOCK, libc::SIGURG);
    reserve_kick_signal().unwrap();
    let mut backend = counted_backend(&EXIT_THEN_SPIN, CounterPlacement::default());
    let pinned = backend.vcpu.clock.placement == CounterPlacement::PinEachEntry;
    let per_entry = if pinned { 2 } else { 0 };
    backend
        .vcpu
        .request_timer(1 << 40, TimerKind::Imprecise)
        .unwrap();
    let before = timer_syscalls();
    assert_eq!(next_exit(&mut backend.vcpu), Exit::Syscall);
    assert_eq!(timer_syscalls() - before, OPEN_SYSCALLS + u64::from(pinned));
    let host = thread_mask();
    assert_ne!(host & kick, 0, "host code blocks the kick signal");
    assert_eq!(host & signal_bit(64), 0, "the entry unblocked signal 64");
    assert_eq!(host & (urg | winch), winch);
    let syscalls = timer_syscalls();
    let inside = mask_inside_kvm_run(&mut backend, &allowed);
    assert_eq!(inside, host & !kick);
    assert_eq!(
        timer_syscalls() - syscalls,
        1 + per_entry,
        "an unchanged mask costs only the kick's drain"
    );
    // reverie-kvm blocks SIGURG on this thread, as for an inline fork child:
    // the next entry composes the mask again.
    assert!(!crate::vm::set_guest_interrupt_signal_mask(libc::SIG_BLOCK).unwrap());
    let syscalls = timer_syscalls();
    let inside = mask_inside_kvm_run(&mut backend, &allowed);
    assert_eq!(timer_syscalls() - syscalls, 3 + per_entry);
    assert_eq!(inside, thread_mask() & !kick);
    assert_ne!(inside & urg, 0);
    // And unblocks it again.
    assert!(crate::vm::set_guest_interrupt_signal_mask(libc::SIG_UNBLOCK).unwrap());
    let syscalls = timer_syscalls();
    let inside = mask_inside_kvm_run(&mut backend, &allowed);
    assert_eq!(timer_syscalls() - syscalls, 3 + per_entry);
    assert_eq!(inside, host & !kick);
    // A call that changes nothing composes nothing.
    assert!(!crate::vm::set_guest_interrupt_signal_mask(libc::SIG_UNBLOCK).unwrap());
    let syscalls = timer_syscalls();
    assert_eq!(mask_inside_kvm_run(&mut backend, &allowed), host & !kick);
    assert_eq!(timer_syscalls() - syscalls, 1 + per_entry);
    assert_eq!(reverie::take_skid_overshoot_count(), 0);
    println!(
        "timer vCPU mask: host code {host:#018x}, KVM_RUN {:#018x}; recomposed after each SIGURG \
         change for 2 syscalls",
        host & !kick
    );
}

/// A kick that arrives while the vCPU thread runs host code interrupts
/// nothing and stays pending. It ends the next KVM_RUN at once, before any
/// guest instruction, and that exit takes it: one extra exit, then the guest
/// runs.
#[test]
fn a_kick_left_pending_ends_the_next_entry_once_and_is_drained() {
    let _turn = witness_turn();
    let _pin = PinThread::here();
    const BLOCK: u32 = 1_000;
    let mut backend = counted_backend(&block_loop(BLOCK), CounterPlacement::default());
    let pinned = backend.vcpu.clock.placement == CounterPlacement::PinEachEntry;
    let per_entry = if pinned { 2 } else { 0 };
    backend
        .vcpu
        .request_timer(1 << 40, TimerKind::Imprecise)
        .unwrap();
    assert_eq!(next_exit(&mut backend.vcpu), Exit::Syscall);
    let clock = backend.vcpu.read_clock().unwrap();
    let (syscalls, drained, taken) = (timer_syscalls(), kicks_drained(), kicks_taken());
    tgkill(host_tid(), KICK_SIGNAL);
    assert!(signal_pending(KICK_SIGNAL), "blocked in host code");
    assert_eq!(next_exit(&mut backend.vcpu), Exit::Kick);
    assert_eq!(
        backend.vcpu.read_clock().unwrap(),
        clock,
        "no guest instruction ran"
    );
    assert!(!signal_pending(KICK_SIGNAL));
    assert_eq!(kicks_drained() - drained, 1);
    assert_eq!(timer_syscalls() - syscalls, 1 + per_entry, "one drain");
    // One extra exit only: the next entry runs the guest to its exit.
    assert_eq!(next_exit(&mut backend.vcpu), Exit::Syscall);
    assert_eq!(backend.vcpu.read_clock().unwrap(), clock + u64::from(BLOCK));
    assert_eq!(timer_syscalls() - syscalls, 1 + 2 * per_entry);
    assert_eq!(kicks_taken(), taken, "no kick ran the handler");
    assert_eq!(reverie::take_skid_overshoot_count(), 0);
}

/// A signal that code outside reverie-kvm blocks on the vCPU thread after
/// the mask was composed, and that then arrives with no kick pending, is
/// still unblocked in the vCPU mask: it ends the next KVM_RUN at once. That
/// exit takes no kick and composes the mask again from the thread's mask, so
/// it ends no other entry.
#[test]
fn a_signal_blocked_after_the_mask_was_composed_ends_one_entry_only() {
    let _turn = witness_turn();
    let _pin = PinThread::here();
    let _restore = RestoreMask::here();
    const BLOCK: u32 = 1_000;
    change_mask(libc::SIG_UNBLOCK, libc::SIGWINCH);
    let mut backend = counted_backend(&block_loop(BLOCK), CounterPlacement::default());
    let pinned = backend.vcpu.clock.placement == CounterPlacement::PinEachEntry;
    let per_entry = if pinned { 2 } else { 0 };
    backend
        .vcpu
        .request_timer(1 << 40, TimerKind::Imprecise)
        .unwrap();
    assert_eq!(next_exit(&mut backend.vcpu), Exit::Syscall);
    // SIGWINCH, ignored by default, is blocked with no notice and sent.
    change_mask(libc::SIG_BLOCK, libc::SIGWINCH);
    tgkill(host_tid(), libc::SIGWINCH);
    assert!(signal_pending(libc::SIGWINCH));
    let clock = backend.vcpu.read_clock().unwrap();
    let (syscalls, drained) = (timer_syscalls(), kicks_drained());
    assert_eq!(next_exit(&mut backend.vcpu), Exit::Kick);
    assert_eq!(backend.vcpu.read_clock().unwrap(), clock);
    assert_eq!(kicks_drained(), drained, "no kick to take");
    // The drain that found nothing, then the block and the mask.
    assert_eq!(timer_syscalls() - syscalls, 3 + per_entry);
    assert_eq!(next_exit(&mut backend.vcpu), Exit::Syscall);
    assert_eq!(backend.vcpu.read_clock().unwrap(), clock + u64::from(BLOCK));
    assert_eq!(timer_syscalls() - syscalls, 3 + 2 * per_entry);
    assert!(signal_pending(libc::SIGWINCH), "still blocked and pending");
    assert_eq!(reverie::take_skid_overshoot_count(), 0);
    // Dropping RestoreMask unblocks SIGWINCH, whose default action discards it.
}

/// The bound for such a signal pending together with a kick: one exit for
/// the kick, which takes it and composes nothing, then one exit that takes
/// no kick and composes the mask again, then the guest runs.
#[test]
fn a_kick_pending_with_a_signal_blocked_after_the_mask_was_composed_costs_two_exits() {
    let _turn = witness_turn();
    let _pin = PinThread::here();
    let _restore = RestoreMask::here();
    const BLOCK: u32 = 1_000;
    change_mask(libc::SIG_UNBLOCK, libc::SIGWINCH);
    let mut backend = counted_backend(&block_loop(BLOCK), CounterPlacement::default());
    let pinned = backend.vcpu.clock.placement == CounterPlacement::PinEachEntry;
    let per_entry = if pinned { 2 } else { 0 };
    backend
        .vcpu
        .request_timer(1 << 40, TimerKind::Imprecise)
        .unwrap();
    assert_eq!(next_exit(&mut backend.vcpu), Exit::Syscall);
    change_mask(libc::SIG_BLOCK, libc::SIGWINCH);
    tgkill(host_tid(), libc::SIGWINCH);
    tgkill(host_tid(), KICK_SIGNAL);
    assert!(signal_pending(libc::SIGWINCH) && signal_pending(KICK_SIGNAL));
    let clock = backend.vcpu.read_clock().unwrap();
    let (syscalls, drained) = (timer_syscalls(), kicks_drained());
    let mut exits = Vec::new();
    while exits.last().is_none_or(|(exit, _)| *exit != Exit::Syscall) && exits.len() < 4 {
        let exit = next_exit(&mut backend.vcpu);
        exits.push((exit, backend.vcpu.read_clock().unwrap()));
    }
    assert_eq!(
        exits,
        [
            (Exit::Kick, clock),
            (Exit::Kick, clock),
            (Exit::Syscall, clock + u64::from(BLOCK))
        ]
    );
    assert_eq!(kicks_drained() - drained, 1, "the kick, taken once");
    // The first exit's drain; the second exit's drain that found nothing,
    // then the block and the mask.
    assert_eq!(timer_syscalls() - syscalls, 4 + 3 * per_entry);
    assert!(!signal_pending(KICK_SIGNAL));
    assert!(signal_pending(libc::SIGWINCH), "still blocked and pending");
    assert_eq!(reverie::take_skid_overshoot_count(), 0);
    println!("timer kick with a blocked signal pending: exits {exits:?}");
}

/// How a test sends the vCPU thread a kick while it waits in a host call.
#[derive(Clone, Copy, Debug)]
enum KickSender {
    Tgkill,
    PerfOverflow,
}

/// Sends the kick signal to `tid` through real perf overflows: a software
/// task-clock event on the calling thread, sampling every 50 µs of its CPU
/// time, whose overflow notifications go to `tid` with `F_SETSIG`, as the
/// timer's own do. Spins until the event has counted 200 µs, about four
/// overflows.
fn kick_through_perf_overflows(tid: libc::pid_t) {
    const F_SETSIG: libc::c_int = 10;
    const F_SETOWN_EX: libc::c_int = 15;
    const F_OWNER_TID: libc::c_int = 0;
    let mut attr = perf::perf_event_attr {
        type_: perf::PERF_TYPE_SOFTWARE,
        size: std::mem::size_of::<perf::perf_event_attr>() as u32,
        config: u64::from(perf::PERF_COUNT_SW_TASK_CLOCK),
        ..Default::default()
    };
    attr.__bindgen_anon_1.sample_period = 50_000;
    attr.__bindgen_anon_2.wakeup_events = 1;
    attr.set_disabled(1);
    // SAFETY: attr describes a software event for the calling thread.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr,
            0,
            -1,
            -1,
            perf::PERF_FLAG_FD_CLOEXEC,
        )
    };
    assert!(fd >= 0, "{}", std::io::Error::last_os_error());
    // SAFETY: a newly returned descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
    let owner: [libc::c_int; 2] = [F_OWNER_TID, tid];
    // SAFETY: fcntl and ioctl on a live descriptor; the owner outlives the
    // call that reads it.
    unsafe {
        assert!(libc::fcntl(fd.as_raw_fd(), F_SETSIG, KICK_SIGNAL) >= 0);
        assert!(libc::fcntl(fd.as_raw_fd(), F_SETOWN_EX, owner.as_ptr()) >= 0);
        assert!(libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_ASYNC) >= 0);
        assert_eq!(ioctls::ENABLE(fd.as_raw_fd(), 0), 0);
    }
    let mut task_clock = 0_u64;
    while task_clock < 200_000 {
        std::hint::spin_loop();
        // SAFETY: a counting read of one native u64.
        let read = unsafe {
            libc::read(
                fd.as_raw_fd(),
                std::ptr::from_mut(&mut task_clock).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        assert_eq!(read, std::mem::size_of::<u64>() as isize);
    }
    // SAFETY: an ioctl on a live descriptor.
    unsafe { ioctls::DISABLE(fd.as_raw_fd(), 0) };
}

/// Runs `code` as a static ELF through LinuxEmu on this thread, with a timer
/// event open (an imprecise request far ahead, which never comes due).
/// Another thread waits until this thread blocks in one of the host syscalls
/// `host_calls`, then sends it a kick by `sender`. Returns the guest's exit
/// status and the kicks this thread took at EINTR exits.
fn guest_status_with_a_kick_in_a_host_call(
    code: &[u8],
    host_calls: &[i64],
    sender: KickSender,
) -> (i32, u64) {
    let mut backend = counted_backend(code, CounterPlacement::default());
    backend
        .vcpu
        .request_timer(1 << 40, TimerKind::Imprecise)
        .unwrap();
    let tid = host_tid();
    let drained = kicks_drained();
    let done = AtomicBool::new(false);
    let sent = AtomicBool::new(false);
    let status = std::thread::scope(|scope| {
        scope.spawn(|| {
            while !done.load(Ordering::SeqCst) {
                if proc_syscall(tid).is_some_and(|number| host_calls.contains(&number)) {
                    match sender {
                        KickSender::Tgkill => tgkill(tid, KICK_SIGNAL),
                        KickSender::PerfOverflow => kick_through_perf_overflows(tid),
                    }
                    sent.store(true, Ordering::SeqCst);
                    return;
                }
                std::thread::sleep(Duration::from_micros(200));
            }
        });
        let status = backend.run_static_elf();
        done.store(true, Ordering::SeqCst);
        status
    });
    assert!(
        sent.load(Ordering::SeqCst),
        "the guest finished before its host call was seen"
    );
    let _ = reverie::take_skid_overshoot_count();
    (status.unwrap(), kicks_drained() - drained)
}

/// Runs a guest whose one host call is among `host_calls`, kicked there by
/// each sender in turn, and checks that the call completed (the guest exits
/// with 0) and that the kick was taken after it. A tgkill sends one kick; the
/// perf overflows, sent while the call waits, merge into one pending kick.
fn check_a_kick_in_a_host_call(what: &str, code: &[u8], host_calls: &[i64]) {
    let mut results = Vec::new();
    for sender in [KickSender::Tgkill, KickSender::PerfOverflow] {
        let (status, drained) = guest_status_with_a_kick_in_a_host_call(code, host_calls, sender);
        println!(
            "timer {what} with a kick by {sender:?}: guest result -{status}, {drained} kick(s) \
             taken at EINTR exits"
        );
        results.push((sender, status, drained));
    }
    for (sender, status, drained) in results {
        assert_eq!(
            status, 0,
            "{sender:?}: the kick interrupted the {what}, which returned -{status} to the guest"
        );
        assert!(drained >= 1, "{sender:?}: the kick was not taken");
        if matches!(sender, KickSender::Tgkill) {
            assert_eq!(drained, 1, "{sender:?}");
        }
    }
}

/// A kick that arrives while the vCPU thread sleeps in LinuxEmu's host
/// nanosleep does not interrupt it: the guest's nanosleep returns 0, not
/// EINTR. The kick stays pending, ends the next KVM_RUN, and is taken there.
#[test]
fn a_kick_during_a_host_sleep_does_not_interrupt_it() {
    let _turn = witness_turn();
    check_a_kick_in_a_host_call("host nanosleep", &SLEEP_GUEST, &[libc::SYS_nanosleep]);
}

/// As for the sleep, with LinuxEmu's blocking host poll for a guest ppoll:
/// it times out normally, returning 0, not EINTR.
#[test]
fn a_kick_during_a_blocking_host_ppoll_does_not_interrupt_it() {
    let _turn = witness_turn();
    check_a_kick_in_a_host_call(
        "blocking host poll",
        &PPOLL_GUEST,
        &[libc::SYS_poll, libc::SYS_ppoll],
    );
}

/// Waits on another thread, on the CPUs `allowed`, until host thread `tid`
/// runs KVM_RUN under a vCPU mask (its blocked signals lack the kick signal,
/// which it blocks in host code), then runs `act` there. Returns false if
/// that was never seen within 20 s, in which case `act` ran anyway.
fn when_inside_kvm_run<T>(
    tid: libc::pid_t,
    allowed: &libc::cpu_set_t,
    act: impl FnOnce() -> T,
) -> (bool, T) {
    set_affinity(allowed).unwrap();
    let kick = signal_bit(KICK_SIGNAL);
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut seen = true;
    while proc_blocked(tid) & kick != 0 {
        if Instant::now() > deadline {
            seen = false;
            break;
        }
        std::thread::yield_now();
    }
    (seen, act())
}

/// Signal 64, the entry signal, keeps the thread's state in the vCPU mask: a
/// closer's kick still ends a KVM_RUN that runs under the timer's vCPU mask,
/// and is accounted as before. That EINTR exit takes no timer kick, so it
/// composes the mask again.
#[test]
fn a_closer_kick_ends_kvm_run_under_the_vcpu_mask() {
    let _turn = witness_turn();
    let allowed = affinity().unwrap();
    let _pin = PinThread::here();
    let mut backend = counted_backend(&EXIT_THEN_SPIN, CounterPlacement::default());
    let pinned = backend.vcpu.clock.placement == CounterPlacement::PinEachEntry;
    let per_entry = if pinned { 2 } else { 0 };
    backend
        .vcpu
        .request_timer(1 << 40, TimerKind::Imprecise)
        .unwrap();
    assert_eq!(next_exit(&mut backend.vcpu), Exit::Syscall);
    let host = thread_mask();
    let gate = backend.memory.entry_gate();
    let tid = host_tid();
    let delivered = crate::entry::delivered_for_test();
    let syscalls = timer_syscalls();
    let (result, (seen, closing)) = std::thread::scope(|scope| {
        let controller = scope
            .spawn(|| when_inside_kvm_run(tid, &allowed, || gate.try_close().unwrap().unwrap()));
        let result = backend.vcpu.run().map(|exit| exit.is_some());
        (result, controller.join().unwrap())
    });
    assert!(seen, "KVM_RUN's mask was never seen");
    assert!(
        matches!(result, Err(Error::Kvm(ref error)) if error.errno() == libc::EINTR),
        "{result:?}"
    );
    assert_eq!(
        crate::entry::delivered_for_test(),
        delivered + 1,
        "the closer's kick reached the entry signal's handler"
    );
    // The drain that found no kick, then the block and the mask.
    assert_eq!(timer_syscalls() - syscalls, 3 + per_entry);
    drop(futures::executor::block_on(closing.finish()).unwrap());
    // The entry after runs under the same mask, and a timer kick ends it.
    let syscalls = timer_syscalls();
    assert_eq!(
        mask_inside_kvm_run(&mut backend, &allowed),
        host & !signal_bit(KICK_SIGNAL)
    );
    assert_eq!(timer_syscalls() - syscalls, 1 + per_entry);
    assert_eq!(reverie::take_skid_overshoot_count(), 0);
}

/// SIGURG, the worker interrupt, keeps the thread's state in the vCPU mask:
/// it ends a KVM_RUN under the timer's vCPU mask while the thread leaves it
/// unblocked, and not while reverie-kvm has it blocked there, which then
/// leaves it pending, as without a timer.
#[test]
fn sigurg_ends_kvm_run_under_the_vcpu_mask_only_while_the_thread_leaves_it_unblocked() {
    let _turn = witness_turn();
    let allowed = affinity().unwrap();
    let _pin = PinThread::here();
    let _restore = RestoreMask::here();
    change_mask(libc::SIG_UNBLOCK, libc::SIGURG);
    let mut backend = counted_backend(&EXIT_THEN_SPIN, CounterPlacement::default());
    backend
        .vcpu
        .request_timer(1 << 40, TimerKind::Imprecise)
        .unwrap();
    assert_eq!(next_exit(&mut backend.vcpu), Exit::Syscall);
    let tid = host_tid();
    let kick = signal_bit(KICK_SIGNAL);
    for (round, blocked) in [false, true, false].into_iter().enumerate() {
        // Through reverie-kvm, which notes the change; unblocking also
        // delivers a SIGURG left pending by the round before to its empty
        // handler.
        crate::vm::set_guest_interrupt_signal_mask(if blocked {
            libc::SIG_BLOCK
        } else {
            libc::SIG_UNBLOCK
        })
        .unwrap();
        let drained = kicks_drained();
        let (exit, (seen, ran_on)) = std::thread::scope(|scope| {
            let controller = scope.spawn(|| {
                when_inside_kvm_run(tid, &allowed, || {
                    tgkill(tid, libc::SIGURG);
                    // A blocked SIGURG cannot end the entry: give it time
                    // to (wrongly) do so, then end it with a kick. An
                    // unblocked one must end it: wait for that, or end it
                    // with a kick and report the failure.
                    let deadline =
                        Instant::now() + Duration::from_millis(if blocked { 200 } else { 10_000 });
                    while Instant::now() < deadline && proc_blocked(tid) & kick == 0 {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    let ran_on = proc_blocked(tid) & kick == 0;
                    if ran_on {
                        tgkill(tid, KICK_SIGNAL);
                    }
                    ran_on
                })
            });
            let exit = next_exit(&mut backend.vcpu);
            (exit, controller.join().unwrap())
        });
        assert!(seen, "round {round}: KVM_RUN's mask was never seen");
        assert_eq!(exit, Exit::Kick, "round {round}");
        assert_eq!(ran_on, blocked, "round {round}: which signal ended KVM_RUN");
        assert_eq!(signal_pending(libc::SIGURG), blocked, "round {round}");
        assert_eq!(
            kicks_drained() - drained,
            u64::from(blocked),
            "round {round}"
        );
    }
    assert_eq!(reverie::take_skid_overshoot_count(), 0);
}

/// Single steps through the stepping engine take a precise request on
/// `SPINNER` exactly to its target, on time, and this reports what that
/// costs: the steps per event and the mean time per step. Each request is
/// unstaged, so the event is first programmed one skid margin short of its
/// target, and the steps start where its kick stops the guest. A kick that
/// comes later than the margin, which the PMU's interrupt latency makes
/// happen to between one in a thousand and one in a hundred (one in seven at
/// a load average of 43), finds the target passed before any entry of the
/// stepping window: that event is late and recorded, and is counted apart,
/// within twice as many requests as events in all.
#[test]
fn single_steps_take_a_precise_request_exactly_to_its_target() {
    let _turn = witness_turn();
    let margin = margin();
    let ticks = 4 * margin;
    let events = 50;
    let mut backend = counted_backend(&SPINNER, CounterPlacement::default());
    let mut steps = Vec::new();
    let mut stepping = Duration::ZERO;
    let mut late = 0;
    while steps.len() < events {
        assert!(
            steps.len() + (late as usize) < 2 * events,
            "{late} late events"
        );
        let clock = backend.vcpu.read_clock().unwrap();
        backend
            .vcpu
            .request_timer(ticks, TimerKind::Precise)
            .unwrap();
        let mut taken = 0_u64;
        let mut first_step = None;
        let due = loop {
            if backend.vcpu.timer_stepping() && first_step.is_none() {
                first_step = Some(Instant::now());
            }
            backend.prepare_timer_steps().unwrap();
            let stepped = backend.vcpu.next_step_mode == StepMode::Step;
            match backend.vcpu.run() {
                Ok(Some(VcpuExit::Debug(debug))) => {
                    backend.finish_timer_step(debug).unwrap();
                    taken += u64::from(stepped);
                }
                Err(Error::Kvm(error)) if error.errno() == libc::EINTR => {}
                other => panic!("unexpected exit {other:?}"),
            }
            if let Some(due) = backend.vcpu.take_due_timer() {
                break due;
            }
        };
        let target = clock + ticks;
        if due.late {
            // The margin's kick came after the target, before any entry of
            // the window.
            assert!(due.clock > target && first_step.is_none(), "{due:?}");
            late += 1;
            continue;
        }
        stepping += first_step.expect("the request was stepped").elapsed();
        assert_eq!(
            due,
            TimerDue {
                target,
                clock: target,
                late: false,
                kind: TimerKind::Precise,
            }
        );
        steps.push(taken);
    }
    assert_eq!(reverie::take_skid_overshoot_count(), late);
    steps.sort_unstable();
    let total: u64 = steps.iter().sum();
    println!(
        "{events} precise events {ticks} RCBs apart, skid margin {margin}, and {late} late: \
         steps per event min {} median {} max {}; {:.2} us per step ({} steps in {:?})",
        steps[0],
        steps[steps.len() / 2],
        steps[steps.len() - 1],
        stepping.as_secs_f64() * 1e6 / total as f64,
        total,
        stepping,
    );
}

/// A host interrupt can end an entry while the CPU delivers an exception to
/// its stub, leaving the guest at the faulting instruction with the exception
/// for KVM to inject at the next entry. A timer event found due there is
/// delivered, but no signal: moving the guest to a handler would deliver the
/// exception at the handler instead. KVM_SET_VCPU_EVENTS stands in for the
/// interrupt here.
#[test]
fn a_timer_boundary_with_an_exception_to_inject_takes_no_signal() {
    // ud2
    let backend = counted_backend(&[0x0f, 0x0b], CounterPlacement::default());
    assert!(backend.timer_boundary_takes_signal().unwrap());
    let mut events = backend.vcpu.get_vcpu_events().unwrap();
    events.exception.injected = 1;
    events.exception.nr = 6;
    backend.vcpu.set_vcpu_events(&events).unwrap();
    assert!(!backend.timer_boundary_takes_signal().unwrap());
    events.exception.injected = 0;
    backend.vcpu.set_vcpu_events(&events).unwrap();
    assert!(backend.timer_boundary_takes_signal().unwrap());
}
