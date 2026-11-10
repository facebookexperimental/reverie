/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Hardware watchpoints (`Guest::set_watchpoints`, `GlobalTool::on_watchpoint_hit`):
//! every access a watch catches is reported once, with the thread and the
//! instruction after the access; the trap is not delivered to the guest; a
//! hit inside the precise timer's single steps is reported and the step still
//! counts; and a hit leaves every timer event where it was. Arming is refused
//! while the thread blocks or ignores SIGTRAP, and a thread's watches are its
//! own: a new thread starts with none.

#![cfg(target_arch = "x86_64")]

mod watch_harness;

use reverie::HitTiming;
use reverie::Pid;
use reverie::SigtrapAtHit;
use reverie::WatchError;
use reverie::WatchKind;
use reverie::WatchSpec;
use reverie_ptrace::ret_without_perf;
use watch_harness::*;

/// The precise timer's step setting and Reverie's watch counters are
/// process-wide, so the tests here take turns.
static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn turn() -> std::sync::MutexGuard<'static, ()> {
    TURN.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn a_write_watch_reports_each_write_at_the_instruction_after_it() {
    let _turn = turn();
    let (claimed, unclaimed) = (
        reverie_ptrace::testing::watch_traps_claimed(),
        reverie_ptrace::testing::unclaimed_sigtraps_suppressed(),
    );
    let watched = run(
        Config {
            sets: vec![vec![watch(0, WatchKind::Write)]],
            ..Config::default()
        },
        || {
            arm(0);
            for i in 0..10 {
                store(0, i);
                assert_eq!(load(0), i);
                // Unwatched.
                store(1, i);
            }
            // The kernel's write for a syscall is not the thread's own.
            let written = unsafe { libc::syscall(libc::SYS_getrandom, word(0), 8usize, 0) };
            assert_eq!(written, 8);
        },
    );
    let armings = watched.armings();
    assert_eq!(armings.len(), 1, "{armings:?}");
    assert_eq!(armings[0].2, Ok(()));
    let hits = watched.hits();
    assert_eq!(hits.len(), 10, "{hits:#?}");
    for hit in &hits {
        assert_eq!(hit.tid, armings[0].0);
        assert_eq!(hit.slot, 0);
        assert_eq!(hit.spec, watch(0, WatchKind::Write));
        assert_eq!(hit.ip, after_store());
        assert_eq!(hit.timing, HitTiming::AfterAccess);
        assert_eq!(hit.backtrace, None);
        // This Tool declares no serialized-execution contract and does not
        // trace the signal-state syscalls, so Reverie cannot tell what the
        // hit's SIGTRAP reset, and says so (`watchpoints_programs.rs`).
        assert_eq!(hit.sigtrap, SigtrapAtHit::Unknown);
    }
    // Every trap was the hit's own. A host that reports a hit with the
    // debug status's single-step bit set (an AMD EPYC VM does) gives it
    // TRAP_TRACE, which is not claimed and reaches the unclaimed-trap arm;
    // one with the bit clear gives TRAP_HWBKPT, which is claimed.
    let claimed = reverie_ptrace::testing::watch_traps_claimed() - claimed;
    let unclaimed = reverie_ptrace::testing::unclaimed_sigtraps_suppressed() - unclaimed;
    eprintln!("WATCH-TRAP-CLASS claimed={claimed} unclaimed={unclaimed}");
    assert_eq!(claimed + unclaimed, 10);
}

/// A real single step whose instruction also fires a watch is the guest's
/// own trap, not the hit's: two `popfq` instructions, the first setting the
/// trap flag and the second clearing it as it reads the watched slot it
/// pops. Its hit is reported, with the SIGTRAP state unknown, and the trap
/// is left to the arms that handle every other trap, which suppress it as
/// before.
#[test]
fn a_real_single_step_that_fires_a_watch_is_not_claimed_as_a_hit() {
    let _turn = turn();
    let (claimed, unclaimed) = (
        reverie_ptrace::testing::watch_traps_claimed(),
        reverie_ptrace::testing::unclaimed_sigtraps_suppressed(),
    );
    let watched = run(Config::default(), || unsafe { watch_test_popfq() });
    let claimed = reverie_ptrace::testing::watch_traps_claimed() - claimed;
    let unclaimed = reverie_ptrace::testing::unclaimed_sigtraps_suppressed() - unclaimed;
    let armings = watched.armings();
    assert_eq!(armings.len(), 1, "{armings:?}");
    assert_eq!(armings[0].2, Ok(()));
    let hits = watched.hits();
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].ip, after_popfq());
    assert_eq!(hits[0].sigtrap, SigtrapAtHit::Unknown);
    assert_eq!(claimed, 0, "the guest's own step trap was claimed as a hit");
    assert!(unclaimed >= 1, "{unclaimed}");
}

/// A failed write, here the kernel refusing a kernel address for the second
/// watch (`hw_breakpoint_parse`), disarms every slot, the first watch's
/// too, and says so; the thread then arms as usual.
#[test]
fn a_failed_arming_disarms_every_watch_and_the_thread_can_arm_again() {
    let _turn = turn();
    const KERNEL_ADDRESS: u64 = 0xffff_8000_0000_0000;
    let watched = run(
        Config {
            sets: vec![
                vec![
                    watch(0, WatchKind::Write),
                    WatchSpec {
                        addr: KERNEL_ADDRESS,
                        ..watch(1, WatchKind::Write)
                    },
                ],
                vec![watch(1, WatchKind::Write)],
            ],
            ..Config::default()
        },
        || {
            arm(0);
            // Watch 0 would report this, had it stayed armed.
            store(0, 1);
            arm(1);
            store(0, 2);
            store(1, 3);
        },
    );
    let armings = watched.armings();
    assert_eq!(armings.len(), 2, "{armings:?}");
    assert_eq!(
        armings[0].2,
        Err(format!(
            "{:?}",
            WatchError::Failed {
                errno: reverie::Errno::EINVAL,
                disarmed: true
            }
        ))
    );
    assert_eq!(armings[1].2, Ok(()));
    let hits = watched.hits();
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].spec, watch(1, WatchKind::Write));
}

#[test]
fn a_read_write_watch_reports_reads_and_writes_in_order() {
    let _turn = turn();
    let watched = run(
        Config {
            sets: vec![vec![
                watch(0, WatchKind::Write),
                watch(2, WatchKind::ReadWrite),
            ]],
            ..Config::default()
        },
        || {
            arm(0);
            for i in 0..5 {
                store(2, i);
                assert_eq!(load(2), i);
                store(0, i);
                load(0);
            }
        },
    );
    let hits: Vec<(u8, u64)> = watched
        .hits()
        .iter()
        .map(|hit| (hit.slot, hit.ip))
        .collect();
    let round = [(1, after_store()), (1, after_load()), (0, after_store())];
    assert_eq!(hits, round.repeat(5));
}

/// A watch's first `backtraces` hits carry the thread's stack, innermost
/// frame at the hit, and later ones none; arming the watch again starts the
/// budget anew. A second watch with no budget gets none.
#[test]
fn a_watchs_first_hits_carry_the_threads_stack_until_its_budget_is_spent() {
    let _turn = turn();
    let set = vec![
        WatchSpec {
            backtraces: 3,
            ..watch(0, WatchKind::Write)
        },
        watch(1, WatchKind::Write),
    ];
    let watched = run(
        Config {
            sets: vec![set.clone()],
            ..Config::default()
        },
        || {
            arm(0);
            for i in 0..5 {
                store(0, i);
            }
            store(1, 1);
            arm(0);
            for i in 0..2 {
                store(0, i);
            }
        },
    );
    let hits = watched.hits();
    assert_eq!(hits.len(), 8, "{hits:#?}");
    let stacked: Vec<(u8, bool)> = hits
        .iter()
        .map(|hit| (hit.slot, hit.backtrace.is_some()))
        .collect();
    assert_eq!(
        stacked,
        [
            (0, true),
            (0, true),
            (0, true),
            (0, false),
            (0, false),
            (1, false),
            (0, true),
            (0, true),
        ]
    );
    for hit in hits.iter().filter(|hit| hit.backtrace.is_some()) {
        assert_eq!(hit.spec, set[0]);
        let frames: Vec<u64> = hit
            .backtrace
            .as_ref()
            .unwrap()
            .iter()
            .map(|frame| frame.ip)
            .collect();
        assert_eq!(frames.first(), Some(&after_store()), "{frames:x?}");
        assert!(frames.len() > 2, "{frames:x?}");
    }
}

#[test]
fn arming_is_refused_while_sigtrap_is_blocked_or_ignored() {
    let _turn = turn();
    let watched = run(
        Config {
            sets: vec![
                vec![watch(0, WatchKind::Write)],
                vec![watch(0, WatchKind::Write); 5],
                vec![WatchSpec {
                    addr: word(0) as u64 + 4,
                    ..watch(0, WatchKind::Write)
                }],
                vec![],
            ],
            ..Config::default()
        },
        || unsafe {
            let mut trap: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut trap);
            libc::sigaddset(&mut trap, libc::SIGTRAP);
            libc::sigprocmask(libc::SIG_BLOCK, &trap, std::ptr::null_mut());
            arm(0);
            libc::sigprocmask(libc::SIG_UNBLOCK, &trap, std::ptr::null_mut());
            libc::signal(libc::SIGTRAP, libc::SIG_IGN);
            arm(0);
            libc::signal(libc::SIGTRAP, libc::SIG_DFL);
            arm(1);
            arm(2);
            // Refused: no watch armed yet.
            store(0, 1);
            arm(0);
            store(0, 2);
            // Disarmed.
            arm(3);
            store(0, 3);
        },
    );
    let results: Vec<String> = watched
        .armings()
        .into_iter()
        .map(|(_, _, result, _)| format!("{result:?}"))
        .collect();
    let refused = |error: WatchError| format!("{:?}", Err::<(), _>(format!("{error:?}")));
    assert_eq!(
        results,
        [
            refused(WatchError::SigtrapBlocked),
            refused(WatchError::SigtrapIgnored),
            refused(WatchError::TooMany {
                requested: 5,
                slots: 4
            }),
            refused(WatchError::Misaligned {
                addr: word(0) as u64 + 4,
                len: 8
            }),
            "Ok(())".to_owned(),
            "Ok(())".to_owned(),
        ]
    );
    let hits = watched.hits();
    assert_eq!(
        hits.len(),
        1,
        "only the store between arming and disarming: {hits:#?}"
    );
}

/// A new thread starts with no watch: Linux does not copy a thread's debug
/// registers to the threads it starts. One armed as it starts (see
/// `Config::at_start`) reports its own accesses.
#[test]
fn a_new_thread_has_no_watch_until_it_arms_at_its_start() {
    let _turn = turn();
    for at_start in [false, true] {
        let watched = run(
            Config {
                // The main thread arms set 0 by its call; a thread arms set
                // 1, the same watch, as it starts.
                sets: vec![
                    vec![watch(0, WatchKind::Write)],
                    vec![watch(0, WatchKind::Write)],
                ],
                at_start: at_start.then_some(1),
                ..Config::default()
            },
            || {
                arm(0);
                std::thread::spawn(|| {
                    for i in 0..3 {
                        store(0, i);
                    }
                })
                .join()
                .unwrap();
                store(0, 7);
            },
        );
        let armings = watched.armings();
        let main = armings
            .iter()
            .find(|(_, set, _, _)| *set == 0)
            .map(|(tid, _, _, _)| *tid)
            .unwrap();
        let hits = watched.hits();
        let main_hits = hits.iter().filter(|hit| hit.tid == main).count();
        let other: Vec<Pid> = hits
            .iter()
            .filter(|hit| hit.tid != main)
            .map(|hit| hit.tid)
            .collect();
        assert_eq!(main_hits, 1, "{at_start}: {hits:#?}");
        if at_start {
            assert_eq!(other.len(), 3, "{armings:?} {hits:#?}");
            assert!(other.iter().all(|tid| *tid == other[0]));
            assert!(
                armings
                    .iter()
                    .any(|(tid, set, result, _)| *tid == other[0] && *set == 1 && result.is_ok()),
                "{armings:?}"
            );
        } else {
            assert_eq!(other, [], "a watch was inherited: {hits:#?}");
        }
    }
}

/// A store that a step of the precise timer runs is reported, once, and the
/// step counts: every event is delivered. With block steps the store ends a
/// block step early, and its trap is a hit's (`TRAP_HWBKPT`), which
/// `handle_sigtrap` takes before the steps go on; with instruction steps it
/// coincides with the step's own trap (`TRAP_TRACE`), and only the step's stop
/// sees the hit.
#[test]
fn a_hit_inside_the_timers_single_steps_is_reported_once() {
    let _turn = turn();
    ret_without_perf!();
    const WRITES: u64 = 2_000;
    for block_steps in [true, false] {
        reverie_ptrace::testing::set_block_steps(block_steps);
        let (claimed, in_steps) = (
            reverie_ptrace::testing::watch_traps_claimed(),
            reverie_ptrace::testing::watch_hits_in_timer_steps(),
        );
        // Shorter than any skid margin, so that each event is reached by
        // single steps from its request.
        let watched = run(timer_config(40, 50, true), timer_guest(WRITES));
        let (claimed, in_steps) = (
            reverie_ptrace::testing::watch_traps_claimed() - claimed,
            reverie_ptrace::testing::watch_hits_in_timer_steps() - in_steps,
        );
        reverie_ptrace::testing::set_block_steps(true);
        eprintln!(
            "WATCH-IN-STEPS block_steps={block_steps} hits={} claimed_traps={claimed} hits_in_steps={in_steps}",
            watched.hits().len()
        );
        assert_eq!(watched.hits().len() as u64, WRITES, "{block_steps}");
        assert!(
            in_steps > 0,
            "{block_steps}: no hit fell inside the timer's steps"
        );
        // A hit read at a step's stop came with the step's trap, which the
        // hit adds nothing to; one with its own trap is not known here.
        let at_steps = watched
            .hits()
            .iter()
            .filter(|hit| hit.sigtrap == SigtrapAtHit::Unchanged)
            .count() as u64;
        assert_eq!(at_steps, in_steps, "{block_steps}");
        if block_steps {
            assert_eq!(claimed, WRITES, "every hit's trap is its own");
        } else {
            assert_eq!(
                claimed + in_steps,
                WRITES,
                "each hit is the guest's trap or a step's, never both"
            );
        }
        assert_eq!(watched.timer_events().len(), 50, "{block_steps}");
        assert!(watched.armings().iter().all(|arming| arming.3));
    }
}

/// A watch leaves every timer event at the clock and instruction it has
/// without one, whether the event is reached by single steps alone or by the
/// PMU's notification and the steps after it, and whether the steps are
/// block steps, which a hit ends early, or instruction steps, whose own trap
/// carries a hit.
#[test]
fn a_watch_does_not_move_a_timer_event() {
    let _turn = turn();
    ret_without_perf!();
    const WRITES: u64 = 20_000;
    for block_steps in [true, false] {
        reverie_ptrace::testing::set_block_steps(block_steps);
        for (rcbs, events) in [(40, 100), (3_000, 20), (30_000, 2)] {
            let quiet = run(timer_config(rcbs, events, false), timer_guest(WRITES));
            let (claimed, in_steps) = (
                reverie_ptrace::testing::watch_traps_claimed(),
                reverie_ptrace::testing::watch_hits_in_timer_steps(),
            );
            let watched = run(timer_config(rcbs, events, true), timer_guest(WRITES));
            let (claimed, in_steps) = (
                reverie_ptrace::testing::watch_traps_claimed() - claimed,
                reverie_ptrace::testing::watch_hits_in_timer_steps() - in_steps,
            );
            eprintln!(
                "WATCH-NO-PERTURBATION block_steps={block_steps} rcbs={rcbs} events={} hits={} \
                 claimed_traps={claimed} hits_in_steps={in_steps} first_events={:?}",
                watched.timer_events().len(),
                watched.hits().len(),
                &watched.timer_events()[..3.min(events)],
            );
            assert_eq!(quiet.hits().len(), 0);
            assert_eq!(watched.hits().len() as u64, WRITES, "{rcbs}");
            // Most hits stop the free-running guest; some fall in the steps.
            assert!(claimed > 0, "{rcbs}");
            assert_eq!(quiet.timer_events().len(), events, "{rcbs}");
            assert_eq!(
                quiet.timer_events(),
                watched.timer_events(),
                "{rcbs} RCBs, block steps {block_steps}: the events moved"
            );
            assert!(watched.armings().iter().all(|arming| arming.3));
        }
    }
    reverie_ptrace::testing::set_block_steps(true);
}

/// The same with an instruction offset after the RCBs
/// (`TimerSchedule::RcbsAndInstructions`), whose last steps are instruction
/// steps whatever the step setting: a hit there comes with a step's trap.
#[test]
fn a_watch_does_not_move_a_timer_event_with_an_instruction_offset() {
    let _turn = turn();
    ret_without_perf!();
    const WRITES: u64 = 20_000;
    for block_steps in [true, false] {
        reverie_ptrace::testing::set_block_steps(block_steps);
        for (rcbs, instructions, events) in [(40, 7, 100), (3_000, 3, 20), (30_000, 11, 2)] {
            let config = |armed| Config {
                timer_instructions: Some(instructions),
                ..timer_config(rcbs, events, armed)
            };
            let quiet = run(config(false), timer_guest(WRITES));
            let in_steps = reverie_ptrace::testing::watch_hits_in_timer_steps();
            let watched = run(config(true), timer_guest(WRITES));
            let in_steps = reverie_ptrace::testing::watch_hits_in_timer_steps() - in_steps;
            eprintln!(
                "WATCH-NO-PERTURBATION-INSTR block_steps={block_steps} rcbs={rcbs} \
                 instructions={instructions} events={} hits={} hits_in_steps={in_steps} \
                 first_events={:?}",
                watched.timer_events().len(),
                watched.hits().len(),
                &watched.timer_events()[..3.min(events)],
            );
            assert_eq!(quiet.hits().len(), 0);
            assert_eq!(watched.hits().len() as u64, WRITES, "{rcbs}+{instructions}");
            assert_eq!(quiet.timer_events().len(), events, "{rcbs}+{instructions}");
            assert_eq!(
                quiet.timer_events(),
                watched.timer_events(),
                "{rcbs} RCBs and {instructions} instructions, block steps {block_steps}: the \
                 events moved"
            );
            assert!(watched.armings().iter().all(|arming| arming.3));
        }
    }
    reverie_ptrace::testing::set_block_steps(true);
}

/// A watch's budget of stacks is the thread's, and the hits inside the
/// precise timer's single steps spend from the same budget as the hits of a
/// freely running thread: 4 of 2,000 hits carry a stack, however the hits
/// fall between the two.
#[test]
fn the_stack_budget_is_spent_across_the_timers_steps_and_free_running_hits() {
    let _turn = turn();
    ret_without_perf!();
    const WRITES: u64 = 2_000;
    const STACKS: usize = 4;
    let in_steps = reverie_ptrace::testing::watch_hits_in_timer_steps();
    let watched = run(
        Config {
            sets: vec![vec![WatchSpec {
                backtraces: STACKS as u32,
                ..watch(0, WatchKind::Write)
            }]],
            ..timer_config(40, 50, true)
        },
        timer_guest(WRITES),
    );
    let in_steps = reverie_ptrace::testing::watch_hits_in_timer_steps() - in_steps;
    let hits = watched.hits();
    assert_eq!(hits.len() as u64, WRITES);
    assert!(in_steps > 0, "no hit fell inside the timer's steps");
    assert!(
        (in_steps as usize) < hits.len(),
        "every hit fell inside the timer's steps"
    );
    let stacks: Vec<usize> = hits
        .iter()
        .enumerate()
        .filter(|(_, hit)| hit.backtrace.is_some())
        .map(|(at, _)| at)
        .collect();
    assert_eq!(
        stacks,
        (0..STACKS).collect::<Vec<_>>(),
        "the first {STACKS} hits carry the stacks ({in_steps} hits were in steps)"
    );
}

/// With the overflow records this host maps, a hit's stop between the
/// timer's period and its target, with the notification held back, leaves the
/// event as it was: it is delivered once, at its target, and the thread says
/// that its hits keep its timer events.
#[test]
fn a_hit_near_a_precise_target_keeps_the_event_where_records_are_mapped() {
    let _turn = turn();
    ret_without_perf!();
    let watched = run(
        timer_config(PERF_RCBS, 1, true),
        store_near_the_target(half_the_keep_margin()),
    );
    assert_eq!(watched.hits().len(), 1);
    assert!(watched.armings().iter().all(|arming| arming.3));
    let events = watched.timer_events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].0, PERF_RCBS, "{events:?}");
}

/// A watch does not move a timer event where Reverie keeps the thread's
/// signal records either, with the hits that make it read and write the
/// guest's SIGTRAP state: the thread blocks SIGTRAP as it arms, so every
/// hit takes the repair, which reads procfs and writes the mask back, at a
/// stop with a precise timer armed.
#[test]
fn a_watch_does_not_move_a_timer_event_while_the_signal_records_are_kept() {
    let _turn = turn();
    ret_without_perf!();
    const WRITES: u64 = 2_000;
    // However many events the guest's own length allows, up to this many.
    for (rcbs, events) in [(40, 50), (3_000, 50)] {
        let config = |armed| Config {
            records: true,
            ..timer_config(rcbs, events, armed)
        };
        let quiet = run(config(false), blocked_timer_guest(WRITES));
        let watched = run(config(true), blocked_timer_guest(WRITES));
        eprintln!(
            "WATCH-NO-PERTURBATION-RECORDS rcbs={rcbs} events={} hits={} repaired={}",
            watched.timer_events().len(),
            watched.hits().len(),
            watched
                .hits()
                .iter()
                .filter(|hit| hit.sigtrap == SigtrapAtHit::Reblocked)
                .count(),
        );
        assert_eq!(quiet.hits().len(), 0);
        assert_eq!(watched.hits().len() as u64, WRITES, "{rcbs}");
        assert!(!quiet.timer_events().is_empty(), "{rcbs}");
        assert_eq!(
            quiet.timer_events(),
            watched.timer_events(),
            "{rcbs} RCBs with the signal records kept: the events moved"
        );
        // Every hit met SIGTRAP blocked and had it blocked again, but for
        // those inside Reverie's own single steps, whose SIGTRAP it
        // shields, so that the hit changes nothing to put back.
        let repaired = watched
            .hits()
            .iter()
            .filter(|hit| hit.sigtrap == SigtrapAtHit::Reblocked)
            .count();
        assert!(repaired > 0, "no hit took the repair");
        assert!(
            watched.hits().iter().all(|hit| matches!(
                hit.sigtrap,
                SigtrapAtHit::Reblocked | SigtrapAtHit::Unchanged
            )),
            "{:?}",
            watched.hits().iter().find(|hit| !matches!(
                hit.sigtrap,
                SigtrapAtHit::Reblocked | SigtrapAtHit::Unchanged
            )),
        );
    }
}

/// What a hit costs, printed: run alone, with `--ignored --nocapture`, so
/// that its quiet log filter is the process's.
#[test]
#[ignore]
fn measure_the_cost_of_a_hit() {
    let _turn = turn();
    let _ = tracing::subscriber::set_global_default(
        tracing_subscriber::fmt().with_env_filter("warn").finish(),
    );
    let time = |cfg: Config, writes: u64| {
        let started = std::time::Instant::now();
        let watched = run(cfg, move || {
            arm(0);
            for i in 0..writes {
                store(0, i);
            }
        });
        (started.elapsed(), watched.hits().len() as u64)
    };
    let set = |watches: Vec<WatchSpec>| Config {
        sets: vec![watches],
        ..Config::default()
    };
    // No stack; a stack on every hit; and a budget of 64 stacks, spent in
    // the first 64 of 20,000 hits.
    for (writes, backtraces) in [(20_000, 0), (2_000, u32::MAX), (20_000, 64)] {
        let spec = WatchSpec {
            backtraces,
            ..watch(0, WatchKind::Write)
        };
        for _ in 0..3 {
            let (quiet, _) = time(set(vec![]), writes);
            let (watched, hits) = time(set(vec![spec]), writes);
            assert_eq!(hits, writes);
            let per_hit = (watched.saturating_sub(quiet)).as_secs_f64() * 1e6 / writes as f64;
            println!(
                "WATCH-COST backtraces={backtraces} writes={writes} quiet={quiet:?} watched={watched:?} per_hit_us={per_hit:.2}"
            );
        }
    }
}
