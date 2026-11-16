/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test-only file and host access lives here, not in the library.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

//! Property tests (quickcheck): two families.
//!
//! 1. Model round-trips: `parse(render(model)) == model` for models
//!    generated from a deterministic seeded generator (quickcheck
//!    shrinks the seed; the generator covers comm edge bytes, status
//!    line subsets, fdinfo kinds, and sched value forms).
//! 2. Arbitrary-byte robustness: no parser panics on arbitrary input,
//!    and anything a parser accepts is stable —
//!    `parse(render(parse(bytes))) == parse(bytes)`.

use quickcheck_macros::quickcheck;
use reverie_proc_grammar::*;

/// Tiny deterministic PRNG so a failing seed prints a reproducer.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn i32(&mut self) -> i32 {
        self.next() as u32 as i32
    }
    fn i64(&mut self) -> i64 {
        self.next() as i64
    }
    fn u64(&mut self) -> u64 {
        self.next()
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[(self.next() as usize) % items.len()]
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

/// A stored comm (≤15 bytes, no NUL) drawn from an adversarial alphabet:
/// spaces, parens, backslash, newline, tab, high bytes.
fn gen_comm(rng: &mut Rng) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ab ()\\\n\t:\xff\xfez-09";
    let len = rng.below(16) as usize;
    (0..len).map(|_| *rng.pick(ALPHABET)).collect()
}

fn gen_stat(rng: &mut Rng) -> Stat {
    Stat {
        pid: rng.i32().abs().max(1),
        comm: gen_comm(rng),
        state: *rng.pick(b"RSDZTtWXxKPI"),
        ppid: rng.i32().abs(),
        pgrp: rng.i32().abs(),
        session: rng.i32().abs(),
        tty_nr: rng.i32(),
        tpgid: rng.i32(),
        flags: rng.u64() as u32,
        minflt: rng.u64(),
        cminflt: rng.u64(),
        majflt: rng.u64(),
        cmajflt: rng.u64(),
        utime: rng.u64(),
        stime: rng.u64(),
        cutime: rng.i64(),
        cstime: rng.i64(),
        priority: rng.i64() % 100,
        nice: (rng.i64() % 41) - 20,
        num_threads: (rng.u64() % 10_000) as i32,
        itrealvalue: 0,
        starttime: rng.u64(),
        vsize: rng.u64(),
        rss: rng.i64(),
        rsslim: *rng.pick(&[0, 1, u64::MAX, 1 << 40]),
        startcode: rng.u64(),
        endcode: rng.u64(),
        startstack: rng.u64(),
        kstkesp: rng.u64(),
        kstkeip: rng.u64(),
        signal: rng.u64(),
        blocked: rng.u64(),
        sigignore: rng.u64(),
        sigcatch: rng.u64(),
        wchan: rng.u64(),
        nswap: 0,
        cnswap: 0,
        exit_signal: (rng.i32() % 65).max(-1),
        processor: (rng.u64() % 1024) as i32,
        rt_priority: rng.u64() as u32 % 100,
        policy: rng.u64() as u32 % 7,
        delayacct_blkio_ticks: rng.u64(),
        guest_time: rng.u64(),
        cguest_time: rng.i64(),
        start_data: rng.u64(),
        end_data: rng.u64(),
        start_brk: rng.u64(),
        arg_start: rng.u64(),
        arg_end: rng.u64(),
        env_start: rng.u64(),
        env_end: rng.u64(),
        exit_code: (rng.i32() % 256) << 8,
    }
}

#[quickcheck]
fn stat_model_round_trip(seed: u64) -> bool {
    let mut rng = Rng(seed | 1);
    let model = gen_stat(&mut rng);
    parse_stat(&render_stat(&model)) == Ok(model)
}

#[quickcheck]
fn statm_and_io_and_comm_round_trip(seed: u64) -> bool {
    let mut rng = Rng(seed | 1);
    let statm = Statm {
        size: rng.u64(),
        resident: rng.u64(),
        shared: rng.u64(),
        text: rng.u64(),
        lib: 0,
        data: rng.u64(),
        dirty: 0,
    };
    let io = ProcessIo {
        rchar: rng.u64(),
        wchar: rng.u64(),
        syscr: rng.u64(),
        syscw: rng.u64(),
        read_bytes: rng.u64(),
        write_bytes: rng.u64(),
        cancelled_write_bytes: rng.u64(),
    };
    let comm = gen_comm(&mut rng);
    parse_statm(&render_statm(&statm)) == Ok(statm)
        && parse_process_io(&render_process_io(&io)) == Ok(io)
        && parse_comm_file(&render_comm_file(&comm)) == Ok(comm)
}

fn gen_status(rng: &mut Rng) -> Status {
    use StatusLabel::*;
    let mut lines = Vec::new();
    let mut push = |label: StatusLabel, value: StatusValue| {
        lines.push(StatusLine::Known { label, value });
    };
    // A plausible subset in kernel order.
    let name: Vec<u8> = gen_comm(rng)
        .iter()
        .flat_map(|b| match b {
            b'\n' => vec![b'\\', b'n'],
            b'\\' => vec![b'\\', b'\\'],
            other => vec![*other],
        })
        .collect();
    push(Name, StatusValue::Name(name));
    push(Umask, StatusValue::Umask(rng.u64() as u32 & 0o777));
    let (letter, word) = *rng.pick(&[
        (b'R', "running"),
        (b'S', "sleeping"),
        (b'D', "disk sleep"),
        (b'Z', "zombie"),
        (b'I', "idle"),
    ]);
    push(State, StatusValue::State(letter, word.as_bytes().to_vec()));
    for label in [Tgid, Pid, PPid, TracerPid] {
        if rng.chance(85) {
            push(label, StatusValue::Decimal((rng.u64() % 100_000) as i64));
        }
    }
    push(Uid, StatusValue::Ids([rng.u64() as u32 % 100_000; 4]));
    if rng.chance(85) {
        push(FDSize, StatusValue::Decimal((rng.u64() % 100_000) as i64));
    }
    let groups: Vec<u32> = (0..rng.below(6))
        .map(|_| rng.u64() as u32 % 200_000)
        .collect();
    push(Groups, StatusValue::Groups(groups));
    push(
        NSpid,
        StatusValue::PidList(vec![(rng.u64() % 100_000) as i32, (rng.u64() % 100) as i32]),
    );
    if rng.chance(70) {
        for label in [VmPeak, VmRSS, VmData] {
            push(label, StatusValue::Kb(rng.u64() % 10_000_000));
        }
    }
    push(UntagMask, StatusValue::PrefixedHex(rng.u64()));
    if rng.chance(85) {
        push(Threads, StatusValue::Decimal((rng.u64() % 100_000) as i64));
    }
    push(
        SigQ,
        StatusValue::SigQ(rng.u64() % 1000, rng.u64() % 10_000_000),
    );
    for label in [SigPnd, SigBlk, SigIgn, CapEff] {
        push(label, StatusValue::HexMask(rng.u64()));
    }
    push(
        SpeculationStoreBypass,
        StatusValue::Text(
            rng.pick(&["vulnerable", "Not affected", "thread force mitigated"])
                .as_bytes()
                .to_vec(),
        ),
    );
    let groups_count = 1 + rng.below(6) as usize;
    let first_digits = if groups_count == 1 {
        1 + (rng.below(8) as u8)
    } else {
        8
    };
    let mut groups: Vec<u32> = (0..groups_count).map(|_| rng.u64() as u32).collect();
    if first_digits < 8 {
        // The top group must fit its printed digit width.
        groups[0] &= (1u32 << (4 * u32::from(first_digits))) - 1;
    }
    push(
        CpusAllowed,
        StatusValue::Bitmap(
            Bitmap::new(first_digits, groups).expect("top group masked to its digit width"),
        ),
    );
    push(
        CpusAllowedList,
        StatusValue::RangeList(vec![(0, (rng.u64() % 64) as u32), (128, 131)]),
    );
    push(VoluntaryCtxtSwitches, StatusValue::Counter(rng.u64()));
    push(NonvoluntaryCtxtSwitches, StatusValue::Counter(rng.u64()));
    if rng.chance(50) {
        push(
            X86ThreadFeatures,
            StatusValue::ThreadFeatures {
                shstk: rng.chance(50),
                wrss: rng.chance(50),
            },
        );
        push(
            X86ThreadFeaturesLocked,
            StatusValue::ThreadFeatures {
                shstk: rng.chance(50),
                wrss: rng.chance(50),
            },
        );
    }
    Status { lines }
}

#[quickcheck]
fn status_model_round_trip(seed: u64) -> bool {
    let mut rng = Rng(seed | 1);
    let model = gen_status(&mut rng);
    parse_status(&render_status(&model)) == Ok(model)
}

fn gen_fdinfo(rng: &mut Rng) -> Fdinfo {
    // Canonical lock models directly (no post-hoc normalization):
    // every class/mode/access combination the kernel prints is in
    // reach, including mandatory record locks and lease modes.
    let locks = if rng.chance(40) {
        let class = *rng.pick(&[
            LockKind::Flock,
            LockKind::Posix,
            LockKind::Access,
            LockKind::OpenFileDescription,
            LockKind::Lease,
            LockKind::Deleg,
            LockKind::Unknown,
        ]);
        let mode = match class {
            LockKind::Posix | LockKind::Access | LockKind::OpenFileDescription => {
                *rng.pick(&[LockMode::Advisory, LockMode::Mandatory])
            }
            LockKind::Flock => LockMode::Advisory,
            LockKind::Lease | LockKind::Deleg => {
                *rng.pick(&[LockMode::Active, LockMode::Breaking, LockMode::Breaker])
            }
            LockKind::Unknown => LockMode::Unknown,
        };
        let record = matches!(
            class,
            LockKind::Posix | LockKind::Access | LockKind::OpenFileDescription
        );
        let start = if record { rng.u64() % 10_000 } else { 0 };
        let end = if !record || rng.chance(50) {
            None
        } else {
            Some(start + rng.u64() % 10_000)
        };
        vec![FdinfoLock {
            class,
            mode,
            access: *rng.pick(&[LockAccess::Read, LockAccess::Write, LockAccess::Unlock]),
            owner: (rng.u64() % 100_000) as i64,
            dev_major: rng.u64() as u32 % 300,
            dev_minor: rng.u64() as u32 % 300,
            inode: rng.u64(),
            start,
            end,
        }]
    } else {
        Vec::new()
    };
    let kind = match rng.below(8) {
        0 => FdinfoKind::Eventfd {
            count: rng.u64(),
            id: rng.u64() % 1_000_000,
            semaphore: if rng.chance(30) {
                None
            } else {
                Some(rng.below(2))
            },
        },
        1 => FdinfoKind::Signalfd { sigmask: rng.u64() },
        2 => FdinfoKind::Timerfd(Timerfd {
            clockid: (rng.u64() % 12) as i32,
            ticks: rng.u64() % 1000,
            settime_flags: rng.u64() as u32 % 4,
            it_value: (rng.u64() % 100, rng.u64() % 1_000_000_000),
            it_interval: (rng.u64() % 100, rng.u64() % 1_000_000_000),
        }),
        3 => FdinfoKind::UnixSocket {
            scm_fds: rng.u64() as u32 % 300,
        },
        4 => FdinfoKind::Pidfd {
            pid: (rng.u64() % 100_000) as i64,
            nspid: vec![(rng.u64() % 100_000) as i64],
        },
        5 => FdinfoKind::Epoll(vec![EpollTarget {
            tfd: (rng.u64() % 1024) as i32,
            events: rng.u64() as u32,
            data: rng.u64(),
            pos: rng.i64().abs(),
            ino: rng.u64(),
            sdev: rng.u64() % 0xfff,
        }]),
        6 => FdinfoKind::Fuse {
            connection: rng.u64() % 10_000,
        },
        _ => FdinfoKind::Plain,
    };
    Fdinfo {
        pos: rng.i64().abs(),
        flags: (rng.u64() as u32) & 0o7_777_777,
        mnt_id: rng.u64() % 100_000,
        ino: rng.u64(),
        locks,
        kind,
    }
}

#[quickcheck]
fn fdinfo_model_round_trip(seed: u64) -> bool {
    let mut rng = Rng(seed | 1);
    let model = gen_fdinfo(&mut rng);
    parse_fdinfo(&render_fdinfo(&model)) == Ok(model)
}

#[quickcheck]
fn sched_model_round_trip(seed: u64) -> bool {
    let mut rng = Rng(seed | 1);
    // Sched comm from a tamer alphabet (header-shape safety is covered
    // by goldens/oracle for paren and newline cases).
    const ALPHABET: &[u8] = b"worker-1 ab";
    let comm: Vec<u8> = (0..(1 + rng.below(15)) as usize)
        .map(|_| *rng.pick(ALPHABET))
        .collect();
    let mut entries = vec![SchedEntry::Separator(67)];
    for label in [
        &b"se.exec_start"[..],
        b"se.vruntime",
        b"nr_switches",
        b"se.load.weight",
        b"custom.counter",
    ] {
        // Kernel columns only: %-45s label, %21Ld / %14Ld.%06ld value.
        let prefix = {
            let mut h = label.to_vec();
            while h.len() < 45 {
                h.push(b' ');
            }
            h
        };
        let value = if rng.chance(50) {
            SchedValue::Int(rng.i64() as i128)
        } else {
            SchedValue::Fixed6((rng.i64().abs() % 10_000_000_000) as i128)
        };
        let value_width = match value {
            SchedValue::Int(_) => 21.max(value.render().len()),
            SchedValue::Fixed6(scaled) => {
                let whole_digits = (scaled.unsigned_abs() / 1_000_000).to_string().len();
                14.max(whole_digits + usize::from(scaled < 0)) + 1 + 6
            }
        };
        entries.push(SchedEntry::Field {
            prefix,
            label: label.to_vec(),
            value,
            value_width,
        });
    }
    let model = Sched {
        comm,
        pid: (rng.u64() % 100_000) as i32,
        threads: 1 + rng.below(64),
        entries,
    };
    parse_sched(&render_sched(&model)) == Ok(model)
}

/// No parser ever panics, and accepted input is value-stable under
/// render+reparse.
#[quickcheck]
fn arbitrary_bytes_never_panic_and_accepted_input_is_stable(bytes: Vec<u8>) -> bool {
    macro_rules! stable {
        ($parse:ident, $render:ident) => {
            if let Ok(parsed) = $parse(&bytes)
                && $parse(&$render(&parsed)) != Ok(parsed)
            {
                return false;
            }
        };
    }
    stable!(parse_stat, render_stat);
    stable!(parse_status, render_status);
    stable!(parse_fdinfo, render_fdinfo);
    stable!(parse_sched, render_sched);
    stable!(parse_process_io, render_process_io);
    stable!(parse_statm, render_statm);
    stable!(parse_comm_file, render_comm_file);
    true
}
