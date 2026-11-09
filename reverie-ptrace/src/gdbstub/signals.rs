/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Signal numbers in the GDB remote protocol.
//!
//! The protocol does not carry Linux's signal numbers but gdb's own
//! (`enum gdb_signal`, defined by gdb's `include/gdb/signals.def`), which
//! differ for many signals: gdb numbers SIGUSR1 30 where Linux numbers it 10,
//! and puts the real-time signals at 45 and up. Stop replies (`X`) and resume
//! actions (`vCont;C`) are translated here, as gdbserver does with
//! `gdb_signal_from_host` and `gdb_signal_to_host` (gdbsupport/signals.cc).

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use safeptrace::AnySignal;

/// gdb's `GDB_SIGNAL_REALTIME_33`; real-time signals 33 to 63 follow it.
const GDB_REALTIME_33: u8 = 45;
/// gdb's `GDB_SIGNAL_REALTIME_32`, placed after `GDB_SIGNAL_CANCEL` (76).
const GDB_REALTIME_32: u8 = 77;
/// gdb's `GDB_SIGNAL_REALTIME_64`; real-time signals 64 to 127 follow it.
const GDB_REALTIME_64: u8 = 78;
/// gdb's `GDB_SIGNAL_REALTIME_127`, the last real-time signal gdb names.
const GDB_REALTIME_127: u8 = 141;
/// gdb's `GDB_SIGNAL_UNKNOWN`, for a signal gdb has no number for.
pub const GDB_SIGNAL_UNKNOWN: u8 = 143;

/// Linux's standard signals and gdb's numbers for them. Linux's SIGSTKFLT has
/// no gdb number. SIGPOLL is SIGIO on Linux, which gdb calls `GDB_SIGNAL_IO`;
/// gdb's `GDB_SIGNAL_POLL` comes back as the same Linux signal.
const STANDARD: [(libc::c_int, u8); 30] = [
    (libc::SIGHUP, 1),
    (libc::SIGINT, 2),
    (libc::SIGQUIT, 3),
    (libc::SIGILL, 4),
    (libc::SIGTRAP, 5),
    (libc::SIGABRT, 6),
    (libc::SIGFPE, 8),
    (libc::SIGKILL, 9),
    (libc::SIGBUS, 10),
    (libc::SIGSEGV, 11),
    (libc::SIGSYS, 12),
    (libc::SIGPIPE, 13),
    (libc::SIGALRM, 14),
    (libc::SIGTERM, 15),
    (libc::SIGURG, 16),
    (libc::SIGSTOP, 17),
    (libc::SIGTSTP, 18),
    (libc::SIGCONT, 19),
    (libc::SIGCHLD, 20),
    (libc::SIGTTIN, 21),
    (libc::SIGTTOU, 22),
    (libc::SIGIO, 23),
    (libc::SIGXCPU, 24),
    (libc::SIGXFSZ, 25),
    (libc::SIGVTALRM, 26),
    (libc::SIGPROF, 27),
    (libc::SIGWINCH, 28),
    (libc::SIGUSR1, 30),
    (libc::SIGUSR2, 31),
    (libc::SIGPWR, 32),
];

/// gdb's `GDB_SIGNAL_POLL`.
const GDB_SIGNAL_POLL: u8 = 33;

/// gdb's number for Linux signal `linux`, or [`GDB_SIGNAL_UNKNOWN`] for one
/// gdb has no number for. Signal 0 is 0 in both.
pub fn to_gdb(linux: libc::c_int) -> u8 {
    if linux == 0 {
        return 0;
    }
    if let Some((_, gdb)) = STANDARD.iter().find(|(host, _)| *host == linux) {
        return *gdb;
    }
    match linux {
        32 => GDB_REALTIME_32,
        33..=63 => GDB_REALTIME_33 + (linux - 33) as u8,
        64..=127 => GDB_REALTIME_64 + (linux - 64) as u8,
        _ => GDB_SIGNAL_UNKNOWN,
    }
}

/// The Linux signal gdb's number `gdb` names, or `None` for a number with no
/// Linux signal (gdb's `SIGEMT`, `SIGLOST`, its Solaris and AIX signals, and
/// real-time signals past Linux's last, 64).
pub fn from_gdb(gdb: u8) -> Option<libc::c_int> {
    if gdb == 0 {
        return Some(0);
    }
    if gdb == GDB_SIGNAL_POLL {
        return Some(libc::SIGPOLL);
    }
    if let Some((linux, _)) = STANDARD.iter().find(|(_, number)| *number == gdb) {
        return Some(*linux);
    }
    let linux = match gdb {
        GDB_REALTIME_32 => 32,
        GDB_REALTIME_33..=75 => 33 + libc::c_int::from(gdb - GDB_REALTIME_33),
        GDB_REALTIME_64..=GDB_REALTIME_127 => 64 + libc::c_int::from(gdb - GDB_REALTIME_64),
        _ => return None,
    };
    (linux <= libc::SIGRTMAX()).then_some(linux)
}

/// Whether gdb has a number for `sig`. Linux's SIGSTKFLT is the only one it
/// lacks: gdb would show it as an unknown signal and could not resume with it.
pub fn signal_has_gdb_number(sig: AnySignal) -> bool {
    to_gdb(sig.raw()) != GDB_SIGNAL_UNKNOWN
}

/// The signals gdb asked the stub to pass to the guest without stopping
/// (`QPassSignals`), shared by the session, which records them, and every
/// traced thread, which reads them at each signal it is about to deliver.
/// gdb names signals it would neither stop at nor print, but pass, such as
/// SIGALRM, SIGCHLD and SIGWINCH by default (gdb's `handle` command).
#[derive(Clone, Debug, Default)]
pub struct PassedSignals(Arc<AtomicU64>);

impl PassedSignals {
    /// Replaces the set with the signals of gdb's numbers `gdb_signals`. A
    /// number with no Linux signal is ignored.
    pub fn set(&self, gdb_signals: &[u8]) {
        let bits = gdb_signals
            .iter()
            .filter_map(|gdb| from_gdb(*gdb))
            .filter(|linux| (1..=64).contains(linux))
            .fold(0u64, |bits, linux| bits | 1 << (linux - 1));
        self.0.store(bits, Ordering::Relaxed);
    }

    /// Whether gdb asked for `sig` to be passed without stopping.
    pub fn passes(&self, sig: AnySignal) -> bool {
        self.0.load(Ordering::Relaxed) & 1 << (sig.raw() - 1) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passed_signals_follow_the_latest_list() {
        let passed = PassedSignals::default();
        let sigalrm = AnySignal::from(nix::sys::signal::Signal::SIGALRM);
        let sigusr1 = AnySignal::from(nix::sys::signal::Signal::SIGUSR1);
        let sig34 = AnySignal::new(34).unwrap();
        assert!(!passed.passes(sigalrm), "nothing passes before gdb asks");
        // gdb's numbers: SIGALRM 14, real-time 34 is 46, and 7 (SIGEMT) has no
        // Linux signal.
        passed.set(&[14, 46, 7]);
        assert!(passed.passes(sigalrm));
        assert!(passed.passes(sig34));
        assert!(!passed.passes(sigusr1));
        passed.set(&[]);
        assert!(!passed.passes(sigalrm), "a new list replaces the old one");
    }

    #[test]
    fn standard_signals_use_gdbs_numbers() {
        // Signals whose numbers differ between Linux and gdb.
        assert_eq!(to_gdb(libc::SIGUSR1), 30);
        assert_eq!(to_gdb(libc::SIGUSR2), 31);
        assert_eq!(to_gdb(libc::SIGBUS), 10);
        assert_eq!(to_gdb(libc::SIGCHLD), 20);
        assert_eq!(to_gdb(libc::SIGSYS), 12);
        // And some that agree.
        assert_eq!(to_gdb(libc::SIGABRT), 6);
        assert_eq!(to_gdb(libc::SIGSEGV), 11);
        assert_eq!(to_gdb(libc::SIGKILL), 9);
        assert_eq!(to_gdb(0), 0);
    }

    #[test]
    fn realtime_signals_use_gdbs_numbers() {
        assert_eq!(to_gdb(32), 77);
        assert_eq!(to_gdb(33), 45);
        assert_eq!(to_gdb(libc::SIGRTMIN()), 45 + (libc::SIGRTMIN() - 33) as u8);
        assert_eq!(to_gdb(63), 75);
        assert_eq!(to_gdb(64), 78);
    }

    #[test]
    fn signals_gdb_cannot_name_are_unknown() {
        assert_eq!(to_gdb(libc::SIGSTKFLT), GDB_SIGNAL_UNKNOWN);
        assert_eq!(to_gdb(-1), GDB_SIGNAL_UNKNOWN);
        assert_eq!(to_gdb(200), GDB_SIGNAL_UNKNOWN);
    }

    #[test]
    fn every_linux_signal_round_trips() {
        for linux in (1..=libc::SIGRTMAX()).filter(|sig| *sig != libc::SIGSTKFLT) {
            let gdb = to_gdb(linux);
            assert_ne!(gdb, GDB_SIGNAL_UNKNOWN, "signal {linux}");
            assert_eq!(from_gdb(gdb), Some(linux), "signal {linux} (gdb {gdb})");
        }
    }

    #[test]
    fn gdb_numbers_without_a_linux_signal_are_refused() {
        assert_eq!(from_gdb(7), None, "GDB_SIGNAL_EMT");
        assert_eq!(from_gdb(29), None, "GDB_SIGNAL_LOST");
        assert_eq!(from_gdb(76), None, "GDB_SIGNAL_CANCEL");
        assert_eq!(from_gdb(79), None, "GDB_SIGNAL_REALTIME_65");
        assert_eq!(from_gdb(GDB_SIGNAL_UNKNOWN), None);
        assert_eq!(from_gdb(GDB_SIGNAL_POLL), Some(libc::SIGIO));
    }
}
