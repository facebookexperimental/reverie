/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Whether a death by signal writes a core, which decides the `0x80` bit of
//! the wait status and `CLD_DUMPED` versus `CLD_KILLED` in `waitid`. gVisor
//! never dumps and never sets the flag (pkg/sentry/kernel/task_signals.go,
//! `WaitStatusTerminationSignal` for a "core" action); this follows the host
//! kernel instead, which a traced guest's death shows.
//!
//! Linux sets the bit only when `vfs_coredump` (formerly `do_coredump`) in
//! fs/coredump.c actually writes a core (`coredump_finish`). Its checks, at
//! v6.17:
//!
//! - the signal's default action is "core" (`sig_kernel_coredump`,
//!   kernel/signal.c:3007);
//! - the mm is dumpable (`coredump_skip`, fs/coredump.c:1084);
//! - for a `|helper` pattern, `RLIMIT_CORE` is not exactly 1
//!   (`coredump_pipe`, fs/coredump.c:978); any other limit, 0 included,
//!   still pipes the core;
//! - for a file pattern, `RLIMIT_CORE` is at least the ELF format's
//!   `min_coredump`, one page (`coredump_file`, fs/coredump.c:884;
//!   fs/binfmt_elf.c:100).
//!
//! The limit is the soft `RLIMIT_CORE` of this process, read when the death
//! happens, as the kernel reads it (`.limit = rlimit(RLIMIT_CORE)`,
//! fs/coredump.c:1101). The guest runs in this process, as a traced guest
//! runs in a child that inherits the same limit, and a guest cannot change
//! it here: `prlimit64` is a Tool-decided call this executor never forwards
//! (`TOOL_DECIDED_SYSCALLS`). The pattern's kind is read once, when the
//! first image is loaded, so every death in a run is judged under one
//! pattern.
//!
//! Not modelled, each a reason a real dump can still fail after these checks:
//! a file that cannot be created or written (an unwritable directory, a full
//! disk), a pipe helper that cannot start, `core_pipe_limit`, and a
//! `SUID_DUMP_ROOT` process's relative path (this executor's dumpable mode is
//! 0 or 1, never 2). A socket (`@`) or empty pattern is judged to write no
//! core.

use std::sync::OnceLock;

/// The kind of destination `/proc/sys/kernel/core_pattern` names, as
/// `format_corename` (fs/coredump.c) classifies it by its first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorePattern {
    /// `|helper`: the kernel pipes the core to a helper program.
    Pipe,
    /// A file name, absolute or relative to the dying process's directory.
    File,
    /// A pattern this does not model as dumping: a socket (`@`), an empty
    /// pattern (whose file name cannot be opened), or an unreadable one.
    NoDump,
}

impl CorePattern {
    /// Classifies the contents of `/proc/sys/kernel/core_pattern`, which end
    /// with a newline.
    pub fn from_contents(contents: &[u8]) -> Self {
        match contents.first() {
            Some(b'|') => Self::Pipe,
            Some(b'@') | Some(b'\n') | None => Self::NoDump,
            Some(_) => Self::File,
        }
    }
}

/// The host's core pattern, read once per process tree.
static CORE_PATTERN: OnceLock<CorePattern> = OnceLock::new();

/// The kind of the host's `core_pattern`, read on the first call and
/// unchanged after it. The loader calls this before the first image runs, so
/// a run judges every death under the pattern it started with.
pub fn host_core_pattern() -> CorePattern {
    *CORE_PATTERN.get_or_init(|| {
        std::fs::read("/proc/sys/kernel/core_pattern").map_or(CorePattern::NoDump, |contents| {
            CorePattern::from_contents(&contents)
        })
    })
}

/// Whether `signal`'s default action is to terminate and dump core
/// (`SIG_KERNEL_COREDUMP_MASK`, include/linux/signal.h).
pub fn default_action_dumps_core(signal: libc::c_int) -> bool {
    matches!(
        signal,
        libc::SIGQUIT
            | libc::SIGILL
            | libc::SIGTRAP
            | libc::SIGABRT
            | libc::SIGBUS
            | libc::SIGFPE
            | libc::SIGSEGV
            | libc::SIGXCPU
            | libc::SIGXFSZ
            | libc::SIGSYS
    )
}

/// Whether Linux writes a core when `signal` ends a process that is
/// `dumpable`, whose soft `RLIMIT_CORE` is `core_limit`, under `pattern`, on
/// a system whose page size is `page_size`: the checks listed in this
/// module's documentation, in the kernel's order.
pub fn linux_writes_core(
    signal: libc::c_int,
    dumpable: bool,
    core_limit: u64,
    pattern: CorePattern,
    page_size: u64,
) -> bool {
    if !default_action_dumps_core(signal) || !dumpable {
        return false;
    }
    match pattern {
        CorePattern::Pipe => core_limit != 1,
        CorePattern::File => core_limit >= page_size,
        CorePattern::NoDump => false,
    }
}

/// Whether a death by `signal` of a guest process that is `dumpable` writes a
/// core ([`linux_writes_core`]), under this process's soft `RLIMIT_CORE` now,
/// the host's pattern ([`host_core_pattern`]) and page size. A limit or page
/// size that cannot be read is judged to write no core.
pub fn guest_writes_core(signal: libc::c_int, dumpable: bool) -> bool {
    if !default_action_dumps_core(signal) || !dumpable {
        return false;
    }
    // SAFETY: limit is writable for the call.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) } != 0 {
        return false;
    }
    // SAFETY: sysconf has no memory arguments.
    let Ok(page_size) = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }) else {
        return false;
    };
    linux_writes_core(
        signal,
        dumpable,
        limit.rlim_cur,
        host_core_pattern(),
        page_size,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u64 = 4096;
    const UNLIMITED: u64 = libc::RLIM_INFINITY;

    fn writes(pattern: CorePattern, limit: u64) -> bool {
        linux_writes_core(libc::SIGSEGV, true, limit, pattern, PAGE)
    }

    /// A piped core ignores the limit except for 1, Linux's opt-out for
    /// pipes (`coredump_pipe`): 0 still pipes.
    #[test]
    fn a_pipe_pattern_dumps_unless_the_limit_is_one() {
        assert!(writes(CorePattern::Pipe, 0));
        assert!(!writes(CorePattern::Pipe, 1));
        assert!(writes(CorePattern::Pipe, 2));
        assert!(writes(CorePattern::Pipe, PAGE));
        assert!(writes(CorePattern::Pipe, UNLIMITED));
    }

    /// A file core needs a limit of at least one page (`min_coredump`).
    #[test]
    fn a_file_pattern_dumps_only_from_one_page() {
        assert!(!writes(CorePattern::File, 0));
        assert!(!writes(CorePattern::File, 1));
        assert!(!writes(CorePattern::File, PAGE - 1));
        assert!(writes(CorePattern::File, PAGE));
        assert!(writes(CorePattern::File, UNLIMITED));
    }

    #[test]
    fn an_unmodelled_pattern_never_dumps() {
        for limit in [0, 1, PAGE, UNLIMITED] {
            assert!(!writes(CorePattern::NoDump, limit), "limit {limit}");
        }
    }

    /// A non-dumpable mm never dumps, under any pattern or limit.
    #[test]
    fn a_process_that_is_not_dumpable_never_dumps() {
        for pattern in [CorePattern::Pipe, CorePattern::File, CorePattern::NoDump] {
            for limit in [0, 1, PAGE, UNLIMITED] {
                assert!(
                    !linux_writes_core(libc::SIGSEGV, false, limit, pattern, PAGE),
                    "{pattern:?} limit {limit}"
                );
            }
        }
    }

    /// Only a signal whose default action is "core" dumps; one that only
    /// terminates never does, under any pattern or limit.
    #[test]
    fn only_a_core_default_signal_dumps() {
        for pattern in [CorePattern::Pipe, CorePattern::File] {
            for signal in [libc::SIGTERM, libc::SIGKILL, libc::SIGINT, libc::SIGPIPE] {
                assert!(
                    !linux_writes_core(signal, true, UNLIMITED, pattern, PAGE),
                    "{pattern:?} signal {signal}"
                );
            }
            for signal in [libc::SIGABRT, libc::SIGQUIT, libc::SIGILL, libc::SIGSYS] {
                assert!(
                    linux_writes_core(signal, true, UNLIMITED, pattern, PAGE),
                    "{pattern:?} signal {signal}"
                );
            }
        }
    }

    #[test]
    fn the_pattern_is_classified_by_its_first_byte() {
        assert_eq!(
            CorePattern::from_contents(b"|/usr/lib/helper %p\n"),
            CorePattern::Pipe
        );
        assert_eq!(
            CorePattern::from_contents(b"/var/cores/core.%p\n"),
            CorePattern::File
        );
        assert_eq!(CorePattern::from_contents(b"core\n"), CorePattern::File);
        assert_eq!(
            CorePattern::from_contents(b"@/run/coredump.socket\n"),
            CorePattern::NoDump
        );
        assert_eq!(CorePattern::from_contents(b"\n"), CorePattern::NoDump);
        assert_eq!(CorePattern::from_contents(b""), CorePattern::NoDump);
    }

    /// The host-reading wrapper agrees with the rule applied to the values
    /// it reads, and reads the pattern once.
    #[test]
    fn the_guest_rule_reads_this_process_limit_and_the_host_pattern() {
        let pattern = host_core_pattern();
        let contents = std::fs::read("/proc/sys/kernel/core_pattern").unwrap_or_default();
        assert_eq!(pattern, CorePattern::from_contents(&contents));
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
        let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        for signal in [libc::SIGSEGV, libc::SIGABRT, libc::SIGTERM] {
            for dumpable in [true, false] {
                assert_eq!(
                    guest_writes_core(signal, dumpable),
                    linux_writes_core(signal, dumpable, limit.rlim_cur, pattern, page),
                    "signal {signal} dumpable {dumpable}"
                );
            }
        }
    }
}
