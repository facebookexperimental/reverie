/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `/proc/<pid>/stat`: one line of 52 fields printed by
//! `do_task_stat` (`fs/proc/array.c`).
//!
//! The line is `%d (%s) %c ...`: the pid, the task's `comm` spliced
//! raw between parentheses, the state letter, then 49 numeric fields.
//! The comm is arbitrary bytes (up to 15 usable bytes of
//! `task_struct::comm`) and may itself contain spaces, `(`, `)`, and
//! newlines, so the only sound delimiters are the first ` (` after
//! the pid and the last `) ` before the numeric tail — with the tail
//! then required to hold exactly 50 fields (52 total). A naive
//! whitespace split of the whole line counts 53 fields for a comm
//! containing one space and shifts every later field by one.

use alloc::format;
use alloc::vec::Vec;

use crate::error::Format;
use crate::error::ProcParseError;
use crate::error::ensure_canonical;
use crate::error::span_of;
use crate::error::strip_final_newline;
use crate::num;

/// Fields per line, counting pid and comm.
pub const STAT_FIELD_COUNT: usize = 52;

/// One task's `stat` line, full-fidelity: every field the kernel
/// prints, named and typed after its `seq_printf` conversion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stat {
    /// Field 1 (`%d`): the task's number in the reader's PID namespace.
    pub pid: i32,
    /// Field 2: the task name, raw bytes as spliced between parens.
    pub comm: Vec<u8>,
    /// Field 3 (`%c`): the state letter byte (e.g. `R`, `S`, `Z`).
    pub state: u8,
    /// Field 4: parent pid.
    pub ppid: i32,
    /// Field 5: process group.
    pub pgrp: i32,
    /// Field 6: session.
    pub session: i32,
    /// Field 7: controlling terminal device number.
    pub tty_nr: i32,
    /// Field 8: controlling terminal's process group.
    pub tpgid: i32,
    /// Field 9 (`%u`): task flags word.
    pub flags: u32,
    /// Field 10: minor faults.
    pub minflt: u64,
    /// Field 11: reaped children's minor faults.
    pub cminflt: u64,
    /// Field 12: major faults.
    pub majflt: u64,
    /// Field 13: reaped children's major faults.
    pub cmajflt: u64,
    /// Field 14: user CPU time in clock ticks.
    pub utime: u64,
    /// Field 15: system CPU time in clock ticks.
    pub stime: u64,
    /// Field 16 (`%ld`): reaped children's user CPU time.
    pub cutime: i64,
    /// Field 17 (`%ld`): reaped children's system CPU time.
    pub cstime: i64,
    /// Field 18 (`%ld`): scheduling priority.
    pub priority: i64,
    /// Field 19 (`%ld`): nice value.
    pub nice: i64,
    /// Field 20: task count of the process.
    pub num_threads: i32,
    /// Field 21 (`%ld`): obsolete interval-timer field, always 0.
    pub itrealvalue: i64,
    /// Field 22 (`%llu`): start time in ticks since boot.
    pub starttime: u64,
    /// Field 23: virtual memory size in bytes.
    pub vsize: u64,
    /// Field 24 (`%ld`): resident set size in pages.
    pub rss: i64,
    /// Field 25: `RLIMIT_RSS` soft limit in bytes.
    pub rsslim: u64,
    /// Field 26: start of executable code.
    pub startcode: u64,
    /// Field 27: end of executable code.
    pub endcode: u64,
    /// Field 28: initial stack address.
    pub startstack: u64,
    /// Field 29: current stack pointer.
    pub kstkesp: u64,
    /// Field 30: current instruction pointer.
    pub kstkeip: u64,
    /// Field 31: obsolete blocked-signals word.
    pub signal: u64,
    /// Field 32: obsolete blocked-signals word.
    pub blocked: u64,
    /// Field 33: obsolete ignored-signals word.
    pub sigignore: u64,
    /// Field 34: obsolete caught-signals word.
    pub sigcatch: u64,
    /// Field 35: wait channel address.
    pub wchan: u64,
    /// Field 36: swapped pages (always 0).
    pub nswap: u64,
    /// Field 37: children's swapped pages (always 0).
    pub cnswap: u64,
    /// Field 38: exit signal for the thread-group leader, else -1.
    pub exit_signal: i32,
    /// Field 39: last CPU the task ran on.
    pub processor: i32,
    /// Field 40 (`%u`): realtime priority.
    pub rt_priority: u32,
    /// Field 41 (`%u`): scheduling policy.
    pub policy: u32,
    /// Field 42 (`%llu`): block-I/O delay in ticks.
    pub delayacct_blkio_ticks: u64,
    /// Field 43: guest CPU time in ticks.
    pub guest_time: u64,
    /// Field 44 (`%ld`): reaped children's guest CPU time.
    pub cguest_time: i64,
    /// Field 45: start of initialized data.
    pub start_data: u64,
    /// Field 46: end of initialized data.
    pub end_data: u64,
    /// Field 47: start of heap.
    pub start_brk: u64,
    /// Field 48: start of argument strings.
    pub arg_start: u64,
    /// Field 49: end of argument strings.
    pub arg_end: u64,
    /// Field 50: start of environment strings.
    pub env_start: u64,
    /// Field 51: end of environment strings.
    pub env_end: u64,
    /// Field 52: exit code for a zombie, as the reader may see it.
    pub exit_code: i32,
}

/// Parse one `stat` file's bytes.
///
/// The comm-delimiter rule is necessarily the kernel's own ambiguity
/// resolved the standard way (first ` (`, last `) `): a comm crafted
/// to embed `) ` followed by 50 plausible tail fields can fool every
/// parser of this format, including the kernel's own readers; the
/// exact tail-count and per-field number checks refuse everything
/// short of that.
pub fn parse_stat(input: &[u8]) -> Result<Stat, ProcParseError> {
    if input.is_empty() {
        return Err(ProcParseError::Empty {
            format: Format::Stat,
        });
    }
    let body = strip_final_newline(input, Format::Stat)?;
    let open = find(body, b" (").ok_or(ProcParseError::BadShape {
        format: Format::Stat,
        span: (0, body.len()),
    })?;
    let close = rfind(body, b") ").ok_or(ProcParseError::BadShape {
        format: Format::Stat,
        span: (0, body.len()),
    })?;
    if close < open + 2 {
        return Err(ProcParseError::BadShape {
            format: Format::Stat,
            span: (0, body.len()),
        });
    }
    let pid_token = &body[..open];
    let pid = num::parse_i32(pid_token, "pid", span_of(input, pid_token))?;
    let comm = body[open + 2..close].to_vec();
    let tail = &body[close + 2..];
    let tokens: Vec<&[u8]> = tail.split(|b| *b == b' ').collect();
    if tokens.len() != STAT_FIELD_COUNT - 2 {
        return Err(ProcParseError::WrongFieldCount {
            format: Format::Stat,
            expected: STAT_FIELD_COUNT,
            found: tokens.len() + 2,
        });
    }
    // tokens[i] is proc stat field i+3.
    let state_token = tokens[0];
    if state_token.len() != 1 || !state_token[0].is_ascii_alphabetic() {
        return Err(ProcParseError::BadValue {
            field: "state",
            span: span_of(input, state_token),
        });
    }
    let t = |i: usize| tokens[i];
    let sp = |i: usize| span_of(input, tokens[i]);
    let stat = Stat {
        pid,
        comm,
        state: state_token[0],
        ppid: num::parse_i32(t(1), "ppid", sp(1))?,
        pgrp: num::parse_i32(t(2), "pgrp", sp(2))?,
        session: num::parse_i32(t(3), "session", sp(3))?,
        tty_nr: num::parse_i32(t(4), "tty_nr", sp(4))?,
        tpgid: num::parse_i32(t(5), "tpgid", sp(5))?,
        flags: num::parse_u32(t(6), "flags", sp(6))?,
        minflt: num::parse_u64(t(7), "minflt", sp(7))?,
        cminflt: num::parse_u64(t(8), "cminflt", sp(8))?,
        majflt: num::parse_u64(t(9), "majflt", sp(9))?,
        cmajflt: num::parse_u64(t(10), "cmajflt", sp(10))?,
        utime: num::parse_u64(t(11), "utime", sp(11))?,
        stime: num::parse_u64(t(12), "stime", sp(12))?,
        cutime: num::parse_i64(t(13), "cutime", sp(13))?,
        cstime: num::parse_i64(t(14), "cstime", sp(14))?,
        priority: num::parse_i64(t(15), "priority", sp(15))?,
        nice: num::parse_i64(t(16), "nice", sp(16))?,
        num_threads: num::parse_i32(t(17), "num_threads", sp(17))?,
        itrealvalue: num::parse_i64(t(18), "itrealvalue", sp(18))?,
        starttime: num::parse_u64(t(19), "starttime", sp(19))?,
        vsize: num::parse_u64(t(20), "vsize", sp(20))?,
        rss: num::parse_i64(t(21), "rss", sp(21))?,
        rsslim: num::parse_u64(t(22), "rsslim", sp(22))?,
        startcode: num::parse_u64(t(23), "startcode", sp(23))?,
        endcode: num::parse_u64(t(24), "endcode", sp(24))?,
        startstack: num::parse_u64(t(25), "startstack", sp(25))?,
        kstkesp: num::parse_u64(t(26), "kstkesp", sp(26))?,
        kstkeip: num::parse_u64(t(27), "kstkeip", sp(27))?,
        signal: num::parse_u64(t(28), "signal", sp(28))?,
        blocked: num::parse_u64(t(29), "blocked", sp(29))?,
        sigignore: num::parse_u64(t(30), "sigignore", sp(30))?,
        sigcatch: num::parse_u64(t(31), "sigcatch", sp(31))?,
        wchan: num::parse_u64(t(32), "wchan", sp(32))?,
        nswap: num::parse_u64(t(33), "nswap", sp(33))?,
        cnswap: num::parse_u64(t(34), "cnswap", sp(34))?,
        exit_signal: num::parse_i32(t(35), "exit_signal", sp(35))?,
        processor: num::parse_i32(t(36), "processor", sp(36))?,
        rt_priority: num::parse_u32(t(37), "rt_priority", sp(37))?,
        policy: num::parse_u32(t(38), "policy", sp(38))?,
        delayacct_blkio_ticks: num::parse_u64(t(39), "delayacct_blkio_ticks", sp(39))?,
        guest_time: num::parse_u64(t(40), "guest_time", sp(40))?,
        cguest_time: num::parse_i64(t(41), "cguest_time", sp(41))?,
        start_data: num::parse_u64(t(42), "start_data", sp(42))?,
        end_data: num::parse_u64(t(43), "end_data", sp(43))?,
        start_brk: num::parse_u64(t(44), "start_brk", sp(44))?,
        arg_start: num::parse_u64(t(45), "arg_start", sp(45))?,
        arg_end: num::parse_u64(t(46), "arg_end", sp(46))?,
        env_start: num::parse_u64(t(47), "env_start", sp(47))?,
        env_end: num::parse_u64(t(48), "env_end", sp(48))?,
        exit_code: num::parse_i32(t(49), "exit_code", sp(49))?,
    };
    ensure_canonical(input, &render_stat(&stat), Format::Stat)?;
    Ok(stat)
}

/// Render a [`Stat`] in the kernel's byte shape: pid, parenthesised
/// comm bytes verbatim, then the 50 tail fields single-space separated
/// and a trailing newline.
pub fn render_stat(stat: &Stat) -> Vec<u8> {
    let mut out = format!("{} (", stat.pid).into_bytes();
    out.extend_from_slice(&stat.comm);
    let state = stat.state as char;
    out.extend_from_slice(
        format!(
            ") {state} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}\n",
            stat.ppid,
            stat.pgrp,
            stat.session,
            stat.tty_nr,
            stat.tpgid,
            stat.flags,
            stat.minflt,
            stat.cminflt,
            stat.majflt,
            stat.cmajflt,
            stat.utime,
            stat.stime,
            stat.cutime,
            stat.cstime,
            stat.priority,
            stat.nice,
            stat.num_threads,
            stat.itrealvalue,
            stat.starttime,
            stat.vsize,
            stat.rss,
            stat.rsslim,
            stat.startcode,
            stat.endcode,
            stat.startstack,
            stat.kstkesp,
            stat.kstkeip,
            stat.signal,
            stat.blocked,
            stat.sigignore,
            stat.sigcatch,
            stat.wchan,
            stat.nswap,
            stat.cnswap,
            stat.exit_signal,
            stat.processor,
            stat.rt_priority,
            stat.policy,
            stat.delayacct_blkio_ticks,
            stat.guest_time,
            stat.cguest_time,
            stat.start_data,
            stat.end_data,
            stat.start_brk,
            stat.arg_start,
            stat.arg_end,
            stat.env_start,
            stat.env_end,
            stat.exit_code,
        )
        .as_bytes(),
    );
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}
