/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! [`reverie::Guest::signal_sets`] of a traced thread: the five signal lines
//! of the kernel's `/proc/<tid>/status` for the thread `tid` names, which
//! the tracer reads while the asking thread is stopped in the tool's
//! callback.
//!
//! A traced guest thread is a host task, and the tracer shares the guest's
//! `/proc` view, so the lines are the kernel's own for that thread. The fact
//! answers for a thread this session traces, in whichever of its processes,
//! and reads no other task's file. It never opens `/proc/<tid>` by number:
//! it opens `status` in the `/proc/<tid>` directory the session retained for
//! the task when it began tracing it (`FatalSession::traced_directories`).
//! That directory names the task it was opened for until the task is
//! reaped, and no task after, so a task that takes the number over while the
//! session still holds it is never read. The file's `TracerPid:` line must
//! then name a thread of this process, and its `State:` line tells a thread
//! that has exited but whose file is still there (a zombie, or a task being
//! released) from a live one.

use std::ffi::CStr;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;

use reverie::Errno;
use reverie::FactError;
use reverie::Pid;
use reverie::SignalSets;

/// The most `status` text read for one thread. Its `Groups:` line lists
/// every supplementary group, up to 65,536 of them, so the text has no small
/// fixed bound; a longer one is not provided.
pub(crate) const STATUS_LIMIT: u64 = 1024 * 1024;

/// What [`parse`] answers for text that is not Linux's `status` format.
const MALFORMED: FactError = FactError::Errno(Errno::EIO);

/// What a thread ID that names no live thread this session traces answers.
pub(crate) const NO_THREAD: FactError = FactError::Errno(Errno::ESRCH);

/// Linux's `PID_MAX_LIMIT` on a 64-bit kernel (`include/linux/threads.h`):
/// every task number is below it.
const PID_MAX_LIMIT: u32 = 4 * 1024 * 1024;

/// Every `State:` value Linux prints (`task_state_array` in
/// `fs/proc/array.c`).
const TASK_STATES: [&[u8]; 9] = [
    b"R (running)",
    b"S (sleeping)",
    b"D (disk sleep)",
    b"T (stopped)",
    b"t (tracing stop)",
    b"X (dead)",
    b"Z (zombie)",
    b"P (parked)",
    b"I (idle)",
];

/// A line [`parse`] reads, by its key.
#[derive(Clone, Copy)]
enum Field {
    State,
    TracerPid,
    /// One of the five signal lines, by its place in [`SignalSets::new`]'s
    /// arguments, which is the order Linux prints them in (`task_sig`).
    Set(usize),
}

/// The keys of the lines [`parse`] reads.
const FIELDS: [(&[u8], Field); 7] = [
    (b"State", Field::State),
    (b"TracerPid", Field::TracerPid),
    (b"SigPnd", Field::Set(0)),
    (b"ShdPnd", Field::Set(1)),
    (b"SigBlk", Field::Set(2)),
    (b"SigIgn", Field::Set(3)),
    (b"SigCgt", Field::Set(4)),
];

/// What [`parse`] reads of a thread's `status`.
#[derive(Debug, PartialEq)]
pub(crate) struct ThreadStatus {
    sets: SignalSets,
    /// The letter of the `State:` line.
    state: u8,
    /// The `TracerPid:` line: the task that traces the thread, 0 for none.
    pub(crate) tracer: u32,
}

impl ThreadStatus {
    /// Whether the thread has exited, though its file is still there: a
    /// zombie (`Z`) or a task being released (`X`).
    pub(crate) fn exited(&self) -> bool {
        matches!(self.state, b'Z' | b'X')
    }
}

/// Reads and parses the signal sets of thread `tid` through `directories`,
/// which gives the retained `/proc/<tid>` directories of the tasks the
/// session traces as `tid` (`FatalSession::traced_directories`): none for a
/// number it does not trace. At most one of them names a live task, the one
/// that holds the number now; a directory whose task has been reaped reads
/// as no task, and the next is tried. The file read must show a tracer that
/// is a thread of this process and a task that has not exited.
pub(crate) fn read<D: AsFd>(
    tid: Pid,
    directories: impl FnOnce(Pid) -> Vec<D>,
) -> Result<SignalSets, FactError> {
    // Linux numbers no task zero or below.
    if tid.as_raw() <= 0 {
        return Err(NO_THREAD);
    }
    for directory in directories(tid) {
        let text = {
            // The guard ends before anything else runs.
            let _open = crate::launch_window::TransientOpen::begin();
            open_status(directory.as_fd()).and_then(|file| read_bounded(file, STATUS_LIMIT))
        };
        let status = match text {
            Ok(Some(text)) => parse(&text)?,
            Ok(None) => return Err(FactError::NotProvided),
            Err(error) => match read_errno(&error) {
                Errno::ESRCH => continue,
                errno => return Err(FactError::Errno(errno)),
            },
        };
        let tracer = Pid::from_raw(i32::try_from(status.tracer).unwrap_or(0));
        if !status.exited() && crate::tracer::tracer_is_current(tracer) {
            return Ok(status.sets);
        }
    }
    Err(NO_THREAD)
}

/// Opens `status` read-only in the task directory `directory`: the file of
/// the task the directory was opened for, whatever task holds its number
/// now. `ENOENT` once that task has been reaped.
pub(crate) fn open_status(directory: BorrowedFd<'_>) -> std::io::Result<std::fs::File> {
    const STATUS: &CStr = c"status";
    // SAFETY: the directory descriptor is open for the call, and the name is
    // a NUL-terminated string.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            STATUS.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor that nothing else owns.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// The whole of `file`, or `None` when it is longer than `limit` bytes.
pub(crate) fn read_bounded(file: std::fs::File, limit: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut text = Vec::new();
    file.take(limit + 1).read_to_end(&mut text)?;
    Ok((text.len() as u64 <= limit).then_some(text))
}

/// What a failed read of a thread's `status` means. Linux answers `ENOENT`
/// at the open for a task directory whose task has been released, and
/// `ESRCH` at the read for a task released since the open; both mean that
/// the task no longer lives. Any other error is the kernel's answer to the
/// tracer's read.
pub(crate) fn read_errno(error: &std::io::Error) -> Errno {
    match error.raw_os_error() {
        Some(libc::ENOENT | libc::ESRCH) => Errno::ESRCH,
        Some(errno) => Errno::new(errno),
        None => Errno::EIO,
    }
}

/// The signal sets, state and tracer in a thread's `status` text.
///
/// The text must be Linux's, or it is `EIO`: every line ends with a newline
/// and is a key of ASCII letters, digits and underscores, a colon, and its
/// value. The `State:` and `TracerPid:` lines and the five signal lines each
/// appear once, with the tab Linux prints after the colon, and each line is
/// checked whole: the state is one Linux prints (`task_state_array`), the
/// tracer a decimal below `PID_MAX_LIMIT` without leading zeros
/// (`seq_put_decimal_ull`), and each set sixteen lowercase hexadecimal
/// digits (`render_sigset_t`, `hex_asc`); there is no `SIGKILL` or `SIGSTOP`
/// in the mask, ignored or caught sets, and no signal both ignored and
/// caught. Lines with other keys are skipped.
pub(crate) fn parse(text: &[u8]) -> Result<ThreadStatus, FactError> {
    let body = text.strip_suffix(b"\n").ok_or(MALFORMED)?;
    let mut state = None;
    let mut tracer = None;
    let mut sets = [None; 5];
    for line in body.split(|byte| *byte == b'\n') {
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(MALFORMED)?;
        let (key, rest) = (&line[..colon], &line[colon + 1..]);
        if key.is_empty()
            || !key
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            return Err(MALFORMED);
        }
        let Some(&(_, field)) = FIELDS.iter().find(|(name, _)| *name == key) else {
            continue;
        };
        let value = rest.strip_prefix(b"\t").ok_or(MALFORMED)?;
        let first = match field {
            Field::State => {
                if !TASK_STATES.contains(&value) {
                    return Err(MALFORMED);
                }
                state.replace(value[0]).is_none()
            }
            Field::TracerPid => tracer.replace(parse_pid(value).ok_or(MALFORMED)?).is_none(),
            Field::Set(index) => sets[index]
                .replace(parse_set(value).ok_or(MALFORMED)?)
                .is_none(),
        };
        if !first {
            return Err(MALFORMED);
        }
    }
    let (
        Some(state),
        Some(tracer),
        [
            Some(pending),
            Some(shared_pending),
            Some(blocked),
            Some(ignored),
            Some(caught),
        ],
    ) = (state, tracer, sets)
    else {
        return Err(MALFORMED);
    };
    // Linux strips both from every mask it installs, refuses an action for
    // either, and keeps one action per signal.
    let unchangeable = bit(libc::SIGKILL) | bit(libc::SIGSTOP);
    if (blocked | ignored | caught) & unchangeable != 0 || ignored & caught != 0 {
        return Err(MALFORMED);
    }
    Ok(ThreadStatus {
        sets: SignalSets::new(pending, shared_pending, blocked, ignored, caught),
        state,
        tracer,
    })
}

/// The bit of `signal` in a set.
fn bit(signal: libc::c_int) -> u64 {
    1 << (signal - 1)
}

/// A task number as `seq_put_decimal_ull` prints it: decimal digits with no
/// sign, padding or leading zero (0 is `0`), below `PID_MAX_LIMIT`. Linux
/// prints 0 for no task, and for one its reader's PID namespace does not
/// see.
fn parse_pid(field: &[u8]) -> Option<u32> {
    if field.is_empty()
        || !field.iter().all(u8::is_ascii_digit)
        || (field.len() > 1 && field[0] == b'0')
    {
        return None;
    }
    std::str::from_utf8(field)
        .ok()?
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid < PID_MAX_LIMIT)
}

/// A set as `render_sigset_t` prints it on x86-64 and aarch64, whose
/// `_NSIG` is 64: exactly sixteen lowercase hexadecimal digits (`hex_asc`),
/// the highest-numbered signals first.
fn parse_set(field: &[u8]) -> Option<u64> {
    if field.len() != 16
        || !field
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(field).ok()?, 16).ok()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::OpenOptionsExt;

    use super::*;

    /// A thread's `status` as Linux 7.1.3 prints it, with the five signal
    /// lines, the `State:` value and the `TracerPid:` number left to fill in.
    fn status(state: &str, tracer: u32, sets: [&str; 5]) -> String {
        let [pending, shared, blocked, ignored, caught] = sets;
        format!(
            "Name:\tworker\\nname\nUmask:\t0022\nState:\t{state}\nTgid:\t4242\nNgid:\t0\n\
             Pid:\t4243\nPPid:\t4000\nTracerPid:\t{tracer}\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n\
             FDSize:\t64\nGroups:\t0 \nNStgid:\t4242\nNSpid:\t4243\nNSpgid:\t4242\n\
             NSsid:\t4000\nKthread:\t0\nVmPeak:\t    5768 kB\nThreads:\t2\nSigQ:\t2/3091463\n\
             SigPnd:\t{pending}\nShdPnd:\t{shared}\nSigBlk:\t{blocked}\nSigIgn:\t{ignored}\n\
             SigCgt:\t{caught}\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\n\
             NoNewPrivs:\t0\nSeccomp:\t0\nCpus_allowed:\tffffffff,ffffffff\n\
             Cpus_allowed_list:\t0-63\nvoluntary_ctxt_switches:\t4\n\
             nonvoluntary_ctxt_switches:\t0\n"
        )
    }

    const ZERO: &str = "0000000000000000";

    fn parse_status(text: &str) -> Result<ThreadStatus, FactError> {
        parse(text.as_bytes())
    }

    fn sets(lines: [&str; 5]) -> Result<SignalSets, FactError> {
        parse_status(&status("S (sleeping)", 4000, lines)).map(|status| status.sets)
    }

    /// Each line fills its own set, signal `n` at bit `n - 1`.
    #[test]
    fn each_line_fills_its_own_set() {
        assert_eq!(
            sets([
                "0000000000000200",
                "0000000000000800",
                "0000000000004002",
                "0000000000000001",
                "0000000000014000",
            ]),
            Ok(SignalSets::new(
                bit(libc::SIGUSR1),
                bit(libc::SIGUSR2),
                bit(libc::SIGINT) | bit(libc::SIGTERM),
                bit(libc::SIGHUP),
                bit(libc::SIGTERM) | bit(libc::SIGCHLD),
            ))
        );
        assert_eq!(sets([ZERO; 5]), Ok(SignalSets::new(0, 0, 0, 0, 0)));
    }

    /// Real-time signals take the high bits: Linux's first, 32, at bit 31,
    /// glibc's `SIGRTMIN`, 34, at bit 33, and the last, 64, at bit 63. One
    /// queued twice is still one bit, as Linux prints it.
    #[test]
    fn real_time_signals_take_the_high_bits() {
        let parsed = sets([
            "0000000200000000",
            "8000000000000000",
            "fffffffe7ffbfeff",
            "0000000080000000",
            "0000000180000000",
        ]);
        assert_eq!(parsed, Err(MALFORMED), "signal 32 both ignored and caught");
        let parsed = sets([
            "0000000200000000",
            "8000000000000000",
            "fffffffe7ffbfeff",
            "0000000080000000",
            "0000000100000000",
        ])
        .unwrap();
        assert_eq!(parsed.pending, bit(34));
        assert_eq!(parsed.shared_pending, bit(64));
        // Every signal but SIGKILL, SIGSTOP and glibc's two internal ones.
        assert_eq!(
            parsed.blocked,
            !(bit(libc::SIGKILL) | bit(libc::SIGSTOP) | bit(32) | bit(33))
        );
        assert_eq!(parsed.ignored, bit(32));
        assert_eq!(parsed.caught, bit(33));
    }

    /// SIGKILL and SIGSTOP can be pending (a dying thread, a stop that no
    /// thread has taken yet), but never blocked, ignored or caught.
    #[test]
    fn sigkill_and_sigstop_are_pending_only() {
        let kill_and_stop = format!("{:016x}", bit(libc::SIGKILL) | bit(libc::SIGSTOP));
        let parsed = sets([&kill_and_stop, &kill_and_stop, ZERO, ZERO, ZERO]).unwrap();
        assert_eq!(parsed.pending, 0x40100);
        assert_eq!(parsed.shared_pending, 0x40100);
        for signal in [libc::SIGKILL, libc::SIGSTOP] {
            let set = format!("{:016x}", bit(signal));
            for index in 2..5 {
                let mut lines = [ZERO; 5];
                lines[index] = &set;
                assert_eq!(
                    sets(lines),
                    Err(MALFORMED),
                    "signal {signal} in set {index}"
                );
            }
        }
    }

    /// The state's letter and the tracer's number are read; a zombie and a
    /// task being released have exited, every other state has not.
    #[test]
    fn the_state_and_the_tracer_are_read() {
        for (state, exited) in [
            ("R (running)", false),
            ("S (sleeping)", false),
            ("D (disk sleep)", false),
            ("T (stopped)", false),
            ("t (tracing stop)", false),
            ("X (dead)", true),
            ("Z (zombie)", true),
            ("P (parked)", false),
            ("I (idle)", false),
        ] {
            let parsed = parse_status(&status(state, 4000, [ZERO; 5])).unwrap();
            assert_eq!(parsed.state, state.as_bytes()[0], "{state}");
            assert_eq!(parsed.exited(), exited, "{state}");
            assert_eq!(parsed.tracer, 4000);
        }
        // No tracer, and the largest task number.
        for tracer in [0, 4_194_303] {
            let parsed = parse_status(&status("S (sleeping)", tracer, [ZERO; 5])).unwrap();
            assert_eq!(parsed.tracer, tracer);
        }
        // A malformed text is EIO whatever its state.
        assert_eq!(
            parse_status(&status("Z (zombie)", 4000, [ZERO, ZERO, ZERO, ZERO, "xyz"])),
            Err(MALFORMED)
        );
    }

    /// Every one of the seven lines read must be there exactly once.
    #[test]
    fn missing_and_repeated_lines_are_eio() {
        let full = status("S (sleeping)", 4000, [ZERO; 5]);
        for label in [
            "State:\t",
            "TracerPid:\t",
            "SigPnd:\t",
            "ShdPnd:\t",
            "SigBlk:\t",
            "SigIgn:\t",
            "SigCgt:\t",
        ] {
            let line = full
                .lines()
                .find(|line| line.starts_with(label))
                .unwrap()
                .to_owned()
                + "\n";
            assert_eq!(
                parse_status(&full.replacen(&line, "", 1)),
                Err(MALFORMED),
                "without {label}"
            );
            assert_eq!(
                parse_status(&format!("{full}{line}")),
                Err(MALFORMED),
                "{label} twice"
            );
        }
    }

    /// A line with a key the parser reads must have the tab Linux prints
    /// after the colon, even beside a well-formed line of the same key: it is
    /// refused, not skipped.
    #[test]
    fn a_read_key_without_linuxs_separator_is_eio() {
        let full = status("S (sleeping)", 4000, [ZERO; 5]);
        for line in [
            "SigPnd: 0000000000000000",
            "SigPnd:0000000000000000",
            "SigPnd:\t\t0000000000000000",
            "SigBlk: 0000000000000000",
            "TracerPid: 4000",
            "TracerPid:4000",
            "State: S (sleeping)",
            "State:",
        ] {
            assert_eq!(
                parse_status(&format!("{full}{line}\n")),
                Err(MALFORMED),
                "{line:?} after a full text"
            );
        }
    }

    /// Every line is a key, a colon and a value; a line that is not is
    /// refused, wherever it is.
    #[test]
    fn a_line_that_is_not_a_key_and_value_is_eio() {
        let full = status("S (sleeping)", 4000, [ZERO; 5]);
        for line in [
            "",
            "SigPnd\t0000000000000000",
            "SigPnd \t0000000000000000",
            "SigPnd :\t0000000000000000",
            " SigPnd:\t0000000000000000",
            "Sig-Pnd:\t0000000000000000",
            ":\t0000000000000000",
            "no colon at all",
        ] {
            assert_eq!(
                parse_status(&full.replacen("Kthread:\t0\n", &format!("Kthread:\t0\n{line}\n"), 1)),
                Err(MALFORMED),
                "{line:?}"
            );
        }
    }

    /// A set is sixteen lowercase hexadecimal digits, a state one Linux
    /// prints, a tracer a decimal below `PID_MAX_LIMIT` without a leading
    /// zero, and the text ends with a newline.
    #[test]
    fn malformed_values_are_eio() {
        for set in [
            "",
            "000000000000000",
            "00000000000000000",
            "0000000000000000000000000000000",
            "000000000000000A",
            "FFFFFFFFFFFFFFFF",
            "000000000000000g",
            "0x00000000000000",
            " 000000000000000",
            "000000000000000 ",
            "-000000000000001",
        ] {
            assert_eq!(
                sets([ZERO, ZERO, set, ZERO, ZERO]),
                Err(MALFORMED),
                "set {set:?}"
            );
        }
        let full = status("S (sleeping)", 4000, [ZERO; 5]);
        for (from, to) in [
            ("TracerPid:\t4000\n", "TracerPid:\t\n"),
            ("TracerPid:\t4000\n", "TracerPid:\t+4000\n"),
            ("TracerPid:\t4000\n", "TracerPid:\t-1\n"),
            ("TracerPid:\t4000\n", "TracerPid:\t04000\n"),
            ("TracerPid:\t4000\n", "TracerPid:\t40x0\n"),
            ("TracerPid:\t4000\n", "TracerPid:\t 4000\n"),
            ("TracerPid:\t4000\n", "TracerPid:\t4000 \n"),
            // PID_MAX_LIMIT and beyond.
            ("TracerPid:\t4000\n", "TracerPid:\t4194304\n"),
            ("TracerPid:\t4000\n", "TracerPid:\t2147483648\n"),
            ("TracerPid:\t4000\n", "TracerPid:\t18446744073709551616\n"),
            ("State:\tS (sleeping)\n", "State:\t\n"),
            ("State:\tS (sleeping)\n", "State:\tS\n"),
            ("State:\tS (sleeping)\n", "State:\tS (sleepy)\n"),
            ("State:\tS (sleeping)\n", "State:\ts (sleeping)\n"),
            ("State:\tS (sleeping)\n", "State:\tS (sleeping) \n"),
            ("State:\tS (sleeping)\n", "State:\tQ (queued)\n"),
        ] {
            assert_eq!(
                parse_status(&full.replacen(from, to, 1)),
                Err(MALFORMED),
                "{to:?}"
            );
        }
        assert_eq!(
            parse_status(full.strip_suffix('\n').unwrap()),
            Err(MALFORMED),
            "no final newline"
        );
        assert_eq!(parse(b""), Err(MALFORMED));
        assert_eq!(parse(b"\n"), Err(MALFORMED));
        // A byte that is not UTF-8 in a set.
        let mut text = full.into_bytes();
        let at = text
            .windows(8)
            .position(|window| window == b"SigCgt:\t")
            .unwrap()
            + 8
            + 15;
        text[at] = 0xff;
        assert_eq!(parse(&text), Err(MALFORMED));
    }

    /// Lines with other keys are skipped, whatever their values: `NStgid:`,
    /// `Ngid:` and `Tgid:` are not read, `SigQ:` is not a set, keys differ by
    /// case, and a name with an escaped newline stays on its line.
    #[test]
    fn lines_with_other_keys_are_skipped() {
        let full = status("S (sleeping)", 4000, [ZERO; 5]);
        let text = full
            .replacen("Tgid:\t4242\n", "Tgid:\t+04242 \n", 1)
            .replacen(
                "Kthread:\t0\n",
                "Kthread:\t0\nsigpnd:\tffffffffffffffff\nSigPndX:\tffff\nopaque:\t\u{fe}\n\
                 Speculation_Store_Bypass:\tthread vulnerable\nx86_Thread_features:\t\n",
                1,
            );
        assert_eq!(
            parse_status(&text).map(|status| status.sets),
            Ok(SignalSets::new(0, 0, 0, 0, 0))
        );
    }

    /// A text of exactly the limit is read whole; one byte more is not read.
    #[test]
    fn the_read_bound_is_inclusive() {
        let path = std::env::temp_dir().join(format!(
            "reverie-ptrace-signal-sets-bound-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"0123456789").unwrap();
        let open = || std::fs::File::open(&path).unwrap();
        assert_eq!(
            read_bounded(open(), 10).unwrap(),
            Some(b"0123456789".to_vec())
        );
        assert_eq!(read_bounded(open(), 9).unwrap(), None);
        std::fs::remove_file(&path).unwrap();
    }

    fn this_thread() -> Pid {
        // SAFETY: gettid takes no arguments and cannot fail.
        Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32)
    }

    /// `/proc/<tid>`, opened as the session retains a task's directory.
    fn task_directory(tid: i32) -> std::fs::File {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(format!("/proc/{tid}"))
            .unwrap()
    }

    /// The session decides first: a number it gives no directory for is
    /// ESRCH, even where a task holds the number. Zero and below are ESRCH
    /// before the session is asked.
    #[test]
    fn a_number_the_session_does_not_trace_is_esrch() {
        let asked = std::cell::Cell::new(0);
        let untraced = |_| {
            asked.set(asked.get() + 1);
            Vec::<std::fs::File>::new()
        };
        assert_eq!(read(this_thread(), untraced), Err(NO_THREAD));
        assert_eq!(read(Pid::from_raw(1), untraced), Err(NO_THREAD));
        assert_eq!(asked.get(), 2);
        for tid in [0, -1, i32::MIN] {
            assert_eq!(read(Pid::from_raw(tid), untraced), Err(NO_THREAD), "{tid}");
        }
        assert_eq!(asked.get(), 2);
    }

    /// Where the session gives a directory, the file read through it must
    /// still show a tracer of this process: this test's own thread and init
    /// are traced by none of ours.
    #[test]
    fn a_task_no_tracer_of_ours_traces_is_esrch() {
        for tid in [this_thread().as_raw(), 1] {
            let directory = task_directory(tid);
            assert_eq!(
                read(Pid::from_raw(tid), |_| vec![directory]),
                Err(NO_THREAD),
                "{tid}"
            );
        }
    }

    /// A child of this process that this thread traces, with SIGUSR2 blocked
    /// and pending, and its directory, opened while it is certainly traced
    /// here. Dropped unreaped, as when a test fails, it is killed and reaped.
    struct TracedChild {
        pid: libc::pid_t,
        directory: std::fs::File,
        reaped: bool,
    }

    impl TracedChild {
        fn new() -> Self {
            let mut ready = [0; 2];
            // SAFETY: ready has room for the two descriptors.
            assert_eq!(
                unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            // SAFETY: the child makes only async-signal-safe calls before it ends.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "{}", std::io::Error::last_os_error());
            if pid == 0 {
                // SAFETY: plain calls on this process's own state and descriptors.
                unsafe {
                    let mut set: libc::sigset_t = std::mem::zeroed();
                    libc::sigemptyset(&mut set);
                    libc::sigaddset(&mut set, libc::SIGUSR2);
                    libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
                    libc::raise(libc::SIGUSR2);
                    libc::write(ready[1], b"r".as_ptr().cast(), 1);
                    loop {
                        libc::pause();
                    }
                }
            }
            let mut byte = 0u8;
            // SAFETY: byte is a live one-byte buffer.
            let read = unsafe { libc::read(ready[0], (&mut byte as *mut u8).cast(), 1) };
            // SAFETY: the descriptors are this test's own.
            unsafe {
                libc::close(ready[0]);
                libc::close(ready[1]);
            }
            // From here a failed check kills and reaps the child; its
            // directory is opened again once the child is traced, as the
            // session opens one.
            let mut child = Self {
                pid,
                directory: task_directory(pid),
                reaped: false,
            };
            assert_eq!(read, 1);
            // SAFETY: the child is this process's own; PTRACE_SEIZE leaves it running.
            let seized = unsafe {
                libc::ptrace(
                    libc::PTRACE_SEIZE,
                    pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    0 as libc::c_long,
                )
            };
            assert_eq!(seized, 0, "{}", std::io::Error::last_os_error());
            child.directory = task_directory(pid);
            child
        }

        /// The child's directory, as the session would give it.
        fn directory(&self) -> std::fs::File {
            self.directory.try_clone().unwrap()
        }

        /// Kills the child and waits until it has exited, without reaping it:
        /// a zombie.
        fn kill(&self) {
            // SAFETY: the child is this process's own and not reaped.
            assert_eq!(unsafe { libc::kill(self.pid, libc::SIGKILL) }, 0);
            // SAFETY: siginfo_t is plain data; an all-zero value is valid.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: info is writable.
            let waited = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            assert_eq!(waited, 0);
        }

        /// Reaps the child, which has exited.
        fn reap(&mut self) {
            let mut status = 0;
            // SAFETY: status is writable.
            assert_eq!(unsafe { libc::waitpid(self.pid, &mut status, 0) }, self.pid);
            self.reaped = true;
        }
    }

    impl Drop for TracedChild {
        fn drop(&mut self) {
            if !self.reaped {
                // SAFETY: the child is this process's own and not reaped, so
                // its number is still its own.
                unsafe { libc::kill(self.pid, libc::SIGKILL) };
                let mut status = 0;
                // SAFETY: status is writable.
                unsafe { libc::waitpid(self.pid, &mut status, 0) };
            }
        }
    }

    /// A child this thread traces: its sets while it lives, then ESRCH as a
    /// zombie (its file still there, its state `Z`), then ESRCH once reaped.
    #[test]
    fn a_traced_child_reports_its_sets_until_it_exits() {
        let mut child = TracedChild::new();
        let number = Pid::from_raw(child.pid);
        let sets = read(number, |_| vec![child.directory()]).unwrap();
        assert_eq!(sets.pending, bit(libc::SIGUSR2));
        assert_eq!(sets.blocked, bit(libc::SIGUSR2));
        child.kill();
        let text = std::fs::read_to_string(format!("/proc/{}/status", child.pid)).unwrap();
        assert!(text.contains("State:\tZ (zombie)\n"), "{text}");
        assert_eq!(read(number, |_| vec![child.directory()]), Err(NO_THREAD));
        child.reap();
        assert_eq!(read(number, |_| vec![child.directory()]), Err(NO_THREAD));
    }

    /// A number taken over, as near as a test comes without waiting for
    /// Linux to hand the same number out again: the directory of a task that
    /// has since been reaped, asked about under a number that a live task
    /// traced by this thread holds. The answer is the reaped task's, none
    /// (ESRCH), never the live task's, which a read of `/proc/<tid>` by
    /// number would give. Given the live task's own directory after the
    /// reaped one, the read passes the reaped one by and answers.
    #[test]
    fn a_directory_names_its_task_not_whoever_holds_the_number() {
        let mut gone = TracedChild::new();
        gone.kill();
        gone.reap();
        let live = TracedChild::new();
        let number = Pid::from_raw(live.pid);
        assert_eq!(read(number, |_| vec![gone.directory()]), Err(NO_THREAD));
        let sets = read(number, |_| vec![gone.directory(), live.directory()]).unwrap();
        assert_eq!(sets.pending, bit(libc::SIGUSR2));
        assert_eq!(sets.blocked, bit(libc::SIGUSR2));
    }
}
