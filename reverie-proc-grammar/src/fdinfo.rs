/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `/proc/<pid>/fdinfo/<fd>`: printed by `seq_show`
//! (`fs/proc/fd.c`) as a fixed four-line header (`pos`, `flags`,
//! `mnt_id`, `ino`), then one `lock:` line per lock held through the
//! open file description (`show_fd_locks`, `fs/locks.c`), then the
//! file's own `show_fdinfo` lines (eventfd `fs/eventfd.c`, signalfd
//! `fs/signalfd.c`, timerfd `fs/timerfd.c`, unix sockets
//! `net/unix/af_unix.c`, pidfd `fs/pidfs.c`).
//!
//! Lines for kinds this grammar does not model are refused as
//! unknown labels, so a caller fails closed rather than serving a
//! truncated file. Known unmodelled kinds at time of writing:
//! io_uring (`SqMask:` … — 146 of 185,816 live files on the corpus
//! host; its `PollList:` entries need their own audit), fanotify,
//! perf events, userfaultfd, and `tty-index`. No `seals:` line is
//! printed for memfds by the cited kernel (verified live with all
//! seals set), so there is deliberately no seals kind.

use alloc::format;
use alloc::vec::Vec;

use crate::error::Format;
use crate::error::ProcParseError;
use crate::error::ensure_canonical;
use crate::error::span_of;
use crate::error::strip_final_newline;
use crate::num;

/// A lock's class as `lock_get_status` names it
/// (fs/locks.c:2781-2811 in v6.17).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockKind {
    /// `POSIX` record lock.
    Posix,
    /// `ACCESS` internal POSIX access-check lock.
    Access,
    /// `OFDLCK` open-file-description lock.
    OpenFileDescription,
    /// `FLOCK` flock(2) lock.
    Flock,
    /// `LEASE` lease.
    Lease,
    /// `DELEG` delegation.
    Deleg,
    /// `UNKNOWN`.
    Unknown,
}

/// A lock line's mode word. Which modes each class may carry is
/// checked at parse (FLOCK is always ADVISORY, for example); a
/// combination the kernel never prints is refused, not normalized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockMode {
    /// `ADVISORY`.
    Advisory,
    /// `MANDATORY` (pre-5.15 record locks).
    Mandatory,
    /// Lease `ACTIVE`.
    Active,
    /// Lease `BREAKING`.
    Breaking,
    /// Lease `BREAKER`.
    Breaker,
    /// `UNKNOWN` (only with [`LockKind::Unknown`]).
    Unknown,
}

/// A lock's access type (`F_RDLCK`/`F_WRLCK`/`F_UNLCK`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockAccess {
    /// `READ`.
    Read,
    /// `WRITE`.
    Write,
    /// `UNLCK`.
    Unlock,
}

/// One `lock:` line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdinfoLock {
    /// The lock class.
    pub class: LockKind,
    /// The mode word.
    pub mode: LockMode,
    /// The access type.
    pub access: LockAccess,
    /// Owner pid in the reader's namespace (-1 for OFD locks).
    pub owner: i64,
    /// Device major (printed hex).
    pub dev_major: u32,
    /// Device minor (printed hex).
    pub dev_minor: u32,
    /// Inode number.
    pub inode: u64,
    /// First locked byte (0 for non-record locks).
    pub start: u64,
    /// Last locked byte, or `None` for `EOF`.
    pub end: Option<u64>,
}

/// A timerfd's own lines (`timerfd_show`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timerfd {
    /// Clock the timerfd was created on.
    pub clockid: i32,
    /// Unread expirations.
    pub ticks: u64,
    /// Flags of the last `timerfd_settime` (`%02x`).
    pub settime_flags: u32,
    /// Time to next expiration as printed: `(sec, nsec)`.
    pub it_value: (u64, u64),
    /// Interval as printed: `(sec, nsec)`.
    pub it_interval: (u64, u64),
}

/// What the file's own `show_fdinfo` adds after any lock lines.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FdinfoKind {
    /// No `show_fdinfo`: regular file, pipe, memfd, most sockets.
    Plain,
    /// eventfd (count prints hexadecimal, `%16llx`).
    Eventfd {
        /// The counter value.
        count: u64,
        /// The eventfd id.
        id: u64,
        /// `EFD_SEMAPHORE` (1) or not (0), as printed. `None` on
        /// kernels before 6.5, whose `eventfd_show_fdinfo` prints
        /// only the count and id lines (fs/eventfd.c:295-304 in
        /// v6.4; the semaphore line is present by v6.17:283-299).
        semaphore: Option<u64>,
    },
    /// signalfd: the mask it reads.
    Signalfd {
        /// Signal mask, bit `n-1` for signal `n`.
        sigmask: u64,
    },
    /// timerfd.
    Timerfd(Timerfd),
    /// Unix socket: descriptors queued in unread `SCM_RIGHTS`.
    UnixSocket {
        /// Queued descriptor count.
        scm_fds: u32,
    },
    /// pidfd: numbers as the reader's namespaces print them.
    Pidfd {
        /// `Pid:` value (-1 after reap).
        pid: i64,
        /// `NSpid:` values, outermost first.
        nspid: Vec<i64>,
    },
    /// epoll instance: one `tfd:` line per watched descriptor
    /// (`ep_show_fdinfo`, `fs/eventpoll.c`).
    Epoll(Vec<EpollTarget>),
    /// inotify instance: one `inotify wd:` line per watch
    /// (`inotify_fdinfo`, `fs/notify/inotify/inotify_user.c`).
    Inotify(Vec<InotifyWatch>),
    /// FUSE device: `fuse_connection:` number (`fs/fuse/dev.c`).
    Fuse {
        /// The connection number.
        connection: u64,
    },
}

/// One epoll `tfd:` line. All but `tfd`/`pos` print hexadecimal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpollTarget {
    /// Watched descriptor number.
    pub tfd: i32,
    /// Requested event mask.
    pub events: u32,
    /// Opaque user data.
    pub data: u64,
    /// The watched file's position at registration.
    pub pos: i64,
    /// The watched file's inode (hex as printed).
    pub ino: u64,
    /// The watched file's device id (hex as printed).
    pub sdev: u64,
}

/// One inotify watch line. Fields print hexadecimal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InotifyWatch {
    /// Watch descriptor.
    pub wd: i32,
    /// Watched inode.
    pub ino: u64,
    /// Watched device id.
    pub sdev: u64,
    /// Event mask.
    pub mask: u32,
    /// Ignored-event mask.
    pub ignored_mask: u32,
    /// File-handle byte count (hex as printed).
    pub fhandle_bytes: u32,
    /// File-handle type (hex as printed).
    pub fhandle_type: u32,
    /// The file handle itself, hex bytes as printed.
    pub f_handle: Vec<u8>,
}

/// One fdinfo file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fdinfo {
    /// File position.
    pub pos: i64,
    /// Descriptor status flags (printed octal with leading `0`).
    pub flags: u32,
    /// Mount id (0 for anonymous-inode files).
    pub mnt_id: u64,
    /// Inode number.
    pub ino: u64,
    /// Lock lines in printed order.
    pub locks: Vec<FdinfoLock>,
    /// The file-kind lines.
    pub kind: FdinfoKind,
}

fn bad_shape(input: &[u8], line: &[u8]) -> ProcParseError {
    ProcParseError::BadShape {
        format: Format::Fdinfo,
        span: span_of(input, line),
    }
}

/// Split `label<sep>value` where `sep` is `:` then `tab` or space per
/// the kernel's per-line spellings.
fn split_line<'a>(line: &'a [u8], label: &[u8], sep: u8) -> Option<&'a [u8]> {
    let rest = line.strip_prefix(label)?;
    let rest = rest.strip_prefix(b":")?;
    rest.strip_prefix(&[sep])
}

fn parse_lock(line: &[u8], input: &[u8], index: usize) -> Result<FdinfoLock, ProcParseError> {
    let rest = line
        .strip_prefix(b"lock:\t")
        .ok_or_else(|| bad_shape(input, line))?;
    let tokens: Vec<&[u8]> = rest
        .split(|b| *b == b' ' || *b == b'\t')
        .filter(|t| !t.is_empty())
        .collect();
    // `1: FLOCK  ADVISORY  WRITE <owner> <maj>:<min>:<ino> <start> <end>`;
    // exact spacing is checked by re-rendering below.
    if tokens.len() != 8 {
        return Err(bad_shape(input, line));
    }
    let id_token = tokens[0]
        .strip_suffix(b":")
        .ok_or_else(|| bad_shape(input, line))?;
    let id = num::parse_u64(id_token, "lock id", span_of(input, id_token))?;
    if id != index as u64 + 1 {
        return Err(ProcParseError::BadValue {
            field: "lock id",
            span: span_of(input, id_token),
        });
    }
    let class = match tokens[1] {
        b"POSIX" => LockKind::Posix,
        b"ACCESS" => LockKind::Access,
        b"OFDLCK" => LockKind::OpenFileDescription,
        b"FLOCK" => LockKind::Flock,
        b"LEASE" => LockKind::Lease,
        b"DELEG" => LockKind::Deleg,
        b"UNKNOWN" => LockKind::Unknown,
        _ => return Err(bad_shape(input, line)),
    };
    let mode = match tokens[2] {
        b"ADVISORY" => LockMode::Advisory,
        b"MANDATORY" => LockMode::Mandatory,
        b"ACTIVE" => LockMode::Active,
        b"BREAKING" => LockMode::Breaking,
        b"BREAKER" => LockMode::Breaker,
        b"UNKNOWN" => LockMode::Unknown,
        _ => return Err(bad_shape(input, line)),
    };
    // Combinations lock_get_status never prints (FLOCK MANDATORY was
    // previously accepted and rendered back as ADVISORY, silently
    // rewriting the file).
    let canonical_combo = match class {
        LockKind::Posix | LockKind::Access | LockKind::OpenFileDescription => {
            matches!(mode, LockMode::Advisory | LockMode::Mandatory)
        }
        LockKind::Flock => mode == LockMode::Advisory,
        LockKind::Lease | LockKind::Deleg => {
            matches!(
                mode,
                LockMode::Active | LockMode::Breaking | LockMode::Breaker
            )
        }
        LockKind::Unknown => mode == LockMode::Unknown,
    };
    if !canonical_combo {
        return Err(bad_shape(input, line));
    }
    let access = match tokens[3] {
        b"WRITE" => LockAccess::Write,
        b"READ" => LockAccess::Read,
        b"UNLCK" => LockAccess::Unlock,
        _ => return Err(bad_shape(input, line)),
    };
    let owner = i64::from(num::parse_i32(
        tokens[4],
        "lock owner",
        span_of(input, tokens[4]),
    )?);
    let dev_parts: Vec<&[u8]> = tokens[5].split(|b| *b == b':').collect();
    if dev_parts.len() != 3 {
        return Err(bad_shape(input, line));
    }
    let hex32 = |token: &[u8], field: &'static str| -> Result<u32, ProcParseError> {
        // `%02x`: at least two digits, zero-padded only to two.
        if token.len() < 2 || (token.len() > 2 && token[0] == b'0') {
            return Err(bad_shape(input, line));
        }
        num::parse_hex_u32(token, field, span_of(input, token))
    };
    let dev_major = hex32(dev_parts[0], "lock device major")?;
    let dev_minor = hex32(dev_parts[1], "lock device minor")?;
    let inode = num::parse_u64(dev_parts[2], "lock inode", span_of(input, dev_parts[2]))?;
    let start = num::parse_u64(tokens[6], "lock start", span_of(input, tokens[6]))?;
    let end = if tokens[7] == b"EOF" {
        None
    } else {
        Some(num::parse_u64(
            tokens[7],
            "lock end",
            span_of(input, tokens[7]),
        )?)
    };
    // Non-record locks print `0 EOF` (fs/locks.c:2823-2829); a FLOCK
    // line carrying a byte range is not a kernel spelling.
    let record = matches!(
        class,
        LockKind::Posix | LockKind::Access | LockKind::OpenFileDescription
    );
    if !record && (start != 0 || end.is_some()) {
        return Err(bad_shape(input, line));
    }
    let lock = FdinfoLock {
        class,
        mode,
        access,
        owner,
        dev_major,
        dev_minor,
        inode,
        start,
        end,
    };
    // Exact column spacing, which tokenization discarded.
    let rendered = render_lock(&lock, index);
    if rendered.strip_suffix(b"\n") != Some(line) {
        return Err(bad_shape(input, line));
    }
    Ok(lock)
}

fn parse_timespec_pair(
    token: &[u8],
    input: &[u8],
    field: &'static str,
) -> Result<(u64, u64), ProcParseError> {
    let inner = token
        .strip_prefix(b"(")
        .and_then(|t| t.strip_suffix(b")"))
        .ok_or(ProcParseError::BadValue {
            field,
            span: span_of(input, token),
        })?;
    let comma = inner
        .iter()
        .position(|b| *b == b',')
        .ok_or(ProcParseError::BadValue {
            field,
            span: span_of(input, token),
        })?;
    let sec = num::parse_u64(&inner[..comma], field, span_of(input, &inner[..comma]))?;
    let nsec_token = inner[comma + 1..]
        .strip_prefix(b" ")
        .ok_or(ProcParseError::BadValue {
            field,
            span: span_of(input, token),
        })?;
    let nsec = num::parse_u64(nsec_token, field, span_of(input, nsec_token))?;
    if nsec >= 1_000_000_000 {
        return Err(ProcParseError::BadValue {
            field,
            span: span_of(input, token),
        });
    }
    Ok((sec, nsec))
}

/// Parse one fdinfo file's bytes.
pub fn parse_fdinfo(input: &[u8]) -> Result<Fdinfo, ProcParseError> {
    if input.is_empty() {
        return Err(ProcParseError::Empty {
            format: Format::Fdinfo,
        });
    }
    let body = strip_final_newline(input, Format::Fdinfo)?;
    let lines: Vec<&[u8]> = body.split(|b| *b == b'\n').collect();
    if lines.len() < 4 {
        return Err(bad_shape(input, input));
    }
    let header = |i: usize, label: &[u8]| -> Result<&[u8], ProcParseError> {
        split_line(lines[i], label, b'\t').ok_or_else(|| bad_shape(input, lines[i]))
    };
    let pos_token = header(0, b"pos")?;
    let pos = num::parse_i64(pos_token, "pos", span_of(input, pos_token))?;
    let flags_token = header(1, b"flags")?;
    let flags = num::parse_octal_u32(flags_token, "flags", span_of(input, flags_token))?;
    let mnt_token = header(2, b"mnt_id")?;
    let mnt_id = num::parse_u64(mnt_token, "mnt_id", span_of(input, mnt_token))?;
    let ino_token = header(3, b"ino")?;
    let ino = num::parse_u64(ino_token, "ino", span_of(input, ino_token))?;

    let mut locks = Vec::new();
    let mut rest: Vec<&[u8]> = Vec::new();
    for line in &lines[4..] {
        if line.starts_with(b"lock:") {
            if !rest.is_empty() {
                return Err(bad_shape(input, line));
            }
            let index = locks.len();
            locks.push(parse_lock(line, input, index)?);
        } else {
            rest.push(line);
        }
    }

    let kind = parse_kind(&rest, input)?;
    let fdinfo = Fdinfo {
        pos,
        flags,
        mnt_id,
        ino,
        locks,
        kind,
    };
    ensure_canonical(input, &render_fdinfo(&fdinfo), Format::Fdinfo)?;
    Ok(fdinfo)
}

fn parse_kind(lines: &[&[u8]], input: &[u8]) -> Result<FdinfoKind, ProcParseError> {
    if lines.is_empty() {
        return Ok(FdinfoKind::Plain);
    }
    let first = lines[0];
    if let Some(v) = split_line(first, b"eventfd-count", b' ') {
        // Two lines before Linux 6.5; the semaphore line is third
        // since (fs/eventfd.c cited on the variant).
        if lines.len() != 2 && lines.len() != 3 {
            return Err(bad_shape(input, first));
        }
        // `%16llx`: space-padded hex in a 16-wide field, no leading
        // zeros inside the digits.
        let hex = trim_spaces(v);
        if hex.is_empty() || hex.len() > 16 || v.len() != 16 || (hex.len() > 1 && hex[0] == b'0') {
            return Err(ProcParseError::BadValue {
                field: "eventfd-count",
                span: span_of(input, v),
            });
        }
        let count = num::parse_hex_u64(hex, hex.len(), "eventfd-count", span_of(input, hex))?;
        let id_token =
            split_line(lines[1], b"eventfd-id", b' ').ok_or_else(|| bad_shape(input, lines[1]))?;
        let id = num::parse_u64(id_token, "eventfd-id", span_of(input, id_token))?;
        let semaphore = if lines.len() == 3 {
            let sem_token = split_line(lines[2], b"eventfd-semaphore", b' ')
                .ok_or_else(|| bad_shape(input, lines[2]))?;
            let value = num::parse_u64(sem_token, "eventfd-semaphore", span_of(input, sem_token))?;
            if value > 1 {
                return Err(ProcParseError::BadValue {
                    field: "eventfd-semaphore",
                    span: span_of(input, sem_token),
                });
            }
            Some(value)
        } else {
            None
        };
        return Ok(FdinfoKind::Eventfd {
            count,
            id,
            semaphore,
        });
    }
    if let Some(v) = split_line(first, b"sigmask", b'\t') {
        if lines.len() != 1 {
            return Err(bad_shape(input, first));
        }
        return Ok(FdinfoKind::Signalfd {
            sigmask: num::parse_hex_u64(v, 16, "sigmask", span_of(input, v))?,
        });
    }
    if let Some(v) = split_line(first, b"clockid", b' ') {
        if lines.len() != 5 {
            return Err(bad_shape(input, first));
        }
        let clockid = num::parse_i32(v, "clockid", span_of(input, v))?;
        let ticks_token =
            split_line(lines[1], b"ticks", b' ').ok_or_else(|| bad_shape(input, lines[1]))?;
        let ticks = num::parse_u64(ticks_token, "ticks", span_of(input, ticks_token))?;
        let flags_token = split_line(lines[2], b"settime flags", b' ')
            .ok_or_else(|| bad_shape(input, lines[2]))?;
        let settime_flags = u32::try_from(num::parse_hex_u64(
            flags_token,
            2,
            "settime flags",
            span_of(input, flags_token),
        )?)
        .map_err(|_| ProcParseError::BadValue {
            field: "settime flags",
            span: span_of(input, flags_token),
        })?;
        let value_token =
            split_line(lines[3], b"it_value", b' ').ok_or_else(|| bad_shape(input, lines[3]))?;
        let it_value = parse_timespec_pair(value_token, input, "it_value")?;
        let interval_token =
            split_line(lines[4], b"it_interval", b' ').ok_or_else(|| bad_shape(input, lines[4]))?;
        let it_interval = parse_timespec_pair(interval_token, input, "it_interval")?;
        return Ok(FdinfoKind::Timerfd(Timerfd {
            clockid,
            ticks,
            settime_flags,
            it_value,
            it_interval,
        }));
    }
    if let Some(v) = split_line(first, b"scm_fds", b' ') {
        if lines.len() != 1 {
            return Err(bad_shape(input, first));
        }
        return Ok(FdinfoKind::UnixSocket {
            scm_fds: num::parse_u32(v, "scm_fds", span_of(input, v))?,
        });
    }
    if let Some(v) = split_line(first, b"Pid", b'\t') {
        if lines.len() != 2 {
            return Err(bad_shape(input, first));
        }
        let pid = num::parse_i64(v, "Pid", span_of(input, v))?;
        let ns_token =
            split_line(lines[1], b"NSpid", b'\t').ok_or_else(|| bad_shape(input, lines[1]))?;
        let mut nspid = Vec::new();
        for part in ns_token.split(|b| *b == b'\t') {
            nspid.push(num::parse_i64(part, "NSpid", span_of(input, part))?);
        }
        return Ok(FdinfoKind::Pidfd { pid, nspid });
    }
    if first.starts_with(b"tfd:") {
        let mut targets = Vec::with_capacity(lines.len());
        for line in lines {
            targets.push(parse_epoll_target(line, input)?);
        }
        return Ok(FdinfoKind::Epoll(targets));
    }
    if first.starts_with(b"inotify ") {
        let mut watches = Vec::with_capacity(lines.len());
        for line in lines {
            watches.push(parse_inotify_watch(line, input)?);
        }
        return Ok(FdinfoKind::Inotify(watches));
    }
    if let Some(v) = split_line(first, b"fuse_connection", b'\t') {
        if lines.len() != 1 {
            return Err(bad_shape(input, first));
        }
        return Ok(FdinfoKind::Fuse {
            connection: num::parse_u64(v, "fuse_connection", span_of(input, v))?,
        });
    }
    let label_end = first.iter().position(|b| *b == b':').unwrap_or(first.len());
    Err(ProcParseError::UnknownLabel {
        format: Format::Fdinfo,
        span: span_of(input, &first[..label_end]),
    })
}

fn hex_var(token: &[u8], input: &[u8], field: &'static str) -> Result<u64, ProcParseError> {
    // `%x`/`%llx` minimal form: no leading zeros beyond a lone zero.
    if token.is_empty() || token.len() > 16 || (token.len() > 1 && token[0] == b'0') {
        return Err(bad_shape(input, token));
    }
    num::parse_hex_u64(token, token.len(), field, span_of(input, token))
}

fn hex32_var(token: &[u8], input: &[u8], field: &'static str) -> Result<u32, ProcParseError> {
    if token.len() > 1 && token[0] == b'0' {
        return Err(bad_shape(input, token));
    }
    num::parse_hex_u32(token, field, span_of(input, token))
}

fn field_after<'a>(
    tokens: &[&'a [u8]],
    want: &[u8],
    line: &[u8],
    input: &[u8],
) -> Result<&'a [u8], ProcParseError> {
    let at = tokens
        .iter()
        .position(|t| *t == want)
        .ok_or_else(|| bad_shape(input, line))?;
    tokens
        .get(at + 1)
        .copied()
        .ok_or_else(|| bad_shape(input, line))
}

fn field_prefixed<'a>(
    token: &'a [u8],
    prefix: &[u8],
    line: &[u8],
    input: &[u8],
) -> Result<&'a [u8], ProcParseError> {
    token
        .strip_prefix(prefix)
        .ok_or_else(|| bad_shape(input, line))
}

fn parse_epoll_target(line: &[u8], input: &[u8]) -> Result<EpollTarget, ProcParseError> {
    // `tfd: %8d events: %8x data: %16llx  pos:%lld ino:%llx sdev:%x`
    let tokens: Vec<&[u8]> = line
        .split(|b| *b == b' ')
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.len() != 9 || tokens[0] != b"tfd:" {
        return Err(bad_shape(input, line));
    }
    let tfd = num::parse_i32(tokens[1], "tfd", span_of(input, tokens[1]))?;
    let events_token = field_after(&tokens, b"events:", line, input)?;
    let events = hex32_var(events_token, input, "events")?;
    let data_token = field_after(&tokens, b"data:", line, input)?;
    let data = hex_var(data_token, input, "data")?;
    let pos_token = field_prefixed(tokens[6], b"pos:", line, input)?;
    let pos = num::parse_i64(pos_token, "pos", span_of(input, pos_token))?;
    let ino_token = field_prefixed(tokens[7], b"ino:", line, input)?;
    let ino = hex_var(ino_token, input, "ino")?;
    let sdev_token = field_prefixed(tokens[8], b"sdev:", line, input)?;
    let sdev = hex_var(sdev_token, input, "sdev")?;
    Ok(EpollTarget {
        tfd,
        events,
        data,
        pos,
        ino,
        sdev,
    })
}

fn parse_inotify_watch(line: &[u8], input: &[u8]) -> Result<InotifyWatch, ProcParseError> {
    // `inotify wd:%x ino:%lx sdev:%lx mask:%x ignored_mask:%x
    //  fhandle-bytes:%x fhandle-type:%x f_handle:%s`
    let tokens: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
    if tokens.len() != 9 || tokens[0] != b"inotify" {
        return Err(bad_shape(input, line));
    }
    let wd_token = field_prefixed(tokens[1], b"wd:", line, input)?;
    let wd =
        i32::try_from(hex32_var(wd_token, input, "wd")?).map_err(|_| bad_shape(input, line))?;
    let ino = hex_var(
        field_prefixed(tokens[2], b"ino:", line, input)?,
        input,
        "ino",
    )?;
    let sdev = hex_var(
        field_prefixed(tokens[3], b"sdev:", line, input)?,
        input,
        "sdev",
    )?;
    let mask = hex32_var(
        field_prefixed(tokens[4], b"mask:", line, input)?,
        input,
        "mask",
    )?;
    let ignored_mask = hex32_var(
        field_prefixed(tokens[5], b"ignored_mask:", line, input)?,
        input,
        "ignored_mask",
    )?;
    let fhandle_bytes = hex32_var(
        field_prefixed(tokens[6], b"fhandle-bytes:", line, input)?,
        input,
        "fhandle-bytes",
    )?;
    let fhandle_type = hex32_var(
        field_prefixed(tokens[7], b"fhandle-type:", line, input)?,
        input,
        "fhandle-type",
    )?;
    let handle_token = field_prefixed(tokens[8], b"f_handle:", line, input)?;
    let (handle_pairs, handle_rem) = handle_token.as_chunks::<2>();
    if !handle_rem.is_empty()
        || handle_token
            .iter()
            .any(|b| !(b.is_ascii_digit() || (b'a'..=b'f').contains(b)))
    {
        return Err(bad_shape(input, line));
    }
    let mut f_handle = Vec::with_capacity(handle_pairs.len());
    for pair in handle_pairs {
        f_handle.push(
            u8::try_from(num::parse_hex_u64(
                pair,
                2,
                "f_handle",
                span_of(input, pair),
            )?)
            .map_err(|_| bad_shape(input, line))?,
        );
    }
    Ok(InotifyWatch {
        wd,
        ino,
        sdev,
        mask,
        ignored_mask,
        fhandle_bytes,
        fhandle_type,
        f_handle,
    })
}

fn trim_spaces(token: &[u8]) -> &[u8] {
    let start = token.iter().position(|b| *b != b' ').unwrap_or(token.len());
    &token[start..]
}

fn render_lock(lock: &FdinfoLock, index: usize) -> Vec<u8> {
    let mut out = format!("lock:\t{}: ", index + 1).into_bytes();
    // The class/mode columns are padded exactly as `lock_get_status`
    // prints them (fs/locks.c:2781-2811 in v6.17; MANDATORY is the
    // pre-5.15 spelling the same columns carried).
    let class_mode = match (lock.class, lock.mode) {
        (LockKind::Posix, LockMode::Mandatory) => "POSIX  MANDATORY ",
        (LockKind::Posix, LockMode::Advisory) => "POSIX  ADVISORY  ",
        (LockKind::Access, LockMode::Mandatory) => "ACCESS MANDATORY ",
        (LockKind::Access, LockMode::Advisory) => "ACCESS ADVISORY  ",
        (LockKind::OpenFileDescription, LockMode::Mandatory) => "OFDLCK MANDATORY ",
        (LockKind::OpenFileDescription, LockMode::Advisory) => "OFDLCK ADVISORY  ",
        (LockKind::Flock, LockMode::Advisory) => "FLOCK  ADVISORY  ",
        (LockKind::Lease, LockMode::Breaking) => "LEASE  BREAKING  ",
        (LockKind::Lease, LockMode::Active) => "LEASE  ACTIVE    ",
        (LockKind::Lease, LockMode::Breaker) => "LEASE  BREAKER   ",
        (LockKind::Deleg, LockMode::Breaking) => "DELEG  BREAKING  ",
        (LockKind::Deleg, LockMode::Active) => "DELEG  ACTIVE    ",
        (LockKind::Deleg, LockMode::Breaker) => "DELEG  BREAKER   ",
        (LockKind::Unknown, LockMode::Unknown) => "UNKNOWN UNKNOWN  ",
        // A combination the kernel never prints (constructible only
        // by hand); render it plainly — the parser refuses it back.
        (class, mode) => {
            let class = match class {
                LockKind::Posix => "POSIX",
                LockKind::Access => "ACCESS",
                LockKind::OpenFileDescription => "OFDLCK",
                LockKind::Flock => "FLOCK",
                LockKind::Lease => "LEASE",
                LockKind::Deleg => "DELEG",
                LockKind::Unknown => "UNKNOWN",
            };
            let mode = match mode {
                LockMode::Advisory => "ADVISORY",
                LockMode::Mandatory => "MANDATORY",
                LockMode::Active => "ACTIVE",
                LockMode::Breaking => "BREAKING",
                LockMode::Breaker => "BREAKER",
                LockMode::Unknown => "UNKNOWN",
            };
            out.extend_from_slice(format!("{class} {mode} ").as_bytes());
            ""
        }
    };
    out.extend_from_slice(class_mode.as_bytes());
    out.extend_from_slice(match lock.access {
        LockAccess::Write => b"WRITE ",
        LockAccess::Read => b"READ ",
        LockAccess::Unlock => b"UNLCK ",
    });
    let record = matches!(
        lock.class,
        LockKind::Posix | LockKind::Access | LockKind::OpenFileDescription
    );
    let (start, end) = if record {
        (lock.start, lock.end)
    } else {
        (0, None)
    };
    let end_text = end.map_or_else(|| alloc::string::String::from("EOF"), |e| format!("{e}"));
    out.extend_from_slice(
        format!(
            "{} {:02x}:{:02x}:{} {} {}\n",
            lock.owner, lock.dev_major, lock.dev_minor, lock.inode, start, end_text
        )
        .as_bytes(),
    );
    out
}

/// Render an [`Fdinfo`] in the kernel's byte shape.
pub fn render_fdinfo(fdinfo: &Fdinfo) -> Vec<u8> {
    // The kernel prints a literal leading zero before the octal
    // digits, so flags 0 renders as "00" (verified live: an inotify
    // fd opened without flags).
    let flags = format!("0{:o}", fdinfo.flags);
    let mut out = format!(
        "pos:\t{}\nflags:\t{}\nmnt_id:\t{}\nino:\t{}\n",
        fdinfo.pos, flags, fdinfo.mnt_id, fdinfo.ino
    )
    .into_bytes();
    for (i, lock) in fdinfo.locks.iter().enumerate() {
        out.extend_from_slice(&render_lock(lock, i));
    }
    let kind_text: Vec<u8> = match &fdinfo.kind {
        FdinfoKind::Plain => Vec::new(),
        FdinfoKind::Eventfd {
            count,
            id,
            semaphore,
        } => {
            let mut text =
                format!("eventfd-count: {count:16x}\neventfd-id: {id}\n").into_bytes();
            if let Some(semaphore) = semaphore {
                text.extend_from_slice(format!("eventfd-semaphore: {semaphore}\n").as_bytes());
            }
            text
        }
        FdinfoKind::Signalfd { sigmask } => format!("sigmask:\t{sigmask:016x}\n").into_bytes(),
        FdinfoKind::Timerfd(timer) => format!(
            "clockid: {}\nticks: {}\nsettime flags: {:02x}\nit_value: ({}, {})\nit_interval: ({}, {})\n",
            timer.clockid,
            timer.ticks,
            timer.settime_flags,
            timer.it_value.0,
            timer.it_value.1,
            timer.it_interval.0,
            timer.it_interval.1
        )
        .into_bytes(),
        FdinfoKind::UnixSocket { scm_fds } => format!("scm_fds: {scm_fds}\n").into_bytes(),
        FdinfoKind::Pidfd { pid, nspid } => {
            let ns: Vec<alloc::string::String> =
                nspid.iter().map(|p| format!("{p}")).collect();
            format!("Pid:\t{pid}\nNSpid:\t{}\n", ns.join("\t")).into_bytes()
        }
        FdinfoKind::Epoll(targets) => {
            let mut text = Vec::new();
            for target in targets {
                text.extend_from_slice(
                    format!(
                        "tfd: {:8} events: {:8x} data: {:16x}  pos:{} ino:{:x} sdev:{:x}\n",
                        target.tfd,
                        target.events,
                        target.data,
                        target.pos,
                        target.ino,
                        target.sdev
                    )
                    .as_bytes(),
                );
            }
            text
        }
        FdinfoKind::Inotify(watches) => {
            let mut text = Vec::new();
            for watch in watches {
                let handle: Vec<alloc::string::String> = watch
                    .f_handle
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                text.extend_from_slice(
                    format!(
                        "inotify wd:{:x} ino:{:x} sdev:{:x} mask:{:x} ignored_mask:{:x} fhandle-bytes:{:x} fhandle-type:{:x} f_handle:{}\n",
                        watch.wd,
                        watch.ino,
                        watch.sdev,
                        watch.mask,
                        watch.ignored_mask,
                        watch.fhandle_bytes,
                        watch.fhandle_type,
                        handle.concat()
                    )
                    .as_bytes(),
                );
            }
            text
        }
        FdinfoKind::Fuse { connection } => {
            format!("fuse_connection:\t{connection}\n").into_bytes()
        }
    };
    out.extend_from_slice(&kind_text);
    out
}
