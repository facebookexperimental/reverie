/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Hardware watchpoints: a tool asks the backend to report every access a
//! guest thread makes to a few bytes of its memory.
//!
//! A tool arms a thread's watches with [`Guest::set_watchpoints`] from any of
//! its callbacks, and each access a watch catches reaches
//! [`GlobalTool::on_watchpoint_hit`] as a [`WatchHit`]. How many watches a
//! thread can hold is [`BackendCapabilities::hardware_watchpoints`]. The
//! watches belong to one thread: a new thread or process starts with none,
//! and a successful `execve` disarms the thread's watches, as Linux does with
//! a debugger's.
//!
//! [`Guest::set_watchpoints`]: crate::Guest::set_watchpoints
//! [`GlobalTool::on_watchpoint_hit`]: crate::GlobalTool::on_watchpoint_hit
//! [`BackendCapabilities::hardware_watchpoints`]: crate::BackendCapabilities::hardware_watchpoints

use serde::Deserialize;
use serde::Serialize;

use crate::Backtrace;
use crate::Pid;

/// Which accesses a watch reports. x86-64 has no read-only watch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WatchKind {
    /// Writes.
    Write,
    /// Reads and writes.
    ReadWrite,
}

/// One watch: the `len` bytes at `addr`, aligned to `len`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WatchSpec {
    /// The first watched byte, a multiple of `len`.
    pub addr: u64,
    /// How many bytes are watched: 1, 2, 4 or 8.
    pub len: u8,
    /// Which accesses are reported.
    pub kind: WatchKind,
    /// How many of this watch's hits on the thread carry the thread's stack,
    /// unwound at the hit ([`WatchHit::backtrace`]): the first `backtraces`
    /// after [`Guest::set_watchpoints`] armed the watch. Later hits carry
    /// none, until the watch is armed again, which starts the count anew.
    /// Unwinding costs far more than the hit itself, so the budget bounds
    /// what a word the thread touches in a loop costs. 0 asks for no stack.
    /// An unwind that fails spends a stack like any other, and its hit
    /// carries none ([`WatchHit::backtrace`] is `None`).
    ///
    /// [`Guest::set_watchpoints`]: crate::Guest::set_watchpoints
    pub backtraces: u32,
}

/// When the hardware reports an access, relative to the access.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HitTiming {
    /// After the accessing instruction has retired: the access has happened,
    /// and the thread's instruction pointer is past the instruction
    /// (x86-64 data breakpoints are traps).
    AfterAccess,
    /// Before the accessing instruction runs, which the backend then runs
    /// by itself (arm64 watchpoints are faults).
    BeforeAccess,
}

/// What the SIGTRAP a hit raised did to the thread's SIGTRAP mask bit and
/// SIGTRAP's action ([`WatchHit::sigtrap`]).
///
/// Linux reports a hit by forcing a SIGTRAP on the thread. If the thread
/// blocks SIGTRAP then, or its process ignores it, the kernel unblocks it
/// for the thread and resets its action to `SIG_DFL` before the backend sees
/// the stop (`force_sig_info_to_task`). Arming is refused in that state
/// ([`WatchError::SigtrapBlocked`], [`WatchError::SigtrapIgnored`]), but the
/// guest can block or ignore SIGTRAP later: a signal handler whose mask
/// blocks every signal does. The backend puts back what it knows was reset,
/// and says what it could not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SigtrapAtHit {
    /// The hit changed nothing: SIGTRAP was neither blocked nor ignored, or
    /// the hit's trap was also another's (a single step's), whose own
    /// SIGTRAP the hit did not add to.
    Unchanged,
    /// SIGTRAP was blocked and its action was the default: the hit unblocked
    /// it, and the backend blocked it again before the thread ran on. The
    /// guest sees no change.
    Reblocked,
    /// The hit reset SIGTRAP's action to `SIG_DFL` (it was ignored, or it was
    /// caught while blocked), and the backend does not put the action back.
    /// The mask bit was put back where it is known to have been blocked.
    ActionReset,
    /// The backend could not tell SIGTRAP's state before the hit, so the
    /// hit may have unblocked it or reset its action, and the backend may
    /// have put back neither. A backend knows the state only when every
    /// change the guest makes to its mask and actions is one it stops at,
    /// and no thread it does not trace shares the thread's signal-action
    /// table. It is also the answer where the hit's trap cannot be told
    /// from another trap of the same instruction, such as a single step the
    /// guest asked for itself.
    Unknown,
}

impl SigtrapAtHit {
    /// Whether the guest may now see a SIGTRAP mask bit or action it did not
    /// set: [`SigtrapAtHit::ActionReset`] or [`SigtrapAtHit::Unknown`]. A
    /// tool that must not change the guest fails closed on it.
    pub fn may_have_changed_guest(self) -> bool {
        matches!(self, SigtrapAtHit::ActionReset | SigtrapAtHit::Unknown)
    }
}

/// An access a watch caught. See [`GlobalTool::on_watchpoint_hit`].
///
/// [`GlobalTool::on_watchpoint_hit`]: crate::GlobalTool::on_watchpoint_hit
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WatchHit {
    /// The thread that made the access.
    pub tid: Pid,
    /// The watch's place in the slice given to [`Guest::set_watchpoints`].
    ///
    /// [`Guest::set_watchpoints`]: crate::Guest::set_watchpoints
    pub slot: u8,
    /// The watch that caught the access.
    pub spec: WatchSpec,
    /// The thread's instruction pointer when the hit was reported: with
    /// [`HitTiming::AfterAccess`], the instruction after the one that made
    /// the access.
    pub ip: u64,
    /// When the hit was reported, relative to the access.
    pub timing: HitTiming,
    /// The thread's stack at the hit, innermost frame first, if the watch's
    /// budget of stacks was not spent ([`WatchSpec::backtraces`]) and the
    /// stack could be unwound.
    pub backtrace: Option<Backtrace>,
    /// What the hit's SIGTRAP did to the thread's SIGTRAP state.
    pub sigtrap: SigtrapAtHit,
}

impl WatchHit {
    /// Describes a hit, for backends that report them.
    pub fn new(
        tid: Pid,
        slot: u8,
        spec: WatchSpec,
        ip: u64,
        timing: HitTiming,
        backtrace: Option<Backtrace>,
        sigtrap: SigtrapAtHit,
    ) -> Self {
        Self {
            tid,
            slot,
            spec,
            ip,
            timing,
            backtrace,
            sigtrap,
        }
    }
}

/// Why [`Guest::set_watchpoints`] did not arm the watches. Every refusal but
/// [`WatchError::Failed`] changes nothing.
///
/// [`Guest::set_watchpoints`]: crate::Guest::set_watchpoints
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WatchError {
    /// The backend has no hardware watchpoints
    /// ([`BackendCapabilities::hardware_watchpoints`] is 0), or cannot
    /// set them at this point.
    ///
    /// [`BackendCapabilities::hardware_watchpoints`]: crate::BackendCapabilities::hardware_watchpoints
    #[error("this backend cannot set hardware watchpoints here")]
    Unsupported,
    /// More watches than the thread has slots.
    #[error("{requested} watches requested, and a thread has {slots} hardware watchpoints")]
    TooMany {
        /// The watches requested.
        requested: usize,
        /// The thread's hardware watchpoints.
        slots: u8,
    },
    /// A length the hardware cannot watch.
    #[error("a hardware watchpoint watches 1, 2, 4 or 8 bytes, not {len}")]
    Length {
        /// The length requested.
        len: u8,
    },
    /// An address that is not a multiple of the watch's length.
    #[error(
        "a hardware watchpoint of {len} bytes needs an address aligned to {len}, not {addr:#x}"
    )]
    Misaligned {
        /// The address requested.
        addr: u64,
        /// The length requested.
        len: u8,
    },
    /// The thread blocks SIGTRAP. Linux reports a hit by forcing a SIGTRAP,
    /// which would unblock it and reset its handler.
    #[error(
        "the thread blocks SIGTRAP, which a hardware watchpoint hit would unblock (and reset its handler)"
    )]
    SigtrapBlocked,
    /// The thread's process ignores SIGTRAP. Linux reports a hit by forcing a
    /// SIGTRAP, which would reset the action to the default.
    #[error(
        "the process ignores SIGTRAP, which a hardware watchpoint hit would reset to the default"
    )]
    SigtrapIgnored,
    /// Writing the thread's debug registers failed after it began. The
    /// backend tried to disarm every watch of the thread; `disarmed` says
    /// whether that took.
    #[error(
        "setting the hardware watchpoints failed ({errno}); the thread's watches were disarmed: {disarmed}"
    )]
    Failed {
        /// The error of the failed write.
        errno: crate::Errno,
        /// Whether the thread was left with no watch armed.
        disarmed: bool,
    },
}
