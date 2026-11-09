/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Hardware watchpoints behind an architecture trait ([`HwWatch`]).
//!
//! A thread's watches ([`WatchSet`]) are armed by `Guest::set_watchpoints`.
//! Linux reports a hit as a SIGTRAP signal-delivery stop. Every SIGTRAP stop
//! of a thread with a watch armed reads which slots fired
//! ([`HwWatch::take_hits`]) before anything consumes the stop, so that no
//! hit is lost and none is read twice:
//!
//! - `handle_sigtrap`, for a stop the guest reached by running. A trap that
//!   is only a hit forced a SIGTRAP of its own, whose reset of a blocked
//!   SIGTRAP's mask bit is repaired (`restore_sigtrap_after_hit`); the trap
//!   is suppressed, and a timer event the stop interrupted is finished as for
//!   any trap without a Tool callback.
//! - the single steps Reverie makes itself, whose own SIGTRAP stop carries
//!   the hit when the stepped instruction made the access: Linux then reports
//!   one trap, with the step's `si_code`, and only the debug status says
//!   that a watch fired too. These are the precise timer's steps
//!   (`drive_timer`), the step of a new image's first instruction after the
//!   post-exec callback, and the GDB server's step over a breakpoint. The
//!   step still counts as a step, and the hit adds nothing to the step's
//!   SIGTRAP.
//!
//! Only a thread with a watch armed reads the status, so a guest without
//! watches pays nothing.

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use reverie::Backtrace;
use reverie::HitTiming;
use reverie::Pid;
use reverie::SigtrapAtHit;
use reverie::WatchError;
use reverie::WatchHit;
use reverie::WatchSpec;
use safeptrace::Error as TraceError;
use safeptrace::Stopped;

/// The most watches any architecture here offers a thread.
pub(crate) const MAX_SLOTS: usize = 4;

/// One architecture's hardware watchpoints. Every method takes a stopped
/// thread and touches only that thread's debug state, from the tracer: the
/// guest runs no code for it.
pub(crate) trait HwWatch {
    /// When the hardware reports an access.
    const HIT_TIMING: HitTiming;

    /// How many watches the thread can hold, at most [`MAX_SLOTS`].
    fn slots(task: &Stopped) -> Result<u8, TraceError>;

    /// Whether the hardware can watch `spec` (length and alignment).
    fn check(spec: &WatchSpec) -> Result<(), WatchError>;

    /// Arms `slot` with `spec`, which [`HwWatch::check`] accepted.
    fn arm(task: &Stopped, slot: u8, spec: &WatchSpec) -> Result<(), TraceError>;

    /// Disarms `slot`.
    fn disarm(task: &Stopped, slot: u8) -> Result<(), TraceError>;

    /// The slots that caught an access since the last call, as a bit mask
    /// (bit `n` for slot `n`), which this clears.
    fn take_hits(task: &Stopped) -> Result<u8, TraceError>;

    /// What `slot` is armed with in the hardware, if it is enabled. The
    /// hardware does not hold [`WatchSpec::backtrace`], which reads `false`.
    fn read(task: &Stopped, slot: u8) -> Result<Option<WatchSpec>, TraceError>;
}

/// This architecture's watchpoints.
#[cfg(target_arch = "x86_64")]
pub(crate) type Arch = x86_64::DebugRegisters;
/// This architecture's watchpoints.
#[cfg(target_arch = "aarch64")]
pub(crate) type Arch = aarch64::Unsupported;

/// The slot operations [`WatchSet::arm`] makes, on one thread. They are
/// [`HwWatch`]'s, apart so that the order of the writes and what a failure
/// leaves can be tested without a thread.
trait SlotOps {
    fn arm(&mut self, slot: u8, spec: &WatchSpec) -> Result<(), TraceError>;
    fn disarm(&mut self, slot: u8) -> Result<(), TraceError>;
    fn take_hits(&mut self) -> Result<u8, TraceError>;
    fn read(&mut self, slot: u8) -> Result<Option<WatchSpec>, TraceError>;
}

/// [`SlotOps`] on a stopped thread, through architecture `A`.
struct OnThread<'a, A>(&'a Stopped, core::marker::PhantomData<A>);

impl<A: HwWatch> SlotOps for OnThread<'_, A> {
    fn arm(&mut self, slot: u8, spec: &WatchSpec) -> Result<(), TraceError> {
        A::arm(self.0, slot, spec)
    }

    fn disarm(&mut self, slot: u8) -> Result<(), TraceError> {
        A::disarm(self.0, slot)
    }

    fn take_hits(&mut self) -> Result<u8, TraceError> {
        A::take_hits(self.0)
    }

    fn read(&mut self, slot: u8) -> Result<Option<WatchSpec>, TraceError> {
        A::read(self.0, slot)
    }
}

/// A thread's armed watches, by slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WatchSet {
    slots: [Option<WatchSpec>; MAX_SLOTS],
    /// How many more hits of each slot's watch carry the thread's stack
    /// ([`WatchSpec::backtraces`]); set when the watch is armed.
    stacks_left: [u32; MAX_SLOTS],
}

impl WatchSet {
    /// Whether any watch is armed.
    pub(crate) fn is_armed(&self) -> bool {
        self.slots.iter().any(Option::is_some)
    }

    /// The set with `specs` in slots 0, 1, and so on, each with its whole
    /// budget of stacks.
    fn of(specs: &[WatchSpec]) -> Self {
        let mut set = Self::default();
        for (slot, spec) in specs.iter().enumerate().take(MAX_SLOTS) {
            set.place(slot, Some(*spec));
        }
        set
    }

    /// Puts `spec` in `slot`, with its whole budget of stacks.
    fn place(&mut self, slot: usize, spec: Option<WatchSpec>) {
        self.slots[slot] = spec;
        self.stacks_left[slot] = spec.map_or(0, |spec| spec.backtraces);
    }

    /// Spends one stack of the budget of each slot in `mask` that has one
    /// left, and returns those slots as a mask: their hits carry the stack.
    fn spend_stacks(&mut self, mask: u8) -> u8 {
        let mut spent = 0;
        for slot in 0..MAX_SLOTS {
            if mask & (1 << slot) != 0 && self.slots[slot].is_some() && self.stacks_left[slot] > 0 {
                self.stacks_left[slot] -= 1;
                spent |= 1 << slot;
            }
        }
        spent
    }

    /// Checks `specs` against what `task`'s hardware can watch, without
    /// changing anything.
    pub(crate) fn check<A: HwWatch>(task: &Stopped, specs: &[WatchSpec]) -> Result<(), WatchError> {
        let slots = A::slots(task).map_err(|error| WatchError::Failed {
            errno: errno_of(&error),
            disarmed: false,
        })?;
        if slots == 0 {
            return Err(WatchError::Unsupported);
        }
        if specs.len() > usize::from(slots) {
            return Err(WatchError::TooMany {
                requested: specs.len(),
                slots,
            });
        }
        specs.iter().try_for_each(A::check)
    }

    /// Arms `task` with `specs`, which [`WatchSet::check`] accepted,
    /// disarming its other slots. `self` is the set armed before. Returns the
    /// set armed after, which is `specs` on success, and the result.
    ///
    /// A failed write disarms every slot it can, trying each even when one
    /// fails, and says whether all took. Where some did not, the set returned
    /// is read back from the hardware, so that the hits of every slot that
    /// may still be armed are read and reported.
    pub(crate) fn arm<A: HwWatch>(
        &self,
        task: &Stopped,
        specs: &[WatchSpec],
    ) -> (Self, Result<(), WatchError>) {
        let slots = match A::slots(task) {
            Ok(slots) => slots,
            Err(error) => {
                // Nothing was written.
                return (
                    *self,
                    Err(WatchError::Failed {
                        errno: errno_of(&error),
                        disarmed: !self.is_armed(),
                    }),
                );
            }
        };
        self.arm_slots(
            &mut OnThread::<A>(task, core::marker::PhantomData),
            slots,
            specs,
        )
    }

    /// [`WatchSet::arm`] through `ops`, on a thread with `slots` slots.
    fn arm_slots(
        &self,
        ops: &mut impl SlotOps,
        slots: u8,
        specs: &[WatchSpec],
    ) -> (Self, Result<(), WatchError>) {
        // Every slot is disarmed first, each tried, so that no old watch
        // stays armed beside the new ones.
        let mut error = disarm_all(ops, slots).err();
        if error.is_none() {
            error = specs
                .iter()
                .zip(0..)
                .try_for_each(|(spec, slot)| ops.arm(slot, spec))
                .err();
        }
        let Some(error) = error else {
            // A hit before this arming is not one of these watches'.
            let _ = ops.take_hits();
            return (Self::of(specs), Ok(()));
        };
        let disarmed = disarm_all(ops, slots).is_ok();
        let set = if disarmed {
            Self::default()
        } else {
            self.read_back(ops, slots, specs)
        };
        (
            set,
            Err(WatchError::Failed {
                errno: errno_of(&error),
                disarmed,
            }),
        )
    }

    /// The set the hardware holds after a failed arming of `specs` over
    /// `self`, read slot by slot. A slot armed with what `specs` or `self`
    /// gave it keeps that spec (and its `backtraces`, whose budget starts
    /// anew); a slot that cannot be read is taken to hold what either gave
    /// it, so that its hits, if any, are still reported.
    fn read_back(&self, ops: &mut impl SlotOps, slots: u8, specs: &[WatchSpec]) -> Self {
        let mut set = Self::default();
        for slot in 0..slots.min(MAX_SLOTS as u8) {
            let new = specs.get(usize::from(slot)).copied();
            let old = self.slots[usize::from(slot)];
            let same = |spec: &WatchSpec, armed: &WatchSpec| {
                (spec.addr, spec.len, spec.kind) == (armed.addr, armed.len, armed.kind)
            };
            let entry = match ops.read(slot) {
                Ok(Some(armed)) => Some(
                    [new, old]
                        .into_iter()
                        .flatten()
                        .find(|spec| same(spec, &armed))
                        .unwrap_or(armed),
                ),
                Ok(None) => None,
                Err(_) => new.or(old),
            };
            set.place(usize::from(slot), entry);
        }
        set
    }

    /// The hits `mask` ([`HwWatch::take_hits`]) reports for these watches,
    /// on thread `tid` stopped at `ip`, in slot order, each with `sigtrap`.
    /// A bit for a slot with no watch is ignored. Each watch with a stack
    /// left in its budget ([`WatchSpec::backtraces`]) spends one and gets the
    /// thread's stack, unwound once for the stop; once no watch has one
    /// left, the stop unwinds nothing.
    pub(crate) fn hits<A: HwWatch>(
        &mut self,
        tid: Pid,
        mask: u8,
        ip: u64,
        sigtrap: SigtrapAtHit,
    ) -> Vec<WatchHit> {
        let stacks = self.spend_stacks(mask);
        let backtrace: Option<Backtrace> = if stacks != 0 { unwind(tid) } else { None };
        self.slots
            .iter()
            .zip(0u8..)
            .filter(|&(_, slot)| mask & (1 << slot) != 0)
            .filter_map(|(spec, slot)| Some((slot, (*spec)?)))
            .map(|(slot, spec)| {
                let stack = (stacks & (1 << slot) != 0)
                    .then(|| backtrace.clone())
                    .flatten();
                WatchHit::new(tid, slot, spec, ip, A::HIT_TIMING, stack, sigtrap)
            })
            .collect()
    }
}

/// Disarms slots `0..slots` through `ops`, trying every one, and returns the
/// first failure.
fn disarm_all(ops: &mut impl SlotOps, slots: u8) -> Result<(), TraceError> {
    let mut result = Ok(());
    for slot in 0..slots {
        if let Err(error) = ops.disarm(slot)
            && result.is_ok()
        {
            result = Err(error);
        }
    }
    result
}

/// The errno of a failed debug-register access; a thread that died reads
/// as ESRCH.
fn errno_of(error: &TraceError) -> reverie::Errno {
    match error {
        TraceError::Errno(errno) => *errno,
        TraceError::Died(_) => reverie::Errno::ESRCH,
    }
}

/// The stack of `tid`, which must be stopped, innermost frame first, unwound
/// remotely with libunwind's ptrace accessors.
pub(crate) fn unwind(tid: Pid) -> Option<Backtrace> {
    use reverie::Frame;
    use unwind::Accessors;
    use unwind::AddressSpace;
    use unwind::Byteorder;
    use unwind::Cursor;
    use unwind::PTraceState;
    use unwind::RegNum;

    let mut frames = Vec::new();

    let space = AddressSpace::new(Accessors::ptrace(), Byteorder::DEFAULT).ok()?;
    let state = PTraceState::new(tid.as_raw() as u32).ok()?;
    let mut cursor = Cursor::remote(&space, &state).ok()?;

    loop {
        let ip = cursor.register(RegNum::IP).ok()?;
        let is_signal = cursor.is_signal_frame().ok()?;

        frames.push(Frame { ip, is_signal });

        if !cursor.step().ok()? {
            break;
        }
    }

    // TODO: Take a snapshot of `/proc/self/maps` so the backtrace can be
    // processed offline?

    Some(Backtrace::new(tid, frames))
}

#[cfg(test)]
mod tests {
    use reverie::Errno;
    use reverie::WatchKind;

    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Op {
        Arm(u8),
        Disarm(u8),
        TakeHits,
        Read(u8),
    }

    /// Four slots in memory, with failures to inject.
    #[derive(Default)]
    struct Fake {
        armed: [Option<WatchSpec>; MAX_SLOTS],
        stale_hits: u8,
        fail_arm: Option<u8>,
        fail_disarm: Option<u8>,
        fail_read: Option<u8>,
        log: Vec<Op>,
    }

    impl SlotOps for Fake {
        fn arm(&mut self, slot: u8, spec: &WatchSpec) -> Result<(), TraceError> {
            self.log.push(Op::Arm(slot));
            if self.fail_arm == Some(slot) {
                return Err(TraceError::Errno(Errno::EINVAL));
            }
            self.armed[usize::from(slot)] = Some(WatchSpec {
                backtraces: 0,
                ..*spec
            });
            Ok(())
        }

        fn disarm(&mut self, slot: u8) -> Result<(), TraceError> {
            self.log.push(Op::Disarm(slot));
            if self.fail_disarm == Some(slot) {
                return Err(TraceError::Errno(Errno::EIO));
            }
            self.armed[usize::from(slot)] = None;
            Ok(())
        }

        fn take_hits(&mut self) -> Result<u8, TraceError> {
            self.log.push(Op::TakeHits);
            Ok(std::mem::take(&mut self.stale_hits))
        }

        fn read(&mut self, slot: u8) -> Result<Option<WatchSpec>, TraceError> {
            self.log.push(Op::Read(slot));
            if self.fail_read == Some(slot) {
                return Err(TraceError::Errno(Errno::EIO));
            }
            Ok(self.armed[usize::from(slot)])
        }
    }

    fn spec(addr: u64, backtraces: u32) -> WatchSpec {
        WatchSpec {
            addr,
            len: 8,
            kind: WatchKind::Write,
            backtraces,
        }
    }

    const ALL_DISARMED: [Op; 4] = [Op::Disarm(0), Op::Disarm(1), Op::Disarm(2), Op::Disarm(3)];

    #[test]
    fn arming_disarms_every_slot_then_arms_and_drops_earlier_hits() {
        let old = WatchSet::of(&[spec(0x3000, 0); 4]);
        let mut fake = Fake {
            armed: old.slots,
            stale_hits: 0b1111,
            ..Fake::default()
        };
        let specs = [spec(0x1000, 1), spec(0x2000, 0)];
        let (set, result) = old.arm_slots(&mut fake, 4, &specs);
        assert_eq!(result, Ok(()));
        assert_eq!(set, WatchSet::of(&specs));
        let mut expected = ALL_DISARMED.to_vec();
        expected.extend([Op::Arm(0), Op::Arm(1), Op::TakeHits]);
        assert_eq!(fake.log, expected);
        assert_eq!(
            fake.stale_hits, 0,
            "the hits from before the arming were cleared"
        );
        assert_eq!(fake.armed[2..], [None, None]);
    }

    #[test]
    fn a_failed_arm_disarms_every_slot() {
        let mut fake = Fake {
            fail_arm: Some(1),
            ..Fake::default()
        };
        let specs = [spec(0x1000, 0), spec(0x2000, 0), spec(0x3000, 0)];
        let (set, result) = WatchSet::default().arm_slots(&mut fake, 4, &specs);
        assert_eq!(
            result,
            Err(WatchError::Failed {
                errno: Errno::EINVAL,
                disarmed: true
            })
        );
        assert_eq!(set, WatchSet::default());
        let mut expected = ALL_DISARMED.to_vec();
        expected.extend([Op::Arm(0), Op::Arm(1)]);
        expected.extend(ALL_DISARMED);
        assert_eq!(fake.log, expected);
        assert_eq!(fake.armed, [None; MAX_SLOTS]);
    }

    #[test]
    fn a_failed_disarm_still_tries_every_other_slot() {
        let old = WatchSet::of(&[spec(0x5000, 0); 4]);
        let mut fake = Fake {
            armed: old.slots,
            fail_disarm: Some(1),
            ..Fake::default()
        };
        let (set, result) = old.arm_slots(&mut fake, 4, &[spec(0x1000, 0)]);
        assert_eq!(
            result,
            Err(WatchError::Failed {
                errno: Errno::EIO,
                disarmed: false
            })
        );
        // Nothing is armed after a failed disarm; the rollback tries every
        // slot again, and the set is read back.
        let mut expected = ALL_DISARMED.to_vec();
        expected.extend(ALL_DISARMED);
        expected.extend([Op::Read(0), Op::Read(1), Op::Read(2), Op::Read(3)]);
        assert_eq!(fake.log, expected);
        assert_eq!(fake.armed, [None, Some(spec(0x5000, 0)), None, None]);
        assert_eq!(set.slots, fake.armed);
    }

    #[test]
    fn a_rollback_that_leaves_slots_armed_reads_the_set_back() {
        // Slot 2 holds an old watch that cannot be disarmed, and slot 3
        // cannot be read.
        let old = WatchSet::of(&[
            spec(0x7000, 0),
            spec(0x8000, 0),
            spec(0x9000, 1),
            spec(0xa000, 1),
        ]);
        let mut fake = Fake {
            armed: old.slots,
            fail_arm: Some(1),
            fail_disarm: Some(2),
            fail_read: Some(3),
            ..Fake::default()
        };
        let specs = [spec(0x1000, 1), spec(0x2000, 0)];
        let (set, result) = old.arm_slots(&mut fake, 4, &specs);
        assert_eq!(
            result,
            Err(WatchError::Failed {
                errno: Errno::EIO,
                disarmed: false
            })
        );
        assert_eq!(
            set.slots,
            [
                None,
                None,
                // Read back, and matched to the old watch, whose backtrace
                // request the hardware does not hold.
                Some(spec(0x9000, 1)),
                // Unreadable: the old watch, which may still be armed.
                Some(spec(0xa000, 1)),
            ]
        );
        assert!(set.is_armed());
    }

    #[test]
    fn a_slot_read_back_with_the_new_watch_keeps_its_backtrace_request() {
        let mut fake = Fake {
            fail_disarm: Some(0),
            ..Fake::default()
        };
        // A failed first pass arms nothing, so make slot 0 hold the new
        // watch as a partial write would have left it.
        fake.armed[0] = Some(spec(0x1000, 0));
        let (set, result) = WatchSet::default().arm_slots(&mut fake, 4, &[spec(0x1000, 1)]);
        assert!(matches!(
            result,
            Err(WatchError::Failed {
                disarmed: false,
                ..
            })
        ));
        assert_eq!(set.slots[0], Some(spec(0x1000, 1)));
        assert_eq!(set.slots[1..], [None, None, None]);
    }

    #[test]
    fn each_watch_spends_its_own_budget_of_stacks_until_armed_again() {
        let mut set = WatchSet::of(&[spec(0x1000, 2), spec(0x2000, 0), spec(0x3000, 1)]);
        // Slot 1 asks for none; slot 3 holds no watch.
        assert_eq!(set.spend_stacks(0b1111), 0b101);
        assert_eq!(set.spend_stacks(0b0111), 0b001);
        assert_eq!(set.spend_stacks(0b0111), 0);
        assert_eq!(set.spend_stacks(0b0001), 0);
        // Arming again starts each budget anew.
        let mut set = WatchSet::of(&set.slots.iter().flatten().copied().collect::<Vec<_>>());
        assert_eq!(set.spend_stacks(0b0001), 0b001);
        // So does a read-back after a failed arming.
        let mut fake = Fake {
            armed: set.slots,
            fail_arm: Some(0),
            fail_disarm: Some(2),
            ..Fake::default()
        };
        let (mut back, _) = set.arm_slots(&mut fake, 4, &[spec(0x5000, 0)]);
        assert_eq!(back.slots[2], Some(spec(0x3000, 1)));
        assert_eq!(back.spend_stacks(0b100), 0b100);
        assert_eq!(back.spend_stacks(0b100), 0);
    }

    #[test]
    fn hits_carry_their_slot_spec_and_sigtrap_state() {
        let specs = [spec(0x1000, 0), spec(0x2000, 0)];
        let mut set = WatchSet::of(&specs);
        let tid = Pid::from_raw(42);
        // Bit 3 is a slot with no watch.
        let hits = set.hits::<Arch>(tid, 0b1010, 0x401000, SigtrapAtHit::Reblocked);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].slot, 1);
        assert_eq!(hits[0].spec, specs[1]);
        assert_eq!(hits[0].ip, 0x401000);
        assert_eq!(hits[0].sigtrap, SigtrapAtHit::Reblocked);
        assert_eq!(hits[0].backtrace, None);
    }
}
