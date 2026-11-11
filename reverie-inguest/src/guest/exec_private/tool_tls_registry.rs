//! Per-thread Tool TLS slot registry: who owns which private TCB slot.
//!
//! One packed `AtomicU64` per slot carries `{state, tid}` together, so a
//! lookup can never mix one occupancy's tid with another's state. Slot 0 is
//! always the leader: it is registered when the authenticated control is
//! published, in every exec-private configuration and on every ISA, so a
//! leader is never refused for lack of a registry.
//!
//! Slots are handed out in birth order and never reused. A slot whose
//! thread exited stays `Retiring` forever; reclaiming by kernel-teardown
//! timing would let host scheduling change guest-visible clone results.
//! The only way back to `Free` is releasing a claim whose physical clone
//! never happened, decided parent-side before any birth.
//!
//! This module is pure atomics: it makes no syscall, reads no FS and grants
//! no admission by itself. Callers pair a `Ready` entry with their own
//! thread-pointer check before admitting a callback.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

/// Fixed private Tool thread cap, leader included. The cap is a named
/// constant, never derived from a reservation size, so the point where a
/// birth is refused cannot move when the Tool's TLS template grows.
pub const MAX_PRIVATE_TOOL_THREADS: usize = 64;

const STATE_SHIFT: u32 = 32;
const FREE: u64 = 0;
// Stage B state/API surface: in Stage A only leader registration has a
// production caller; the rest is exercised by this module's tests.
#[allow(dead_code)]
const BUILDING: u64 = 1;
const READY: u64 = 2;
#[allow(dead_code)]
const RETIRING: u64 = 3;

fn pack(state: u64, tid: i32) -> u64 {
    (state << STATE_SHIFT) | u64::from(tid as u32)
}

#[allow(dead_code)]
fn unpack(word: u64) -> (u64, i32) {
    (word >> STATE_SHIFT, (word & 0xffff_ffff) as u32 as i32)
}

/// Why leader registration was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterLeaderError {
    /// The supplied tid is not a positive kernel tid.
    InvalidTid,
    /// Slot 0 already holds an entry; the leader registers exactly once.
    AlreadyRegistered,
}

/// The slot table. Constructed as one process static; tests build fresh
/// instances so no test observes another's registrations.
pub struct ToolTlsRegistry {
    slots: [AtomicU64; MAX_PRIVATE_TOOL_THREADS],
}

impl Default for ToolTlsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Stage B birth/exit API: only register_leader has a production caller in
// Stage A; the remaining transitions are exercised by unit tests until
// Stage B wires the HostRuntime hooks.
#[allow(dead_code)]
impl ToolTlsRegistry {
    /// An empty registry: every slot `Free` with tid 0.
    pub const fn new() -> Self {
        Self {
            slots: [const { AtomicU64::new(0) }; MAX_PRIVATE_TOOL_THREADS],
        }
    }

    /// The decoded `(state, tid)` snapshot of one slot, for diagnostics.
    /// State is one of the module's internal encodings; prefer the typed
    /// queries below for decisions.
    pub fn slot(&self, index: usize) -> Option<(u64, i32)> {
        self.slots
            .get(index)
            .map(|slot| unpack(slot.load(Ordering::Acquire)))
    }

    /// Register the leader in slot 0 as `Ready`. Called exactly once, when
    /// the authenticated private control is published.
    pub fn register_leader(&self, tid: i32) -> Result<(), RegisterLeaderError> {
        if tid <= 0 {
            return Err(RegisterLeaderError::InvalidTid);
        }
        self.slots[0]
            .compare_exchange(
                pack(FREE, 0),
                pack(READY, tid),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| RegisterLeaderError::AlreadyRegistered)
    }

    /// The registered leader tid, if slot 0 is `Ready`.
    pub fn leader(&self) -> Option<i32> {
        let (state, tid) = unpack(self.slots[0].load(Ordering::Acquire));
        (state == READY).then_some(tid)
    }

    /// Claim the lowest free non-leader slot for a birth that has not
    /// happened yet. Parent-side and deterministic: slots go out in birth
    /// order and there is no racing atomic hand-out to order. `None` is the
    /// exhaustion point where a caller refuses the birth before cloning.
    pub fn claim(&self) -> Option<usize> {
        for (index, slot) in self.slots.iter().enumerate().skip(1) {
            if slot
                .compare_exchange(
                    pack(FREE, 0),
                    pack(BUILDING, 0),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Some(index);
            }
        }
        None
    }

    /// Record the newborn kernel tid on a claimed slot once the creating
    /// clone has produced it. Fails unless the slot is `Building` unbound.
    pub fn bind_tid(&self, index: usize, tid: i32) -> bool {
        if tid <= 0 {
            return false;
        }
        self.transition(index, pack(BUILDING, 0), pack(BUILDING, tid))
    }

    /// Publish a bound slot as callback-ready. This publication, after the
    /// thread's own TCB and FS are installed, is the admission point.
    pub fn mark_ready(&self, index: usize, tid: i32) -> bool {
        self.transition(index, pack(BUILDING, tid), pack(READY, tid))
    }

    /// Mark a live slot retiring at thread exit. A `Retiring` slot is never
    /// admitted again and is never handed out again.
    pub fn mark_retiring(&self, index: usize, tid: i32) -> bool {
        self.transition(index, pack(READY, tid), pack(RETIRING, tid))
    }

    /// Release a claim whose physical clone failed before any thread
    /// existed. Only an *unbound* `Building` slot (tid still 0) can
    /// return to `Free`: a bound tid means the creating clone already
    /// succeeded and a thread may be running on that slot's TCB, so a
    /// bound slot can never be released or reused.
    pub fn release_claim(&self, index: usize) -> bool {
        self.transition(index, pack(BUILDING, 0), pack(FREE, 0))
    }

    /// The slot holding `tid` as callback-ready, if any. A tid recycled by
    /// the kernel after its slot retired never resolves: the stale entry
    /// stays `Retiring`, and a new birth always takes a later slot.
    pub fn lookup_ready(&self, tid: i32) -> Option<usize> {
        if tid <= 0 {
            return None;
        }
        self.slots
            .iter()
            .position(|slot| unpack(slot.load(Ordering::Acquire)) == (READY, tid))
    }

    fn transition(&self, index: usize, from: u64, to: u64) -> bool {
        let Some(slot) = self.slots.get(index) else {
            return false;
        };
        slot.compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

/// The one process registry. Slot 0 is registered by control publication;
/// every exec successor image starts from a fresh process static.
/// Crate-private until Stage C defines the HostRuntime hooks: no other
/// crate may fill slot 0 (or any slot) first.
pub(crate) static TOOL_TLS_REGISTRY: ToolTlsRegistry = ToolTlsRegistry::new();

/// Register the leader in the process registry. See
/// [`ToolTlsRegistry::register_leader`].
pub(crate) fn register_leader(tid: i32) -> Result<(), RegisterLeaderError> {
    TOOL_TLS_REGISTRY.register_leader(tid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_cap_is_pinned() {
        // The cap decides where a guest clone starts receiving EAGAIN;
        // it is a fixed ruling, not derived from any reservation size.
        assert_eq!(MAX_PRIVATE_TOOL_THREADS, 64);
    }

    #[test]
    fn leader_registers_once_in_slot_zero() {
        let registry = ToolTlsRegistry::new();
        assert_eq!(registry.leader(), None);
        assert_eq!(
            registry.register_leader(0),
            Err(RegisterLeaderError::InvalidTid)
        );
        registry.register_leader(4242).unwrap();
        assert_eq!(registry.leader(), Some(4242));
        assert_eq!(registry.lookup_ready(4242), Some(0));
        assert_eq!(
            registry.register_leader(4242),
            Err(RegisterLeaderError::AlreadyRegistered)
        );
        assert_eq!(
            registry.register_leader(7),
            Err(RegisterLeaderError::AlreadyRegistered)
        );
        // The leader slot is never handed out as a birth claim.
        assert_eq!(registry.claim(), Some(1));
    }

    #[test]
    fn claim_bind_ready_retire_in_birth_order() {
        let registry = ToolTlsRegistry::new();
        registry.register_leader(100).unwrap();
        let first = registry.claim().unwrap();
        let second = registry.claim().unwrap();
        assert_eq!((first, second), (1, 2));
        // An unbound building slot admits nobody.
        assert_eq!(registry.lookup_ready(0), None);
        assert!(!registry.mark_ready(first, 101));
        assert!(registry.bind_tid(first, 101));
        assert!(!registry.bind_tid(first, 102));
        assert_eq!(registry.lookup_ready(101), None);
        assert!(registry.mark_ready(first, 101));
        assert_eq!(registry.lookup_ready(101), Some(first));
        assert!(registry.mark_retiring(first, 101));
        assert_eq!(registry.lookup_ready(101), None);
        // A recycled kernel tid never resolves to the retired slot, and
        // the retired slot is never handed out again.
        assert!(!registry.mark_ready(first, 101));
        assert!(!registry.release_claim(first));
        assert_eq!(registry.claim(), Some(3));
    }

    #[test]
    fn failed_clone_claim_is_released_before_any_birth() {
        let registry = ToolTlsRegistry::new();
        let slot = registry.claim().unwrap();
        assert!(registry.release_claim(slot));
        // The same lowest slot is offered to the next birth attempt only
        // because no thread ever occupied it.
        assert_eq!(registry.claim(), Some(slot));
        assert!(registry.bind_tid(slot, 55));
        // A bound tid means the clone succeeded: the slot held a born
        // thread and must never return to Free or be handed out again.
        assert!(!registry.release_claim(slot));
        assert_eq!(registry.lookup_ready(55), None);
        let next = registry.claim().unwrap();
        assert_ne!(next, slot);
    }

    #[test]
    fn exhaustion_is_at_the_fixed_cap() {
        let registry = ToolTlsRegistry::new();
        registry.register_leader(1).unwrap();
        for expected in 1..MAX_PRIVATE_TOOL_THREADS {
            assert_eq!(registry.claim(), Some(expected));
        }
        assert_eq!(registry.claim(), None);
    }

    #[test]
    fn out_of_range_and_mismatched_tid_never_transition() {
        let registry = ToolTlsRegistry::new();
        assert!(!registry.bind_tid(MAX_PRIVATE_TOOL_THREADS, 9));
        assert!(!registry.mark_ready(MAX_PRIVATE_TOOL_THREADS, 9));
        assert!(!registry.mark_retiring(0, 9));
        assert!(!registry.release_claim(MAX_PRIVATE_TOOL_THREADS));
        let slot = registry.claim().unwrap();
        assert!(registry.bind_tid(slot, 9));
        assert!(registry.mark_ready(slot, 9));
        assert!(!registry.mark_retiring(slot, 10));
        assert_eq!(registry.lookup_ready(9), Some(slot));
    }
}
