//! Source-bound x86_64 musl 1.2.5 geometry; no pointers dereferenced here.
//! Inputs are untrusted numbers. Success is geometry only, never mapping authority.

/// Exact retained x86-64 musl 1.2.5 pthread structure size in bytes.
pub const PTHREAD_BYTES: usize = 200;
/// Minimum x86-64 TLS/TCB backing alignment in bytes.
pub const MIN_TLS_ALIGN: usize = 8;
/// Single main TLS module DTV size: count plus one entry, in bytes.
pub const DTV_BYTES: usize = 16;

/// Numeric geometry refusal; never a fallback or mapping authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Checked address or size arithmetic overflowed.
    Overflow,
    /// Template or backing alignment is invalid.
    Alignment,
    /// A required region, backing, mapped load or TLS memory extent is empty.
    Empty,
    /// A required extent is outside its supplied numeric container.
    Outside,
    /// TLS file geometry or below-TP congruence is invalid.
    Image,
    /// Supplied or calculated live extents overlap.
    Overlap,
}

/// Numeric half-open interval, with no mapping or ownership authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extent {
    /// Inclusive first numeric byte address.
    pub start: usize,
    /// Byte length; containment and end arithmetic remain checked.
    pub bytes: usize,
}
impl Extent {
    /// Checked exclusive numeric end address.
    pub fn end(self) -> Result<usize, Error> {
        self.start.checked_add(self.bytes).ok_or(Error::Overflow)
    }
    /// Checked containment; preserves the existing empty-at-end semantics.
    pub fn contains(self, other: Self) -> Result<bool, Error> {
        Ok(other.start >= self.start && other.end()? <= self.end()?)
    }
    /// Checked half-open overlap predicate.
    pub fn overlaps(self, other: Self) -> Result<bool, Error> {
        Ok(self.start < other.end()? && other.start < self.end()?)
    }
}

/// A single final PT_TLS inside actual sealed, readable PT_LOAD bytes.
/// This numeric descriptor does not authenticate an ELF or its ownership.
#[derive(Clone, Copy, Debug)]
pub struct Template {
    /// Mapped address of the actual TLS file template, supplied numerically.
    pub image: usize,
    /// Initialized TLS template byte count.
    pub file_bytes: usize,
    /// Total TLS template memory byte count, including zero-fill.
    pub memory_bytes: usize,
    /// Actual PT_TLS alignment, required to be a nonzero power of two.
    pub alignment: usize,
}

/// Checked numeric placement produced only by [`plan`].
///
/// This value does not prove authentic image bytes, physical reservation,
/// zeroed backing, private TLS initialization, admission or runtime readiness.
/// Read-only projections cannot create or modify a plan.
#[derive(Clone, Copy, Debug)]
pub struct Plan {
    template: Template,
    backing: Extent,
    module_bytes: usize,
    tls_align: usize,
    total_bytes: usize,
    tls: Extent,
    pthread: Extent,
    dtv: Extent,
}

impl Plan {
    /// Original caller-supplied numeric TLS template.
    pub fn template(self) -> Template {
        self.template
    }
    /// Original dedicated numeric backing extent.
    pub fn backing(self) -> Extent {
        self.backing
    }
    /// Calculated below-TP module byte count including congruence padding.
    pub fn module_bytes(self) -> usize {
        self.module_bytes
    }
    /// Calculated TLS alignment, at least the minimum TCB alignment.
    pub fn tls_align(self) -> usize {
        self.tls_align
    }
    /// Calculated complete DTV/TLS/TCB allocation byte count.
    pub fn total_bytes(self) -> usize {
        self.total_bytes
    }
    /// Calculated TLS module interval.
    pub fn tls(self) -> Extent {
        self.tls
    }
    /// Calculated pthread/TCB interval whose start is the private TP.
    pub fn pthread(self) -> Extent {
        self.pthread
    }
    /// Calculated single-module DTV interval.
    pub fn dtv(self) -> Extent {
        self.dtv
    }
}

fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Overflow)
}
fn align_up(value: usize, alignment: usize) -> Result<usize, Error> {
    Ok(add(value, alignment - 1)? & !(alignment - 1))
}

/// `backing` must be a dedicated interior, excluding guards, images, control,
/// stacks and all other occupied extents. Real ownership/zeroing is not proved.
/// `mapped_load` is the complete mapped PT_LOAD memory extent. `file_backed_load`
/// is its initialized file-byte extent at the corresponding mapped addresses;
/// neither argument is a substitute for authentic ELF/file-offset authority.
/// Empty file-backed extents permit BSS-only TLS at that interval anchor.
/// Missing/multiple PT_TLS is outside this first bounded cohort, NOT accepted.
pub fn plan(
    region: Extent,
    backing: Extent,
    mapped_load: Extent,
    file_backed_load: Extent,
    t: Template,
) -> Result<Plan, Error> {
    if region.bytes == 0 || backing.bytes == 0 || mapped_load.bytes == 0 || t.memory_bytes == 0 {
        return Err(Error::Empty);
    }
    if t.alignment == 0
        || !t.alignment.is_power_of_two()
        || !backing.start.is_multiple_of(MIN_TLS_ALIGN)
    {
        return Err(Error::Alignment);
    }
    if !region.contains(backing)?
        || !region.contains(mapped_load)?
        || !mapped_load.contains(file_backed_load)?
    {
        return Err(Error::Outside);
    }
    if backing.overlaps(mapped_load)? {
        return Err(Error::Overlap);
    }
    if t.file_bytes > t.memory_bytes
        || !file_backed_load.contains(Extent {
            start: t.image,
            bytes: t.file_bytes,
        })?
    {
        return Err(Error::Image);
    }
    // Checked equivalent of musl's below-TP congruence, not unchecked wrapping
    // addition of memsz + image. Only the modulo power-of-two residues wrap.
    let mask = t.alignment - 1;
    let residue = (t.memory_bytes & mask).wrapping_add(t.image & mask) & mask;
    let padding = 0usize.wrapping_sub(residue) & mask;
    let module_bytes = add(t.memory_bytes, padding)?;
    let tls_align = t.alignment.max(MIN_TLS_ALIGN);
    let total_bytes = align_up(
        add(
            add(DTV_BYTES, PTHREAD_BYTES)?,
            add(module_bytes, tls_align)?,
        )?,
        MIN_TLS_ALIGN,
    )?;
    let used = Extent {
        start: backing.start,
        bytes: total_bytes,
    };
    if !backing.contains(used)? {
        return Err(Error::Outside);
    }
    // Exact below-TP placement performed by retained __copy_tls.
    let unaligned_tp = add(backing.start, total_bytes - PTHREAD_BYTES)?;
    let tp = unaligned_tp & !(tls_align - 1);
    let tls_start = tp.checked_sub(module_bytes).ok_or(Error::Overflow)?;
    let tls = Extent {
        start: tls_start,
        bytes: module_bytes,
    };
    let pthread = Extent {
        start: tp,
        bytes: PTHREAD_BYTES,
    };
    let dtv = Extent {
        start: backing.start,
        bytes: DTV_BYTES,
    };
    if !used.contains(tls)?
        || !used.contains(pthread)?
        || !used.contains(dtv)?
        || tls.overlaps(dtv)?
        || tls.overlaps(pthread)?
        || pthread.overlaps(dtv)?
    {
        return Err(Error::Overlap);
    }
    if (tls.start & mask) != (t.image & mask) {
        return Err(Error::Image);
    }
    Ok(Plan {
        template: t,
        backing,
        module_bytes,
        tls_align,
        total_bytes,
        tls,
        pthread,
        dtv,
    })
}

/// Exact musl 1.2.5 `detach_state` values (`src/internal/pthread_impl.h`).
/// A freshly built thread head is joinable unless its creator requested a
/// detached thread, exactly as `__pthread_create` selects from the attribute.
pub const DT_EXITED: u32 = 0;
/// Transient exiting state; never written into a fresh head.
pub const DT_EXITING: u32 = 1;
/// Fresh joinable thread head state.
pub const DT_JOINABLE: u32 = 2;
/// Fresh detached thread head state.
pub const DT_DETACHED: u32 = 3;

/// Per-thread `tsd` array bytes: musl `PTHREAD_KEYS_MAX` (128) pointers.
/// A fresh head must never carry a null `tsd`: musl `pthread_setspecific`
/// writes through it, and a shared array would alias another thread's keys.
pub const TSD_BYTES: usize = 128 * size_of::<usize>();

/// Byte offset of `robust_list` inside the 200-byte pthread head, so the
/// self-referential `robust_list.head` word is `tp + ROBUST_LIST_OFFSET`.
pub const ROBUST_LIST_OFFSET: usize = 136;

/// Process-wide head values a fresh thread copies from the leader, exactly as
/// musl `__pthread_create` copies `canary`/`sysinfo` from the creating thread
/// and points `locale` at `&__libc.global_locale`. Numeric inputs only.
#[derive(Clone, Copy, Debug)]
pub struct LeaderHead {
    /// The leader's stack canary word.
    pub canary: usize,
    /// The leader's vDSO `sysinfo` word.
    pub sysinfo: usize,
    /// Numeric address of the retained libc global locale object.
    pub locale: usize,
}

/// Slot-owned head inputs for one fresh thread, mirroring the fields musl
/// `__pthread_create` fills from its stack mapping and attributes before the
/// clone. `stack` must name the thread's lasting stack extent, never a
/// transient birth stack that is unmapped while the thread may still run.
/// `tsd` must name a zeroed per-slot extent of at least [`TSD_BYTES`].
/// Numeric inputs only; supplying them proves no mapping or ownership.
#[derive(Clone, Copy, Debug)]
pub struct ThreadHead {
    /// Base of the mapping the slot owns for this thread, if any.
    pub map_base: usize,
    /// Byte length of that mapping.
    pub map_size: usize,
    /// Lasting stack pointer recorded for the thread.
    pub stack: usize,
    /// Usable stack byte length below `stack`.
    pub stack_size: usize,
    /// Guard byte length below the usable stack.
    pub guard_size: usize,
    /// Per-slot zeroed `tsd` array address; never null for a live head.
    pub tsd: usize,
    /// Creator requested a detached thread.
    pub detached: bool,
}

/// The complete 25-word image of one fresh pthread head over a zeroed extent,
/// for the single-module [`Plan`] of one slot. This is the exact head fill of
/// musl 1.2.5 `__copy_tls` plus `__pthread_create` before the clone:
///
/// - `self`, `prev` and `next` start self-linked, as `__init_tp` leaves the
///   leader; list insertion under the thread-list lock is a later step.
/// - `dtv` is the plan's DTV and `tid` stays zero: the creating clone writes
///   it (`CLONE_PARENT_SETTID`), and `__init_tp` is never reused because its
///   `set_tid_address` would replace the guest's clear-tid registration.
/// - `robust_list.head` points at itself; `off`/`pending` stay zero.
/// - Every other word stays zero, as musl relies on zeroed fresh mappings
///   for `errno_val`, `cancel`, `result`, `cancelbuf`, `killlock` and the
///   opaque flag byte at offset 66.
///
/// Pure numeric geometry: the caller zeroes the extent, runs the retained
/// `__copy_tls`, verifies its placement, then writes these words.
pub fn thread_head_words(plan: Plan, leader: LeaderHead, head: ThreadHead) -> [u64; 25] {
    let tp = plan.pthread().start;
    let mut words = [0_u64; 25];
    words[0] = tp as u64;
    words[1] = plan.dtv().start as u64;
    words[2] = tp as u64;
    words[3] = tp as u64;
    words[4] = leader.sysinfo as u64;
    words[5] = leader.canary as u64;
    words[7] = u64::from(if head.detached {
        DT_DETACHED
    } else {
        DT_JOINABLE
    });
    words[9] = head.map_base as u64;
    words[10] = head.map_size as u64;
    words[11] = head.stack as u64;
    words[12] = head.stack_size as u64;
    words[13] = head.guard_size as u64;
    words[16] = head.tsd as u64;
    words[17] = (tp + ROBUST_LIST_OFFSET) as u64;
    words[21] = leader.locale as u64;
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    const BACKING: usize = 0x1000_0000;
    const STRIDE: usize = 0x4000;
    const IMAGE: usize = 0x2000_1000;
    const LOCALE: usize = 0x3000_0040;

    fn plan_at(backing_start: usize) -> Plan {
        plan(
            Extent {
                start: 0x1000_0000,
                bytes: 0x1001_0000,
            },
            Extent {
                start: backing_start,
                bytes: 0x1_0000,
            },
            Extent {
                start: 0x2000_0000,
                bytes: 0x1_0000,
            },
            Extent {
                start: 0x2000_0000,
                bytes: 0x1_0000,
            },
            Template {
                image: IMAGE,
                file_bytes: 16,
                memory_bytes: 64,
                alignment: 16,
            },
        )
        .unwrap()
    }

    fn head(tsd: usize, detached: bool) -> ThreadHead {
        ThreadHead {
            map_base: 0x4000_0000,
            map_size: 0x2_1000,
            stack: 0x4002_0000,
            stack_size: 0x1_f000,
            guard_size: 0x1000,
            tsd,
            detached,
        }
    }

    /// Erase values that point into the head's own extent so two heads can
    /// be compared independently of where their slots sit.
    fn relocated(plan: Plan, words: [u64; 25]) -> [u64; 25] {
        let tp = plan.pthread().start as u64;
        words.map(|w| {
            if w == tp {
                u64::MAX
            } else if w == tp + ROBUST_LIST_OFFSET as u64 {
                ROBUST_LIST_OFFSET as u64
            } else if w == plan.dtv().start as u64 {
                u64::MAX - 1
            } else {
                w
            }
        })
    }

    // Witness level, stated plainly: this compares the pure model
    // (thread_head_words) against a hand-written model array. The
    // builder that applies these words (build_thread_tcb, plus
    // first_thread_switch and note_thread_* in private_runtime::tls)
    // has never executed — there is no musl runtime harness yet — so
    // mutants inside it survive this test. Stage B's harness must
    // compare a real second TCB against the live leader head.
    #[test]
    fn second_tcb_head_equals_leader_head_after_relocation() {
        let leader = LeaderHead {
            canary: 0x1122_3344_5566_7700,
            sysinfo: 0x7f00_0000,
            locale: LOCALE,
        };
        // The leader's own head as __init_tp leaves it on zeroed backing,
        // except word 6: __init_tp writes the leader's tid there (via
        // set_tid_address), while a newborn head leaves it zero for the
        // creating clone/child to write, so both models use 0 and word 6
        // is asserted separately below. Otherwise: self-linked, joinable,
        // locale/sysinfo/canary set, robust list self-referential, no
        // stack mapping recorded, no tsd array.
        let leader_plan = plan_at(BACKING);
        let leader_tp = leader_plan.pthread().start as u64;
        let mut leader_words = [0_u64; 25];
        leader_words[0] = leader_tp;
        leader_words[1] = leader_plan.dtv().start as u64;
        leader_words[2] = leader_tp;
        leader_words[3] = leader_tp;
        leader_words[4] = leader.sysinfo as u64;
        leader_words[5] = leader.canary as u64;
        leader_words[7] = u64::from(DT_JOINABLE);
        leader_words[17] = leader_tp + ROBUST_LIST_OFFSET as u64;
        leader_words[21] = LOCALE as u64;

        let second_plan = plan_at(BACKING + STRIDE);
        assert_eq!(second_plan.total_bytes(), leader_plan.total_bytes());
        assert_eq!(
            second_plan.pthread().start - leader_plan.pthread().start,
            STRIDE
        );
        let second = thread_head_words(second_plan, leader, head(0x5000_0000, false));
        let got = relocated(second_plan, second);
        let want = relocated(leader_plan, leader_words);
        for index in 0..25 {
            // Slot-record words musl fills from the new mapping and its
            // per-slot tsd; the leader keeps zeros there.
            if matches!(index, 9..=13 | 16) {
                continue;
            }
            assert_eq!(got[index], want[index], "word {index}");
        }
        // The slot-record words are exactly the supplied slot inputs.
        assert_eq!(second[9], 0x4000_0000);
        assert_eq!(second[10], 0x2_1000);
        assert_eq!(second[11], 0x4002_0000);
        assert_eq!(second[12], 0x1_f000);
        assert_eq!(second[13], 0x1000);
        assert_eq!(second[16], 0x5000_0000);
        // The tid word stays zero for the creating clone to write.
        assert_eq!(second[6], 0);
    }

    #[test]
    fn detached_head_and_tsd_geometry() {
        assert_eq!(TSD_BYTES, 1024);
        let plan = plan_at(BACKING);
        let words = thread_head_words(
            plan,
            LeaderHead {
                canary: 0,
                sysinfo: 0,
                locale: LOCALE,
            },
            head(0x5000_0000, true),
        );
        assert_eq!(words[7], u64::from(DT_DETACHED));
        // The DTV word is the plan's single-module DTV, whose entries the
        // builder verifies as dtv[0] == 1 and dtv[1] == tls start.
        assert_eq!(words[1], plan.dtv().start as u64);
        assert_eq!(plan.dtv().bytes, DTV_BYTES);
    }
}
