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
