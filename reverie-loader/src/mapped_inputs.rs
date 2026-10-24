//! Shared complete mapped-input numeric validation.
//! Explicit represented addresses may differ from this slice's host address.
//! Success does not authenticate mappings, a source image, ownership or readiness.

use crate::handoff::Code;
use crate::handoff::Error;
use crate::handoff::Extent;
use crate::handoff::Map;
use crate::handoff::Registers;
use crate::handoff::Site;
use crate::handoff::View;
use crate::musl_tls as layout;

/// Numeric caller expectations from this exact compiled consumer, not wire data.
/// `free_band` must be obtained from tool_region's existing private constants;
/// expose one pure accessor there, not a duplicate reservation/layout owner.
#[derive(Clone, Copy)]
pub struct ConsumerLayout {
    /// Existing low free band between Control and Tool band.
    pub free_band: Extent,
    /// Existing complete four-GiB reservation.
    pub region: Extent,
    /// `size_of::<NativeControl>()` of this actual consumer.
    pub control_bytes: u64,
    /// `size_of::<libc_relay::RelayStorage>()` of this actual consumer.
    pub relay_bytes: u64,
    /// Actual target NativeControl alignment, from its compiled descriptor.
    pub control_align: u64,
    /// Actual target RelayStorage alignment, from its compiled descriptor.
    pub relay_align: u64,
}

/// Data-only, immutable borrowed inputs for the existing mapped lifecycle.
/// No safe construction here creates CapturedMappedInitial, a permit or Ready.
/// The actual unsafe capture retains its same-generation physical contract.
/// No references to transient projected layouts/maps/enums are manufactured.
pub struct ProductionMappedInputs<'a> {
    view: View<'a>,
    plan: layout::Plan,
    expected: ConsumerLayout,
}
fn inside(role: Extent, address: u64, bytes: u64) -> bool {
    role.start
        .checked_add(4096)
        .is_some_and(|first| address >= first)
        && role
            .end
            .checked_sub(4096)
            .is_some_and(|last| address.checked_add(bytes).is_some_and(|end| end <= last))
}
fn contains(map: Map, address: u64, bytes: u64, protection: u64) -> bool {
    map.protection == protection
        && Extent {
            start: map.start,
            end: map.end,
        }
        .contains(address, bytes)
}
fn extent(start: u64, bytes: u64) -> Result<layout::Extent, Error> {
    Ok(layout::Extent {
        start: usize::try_from(start).map_err(|_| Error::Bounds)?,
        bytes: usize::try_from(bytes).map_err(|_| Error::Bounds)?,
    })
}
// Called only after the complete map list has passed the nonempty/page,
// protection and pairwise-disjoint checks above. View::parse caps it at 64
// rows. Walk at most that many rows without allocation or ordering assumptions.
fn readable_load_coverage(view: View<'_>, start: u64, bytes: u64) -> Result<(), Error> {
    let end = start.checked_add(bytes).ok_or(Error::Value)?;
    if bytes == 0 {
        return Err(Error::Value);
    }
    let count = view.table(0)?.len();
    let mut cursor = start;
    for _ in 0..count {
        let mut next = cursor;
        for i in 0..count {
            let map = view.map(i)?;
            if map.start <= cursor && cursor < map.end && map.protection & 1 == 1 {
                next = map.end.min(end);
                break;
            }
        }
        if next == cursor {
            return Err(Error::Value);
        }
        cursor = next;
        if cursor == end {
            return Ok(());
        }
    }
    Err(Error::Value)
}
impl<'a> ProductionMappedInputs<'a> {
    /// Decode actual retained RO bytes; all physical/ELF/source joins remain
    /// the unsafe capture caller's obligations, not deductions from this view.
    pub fn decode(bytes: &'a [u8], expected: ConsumerLayout) -> Result<Self, Error> {
        Self::decode_at(bytes, bytes.as_ptr() as u64, expected)
    }
    /// Run the original decoder against an explicit represented child address.
    /// This does not dereference represented addresses. The complete pure
    /// predicate also requires `check_structure` at the existing capture cut.
    pub fn decode_at(
        bytes: &'a [u8],
        address: u64,
        expected: ConsumerLayout,
    ) -> Result<Self, Error> {
        let view = View::parse(bytes, address)?;
        view.validate_roles(expected.free_band)?;
        if view.scalar(2)? != expected.control_bytes
            || view.scalar(4)? != expected.relay_bytes
            || view.scalar(1)? % 64 != 0
            || view.scalar(3)? % 64 != 0
        {
            return Err(Error::Value);
        }
        let state = view.role(4)?;
        let lo = state.start.checked_add(4096).ok_or(Error::Bounds)?;
        let hi = state.end.checked_sub(4096).ok_or(Error::Bounds)?;
        let state = Extent { start: lo, end: hi };
        let c = view.scalar(1)?;
        let cb = view.scalar(2)?;
        let r = view.scalar(3)?;
        let rb = view.scalar(4)?;
        if cb == 0
            || rb == 0
            || !state.contains(c, cb)
            || !state.contains(r, rb)
            || (c < r.checked_add(rb).ok_or(Error::Bounds)?
                && r < c.checked_add(cb).ok_or(Error::Bounds)?)
        {
            return Err(Error::Bounds);
        }
        let mut ro = false;
        let mut control_rw = false;
        let mut relay_rw = false;
        for i in 0..view.table(0)?.len() {
            let map = view.map(i)?;
            if map.start == 0
                || map.start >= map.end
                || map.start % 4096 != 0
                || map.end % 4096 != 0
                || map.protection & !7 != 0
                || map.protection & 6 == 6
            {
                return Err(Error::Value);
            }
            for j in 0..i {
                let other = view.map(j)?;
                if map.start < other.end && other.start < map.end {
                    return Err(Error::Bounds);
                }
            }
            ro |= contains(map, view.address(), bytes.len() as u64, 1);
            control_rw |= contains(map, c, cb, 3);
            relay_rw |= contains(map, r, rb, 3);
        }
        if !ro || !control_rw || !relay_rw {
            return Err(Error::Value);
        }
        for i in 0..view.table(1)?.len() {
            let code = view.code(i)?;
            if code.start >= code.end {
                return Err(Error::Value);
            }
            let mut covered = false;
            for j in 0..view.table(0)?.len() {
                covered |= contains(
                    view.map(j)?,
                    code.start,
                    code.end.checked_sub(code.start).ok_or(Error::Bounds)?,
                    5,
                );
            }
            if !covered {
                return Err(Error::Value);
            }
        }
        let mut gate_ro = false;
        let mut handler = false;
        let mut dev_null_ro = false;
        for i in 0..view.table(0)?.len() {
            let map = view.map(i)?;
            gate_ro |= contains(map, view.scalar(10)?, 4096, 1);
            dev_null_ro |= contains(map, view.scalar(13)?, 10, 1);
        }
        for i in 0..view.table(1)?.len() {
            let code = view.code(i)?;
            handler |= view.scalar(9)? >= code.start && view.scalar(9)? < code.end;
        }
        let runtime = crate::artifact::RUNTIME_WINDOW;
        let dev = view.scalar(13)?;
        if dev < runtime.start
            || dev.checked_add(10).is_none_or(|end| end > runtime.end)
            || !gate_ro
            || !handler
            || !dev_null_ro
        {
            return Err(Error::Value);
        }
        let mut seen = [false; 4];
        let mut previous = 0;
        for i in 0..view.table(2)?.len() {
            let site = view.site(i)?;
            if site.return_ip <= previous {
                return Err(Error::Value);
            }
            previous = site.return_ip;
            let mut covered = false;
            for j in 0..view.table(1)?.len() {
                let code = view.code(j)?;
                covered |= site.syscall_ip >= code.start && site.return_ip <= code.end;
            }
            if !covered {
                return Err(Error::Value);
            }
            use crate::handoff::Operation::*;
            seen[match site.operation {
                SetFs => 0,
                SetTid => 1,
                SecurePoll => 2,
                SecureOpen => 3,
            }] = true;
        }
        if seen != [true; 4] {
            return Err(Error::Value);
        }
        for i in 0..view.table(8)?.len() {
            let post = view.table(8)?.field(i, 0)?;
            let mut covered = false;
            for j in 0..view.table(1)?.len() {
                let code = view.code(j)?;
                covered |=
                    post.checked_sub(2).ok_or(Error::Bounds)? >= code.start && post <= code.end;
            }
            if !covered {
                return Err(Error::Value);
            }
        }
        // Actual instruction bytes and source role identity are NOT read here;
        // retain existing unsafe relay validation against sealed physical code.
        if view.tls(1)? != 56 || view.tls(2)? == 0 || view.tls(2)? > 64 {
            return Err(Error::Value);
        }
        let aux = view.table(5)?;
        let mut private_aux = [false; 4];
        let aux_end = aux.len().checked_sub(2).ok_or(Error::Bounds)?;
        for i in (0..aux_end).step_by(2) {
            let expected = match aux.field(i, 0)? {
                3 => Some((0, view.tls(0)?)),
                4 => Some((1, 56)),
                5 => Some((2, view.tls(2)?)),
                6 => Some((3, 4096)),
                _ => None,
            };
            if let Some((slot, value)) = expected {
                if aux.field(i.checked_add(1).ok_or(Error::Bounds)?, 0)? != value {
                    return Err(Error::Value);
                }
                private_aux[slot] = true;
            }
        }
        if private_aux != [true; 4] {
            return Err(Error::Value);
        }
        let phdr_bytes = view
            .tls(1)?
            .checked_mul(view.tls(2)?)
            .ok_or(Error::Bounds)?;
        let mut phdr_ro = false;
        for i in 0..view.table(0)?.len() {
            phdr_ro |= contains(view.map(i)?, view.tls(0)?, phdr_bytes, 1);
        }
        if !phdr_ro {
            return Err(Error::Value);
        }
        let tls_role = view.role(1)?;
        let backing = extent(view.tls(7)?, view.tls(8)?)?;
        if !(Extent {
            start: tls_role.start.checked_add(4096).ok_or(Error::Bounds)?,
            end: tls_role.end.checked_sub(4096).ok_or(Error::Bounds)?,
        })
        .contains(view.tls(7)?, view.tls(8)?)
        {
            return Err(Error::Bounds);
        }
        let mut backing_rw = false;
        for i in 0..view.table(0)?.len() {
            backing_rw |= contains(view.map(i)?, view.tls(7)?, view.tls(8)?, 3);
        }
        if !backing_rw {
            return Err(Error::Value);
        }
        let load = extent(view.tls(9)?, view.tls(10)?)?;
        let file = extent(view.tls(9)?, view.tls(11)?)?;
        readable_load_coverage(view, view.tls(9)?, view.tls(10)?)?;
        let region = extent(
            expected.region.start,
            expected
                .region
                .end
                .checked_sub(expected.region.start)
                .ok_or(Error::Bounds)?,
        )?;
        let plan = layout::plan(
            region,
            backing,
            load,
            file,
            layout::Template {
                image: usize::try_from(view.tls(3)?).map_err(|_| Error::Bounds)?,
                file_bytes: usize::try_from(view.tls(4)?).map_err(|_| Error::Bounds)?,
                memory_bytes: usize::try_from(view.tls(5)?).map_err(|_| Error::Bounds)?,
                alignment: usize::try_from(view.tls(6)?).map_err(|_| Error::Bounds)?,
            },
        )
        .map_err(|_| Error::Value)?;
        if view.scalar(8)? != plan.pthread().start as u64 {
            return Err(Error::Value);
        }
        Ok(Self {
            view,
            plan,
            expected,
        })
    }
    /// Run both existing pure phases before any host child mutation.
    /// No physical origin, code bytes or kernel facts follow from this result.
    pub fn validate_at(
        bytes: &'a [u8],
        address: u64,
        expected: ConsumerLayout,
    ) -> Result<Self, Error> {
        let input = Self::decode_at(bytes, address, expected)?;
        input.check_structure()?;
        Ok(input)
    }
    /// All pure checks formerly run by MappedInitialInputs::check_structure.
    /// Child pointer-origin equality remains a separate physical check. Table
    /// ranges are projected from the represented address, never host pointers.
    pub fn check_structure(&self) -> Result<(), Error> {
        let view = self.view;
        view.validate_roles(self.expected.free_band)?;
        // scalar_layout's binding projections and role/owner conversions.
        for i in 0..5 {
            let _ = view.binding(i)?;
            let _ = view.role(i)?;
        }
        let owner = i32::try_from(view.scalar(0)?).map_err(|_| Error::Value)?;
        let fd = i32::try_from(view.scalar(5)?).map_err(|_| Error::Value)?;
        let pkru = u32::try_from(view.scalar(6)?).map_err(|_| Error::Value)?;
        let packet = view.table(3)?;
        let packet_at = view.table_address(3)?;
        let resume = view.address().checked_add(38 * 8).ok_or(Error::Bounds)?;
        let maps = view.table(0)?;
        let codes = view.table(1)?;
        let c = view.scalar(1)?;
        let cb = self.expected.control_bytes;
        let state = view.role(4)?;
        let handoff = view.role(3)?;
        if c % 64 != 0
            || !inside(state, c, cb)
            || packet.bytes().is_empty()
            || packet.bytes().len() > 4096
            || fd < 0
            || !inside(handoff, packet_at, packet.bytes().len() as u64)
            || resume % 8 != 0
            || !inside(handoff, resume, 216)
            || !inside(handoff, view.table_address(0)?, maps.bytes().len() as u64)
            || !inside(handoff, view.table_address(1)?, codes.bytes().len() as u64)
            || maps.is_empty()
            || maps.len() > 64
            || codes.is_empty()
            || codes.len() > 64
            || !inside(view.role(1)?, view.scalar(8)?, 1)
        {
            return Err(Error::Value);
        }
        for i in 0..maps.len() {
            let map = view.map(i)?;
            if map.start == 0
                || map.start >= map.end
                || map.start % 4096 != 0
                || map.end % 4096 != 0
                || map.protection & !7 != 0
                || map.protection & 6 == 6
            {
                return Err(Error::Value);
            }
            for j in 0..i {
                let other = view.map(j)?;
                if map.start < other.end && other.start < map.end {
                    return Err(Error::Value);
                }
            }
        }
        let mut packet_ro = false;
        let mut resume_ro = false;
        let mut gate_ro = false;
        let mut control_rw = false;
        for i in 0..maps.len() {
            let map = view.map(i)?;
            packet_ro |= contains(map, packet_at, packet.bytes().len() as u64, 1);
            resume_ro |= contains(map, resume, 216, 1);
            gate_ro |= contains(map, view.scalar(10)?, 4096, 1);
            control_rw |= contains(map, c, cb, 3);
        }
        if !packet_ro || !resume_ro || !gate_ro || !control_rw {
            return Err(Error::Value);
        }
        for i in 0..codes.len() {
            let code = view.code(i)?;
            if code.start >= code.end {
                return Err(Error::Value);
            }
            let mut covered = false;
            for j in 0..maps.len() {
                covered |= contains(view.map(j)?, code.start, code.end - code.start, 5);
            }
            if !covered {
                return Err(Error::Value);
            }
        }
        let mut handler = false;
        for i in 0..codes.len() {
            let code = view.code(i)?;
            handler |= view.scalar(9)? >= code.start && view.scalar(9)? < code.end;
        }
        if !handler || owner <= 0 || pkru & 1 != 0 {
            return Err(Error::Value);
        }
        // The existing host path already enforced these actual descriptor
        // alignments. Preserve them when using the common complete predicate.
        if !self.expected.control_align.is_power_of_two()
            || !self.expected.relay_align.is_power_of_two()
            || c % self.expected.control_align != 0
            || view.scalar(3)? % self.expected.relay_align != 0
        {
            return Err(Error::Value);
        }
        Ok(())
    }
    /// Original immutable records for current physical provenance checks.
    pub fn view(&self) -> View<'a> {
        self.view
    }
    /// Local checked private TLS plan, not a scalar readiness witness.
    pub fn tls_plan(&self) -> layout::Plan {
        self.plan
    }
    /// Scalar original registers; NativeControl consumes words by value.
    pub fn registers(&self) -> Registers<'a> {
        self.view.registers()
    }
    /// Existing maps loop decodes one value; no native reference cast.
    pub fn map(&self, index: usize) -> Result<Map, Error> {
        self.view.map(index)
    }
    /// Existing code loop decodes one value.
    pub fn code(&self, index: usize) -> Result<Code, Error> {
        self.view.code(index)
    }
    /// Existing relay match consumes a checked local operation.
    pub fn site(&self, index: usize) -> Result<Site, Error> {
        self.view.site(index)
    }
}
