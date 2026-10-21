//! Read-only original-input capture under the retained initial exec stop.
//! These are owned observations, not a mapping/launch/readiness capability.
#![forbid(unsafe_code)]

use std::io::Read;

use reverie_memory::Addr;
use reverie_memory::MemoryAccess;

use super::InitialExecStop;
use super::Result;
use super::initial_stack_inputs::Aux;
use super::initial_stack_inputs::Error as ParseError;
use super::initial_stack_inputs::OwnedRead;
use super::initial_stack_inputs::ParsedInitial;
#[cfg(feature = "loader-private-runtime")]
use super::initial_stack_inputs::PlacedInputs;
#[cfg(feature = "loader-private-runtime")]
use super::initial_stack_inputs::PrivateImageAux;
use super::initial_stack_inputs::ReadKind;
use super::initial_stack_inputs::ReadRequest;
use super::initial_stack_inputs::RetainedAux;
use super::register_words;

const MAX_MAP_BYTES: usize = 4 * 1024 * 1024;
const MAX_EXTERNAL_BYTES: usize = 16 * 1024 * 1024;
const READ_CHUNK: usize = 256;

/// One actual `/proc/PID/maps` record; private construction preserves capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputMapping {
    start: u64,
    end: u64,
    permissions: [u8; 4],
    file_offset: u64,
    device: (u64, u64),
    inode: u64,
    path: Vec<u8>,
}
impl InputMapping {
    /// Actual half-open virtual interval.
    pub fn range(&self) -> std::ops::Range<u64> {
        self.start..self.end
    }
    /// Exact r/w/x/private-or-shared fields, including unset permissions.
    pub fn permissions(&self) -> [u8; 4] {
        self.permissions
    }
    /// Actual file mapping byte offset.
    pub fn file_offset(&self) -> u64 {
        self.file_offset
    }
    /// Recorded Linux device major/minor; not a file-content identity.
    pub fn device(&self) -> (u64, u64) {
        self.device
    }
    /// Recorded inode; not proof of sealed contents or mapping stability.
    pub fn inode(&self) -> u64 {
        self.inode
    }
    /// Original path-label bytes; never reopened as a host replacement file.
    pub fn path(&self) -> &[u8] {
        &self.path
    }
}
struct Chunk {
    address: u64,
    bytes: Vec<u8>,
    mapping: usize,
}
struct ExternalRead {
    owned: OwnedRead,
    chunks: Vec<Chunk>,
}
struct RetainedRead {
    owned: RetainedAux,
    mapping: usize,
}

/// Owned original observations captured before any guest instruction or Detcore
/// mutation. This neither owns the child nor permits resuming/mapping it.
/// Private fields have no public fabricated-evidence constructor.
pub struct CapturedInitialInputs {
    generation: safeptrace::TraceeGeneration,
    pid: safeptrace::Pid,
    registers: [u64; 27],
    stack_start: u64,
    stack_bytes: Vec<u8>,
    maps_before: Vec<u8>,
    maps_after: Vec<u8>,
    mappings: Vec<InputMapping>,
    original_aux: Vec<Aux>,
    reads: Vec<ExternalRead>,
    retained: Vec<RetainedRead>,
}
impl CapturedInitialInputs {
    /// Actual stopped child identity at observation time, not lifetime authority.
    pub fn pid(&self) -> safeptrace::Pid {
        self.pid
    }
    /// Exact original27-register codec, including guest original FS/GS.
    pub fn registers(&self) -> &[u64; 27] {
        &self.registers
    }
    /// Original stack VMA start.
    pub fn stack_start(&self) -> u64 {
        self.stack_start
    }
    /// Actual unchanged original stack bytes. Do not restore over Detcore writes.
    pub fn stack_bytes(&self) -> &[u8] {
        &self.stack_bytes
    }
    /// Exact raw maps bytes before and after bounded reads, including paths.
    pub fn maps_snapshots(&self) -> (&[u8], &[u8]) {
        (&self.maps_before, &self.maps_after)
    }
    /// Parsed actual mapping ledger matching both snapshots.
    pub fn mappings(&self) -> &[InputMapping] {
        &self.mappings
    }
    /// Genuine unmodified original aux pairs; no private-image substitution.
    pub fn original_aux(&self) -> impl ExactSizeIterator<Item = (u64, u64)> + '_ {
        self.original_aux.iter().map(|a| (a.kind, a.value))
    }
    /// Completed bounded external string/random observations, by child address.
    pub fn external_reads(&self) -> impl ExactSizeIterator<Item = (u64, &[u8])> + '_ {
        self.reads
            .iter()
            .map(|r| (r.owned.request.address, r.owned.bytes.as_slice()))
    }
    /// Actual retained pointer-valued aux observation and its mapping index.
    /// The mapping/content observation is not source/immutability authority.
    pub fn retained_aux(&self) -> impl ExactSizeIterator<Item = (u64, u64, usize, &[u8])> + '_ {
        self.retained.iter().map(|r| {
            (
                r.owned.aux.kind,
                r.owned.aux.value,
                r.mapping,
                r.owned.observed.as_slice(),
            )
        })
    }
    /// Actual read chunks, preserving map identity and reads past a C NUL.
    pub fn read_chunks(&self) -> impl Iterator<Item = (u64, usize, &[u8])> + '_ {
        self.reads.iter().flat_map(|r| {
            r.chunks
                .iter()
                .map(|c| (c.address, c.mapping, c.bytes.as_slice()))
        })
    }

    // Only the real internal producer may project actual final-image metadata.
    // Numeric placement is safe data transformation, NOT source qualification,
    // mapping authority or readiness. Keep it crate-private until that producer
    // owns the actual sealed image, all mappings and this same birth/generation.
    #[cfg(feature = "loader-private-runtime")]
    pub(crate) fn place(
        &self,
        image: PrivateImageAux,
        base: u64,
        capacity: usize,
    ) -> Result<PlacedInputs> {
        let parsed = ParsedInitial::parse(self.stack_start, &self.stack_bytes, self.registers[19])
            .map_err(parse_error)?;
        let reads: Vec<OwnedRead> = self
            .reads
            .iter()
            .map(|r| OwnedRead {
                request: r.owned.request,
                bytes: r.owned.bytes.clone(),
            })
            .collect();
        let retained: Vec<RetainedAux> = self
            .retained
            .iter()
            .map(|r| RetainedAux {
                aux: r.owned.aux,
                start: r.owned.start,
                end: r.owned.end,
                observed: r.owned.observed.clone(),
            })
            .collect();
        parsed
            .copy_plan(image, &reads, &retained, capacity)
            .map_err(parse_error)?
            .place(base, u64::try_from(capacity)?)
            .map_err(parse_error)
    }
    // No public generation capability is exposed. The producer must bind this
    // before adding/replacing mappings; capture data alone cannot preserve them.
    pub(crate) fn matches_stop(&self, stop: &InitialExecStop<'_>) -> bool {
        self.generation == stop.task.generation()
            && self.generation == stop.owner.generation
            && self.generation == stop.context.generation
            && self.pid == stop.task.pid()
    }
}
fn parse_error(error: ParseError) -> Box<dyn std::error::Error> {
    format!("exec-stop original-input refusal: {error:?}").into()
}
fn token<'a>(line: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
    while *cursor < line.len() && line[*cursor].is_ascii_whitespace() {
        *cursor += 1;
    }
    let start = *cursor;
    while *cursor < line.len() && !line[*cursor].is_ascii_whitespace() {
        *cursor += 1;
    }
    if *cursor == start {
        return Err("exec-stop truncated maps record".into());
    }
    Ok(&line[start..*cursor])
}
fn number(bytes: &[u8], radix: u32) -> Result<u64> {
    Ok(u64::from_str_radix(std::str::from_utf8(bytes)?, radix)?)
}
fn pair(bytes: &[u8], separator: u8, radix: u32) -> Result<(u64, u64)> {
    let at = bytes
        .iter()
        .position(|b| *b == separator)
        .ok_or("exec-stop malformed maps pair")?;
    if bytes[at + 1..].contains(&separator) {
        return Err("exec-stop ambiguous maps pair".into());
    }
    Ok((
        number(&bytes[..at], radix)?,
        number(&bytes[at + 1..], radix)?,
    ))
}
fn parse_maps(bytes: &[u8]) -> Result<Vec<InputMapping>> {
    if bytes.is_empty() || bytes.len() > MAX_MAP_BYTES || bytes.last() != Some(&b'\n') {
        return Err("exec-stop empty/oversized/incomplete maps snapshot".into());
    }
    let mut result = Vec::new();
    for line in bytes[..bytes.len() - 1].split(|b| *b == b'\n') {
        let mut cursor = 0;
        let (start, end) = pair(token(line, &mut cursor)?, b'-', 16)?;
        let perms = token(line, &mut cursor)?;
        if start >= end
            || !start.is_multiple_of(4096)
            || !end.is_multiple_of(4096)
            || perms.len() != 4
            || !matches!(perms[0], b'r' | b'-')
            || !matches!(perms[1], b'w' | b'-')
            || !matches!(perms[2], b'x' | b'-')
            || !matches!(perms[3], b'p' | b's')
        {
            return Err("exec-stop invalid maps range/permissions".into());
        }
        let file_offset = number(token(line, &mut cursor)?, 16)?;
        let device = pair(token(line, &mut cursor)?, b':', 16)?;
        let inode = number(token(line, &mut cursor)?, 10)?;
        while cursor < line.len() && line[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if result.last().is_some_and(|m: &InputMapping| m.end > start) {
            return Err("exec-stop unsorted/overlapping maps snapshot".into());
        }
        result.push(InputMapping {
            start,
            end,
            permissions: perms.try_into()?,
            file_offset,
            device,
            inode,
            path: line[cursor..].to_vec(),
        });
    }
    Ok(result)
}
fn read_maps(stop: &InitialExecStop<'_>) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    std::fs::File::open(format!("/proc/{}/maps", stop.task.pid()))?
        .take((MAX_MAP_BYTES + 1) as u64)
        .read_to_end(&mut raw)?;
    if raw.len() > MAX_MAP_BYTES {
        return Err("exec-stop maps snapshot exceeds4MiB bound".into());
    }
    Ok(raw)
}
fn mapping_at(maps: &[InputMapping], address: u64) -> Result<usize> {
    maps.iter()
        .position(|m| m.start <= address && address < m.end)
        .ok_or_else(|| "exec-stop input address has no actual retained mapping".into())
}
fn spend(budget: &mut usize, bytes: usize) -> Result<()> {
    *budget = budget
        .checked_add(bytes)
        .ok_or("exec-stop input read budget overflow")?;
    if *budget > MAX_EXTERNAL_BYTES {
        return Err("exec-stop external input reads exceed16MiB".into());
    }
    Ok(())
}
// Permission-respecting, exact-span copy. The actual Stopped implementation
// keeps on_held_tid around process_vm_readv for every length, including 1..8;
// ordinary MemoryAccess::read_exact would select a full PEEKDATA word there.
// No raw PID read, retry, widening or ptrace fallback is permitted here.
fn read_exact_span(task: &safeptrace::Stopped, address: u64, length: usize) -> Result<Vec<u8>> {
    let address = usize::try_from(address)?;
    address
        .checked_add(length)
        .ok_or("exec-stop exact input read overflow")?;
    let mut bytes = vec![0; length];
    task.read_exact_with_user_access(
        Addr::from_raw(address).ok_or("exec-stop null exact input address")?,
        &mut bytes,
    )?;
    Ok(bytes)
}
fn read_request(
    stop: &InitialExecStop<'_>,
    maps: &[InputMapping],
    request: ReadRequest,
    budget: &mut usize,
) -> Result<ExternalRead> {
    let maximum = request.maximum_bytes();
    request
        .address
        .checked_add(maximum as u64)
        .ok_or("exec-stop source address overflow")?;
    let mut owned = OwnedRead {
        request,
        bytes: Vec::new(),
    };
    let mut chunks = Vec::new();
    loop {
        let address = request
            .address
            .checked_add(owned.bytes.len() as u64)
            .ok_or("exec-stop source cursor overflow")?;
        let index = mapping_at(maps, address)?;
        let map = &maps[index];
        let length = (maximum - owned.bytes.len())
            .min(READ_CHUNK)
            .min(usize::try_from(map.end - address)?)
            .min(4096 - (address as usize & 4095));
        if length == 0 {
            return Err("exec-stop incomplete bounded input read".into());
        }
        spend(budget, length)?;
        let bytes = read_exact_span(&stop.task, address, length)?;
        let take = match request.kind {
            ReadKind::CString => bytes.iter().position(|b| *b == 0).map(|i| i + 1),
            ReadKind::Random16 => (owned.bytes.len() + bytes.len() == 16).then_some(bytes.len()),
        };
        owned
            .bytes
            .extend_from_slice(&bytes[..take.unwrap_or(bytes.len())]);
        chunks.push(Chunk {
            address,
            bytes,
            mapping: index,
        });
        if take.is_some() {
            return Ok(ExternalRead { owned, chunks });
        }
        if owned.bytes.len() == maximum {
            return Err("exec-stop unterminated bounded input string".into());
        }
    }
}
pub(super) fn unchanged(stop: &InitialExecStop<'_>) -> Result<()> {
    let task = &stop.task;
    let context = &stop.context;
    if task.generation() != context.generation
        || task.generation() != stop.owner.generation
        || register_words(&task.getregs()?) != register_words(&context.regs)
        || task.getsigmask()? != context.signal_mask
        || task.getxstate()? != context.xstate
        || read_exact_span(task, context.stack_start, context.stack_bytes.len())?
            != context.stack_bytes
    {
        return Err("exec-stop input capture lost original stopped context/stack".into());
    }
    Ok(())
}
impl InitialExecStop<'_> {
    /// Read original input bytes from this actual stopped generation only.
    /// The stop/ChildOwner remain borrowed in place on success and error; no
    /// Stopped, Running, arbitrary read or resume capability escapes. Run on the
    /// original ptracer OS thread with the existing outer physical deadline.
    /// Maps/readback equality is an observation, not a proof against external
    /// Exact reads respect user VMA access permissions; inaccessible or short
    /// reads refuse without ptrace fallback or retries. This does not prove
    /// protection-key access. Maps/readback do not exclude
    /// shared/file-memory writers or later mapping destruction: the real host
    /// producer must retain exact source/mapping custody through handover.
    pub fn capture_initial_inputs(&self) -> Result<CapturedInitialInputs> {
        unchanged(self)?;
        let maps_before = read_maps(self)?;
        let mappings = parse_maps(&maps_before)?;
        let context = &self.context;
        let stack_end = context
            .stack_start
            .checked_add(context.stack_bytes.len() as u64)
            .ok_or("exec-stop original stack extent overflow")?;
        if !mappings
            .iter()
            .any(|m| m.start == context.stack_start && m.end == stack_end && m.path == b"[stack]")
        {
            return Err("exec-stop current maps do not retain exact original stack VMA".into());
        }
        let parsed =
            ParsedInitial::parse(context.stack_start, &context.stack_bytes, context.regs.rsp)
                .map_err(parse_error)?;
        let mut budget = 0;
        let mut reads = Vec::new();
        for request in parsed.read_requests().map_err(parse_error)? {
            reads.push(read_request(self, &mappings, request, &mut budget)?);
        }
        let mut retained = Vec::new();
        for aux in parsed
            .original_aux()
            .iter()
            .filter(|a| matches!(a.kind, 7 | 9 | 32 | 33) && a.value != 0)
        {
            let index = mapping_at(&mappings, aux.value)?;
            let map = &mappings[index];
            let length = usize::try_from((map.end - aux.value).min(4096))?;
            spend(&mut budget, length)?;
            retained.push(RetainedRead {
                mapping: index,
                owned: RetainedAux {
                    aux: *aux,
                    #[cfg(any(test, feature = "loader-private-runtime"))]
                    start: map.start,
                    #[cfg(any(test, feature = "loader-private-runtime"))]
                    end: map.end,
                    observed: read_exact_span(&self.task, aux.value, length)?,
                },
            });
        }
        // Reconcile actual reads before any future mapping/entry mutation. Keep
        // full raw chunk bytes, including harmless reads beyond a string NUL.
        for read in &reads {
            for chunk in &read.chunks {
                if read_exact_span(&self.task, chunk.address, chunk.bytes.len())? != chunk.bytes {
                    return Err("exec-stop external input bytes changed during capture".into());
                }
            }
        }
        for read in &retained {
            if read_exact_span(&self.task, read.owned.aux.value, read.owned.observed.len())?
                != read.owned.observed
            {
                return Err("exec-stop retained aux bytes changed during capture".into());
            }
        }
        unchanged(self)?;
        let maps_after = read_maps(self)?;
        if maps_before != maps_after {
            return Err("exec-stop mapping ledger changed during input capture".into());
        }
        let evidence = CapturedInitialInputs {
            generation: self.task.generation(),
            pid: self.task.pid(),
            registers: register_words(&context.regs),
            stack_start: context.stack_start,
            stack_bytes: context.stack_bytes.clone(),
            maps_before,
            maps_after,
            mappings,
            original_aux: parsed.original_aux().to_vec(),
            reads,
            retained,
        };
        if !evidence.matches_stop(self) {
            return Err("exec-stop capture identity changed before return".into());
        }
        Ok(evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initial_input_maps_preserve_shared_flags_offsets_and_non_utf8_paths() {
        let bytes=b"00001000-00002000 r--s 000000ff 08:01 17 /tmp/name \xff (deleted)\n00003000-00004000 rw-p 00000000 00:00 0 [stack]\n";
        let maps = parse_maps(bytes).unwrap();
        assert_eq!(maps.len(), 2);
        assert_eq!(maps[0].permissions(), *b"r--s");
        assert_eq!(maps[0].file_offset(), 255);
        assert_eq!(maps[0].device(), (8, 1));
        assert_eq!(maps[0].inode(), 17);
        assert_eq!(maps[0].path(), b"/tmp/name \xff (deleted)");
        assert_eq!(maps[1].path(), b"[stack]");
        assert_eq!(mapping_at(&maps, 0x1000).unwrap(), 0);
        assert!(mapping_at(&maps, 0x2000).is_err());
    }
    #[test]
    fn initial_input_maps_refuse_partial_malformed_overlap_and_unbounded_files() {
        for bytes in [
            b"".as_slice(),
            b"00001000-00002000 r--p 0 00:00 0",
            b"00001001-00002000 r--p 0 00:00 0\n",
            b"00001000-00002000 r--q 0 00:00 0\n",
            b"00001000-00003000 r--p 0 00:00 0\n00002000-00004000 r--p 0 00:00 0\n",
        ] {
            assert!(parse_maps(bytes).is_err());
        }
        assert!(parse_maps(&vec![b'\n'; MAX_MAP_BYTES + 1]).is_err());
    }
    #[test]
    fn initial_input_capture_keeps_actual_aux_stack_maps_and_cancel_owner() {
        let argv = [std::ffi::OsString::from("actual-input-capture-argv0")];
        let env = [(
            std::ffi::OsString::from("ACTUAL_INPUT_CAPTURE"),
            std::ffi::OsString::from("original-value"),
        )];
        let request = super::super::PreparedExec::new(
            std::path::Path::new("/bin/true"),
            &argv,
            &env,
            None,
            vec![],
        )
        .unwrap();
        let receipt = super::super::CleanupReceipt::default();
        let stop = super::super::ExecStop::spawn(request, receipt.clone()).unwrap();
        let inputs = stop.capture_initial_inputs().unwrap();
        assert!(inputs.matches_stop(&stop));
        assert_eq!(inputs.pid(), stop.pid());
        assert_eq!(inputs.registers(), &register_words(stop.entry().regs()));
        assert_eq!(inputs.stack_bytes(), stop.entry().stack_bytes());
        assert_eq!(inputs.maps_snapshots().0, inputs.maps_snapshots().1);
        assert!(inputs.mappings().iter().any(|m| m.path() == b"[stack]"));
        let aux: Vec<_> = inputs.original_aux().collect();
        for kind in [3, 4, 5, 6, 11, 12, 13, 14, 16, 23, 25, 31] {
            assert_eq!(aux.iter().filter(|a| a.0 == kind).count(), 1);
        }
        let random = aux.iter().find(|a| a.0 == 25).unwrap().1;
        let offset = usize::try_from(random - inputs.stack_start()).unwrap();
        assert_eq!(
            inputs.stack_bytes()[offset..offset + 16],
            stop.entry().stack_bytes()[offset..offset + 16]
        );
        let observed: Vec<_> = inputs.retained_aux().collect();
        for (kind, value, index, bytes) in observed {
            let map = &inputs.mappings()[index];
            assert!(matches!(kind, 7 | 9 | 32 | 33));
            assert!(map.range().contains(&value));
            assert!(!bytes.is_empty());
            assert!(bytes.len() <= 4096);
        }
        let cancelled = stop.cancel().unwrap();
        assert!(cancelled.confirmed);
        assert!(cancelled.kill_requested);
        assert!(receipt.snapshot().confirmed);
    }
    #[test]
    fn initial_input_capture_refuses_stale_context_without_releasing_child() {
        let argv = [std::ffi::OsString::from("stale-input-context")];
        let request = super::super::PreparedExec::new(
            std::path::Path::new("/bin/true"),
            &argv,
            &[],
            None,
            vec![],
        )
        .unwrap();
        let receipt = super::super::CleanupReceipt::default();
        let mut stop = super::super::ExecStop::spawn(request, receipt.clone()).unwrap();
        stop.context.regs.rsp ^= 8;
        assert!(stop.capture_initial_inputs().is_err());
        assert!(!receipt.snapshot().confirmed);
        let cancelled = stop.cancel().unwrap();
        assert!(cancelled.confirmed);
        assert!(receipt.snapshot().confirmed);
    }

    #[test]
    fn initial_input_final_byte_cstring_uses_exact_span_before_unmapped_neighbor() {
        let argv = [std::ffi::OsString::from("final-byte-input-control")];
        let request = super::super::PreparedExec::new(
            std::path::Path::new("/bin/true"),
            &argv,
            &[],
            None,
            vec![],
        )
        .unwrap();
        let receipt = super::super::CleanupReceipt::default();
        let stop = super::super::ExecStop::spawn(request, receipt.clone()).unwrap();
        let outcome = (|| -> Result<()> {
            let maps = parse_maps(&read_maps(&stop)?)?;
            let end = stop
                .context
                .stack_start
                .checked_add(stop.context.stack_bytes.len() as u64)
                .ok_or("stack overflow")?;
            assert!(
                mapping_at(&maps, end).is_err(),
                "control requires actually unmapped stack neighbor"
            );
            assert_eq!(
                stop.context.stack_bytes.last(),
                Some(&0),
                "actual last byte is the CString NUL"
            );
            let mut budget = 0;
            let read = read_request(
                &stop,
                &maps,
                ReadRequest {
                    address: end - 1,
                    kind: ReadKind::CString,
                },
                &mut budget,
            )?;
            assert_eq!(read.owned.bytes, [0]);
            assert_eq!(budget, 1);
            assert_eq!(read.chunks.len(), 1);
            assert_eq!(read.chunks[0].address, end - 1);
            assert_eq!(read.chunks[0].bytes, [0]);
            // Same exact primitive on reconciliation and a retained-aux tail.
            assert_eq!(
                read_exact_span(&stop.task, end - 1, 1)?,
                read.chunks[0].bytes
            );
            assert!(
                read_exact_span(&stop.task, end - 1, 2).is_err(),
                "partial/inaccessible span must refuse"
            );
            unchanged(&stop)?;
            Ok(())
        })();
        let cancelled = stop.cancel().unwrap();
        assert!(cancelled.confirmed);
        assert!(receipt.snapshot().confirmed);
        outcome.unwrap();
    }
    #[test]
    fn initial_input_random16_cross_page_keeps_exact_seven_and_nine_byte_chunks() {
        let argv = [std::ffi::OsString::from("split-random-input-control")];
        let request = super::super::PreparedExec::new(
            std::path::Path::new("/bin/true"),
            &argv,
            &[],
            None,
            vec![],
        )
        .unwrap();
        let receipt = super::super::CleanupReceipt::default();
        let stop = super::super::ExecStop::spawn(request, receipt.clone()).unwrap();
        let outcome = (|| -> Result<()> {
            let maps = parse_maps(&read_maps(&stop)?)?;
            assert!(stop.context.stack_bytes.len() >= 8192);
            let address = stop.context.stack_start + 4096 - 7;
            let mut budget = 0;
            let read = read_request(
                &stop,
                &maps,
                ReadRequest {
                    address,
                    kind: ReadKind::Random16,
                },
                &mut budget,
            )?;
            assert_eq!(budget, 16);
            assert_eq!(read.chunks.len(), 2);
            assert_eq!(read.chunks[0].bytes.len(), 7);
            assert_eq!(read.chunks[1].bytes.len(), 9);
            assert_eq!(read.chunks[0].address, address);
            assert_eq!(read.chunks[1].address, address + 7);
            assert_eq!(read.owned.bytes, stop.context.stack_bytes[4089..4105]);
            assert_eq!(read_exact_span(&stop.task, address, 16)?, read.owned.bytes);
            for chunk in &read.chunks {
                assert_eq!(
                    read_exact_span(&stop.task, chunk.address, chunk.bytes.len())?,
                    chunk.bytes
                );
            }
            unchanged(&stop)?;
            Ok(())
        })();
        let cancelled = stop.cancel().unwrap();
        assert!(cancelled.confirmed);
        assert!(receipt.snapshot().confirmed);
        outcome.unwrap();
    }
}
