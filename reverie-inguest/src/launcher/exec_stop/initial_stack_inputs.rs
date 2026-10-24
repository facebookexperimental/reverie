//! Host-only pure projection of an actual stopped x86-64 initial-stack snapshot.
//! Data parsing is not task/mapping authority. No process memory is accessed here.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;

const MAX_SNAPSHOT: usize = 16 * 1024 * 1024;
const MAX_STRING: usize = 128 * 1024; // Linux MAX_ARG_STRLEN, including NUL.

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum ReadKind {
    CString,
    Random16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ReadRequest {
    pub address: u64,
    pub kind: ReadKind,
}
impl ReadRequest {
    pub fn maximum_bytes(self) -> usize {
        match self.kind {
            ReadKind::CString => MAX_STRING,
            ReadKind::Random16 => 16,
        }
    }
}
/// Actual bounded same-generation read retained by the host. Bytes are evidence
/// supplied by that owner, not authenticated by constructing this data record.
pub(crate) struct OwnedRead {
    pub request: ReadRequest,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Aux {
    pub kind: u64,
    pub value: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Invalid(&'static str),
    Overflow,
    #[cfg(any(test, feature = "loader-private-runtime"))]
    Capacity,
    #[cfg(any(test, feature = "loader-private-runtime"))]
    MissingAux(u64),
    DuplicateAux(u64),
    UnsupportedAux(u64),
    NeedRead(ReadRequest),
    #[cfg(any(test, feature = "loader-private-runtime"))]
    RetainedPointerRequired(Aux),
}

#[derive(Clone, Copy)]
struct Snapshot<'a> {
    base: u64,
    bytes: &'a [u8],
}
impl<'a> Snapshot<'a> {
    fn offset(self, address: u64) -> Result<usize, Error> {
        usize::try_from(address.checked_sub(self.base).ok_or(Error::Overflow)?)
            .map_err(|_| Error::Overflow)
    }
    fn word(self, cursor: &mut usize) -> Result<u64, Error> {
        let end = cursor.checked_add(8).ok_or(Error::Overflow)?;
        let value = self
            .bytes
            .get(*cursor..end)
            .ok_or(Error::Invalid("truncated pointer/aux vector"))?;
        *cursor = end;
        Ok(u64::from_le_bytes(value.try_into().unwrap()))
    }
    fn available(self, address: u64, maximum: usize) -> &'a [u8] {
        let Ok(start) = self.offset(address) else {
            return &[];
        };
        let Some(tail) = self.bytes.get(start..) else {
            return &[];
        };
        &tail[..tail.len().min(maximum)]
    }
}

/// Borrows only the retained host snapshot. Never passed over the wire.
pub(crate) struct ParsedInitial<'a> {
    snapshot: Snapshot<'a>,
    argv: Vec<u64>,
    env: Vec<u64>,
    aux: Vec<Aux>,
    #[cfg(feature = "loader-private-runtime")]
    aux_start: usize,
}
impl<'a> ParsedInitial<'a> {
    pub fn parse(stack_start: u64, stack_bytes: &'a [u8], rsp: u64) -> Result<Self, Error> {
        if stack_bytes.len() > MAX_SNAPSHOT || !rsp.is_multiple_of(8) {
            return Err(Error::Invalid("stack size or initial RSP alignment"));
        }
        stack_start
            .checked_add(u64::try_from(stack_bytes.len()).map_err(|_| Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        let snapshot = Snapshot {
            base: stack_start,
            bytes: stack_bytes,
        };
        let mut cursor = snapshot.offset(rsp)?;
        let argc = usize::try_from(snapshot.word(&mut cursor)?).map_err(|_| Error::Overflow)?;
        // Bound argc and its null before allocating or iterating. The snapshot
        // itself supplies a finite bound; no new small argc/env-count exemption.
        let argv_bytes = argc
            .checked_add(1)
            .and_then(|n| n.checked_mul(8))
            .ok_or(Error::Overflow)?;
        if cursor
            .checked_add(argv_bytes)
            .is_none_or(|end| end > stack_bytes.len())
        {
            return Err(Error::Invalid("argc exceeds retained snapshot"));
        }
        let mut argv = Vec::with_capacity(argc);
        for _ in 0..argc {
            let pointer = snapshot.word(&mut cursor)?;
            if pointer == 0 {
                return Err(Error::Invalid("premature argv NULL"));
            }
            argv.push(pointer);
        }
        if snapshot.word(&mut cursor)? != 0 {
            return Err(Error::Invalid("missing argv NULL"));
        }
        let mut env = Vec::new();
        loop {
            let pointer = snapshot.word(&mut cursor)?;
            if pointer == 0 {
                break;
            }
            env.push(pointer);
        }
        #[cfg(feature = "loader-private-runtime")]
        let aux_start = cursor;
        let mut aux = Vec::new();
        let mut seen = BTreeSet::new();
        loop {
            let kind = snapshot.word(&mut cursor)?;
            let value = snapshot.word(&mut cursor)?;
            if kind == 0 {
                if value != 0 {
                    return Err(Error::Invalid("nonzero AT_NULL value"));
                }
                break;
            }
            if !seen.insert(kind) {
                return Err(Error::DuplicateAux(kind));
            }
            aux.push(Aux { kind, value });
        }
        Ok(Self {
            snapshot,
            argv,
            env,
            aux,
            #[cfg(feature = "loader-private-runtime")]
            aux_start,
        })
    }

    pub fn original_aux(&self) -> &[Aux] {
        &self.aux
    }

    /// Addresses of value words in the actual bounded parsed stack snapshot.
    /// No pointed-to random/string bytes are returned as write destinations.
    #[cfg(feature = "loader-private-runtime")]
    pub(super) fn auxiliary_value_slots(&self) -> impl Iterator<Item = (u64, Aux)> + '_ {
        self.aux.iter().copied().enumerate().map(|(index, aux)| {
            // parse checked the full snapshot address range and read this pair.
            (
                self.snapshot.base + (self.aux_start + index * 16 + 8) as u64,
                aux,
            )
        })
    }
    #[cfg(any(test, feature = "loader-private-runtime"))]
    fn value(&self, kind: u64) -> Result<u64, Error> {
        self.aux
            .iter()
            .find(|a| a.kind == kind)
            .map(|a| a.value)
            .ok_or(Error::MissingAux(kind))
    }

    /// Enumerate missing bounded reads; the caller must perform them under its
    /// actual retained stop/generation authority. There is no read/retry here.
    pub fn read_requests(&self) -> Result<Vec<ReadRequest>, Error> {
        let mut requests = BTreeSet::new();
        for request in self.copy_sources()? {
            match source(self.snapshot, request, &[]) {
                Ok(_) => {}
                Err(Error::NeedRead(request)) => {
                    requests.insert(request);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(requests.into_iter().collect())
    }

    fn copy_sources(&self) -> Result<Vec<ReadRequest>, Error> {
        let mut sources = Vec::new();
        for &address in self.argv.iter().chain(&self.env) {
            sources.push(ReadRequest {
                address,
                kind: ReadKind::CString,
            });
        }
        for aux in &self.aux {
            match aux.kind {
                15 | 24 | 31 => sources.push(ReadRequest {
                    address: aux.value,
                    kind: ReadKind::CString,
                }),
                25 => sources.push(ReadRequest {
                    address: aux.value,
                    kind: ReadKind::Random16,
                }),
                1..=14 | 16 | 17 | 23 | 26..=30 | 32 | 33 | 51 => {}
                _ => return Err(Error::UnsupportedAux(aux.kind)),
            }
        }
        Ok(sources)
    }

    /// Form a private-copy plan. All supplied ELF/read/mapping records are data,
    /// not ownership capabilities: the actual host producer must authenticate
    /// their source, generation, extent/protection and lifetime separately.
    #[cfg(any(test, feature = "loader-private-runtime"))]
    pub fn copy_plan(
        &self,
        image: PrivateImageAux,
        reads: &[OwnedRead],
        retained: &[RetainedAux],
        capacity: usize,
    ) -> Result<PrivateCopyPlan, Error> {
        self.copy_sources()?; // reject unknown aux semantics before projection
        for kind in [3, 4, 5, 6, 11, 12, 13, 14, 16, 23, 25, 31] {
            self.value(kind)?;
        }
        for kind in [11, 12, 13, 14] {
            if self.value(kind)? > u32::MAX as u64 {
                return Err(Error::Invalid("credential width"));
            }
        }
        if self.value(3)? == 0 || self.value(4)? != 56 || self.value(5)? == 0 {
            return Err(Error::Invalid("original ELF program-header facts"));
        }
        if image.phdr == 0
            || !image.phdr.is_multiple_of(8)
            || image.phent != 56
            || image.phnum == 0
            || image.phnum.checked_mul(image.phent) != Some(image.phdr_bytes)
            || image.phdr.checked_add(image.phdr_bytes).is_none()
            || !image.page_size.is_power_of_two()
            || image.page_size != self.value(6)?
        {
            return Err(Error::Invalid("private ELF facts or inherited page size"));
        }
        let mut read_keys = BTreeSet::new();
        let mut total = 0usize;
        for read in reads {
            if !read_keys.insert(read.request) {
                return Err(Error::Invalid("duplicate external read"));
            }
            if read.bytes.len() > read.request.maximum_bytes() {
                return Err(Error::Invalid("unbounded external read"));
            }
            total = total.checked_add(read.bytes.len()).ok_or(Error::Overflow)?;
            if total > MAX_SNAPSHOT {
                return Err(Error::Capacity);
            }
        }
        // Metadata is argc/argv/NULL/envp/NULL/raw aux/AT_NULL pair, contiguous.
        let argv_words = self.argv.len().checked_add(1).ok_or(Error::Overflow)?;
        let env_words = self.env.len().checked_add(1).ok_or(Error::Overflow)?;
        let aux_words = self
            .aux
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_mul(2))
            .ok_or(Error::Overflow)?;
        let metadata = 1usize
            .checked_add(argv_words)
            .and_then(|n| n.checked_add(env_words))
            .and_then(|n| n.checked_add(aux_words))
            .and_then(|n| n.checked_mul(8))
            .ok_or(Error::Overflow)?;
        if capacity > MAX_SNAPSHOT || metadata > capacity {
            return Err(Error::Capacity);
        }
        let mut plan = PrivateCopyPlan {
            bytes: vec![0; metadata],
            relocations: Vec::new(),
            capacity,
            argc: self.argv.len() as u64,
            argv: 8,
            envp: (1 + argv_words) * 8,
            auxv: (1 + argv_words + env_words) * 8,
            program_name: 0,
            program_name_bytes: 0,
            random: 0,
            original_aux: self.aux.clone(),
            private_image: image,
        };
        put(&mut plan.bytes, 0, plan.argc);
        for (index, &address) in self.argv.iter().enumerate() {
            let target = plan.append(source(
                self.snapshot,
                ReadRequest {
                    address,
                    kind: ReadKind::CString,
                },
                reads,
            )?)?;
            plan.relocations.push((8 + index * 8, target));
            if index == 0 {
                plan.program_name = target;
                plan.program_name_bytes = plan.bytes.len() - target;
            }
        }
        for (index, &address) in self.env.iter().enumerate() {
            let target = plan.append(source(
                self.snapshot,
                ReadRequest {
                    address,
                    kind: ReadKind::CString,
                },
                reads,
            )?)?;
            plan.relocations.push((plan.envp + index * 8, target));
        }
        for (index, aux) in self.aux.iter().enumerate() {
            let at = plan.auxv + index * 16;
            put(&mut plan.bytes, at, aux.kind);
            let value = match aux.kind {
                3 => image.phdr,
                4 => image.phent,
                5 => image.phnum,
                15 | 24 | 25 | 31 => {
                    let kind = if aux.kind == 25 {
                        ReadKind::Random16
                    } else {
                        ReadKind::CString
                    };
                    let target = plan.append(source(
                        self.snapshot,
                        ReadRequest {
                            address: aux.value,
                            kind,
                        },
                        reads,
                    )?)?;
                    plan.relocations.push((at + 8, target));
                    if aux.kind == 25 {
                        plan.random = target;
                    }
                    if aux.kind == 31 && self.argv.is_empty() {
                        plan.program_name = target;
                        plan.program_name_bytes = plan.bytes.len() - target;
                    }
                    0 // offset relocation below, never exposed as a placed pointer
                }
                7 | 9 | 32 | 33 if aux.value != 0 => {
                    if !retained.iter().any(|r| {
                        r.aux == *aux
                            && r.start <= aux.value
                            && !r.observed.is_empty()
                            && r.observed.len() <= 4096
                            && aux
                                .value
                                .checked_add(r.observed.len() as u64)
                                .is_some_and(|end| end <= r.end)
                    }) {
                        return Err(Error::RetainedPointerRequired(*aux));
                    }
                    aux.value
                }
                _ => aux.value, // classified scalar or actual inherited null address
            };
            put(&mut plan.bytes, at + 8, value);
        }
        Ok(plan)
    }
}

/// Facts derived from the actual qualified private image, never guest PHDRs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(test, feature = "loader-private-runtime"))]
pub(crate) struct PrivateImageAux {
    pub phdr: u64,
    pub phent: u64,
    pub phnum: u64,
    pub phdr_bytes: u64,
    pub page_size: u64,
}
/// Original child mapping retained by the real owner, not a borrowed host pointer.
/// This geometry does not itself prove ownership, mapping contents or permissions.
pub(crate) struct RetainedAux {
    pub aux: Aux,
    #[cfg(any(test, feature = "loader-private-runtime"))]
    pub start: u64,
    #[cfg(any(test, feature = "loader-private-runtime"))]
    pub end: u64,
    /// Actual bounded same-generation read at aux.value, retained with the
    /// owning mapping ledger. Contents/source qualifications remain external.
    pub observed: Vec<u8>,
}

fn source(
    snapshot: Snapshot<'_>,
    request: ReadRequest,
    reads: &[OwnedRead],
) -> Result<Vec<u8>, Error> {
    if request.address == 0 {
        return Err(Error::Invalid("NULL source pointer"));
    }
    let maximum = request.maximum_bytes();
    request
        .address
        .checked_add(maximum as u64)
        .ok_or(Error::Overflow)?;
    let captured = snapshot.available(request.address, maximum);
    let complete = |data: &[u8]| -> Option<usize> {
        match request.kind {
            ReadKind::Random16 => (data.len() >= 16).then_some(16),
            ReadKind::CString => data.iter().position(|&b| b == 0).map(|i| i + 1),
        }
    };
    if let Some(end) = complete(captured) {
        return Ok(captured[..end].to_vec());
    }
    if captured.len() == maximum {
        return Err(Error::Invalid("unterminated bounded string"));
    }
    let read = reads
        .iter()
        .find(|r| r.request == request)
        .ok_or(Error::NeedRead(request))?;
    if read.bytes.len() > maximum {
        return Err(Error::Invalid("external read exceeds source bound"));
    }
    let read_end = request
        .address
        .checked_add(read.bytes.len() as u64)
        .ok_or(Error::Overflow)?;
    let stack_end = snapshot
        .base
        .checked_add(snapshot.bytes.len() as u64)
        .ok_or(Error::Overflow)?;
    let overlap_start = request.address.max(snapshot.base);
    let overlap_end = read_end.min(stack_end);
    if overlap_start < overlap_end {
        let stack_at =
            usize::try_from(overlap_start - snapshot.base).map_err(|_| Error::Overflow)?;
        let read_at =
            usize::try_from(overlap_start - request.address).map_err(|_| Error::Overflow)?;
        let length = usize::try_from(overlap_end - overlap_start).map_err(|_| Error::Overflow)?;
        if snapshot.bytes[stack_at..stack_at + length] != read.bytes[read_at..read_at + length] {
            return Err(Error::Invalid("read contradicts original stack bytes"));
        }
    }
    let end = complete(&read.bytes).ok_or(Error::Invalid("incomplete external source read"))?;
    Ok(read.bytes[..end].to_vec())
}
#[cfg(any(test, feature = "loader-private-runtime"))]
fn put(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Owned private bytes with internal offset relocations; no guest writes.
#[cfg(any(test, feature = "loader-private-runtime"))]
pub(crate) struct PrivateCopyPlan {
    bytes: Vec<u8>,
    relocations: Vec<(usize, usize)>,
    capacity: usize,
    argc: u64,
    argv: usize,
    envp: usize,
    auxv: usize,
    program_name: usize,
    program_name_bytes: usize,
    random: usize,
    original_aux: Vec<Aux>,
    private_image: PrivateImageAux,
}
#[cfg(any(test, feature = "loader-private-runtime"))]
impl PrivateCopyPlan {
    fn append(&mut self, bytes: Vec<u8>) -> Result<usize, Error> {
        let at = self.bytes.len();
        if at
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.capacity)
        {
            return Err(Error::Capacity);
        }
        self.bytes.extend(bytes);
        Ok(at)
    }
    pub fn place(mut self, base: u64, capacity: u64) -> Result<PlacedInputs, Error> {
        if base == 0 || !base.is_multiple_of(8) || self.bytes.len() as u64 > capacity {
            return Err(Error::Invalid("private placement extent/alignment"));
        }
        base.checked_add(capacity).ok_or(Error::Overflow)?;
        for (word, target) in self.relocations {
            put(
                &mut self.bytes,
                word,
                base.checked_add(target as u64).ok_or(Error::Overflow)?,
            );
        }
        Ok(PlacedInputs {
            argc: self.argc,
            argv: base + self.argv as u64,
            envp: base + self.envp as u64,
            envp_words: (self.auxv - self.envp) as u64 / 8,
            raw_aux: base + self.auxv as u64,
            raw_aux_words: (self.original_aux.len() as u64 + 1) * 2,
            program_name: base + self.program_name as u64,
            program_name_bytes: self.program_name_bytes as u64,
            random: base + self.random as u64,
            bytes: self.bytes,
            original_aux: self.original_aux,
            private_image: self.private_image,
        })
    }
}
/// Pure data to join into the scalar handoff after actual host mapping/sealing.
/// Physical ownership, guards, lifetime and write/seal operations remain external.
#[cfg(any(test, feature = "loader-private-runtime"))]
pub(crate) struct PlacedInputs {
    pub bytes: Vec<u8>,
    pub argc: u64,
    pub argv: u64,
    pub envp: u64,
    pub envp_words: u64,
    pub raw_aux: u64,
    pub raw_aux_words: u64,
    pub program_name: u64,
    pub program_name_bytes: u64,
    pub random: u64,
    pub original_aux: Vec<Aux>,
    pub private_image: PrivateImageAux,
}

#[cfg(test)]
mod tests {
    use super::*;
    const STACK: u64 = 0x7000;
    const PRIVATE: u64 = 0x6000_e300_1000;
    fn aux() -> Vec<Aux> {
        [
            (3, 0x400040),
            (4, 56),
            (5, 4),
            (6, 4096),
            (7, 0x7f00_0000),
            (9, 0x400000),
            (11, 1001),
            (12, 0),
            (13, 1002),
            (14, 0),
            (15, STACK + 1080),
            (16, 0xffff_ffff_8000_0000),
            (23, 1),
            (24, STACK + 1100),
            (25, STACK + 1120),
            (26, 0x8000_0000_0000_0001),
            (31, STACK + 1152),
            (33, 0x7f10_0000),
            (51, 11952),
        ]
        .into_iter()
        .map(|(kind, value)| Aux { kind, value })
        .collect()
    }
    fn fixture(aux: &[Aux]) -> Vec<u8> {
        let mut bytes = vec![0xcc; 4096];
        let mut words = vec![1, STACK + 1024, 0, STACK + 1040, 0];
        for pair in aux {
            words.extend([pair.kind, pair.value]);
        }
        words.extend([0, 0]);
        for (i, word) in words.into_iter().enumerate() {
            put(&mut bytes, i * 8, word);
        }
        for (at, string) in [
            (1024, b"prog\0".as_slice()),
            (1040, b"X=Y\0"),
            (1080, b"x86_64\0"),
            (1100, b"real-cpu\0"),
            (1152, b"/bin/prog\0"),
        ] {
            bytes[at..at + string.len()].copy_from_slice(string);
        }
        for i in 0..16 {
            bytes[1120 + i] = (i * 17) as u8;
        }
        bytes
    }
    fn image() -> PrivateImageAux {
        PrivateImageAux {
            phdr: 0x6000_e100_0040,
            phent: 56,
            phnum: 4,
            phdr_bytes: 224,
            page_size: 4096,
        }
    }
    fn retained() -> Vec<RetainedAux> {
        aux()
            .into_iter()
            .filter(|a| matches!(a.kind, 7 | 9 | 33))
            .map(|aux| RetainedAux {
                start: aux.value,
                end: aux.value + 4096,
                aux,
                observed: vec![0x90],
            })
            .collect()
    }
    fn value(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn private_vectors_aux_and_entropy_preserve_real_source_without_guest_writes() {
        let original = aux();
        let bytes = fixture(&original);
        let before = bytes.clone();
        let parsed = ParsedInitial::parse(STACK, &bytes, STACK).unwrap();
        assert!(parsed.read_requests().unwrap().is_empty());
        let placed = parsed
            .copy_plan(image(), &[], &retained(), 4096)
            .unwrap()
            .place(PRIVATE, 4096)
            .unwrap();
        assert_eq!(bytes, before);
        assert_eq!(placed.argc, 1);
        assert_eq!(placed.original_aux, original);
        assert_eq!(placed.raw_aux, placed.envp + placed.envp_words * 8);
        assert_eq!(
            value(&placed.bytes, (placed.raw_aux - PRIVATE) as usize - 8),
            0
        );
        assert_eq!(value(&placed.bytes, 0), 1);
        let program = (placed.program_name - PRIVATE) as usize;
        assert_eq!(&placed.bytes[program..program + 5], b"prog\0");
        let random = (placed.random - PRIVATE) as usize;
        assert_eq!(&placed.bytes[random..random + 16], &before[1120..1136]);
        for (i, original) in original.iter().enumerate() {
            let at = (placed.raw_aux - PRIVATE) as usize + i * 16;
            assert_eq!(value(&placed.bytes, at), original.kind);
            let private = value(&placed.bytes, at + 8);
            match original.kind {
                3 => assert_eq!(private, image().phdr),
                4 => assert_eq!(private, image().phent),
                5 => assert_eq!(private, image().phnum),
                15 | 24 | 25 | 31 => {
                    assert!((PRIVATE..PRIVATE + placed.bytes.len() as u64).contains(&private))
                }
                _ => assert_eq!(private, original.value), // includes secure unequal credentials/high HWCAPs
            }
        }
        let end = (placed.raw_aux - PRIVATE) as usize + (placed.raw_aux_words as usize - 2) * 8;
        assert_eq!(&placed.bytes[end..end + 16], &[0; 16]);
        assert!(placed.argv >= PRIVATE);
        assert_eq!(placed.private_image, image());
    }

    #[test]
    fn empty_vectors_use_actual_execfn_without_inventing_an_argument() {
        let original = aux();
        let mut bytes = fixture(&original);
        let mut words = vec![0, 0, 0]; // actual argc0, argv NULL, envp NULL
        for pair in &original {
            words.extend([pair.kind, pair.value]);
        }
        words.extend([0, 0]);
        for (i, word) in words.into_iter().enumerate() {
            put(&mut bytes, i * 8, word);
        }
        let parsed = ParsedInitial::parse(STACK, &bytes, STACK).unwrap();
        let placed = parsed
            .copy_plan(image(), &[], &retained(), 4096)
            .unwrap()
            .place(PRIVATE, 4096)
            .unwrap();
        assert_eq!(placed.argc, 0);
        assert_eq!(placed.envp_words, 1);
        assert_eq!(value(&placed.bytes, (placed.argv - PRIVATE) as usize), 0);
        let at = (placed.program_name - PRIVATE) as usize;
        assert_eq!(
            &placed.bytes[at..at + placed.program_name_bytes as usize],
            b"/bin/prog\0"
        );
    }

    #[test]
    fn malformed_argv_env_aux_and_duplicate_are_refused() {
        let mut bytes = fixture(&aux());
        put(&mut bytes, 16, 123);
        assert!(matches!(
            ParsedInitial::parse(STACK, &bytes, STACK),
            Err(Error::Invalid("missing argv NULL"))
        ));
        put(&mut bytes, 16, 0);
        put(&mut bytes, 8, 0);
        assert!(matches!(
            ParsedInitial::parse(STACK, &bytes, STACK),
            Err(Error::Invalid("premature argv NULL"))
        ));
        let mut duplicate = aux();
        duplicate.push(duplicate[0]);
        assert!(matches!(
            ParsedInitial::parse(STACK, &fixture(&duplicate), STACK),
            Err(Error::DuplicateAux(3))
        ));
        let words = [0_u64, 0, 1, 1];
        let incomplete: Vec<u8> = words.into_iter().flat_map(u64::to_le_bytes).collect();
        assert!(ParsedInitial::parse(STACK, &incomplete, STACK).is_err());
        let mut bytes = fixture(&aux());
        let at_null = (5 + aux().len() * 2) * 8;
        put(&mut bytes, at_null + 8, 1);
        assert!(matches!(
            ParsedInitial::parse(STACK, &bytes, STACK),
            Err(Error::Invalid("nonzero AT_NULL value"))
        ));
    }

    #[test]
    fn missing_security_random_and_unknown_aux_are_not_defaulted() {
        for missing in [11, 12, 13, 14, 16, 23, 25, 31] {
            let list: Vec<Aux> = aux().into_iter().filter(|a| a.kind != missing).collect();
            let bytes = fixture(&list);
            let parsed = ParsedInitial::parse(STACK, &bytes, STACK).unwrap();
            assert!(
                matches!(parsed.copy_plan(image(), &[], &retained(), 4096), Err(Error::MissingAux(k)) if k == missing)
            );
        }
        let mut list = aux();
        list.push(Aux {
            kind: 1000,
            value: 0,
        });
        let bytes = fixture(&list);
        let parsed = ParsedInitial::parse(STACK, &bytes, STACK).unwrap();
        assert_eq!(parsed.read_requests(), Err(Error::UnsupportedAux(1000)));
    }

    #[test]
    fn outside_strings_require_exact_bounded_host_read_and_do_not_drop_environment() {
        let mut bytes = fixture(&aux());
        put(&mut bytes, 24, 0x9000);
        let parsed = ParsedInitial::parse(STACK, &bytes, STACK).unwrap();
        let request = ReadRequest {
            address: 0x9000,
            kind: ReadKind::CString,
        };
        assert_eq!(parsed.read_requests(), Ok(vec![request]));
        assert!(
            matches!(parsed.copy_plan(image(), &[], &retained(), 4096), Err(Error::NeedRead(r)) if r == request)
        );
        let reads = [OwnedRead {
            request,
            bytes: b"REAL=outside\0".to_vec(),
        }];
        let placed = parsed
            .copy_plan(image(), &reads, &retained(), 4096)
            .unwrap()
            .place(PRIVATE, 4096)
            .unwrap();
        let env = value(&placed.bytes, (placed.envp - PRIVATE) as usize);
        assert_eq!(
            &placed.bytes[(env - PRIVATE) as usize..][..13],
            b"REAL=outside\0"
        );
    }

    #[test]
    fn outside_random_and_snapshot_overlap_cannot_be_fabricated() {
        let mut list = aux();
        list.iter_mut().find(|a| a.kind == 25).unwrap().value = STACK + 4090;
        let bytes = fixture(&list);
        let parsed = ParsedInitial::parse(STACK, &bytes, STACK).unwrap();
        let request = ReadRequest {
            address: STACK + 4090,
            kind: ReadKind::Random16,
        };
        assert_eq!(parsed.read_requests(), Ok(vec![request]));
        let mut data = vec![0xcc; 16];
        data[0] = 1;
        assert!(matches!(
            parsed.copy_plan(
                image(),
                &[OwnedRead {
                    request,
                    bytes: data
                }],
                &retained(),
                4096
            ),
            Err(Error::Invalid("read contradicts original stack bytes"))
        ));
        let mut data = vec![0xcc; 16];
        data[6..].copy_from_slice(&[9; 10]);
        let placed = parsed
            .copy_plan(
                image(),
                &[OwnedRead {
                    request,
                    bytes: data.clone(),
                }],
                &retained(),
                4096,
            )
            .unwrap()
            .place(PRIVATE, 4096)
            .unwrap();
        assert_eq!(
            &placed.bytes[(placed.random - PRIVATE) as usize..][..16],
            data.as_slice()
        );
    }

    #[test]
    fn unretained_guest_mapping_pointers_and_wrong_private_image_are_refused() {
        let bytes = fixture(&aux());
        let parsed = ParsedInitial::parse(STACK, &bytes, STACK).unwrap();
        assert!(matches!(
            parsed.copy_plan(image(), &[], &[], 4096),
            Err(Error::RetainedPointerRequired(Aux { kind: 7, .. }))
        ));
        let mut wrong = image();
        wrong.page_size = 8192;
        assert!(matches!(
            parsed.copy_plan(wrong, &[], &retained(), 4096),
            Err(Error::Invalid(_))
        ));
        wrong = image();
        wrong.phdr_bytes -= 1;
        assert!(matches!(
            parsed.copy_plan(wrong, &[], &retained(), 4096),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn arithmetic_capacity_alignment_and_bounded_termination_refused() {
        let mut bytes = fixture(&aux());
        put(&mut bytes, 0, u64::MAX);
        assert!(ParsedInitial::parse(STACK, &bytes, STACK).is_err());
        assert!(matches!(
            ParsedInitial::parse(u64::MAX - 7, &[0; 16], u64::MAX - 7),
            Err(Error::Overflow)
        ));
        assert!(ParsedInitial::parse(STACK, &[0; 16], STACK + 1).is_err());
        let bytes = fixture(&aux());
        let parsed = ParsedInitial::parse(STACK, &bytes, STACK).unwrap();
        assert!(matches!(
            parsed.copy_plan(image(), &[], &retained(), 8),
            Err(Error::Capacity)
        ));
        assert!(matches!(
            parsed
                .copy_plan(image(), &[], &retained(), 4096)
                .unwrap()
                .place(u64::MAX - 7, 4096),
            Err(Error::Overflow)
        ));
        let snapshot = Snapshot {
            base: STACK,
            bytes: &[1; MAX_STRING],
        };
        assert_eq!(
            source(
                snapshot,
                ReadRequest {
                    address: STACK,
                    kind: ReadKind::CString
                },
                &[]
            ),
            Err(Error::Invalid("unterminated bounded string"))
        );
        assert_eq!(
            source(
                snapshot,
                ReadRequest {
                    address: u64::MAX - 1,
                    kind: ReadKind::Random16
                },
                &[]
            ),
            Err(Error::Overflow)
        );
    }
}
