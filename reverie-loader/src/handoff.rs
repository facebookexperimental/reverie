//! Scalar first-image input codec. Numeric validation is not physical authority.
//! This module allocates nothing, dereferences no numeric address and invokes
//! no syscall. All integers are x86-64 little-endian, including digest words.
//! Views borrow retained bytes; no native struct or enum is cast from bytes.

use core::num::NonZeroUsize;

// Fixed local record construction; const evaluation creates no runtime panic.
const WORD_STRIDE: NonZeroUsize = NonZeroUsize::new(8).unwrap();

/// Wire discriminator, distinct from the ordinary HLNI packet.
pub const MAGIC: u64 = u64::from_le_bytes(*b"HLSCAL01");
/// Only supported wire revision. This unpublished candidate replaces the earlier
/// unpublished117-word candidate; no deployed wire compatibility is claimed.
pub const VERSION: u64 = 1;
/// Fixed header length, in u64 words.
pub const HEADER_WORDS: usize = 120;
/// Fixed header length in bytes.
pub const HEADER_BYTES: usize = HEADER_WORDS * 8;
/// Maximum complete handoff blob (private strings included).
pub const MAX_BYTES: usize = 1024 * 1024;

/// Host-side record shape; serialize each word explicitly with `to_le_bytes`.
/// Never copy struct padding or transmute this structure into a guest reference.
#[repr(C)]
pub struct Header {
    /// Magic, version, total bytes, header bytes, four zero reserved words.
    pub prefix: [u64; 8],
    /// Launch, loader, runtime, source and layout SHA256 values as four LE words.
    pub binding: [[u64; 4]; 5],
    /// Complete guarded stack, TLS, signal stack, handoff and state extents.
    pub roles: [Extent; 5],
    /// Exact Linux x86-64 27-register word order (see `Registers`).
    pub registers: [u64; 27],
    /// TID, control addr/size, relay addr/size, fd, PKRU, mask, TCB, handler,
    /// independent gate reference addr/size, GNU stack bytes, actual final-ELF dev-null address, two zero words.
    pub scalars: [u64; 16],
    /// Maps, code, relay sites, HLNI packet, envp words, raw aux words,
    /// program-name bytes, dev-null bytes and exact ToolInit post-syscall PCs;
    /// offsets relative to blob start. Table8 contains sorted unique LEu64 PCs.
    pub tables: [Table; 9],
    /// Private final PHDR addr/entry-size/count, TLS image/file/memory/alignment,
    /// dedicated TLS backing addr/bytes, load addr/memory-bytes/file-bytes.
    pub tls: [u64; 12],
}
/// One scalar half-open address interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Extent {
    /// Inclusive first byte.
    pub start: u64,
    /// Exclusive end, not a byte length.
    pub end: u64,
}
impl Extent {
    /// Checked byte interval containment; permits an empty range at the end.
    pub fn contains(self, address: u64, bytes: u64) -> bool {
        self.start <= address
            && address
                .checked_add(bytes)
                .is_some_and(|end| end <= self.end)
    }
    fn interior(self) -> Result<Self, Error> {
        let start = self.start.checked_add(4096).ok_or(Error::Bounds)?;
        let end = self.end.checked_sub(4096).ok_or(Error::Bounds)?;
        if start >= end {
            return Err(Error::Bounds);
        }
        Ok(Self { start, end })
    }
}
/// A bounded array inside the immutable handoff blob.
#[repr(C)]
pub struct Table {
    /// Blob-relative first byte.
    pub offset: u64,
    /// Record count, or byte count for a byte table.
    pub count: u64,
    /// Exact record byte size, not caller-selected native `size_of`.
    pub stride: u64,
}
/// Exact observed mapping ledger record.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Map {
    /// Actual inclusive mapped page boundary.
    pub start: u64,
    /// Actual exclusive mapped page boundary.
    pub end: u64,
    /// Exact Linux PROT bits.
    pub protection: u64,
    /// Exact observed producer flags; never rewritten by the decoder.
    pub flags: u64,
}
/// Executable interval from the authenticated final image.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Code {
    /// Inclusive first executable byte.
    pub start: u64,
    /// Exclusive executable byte boundary.
    pub end: u64,
}
/// Source-qualified syscall tuple, using a numeric role rather than an enum ABI.
#[repr(C)]
pub struct SiteRecord {
    /// Address of the real 0f05 instruction.
    pub syscall_ip: u64,
    /// Exact following instruction address.
    pub return_ip: u64,
    /// Real syscall number.
    pub number: u64,
    /// Role: 1 SET_FS, 2 set_tid_address, 3 secure poll, 4 secure open.
    pub operation: u64,
}
/// A checked local Rust operation; never serialized or cast from memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Source-qualified musl __init_tp FS setter.
    SetFs,
    /// Source-qualified musl __init_tp clear-tid setter.
    SetTid,
    /// Source-qualified secure libc poll.
    SecurePoll,
    /// Source-qualified secure libc open.
    SecureOpen,
}
/// A decoded syscall site, not an IP bypass capability.
#[derive(Clone, Copy, Debug)]
pub struct Site {
    /// Actual syscall instruction address.
    pub syscall_ip: u64,
    /// Actual return instruction address.
    pub return_ip: u64,
    /// Actual syscall number.
    pub number: u64,
    /// Checked operation role.
    pub operation: Operation,
}
/// Malformed scalar data; no refusal grants fallback or guest release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Unsupported discriminator/revision or fixed layout.
    Format,
    /// Nonzero reserved word.
    Reserved,
    /// Arithmetic overflow, truncation, alignment, overlap or capacity failure.
    Bounds,
    /// Invalid mapping, role, register-independent scalar or operation.
    Value,
}
#[inline]
fn word(bytes: &[u8], index: usize) -> Result<u64, Error> {
    let offset = index.checked_mul(8).ok_or(Error::Bounds)?;
    let value = bytes
        .get(offset..offset.checked_add(8).ok_or(Error::Bounds)?)
        .ok_or(Error::Bounds)?;
    Ok(u64::from_le_bytes(
        value.try_into().map_err(|_| Error::Bounds)?,
    ))
}
// Deliberately scalar: keep the pre-TLS codec independent of a slice-search
// implementation. This is syntax validation, not a source/machine proof.
#[inline]
fn has_zero(bytes: &[u8]) -> Result<bool, Error> {
    let mut index = 0usize;
    while index < bytes.len() {
        if *bytes.get(index).ok_or(Error::Bounds)? == 0 {
            return Ok(true);
        }
        index = index.checked_add(1).ok_or(Error::Bounds)?;
    }
    Ok(false)
}
/// A bounded immutable scalar table. Values are copied, never referenced as a
/// compiler-dependent record. A lifetime cannot outlive the retained byte slice.
#[derive(Clone, Copy)]
pub struct Records<'a> {
    bytes: &'a [u8],
    stride: NonZeroUsize,
}
impl<'a> Records<'a> {
    // All variable-stride storage enters here. A zero wire/private stride is a
    // scalar Bounds error before a Records value can be observed or divided.
    fn new(bytes: &'a [u8], stride: usize) -> Result<Self, Error> {
        let stride = NonZeroUsize::new(stride).ok_or(Error::Bounds)?;
        Ok(Self { bytes, stride })
    }

    /// Actual record count.
    pub fn len(self) -> usize {
        self.bytes.len() / self.stride.get()
    }
    /// Whether no records exist.
    pub fn is_empty(self) -> bool {
        self.bytes.is_empty()
    }
    /// Original immutable byte representation for physical range checks.
    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Checked scalar field of one record.
    #[inline]
    pub fn field(self, index: usize, field: usize) -> Result<u64, Error> {
        let count = self.len();
        let words = self.stride.get() / 8;
        if index >= count || field >= words {
            return Err(Error::Bounds);
        }
        let offset = index.checked_mul(words).ok_or(Error::Bounds)?;
        word(self.bytes, offset.checked_add(field).ok_or(Error::Bounds)?)
    }
}
/// Borrowed original register words; native registers must be decoded by value.
#[derive(Clone, Copy)]
pub struct Registers<'a>(Records<'a>);
impl<'a> Registers<'a> {
    /// Original immutable 216-byte register source.
    pub fn bytes(self) -> &'a [u8] {
        self.0.bytes()
    }
    /// Exact codec: r15,r14,r13,r12,rbp,rbx,r11,r10,r9,r8,rax,rcx,rdx,rsi,
    /// rdi,orig_rax,rip,cs,eflags,rsp,ss,fs_base,gs_base,ds,es,fs,gs.
    pub fn words(self) -> Result<[u64; 27], Error> {
        let mut result = [0; 27];
        let mut i = 0usize;
        while i < result.len() {
            *result.get_mut(i).ok_or(Error::Bounds)? = self.0.field(i, 0)?;
            i = i.checked_add(1).ok_or(Error::Bounds)?;
        }
        Ok(result)
    }
    /// Original FS value, not the host's current FS.
    pub fn fs_base(self) -> Result<u64, Error> {
        self.0.field(21, 0)
    }
    /// Original guest instruction pointer.
    pub fn rip(self) -> Result<u64, Error> {
        self.0.field(16, 0)
    }
    /// Original guest stack pointer.
    pub fn rsp(self) -> Result<u64, Error> {
        self.0.field(19, 0)
    }
}
/// Bounded bootstrap data from the SAME immutable scalar wire, not full validation.
///
/// This projection checks consumed header/table shapes and native narrowing only.
/// It does not authenticate represented addresses, mappings, source code, kernel
/// state or ownership. The complete host predicate and unchanged post-libc View
/// validation remain required before any actual bootstrap consumer may rely on
/// them. Numeric addresses are never dereferenced here. Unconsumed tables7/8 and
/// semantic role/map/env/aux/site-order checks are deliberately not a second View.
#[derive(Clone, Copy)]
pub struct Bootstrap<'a> {
    bytes: &'a [u8],
    address: u64,
}
#[derive(Clone, Copy)]
struct BootstrapTable {
    offset: usize,
    count: usize,
    stride: usize,
    end: usize,
}
impl<'a> Bootstrap<'a> {
    /// Project bounded data; success grants no capture or execution authority.
    /// `address` represents the child blob, not necessarily this slice's pointer.
    pub fn project(bytes: &'a [u8], address: u64) -> Result<Self, Error> {
        if bytes.len() < HEADER_BYTES
            || bytes.len() > MAX_BYTES
            || !address.is_multiple_of(8)
            || word(bytes, 0)? != MAGIC
            || word(bytes, 1)? != VERSION
            || word(bytes, 2)? != bytes.len() as u64
            || word(bytes, 3)? != HEADER_BYTES as u64
        {
            return Err(Error::Format);
        }
        usize::try_from(address).map_err(|_| Error::Bounds)?;
        let end = address
            .checked_add(bytes.len() as u64)
            .ok_or(Error::Bounds)?;
        usize::try_from(end).map_err(|_| Error::Bounds)?;
        for index in [4, 5, 6, 7, 79, 80] {
            if word(bytes, index)? != 0 {
                return Err(Error::Reserved);
            }
        }
        let this = Self { bytes, address };
        let mut index = 0usize;
        while index < 7 {
            let current = this.descriptor(index)?;
            let mut earlier = 0usize;
            while earlier < index {
                let other = this.descriptor(earlier)?;
                if current.offset < other.end && other.offset < current.end {
                    return Err(Error::Bounds);
                }
                earlier = earlier.checked_add(1).ok_or(Error::Bounds)?;
            }
            index = index.checked_add(1).ok_or(Error::Bounds)?;
        }
        let env = this.descriptor(4)?;
        let aux = this.descriptor(5)?;
        this.env_aux_words()?;
        if env.end != aux.offset {
            return Err(Error::Bounds);
        }
        // Native widths are checked without giving these values pointer or
        // owner authority. Full scalar semantics remain the complete predicate.
        for index in 0..5 {
            this.role(index)?;
        }
        for index in 0..16 {
            this.scalar(index)?;
        }
        for index in 0..12 {
            this.tls(index)?;
        }
        for index in [16, 19, 21] {
            let register = word(bytes, 38usize.checked_add(index).ok_or(Error::Bounds)?)?;
            usize::try_from(register).map_err(|_| Error::Bounds)?;
        }
        Ok(this)
    }
    // Only the seven consumed fixed shapes can enter this private helper. No
    // permissive table/Records constructor is exported by Bootstrap.
    fn descriptor(self, index: usize) -> Result<BootstrapTable, Error> {
        let (stride, max) = match index {
            0 => (32, 64),
            1 => (16, 64),
            2 => (32, 128),
            3 | 6 => (1, 4096),
            4 | 5 => (8, 512),
            _ => return Err(Error::Bounds),
        };
        let base = index
            .checked_mul(3)
            .and_then(|n| n.checked_add(81))
            .ok_or(Error::Bounds)?;
        let offset = usize::try_from(word(self.bytes, base)?).map_err(|_| Error::Bounds)?;
        let count = usize::try_from(word(self.bytes, base.checked_add(1).ok_or(Error::Bounds)?)?)
            .map_err(|_| Error::Bounds)?;
        if word(self.bytes, base.checked_add(2).ok_or(Error::Bounds)?)? != stride as u64
            || count == 0
            || count > max
            || offset < HEADER_BYTES
            || !offset.is_multiple_of(8)
        {
            return Err(Error::Bounds);
        }
        let end = offset
            .checked_add(count.checked_mul(stride).ok_or(Error::Bounds)?)
            .ok_or(Error::Bounds)?;
        self.bytes.get(offset..end).ok_or(Error::Bounds)?;
        Ok(BootstrapTable {
            offset,
            count,
            stride,
            end,
        })
    }
    fn table_bytes(self, index: usize) -> Result<&'a [u8], Error> {
        let table = self.descriptor(index)?;
        self.bytes.get(table.offset..table.end).ok_or(Error::Bounds)
    }
    fn record(self, table: usize, index: usize) -> Result<&'a [u8], Error> {
        let table = self.descriptor(table)?;
        if index >= table.count {
            return Err(Error::Bounds);
        }
        let start = table
            .offset
            .checked_add(index.checked_mul(table.stride).ok_or(Error::Bounds)?)
            .ok_or(Error::Bounds)?;
        let end = start.checked_add(table.stride).ok_or(Error::Bounds)?;
        self.bytes.get(start..end).ok_or(Error::Bounds)
    }
    /// Original retained bytes, including unconsumed data for later full parse.
    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Represented blob address; not authenticated pointer provenance.
    pub fn address(self) -> u64 {
        self.address
    }
    /// Original digest words; data, not an authenticated source binding.
    pub fn binding(self, index: usize) -> Result<[u64; 4], Error> {
        if index >= 5 {
            return Err(Error::Bounds);
        }
        let base = index
            .checked_mul(4)
            .and_then(|n| n.checked_add(8))
            .ok_or(Error::Bounds)?;
        let mut out = [0; 4];
        let mut field = 0usize;
        while field < 4 {
            *out.get_mut(field).ok_or(Error::Bounds)? =
                word(self.bytes, base.checked_add(field).ok_or(Error::Bounds)?)?;
            field = field.checked_add(1).ok_or(Error::Bounds)?;
        }
        Ok(out)
    }
    /// Guarded-role numeric interval, with native-width conversion checked.
    pub fn role(self, index: usize) -> Result<Extent, Error> {
        if index >= 5 {
            return Err(Error::Bounds);
        }
        let base = index
            .checked_mul(2)
            .and_then(|n| n.checked_add(28))
            .ok_or(Error::Bounds)?;
        let start = word(self.bytes, base)?;
        let end = word(self.bytes, base.checked_add(1).ok_or(Error::Bounds)?)?;
        usize::try_from(start).map_err(|_| Error::Bounds)?;
        usize::try_from(end).map_err(|_| Error::Bounds)?;
        Ok(Extent { start, end })
    }
    /// Original immutable register representation; no native register cast.
    pub fn registers(self) -> Result<Registers<'a>, Error> {
        let bytes = self.bytes.get(38 * 8..65 * 8).ok_or(Error::Bounds)?;
        Ok(Registers(Records::new(bytes, 8)?))
    }
    /// Fixed scalar value, including checked native owner/fd/PKRU widths.
    pub fn scalar(self, index: usize) -> Result<u64, Error> {
        if index >= 16 {
            return Err(Error::Bounds);
        }
        let value = word(self.bytes, index.checked_add(65).ok_or(Error::Bounds)?)?;
        match index {
            0 | 5 => {
                i32::try_from(value).map_err(|_| Error::Value)?;
            }
            6 => {
                u32::try_from(value).map_err(|_| Error::Value)?;
            }
            1..=4 | 8..=13 => {
                usize::try_from(value).map_err(|_| Error::Bounds)?;
            }
            _ => {}
        }
        Ok(value)
    }
    /// Original TLS header value, checked for the target native width.
    pub fn tls(self, index: usize) -> Result<u64, Error> {
        if index >= 12 {
            return Err(Error::Bounds);
        }
        let value = word(self.bytes, index.checked_add(108).ok_or(Error::Bounds)?)?;
        usize::try_from(value).map_err(|_| Error::Bounds)?;
        Ok(value)
    }
    /// Bounded original map count, never an observed-kernel ledger claim.
    pub fn map_count(self) -> Result<usize, Error> {
        Ok(self.descriptor(0)?.count)
    }
    /// Exact immutable map source bytes.
    pub fn map_bytes(self) -> Result<&'a [u8], Error> {
        self.table_bytes(0)
    }
    /// One map by value; protection, geometry and physical identity are not proved.
    pub fn map(self, index: usize) -> Result<Map, Error> {
        let row = self.record(0, index)?;
        let start = word(row, 0)?;
        let end = word(row, 1)?;
        usize::try_from(start).map_err(|_| Error::Bounds)?;
        usize::try_from(end).map_err(|_| Error::Bounds)?;
        Ok(Map {
            start,
            end,
            protection: word(row, 2)?,
            flags: word(row, 3)?,
        })
    }
    /// Bounded original executable-interval count.
    pub fn code_count(self) -> Result<usize, Error> {
        Ok(self.descriptor(1)?.count)
    }
    /// Exact immutable code-interval source bytes.
    pub fn code_bytes(self) -> Result<&'a [u8], Error> {
        self.table_bytes(1)
    }
    /// One numeric code interval, not source or instruction qualification.
    pub fn code(self, index: usize) -> Result<Code, Error> {
        let row = self.record(1, index)?;
        let start = word(row, 0)?;
        let end = word(row, 1)?;
        usize::try_from(start).map_err(|_| Error::Bounds)?;
        usize::try_from(end).map_err(|_| Error::Bounds)?;
        Ok(Code { start, end })
    }
    /// Bounded original bootstrap-site count, including multiple sites per role.
    pub fn site_count(self) -> Result<usize, Error> {
        Ok(self.descriptor(2)?.count)
    }
    /// Exact immutable bootstrap-site source bytes.
    pub fn site_bytes(self) -> Result<&'a [u8], Error> {
        self.table_bytes(2)
    }
    /// Decode the exact four local operation/number pairs and instruction length.
    /// No ordering, source, code coverage or physical instruction proof follows.
    pub fn site(self, index: usize) -> Result<Site, Error> {
        let row = self.record(2, index)?;
        let number = word(row, 2)?;
        let operation = match (word(row, 3)?, number) {
            (1, 158) => Operation::SetFs,
            (2, 218) => Operation::SetTid,
            (3, 7) => Operation::SecurePoll,
            (4, 2) => Operation::SecureOpen,
            _ => return Err(Error::Value),
        };
        let syscall_ip = word(row, 0)?;
        let return_ip = word(row, 1)?;
        usize::try_from(syscall_ip).map_err(|_| Error::Bounds)?;
        usize::try_from(return_ip).map_err(|_| Error::Bounds)?;
        if syscall_ip.checked_add(2) != Some(return_ip) {
            return Err(Error::Value);
        }
        Ok(Site {
            syscall_ip,
            return_ip,
            number,
            operation,
        })
    }
    /// Original packet bytes; neither HLIINIT1 admission nor ownership is proved.
    pub fn packet(self) -> Result<&'a [u8], Error> {
        self.table_bytes(3)
    }
    /// Represented start of the bounded envp array, never dereferenced here.
    pub fn envp_address(self) -> Result<u64, Error> {
        self.address
            .checked_add(self.descriptor(4)?.offset as u64)
            .ok_or(Error::Bounds)
    }
    /// Combined bounded env/aux words. Values and secure credentials are unproved.
    pub fn env_aux_words(self) -> Result<usize, Error> {
        let count = self
            .descriptor(4)?
            .count
            .checked_add(self.descriptor(5)?.count)
            .ok_or(Error::Bounds)?;
        if count > 512 {
            return Err(Error::Value);
        }
        Ok(count)
    }
    /// Represented start of program-name bytes; termination remains full validation.
    pub fn program_name_address(self) -> Result<u64, Error> {
        self.address
            .checked_add(self.descriptor(6)?.offset as u64)
            .ok_or(Error::Bounds)
    }
}

/// Parsed permanent input bytes. This is data validation, NOT an owner or Ready.
#[derive(Clone, Copy)]
pub struct View<'a> {
    bytes: &'a [u8],
    address: u64,
}
impl<'a> View<'a> {
    /// Check fixed syntax and all table ranges; `address` is the claimed actual
    /// mapped blob address, supplied by the physical caller, never trusted here.
    pub fn parse(bytes: &'a [u8], address: u64) -> Result<Self, Error> {
        if bytes.len() < HEADER_BYTES
            || bytes.len() > MAX_BYTES
            || !address.is_multiple_of(8)
            || word(bytes, 0)? != MAGIC
            || word(bytes, 1)? != VERSION
            || word(bytes, 2)? != bytes.len() as u64
            || word(bytes, 3)? != HEADER_BYTES as u64
        {
            return Err(Error::Format);
        }
        address
            .checked_add(bytes.len() as u64)
            .ok_or(Error::Bounds)?;
        let reserved = [4, 5, 6, 7, 79, 80];
        let mut reserved_index = 0usize;
        while reserved_index < reserved.len() {
            if word(bytes, *reserved.get(reserved_index).ok_or(Error::Bounds)?)? != 0 {
                return Err(Error::Reserved);
            }
            reserved_index = reserved_index.checked_add(1).ok_or(Error::Bounds)?;
        }
        let this = Self { bytes, address };
        let limits = [
            (32, 64),
            (16, 64),
            (32, 128),
            (1, 4096),
            (8, 512),
            (8, 512),
            (1, 4096),
            (1, 10),
            (8, 4096),
        ];
        let mut ends = [(0, 0); 9];
        let mut i = 0usize;
        while i < limits.len() {
            let (stride, max) = *limits.get(i).ok_or(Error::Bounds)?;
            let base = i
                .checked_mul(3)
                .and_then(|n| n.checked_add(81))
                .ok_or(Error::Bounds)?;
            let (offset, count, actual_stride) = (
                word(bytes, base)?,
                word(bytes, base.checked_add(1).ok_or(Error::Bounds)?)?,
                word(bytes, base.checked_add(2).ok_or(Error::Bounds)?)?,
            );
            if actual_stride != stride
                || count == 0
                || count > max
                || offset < HEADER_BYTES as u64
                || offset % 8 != 0
            {
                return Err(Error::Bounds);
            }
            let end = offset
                .checked_add(count.checked_mul(stride).ok_or(Error::Bounds)?)
                .ok_or(Error::Bounds)?;
            if end > bytes.len() as u64 {
                return Err(Error::Bounds);
            }
            let mut j = 0usize;
            while j < i {
                let (lo, hi) = *ends.get(j).ok_or(Error::Bounds)?;
                if offset < hi && lo < end {
                    return Err(Error::Bounds);
                }
                j = j.checked_add(1).ok_or(Error::Bounds)?;
            }
            *ends.get_mut(i).ok_or(Error::Bounds)? = (offset, end);
            i = i.checked_add(1).ok_or(Error::Bounds)?;
        }
        if this.scalar(0)? == 0
            || this.scalar(0)? > i32::MAX as u64
            || this.scalar(5)? > i32::MAX as u64
            || this.scalar(6)? > u32::MAX as u64
            || this.scalar(6)? & 1 != 0
            || this.scalar(11)? != 4096
            || this.scalar(13)? == 0
        {
            return Err(Error::Value);
        }
        if this.table(7)?.bytes != b"/dev/null\0" {
            return Err(Error::Value);
        }
        let name = this.table(6)?.bytes;
        if name.last() != Some(&0) {
            return Err(Error::Value);
        }
        let name_end = name.len().checked_sub(1).ok_or(Error::Value)?;
        if has_zero(name.get(..name_end).ok_or(Error::Bounds)?)? {
            return Err(Error::Value);
        }
        let env = this.table(4)?;
        let env_end = env.len().checked_sub(1).ok_or(Error::Bounds)?;
        if env.field(env_end, 0)? != 0 {
            return Err(Error::Value);
        }
        let mut i = 0usize;
        while i < env_end {
            let p = env.field(i, 0)?;
            let relative = p.checked_sub(address).ok_or(Error::Bounds)?;
            let relative = usize::try_from(relative).map_err(|_| Error::Bounds)?;
            if relative < HEADER_BYTES {
                return Err(Error::Bounds);
            }
            let suffix = bytes.get(relative..).ok_or(Error::Bounds)?;
            if !has_zero(suffix)? {
                return Err(Error::Bounds);
            }
            i = i.checked_add(1).ok_or(Error::Bounds)?;
        }
        let aux = this.table(5)?;
        if env.len().checked_add(aux.len()).is_none_or(|n| n > 512) || aux.len() % 2 != 0 {
            return Err(Error::Value);
        }
        let aux_end = aux.len().checked_sub(2).ok_or(Error::Bounds)?;
        let aux_last = aux.len().checked_sub(1).ok_or(Error::Bounds)?;
        if aux.field(aux_end, 0)? != 0 || aux.field(aux_last, 0)? != 0 {
            return Err(Error::Value);
        }
        let mut i = 0usize;
        while i < aux_end {
            let kind = aux.field(i, 0)?;
            if kind == 0 {
                return Err(Error::Value);
            }
            let mut j = 0usize;
            while j < i {
                if aux.field(j, 0)? == kind {
                    return Err(Error::Value);
                }
                j = j.checked_add(2).ok_or(Error::Bounds)?;
            }
            i = i.checked_add(2).ok_or(Error::Bounds)?;
        }
        let expected_aux = this
            .table_address(4)?
            .checked_add(env.bytes.len() as u64)
            .ok_or(Error::Bounds)?;
        if this.table_address(5)? != expected_aux {
            return Err(Error::Bounds);
        }
        // Instruction/source authority is an unsafe producer obligation. Syntax
        // only: each post-PC identifies two preceding bytes, sorted and unique.
        let sites = this.table(8)?;
        let mut previous = 0;
        let mut i = 0usize;
        while i < sites.len() {
            let pc = sites.field(i, 0)?;
            if pc < 2 || pc <= previous {
                return Err(Error::Value);
            }
            previous = pc;
            i = i.checked_add(1).ok_or(Error::Bounds)?;
        }
        Ok(this)
    }
    /// Actual retained blob bytes; callers verify read-only physical mapping.
    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Claimed mapped address, not address authority.
    pub fn address(self) -> u64 {
        self.address
    }
    /// Binding digest in launch/loader/runtime/sources/layout order.
    pub fn binding(self, index: usize) -> Result<[u64; 4], Error> {
        if index >= 5 {
            return Err(Error::Bounds);
        }
        let mut out = [0; 4];
        let base = index
            .checked_mul(4)
            .and_then(|n| n.checked_add(8))
            .ok_or(Error::Bounds)?;
        let mut j = 0usize;
        while j < out.len() {
            *out.get_mut(j).ok_or(Error::Bounds)? =
                word(self.bytes, base.checked_add(j).ok_or(Error::Bounds)?)?;
            j = j.checked_add(1).ok_or(Error::Bounds)?;
        }
        Ok(out)
    }
    /// Guarded role in stack/TLS/signal-stack/handoff/state order.
    pub fn role(self, index: usize) -> Result<Extent, Error> {
        if index >= 5 {
            return Err(Error::Bounds);
        }
        let base = index
            .checked_mul(2)
            .and_then(|n| n.checked_add(28))
            .ok_or(Error::Bounds)?;
        Ok(Extent {
            start: word(self.bytes, base)?,
            end: word(self.bytes, base.checked_add(1).ok_or(Error::Bounds)?)?,
        })
    }
    /// Original 27 scalar register words.
    pub fn registers(self) -> Registers<'a> {
        Registers(Records {
            bytes: &self.bytes[38 * 8..65 * 8],
            stride: WORD_STRIDE,
        })
    }
    /// Fixed scalar field in the documented `Header::scalars` order.
    pub fn scalar(self, index: usize) -> Result<u64, Error> {
        if index >= 16 {
            return Err(Error::Bounds);
        }
        word(self.bytes, index.checked_add(65).ok_or(Error::Bounds)?)
    }
    /// Private final image/TLS fact in `Header::tls` order.
    pub fn tls(self, index: usize) -> Result<u64, Error> {
        if index >= 12 {
            return Err(Error::Bounds);
        }
        word(self.bytes, index.checked_add(108).ok_or(Error::Bounds)?)
    }
    /// Checked table; all slicing uses previously checked lengths.
    pub fn table(self, index: usize) -> Result<Records<'a>, Error> {
        if index >= 9 {
            return Err(Error::Bounds);
        }
        let b = index
            .checked_mul(3)
            .and_then(|n| n.checked_add(81))
            .ok_or(Error::Bounds)?;
        let offset = usize::try_from(word(self.bytes, b)?).map_err(|_| Error::Bounds)?;
        let count = usize::try_from(word(self.bytes, b.checked_add(1).ok_or(Error::Bounds)?)?)
            .map_err(|_| Error::Bounds)?;
        let stride = usize::try_from(word(self.bytes, b.checked_add(2).ok_or(Error::Bounds)?)?)
            .map_err(|_| Error::Bounds)?;
        let end = offset
            .checked_add(count.checked_mul(stride).ok_or(Error::Bounds)?)
            .ok_or(Error::Bounds)?;
        Records::new(self.bytes.get(offset..end).ok_or(Error::Bounds)?, stride)
    }
    /// Claimed real address of one blob-relative table.
    pub fn table_address(self, index: usize) -> Result<u64, Error> {
        if index >= 9 {
            return Err(Error::Bounds);
        }
        let base = index
            .checked_mul(3)
            .and_then(|n| n.checked_add(81))
            .ok_or(Error::Bounds)?;
        self.address
            .checked_add(word(self.bytes, base)?)
            .ok_or(Error::Bounds)
    }
    /// Decode one map by value without a native representation cast.
    pub fn map(self, index: usize) -> Result<Map, Error> {
        let r = self.table(0)?;
        Ok(Map {
            start: r.field(index, 0)?,
            end: r.field(index, 1)?,
            protection: r.field(index, 2)?,
            flags: r.field(index, 3)?,
        })
    }
    /// Decode one executable interval by value.
    pub fn code(self, index: usize) -> Result<Code, Error> {
        let r = self.table(1)?;
        Ok(Code {
            start: r.field(index, 0)?,
            end: r.field(index, 1)?,
        })
    }
    /// Decode a source-qualified operation; unknown role/number is refused.
    pub fn site(self, index: usize) -> Result<Site, Error> {
        let r = self.table(2)?;
        let number = r.field(index, 2)?;
        let operation = match (r.field(index, 3)?, number) {
            (1, 158) => Operation::SetFs,
            (2, 218) => Operation::SetTid,
            (3, 7) => Operation::SecurePoll,
            (4, 2) => Operation::SecureOpen,
            _ => return Err(Error::Value),
        };
        let syscall_ip = r.field(index, 0)?;
        let return_ip = r.field(index, 1)?;
        if syscall_ip.checked_add(2) != Some(return_ip) {
            return Err(Error::Value);
        }
        Ok(Site {
            syscall_ip,
            return_ip,
            number,
            operation,
        })
    }
    /// Validate guarded roles against actual compiled ToolRegion free-band
    /// bounds; validates data geometry only, never reservation/adoption.
    pub fn validate_roles(self, free_band: Extent) -> Result<(), Error> {
        for i in 0..5 {
            let role = self.role(i)?;
            if role.start % 4096 != 0
                || role.end % 4096 != 0
                || !free_band.contains(
                    role.start,
                    role.end.checked_sub(role.start).ok_or(Error::Bounds)?,
                )
            {
                return Err(Error::Bounds);
            }
            role.interior()?;
            for j in 0..i {
                let other = self.role(j)?;
                if role.start < other.end && other.start < role.end {
                    return Err(Error::Bounds);
                }
            }
        }
        if !self
            .role(3)?
            .interior()?
            .contains(self.address, self.bytes.len() as u64)
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }
}
/// Borrowed numeric payloads in the existing nine-table wire order.
/// These slices carry no source, mapping, child, admission or execution authority.
pub struct TableData<'a> {
    /// Planned mapping records, not authenticated kernel observations.
    pub maps: &'a [Map],
    /// Numeric code extents; source and instruction proof remain external.
    pub code: &'a [Code],
    /// Numeric bootstrap syscall tuples, decoded lazily by `View::site`.
    pub sites: &'a [SiteRecord],
    /// Exact ordinary initialization packet bytes, not an admission receipt.
    pub packet: &'a [u8],
    /// Already placed environment pointers followed by their terminating zero.
    pub env: &'a [u64],
    /// Already placed aux pairs including the final AT_NULL pair.
    pub aux: &'a [u64],
    /// Exact NUL-terminated program-name bytes.
    pub program_name: &'a [u8],
    /// Exact `/dev/null\0` bytes.
    pub dev_null: &'a [u8],
    /// Numeric sorted unique ToolInit post-syscall PCs, not instruction proof.
    pub tool_init: &'a [u64],
}

struct WordWriter<'a> {
    bytes: &'a mut [u8],
    offset: usize,
}
impl WordWriter<'_> {
    fn words(&mut self, values: &[u64]) -> Result<(), Error> {
        for value in values {
            let end = self.offset.checked_add(8).ok_or(Error::Bounds)?;
            self.bytes
                .get_mut(self.offset..end)
                .ok_or(Error::Bounds)?
                .copy_from_slice(&value.to_le_bytes());
            self.offset = end;
        }
        Ok(())
    }
}

fn table_destination<'a>(
    table: &Table,
    count: usize,
    stride: usize,
    bytes: &'a mut [u8],
) -> Result<&'a mut [u8], Error> {
    if table.count != u64::try_from(count).map_err(|_| Error::Bounds)?
        || table.stride != u64::try_from(stride).map_err(|_| Error::Bounds)?
    {
        return Err(Error::Bounds);
    }
    let offset = usize::try_from(table.offset).map_err(|_| Error::Bounds)?;
    let end = offset
        .checked_add(count.checked_mul(stride).ok_or(Error::Bounds)?)
        .ok_or(Error::Bounds)?;
    // Do not let a malformed table rewrite the fixed header. All other wire
    // shape/overlap/count checks remain the existing parser's responsibility.
    if offset < HEADER_BYTES {
        return Err(Error::Bounds);
    }
    bytes.get_mut(offset..end).ok_or(Error::Bounds)
}

/// Write numeric data into an already placed caller-owned complete blob.
///
/// Integers are written explicitly little-endian. Bytes outside the fixed header
/// and declared tables remain unchanged, retaining copied strings/random/argv.
/// No pointer is relocated or dereferenced. The caller supplies final numeric
/// offsets and addresses; successful `View::parse` is syntax, never ownership,
/// source/machine proof, initialized TLS, admission, Ready or entry permission.
/// `validate_roles` and lazy value accessors retain their existing separate checks.
///
/// On error the destination may be partially written. No view is returned; the
/// caller must discard or rebuild it before any physical operation.
pub fn serialize<'a>(
    header: &Header,
    tables: &TableData<'_>,
    address: u64,
    bytes: &'a mut [u8],
) -> Result<View<'a>, Error> {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_BYTES {
        return Err(Error::Format);
    }
    let mut writer = WordWriter {
        bytes: bytes.get_mut(..HEADER_BYTES).ok_or(Error::Bounds)?,
        offset: 0,
    };
    writer.words(&header.prefix)?;
    for binding in &header.binding {
        writer.words(binding)?;
    }
    for role in &header.roles {
        writer.words(&[role.start, role.end])?;
    }
    writer.words(&header.registers)?;
    writer.words(&header.scalars)?;
    for table in &header.tables {
        writer.words(&[table.offset, table.count, table.stride])?;
    }
    writer.words(&header.tls)?;
    if writer.offset != HEADER_BYTES {
        return Err(Error::Bounds);
    }

    let mut writer = WordWriter {
        bytes: table_destination(&header.tables[0], tables.maps.len(), 32, bytes)?,
        offset: 0,
    };
    for map in tables.maps {
        writer.words(&[map.start, map.end, map.protection, map.flags])?;
    }
    let mut writer = WordWriter {
        bytes: table_destination(&header.tables[1], tables.code.len(), 16, bytes)?,
        offset: 0,
    };
    for code in tables.code {
        writer.words(&[code.start, code.end])?;
    }
    let mut writer = WordWriter {
        bytes: table_destination(&header.tables[2], tables.sites.len(), 32, bytes)?,
        offset: 0,
    };
    for site in tables.sites {
        writer.words(&[site.syscall_ip, site.return_ip, site.number, site.operation])?;
    }
    table_destination(&header.tables[3], tables.packet.len(), 1, bytes)?
        .copy_from_slice(tables.packet);
    for (index, values) in [(4, tables.env), (5, tables.aux), (8, tables.tool_init)] {
        WordWriter {
            bytes: table_destination(&header.tables[index], values.len(), 8, bytes)?,
            offset: 0,
        }
        .words(values)?;
    }
    table_destination(&header.tables[6], tables.program_name.len(), 1, bytes)?
        .copy_from_slice(tables.program_name);
    table_destination(&header.tables[7], tables.dev_null.len(), 1, bytes)?
        .copy_from_slice(tables.dev_null);
    View::parse(bytes, address)
}

const _: () = {
    assert!(core::mem::size_of::<Header>() == HEADER_BYTES);
    assert!(core::mem::align_of::<Header>() == 8);
    assert!(core::mem::size_of::<Map>() == 32);
    assert!(core::mem::size_of::<Code>() == 16);
    assert!(core::mem::size_of::<SiteRecord>() == 32);
};

#[cfg(test)]
mod tests {
    use super::*;
    fn put(b: &mut [u8], word: usize, value: u64) {
        b[word * 8..word * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    // Deliberately data-only fixture: never supplies physical mapping authority.
    fn fixture() -> std::vec::Vec<u8> {
        let mut b = std::vec![0;2048];
        put(&mut b, 0, MAGIC);
        put(&mut b, 1, VERSION);
        put(&mut b, 2, 2048);
        put(&mut b, 3, HEADER_BYTES as u64);
        put(&mut b, 65, 1);
        put(&mut b, 76, 4096);
        put(&mut b, 78, 0x5000);
        let mut offset = HEADER_BYTES;
        for (i, (count, stride)) in [
            (1, 32),
            (1, 16),
            (4, 32),
            (8, 1),
            (1, 8),
            (2, 8),
            (8, 1),
            (10, 1),
            (3, 8),
        ]
        .into_iter()
        .enumerate()
        {
            put(&mut b, 81 + i * 3, offset as u64);
            put(&mut b, 82 + i * 3, count);
            put(&mut b, 83 + i * 3, stride);
            if i == 6 {
                b[offset..offset + 8].copy_from_slice(b"hermit!\0");
            }
            if i == 7 {
                b[offset..offset + 10].copy_from_slice(b"/dev/null\0");
            }
            if i == 8 {
                for (j, pc) in [0x5002u64, 0x5012, 0x5022].into_iter().enumerate() {
                    b[offset + j * 8..offset + j * 8 + 8].copy_from_slice(&pc.to_le_bytes());
                }
            }
            offset = (offset + count as usize * stride as usize + 7) & !7;
        }
        for i in 0..27 {
            put(&mut b, 38 + i, 0x1000 + i as u64);
        }
        b
    }
    #[test]
    fn scalar_register_codec_preserves_every_original_word() {
        let b = fixture();
        let v = View::parse(&b, 0x100000).unwrap();
        let words = v.registers().words().unwrap();
        for (i, w) in words.into_iter().enumerate() {
            assert_eq!(w, 0x1000 + i as u64);
        }
        assert_eq!(v.registers().fs_base().unwrap(), 0x1015);
        assert_eq!(v.registers().rip().unwrap(), 0x1010);
        assert_eq!(v.registers().rsp().unwrap(), 0x1013);
    }
    #[test]
    fn scalar_reserved_revision_and_header_size_are_closed() {
        for (index, value) in [(1, 2), (3, 0), (4, 1), (78, 0), (79, 1), (80, 1)] {
            let mut b = fixture();
            put(&mut b, index, value);
            assert!(View::parse(&b, 0x100000).is_err());
        }
    }
    #[test]
    fn scalar_overflow_overlap_stride_and_truncation_are_refused() {
        for (index, value) in [
            (81, u64::MAX - 7),
            (82, u64::MAX),
            (83, 8),
            (84, HEADER_BYTES as u64),
        ] {
            let mut b = fixture();
            put(&mut b, index, value);
            assert!(View::parse(&b, 0x100000).is_err());
        }
        let b = fixture();
        assert!(View::parse(&b[..HEADER_BYTES - 1], 0x100000).is_err());
        assert!(View::parse(&b, u64::MAX - 7).is_err());
    }
    #[test]
    fn scalar_operation_codes_require_exact_kernel_number_and_post_ip() {
        let mut b = fixture();
        let v = View::parse(&b, 0x100000).unwrap();
        let start = (v.table_address(2).unwrap() - v.address()) as usize / 8;
        for (index, (op, nr)) in [(1, 158), (2, 218), (3, 7), (4, 2)].into_iter().enumerate() {
            let at = start + index * 4;
            put(&mut b, at, 0x5000 + index as u64 * 4);
            put(&mut b, at + 1, 0x5002 + index as u64 * 4);
            put(&mut b, at + 2, nr);
            put(&mut b, at + 3, op);
        }
        let v = View::parse(&b, 0x100000).unwrap();
        for i in 0..4 {
            assert!(v.site(i).is_ok());
        }
        put(&mut b, start + 3, 5);
        assert!(View::parse(&b, 0x100000).unwrap().site(0).is_err());
        put(&mut b, start + 3, 1);
        put(&mut b, start + 2, 2);
        assert!(View::parse(&b, 0x100000).unwrap().site(0).is_err());
        put(&mut b, start + 2, 158);
        put(&mut b, start + 1, 0x5003);
        assert!(View::parse(&b, 0x100000).unwrap().site(0).is_err());
    }
    #[test]
    fn scalar_env_termination_adjacent_aux_and_dev_null_are_exact() {
        let mut b = fixture();
        let v = View::parse(&b, 0x100000).unwrap();
        let env = (v.table_address(4).unwrap() - v.address()) as usize / 8;
        put(&mut b, env, 1);
        assert!(View::parse(&b, 0x100000).is_err());
        let mut b = fixture();
        put(&mut b, 96, 1800);
        assert!(View::parse(&b, 0x100000).is_err());
        let mut b = fixture();
        let v = View::parse(&b, 0x100000).unwrap();
        let null = (v.table_address(7).unwrap() - v.address()) as usize;
        b[null] = b'x';
        assert!(View::parse(&b, 0x100000).is_err());
    }
    #[test]
    fn scalar_guarded_roles_must_be_disjoint_inside_compiled_free_band() {
        let mut b = fixture();
        for i in 0..5 {
            let start = 0x100000 + i as u64 * 0x10000;
            put(&mut b, 28 + i * 2, start);
            put(&mut b, 29 + i * 2, start + 0x4000);
        }
        // Blob is in role3's interior, not the protected guard page.
        let address = 0x131000;
        let v = View::parse(&b, address).unwrap();
        assert!(
            v.validate_roles(Extent {
                start: 0x100000,
                end: 0x150000
            })
            .is_ok()
        );
        put(&mut b, 30, 0x100000);
        assert!(
            View::parse(&b, address)
                .unwrap()
                .validate_roles(Extent {
                    start: 0x100000,
                    end: 0x150000
                })
                .is_err()
        );
    }

    #[test]
    fn tool_init_sites_require_finite_sorted_unique_complete_records() {
        let b = fixture();
        let v = View::parse(&b, 0x100000).unwrap();
        assert_eq!(v.table(8).unwrap().len(), 3);
        assert_eq!(v.table(8).unwrap().field(2, 0).unwrap(), 0x5022);
        // Complete boundary-sized source, not an undersized buffer whose
        // truncation would hide a count-limit bug.
        let mut max = fixture();
        let offset = View::parse(&max, 0x100000)
            .unwrap()
            .table(8)
            .unwrap()
            .bytes()
            .as_ptr() as usize
            - max.as_ptr() as usize;
        max.resize(offset + 4096 * 8, 0);
        let size = max.len() as u64;
        put(&mut max, 2, size);
        put(&mut max, 106, 4096);
        for i in 0..4096 {
            put(&mut max, offset / 8 + i, 0x10002 + i as u64 * 16);
        }
        assert_eq!(
            View::parse(&max, 0x100000).unwrap().table(8).unwrap().len(),
            4096
        );
        max.resize(offset + 4097 * 8, 0);
        let size = max.len() as u64;
        put(&mut max, 2, size);
        put(&mut max, 106, 4097);
        put(&mut max, offset / 8 + 4096, 0x20002);
        assert!(View::parse(&max, 0x100000).is_err());
        for (field, value) in [(105, HEADER_BYTES as u64), (106, 4097), (107, 16)] {
            let mut b = fixture();
            put(&mut b, field, value);
            assert!(View::parse(&b, 0x100000).is_err());
        }
        for value in [0, 1, 0x5002] {
            let mut b = fixture();
            let start = View::parse(&b, 0x100000)
                .unwrap()
                .table(8)
                .unwrap()
                .bytes()
                .as_ptr() as usize
                - b.as_ptr() as usize;
            put(&mut b, start / 8 + 1, value);
            assert!(View::parse(&b, 0x100000).is_err());
        }
        let b = fixture();
        let end = View::parse(&b, 0x100000)
            .unwrap()
            .table(8)
            .unwrap()
            .bytes()
            .as_ptr() as usize
            - b.as_ptr() as usize
            + 24;
        let mut truncated = b[..end - 1].to_vec();
        let n = truncated.len() as u64;
        put(&mut truncated, 2, n);
        assert!(View::parse(&truncated, 0x100000).is_err());
    }

    #[test]
    fn checked_scalar_error_precedence_remains_format_reserved_bounds_value() {
        fn error(bytes: &[u8], address: u64) -> Error {
            View::parse(bytes, address).err().unwrap()
        }
        let mut b = fixture();
        put(&mut b, 0, 0);
        put(&mut b, 4, 1);
        put(&mut b, 82, 0);
        put(&mut b, 65, 0);
        assert_eq!(error(&b, 0x100000), Error::Format);
        put(&mut b, 0, MAGIC);
        assert_eq!(error(&b, 0x100000), Error::Reserved);
        put(&mut b, 4, 0);
        assert_eq!(error(&b, 0x100000), Error::Bounds);
        put(&mut b, 82, 1);
        assert_eq!(error(&b, 0x100000), Error::Value);
        // Address overflow still precedes reserved words, as in the original.
        put(&mut b, 4, 1);
        assert_eq!(error(&b, u64::MAX - 7), Error::Bounds);
    }

    #[test]
    fn checked_scalar_name_and_env_scan_boundaries_keep_the_wire_contract() {
        let mut b = fixture();
        let v = View::parse(&b, 0x100000).unwrap();
        let name = (v.table_address(6).unwrap() - v.address()) as usize;
        // A one-byte NUL program name was and remains permitted.
        put(&mut b, 100, 1);
        b[name] = 0;
        assert!(View::parse(&b, 0x100000).is_ok());
        put(&mut b, 100, 8);
        assert_eq!(View::parse(&b, 0x100000).err(), Some(Error::Value));
        b[name..name + 8].copy_from_slice(b"hermit!!");
        assert_eq!(View::parse(&b, 0x100000).err(), Some(Error::Value));
        // Move env/aux into unused space, giving env one real string pointer
        // plus its terminating NULL. The string may reside in the blob tail;
        // neither old nor new codec restricts it to a fabricated string table.
        let mut b = fixture();
        put(&mut b, 93, 1800);
        put(&mut b, 94, 2);
        put(&mut b, 96, 1816);
        put(&mut b, 1800 / 8, 0x100000 + 2047);
        put(&mut b, 1808 / 8, 0);
        assert!(View::parse(&b, 0x100000).is_ok());
        b[2047] = b'x';
        assert_eq!(View::parse(&b, 0x100000).err(), Some(Error::Bounds));
        put(&mut b, 1800 / 8, 0x100000 + 2048);
        assert_eq!(View::parse(&b, 0x100000).err(), Some(Error::Bounds));
        put(&mut b, 1800 / 8, 0x100000 + HEADER_BYTES as u64 - 1);
        assert_eq!(View::parse(&b, 0x100000).err(), Some(Error::Bounds));
    }

    #[test]
    fn checked_scalar_aux_pair_edges_and_duplicates_keep_exact_refusals() {
        let mut b = fixture();
        // Table shape rejects zero before any inferred terminal subtraction.
        put(&mut b, 97, 0);
        assert_eq!(View::parse(&b, 0x100000).err(), Some(Error::Bounds));
        let mut b = fixture();
        put(&mut b, 97, 1);
        assert_eq!(View::parse(&b, 0x100000).err(), Some(Error::Value));
        let mut b = fixture();
        put(&mut b, 96, 1800);
        put(&mut b, 93, 1792);
        put(&mut b, 97, 6);
        for (i, value) in [3, 9, 3, 10, 0, 0].into_iter().enumerate() {
            put(&mut b, 1800 / 8 + i, value);
        }
        assert_eq!(View::parse(&b, 0x100000).err(), Some(Error::Value));
        put(&mut b, 1800 / 8 + 2, 4);
        assert!(View::parse(&b, 0x100000).is_ok());
        put(&mut b, 1800 / 8 + 4, 5);
        assert_eq!(View::parse(&b, 0x100000).err(), Some(Error::Value));
    }

    #[test]
    fn checked_scalar_field_and_word_bounds_do_not_wrap() {
        let bytes = [0u8; 16];
        let records = Records::new(&bytes, 8).unwrap();
        assert_eq!(records.field(1, 0), Ok(0));
        assert_eq!(records.field(2, 0), Err(Error::Bounds));
        assert_eq!(records.field(0, 1), Err(Error::Bounds));
        assert_eq!(records.field(usize::MAX, usize::MAX), Err(Error::Bounds));
        assert_eq!(word(&bytes, usize::MAX), Err(Error::Bounds));
        assert_eq!(word(&bytes[..7], 0), Err(Error::Bounds));
        // The same malformed zero-stride input now fails at the real private
        // constructor: an invalid Records value cannot be represented.
        assert!(matches!(Records::new(&bytes, 0), Err(Error::Bounds)));
    }
    #[test]
    fn every_zero_wire_stride_is_refused_before_record_construction() {
        for table in 0..9 {
            let mut bytes = fixture();
            put(&mut bytes, 83 + table * 3, 0);
            assert_eq!(View::parse(&bytes, 0x100000).err(), Some(Error::Bounds));
        }
    }

    #[test]
    fn nonzero_record_construction_preserves_empty_and_bounded_count_behavior() {
        let bytes = [0u8; 16];
        let empty = Records::new(&[], 8).unwrap();
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
        assert_eq!(empty.field(0, 0), Err(Error::Bounds));
        let one = Records::new(&bytes, 16).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one.field(0, 1), Ok(0));
        assert_eq!(one.field(1, 0), Err(Error::Bounds));
        let huge = Records::new(&bytes, usize::MAX).unwrap();
        assert_eq!(huge.len(), 0);
        assert_eq!(huge.field(usize::MAX, usize::MAX), Err(Error::Bounds));
        assert!(matches!(Records::new(&[], 0), Err(Error::Bounds)));
    }

    // These are numeric codec tests, not a captured-input constructor, ELF
    // qualifier, mapping receipt or runtime initialization control.
    fn serialize_fixture<'a>(
        source: &[u8],
        address: u64,
        output: &'a mut [u8],
        change: impl FnOnce(&mut Header),
    ) -> Result<View<'a>, Error> {
        let mut header = Header {
            prefix: core::array::from_fn(|i| word(source, i).unwrap()),
            binding: core::array::from_fn(|i| {
                core::array::from_fn(|j| word(source, 8 + i * 4 + j).unwrap())
            }),
            roles: core::array::from_fn(|i| Extent {
                start: word(source, 28 + i * 2).unwrap(),
                end: word(source, 29 + i * 2).unwrap(),
            }),
            registers: core::array::from_fn(|i| word(source, 38 + i).unwrap()),
            scalars: core::array::from_fn(|i| word(source, 65 + i).unwrap()),
            tables: core::array::from_fn(|i| Table {
                offset: word(source, 81 + i * 3).unwrap(),
                count: word(source, 82 + i * 3).unwrap(),
                stride: word(source, 83 + i * 3).unwrap(),
            }),
            tls: core::array::from_fn(|i| word(source, 108 + i).unwrap()),
        };
        // Read fixture payloads independently of View::parse so malformed
        // payload tests really reach the serializer's final parser call.
        let data = |index: usize| {
            let table = &header.tables[index];
            let start = usize::try_from(table.offset).unwrap();
            let size = usize::try_from(table.count * table.stride).unwrap();
            &source[start..start + size]
        };
        let maps: std::vec::Vec<_> = data(0)
            .as_chunks::<32>()
            .0
            .iter()
            .map(|row| Map {
                start: word(row, 0).unwrap(),
                end: word(row, 1).unwrap(),
                protection: word(row, 2).unwrap(),
                flags: word(row, 3).unwrap(),
            })
            .collect();
        let code: std::vec::Vec<_> = data(1)
            .as_chunks::<16>()
            .0
            .iter()
            .map(|row| Code {
                start: word(row, 0).unwrap(),
                end: word(row, 1).unwrap(),
            })
            .collect();
        let sites: std::vec::Vec<_> = data(2)
            .as_chunks::<32>()
            .0
            .iter()
            .map(|row| SiteRecord {
                syscall_ip: word(row, 0).unwrap(),
                return_ip: word(row, 1).unwrap(),
                number: word(row, 2).unwrap(),
                operation: word(row, 3).unwrap(),
            })
            .collect();
        let words = |index| -> std::vec::Vec<u64> {
            data(index)
                .as_chunks::<8>()
                .0
                .iter()
                .map(|row| u64::from_le_bytes(*row))
                .collect()
        };
        let env = words(4);
        let aux = words(5);
        let tool_init = words(8);
        let tables = TableData {
            maps: &maps,
            code: &code,
            sites: &sites,
            packet: data(3),
            env: &env,
            aux: &aux,
            program_name: data(6),
            dev_null: data(7),
            tool_init: &tool_init,
        };
        change(&mut header);
        serialize(&header, &tables, address, output)
    }

    #[test]
    fn serializer_matches_existing_wire_and_preserves_unlisted_backing() {
        let mut source = fixture();
        for i in 8..28 {
            put(&mut source, i, 0x0102030405060708 + i as u64);
        }
        for i in 108..120 {
            put(&mut source, i, 0x8877665544332200 + i as u64);
        }
        // Not a table: retained copied-input/random bytes in the blob tail.
        source[2000..2016].copy_from_slice(b"actual-tail-data");
        let mut output = source.clone();
        output[..HEADER_BYTES].fill(0xcc);
        let view = serialize_fixture(&source, 0x100000, &mut output, |_| {}).unwrap();
        assert_eq!(view.bytes(), source);
        assert_eq!(
            &view.bytes()[8 * 8..9 * 8],
            &0x0102030405060710u64.to_le_bytes()
        );
        assert_eq!(view.registers().words().unwrap()[26], 0x101a);
        // Existing View::parse is intentionally lazy about operation tuples;
        // the encoder neither invents nor weakens the existing accessor check.
        assert_eq!(view.site(0).err(), Some(Error::Value));
    }

    #[test]
    fn serializer_refuses_bad_capacity_and_claimed_address() {
        let source = fixture();
        for size in [HEADER_BYTES - 1, MAX_BYTES + 1] {
            let mut output = std::vec![0; size];
            assert_eq!(
                serialize_fixture(&source, 0x100000, &mut output, |_| {}).err(),
                Some(Error::Format)
            );
        }
        for (address, error) in [(1, Error::Format), (u64::MAX - 7, Error::Bounds)] {
            let mut output = source.clone();
            assert_eq!(
                serialize_fixture(&source, address, &mut output, |_| {}).err(),
                Some(error)
            );
        }
        let mut output = source[..source.len() - 1].to_vec();
        assert_eq!(
            serialize_fixture(&source, 0x100000, &mut output, |_| {}).err(),
            Some(Error::Format)
        );
    }

    #[test]
    fn serializer_checks_typed_counts_strides_ranges_and_overlap() {
        let source = fixture();
        for index in 0..9 {
            for change_kind in 0..5 {
                let mut output = source.clone();
                let error = serialize_fixture(&source, 0x100000, &mut output, |header| {
                    let table = &mut header.tables[index];
                    match change_kind {
                        0 => table.count += 1,
                        1 => table.stride += 1,
                        2 => table.offset = u64::MAX - 7,
                        3 => table.offset = (HEADER_BYTES - 8) as u64,
                        4 => table.offset += 1,
                        _ => unreachable!(),
                    }
                })
                .err();
                assert_eq!(
                    error,
                    Some(Error::Bounds),
                    "table {index}, case {change_kind}"
                );
            }
        }
        let mut output = source.clone();
        assert_eq!(
            serialize_fixture(&source, 0x100000, &mut output, |header| {
                header.tables[1].offset = header.tables[0].offset;
            })
            .err(),
            Some(Error::Bounds)
        );
    }

    #[test]
    fn serializer_keeps_reserved_name_and_dev_null_refusals() {
        let source = fixture();
        let mut output = source.clone();
        assert_eq!(
            serialize_fixture(&source, 0x100000, &mut output, |header| {
                header.prefix[4] = 1;
            })
            .err(),
            Some(Error::Reserved)
        );
        for table in [6, 7] {
            let mut source = fixture();
            let offset = word(&source, 81 + table * 3).unwrap() as usize;
            source[offset] = if table == 6 { 0 } else { b'x' };
            let mut output = source.clone();
            assert_eq!(
                serialize_fixture(&source, 0x100000, &mut output, |_| {}).err(),
                Some(Error::Value)
            );
        }
    }

    #[test]
    fn serializer_preserves_placed_env_aux_and_rejects_bad_tail_pointer() {
        let mut source = fixture();
        put(&mut source, 93, 1800);
        put(&mut source, 94, 2);
        put(&mut source, 96, 1816);
        put(&mut source, 1800 / 8, 0x100000 + 2047);
        put(&mut source, 1808 / 8, 0);
        let mut output = source.clone();
        let view = serialize_fixture(&source, 0x100000, &mut output, |_| {}).unwrap();
        assert_eq!(view.table_address(4).unwrap(), 0x100000 + 1800);
        assert_eq!(view.table_address(5).unwrap(), 0x100000 + 1816);
        assert_eq!(view.table(4).unwrap().field(0, 0).unwrap(), 0x100000 + 2047);
        assert_eq!(view.bytes(), source);
        source[2047] = b'x';
        let mut output = source.clone();
        assert_eq!(
            serialize_fixture(&source, 0x100000, &mut output, |_| {}).err(),
            Some(Error::Bounds)
        );
        let mut output = fixture();
        assert_eq!(
            serialize_fixture(&fixture(), 0x100000, &mut output, |header| {
                header.tables[5].offset = 1800;
            })
            .err(),
            Some(Error::Bounds)
        );
    }

    #[test]
    fn serializer_rejects_duplicate_aux_and_exact_finite_site_excess() {
        let mut source = fixture();
        put(&mut source, 93, 1792);
        put(&mut source, 96, 1800);
        put(&mut source, 97, 6);
        for (i, value) in [3, 9, 3, 10, 0, 0].into_iter().enumerate() {
            put(&mut source, 1800 / 8 + i, value);
        }
        let mut output = source.clone();
        assert_eq!(
            serialize_fixture(&source, 0x100000, &mut output, |_| {}).err(),
            Some(Error::Value)
        );
        for count in [4096, 4097] {
            let mut source = fixture();
            let offset = word(&source, 105).unwrap() as usize;
            source.resize(offset + count * 8, 0);
            let length = source.len() as u64;
            put(&mut source, 2, length);
            put(&mut source, 106, count as u64);
            for index in 0..count {
                put(&mut source, offset / 8 + index, 0x10002 + index as u64 * 16);
            }
            let mut output = source.clone();
            let result = serialize_fixture(&source, 0x100000, &mut output, |_| {});
            if count == 4096 {
                assert_eq!(result.unwrap().table(8).unwrap().len(), 4096);
            } else {
                assert_eq!(result.err(), Some(Error::Bounds));
            }
        }
    }

    #[test]
    fn serializer_keeps_maximum_envelope_and_sorted_unique_site_rules() {
        let mut source = fixture();
        source.resize(MAX_BYTES, 0);
        put(&mut source, 2, MAX_BYTES as u64);
        let mut output = source.clone();
        assert_eq!(
            serialize_fixture(&source, 0x100000, &mut output, |_| {})
                .unwrap()
                .bytes()
                .len(),
            MAX_BYTES
        );
        for value in [1, 0x5002, 0x5001] {
            let mut source = fixture();
            let offset = word(&source, 105).unwrap() as usize;
            put(&mut source, offset / 8 + 1, value);
            let mut output = source.clone();
            assert_eq!(
                serialize_fixture(&source, 0x100000, &mut output, |_| {}).err(),
                Some(Error::Value)
            );
        }
    }

    #[test]
    fn bootstrap_fixed_fields_match_full_valid_view() {
        let mut b = fixture();
        for index in 8..38 {
            put(&mut b, index, 0x2000 + index as u64);
        }
        for index in 108..120 {
            put(&mut b, index, 0x3000 + index as u64);
        }
        let view = View::parse(&b, 0x100000).unwrap();
        let boot = Bootstrap::project(&b, 0x100000).unwrap();
        assert!(core::ptr::eq(boot.bytes(), view.bytes()));
        assert_eq!(boot.address(), view.address());
        for index in 0..5 {
            assert_eq!(boot.binding(index).unwrap(), view.binding(index).unwrap());
            assert_eq!(boot.role(index).unwrap(), view.role(index).unwrap());
        }
        for index in 0..16 {
            assert_eq!(boot.scalar(index), view.scalar(index));
        }
        for index in 0..12 {
            assert_eq!(boot.tls(index), view.tls(index));
        }
    }

    #[test]
    fn bootstrap_registers_preserve_complete_original_source() {
        let b = fixture();
        let view = View::parse(&b, 0x100000).unwrap();
        let regs = Bootstrap::project(&b, 0x100000)
            .unwrap()
            .registers()
            .unwrap();
        assert_eq!(regs.bytes(), view.registers().bytes());
        assert_eq!(regs.words(), view.registers().words());
        assert_eq!(regs.fs_base(), Ok(0x1015));
        assert_eq!(regs.rip(), Ok(0x1010));
        assert_eq!(regs.rsp(), Ok(0x1013));
    }

    #[test]
    fn bootstrap_map_retains_flags_and_exact_bytes() {
        let mut b = fixture();
        let offset = word(&b, 81).unwrap() as usize;
        for (index, value) in [0x4000, 0x6000, 3, 0x100022].into_iter().enumerate() {
            put(&mut b, offset / 8 + index, value);
        }
        let view = View::parse(&b, 0x100000).unwrap();
        let boot = Bootstrap::project(&b, 0x100000).unwrap();
        let old = view.map(0).unwrap();
        let new = boot.map(0).unwrap();
        assert_eq!(boot.map_count(), Ok(view.table(0).unwrap().len()));
        assert_eq!(boot.map_bytes().unwrap(), view.table(0).unwrap().bytes());
        assert_eq!(
            (new.start, new.end, new.protection, new.flags),
            (old.start, old.end, old.protection, old.flags)
        );
    }

    #[test]
    fn bootstrap_code_retains_exact_extent_and_bytes() {
        let mut b = fixture();
        let offset = word(&b, 84).unwrap() as usize;
        put(&mut b, offset / 8, 0x5000);
        put(&mut b, offset / 8 + 1, 0x6000);
        let view = View::parse(&b, 0x100000).unwrap();
        let boot = Bootstrap::project(&b, 0x100000).unwrap();
        let old = view.code(0).unwrap();
        let new = boot.code(0).unwrap();
        assert_eq!(boot.code_count(), Ok(view.table(1).unwrap().len()));
        assert_eq!(boot.code_bytes().unwrap(), view.table(1).unwrap().bytes());
        assert_eq!((new.start, new.end), (old.start, old.end));
    }

    #[test]
    fn bootstrap_all_four_site_roles_match_full_accessor() {
        let mut b = fixture();
        let offset = word(&b, 87).unwrap() as usize;
        for (index, (op, nr)) in [(1, 158), (2, 218), (3, 7), (4, 2)].into_iter().enumerate() {
            let row = offset / 8 + index * 4;
            put(&mut b, row, 0x5000 + index as u64 * 4);
            put(&mut b, row + 1, 0x5002 + index as u64 * 4);
            put(&mut b, row + 2, nr);
            put(&mut b, row + 3, op);
        }
        let view = View::parse(&b, 0x100000).unwrap();
        let boot = Bootstrap::project(&b, 0x100000).unwrap();
        assert_eq!(boot.site_count(), Ok(4));
        assert_eq!(boot.site_bytes().unwrap(), view.table(2).unwrap().bytes());
        for index in 0..4 {
            let old = view.site(index).unwrap();
            let new = boot.site(index).unwrap();
            assert_eq!(
                (new.syscall_ip, new.return_ip, new.number, new.operation),
                (old.syscall_ip, old.return_ip, old.number, old.operation)
            );
        }
    }

    #[test]
    fn bootstrap_packet_env_and_name_keep_represented_addresses() {
        let b = fixture();
        let address = 0x700000;
        let view = View::parse(&b, address).unwrap();
        let boot = Bootstrap::project(&b, address).unwrap();
        assert_ne!(b.as_ptr() as u64, address);
        assert_eq!(boot.packet().unwrap(), view.table(3).unwrap().bytes());
        assert_eq!(boot.envp_address(), view.table_address(4));
        assert_eq!(boot.program_name_address(), view.table_address(6));
        assert_eq!(
            boot.env_aux_words(),
            Ok(view.table(4).unwrap().len() + view.table(5).unwrap().len())
        );
    }

    #[test]
    fn bootstrap_rejects_each_fixed_prefix_mismatch() {
        for (index, value) in [(0, 0), (1, VERSION + 1), (2, 2047), (3, 0)] {
            let mut b = fixture();
            put(&mut b, index, value);
            assert_eq!(Bootstrap::project(&b, 0x100000).err(), Some(Error::Format));
        }
    }

    #[test]
    fn bootstrap_rejects_every_reserved_header_word() {
        for index in [4, 5, 6, 7, 79, 80] {
            let mut b = fixture();
            put(&mut b, index, 1);
            assert_eq!(
                Bootstrap::project(&b, 0x100000).err(),
                Some(Error::Reserved)
            );
        }
    }

    #[test]
    fn bootstrap_rejects_fixed_header_truncation_without_loading_past_slice() {
        let b = fixture();
        for length in [0, 7, 8, HEADER_BYTES - 1] {
            assert_eq!(
                Bootstrap::project(&b[..length], 0x100000).err(),
                Some(Error::Format)
            );
        }
        assert_eq!(
            Bootstrap::project(&b[..HEADER_BYTES], 0x100000).err(),
            Some(Error::Format)
        );
    }

    #[test]
    fn bootstrap_keeps_exact_complete_blob_capacity() {
        let mut b = fixture();
        b.resize(MAX_BYTES, 0);
        put(&mut b, 2, MAX_BYTES as u64);
        assert_eq!(
            Bootstrap::project(&b, 0x100000).unwrap().bytes().len(),
            MAX_BYTES
        );
        b.push(0);
        put(&mut b, 2, (MAX_BYTES + 1) as u64);
        assert_eq!(Bootstrap::project(&b, 0x100000).err(), Some(Error::Format));
    }

    #[test]
    fn bootstrap_rejects_represented_address_alignment_and_overflow() {
        let b = fixture();
        assert_eq!(Bootstrap::project(&b, 0x100001).err(), Some(Error::Format));
        assert_eq!(
            Bootstrap::project(&b, u64::MAX - 7).err(),
            Some(Error::Bounds)
        );
    }

    #[test]
    fn bootstrap_bounds_every_consumed_table_offset() {
        for table in 0..7 {
            for offset in [
                0,
                (HEADER_BYTES - 8) as u64,
                (HEADER_BYTES + 1) as u64,
                u64::MAX - 7,
            ] {
                let mut b = fixture();
                put(&mut b, 81 + table * 3, offset);
                assert_eq!(Bootstrap::project(&b, 0x100000).err(), Some(Error::Bounds));
            }
        }
    }

    #[test]
    fn bootstrap_requires_every_literal_consumed_stride() {
        for (table, stride) in [32, 16, 32, 1, 8, 8, 1].into_iter().enumerate() {
            for wrong in [0, stride + 1, u64::MAX] {
                let mut b = fixture();
                put(&mut b, 83 + table * 3, wrong);
                assert_eq!(Bootstrap::project(&b, 0x100000).err(), Some(Error::Bounds));
            }
        }
    }

    #[test]
    fn bootstrap_refuses_zero_and_excess_counts_for_all_consumed_tables() {
        for (table, max) in [64, 64, 128, 4096, 512, 512, 4096].into_iter().enumerate() {
            for count in [0, max + 1, u64::MAX] {
                let mut b = fixture();
                put(&mut b, 82 + table * 3, count);
                assert_eq!(Bootstrap::project(&b, 0x100000).err(), Some(Error::Bounds));
            }
        }
    }

    #[test]
    fn bootstrap_requires_complete_consumed_table_bytes() {
        for table in 0..7 {
            let mut b = fixture();
            let end = b.len() as u64;
            put(&mut b, 81 + table * 3, end);
            assert_eq!(Bootstrap::project(&b, 0x100000).err(), Some(Error::Bounds));
        }
    }

    #[test]
    fn bootstrap_refuses_overlap_in_every_consumed_table_pair() {
        for first in 0..7 {
            for second in first + 1..7 {
                let mut b = fixture();
                let offset = word(&b, 81 + first * 3).unwrap();
                put(&mut b, 81 + second * 3, offset);
                assert_eq!(Bootstrap::project(&b, 0x100000).err(), Some(Error::Bounds));
            }
        }
    }

    #[test]
    fn bootstrap_accepts_exact_map_code_site_and_byte_capacities() {
        for (table, count, stride) in [
            (0, 64, 32),
            (1, 64, 16),
            (2, 128, 32),
            (3, 4096, 1),
            (6, 4096, 1),
        ] {
            let mut b = fixture();
            let offset = b.len();
            b.resize(offset + count * stride, 0);
            let length = b.len() as u64;
            put(&mut b, 2, length);
            put(&mut b, 81 + table * 3, offset as u64);
            put(&mut b, 82 + table * 3, count as u64);
            let boot = Bootstrap::project(&b, 0x100000).unwrap();
            match table {
                0 => assert_eq!(boot.map_count(), Ok(64)),
                1 => assert_eq!(boot.code_count(), Ok(64)),
                2 => assert_eq!(boot.site_count(), Ok(128)),
                3 => assert_eq!(boot.packet().unwrap().len(), 4096),
                6 => assert_eq!(boot.program_name_address(), Ok(0x100000 + offset as u64)),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn bootstrap_env_aux_total_is_bounded_without_credential_fabrication() {
        let mut b = fixture();
        let offset = b.len();
        b.resize(offset + 513 * 8, 0);
        let length = b.len() as u64;
        put(&mut b, 2, length);
        put(&mut b, 93, offset as u64);
        put(&mut b, 94, 511);
        put(&mut b, 96, (offset + 511 * 8) as u64);
        put(&mut b, 97, 1);
        // Shape only: odd aux count still requires the unchanged full validator.
        assert_eq!(
            Bootstrap::project(&b, 0x100000).unwrap().env_aux_words(),
            Ok(512)
        );
        put(&mut b, 97, 2);
        assert_eq!(Bootstrap::project(&b, 0x100000).err(), Some(Error::Value));
    }

    #[test]
    fn bootstrap_requires_env_aux_adjacency() {
        let mut b = fixture();
        put(&mut b, 96, 1800);
        assert_eq!(Bootstrap::project(&b, 0x100000).err(), Some(Error::Bounds));
    }

    #[test]
    fn bootstrap_site_accessor_refuses_bad_role_number_and_ip_pair() {
        for (ip, post, number, operation) in [
            (0x5000, 0x5002, 158, 5),
            (0x5000, 0x5002, 2, 1),
            (0x5000, 0x5003, 158, 1),
            (u64::MAX, 1, 158, 1),
        ] {
            let mut b = fixture();
            let offset = word(&b, 87).unwrap() as usize / 8;
            for (field, value) in [ip, post, number, operation].into_iter().enumerate() {
                put(&mut b, offset + field, value);
            }
            let boot = Bootstrap::project(&b, 0x100000).unwrap();
            assert_eq!(boot.site(0).err(), Some(Error::Value));
        }
    }

    #[test]
    fn bootstrap_accessors_refuse_out_of_range_indices_and_native_widths() {
        let b = fixture();
        let boot = Bootstrap::project(&b, 0x100000).unwrap();
        for index in [5, usize::MAX] {
            assert_eq!(boot.binding(index).err(), Some(Error::Bounds));
            assert_eq!(boot.role(index).err(), Some(Error::Bounds));
        }
        assert_eq!(boot.scalar(16), Err(Error::Bounds));
        assert_eq!(boot.tls(12), Err(Error::Bounds));
        assert_eq!(boot.map(1).err(), Some(Error::Bounds));
        assert_eq!(boot.code(1).err(), Some(Error::Bounds));
        assert_eq!(boot.site(4).err(), Some(Error::Bounds));
        for index in [0, 1, 2] {
            let mut b = fixture();
            let (field, value) = [
                (65, i32::MAX as u64 + 1),
                (70, i32::MAX as u64 + 1),
                (71, u32::MAX as u64 + 1),
            ][index];
            put(&mut b, field, value);
            assert_eq!(Bootstrap::project(&b, 0x100000).err(), Some(Error::Value));
        }
    }

    #[test]
    fn bootstrap_is_not_full_validation_or_unconsumed_table_authority() {
        let mut b = fixture();
        put(&mut b, 106, 0); // ToolInit count: not consumed before libc.
        assert!(Bootstrap::project(&b, 0x100000).is_ok());
        assert_eq!(View::parse(&b, 0x100000).err(), Some(Error::Bounds));
        let mut b = fixture();
        let name = word(&b, 99).unwrap() as usize;
        b[name + 7] = b'x';
        assert!(Bootstrap::project(&b, 0x100000).is_ok());
        assert_eq!(View::parse(&b, 0x100000).err(), Some(Error::Value));
    }
}
