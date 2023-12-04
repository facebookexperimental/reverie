/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::borrow::Cow;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;

use addr2line::gimli;
use addr2line::gimli::EndianSlice;
use addr2line::gimli::RunTimeEndian as Endian;
use memmap2::Mmap;
use object::Object as _;
use object::ObjectSegment;
use object::SymbolMapName;
use typed_arena::Arena;

/// A type alias for a decompressed section data stash.
type SectionStash = Arena<Vec<u8>>;

struct Context<'mmap> {
    dwarf: addr2line::Context<EndianSlice<'mmap, Endian>>,
    symbol_map: object::SymbolMap<SymbolMapName<'mmap>>,
    base_addr: u64,
    _object: object::File<'mmap>,
}

/// Symbols that have been loaded for a library.
pub struct Symbols {
    // This is a self-referential struct. The `context` and `symbol_data`
    // reference the memory in `mmap`. This is all safe because the memory in
    // the mmap is guaranteed to never move or be modified. However, since Rust
    // cannot do self-referential structs, we must resort to some unsafe
    // shenanigans like transmuting the 'static lifetime below.
    _mmap: Mmap,
    context: Context<'static>,
    /// If a section is compressed, the decompressed data is put here.
    symbol_data: SectionStash,
}

/// After the initial creation, symbol data is not mutated again so it is safe
/// to use from multiple threads.
unsafe impl Sync for Symbols {}

/// Helper for loading *either* a `Context` or `Symbols`. This is mainly to work
/// around the fact that Rust does not have self-referential structs.
enum Either<A, B> {
    A(A),
    B(B),
}

impl Symbols {
    /// Loads the given `mmap` of an object file using `func`.
    fn load_with<F>(mmap: Mmap, func: F) -> anyhow::Result<Self>
    where
        F: for<'a> FnOnce(&'a [u8], &'a SectionStash) -> anyhow::Result<Context<'a>>,
    {
        Self::load_either_with(mmap, move |mmap, symbol_data| {
            let context = func(mmap, symbol_data)?;
            Ok(Either::B(context))
        })
    }

    /// Loads the given `mmap` of an object file using `func`. The resulting
    /// `Self` may not contain the same `mmap` that was given if the object
    /// contains a `.gnu_debuglink` section. That is, the callback `func` should
    /// return *either* a `Context` (i.e., the original object) or `Self` (i.e.,
    /// a new object loaded via `.gnu_debuglink`).
    fn load_either_with<F>(mmap: Mmap, func: F) -> anyhow::Result<Self>
    where
        F: for<'a> FnOnce(&'a [u8], &'a SectionStash) -> anyhow::Result<Either<Self, Context<'a>>>,
    {
        let symbol_data = SectionStash::new();
        let context = match func(&mmap, &symbol_data)? {
            Either::A(symbols) => return Ok(symbols),
            Either::B(context) => context,
        };

        // Must do this lifetime transmute shenangians to get around
        // self-referential struct limitations. This lifetime transformation is
        // safe since the references all point to `mmap`, which is guaranteed to
        // not move and will be dropped at the same time as these references.
        //
        // Note that we try hard to make sure this is the *only* place where
        // this transmute happens. Thus is the reason why symbols are loaded via
        // a callback function instead of more directly.
        let context = unsafe { core::mem::transmute::<Context<'_>, Context<'static>>(context) };

        Ok(Self {
            _mmap: mmap,
            context,
            symbol_data,
        })
    }

    /// Like [`load_with`], but maps the `path` into memory for us.
    fn load_path_with<F>(path: &Path, func: F) -> anyhow::Result<Self>
    where
        F: for<'a> FnOnce(&'a [u8], &'a SectionStash) -> anyhow::Result<Context<'a>>,
    {
        let mmap = mmap_path(path)?;
        Self::load_with(mmap, func)
    }

    /// Like [`load_either_with`], but maps the `path` into memory for us.
    fn load_either_path_with<F>(path: &Path, func: F) -> anyhow::Result<Self>
    where
        F: for<'a> FnOnce(&'a [u8], &'a SectionStash) -> anyhow::Result<Either<Self, Context<'a>>>,
    {
        let mmap = mmap_path(path)?;
        Self::load_either_with(mmap, func)
    }

    /// Loads the symbol data from the given path. If the given object path
    /// contains a `.gnu_debuglink` section, then the symbol data is loaded from
    /// there instead.
    pub fn load(path: &Path) -> Result<Self, anyhow::Error> {
        Self::load_either_path_with(path, |mmap, symbol_data| {
            let object = object::File::parse(mmap)?;

            // If this object has a `.gnu_debuglink` section, then find the
            // associated file path and use it instead. This other file should have
            // the complete debug information as well as the symbol table so we can
            // avoid keeping both around.
            let debuglink = object
                .gnu_debuglink()?
                .map(|(data, _)| Path::new(OsStr::from_bytes(data)))
                .and_then(|debuglink| locate_debuglink(path, debuglink));

            if let Some(path) = debuglink {
                return Self::load_debug(&path).map(Either::A);
            }

            let context = Context::load(object, symbol_data)?;
            Ok(Either::B(context))
        })
    }

    /// Loads the debug info from the given `path`.
    fn load_debug(path: &Path) -> anyhow::Result<Self> {
        Self::load_path_with(path, |mmap, symbol_data| {
            let object = object::File::parse(mmap)?;
            let context = Context::load(object, symbol_data)?;

            // TODO: Load the `.gnu_debugaltlink` file as a supplementary
            // object. We need to be sure to keep the supplementary `mmap` in
            // scope so that it is not dropped.

            Ok(context)
        })
    }

    /// Returns the base address of the object.
    pub fn base_addr(&self) -> u64 {
        self.context.base_addr
    }

    /// Finds the associated function (or inlined functions) from the given
    /// `probe` using the debug information.
    ///
    /// The `probe` should be an address which assumes the object has a base
    /// address of 0. While libraries normally have a base address of 0,
    /// executables are often loaded a fixed address of 0x400000. This function
    /// will account for the differences in these two scenarios by offsetting
    /// the given `probe` by the object's base address.
    pub fn find_frames(
        &self,
        probe: u64,
    ) -> addr2line::LookupResult<
        impl addr2line::LookupContinuation<
            Output = Result<addr2line::FrameIter<EndianSlice<'static, Endian>>, gimli::read::Error>,
        >,
    > {
        self.context.dwarf.find_frames(probe + self.base_addr())
    }

    /// Finds a symbol in the symbol table using the given address. If the
    /// symbol does not exist, returns `None`. Note that this purely uses the
    /// symbol table to find the symbol name and does not depend on the debug
    /// info at all. This should be used as a fallback if `find_frames` is
    /// unable to locate the symbol name using the debug info.
    ///
    /// Symbol lookup uses binary search, so lookup happens in `O(log n)`
    /// amortized time.
    pub fn find_symbol(&self, probe: u64) -> Option<SymbolMapName> {
        self.context
            .symbol_map
            .get(probe + self.base_addr())
            .copied()
    }

    /// Returns the number of bytes used to store the debug information. This is
    /// used to keep track of our memory overhead when loading symbols.
    pub fn bytes_used(&self) -> usize {
        self.symbol_data.len()
    }
}

impl<'mmap> Context<'mmap> {
    fn load(object: object::File<'mmap>, symbol_data: &'mmap SectionStash) -> anyhow::Result<Self> {
        // Find the address of the first segment. This is the base address of
        // the object. We need this to correctly offset addresses.
        let base_addr = object.segments().next().map_or(0, |seg| seg.address());

        let endian = if object.is_little_endian() {
            Endian::Little
        } else {
            Endian::Big
        };

        let dwarf = {
            let mut symbol_loader = |id| load_file_section(id, &object, endian, symbol_data);
            gimli::Dwarf::load(&mut symbol_loader)?
        };

        let symbol_map = object.symbol_map();

        let context = Context {
            dwarf: addr2line::Context::from_dwarf(dwarf)?,
            symbol_map,
            base_addr,
            _object: object,
        };

        Ok(context)
    }
}

/// Creates a memory map from the given path.
fn mmap_path(path: &Path) -> io::Result<Mmap> {
    let f = File::open(path)?;
    unsafe { Mmap::map(&f) }
}

/// Loads a single section. This is called by gimli to load each of the
/// sections. Some sections may be compressed and need to be decompressed into
/// an intermediate buffer (`data`).
fn load_file_section<'a, 'b>(
    id: gimli::SectionId,
    file: &object::File<'a>,
    endian: gimli::RunTimeEndian,
    data: &'b SectionStash,
) -> object::Result<gimli::EndianSlice<'b, gimli::RunTimeEndian>>
where
    'a: 'b,
{
    use object::Object;
    use object::ObjectSection;

    match file.section_by_name(id.name()) {
        // FIXME: There is an intermediate allocation if the data is compressed.
        // It would be better to decompress it directly into the arena allocator
        // to avoid the intermediate heap allocation, but this isn't easy to do
        // with the current interface for `uncompressed_data`.
        Some(section) => match section.uncompressed_data()? {
            Cow::Borrowed(bytes) => Ok(gimli::EndianSlice::new(bytes, endian)),
            Cow::Owned(bytes) => Ok(gimli::EndianSlice::new(data.alloc(bytes), endian)),
        },
        None => Ok(gimli::EndianSlice::new(&[][..], endian)),
    }
}

/// Searches for the associated debuglink file. The search rules follow the ones
/// described in
/// https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
fn locate_debuglink(elf_path: &Path, debuglink: &Path) -> Option<PathBuf> {
    const DEBUG_PATH: &str = "/usr/lib/debug";

    let elf_path = elf_path.canonicalize().ok()?;
    let parent = elf_path.parent()?;

    // TODO: Check "/usr/lib/debug/.build-id/ab/cdef1234.debug"

    // Check "/path/to/parent/{debuglink}"
    let path = parent.join(debuglink);
    if path != elf_path && path.is_file() {
        return Some(path);
    }

    // Check "/path/to/parent/.debug/{debuglink}"
    let mut path = parent.join(".debug");
    path.push(debuglink);
    if path != elf_path && path.is_file() {
        return Some(path);
    }

    // Check "/usr/lib/debug/path/to/parent/{debuglink}"
    let mut path = Path::new(DEBUG_PATH).join(parent.strip_prefix("/").unwrap());
    path.push(debuglink);
    if path.is_file() {
        return Some(path);
    }

    None
}
