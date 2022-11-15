/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::borrow::Cow;
use std::fs::File;
use std::path::Path;

use gimli::EndianSlice;
use gimli::RunTimeEndian as Endian;
use object::Object as _;
use object::SymbolMapName;
use typed_arena::Arena;

struct Context<'mmap> {
    dwarf: addr2line::Context<EndianSlice<'mmap, Endian>>,
    symbol_map: object::SymbolMap<SymbolMapName<'mmap>>,
    _object: object::File<'mmap>,
}

/// Symbols that have been loaded for a library.
pub struct Symbols {
    // This is a self-referential struct. The `context` and `symbol_data`
    // reference the memory in `mmap`. This is all safe because the memory in
    // the mmap is guaranteed to never move or be modified. However, since Rust
    // cannot do self-referential structs, we must resort to some unsafe
    // shenanigans like transmuting the 'static lifetime below.
    _mmap: memmap::Mmap,
    context: Context<'static>,
    symbol_data: Arena<Cow<'static, [u8]>>,
}

/// After the initial creation, symbol data is not mutated again so it is safe
/// to use from multiple threads.
unsafe impl Sync for Symbols {}

impl Symbols {
    /// Loads the symbol data from the given path.
    pub fn load(path: &Path) -> Result<Self, anyhow::Error> {
        use core::mem::transmute;

        let f = File::open(path)?;
        let mmap = unsafe { memmap::Mmap::map(&f) }?;
        let object = object::File::parse(&*mmap)?;

        // TODO: Locate the gnu_debuglink path and load it as a supplemenetary
        // object.

        let endian = if object.is_little_endian() {
            Endian::Little
        } else {
            Endian::Big
        };

        let symbol_data = Arena::new();

        let dwarf = {
            let mut symbol_loader = |id| load_file_section(id, &object, endian, &symbol_data);
            gimli::Dwarf::load(&mut symbol_loader)?
        };

        let context = Context {
            dwarf: addr2line::Context::from_dwarf(dwarf)?,
            symbol_map: object.symbol_map(),
            _object: object,
        };

        // Must do this lifetime transmute shenangians to get around
        // self-referential struct limitations. This lifetime transformation is
        // safe since the references all point to `mmap`, which is guaranteed to
        // not move and will be dropped at the same time as these references.
        let context = unsafe { transmute::<Context<'_>, Context<'static>>(context) };

        // Similarly, the arena-allocated symbol data will not change or move
        // during the lifetime of `Context`.
        let symbol_data =
            unsafe { transmute::<Arena<Cow<'_, [u8]>>, Arena<Cow<'static, [u8]>>>(symbol_data) };

        Ok(Self {
            _mmap: mmap,
            context,
            symbol_data,
        })
    }

    pub fn find_frames(
        &self,
        probe: u64,
    ) -> Result<addr2line::FrameIter<EndianSlice<'static, Endian>>, gimli::read::Error> {
        self.context.dwarf.find_frames(probe)
    }

    /// Finds a symbol in the symbol table using the given address. If the
    /// symbol does not exist, returns `None`. Note that this purely uses the
    /// symbol table to find the symbol name and does not depend on the debug
    /// info at all. This should be used as a fallback if `find_frames` is
    /// unable to locate the symbol name using the debug info.
    ///
    /// Symbol lookup uses binary search, so it lookup happens in `O(log n)`
    /// amortized time.
    pub fn find_symbol(&self, probe: u64) -> Option<SymbolMapName> {
        self.context.symbol_map.get(probe).copied()
    }

    /// Returns the number of bytes used to store the debug information. This is
    /// used to keep track of our memory overhead when loading symbols.
    pub fn bytes_used(&self) -> usize {
        self.symbol_data.len()
    }
}

fn load_file_section<'a, 'b>(
    id: gimli::SectionId,
    file: &object::File<'a>,
    endian: gimli::RunTimeEndian,
    data: &'b Arena<Cow<'a, [u8]>>,
) -> object::Result<gimli::EndianSlice<'b, gimli::RunTimeEndian>> {
    use object::Object;
    use object::ObjectSection;

    match file.section_by_name(id.name()) {
        // FIXME: There is an intermediate allocation if the data is compressed.
        // It would be better to decompress it directly into the arena allocator
        // to avoid the intermediate heap allocation.
        Some(section) => match section.uncompressed_data()? {
            Cow::Borrowed(bytes) => Ok(gimli::EndianSlice::new(bytes, endian)),
            Cow::Owned(bytes) => Ok(gimli::EndianSlice::new(data.alloc(bytes.into()), endian)),
        },
        None => Ok(gimli::EndianSlice::new(&[][..], endian)),
    }
}
