/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Finds a versioned function in the process's `libc.so.6` without the `dl*`
//! API (<https://github.com/rrnewton/reverie/issues/980>).
//!
//! Guest preloads that link gcc 15's unwinder statically need glibc's real
//! `_dl_find_object@GLIBC_2.35` and must find it at any time: while another
//! thread runs a library constructor under `dlopen`, before their own
//! initializer, and without changing the caller's `dlerror` state.
//! `dlsym`/`dlvsym` take the loader's `dl_load_lock`, which `dlopen` holds
//! while it runs constructors, and they set or clear `dlerror`. This module
//! calls only libc's `gnu_get_libc_version`, which returns a constant, and
//! `dl_iterate_phdr`, which takes the loader's recursive `dl_load_write_lock`;
//! neither touches `dlerror` (an interposer of the first may: see the end of
//! this documentation). glibc holds that lock
//! only while it appends to or removes from its list of loaded objects
//! (`_dl_add_to_namespace_list`, and `dlclose` after destructors have run) and
//! while `dl_iterate_phdr` calls its callback. No constructor or destructor
//! runs under it, so a lookup cannot wait on a thread that is running one.
//!
//! It finds libc as the object whose loaded segments contain the version
//! string `gnu_get_libc_version` returns, reading only each object's
//! program-header array to do so, checks its `DT_SONAME`, and reads its
//! dynamic section: the string and symbol tables, the
//! GNU hash table (or the SysV one, which glibc 2.36 and later may omit), and
//! the version tables. Every address it reads is checked to lie in one of the
//! object's readable loaded segments. A name is found only as a defined
//! `STT_FUNC` symbol (not an IFUNC, whose address is its resolver) of global or
//! weak binding whose version index names the requested version. Anything
//! unexpected gives `None`. It allocates nothing and cannot panic, so it may run
//! inside a `dl_iterate_phdr` callback or an unwinder.
//!
//! Its exposure is libgcc's before glibc 2.35, when its unwinder found unwind
//! tables with `dl_iterate_phdr` on every unwind: the lock (the same thread may
//! re-enter it, but another thread's `dl_iterate_phdr` callback that waits for
//! this lookup would wait forever, and a signal handler that interrupted the
//! loader's own list update on this thread would see that update half done),
//! and the program headers it reads for every object (an object that made its
//! own program-header array unreadable would fault it). One more, for the way
//! libc is found: a preload that defines `gnu_get_libc_version` itself and
//! returns a string of its own makes the lookup read that preload's dynamic
//! section and refuse it by soname, so the answer is `None`, and a fault if
//! that preload had made its own dynamic section unreadable. And any preload
//! that interposes `gnu_get_libc_version`, even one that forwards it to libc
//! truthfully, runs on the lookup's path, so its own side effects apply: a
//! wrapper that finds libc's function with `dlsym` on each call clears the
//! caller's pending `dlerror` and takes the loader lock that `dlopen` holds
//! while it runs constructors.

use std::ffi::c_int;
use std::ffi::c_void;
use std::mem::size_of;

/// The address of `name` at `version` (for example `_dl_find_object` at
/// `GLIBC_2.35`) in this process's `libc.so.6`, or `None` when that libc does
/// not define it, defines it only as an IFUNC, or cannot be read as expected.
pub fn glibc_versioned_function(name: &[u8], version: &[u8]) -> Option<usize> {
    find(name, version, &LOOKUP_ORDER)
}

/// The hash tables a lookup tries, in order: a libc may have either or both.
const LOOKUP_ORDER: [HashTable; 2] = [HashTable::Gnu, HashTable::SysV];

/// Which symbol hash table a lookup may use, in order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HashTable {
    Gnu,
    SysV,
}

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_R: u32 = 4;

const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SONAME: i64 = 14;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_VERSYM: i64 = 0x6fff_fff0;
const DT_VERDEF: i64 = 0x6fff_fffc;
const DT_VERDEFNUM: i64 = 0x6fff_fffd;

const STT_FUNC: u8 = 2;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const SHN_UNDEF: u16 = 0;
const VERSYM_INDEX: u16 = 0x7fff;

/// More loaded segments than any libc has; extra ones are ignored, which can
/// only make a read fail.
const MAX_SEGMENTS: usize = 16;
/// Bounds on table walks, so corrupt data cannot loop forever.
const MAX_STEPS: usize = 1 << 20;
const MAX_NAME: usize = 256;

fn find(name: &[u8], version: &[u8], tables: &[HashTable]) -> Option<usize> {
    with_libc(|object| {
        tables
            .iter()
            .find_map(|table| object.lookup(name, version, *table))
    })
}

/// Runs `inspect` on this process's `libc.so.6` and returns its answer.
///
/// libc is the object whose loaded segments contain the string
/// `gnu_get_libc_version` returns: glibc's `__libc_version`, a constant in
/// libc's own read-only data that libc's code addresses directly. Neither of
/// the two ways a function address can lie outside libc moves that pointer: a
/// preload that interposes `gnu_get_libc_version` and forwards it to libc (as
/// profilers' and sanitizers' wrappers forward the functions they wrap) returns
/// libc's pointer, and a non-PIE executable whose PLT entry is the function's
/// canonical address still calls libc's code through it. So the object found
/// is the libc this process uses, whatever path it was loaded from. (The
/// address of a libc function would be neither: it is the interposer's
/// definition, or the executable's PLT entry.) libc's function takes no lock
/// and leaves `dlerror` alone; an interposer's need not (see the module
/// documentation).
///
/// Finding the object reads only the program-header array `dl_iterate_phdr`
/// passes for each object, as libgcc's unwinder did for every object before
/// glibc 2.35. Nothing else of any other object is read: not its dynamic
/// section, which a library may have made unreadable with `mprotect`, whatever
/// its name or segment flags say. libc's own dynamic section stays readable
/// because the loader itself uses it. Its `DT_SONAME` must also be
/// `libc.so.6`, so an interposer that returned a string of its own gives
/// `None`.
fn with_libc<R>(mut inspect: impl FnMut(&Object) -> Option<R>) -> Option<R> {
    struct Search<'a, R> {
        libc_data: usize,
        inspect: &'a mut dyn FnMut(&Object) -> Option<R>,
        found: Option<R>,
    }

    unsafe extern "C" fn visit<R>(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut c_void,
    ) -> c_int {
        // SAFETY: `data` is the `Search` passed below, and glibc passes a valid
        // `info` whose program headers stay mapped during the callback.
        let (search, info) = unsafe { (&mut *data.cast::<Search<R>>(), &*info) };
        // SAFETY: as above.
        if !unsafe { maps(info, search.libc_data) } {
            return 0;
        }
        // SAFETY: as above.
        if let Some(object) = unsafe { Object::new(info) }
            && object.soname_is(b"libc.so.6")
        {
            search.found = (search.inspect)(&object);
        }
        1
    }

    // SAFETY: gnu_get_libc_version takes no arguments and returns a pointer to
    // a constant string, or so glibc documents.
    let libc_data = unsafe { libc::gnu_get_libc_version() } as usize;
    if libc_data == 0 {
        return None;
    }
    let mut search = Search {
        libc_data,
        inspect: &mut inspect,
        found: None,
    };
    // SAFETY: `visit` matches dl_iterate_phdr's callback contract and `search`
    // outlives the call.
    unsafe { libc::dl_iterate_phdr(Some(visit::<R>), (&raw mut search).cast()) };
    search.found
}

/// Whether one of the object's loaded segments contains `address`, from its
/// program headers alone.
///
/// # Safety
///
/// `info` must describe a loaded object whose program headers are mapped.
unsafe fn maps(info: &libc::dl_phdr_info, address: usize) -> bool {
    if info.dlpi_phdr.is_null() {
        return false;
    }
    // SAFETY: glibc passes `dlpi_phnum` mapped program headers.
    let headers = unsafe { std::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum.into()) };
    headers.iter().any(|header| {
        let start = (info.dlpi_addr as usize).wrapping_add(header.p_vaddr as usize);
        header.p_type == PT_LOAD && start <= address && address - start < header.p_memsz as usize
    })
}

/// One loaded object's readable segments and dynamic-section entries.
#[derive(Clone)]
struct Object {
    base: usize,
    segments: [(usize, usize); MAX_SEGMENTS],
    segment_count: usize,
    strtab: Option<usize>,
    strsz: Option<usize>,
    symtab: Option<usize>,
    soname: Option<usize>,
    gnu_hash: Option<usize>,
    sysv_hash: Option<usize>,
    versym: Option<usize>,
    verdef: Option<usize>,
    verdefnum: Option<usize>,
}

impl Object {
    /// # Safety
    ///
    /// `info` must describe a loaded object whose program headers are mapped.
    unsafe fn new(info: &libc::dl_phdr_info) -> Option<Self> {
        let mut object = Object {
            base: info.dlpi_addr as usize,
            segments: [(0, 0); MAX_SEGMENTS],
            segment_count: 0,
            strtab: None,
            strsz: None,
            symtab: None,
            soname: None,
            gnu_hash: None,
            sysv_hash: None,
            versym: None,
            verdef: None,
            verdefnum: None,
        };
        if info.dlpi_phdr.is_null() {
            return None;
        }
        // SAFETY: glibc passes `dlpi_phnum` mapped program headers.
        let headers = unsafe { std::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum.into()) };
        let mut dynamic = None;
        for header in headers {
            let start = object.base.checked_add(header.p_vaddr as usize)?;
            let end = start.checked_add(header.p_memsz as usize)?;
            match header.p_type {
                PT_LOAD if header.p_flags & PF_R != 0 && object.segment_count < MAX_SEGMENTS => {
                    object.segments[object.segment_count] = (start, end);
                    object.segment_count += 1;
                }
                PT_DYNAMIC => dynamic = Some((start, end)),
                _ => {}
            }
        }
        let (mut entry, end) = dynamic?;
        while entry.checked_add(16)? <= end {
            let tag = object.read::<i64>(entry)?;
            let value = object.read::<u64>(entry.wrapping_add(8))? as usize;
            match tag {
                DT_NULL => break,
                DT_STRTAB => object.strtab = Some(object.relocate(value)),
                DT_STRSZ => object.strsz = Some(value),
                DT_SYMTAB => object.symtab = Some(object.relocate(value)),
                DT_SONAME => object.soname = Some(value),
                DT_GNU_HASH => object.gnu_hash = Some(object.relocate(value)),
                DT_HASH => object.sysv_hash = Some(object.relocate(value)),
                DT_VERSYM => object.versym = Some(object.relocate(value)),
                DT_VERDEF => object.verdef = Some(object.relocate(value)),
                DT_VERDEFNUM => object.verdefnum = Some(value),
                _ => {}
            }
            entry = entry.wrapping_add(16);
        }
        Some(object)
    }

    /// An address-valued dynamic entry as an address: glibc has already
    /// added the load base to most of them in place on x86-64, but a value
    /// below the base is still an offset from it.
    fn relocate(&self, value: usize) -> usize {
        if value < self.base {
            self.base.wrapping_add(value)
        } else {
            value
        }
    }

    /// Reads a `T` at `address` if all of it lies in one readable segment.
    fn read<T: Copy>(&self, address: usize) -> Option<T> {
        let end = address.checked_add(size_of::<T>())?;
        self.segments[..self.segment_count]
            .iter()
            .any(|(start, stop)| *start <= address && end <= *stop)
            // SAFETY: the bytes lie in a readable segment of a loaded object.
            .then(|| unsafe { std::ptr::read_unaligned(address as *const T) })
    }

    /// Whether the string at `offset` in the string table is exactly `text`.
    fn string_is(&self, offset: usize, text: &[u8]) -> bool {
        let (Some(strtab), Some(strsz)) = (self.strtab, self.strsz) else {
            return false;
        };
        if text.len() >= MAX_NAME
            || offset
                .checked_add(text.len())
                .is_none_or(|end| end >= strsz)
        {
            return false;
        }
        let start = strtab.wrapping_add(offset);
        text.iter()
            .chain(std::iter::once(&0u8))
            .enumerate()
            .all(|(index, byte)| self.read::<u8>(start.wrapping_add(index)) == Some(*byte))
    }

    fn soname_is(&self, text: &[u8]) -> bool {
        self.soname
            .is_some_and(|offset| self.string_is(offset, text))
    }

    fn lookup(&self, name: &[u8], version: &[u8], table: HashTable) -> Option<usize> {
        let index = self.version_index(version)?;
        match table {
            HashTable::Gnu => self.gnu_lookup(name, index),
            HashTable::SysV => self.sysv_lookup(name, index),
        }
    }

    /// The `vd_ndx` of the version definition named `version`.
    fn version_index(&self, version: &[u8]) -> Option<u16> {
        let mut definition = self.verdef?;
        for _ in 0..self.verdefnum?.min(MAX_STEPS) {
            // Elf64_Verdef: vd_version, vd_flags, vd_ndx, vd_cnt (u16 each),
            // vd_hash, vd_aux, vd_next (u32 each).
            let ndx = self.read::<u16>(definition.wrapping_add(4))?;
            let aux = self.read::<u32>(definition.wrapping_add(12))? as usize;
            let next = self.read::<u32>(definition.wrapping_add(16))? as usize;
            // Elf64_Verdaux: vda_name, vda_next (u32 each).
            let name = self.read::<u32>(definition.checked_add(aux)?)? as usize;
            if self.string_is(name, version) {
                return Some(ndx);
            }
            if next == 0 {
                return None;
            }
            definition = definition.checked_add(next)?;
        }
        None
    }

    /// The address of symbol `index` if it is `name`, a defined function of
    /// global or weak binding, at version index `version`.
    fn symbol_matches(&self, index: usize, name: &[u8], version: u16) -> Option<usize> {
        // Elf64_Sym: st_name (u32), st_info, st_other (u8), st_shndx (u16),
        // st_value, st_size (u64): 24 bytes.
        let symbol = self.symtab?.checked_add(index.checked_mul(24)?)?;
        let st_name = self.read::<u32>(symbol)? as usize;
        let st_info = self.read::<u8>(symbol.wrapping_add(4))?;
        let st_shndx = self.read::<u16>(symbol.wrapping_add(6))?;
        let st_value = self.read::<u64>(symbol.wrapping_add(8))? as usize;
        if st_info & 0xf != STT_FUNC
            || !matches!(st_info >> 4, STB_GLOBAL | STB_WEAK)
            || st_shndx == SHN_UNDEF
            || st_value == 0
            || !self.string_is(st_name, name)
        {
            return None;
        }
        let versym = self.read::<u16>(self.versym?.checked_add(index.checked_mul(2)?)?)?;
        (versym & VERSYM_INDEX == version).then(|| self.base.wrapping_add(st_value))
    }

    fn gnu_lookup(&self, name: &[u8], version: u16) -> Option<usize> {
        let table = self.gnu_hash?;
        let nbuckets = self.read::<u32>(table)? as usize;
        let symoffset = self.read::<u32>(table.wrapping_add(4))? as usize;
        let bloom_size = self.read::<u32>(table.wrapping_add(8))? as usize;
        let bloom_shift = self.read::<u32>(table.wrapping_add(12))?;
        if nbuckets == 0 || bloom_size == 0 {
            return None;
        }
        let hash = gnu_hash(name);
        let bloom = table.wrapping_add(16);
        let word = self.read::<u64>(bloom.checked_add(((hash as usize / 64) % bloom_size) * 8)?)?;
        let mask = (1u64 << (hash % 64)) | (1u64 << ((hash >> (bloom_shift % 32)) % 64));
        if word & mask != mask {
            return None;
        }
        let buckets = bloom.checked_add(bloom_size.checked_mul(8)?)?;
        let chains = buckets.checked_add(nbuckets.checked_mul(4)?)?;
        let mut index =
            self.read::<u32>(buckets.wrapping_add((hash as usize % nbuckets) * 4))? as usize;
        if index < symoffset {
            return None;
        }
        for _ in 0..MAX_STEPS {
            let chain =
                self.read::<u32>(chains.checked_add((index - symoffset).checked_mul(4)?)?)?;
            if (chain | 1) == (hash | 1)
                && let Some(address) = self.symbol_matches(index, name, version)
            {
                return Some(address);
            }
            if chain & 1 != 0 {
                return None;
            }
            index = index.checked_add(1)?;
        }
        None
    }

    fn sysv_lookup(&self, name: &[u8], version: u16) -> Option<usize> {
        let table = self.sysv_hash?;
        let nbucket = self.read::<u32>(table)? as usize;
        let nchain = self.read::<u32>(table.wrapping_add(4))? as usize;
        if nbucket == 0 {
            return None;
        }
        let buckets = table.wrapping_add(8);
        let chains = buckets.checked_add(nbucket.checked_mul(4)?)?;
        let mut index = self
            .read::<u32>(buckets.wrapping_add((sysv_hash(name) as usize % nbucket) * 4))?
            as usize;
        for _ in 0..nchain.min(MAX_STEPS) {
            if index == 0 || index >= nchain {
                return None;
            }
            if let Some(address) = self.symbol_matches(index, name, version) {
                return Some(address);
            }
            index = self.read::<u32>(chains.checked_add(index.checked_mul(4)?)?)? as usize;
        }
        None
    }
}

fn gnu_hash(name: &[u8]) -> u32 {
    name.iter().fold(5381u32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(u32::from(*byte))
    })
}

fn sysv_hash(name: &[u8]) -> u32 {
    name.iter().fold(0u32, |hash, byte| {
        let hash = (hash << 4).wrapping_add(u32::from(*byte));
        let high = hash & 0xf000_0000;
        (hash ^ (high >> 24)) & !high
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use std::ffi::CString;

    use super::*;

    /// What `dlvsym` reports for `name` at `version`, as the reference.
    fn dlvsym(name: &str, version: &str) -> Option<usize> {
        let (name, version) = (CString::new(name).unwrap(), CString::new(version).unwrap());
        // SAFETY: both names are NUL-terminated.
        let symbol = unsafe { libc::dlvsym(libc::RTLD_DEFAULT, name.as_ptr(), version.as_ptr()) };
        (!symbol.is_null()).then_some(symbol as usize)
    }

    /// Which hash tables this process's libc has: (GNU, SysV).
    fn libc_tables() -> (bool, bool) {
        let tables =
            with_libc(|object| Some((object.gnu_hash.is_some(), object.sysv_hash.is_some())));
        let tables = tables.expect("this process has a libc.so.6");
        assert!(tables.0 || tables.1, "libc.so.6 has neither hash table");
        tables
    }

    /// The lookup through both tables, through the GNU table alone and through
    /// the SysV table alone.
    fn each_table(name: &str, version: &str) -> [Option<usize>; 3] {
        let (name, version) = (name.as_bytes(), version.as_bytes());
        [
            glibc_versioned_function(name, version),
            find(name, version, &[HashTable::Gnu]),
            find(name, version, &[HashTable::SysV]),
        ]
    }

    /// What [`each_table`] must give where `dlvsym` gives `expected`: the
    /// combined lookup finds it, and each single table finds it exactly when
    /// this libc has that table, so libcs with one table (GNU only, as glibc
    /// 2.36 and later may be built, or SysV only) check too.
    fn expected_tables(expected: Option<usize>) -> [Option<usize>; 3] {
        let (gnu, sysv) = libc_tables();
        [
            expected,
            expected.filter(|_| gnu),
            expected.filter(|_| sysv),
        ]
    }

    #[test]
    fn dl_find_object_is_found_where_dlvsym_finds_it() {
        let expected = dlvsym("_dl_find_object", "GLIBC_2.35");
        assert_eq!(
            each_table("_dl_find_object", "GLIBC_2.35"),
            expected_tables(expected)
        );
    }

    /// A libc with only one of the two hash tables is searched through that
    /// table: this libc with its GNU or its SysV table taken away, through the
    /// production lookup order, finds what `dlvsym` finds.
    #[test]
    fn a_libc_with_one_hash_table_is_searched_through_it() {
        let (gnu, sysv) = libc_tables();
        for (name, version) in [
            ("_dl_find_object", "GLIBC_2.35"),
            ("realpath", "GLIBC_2.2.5"),
        ] {
            let expected = dlvsym(name, version);
            for (keep_gnu, keep_sysv) in [(true, false), (false, true)] {
                let found = with_libc(|object| {
                    let mut object = object.clone();
                    if !keep_gnu {
                        object.gnu_hash = None;
                    }
                    if !keep_sysv {
                        object.sysv_hash = None;
                    }
                    LOOKUP_ORDER.iter().find_map(|table| {
                        object.lookup(name.as_bytes(), version.as_bytes(), *table)
                    })
                });
                let present = (keep_gnu && gnu) || (keep_sysv && sysv);
                assert_eq!(
                    found,
                    expected.filter(|_| present),
                    "{name}@{version} with gnu={keep_gnu} sysv={keep_sysv}"
                );
            }
        }
    }

    /// Plain functions at their versions, found through each hash table as
    /// `dlvsym` finds them.
    #[test]
    fn versioned_functions_are_found_where_dlvsym_finds_them() {
        for (name, version) in [
            ("dl_iterate_phdr", "GLIBC_2.2.5"),
            ("dlvsym", "GLIBC_2.34"),
            ("pthread_create", "GLIBC_2.34"),
            ("realpath", "GLIBC_2.3"),
            ("realpath", "GLIBC_2.2.5"),
        ] {
            let expected = dlvsym(name, version);
            assert!(expected.is_some(), "dlvsym finds no {name}@{version}");
            assert_eq!(
                each_table(name, version),
                expected_tables(expected),
                "{name}@{version}"
            );
        }
    }

    /// `realpath` has two versions at two addresses; each version finds its
    /// own, including the older, non-default one (its versym hidden bit is
    /// set).
    #[test]
    fn each_version_of_a_function_is_its_own() {
        let new = glibc_versioned_function(b"realpath", b"GLIBC_2.3");
        let old = glibc_versioned_function(b"realpath", b"GLIBC_2.2.5");
        assert!(new.is_some() && old.is_some());
        assert_ne!(new, old);
    }

    #[test]
    fn an_absent_name_or_version_or_a_prefix_is_not_found() {
        assert_eq!(each_table("_dl_find_object", "GLIBC_2.99"), [None; 3]);
        assert_eq!(
            each_table("no_such_function_anywhere", "GLIBC_2.2.5"),
            [None; 3]
        );
        assert_eq!(each_table("realpat", "GLIBC_2.3"), [None; 3]);
        assert_eq!(each_table("realpath", "GLIBC_2.3.4"), [None; 3]);
    }

    /// An IFUNC's symbol value is its resolver, not the function, so it is
    /// refused (memcpy is an IFUNC in x86-64 glibc).
    #[test]
    fn an_ifunc_is_not_found() {
        assert!(dlvsym("memcpy", "GLIBC_2.14").is_some());
        assert_eq!(each_table("memcpy", "GLIBC_2.14"), [None; 3]);
    }

    /// The lookup changes no `dlerror` state: a caller's pending message is
    /// still there after it.
    #[test]
    fn a_lookup_keeps_a_pending_dlerror() {
        // SAFETY: the name is NUL-terminated; it names no library.
        let missing = unsafe {
            libc::dlopen(
                c"/nonexistent/reverie-glibc-symbol-missing.so".as_ptr(),
                libc::RTLD_NOW,
            )
        };
        assert!(missing.is_null());
        assert!(glibc_versioned_function(b"dl_iterate_phdr", b"GLIBC_2.2.5").is_some());
        assert!(glibc_versioned_function(b"_dl_find_object", b"GLIBC_2.99").is_none());
        // SAFETY: dlerror has no preconditions; a non-null result is a
        // NUL-terminated message.
        let error = unsafe { libc::dlerror() };
        assert!(!error.is_null(), "the pending dlerror message is gone");
        // SAFETY: as above.
        let message = unsafe { CStr::from_ptr(error) }.to_string_lossy();
        assert!(
            message.contains("reverie-glibc-symbol-missing.so"),
            "{message}"
        );
    }

    /// libc's soname matches exactly "libc.so.6", not a prefix or extension
    /// of it.
    #[test]
    fn a_string_matches_only_itself() {
        let checks = with_libc(|object| {
            Some([
                object.soname_is(b"libc.so.6"),
                object.soname_is(b"libc.so"),
                object.soname_is(b"libc.so.6x"),
            ])
        });
        assert_eq!(checks, Some([true, false, false]));
    }

    /// Set in the children of the preload tests: the child looks the function
    /// up before libtest's main and exits.
    const PRELOAD_CHILD: &str = "REVERIE_GLIBC_SYMBOL_PRELOAD_CHILD";

    /// A preload whose constructor makes the page holding its own dynamic
    /// section unreadable. Preloads come before libc in the loader's list.
    const POISON_LIBRARY: &str = r#"
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
extern char _DYNAMIC[] __attribute__((visibility("hidden")));
__attribute__((constructor)) static void hide_dynamic(void) {
    uintptr_t page = (uintptr_t)sysconf(_SC_PAGESIZE);
    mprotect((void *)((uintptr_t)_DYNAMIC & ~(page - 1)), page, PROT_NONE);
}
"#;

    #[used]
    #[unsafe(link_section = ".init_array")]
    static PRELOAD_CHECK: extern "C" fn() = preload_check;

    /// In a preload test's child, looks the function up before libtest's main
    /// (whose later `dlsym` calls could read a poisoned preload) and exits.
    extern "C" fn preload_check() {
        if std::env::var_os(PRELOAD_CHILD).is_none() {
            return;
        }
        let found = glibc_versioned_function(b"_dl_find_object", b"GLIBC_2.35");
        let line: &[u8] = if found.is_some() {
            b"resolved=1\n"
        } else {
            b"resolved=0\n"
        };
        // SAFETY: writes a static buffer to stdout, then exits without
        // running anything else in this process.
        unsafe {
            libc::write(1, line.as_ptr().cast(), line.len());
            libc::_exit(0);
        }
    }

    /// A new directory for a preload test, named for it.
    fn preload_directory(label: &str) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "reverie-glibc-symbol-{label}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    /// Builds `source` as `file_name` in `directory`.
    fn build_preload(
        directory: &std::path::Path,
        source: &str,
        file_name: &str,
        extra: &[&str],
    ) -> std::path::PathBuf {
        let source_path = directory.join("preload.c");
        let library = directory.join(file_name);
        std::fs::write(&source_path, source).unwrap();
        let built = std::process::Command::new("cc")
            .args(["-shared", "-fPIC", "-O0"])
            .args(extra)
            .arg("-o")
            .arg(&library)
            .arg(&source_path)
            .status()
            .expect("the preload tests need a C compiler (cc) on PATH");
        assert!(built.success(), "cc failed: {built}");
        library
    }

    /// Runs this binary with `library` preloaded and PRELOAD_CHILD set, and
    /// requires the child to find `_dl_find_object` exactly when this process
    /// does; then removes `directory`.
    fn lookup_with_a_preload(label: &str, directory: &std::path::Path, library: &std::path::Path) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .env(PRELOAD_CHILD, "1")
            .env("LD_PRELOAD", library)
            .output()
            .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
        let expected = if dlvsym("_dl_find_object", "GLIBC_2.35").is_some() {
            "resolved=1"
        } else {
            "resolved=0"
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.trim() == expected,
            "the {label} child exited with {}\nstdout:\n{stdout}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// A preload that interposes `dl_iterate_phdr` and `gnu_get_libc_version`
    /// and forwards each to the next definition (libc's), as profilers' and
    /// sanitizers' wrappers do.
    const FORWARDING_INTERPOSER: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stddef.h>
typedef int (*iterate_function)(int (*)(struct dl_phdr_info *, size_t, void *), void *);
typedef const char *(*version_function)(void);
static iterate_function next_iterate;
static version_function next_version;
__attribute__((constructor)) static void find_the_next_definitions(void) {
    next_iterate = (iterate_function)dlsym(RTLD_NEXT, "dl_iterate_phdr");
    next_version = (version_function)dlsym(RTLD_NEXT, "gnu_get_libc_version");
}
int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data) {
    return next_iterate(callback, data);
}
const char *gnu_get_libc_version(void) { return next_version(); }
"#;

    /// With a forwarding interposer of `dl_iterate_phdr` and
    /// `gnu_get_libc_version` preloaded, the lookup still finds libc: the
    /// string libc returns through the interposer lies in libc, though both
    /// functions' addresses lie in the interposer.
    #[test]
    fn libc_is_found_through_a_forwarding_interposer() {
        let directory = preload_directory("interposer");
        let library = build_preload(&directory, FORWARDING_INTERPOSER, "interposer.so", &[]);
        lookup_with_a_preload("interposer", &directory, &library);
    }

    /// The lookup reads nothing of an object other than libc beyond its
    /// program headers: with a preload whose dynamic section is unreadable
    /// ahead of libc, it still succeeds instead of faulting.
    #[test]
    fn an_unreadable_dynamic_section_elsewhere_is_never_read() {
        let directory = preload_directory("poison");
        let library = build_preload(&directory, POISON_LIBRARY, "poison.so", &[]);
        lookup_with_a_preload("poison", &directory, &library);
    }

    /// A name is not identity: a preload named libc.so.6, with another soname
    /// and an unreadable dynamic section, ahead of libc, is never read.
    #[test]
    fn an_object_named_libc_with_an_unreadable_dynamic_section_is_never_read() {
        let directory = preload_directory("impostor");
        let library = build_preload(
            &directory,
            POISON_LIBRARY,
            "libc.so.6",
            &["-Wl,-soname,impostor.so"],
        );
        lookup_with_a_preload("impostor", &directory, &library);
    }

    /// The real libc loaded through a path with another name (preloaded
    /// through a symlink, so the loader names it by that path) is still found.
    #[test]
    fn libc_loaded_under_another_name_is_found() {
        let directory = preload_directory("alias");
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        // SAFETY: dladdr fills `info` for an address in a loaded object.
        assert_ne!(
            unsafe { libc::dladdr(libc::dl_iterate_phdr as *const c_void, &mut info) },
            0
        );
        // SAFETY: dladdr's dli_fname is a NUL-terminated path.
        let real = unsafe { CStr::from_ptr(info.dli_fname) }
            .to_str()
            .unwrap()
            .to_owned();
        let alias = directory.join("libc-alias-2.99.so");
        std::os::unix::fs::symlink(std::fs::canonicalize(&real).unwrap(), &alias).unwrap();
        lookup_with_a_preload("alias", &directory, &alias);
    }

    #[test]
    fn the_hashes_are_the_elf_ones() {
        assert_eq!(gnu_hash(b""), 5381);
        assert_eq!(gnu_hash(b"printf"), 0x156b_2bb8);
        assert_eq!(sysv_hash(b""), 0);
        assert_eq!(sysv_hash(b"printf"), 0x0779_05a6);
    }
}
