/*
 * Copyright (c) Meta Platforms, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;

use linked_hash_map::Entry;
use linked_hash_map::LinkedHashMap;

use super::library::Library;
use super::symbols::Symbols;

/// Maximum cache size in bytes, including all of the loaded debug info.
///
/// When the cache starts to exceed this size, the least recently used library's
/// symbols will be removed.
const DEFAULT_MAX_CACHE_SIZE: usize = 1 << 30; // 1 GiB

lazy_static::lazy_static! {
    static ref CACHE: Mutex<DebugInfoCache> = Mutex::new(DebugInfoCache::new());
}

/// An LRU cache of loaded symbols. This is shared by all processes since we
/// only need to load symbols once for a particular inode. However, each process
/// will have mapped these libraries into memory differently, so that is tracked
/// on a per-process basis.
pub struct DebugInfoCache {
    /// Mapping of inode -> symbols.
    cache: LinkedHashMap<u64, Arc<Symbols>>,
    size: usize,
    max_size: usize,
}

impl DebugInfoCache {
    fn new() -> Self {
        Self {
            cache: Default::default(),
            size: 0,
            max_size: DEFAULT_MAX_CACHE_SIZE,
        }
    }

    /// Loads the symbols for the given library. Returns an error if the symbols
    /// failed to load.
    pub fn load(&mut self, library: &Library) -> Result<Arc<Symbols>, anyhow::Error> {
        match self.cache.entry(library.inode) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let symbols = Arc::new(Symbols::load(&library.path)?);

                self.size += symbols.bytes_used();

                let symbols = entry.insert(symbols).clone();

                // Evict older entries if we've exceeded the max cache size.
                // Even if we evict the entry we just inserted, that's fine
                // since we still return an `Arc`.
                while self.size > self.max_size {
                    if let Some((_k, v)) = self.cache.pop_front() {
                        self.size -= v.bytes_used();
                    }
                }

                Ok(symbols)
            }
        }
    }
}

pub fn cache() -> MutexGuard<'static, DebugInfoCache> {
    CACHE.lock().expect("lock poisoned")
}
