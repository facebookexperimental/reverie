/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::ffi::OsStr;
use std::ffi::OsString;

use super::util::CStringArray;

/// A mapping of environment variables.
#[derive(Default, Clone, Debug)]
pub struct Env {
    clear: bool,
    vars: BTreeMap<OsString, Option<OsString>>,
}

impl Env {
    /// Clear out all environment variables, including the ones inherited from
    /// the parent process. Any variables set after this are completely new
    /// variables.
    pub fn clear(&mut self) {
        self.clear = true;
        self.vars.clear();
    }

    pub fn is_cleared(&self) -> bool {
        self.clear
    }

    pub fn set(&mut self, key: &OsStr, value: &OsStr) {
        self.vars.insert(key.to_owned(), Some(value.to_owned()));
    }

    pub fn get<K: AsRef<OsStr>>(&self, key: K) -> Option<&OsStr> {
        self.vars
            .get(key.as_ref())
            .and_then(|v| v.as_ref().map(|v| v.as_os_str()))
    }

    pub fn get_captured<K: AsRef<OsStr>>(&self, key: K) -> Option<Cow<OsStr>> {
        let key = key.as_ref();

        if !self.clear {
            if let Some(var) = std::env::var_os(key) {
                return Some(Cow::Owned(var));
            }
        }

        self.get(key).map(Cow::Borrowed)
    }

    pub fn remove(&mut self, key: &OsStr) {
        if self.clear {
            self.vars.remove(key);
        } else {
            self.vars.insert(key.to_owned(), None);
        }
    }

    /// Capture the current environment and merge it with the changes we've
    /// applied.
    pub fn capture(&self) -> BTreeMap<OsString, OsString> {
        let mut env = if self.clear {
            BTreeMap::new()
        } else {
            // Capture from the current environment.
            std::env::vars_os().collect()
        };

        for (k, v) in &self.vars {
            if let Some(v) = v {
                env.insert(k.clone(), v.clone());
            } else {
                env.remove(k);
            }
        }

        env
    }

    pub fn array(&self) -> CStringArray {
        use std::os::unix::ffi::OsStringExt;

        let env = self.capture();

        let mut result = CStringArray::with_capacity(env.len());
        for (mut k, v) in env {
            // Reserve additional space for '=' and null terminator
            k.reserve_exact(v.len() + 2);
            k.push("=");
            k.push(&v);

            // Add the new entry into the array
            result.push(CString::new(k.into_vec()).unwrap());
        }

        result
    }

    pub fn iter(&self) -> impl Iterator<Item = (&OsStr, Option<&OsStr>)> {
        self.vars.iter().map(|(k, v)| (k.as_ref(), v.as_deref()))
    }
}
