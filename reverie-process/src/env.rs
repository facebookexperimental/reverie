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

    pub fn get_captured<K: AsRef<OsStr>>(&self, key: K) -> Option<Cow<'_, OsStr>> {
        let key = key.as_ref();
        match self.vars.get(key) {
            // Explicit settings and removals take precedence, as in capture().
            Some(value) => value.as_deref().map(Cow::Borrowed),
            None if self.clear => None,
            None => std::env::var_os(key).map(Cow::Owned),
        }
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

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStrExt;

    use super::*;

    fn assert_captured_value(env: &Env, key: &OsStr, expected: Option<&OsStr>) {
        assert_eq!(env.get_captured(key).as_deref(), expected);
        assert_eq!(env.capture().get(key).map(OsString::as_os_str), expected);
    }

    #[test]
    fn get_captured_inherits_unmodified_environment() {
        let inherited = std::env::var_os("PATH").expect("the test process has a PATH");
        let env = Env::default();

        assert_captured_value(&env, OsStr::new("PATH"), Some(&inherited));
    }

    #[test]
    fn get_captured_prefers_explicit_value() {
        let mut explicit = std::env::var_os("PATH").expect("the test process has a PATH");
        // Appending guarantees a different value, including non-UTF8 bytes,
        // without changing the test process's environment.
        explicit.push(OsStr::from_bytes(b":/guest/\xff/bin"));
        let mut env = Env::default();
        env.set(OsStr::new("PATH"), &explicit);

        assert_captured_value(&env, OsStr::new("PATH"), Some(&explicit));
    }

    #[test]
    fn get_captured_honors_explicit_removal() {
        assert!(std::env::var_os("PATH").is_some());
        let mut env = Env::default();
        env.remove(OsStr::new("PATH"));

        assert_captured_value(&env, OsStr::new("PATH"), None);
    }

    #[test]
    fn get_captured_clear_discards_explicit_and_inherited_values() {
        let mut env = Env::default();
        env.set(OsStr::new("PATH"), OsStr::new("/guest/bin"));
        env.clear();

        assert_captured_value(&env, OsStr::new("PATH"), None);
        assert!(env.capture().is_empty());
    }

    #[test]
    fn get_captured_uses_values_set_after_clear() {
        let mut env = Env::default();
        env.clear();
        env.set(OsStr::new("PATH"), OsStr::new("/guest/bin"));

        assert_captured_value(&env, OsStr::new("PATH"), Some(OsStr::new("/guest/bin")));

        env.remove(OsStr::new("PATH"));
        assert_captured_value(&env, OsStr::new("PATH"), None);
        assert!(env.capture().is_empty());
    }

    #[test]
    fn get_captured_preserves_non_utf8_keys_and_values() {
        let key = OsStr::from_bytes(b"REVERIE_\xff");
        let value = OsStr::from_bytes(b"value_\xfe");
        let mut env = Env::default();
        env.clear();
        env.set(key, value);

        assert_captured_value(&env, key, Some(value));

        env.remove(key);
        assert_captured_value(&env, key, None);
    }
}
