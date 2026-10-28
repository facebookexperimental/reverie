/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Turning off a sanitizer build's leak check in the environment a [`Command`]
//! gives its program, keeping every other sanitizer setting.
//!
//! LeakSanitizer checks for leaks at exit from a helper thread it clones with
//! `CLONE_UNTRACED`, which stops every other thread of the process with
//! `PTRACE_ATTACH`. A traced program cannot pass that check: each of its
//! threads already has a tracer, so Linux refuses the helper's attach with
//! `EPERM`, which LeakSanitizer reports as a fatal error.

use std::ffi::OsStr;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;

use crate::Command;

/// The variables an AddressSanitizer build reads the common sanitizer flags,
/// `detect_leaks` among them, from, in the order it reads them: a setting in a
/// later one replaces one in an earlier one. LeakSanitizer alone reads only
/// `LSAN_OPTIONS`.
pub const SANITIZER_OPTIONS: [&str; 3] = ["ASAN_OPTIONS", "LSAN_OPTIONS", "UBSAN_OPTIONS"];

/// The setting that turns LeakSanitizer's exit-time check off.
pub const LEAK_CHECK_OFF: &str = "detect_leaks=0";

/// The sanitizers' option separators: they read `name=value` settings split
/// at any of these, left to right, a later setting of a flag replacing an
/// earlier one.
const SEPARATORS: &[u8] = b" ,:\n\t\r";

/// The settings in sanitizer `options`, in the order the sanitizers read them.
fn settings(options: &OsStr) -> impl Iterator<Item = &[u8]> {
    options
        .as_bytes()
        .split(|byte| SEPARATORS.contains(byte))
        .filter(|setting| !setting.is_empty())
}

/// Whether `setting` turns the leak check off.
fn turns_leak_check_off(setting: &[u8]) -> bool {
    setting
        .strip_prefix(b"detect_leaks=")
        .is_some_and(|value| matches!(value, b"0" | b"no" | b"false"))
}

/// Sanitizer `options` with the leak check turned off and every other setting
/// kept: [`LEAK_CHECK_OFF`] after them, unless their last setting already
/// turns the check off, in which case they are returned unchanged. A value
/// this returns is therefore returned unchanged by it.
pub fn with_leak_check_off(options: Option<&OsStr>) -> OsString {
    let options = options.unwrap_or_default();
    if settings(options).last().is_some_and(turns_leak_check_off) {
        return options.to_os_string();
    }
    let mut merged = options.to_os_string();
    if !merged.is_empty() {
        merged.push(":");
    }
    merged.push(LEAK_CHECK_OFF);
    merged
}

/// Whether sanitizer options `values`, given in [`SANITIZER_OPTIONS`] order,
/// leave the leak check on: on unless the last `detect_leaks` setting in them
/// turns it off.
pub fn leak_check_left_on<'a>(values: impl IntoIterator<Item = Option<&'a OsStr>>) -> bool {
    let mut on = true;
    for setting in values.into_iter().flatten().flat_map(settings) {
        if setting.starts_with(b"detect_leaks=") {
            on = !turns_leak_check_off(setting);
        }
    }
    on
}

impl Command {
    /// Turns off a sanitizer build's leak check in the environment this
    /// command gives its program, keeping every other sanitizer setting:
    /// [`with_leak_check_off`] of `ASAN_OPTIONS` and `LSAN_OPTIONS`, and of
    /// `UBSAN_OPTIONS` when that is set. A command this was already applied to
    /// is left as it is.
    pub fn turn_off_leak_check(&mut self) -> &mut Self {
        for name in SANITIZER_OPTIONS {
            let options = self.get_env(name);
            if name == "UBSAN_OPTIONS" && options.is_none() {
                continue;
            }
            let options = with_leak_check_off(options.as_deref());
            self.env(name, options);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_leak_check_is_turned_off_and_every_other_setting_kept() {
        let off = |options: &str| with_leak_check_off(Some(OsStr::new(options)));
        assert_eq!(with_leak_check_off(None), "detect_leaks=0");
        assert_eq!(off(""), "detect_leaks=0");
        assert_eq!(
            off("exitcode=42:symbolize=0"),
            "exitcode=42:symbolize=0:detect_leaks=0"
        );
        assert_eq!(off("detect_leaks=1"), "detect_leaks=1:detect_leaks=0");
        // Only a last setting that turns the check off is enough: an include
        // after it, or a quoted value, can turn it back on.
        assert_eq!(
            off("detect_leaks=0:include=/etc/asan"),
            "detect_leaks=0:include=/etc/asan:detect_leaks=0"
        );
        assert_eq!(
            off("log_path=\"a detect_leaks=0 b\""),
            "log_path=\"a detect_leaks=0 b\":detect_leaks=0"
        );
        for kept in [
            "detect_leaks=0",
            "exitcode=42,detect_leaks=false",
            "detect_leaks=1 detect_leaks=no",
            "exitcode=42:detect_leaks=0:",
        ] {
            assert_eq!(off(kept), kept, "already off");
        }
    }

    #[test]
    fn the_leak_check_is_read_as_the_sanitizers_read_their_options() {
        let left_on =
            |values: [Option<&str>; 3]| leak_check_left_on(values.map(|v| v.map(OsStr::new)));
        assert!(left_on([None, None, None]), "on by default");
        assert!(left_on([Some("exitcode=42"), None, None]));
        assert!(!left_on([Some("detect_leaks=0"), None, None]));
        assert!(!left_on([
            Some("halt_on_error=0,detect_leaks=false"),
            None,
            None
        ]));
        assert!(!left_on([None, Some("verbosity=1 detect_leaks=no"), None]));
        assert!(
            left_on([Some("detect_leaks=0:detect_leaks=1"), None, None]),
            "the last wins"
        );
        assert!(left_on([
            Some("detect_leaks=0"),
            Some("detect_leaks=1"),
            None
        ]));
        assert!(!left_on([
            Some("detect_leaks=1"),
            Some("detect_leaks=0"),
            None
        ]));
        assert!(
            left_on([
                Some("detect_leaks=0"),
                Some("detect_leaks=0"),
                Some("detect_leaks=1")
            ]),
            "UBSAN_OPTIONS is read last"
        );
    }

    #[test]
    fn a_command_turns_the_leak_check_off_once_in_every_variable_it_sets() {
        let mut command = Command::new("/bin/true");
        command
            .env_clear()
            .env("ASAN_OPTIONS", "exitcode=42")
            .turn_off_leak_check();
        let env = command.get_captured_envs();
        assert_eq!(
            env.get(OsStr::new("ASAN_OPTIONS")).unwrap(),
            "exitcode=42:detect_leaks=0"
        );
        assert_eq!(
            env.get(OsStr::new("LSAN_OPTIONS")).unwrap(),
            "detect_leaks=0"
        );
        assert!(
            !env.contains_key(OsStr::new("UBSAN_OPTIONS")),
            "an unset UBSAN_OPTIONS stays unset"
        );
        command
            .env("UBSAN_OPTIONS", "detect_leaks=1")
            .turn_off_leak_check();
        assert_eq!(
            command.get_captured_envs(),
            [
                ("ASAN_OPTIONS", "exitcode=42:detect_leaks=0"),
                ("LSAN_OPTIONS", "detect_leaks=0"),
                ("UBSAN_OPTIONS", "detect_leaks=1:detect_leaks=0"),
            ]
            .into_iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect(),
            "applying it again changes only the newly set variable"
        );
    }
}
