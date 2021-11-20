/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use reverie::syscalls::Sysno;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
pub struct Filter {
    /// Inverses the match.
    pub inverse: bool,

    /// The set of syscalls to match.
    pub syscalls: Vec<Sysno>,
}

impl std::str::FromStr for Filter {
    type Err = String;

    // Must parse this: [!][?]value1[,[?]value2]...
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (inverse, s) = match s.strip_prefix('!') {
            Some(s) => (true, s),
            None => (false, s),
        };

        let mut syscalls = Vec::new();

        for value in s.split(',') {
            // FIXME: Handle syscall sets, so we can use '%stat` to trace all
            // stat calls, for example.
            if value.strip_prefix('%').is_some() {
                return Err("filtering sets of syscall is not yet supported".into());
            }

            let syscall: Sysno = value
                .parse()
                .map_err(|()| format!("invalid syscall name '{}'", value))?;

            syscalls.push(syscall);
        }

        Ok(Self { inverse, syscalls })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_filter() {
        assert_eq!(
            "open,mmap".parse(),
            Ok(Filter {
                inverse: false,
                syscalls: vec![Sysno::open, Sysno::mmap]
            })
        );

        assert_eq!(
            "open,foobar".parse::<Filter>(),
            Err("invalid syscall name 'foobar'".into())
        );

        assert_eq!(
            "!read,write".parse(),
            Ok(Filter {
                inverse: true,
                syscalls: vec![Sysno::read, Sysno::write]
            })
        );
    }
}
