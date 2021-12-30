/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use serde::{Deserialize, Serialize};
use std::str::FromStr;

bitflags::bitflags! {
    /// A namespace that may be unshared with [`Command::unshare`].
    ///
    /// [`Command::unshare`]: super::Command::unshare
    #[derive(Deserialize, Serialize)]
    pub struct Namespace: i32 {
        /// Cgroup namespace.
        const CGROUP = libc::CLONE_NEWCGROUP;
        /// IPC namespace.
        const IPC = libc::CLONE_NEWIPC;
        /// Network namespace.
        const NETWORK = libc::CLONE_NEWNET;
        /// Mount namespace.
        const MOUNT = libc::CLONE_NEWNS;
        /// PID namespace.
        const PID = libc::CLONE_NEWPID;
        /// User and group namespace.
        const USER = libc::CLONE_NEWUSER;
        /// UTS namespace.
        const UTS = libc::CLONE_NEWUTS;
    }
}

impl Default for Namespace {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug, Clone)]
pub enum ParseNamespaceError {
    InvalidNamespace(String),
}

impl std::error::Error for ParseNamespaceError {}

impl core::fmt::Display for ParseNamespaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ParseNamespaceError::InvalidNamespace(ns) => {
                write!(f, "Invalid namespace: {}", ns)
            }
        }
    }
}

impl FromStr for Namespace {
    type Err = ParseNamespaceError;
    fn from_str(s: &str) -> Result<Self, ParseNamespaceError> {
        s.split(',').try_fold(Namespace::empty(), |ns, s| match s {
            "cgroup" => Ok(ns | Namespace::CGROUP),
            "ipc" => Ok(ns | Namespace::IPC),
            "network" => Ok(ns | Namespace::NETWORK),
            "pid" => Ok(ns | Namespace::PID),
            "mount" => Ok(ns | Namespace::MOUNT),
            "user" => Ok(ns | Namespace::USER),
            "uts" => Ok(ns | Namespace::UTS),
            "" | "none" => Ok(ns),
            invalid_ns => Err(ParseNamespaceError::InvalidNamespace(invalid_ns.to_owned())),
        })
    }
}
