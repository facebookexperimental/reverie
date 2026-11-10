/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Coordinator RPC transport selection (C1).
//!
//! Both ends read the same environment variable once at launch. There is
//! no in-band negotiation: a run is socket or mapped for its whole life,
//! and constructing the wrong stream kind for the selected transport is
//! a named refusal, never a silent fallback. Changing transport is a
//! launch-time choice only.

use std::fmt;

/// Environment variable selecting the coordinator RPC transport.
pub const TRANSPORT_ENV: &str = "REVERIE_RPC_TRANSPORT";

/// Initial per-direction queue capacity for mapped connections.
pub const DEFAULT_MAPPED_CAPACITY: usize = 256 * 1024;

/// The transport one coordinator/guest pair uses for its whole life.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RpcTransport {
    /// Unix-domain stream socket (current production default).
    #[default]
    Socket,
    /// Shared-memory SPSC queues with futex wakeups ([`crate::mapped`]).
    Mapped,
}

/// Why transport selection refused to construct a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportSelectError {
    /// The environment value names no known transport.
    UnknownValue(String),
    /// The environment value is not valid UTF-8 (never a silent default).
    NonUnicodeValue,
    /// The supplied stream kind does not match the selected transport.
    Mismatch {
        /// Transport selected for this run.
        selected: RpcTransport,
        /// Stream kind actually supplied (`"socket"` or `"mapped"`).
        supplied: &'static str,
    },
}

impl fmt::Display for TransportSelectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownValue(value) => {
                write!(
                    f,
                    "unknown {TRANSPORT_ENV} value {value:?} (want socket|mapped)"
                )
            }
            Self::NonUnicodeValue => {
                write!(f, "non-UTF-8 {TRANSPORT_ENV} value (want socket|mapped)")
            }
            Self::Mismatch { selected, supplied } => write!(
                f,
                "RPC transport mismatch: selected {selected:?} but supplied {supplied} stream"
            ),
        }
    }
}

impl std::error::Error for TransportSelectError {}

impl RpcTransport {
    /// Parse an explicit value; `None`/empty means the default (Socket).
    pub fn parse(value: Option<&str>) -> Result<Self, TransportSelectError> {
        match value {
            None | Some("") | Some("socket") => Ok(Self::Socket),
            Some("mapped") => Ok(Self::Mapped),
            Some(other) => Err(TransportSelectError::UnknownValue(other.to_owned())),
        }
    }

    /// Read the selection from [`TRANSPORT_ENV`] once. Only an absent
    /// variable uses the default; a present-but-non-UTF-8 value is a
    /// named refusal, never a silent default.
    pub fn from_env() -> Result<Self, TransportSelectError> {
        Self::from_env_os(std::env::var_os(TRANSPORT_ENV))
    }

    fn from_env_os(value: Option<std::ffi::OsString>) -> Result<Self, TransportSelectError> {
        match value {
            None => Self::parse(None),
            Some(value) => match value.to_str() {
                Some(value) => Self::parse(Some(value)),
                None => Err(TransportSelectError::NonUnicodeValue),
            },
        }
    }

    /// Refuse a stream whose kind does not match this selection.
    pub fn require(self, supplied: &'static str) -> Result<(), TransportSelectError> {
        let want = match self {
            Self::Socket => "socket",
            Self::Mapped => "mapped",
        };
        if supplied == want {
            Ok(())
        } else {
            Err(TransportSelectError::Mismatch {
                selected: self,
                supplied,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_defaults_to_socket() {
        assert_eq!(RpcTransport::parse(None).unwrap(), RpcTransport::Socket);
        assert_eq!(RpcTransport::parse(Some("")).unwrap(), RpcTransport::Socket);
        assert_eq!(
            RpcTransport::parse(Some("socket")).unwrap(),
            RpcTransport::Socket
        );
    }

    #[test]
    fn parse_mapped_and_refuses_unknown_by_name() {
        assert_eq!(
            RpcTransport::parse(Some("mapped")).unwrap(),
            RpcTransport::Mapped
        );
        let err = RpcTransport::parse(Some("shm")).unwrap_err();
        assert_eq!(err, TransportSelectError::UnknownValue("shm".into()));
        assert!(err.to_string().contains(TRANSPORT_ENV));
    }

    #[test]
    fn require_refuses_mismatch_by_name() {
        assert!(RpcTransport::Socket.require("socket").is_ok());
        assert!(RpcTransport::Mapped.require("mapped").is_ok());
        let err = RpcTransport::Mapped.require("socket").unwrap_err();
        assert!(matches!(
            err,
            TransportSelectError::Mismatch {
                selected: RpcTransport::Mapped,
                supplied: "socket"
            }
        ));
        assert!(RpcTransport::Socket.require("mapped").is_err());
    }
}

#[cfg(all(test, unix))]
mod env_tests {
    use std::os::unix::ffi::OsStringExt;

    use super::*;

    #[test]
    fn non_utf8_env_is_named_refusal_not_default() {
        let bad = std::ffi::OsString::from_vec(vec![0xff]);
        assert_eq!(
            RpcTransport::from_env_os(Some(bad)),
            Err(TransportSelectError::NonUnicodeValue)
        );
        assert_eq!(
            RpcTransport::from_env_os(None).unwrap(),
            RpcTransport::Socket
        );
    }
}
