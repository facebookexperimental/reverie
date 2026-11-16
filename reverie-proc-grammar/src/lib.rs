/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Grammar-backed parsers and renderers for the Linux `/proc` per-task
//! text files: `stat`, `status`, `comm`, `fdinfo`, `io`, `sched`, and
//! `statm`.
//!
//! Every format here is defined by one kernel printing function, named
//! in the module that owns it. Each module provides the pair the kernel
//! implies — `parse_*` from the file's bytes to a full-fidelity typed
//! value, and `render_*` back to the kernel's byte shape — plus typed
//! field setters so a caller can rewrite a parsed value before
//! rendering. Which fields a caller rewrites, and to what, is policy
//! and stays with the caller; this crate decides only what the bytes
//! mean.
//!
//! Everything is a pure function over caller-supplied bytes: no system
//! calls, no clock, no environment, no backend knowledge. Inputs are
//! treated as bytes throughout, because the kernel emits name fields
//! (`comm` above all) as bytes: a task name may contain spaces,
//! parentheses, newlines, and non-UTF-8 bytes. A parse that cannot
//! account for every byte fails with a typed [`ProcParseError`] naming
//! the field; there is no partial or lossy parse.

#![no_std]

extern crate alloc;

pub mod comm;
pub mod error;
pub mod fdinfo;
pub mod num;
pub mod process_io;
pub mod sched;
pub mod stat;
pub mod statm;
pub mod status;

pub use comm::TASK_COMM_MAX;
pub use comm::parse_comm_file;
pub use comm::render_comm_file;
pub use error::Format;
pub use error::ProcParseError;
pub use fdinfo::EpollTarget;
pub use fdinfo::Fdinfo;
pub use fdinfo::FdinfoKind;
pub use fdinfo::FdinfoLock;
pub use fdinfo::InotifyWatch;
pub use fdinfo::LockAccess;
pub use fdinfo::LockKind;
pub use fdinfo::LockMode;
pub use fdinfo::Timerfd;
pub use fdinfo::parse_fdinfo;
pub use fdinfo::render_fdinfo;
pub use process_io::ProcessIo;
pub use process_io::parse_process_io;
pub use process_io::render_process_io;
pub use sched::Sched;
pub use sched::SchedEntry;
pub use sched::SchedValue;
pub use sched::parse_sched;
pub use sched::render_sched;
pub use stat::Stat;
pub use stat::parse_stat;
pub use stat::render_stat;
pub use statm::Statm;
pub use statm::parse_statm;
pub use statm::render_statm;
pub use status::Bitmap;
pub use status::Status;
pub use status::StatusLabel;
pub use status::StatusLine;
pub use status::StatusValue;
pub use status::parse_bitmap_token;
pub use status::parse_range_list_token;
pub use status::parse_status;
pub use status::parse_status_preserving_unknown;
pub use status::render_status;
