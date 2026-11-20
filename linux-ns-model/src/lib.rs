/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A pure model of Linux mount namespaces and mount tables.
//!
//! The model decides what a guest's bind mounts and unmounts mean:
//! admit a request with its predicted effect, refuse it with Linux's
//! `errno`, or refuse by name a request Linux would accept but this
//! model does not cover yet. Only a performed, admitted request whose
//! observed effect matches the prediction changes the model; the
//! model then renders everything the guest can observe about the
//! result (`mountinfo`, `mounts`, `statfs`, device numbers, mount
//! IDs).
//!
//! This crate is pure state: no I/O, no clock, no host access. Four
//! inputs are injected by the consumer through traits:
//!
//! - [`IdSource`]: mount IDs, peer groups, device minors, namespace
//!   IDs, filesystem IDs. What makes the values the consumer's
//!   business (for example reproducible) is the consumer's choice.
//! - [`Clock`]: timestamps for mount points the model creates.
//! - [`Presentation`]: values shown where Linux would show
//!   host-derived ones (a filesystem's capacity, the memory size
//!   behind Linux's machine-derived defaults).
//! - [`Performer`]: identifies path operands and carries out one
//!   admitted host operation, reporting what the kernel did. The
//!   performer carries no semantics of its own.
//!
//! Facts the model needs about a path operand (which mount resolved
//! it, its file type, whether it is a mount root) are supplied to
//! [`Model::admit`] as [`IdentifiedPath`] values from
//! [`Performer::identify`], so admission never has to guess what the
//! filesystem resolved. Facts only the call itself can resolve (the
//! root of a new bind mount within its source filesystem, reached
//! through symlinks) arrive in [`Observed`] and are plugged into the
//! prediction at [`Pending::commit`]: the model computes the rest.
//!
//! Semantics are taken from `mount(2)`, `umount(2)`,
//! `mount_namespaces(7)`, `proc(5)` (the `mountinfo` format), and the
//! kernel's `Documentation/filesystems/sharedsubtree.rst` for
//! propagation. Test comments cite the page and section each case
//! comes from.
//!
//! The transition contract, in short:
//!
//! 1. One transition at a time: [`Model::admit`] returns a
//!    [`Pending`] that holds the model until
//!    [`Pending::commit`] or drop.
//! 2. The guest's own call, performed as made; at most one host
//!    operation per transition.
//! 3. `commit` checks the observed effect against the prediction,
//!    including the return value. A mismatch is a [`Divergence`],
//!    the model is left unchanged, and the consumer must stop the
//!    affected run rather than pass an unmodeled result to the guest.
//! 4. A request the model can fault on Linux's own rules is refused
//!    with Linux's `errno` and no host operation happens; a valid
//!    request the model does not cover is refused by name with
//!    `EPERM` and [`RefuseReason::Unsupported`].

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod bind;
mod model;
mod mount;
mod render;
mod umount;

pub mod errno;
pub mod injected;
pub mod request;
pub mod types;

pub use errno::Errno;
pub use injected::Clock;
pub use injected::Follow;
pub use injected::FsFacts;
pub use injected::IdSource;
pub use injected::Performer;
pub use injected::Presentation;
pub use injected::StatfsView;
pub use model::Model;
pub use model::Namespace;
pub use model::NsKind;
pub use model::SeedError;
pub use model::SeedMount;
pub use mount::Mount;
pub use mount::MountState;
pub use mount::Propagation;
pub use mount::Superblock;
pub use request::BindRequest;
pub use request::CallerContext;
pub use request::Committed;
pub use request::Decision;
pub use request::Divergence;
pub use request::IdentifiedPath;
pub use request::MNT_DETACH;
pub use request::MNT_EXPIRE;
pub use request::MNT_FORCE;
pub use request::MS_BIND;
pub use request::MS_DIRSYNC;
pub use request::MS_I_VERSION;
pub use request::MS_LAZYTIME;
pub use request::MS_MANDLOCK;
pub use request::MS_MOVE;
pub use request::MS_NOATIME;
pub use request::MS_NODEV;
pub use request::MS_NODIRATIME;
pub use request::MS_NOEXEC;
pub use request::MS_NOSUID;
pub use request::MS_NOSYMFOLLOW;
pub use request::MS_POSIXACL;
pub use request::MS_PRIVATE;
pub use request::MS_RDONLY;
pub use request::MS_REC;
pub use request::MS_RELATIME;
pub use request::MS_REMOUNT;
pub use request::MS_SHARED;
pub use request::MS_SILENT;
pub use request::MS_SLAVE;
pub use request::MS_STRICTATIME;
pub use request::MS_SYNCHRONOUS;
pub use request::MS_UNBINDABLE;
pub use request::Observed;
pub use request::ObservedMount;
pub use request::PathInNs;
pub use request::Pending;
pub use request::Refusal;
pub use request::RefuseReason;
pub use request::Request;
pub use request::UMOUNT_NOFOLLOW;
pub use request::UmountRequest;
pub use types::FileType;
pub use types::IdKind;
pub use types::MountId;
pub use types::NsId;
pub use types::SbId;
pub use types::TaskKey;
pub use types::Timespec;
