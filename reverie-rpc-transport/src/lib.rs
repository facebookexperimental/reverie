/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// TODO-HUMAN-REVIEW(PR-98): New cross-process RPC transport crate authored by an
// autonomous bot (https://github.com/rrnewton/reverie/pull/98). This is
// transport/API scaffolding; no guest-visible syscall behavior changes here.

//! Cross-process transport for the Reverie [`GlobalTool`] RPC.
//!
//! # Why this crate exists
//!
//! Reverie models the tool → global-state channel as a serializable, blocking
//! request/response RPC: [`GlobalRPC::send_rpc`] takes a
//! [`GlobalTool::Request`] and returns a [`GlobalTool::Response`], both bounded
//! `Serialize + DeserializeOwned`. Today every backend (ptrace, KVM, SaBRe,
//! DBI) implements that trait by calling [`GlobalTool::receive_rpc`] *directly,
//! in the same address space*. That is fine only while the whole process tree
//! shares one `GlobalState`.
//!
//! The DBI backend breaks this assumption: DynamoRIO follows `fork`, so each
//! guest process ends up with its own copy of the global state and counts /
//! scheduling never aggregate across the tree. The fix is to move `GlobalState`
//! into a single **coordinator** process and have every guest process talk to
//! it over IPC — which is exactly the shape [`GlobalRPC`] already describes.
//!
//! This crate provides that IPC as a thin, dependency-light layer:
//!
//! * [`codec`] — length-prefixed [`bincode`] framing over any async stream.
//! * [`RpcServer`] — the coordinator: owns an `Arc<G>`, listens on a
//!   Unix-domain socket, and dispatches each request frame to `receive_rpc` on
//!   the one shared instance (so forked children that connect later share it).
//! * [`RpcClient`] — the guest side: connects, receives the config handshake,
//!   and implements [`GlobalRPC`] so a backend's `Guest` can forward `send_rpc`
//!   to it verbatim.
//!
//! # Design choices (see task research `research-rpc-library-comparison`)
//!
//! * **Raw Unix-domain socket + bincode**, not a framework (tarpc / tonic /
//!   zbus). The workload is latency-bound with tiny messages and ~one RPC per
//!   syscall; a framework would add a redundant abstraction over a trait that
//!   is already a typed request/response RPC, plus determinism-hostile
//!   background timers.
//! * **bincode 2 with `config::legacy()`**, matching every other bincode call
//!   site in the tree, so the byte format is consistent.
//! * **Per-connection, single-in-flight**, so no request-id multiplexing.
//!
//! # Status
//!
//! This is the shared scaffolding plus round-trip tests. Wiring a backend's
//! `Guest`/launcher to spawn a coordinator and connect clients (starting with
//! DBI) is a follow-up; that work is additionally gated on the separate
//! Detcore-over-DBI hang tracked by the verification task.
//!
//! [`GlobalTool`]: reverie::GlobalTool
//! [`GlobalTool::Request`]: reverie::GlobalTool::Request
//! [`GlobalTool::Response`]: reverie::GlobalTool::Response
//! [`GlobalTool::receive_rpc`]: reverie::GlobalTool::receive_rpc
//! [`GlobalRPC`]: reverie::GlobalRPC
//! [`GlobalRPC::send_rpc`]: reverie::GlobalRPC::send_rpc

pub mod codec;

mod client;
mod envelope;
mod error;
mod server;

pub use client::RpcClient;
pub use envelope::RequestEnvelope;
pub use error::RpcError;
pub use server::RpcServer;
pub use server::serve_connection;
