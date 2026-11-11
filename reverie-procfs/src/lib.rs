/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Pure helpers for presenting a Linux `/proc` view to a guest program:
//! path classification, file-content formatting, `seq_file` positioning,
//! and synthetic file metadata.
//!
//! Everything here is a pure function over caller-supplied values. The
//! crate holds no process, descriptor, or scheduling state, makes no
//! system calls, and decides no policy: which paths exist, what facts a
//! file reports, and how a call is answered remain the caller's business.
//! Backends and tools that present a `/proc` view share these helpers so
//! the bytes and metadata they produce agree byte for byte.
//!
//! The formatting rules follow Linux's procfs (`fs/proc/`); each helper
//! names the kernel source it matches.
