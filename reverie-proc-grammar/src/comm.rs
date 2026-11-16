/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `/proc/<pid>/comm`: the task name and a newline, printed by
//! `comm_show` (`fs/proc/base.c`, via `proc_task_name`). For user
//! tasks the name is `task_struct::comm` — at most 15 usable bytes
//! plus the terminating NUL `__set_task_comm`'s `strscpy_pad` stores
//! (`kernel/sys.c:PR_SET_NAME`, `fs/exec.c:begin_new_exec`). Kernel
//! threads print their full untruncated name here instead (22 bytes
//! for `pool_workqueue_release`, observed live on Linux 7.1.3), so
//! this parser places no length bound on the file's contents; the
//! 15-byte bound belongs to the stored comm that `stat` and `sched`
//! splice. The name is bytes: it may contain spaces, parentheses,
//! backslashes, and non-UTF-8 bytes, and the file presents it raw. A
//! newline *inside* the name is also presented raw, so the file can
//! hold more than one physical line; the final byte the kernel adds
//! is the terminator stripped here.

use alloc::vec::Vec;

use crate::error::Format;
use crate::error::ProcParseError;

/// Usable name bytes: `TASK_COMM_LEN` (16) minus the NUL.
pub const TASK_COMM_MAX: usize = 15;

/// Parse one `comm` file's bytes into the printed name bytes.
///
/// Refuses an empty file, a missing terminating newline, and a name
/// containing NUL — none of which the kernel can print.
pub fn parse_comm_file(input: &[u8]) -> Result<Vec<u8>, ProcParseError> {
    if input.is_empty() {
        return Err(ProcParseError::Empty {
            format: Format::Comm,
        });
    }
    let name = input.strip_suffix(b"\n").ok_or(ProcParseError::BadShape {
        format: Format::Comm,
        span: (input.len() - 1, input.len()),
    })?;
    if name.contains(&0) {
        let at = name.iter().position(|b| *b == 0).unwrap_or(0);
        return Err(ProcParseError::BadValue {
            field: "comm",
            span: (at, at + 1),
        });
    }
    Ok(name.to_vec())
}

/// Render stored name bytes as the `comm` file: the name and one
/// newline.
pub fn render_comm_file(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 1);
    out.extend_from_slice(name);
    out.push(b'\n');
    out
}
