/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Rendering: the guest-visible views of the mount table, as
//! exact bytes. Formats follow `proc(5)` (`/proc/<pid>/mountinfo`
//! and `/proc/<pid>/mounts`, as printed by the kernel's
//! `show_mountinfo`/`show_vfsmnt`). Paths carry the kernel's octal
//! escapes for space, tab, newline, and backslash, so no field
//! ever contains a literal space; every other byte, including
//! non-ASCII and non-UTF-8 path bytes, is emitted raw as the
//! kernel emits it. Only model values are printed — host paths,
//! host IDs, and host options never reach a rendering.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::model::Model;
use crate::model::join_path;
use crate::mount::Mount;
use crate::mount::MountState;
use crate::mount::Propagation;
use crate::request::PathInNs;
use crate::types::MountId;
use crate::types::NsId;

fn escape(out: &mut Vec<u8>, bytes: &[u8]) {
    for b in bytes {
        match b {
            b' ' => out.extend_from_slice(b"\\040"),
            b'\t' => out.extend_from_slice(b"\\011"),
            b'\n' => out.extend_from_slice(b"\\012"),
            b'\\' => out.extend_from_slice(b"\\134"),
            _ => out.push(*b),
        }
    }
}

/// One mount as a viewer sees it: the mount, its shown root field,
/// and its shown mount point (relative to the viewer's root).
struct ViewRow<'a> {
    mount: &'a Mount,
    root_field: Vec<u8>,
    mount_point: Vec<u8>,
}

impl Model {
    /// Whether `mount` is reachable from a viewer rooted at
    /// `containing`: every step of its parent chain must be the
    /// mount a lookup would land on (not covered by a stack).
    fn reachable(&self, mount: MountId, containing: MountId) -> bool {
        let mut cur = mount;
        for _ in 0..=self.mounts.len() {
            if cur == containing {
                return true;
            }
            let m = &self.mounts[&cur];
            if m.parent == cur {
                return false;
            }
            // The child must be in the stack that lookup reaches
            // at its mount point under its parent.
            let Some(top) = self.topmost_at(m.parent, &m.mountpoint_in_parent) else {
                return false;
            };
            let mut s = top;
            let in_stack = loop {
                if s == cur {
                    break true;
                }
                let sm = &self.mounts[&s];
                if sm.parent == s || !sm.mountpoint_in_parent.is_empty() {
                    break false;
                }
                s = sm.parent;
            };
            if !in_stack {
                return false;
            }
            cur = m.parent;
        }
        false
    }

    fn view_rows(&self, ns: NsId, viewer_root: &PathInNs) -> Vec<ViewRow<'_>> {
        let Some(root_visible) = self.path_visible(viewer_root) else {
            return Vec::new();
        };
        let mut rows: Vec<ViewRow<'_>> = Vec::new();
        for mount in self.mounts_in(ns) {
            if mount.state != MountState::Visible {
                continue;
            }
            if mount.id == viewer_root.mount {
                rows.push(ViewRow {
                    mount,
                    root_field: join_path(&mount.root, &viewer_root.below_root),
                    mount_point: b"/".to_vec(),
                });
                continue;
            }
            let Some(visible) = self.visible_path(mount.id) else {
                continue;
            };
            let under_root = visible.len() > root_visible.len()
                && visible.starts_with(&root_visible)
                && (root_visible == b"/" || visible[root_visible.len()] == b'/');
            if !under_root || !self.reachable(mount.id, viewer_root.mount) {
                continue;
            }
            let rel = if root_visible == b"/" {
                visible.clone()
            } else {
                visible[root_visible.len()..].to_vec()
            };
            rows.push(ViewRow {
                mount,
                root_field: mount.root.clone(),
                mount_point: rel,
            });
        }
        rows
    }

    fn optional_fields(&self, ns: NsId, mount: &Mount) -> String {
        let mut out = String::new();
        let master_field = |out: &mut String, g: u64| {
            // The kernel prints `master:` when the master group
            // has a member in the viewer's namespace and
            // `propagate_from:` when propagation comes from
            // outside it (`proc(5)`).
            let in_ns = self.mounts.values().any(|m| {
                m.ns == ns
                    && m.state == MountState::Visible
                    && m.propagation.peer_group() == Some(g)
            });
            let _ = write!(
                out,
                " {}:{g}",
                if in_ns { "master" } else { "propagate_from" }
            );
        };
        match mount.propagation {
            Propagation::Private => {}
            Propagation::Unbindable => out.push_str(" unbindable"),
            Propagation::Shared(g) => {
                let _ = write!(out, " shared:{g}");
            }
            Propagation::Slave(master) => {
                if let Some(g) = master {
                    master_field(&mut out, g);
                }
            }
            Propagation::SharedSlave { peer, master } => {
                let _ = write!(out, " shared:{peer}");
                if let Some(g) = master {
                    master_field(&mut out, g);
                }
            }
        }
        out
    }

    /// Render `/proc/<pid>/mountinfo` for a viewer in `ns` rooted
    /// at `viewer_root`, in `proc(5)` format: one line per
    /// visible mount, parents before children. A namespace with
    /// no visible mounts renders empty, as on Linux.
    pub fn render_mountinfo(&self, ns: NsId, viewer_root: &PathInNs) -> Vec<u8> {
        let mut out = Vec::new();
        for row in self.view_rows(ns, viewer_root) {
            let m = row.mount;
            let sb = &self.superblocks[&m.sb];
            // Field 2 is the parent mount's ID as-is (the mount
            // itself only for the namespace root); a viewer rooted
            // below it still sees the real parent ID (proc(5)).
            out.extend_from_slice(
                alloc::format!(
                    "{} {} {}:{} ",
                    m.id.0,
                    m.parent.0,
                    sb.dev_major,
                    sb.dev_minor
                )
                .as_bytes(),
            );
            escape(&mut out, &row.root_field);
            out.push(b' ');
            escape(&mut out, &row.mount_point);
            out.push(b' ');
            out.extend_from_slice(&m.mount_options);
            out.extend_from_slice(self.optional_fields(ns, m).as_bytes());
            out.extend_from_slice(b" - ");
            escape(&mut out, &sb.facts.fs_type);
            out.push(b' ');
            escape(&mut out, &sb.facts.source);
            out.push(b' ');
            out.extend_from_slice(&sb.facts.super_options);
            out.push(b'\n');
        }
        out
    }

    /// Render `/proc/<pid>/mounts` for the same viewer, in
    /// `proc(5)` format (`source target fstype options 0 0`). The
    /// options field merges per-mount and superblock tokens the
    /// way the kernel's `show_vfsmnt` does: mount flags first,
    /// then superblock tokens not already present.
    pub fn render_mounts(&self, ns: NsId, viewer_root: &PathInNs) -> Vec<u8> {
        let mut out = Vec::new();
        for row in self.view_rows(ns, viewer_root) {
            let m = row.mount;
            let sb = &self.superblocks[&m.sb];
            escape(&mut out, &sb.facts.source);
            out.push(b' ');
            escape(&mut out, &row.mount_point);
            out.push(b' ');
            escape(&mut out, &sb.facts.fs_type);
            let mut opts: Vec<&[u8]> = m.mount_options.split(|b| *b == b',').collect();
            for tok in sb.facts.super_options.split(|b| *b == b',') {
                if !opts.contains(&tok) {
                    opts.push(tok);
                }
            }
            out.push(b' ');
            for (i, tok) in opts.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(tok);
            }
            out.extend_from_slice(b" 0 0\n");
        }
        out
    }
}
