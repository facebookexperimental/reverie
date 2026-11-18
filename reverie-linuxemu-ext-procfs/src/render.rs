/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The procfs extension: synthetic `/proc/self/maps` rendered
//! from the core's [`ProcFacts`] snapshot for standalone
//! compositions. Compositions whose tool serves `/proc` never
//! link this crate, so such a run answers this path only through
//! its tool; the core itself does not serve maps (Slice 2 S2-R4
//! moved the rendering here from `executor/proc.rs`).
//! `/proc/self/status` is core mechanics (a readable seq
//! description the core always serves), so it is not claimed here.

use std::any::Any;
use std::sync::Arc;

use reverie_linuxemu::extension::ExtensionClone;
use reverie_linuxemu::extension::ExtensionRegistrationError;
use reverie_linuxemu::extension::ExtensionSlotId;
use reverie_linuxemu::extension::ExtensionState;
use reverie_linuxemu::extension::ExtensionTable;
use reverie_linuxemu::extension::ExtensionTableBuilder;
use reverie_linuxemu::extension::ProcFacts;

use crate::MapsEntry;
use crate::format_maps_line;

/// This extension keeps no per-task state: it renders from the
/// core's facts snapshot on every claim.
#[derive(Debug)]
struct ProcfsState;

impl ExtensionState for ProcfsState {
    fn on_clone(&self, _clone: ExtensionClone) -> Box<dyn ExtensionState> {
        Box::new(ProcfsState)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

fn factory() -> Box<dyn ExtensionState> {
    Box::new(ProcfsState)
}

/// Registers the procfs extension's claims on `builder` and returns
/// its slot. Refusals (duplicate claim, unknown slot) propagate as
/// the builder's errors.
pub fn register(
    builder: &mut ExtensionTableBuilder,
) -> Result<ExtensionSlotId, ExtensionRegistrationError> {
    let slot = builder.register_extension("procfs", factory);
    builder.register_proc_claim(slot, b"/proc/self/maps", maps_render)?;
    Ok(slot)
}

/// The standalone composition table carrying only this extension.
/// A duplicate-free constant registration cannot fail; a panic here
/// is a coding error in this crate, not a guest condition.
pub fn extension_table() -> Arc<ExtensionTable> {
    let mut builder = ExtensionTableBuilder::default();
    register(&mut builder).expect("constant procfs registration is valid");
    Arc::new(builder.build())
}

/// `/proc/self/maps`: one line per facts entry, spelled by this
/// crate's [`format_maps_line`].
// AUTONOMOUS-BOT-IMPLEMENTED: Expose only the deterministic guest stack map.
// TODO-HUMAN-REVIEW(PR-223): Review the minimal synthetic process map surface.
fn maps_render(state: &dyn ExtensionState, facts: &ProcFacts) -> Option<Vec<u8>> {
    state.as_any().is::<ProcfsState>().then(|| {
        let mut content = Vec::new();
        for entry in &facts.maps {
            content.extend_from_slice(&format_maps_line(&MapsEntry {
                start: entry.start,
                end: entry.end,
                perms: &entry.perms,
                offset: entry.offset,
                dev_major: entry.dev_major,
                dev_minor: entry.dev_minor,
                inode: entry.inode,
                name: entry.name.as_deref(),
            }));
        }
        content
    })
}

#[cfg(test)]
mod tests {
    use reverie_linuxemu::extension::ProcMapEntry;

    use super::*;

    fn facts() -> ProcFacts {
        ProcFacts {
            pid: 7,
            ppid: 3,
            tgid: 7,
            comm: b"worker".to_vec(),
            leader_name: b"a\nb".to_vec(),
            umask: 0o022,
            maps: vec![ProcMapEntry {
                start: 0x1000,
                end: 0x2000,
                perms: "rw-p".to_owned(),
                offset: 0,
                dev_major: 0,
                dev_minor: 0,
                inode: 0,
                name: Some("[stack]".to_owned()),
            }],
        }
    }

    #[test]
    fn maps_render_formats_each_entry() {
        let state = ProcfsState;
        let rendered = maps_render(&state, &facts()).expect("own state renders");
        assert_eq!(
            rendered,
            b"000000001000-000000002000 rw-p 00000000 00:00 0 [stack]\n"
        );
    }

    #[test]
    fn maps_render_pins_the_guest_stack_line_spelling() {
        // The one entry ProcFacts::of_state carries: the guest stack
        // window. This pins the exact bytes the in-crate test suite
        // used as SELF_MAPS_CONTENT before S2-R4 moved the claim here.
        let state = ProcfsState;
        let mut facts = facts();
        facts.maps = vec![ProcMapEntry {
            start: 0x7fff_ff80_0000,
            end: 0x7fff_ffff_f000,
            perms: "rw-p".to_owned(),
            offset: 0,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
            name: Some("[stack]".to_owned()),
        }];
        let rendered = maps_render(&state, &facts).expect("own state renders");
        assert_eq!(
            rendered,
            b"7fffff800000-7ffffffff000 rw-p 00000000 00:00 0 [stack]\n"
        );
    }

    #[test]
    fn register_claims_maps_once() {
        let mut builder = ExtensionTableBuilder::default();
        register(&mut builder).expect("first registration succeeds");
        // The maps claim landed: a second claim for the same path
        // on the same builder must refuse.
        let slot = builder.register_extension("procfs-again", factory);
        assert!(
            builder
                .register_proc_claim(slot, b"/proc/self/maps", maps_render)
                .is_err(),
            "duplicate maps claim must refuse"
        );
        // Registering this extension again fails the same way.
        assert!(
            register(&mut builder).is_err(),
            "second registration must refuse on the duplicate maps claim"
        );
    }
}
