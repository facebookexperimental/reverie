/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The optional stop events gdb asked for.

use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;

/// The optional stop events gdb asked for in its `qSupported`, shared by the
/// session, which records them, and every traced thread, which reads them at
/// each fork, vfork or exec. gdb lists `fork-events+`, `vfork-events+` and
/// `exec-events+` when it can follow such an event, and the stub reports one
/// only if gdb listed it ("General Query Packets", `qSupported`): a stop gdb
/// did not ask for is one it cannot handle. None before gdb's `qSupported`.
#[derive(Clone, Debug, Default)]
pub struct ClientFeatures(Arc<AtomicU8>);

const FORK_EVENTS: u8 = 1 << 0;
const VFORK_EVENTS: u8 = 1 << 1;
const EXEC_EVENTS: u8 = 1 << 2;

impl ClientFeatures {
    /// Records the features gdb lists in `features`, the data of its
    /// `qSupported` packet after the packet's name: `:` and then features
    /// separated by `;`, each `name+`, `name-`, `name?` or `name=value`.
    pub fn set_from_qsupported(&self, features: &[u8]) {
        let features = features.strip_prefix(b":").unwrap_or(features);
        let bits = features
            .split(|byte| *byte == b';')
            .fold(0, |bits, feature| {
                bits | match feature {
                    b"fork-events+" => FORK_EVENTS,
                    b"vfork-events+" => VFORK_EVENTS,
                    b"exec-events+" => EXEC_EVENTS,
                    _ => 0,
                }
            });
        self.0.store(bits, Ordering::SeqCst);
    }

    fn has(&self, bit: u8) -> bool {
        self.0.load(Ordering::SeqCst) & bit != 0
    }

    /// gdb follows forks: a fork is reported as a `fork` stop.
    pub fn fork_events(&self) -> bool {
        self.has(FORK_EVENTS)
    }

    /// gdb follows vforks: a vfork is reported as a `vfork` stop, and the
    /// parent's return from it as a `vforkdone` stop.
    pub fn vfork_events(&self) -> bool {
        self.has(VFORK_EVENTS)
    }

    /// gdb follows execs: an exec is reported as an `exec` stop.
    pub fn exec_events(&self) -> bool {
        self.has(EXEC_EVENTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdbs_default_list_asks_for_every_event() {
        // gdb 17.2's `qSupported`, as sent to a stub.
        let features = ClientFeatures::default();
        features.set_from_qsupported(
            b":multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;\
              exec-events+;vContSupported+;QThreadEvents+;QThreadOptions=5;no-resumed+;\
              memory-tagging+;error-message+",
        );
        assert!(features.fork_events());
        assert!(features.vfork_events());
        assert!(features.exec_events());
    }

    #[test]
    fn an_event_gdb_turned_off_is_not_reported() {
        // `set remote fork-event-feature-packet off` and the vfork one drop
        // the two from the list.
        let features = ClientFeatures::default();
        features.set_from_qsupported(b":multiprocess+;swbreak+;exec-events+;vContSupported+");
        assert!(!features.fork_events());
        assert!(!features.vfork_events());
        assert!(features.exec_events());
    }

    #[test]
    fn only_a_feature_marked_supported_counts() {
        let features = ClientFeatures::default();
        features.set_from_qsupported(b":fork-events-;vfork-events?;exec-events=1");
        assert!(!features.fork_events());
        assert!(!features.vfork_events());
        assert!(!features.exec_events());
    }

    #[test]
    fn a_later_list_replaces_an_earlier_one() {
        let features = ClientFeatures::default();
        assert!(!features.vfork_events(), "none before gdb's qSupported");
        features.set_from_qsupported(b":vfork-events+");
        assert!(features.vfork_events());
        features.set_from_qsupported(b":multiprocess+");
        assert!(!features.vfork_events());
    }
}
