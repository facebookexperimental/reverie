/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::BytesMut;

use crate::gdbstub::InferiorThreadId;
use crate::gdbstub::commands::*;
use crate::gdbstub::hex::*;

/// `T thread-id`: is the thread still alive?
///
/// GDB sends this whenever it switches to a thread by number (the `thread N`
/// command, and every DAP request that names a `threadId`). Any reply other
/// than `OK` makes GDB report the thread as terminated, so this must be
/// answered rather than left to the empty "unsupported" reply.
#[derive(PartialEq, Debug)]
pub struct T {
    /// `None` when the thread id does not parse. The reply is then `E01`
    /// rather than a malformed-packet error, which would close the session.
    pub thread: Option<ThreadId>,
}

impl ParseCommand for T {
    fn parse(bytes: BytesMut) -> Option<Self> {
        let thread = if bytes.starts_with(b"p") {
            // Multiprocess form: `ppid.tid`.
            ThreadId::decode(&bytes)
        } else {
            // Without multiprocess extensions GDB sends the bare thread id.
            decode_hex::<i32>(&bytes).ok().map(|tid| ThreadId {
                pid: IdKind::Any,
                tid: IdKind::from_raw(tid),
            })
        };
        Some(T { thread })
    }
}

impl T {
    /// The reply to this query when `live` lists the threads the stub
    /// currently controls: `OK` if one of them matches the queried id, and
    /// `E01` otherwise, including for an id that did not parse.
    pub fn reply(&self, live: impl IntoIterator<Item = InferiorThreadId>) -> &'static str {
        let alive = self.thread.is_some_and(|query| {
            live.into_iter()
                .any(|id| query.matches(&ThreadId::from(id)))
        });
        if alive { "OK" } else { "E01" }
    }
}

#[cfg(test)]
mod test {
    use reverie::Pid;

    use super::*;

    #[test]
    fn parses_multiprocess_thread_id() {
        assert_eq!(
            T::parse(BytesMut::from("p3.3")),
            Some(T {
                thread: Some(ThreadId::pid_tid(3, 3))
            })
        );
        assert_eq!(
            T::parse(BytesMut::from("p1a.2b")),
            Some(T {
                thread: Some(ThreadId::pid_tid(0x1a, 0x2b))
            })
        );
    }

    #[test]
    fn parses_bare_thread_id() {
        assert_eq!(
            T::parse(BytesMut::from("1f")),
            Some(T {
                thread: Some(ThreadId {
                    pid: IdKind::Any,
                    tid: IdKind::Id(Pid::from_raw(0x1f)),
                }),
            })
        );
    }

    #[test]
    fn malformed_thread_id_parses_to_no_thread() {
        // A rejected id still yields a command, so the session answers it
        // instead of closing the connection.
        for packet in ["", "pzz.1", "xyz", "-1", "p-1.-1"] {
            assert_eq!(
                T::parse(BytesMut::from(packet)),
                Some(T { thread: None }),
                "{packet:?}"
            );
        }
    }

    fn reply(packet: &str, live: &[(i32, i32)]) -> &'static str {
        let query = T::parse(BytesMut::from(packet)).unwrap();
        query.reply(
            live.iter()
                .map(|&(pid, tid)| InferiorThreadId::new(Pid::from_raw(tid), Pid::from_raw(pid))),
        )
    }

    #[test]
    fn live_thread_is_ok() {
        // Process 0x64 has threads 0x64 and 0x65.
        let live = [(0x64, 0x64), (0x64, 0x65)];
        assert_eq!(reply("p64.64", &live), "OK");
        assert_eq!(reply("p64.65", &live), "OK");
        assert_eq!(reply("65", &live), "OK");
    }

    #[test]
    fn exited_or_unknown_thread_is_e01() {
        // Thread 0x65 has exited; 0x66 never existed. Process 0x64 is still
        // alive, so matching on the pid alone would wrongly answer `OK`.
        let live = [(0x64, 0x64)];
        assert_eq!(reply("p64.65", &live), "E01");
        assert_eq!(reply("p64.66", &live), "E01");
        assert_eq!(reply("65", &live), "E01");
        assert_eq!(reply("p64.64", &[]), "E01");
    }

    #[test]
    fn right_tid_in_the_wrong_process_is_e01() {
        let live = [(0x64, 0x64)];
        assert_eq!(reply("p1.64", &live), "E01");
    }

    #[test]
    fn malformed_thread_id_is_e01() {
        let live = [(0x64, 0x64)];
        assert_eq!(reply("", &live), "E01");
        assert_eq!(reply("pzz.1", &live), "E01");
        assert_eq!(reply("p-1.-1", &live), "E01");
    }
}
