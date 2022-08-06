/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::BytesMut;
use nix::sys::signal::Signal;

use crate::gdbstub::commands::*;
use crate::gdbstub::hex::*;

#[derive(PartialEq, Debug)]
pub enum vCont {
    Query,
    Actions(Vec<(ResumeAction, ThreadId)>),
}

impl ParseCommand for vCont {
    fn parse(mut bytes: BytesMut) -> Option<Self> {
        if bytes == b"?"[..] {
            Some(vCont::Query)
        } else if bytes.is_empty() {
            None
        } else {
            let mut bytes = bytes.split_off(1);
            // example packet: $vCont;s:p3e86d3.3e86d3;c:p3e86d3.-1#3b
            // with prefix (`$vCont`) and checksum stripped.
            let actions: Vec<(ResumeAction, ThreadId)> = bytes
                .split_mut(|c| *c == b';')
                .filter_map(|act| {
                    let mut iter = act.split_mut(|c| *c == b':');
                    let action = iter.next()?;
                    let thread_id = iter.next().and_then(|tid| ThreadId::decode(tid))?;
                    let action = if action.is_empty() {
                        None
                    } else {
                        match action[0] {
                            b'c' => Some(ResumeAction::Continue(None)),
                            b'C' => {
                                let sig = decode_hex::<i32>(&action[1..])
                                    .ok()
                                    .and_then(|s| Signal::try_from(s).ok())?;
                                Some(ResumeAction::Continue(Some(sig)))
                            }
                            b's' => Some(ResumeAction::Step(None)),
                            b'S' => {
                                let sig = decode_hex::<i32>(&action[1..])
                                    .ok()
                                    .and_then(|s| Signal::try_from(s).ok())?;
                                Some(ResumeAction::Step(Some(sig)))
                            }
                            b't' => Some(ResumeAction::Stop),
                            b'r' => {
                                let mut iter = action[1..].split_mut(|c| *c == b',');
                                let start: u64 = iter.next().and_then(|x| decode_hex(x).ok())?;
                                let end: u64 = iter.next().and_then(|x| decode_hex(x).ok())?;
                                Some(ResumeAction::StepUntil(start, end))
                            }
                            _ => None,
                        }
                    }?;
                    Some((action, thread_id))
                })
                .collect();
            if actions.is_empty() {
                None
            } else {
                Some(vCont::Actions(actions))
            }
        }
    }
}
