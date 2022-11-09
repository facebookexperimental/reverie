/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io;
use std::sync::Mutex;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde_json::json;
use syscalls::Sysno;
use syscalls::SysnoSet;
use trace_objects::Block;
use trace_objects::BlockProperties;
use trace_objects::ExecutionUnit;
use trace_objects::Properties;
use trace_objects::Timestamp;
use trace_objects::Trace;
use traceviz_rpc::MyService;
use traceviz_rpc::SyscallEvent;

pub struct GlobalState {
    pub epoch: SystemTime,
    /// All of the syscall events we've received so far. Since this array is
    /// monotonically increasing, we will use its length as the event_id for
    /// the next incoming event.
    pub syscall_events: Mutex<Vec<SyscallEvent>>,
}

#[async_trait::async_trait]
impl MyService for GlobalState {
    async fn print(&self, thread_id: usize, s: &str) {
        println!("[{}] {}", thread_id, s);
    }

    async fn send_syscall_event(&self, mut syscall_event: SyscallEvent) -> u64 {
        let mut global_state_events = self.syscall_events.lock().unwrap();
        let event_id: u64 = global_state_events.len() as u64;
        syscall_event.event_id = event_id;
        global_state_events.push(syscall_event);
        event_id
    }
}

impl GlobalState {
    pub fn new() -> Self {
        Self {
            epoch: SystemTime::now(),
            syscall_events: Mutex::new(Vec::new()),
        }
    }

    pub fn upload_artillery_traces(&self, trace: Trace) {
        let events = self.syscall_events.lock().unwrap();

        // Each process is represented as an Execution Unit
        let mut pid_to_eu: HashMap<i32, ExecutionUnit> = HashMap::new();

        let mut open_syscall_events: HashMap<u64, (Block, Timestamp)> = HashMap::new();
        let mut event_to_num_fds: HashMap<u64, i32> = HashMap::new();

        let open_sysnos: SysnoSet = SysnoSet::new(&[
            Sysno::accept,
            Sysno::accept4,
            Sysno::openat,
            Sysno::open,
            Sysno::socket,
            Sysno::socketpair,
            Sysno::epoll_create,
            Sysno::dup,
            Sysno::dup2,
            Sysno::pipe,
        ]);

        for event in events.iter() {
            pid_to_eu.entry(event.process_id).or_insert_with(|| {
                trace
                    .add_execution_unit(&event.process_id.to_string())
                    .unwrap()
            });

            // Each syscall event is represented as a Block
            let block_props = {
                let mut block_props = BlockProperties::new();

                block_props.set_name(&event.syscall_num.to_string());
                block_props.set_custom("tid", &event.process_id.to_string());
                block_props.set_custom("pretty", &event.args);
                block_props.set_custom("result", &format!("{:?}", event.syscall_result));

                block_props
            };

            let execution_unit = pid_to_eu.get(&event.process_id).unwrap();

            let start_timestamp = event
                .syscall_start
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64;
            let start_timestamp = Timestamp::from_raw_timestamp_us(start_timestamp);

            let end_timestamp = event
                .syscall_end
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64;
            let end_timestamp = Timestamp::from_raw_timestamp_us(end_timestamp);

            let block = execution_unit
                .begin_block_with_properties(start_timestamp, &block_props)
                .get_block();
            block.end_block(end_timestamp);

            // If an event has a parent id, then it operates on an open file
            // descriptor and therefore can be grouped.
            if let Some(parent_event_id) = event.parent_event_id {
                // Draw edge from parent to current block
                let (parent_block, parent_end_timestamp) =
                    open_syscall_events.get(&parent_event_id).unwrap();
                let start_point = parent_block.add_point(*parent_end_timestamp, &Properties::new());
                let edge = start_point.begin_edge_with_stage("rq");
                let end_point = block.add_point(start_timestamp, &Properties::new());
                end_point.end_edge(&edge);

                if event.syscall_num == Sysno::close {
                    // Some syscalls (like pipe) open multiple file
                    // descriptors, so we track the syscalls until all of their
                    // file descriptors close
                    if let Entry::Occupied(mut entry) = event_to_num_fds.entry(parent_event_id) {
                        let num_fds = *entry.get();
                        if num_fds > 1 {
                            entry.insert(num_fds - 1);
                        } else {
                            entry.remove();
                            open_syscall_events.remove(&parent_event_id);
                        }
                    }
                }
            }

            if open_sysnos.contains(event.syscall_num) {
                let num_fds = match event.syscall_num {
                    Sysno::pipe | Sysno::socketpair => 2,
                    _ => 1,
                };
                event_to_num_fds.insert(event.event_id, num_fds);
                open_syscall_events.insert(event.event_id, (block, end_timestamp));
            }
        }
    }

    pub fn read_traceviz_input<R: io::Read>(&self, reader: R) -> serde_json::Result<()> {
        let events: Vec<SyscallEvent> = serde_json::from_reader(reader)?;
        let mut global_state_events = self.syscall_events.lock().unwrap();

        for event in events.into_iter() {
            global_state_events.push(event);
        }
        Ok(())
    }

    pub fn generate_traceviz_output<W: io::Write>(&self, writer: &mut W) -> serde_json::Result<()> {
        let events = self.syscall_events.lock().unwrap();
        let mut serialized_events: Vec<SyscallEvent> = Vec::new();

        for event in events.iter() {
            serialized_events.push((*event).clone());
        }

        serde_json::to_writer(writer, &serialized_events)
    }

    pub fn generate_chrome_trace<W: io::Write>(&self, writer: &mut W) -> serde_json::Result<()> {
        let events = self.syscall_events.lock().unwrap();
        let mut json: Vec<serde_json::Value> = Vec::new();

        for event in events.iter() {
            let ts = event
                .syscall_start
                .duration_since(self.epoch)
                .unwrap()
                .as_micros() as u64;
            let duration = event
                .syscall_end
                .duration_since(event.syscall_start)
                .unwrap()
                .as_micros() as u64;

            json.push(json!({
                "name": event.syscall_num.to_string(),
                "cat": "syscall",
                "ph": "X",
                "ts": ts,
                "dur": duration,
                "pid": event.process_id,
                "tid": event.thread_id,
                "args": {
                    "pretty": event.args,
                    "result": format!("{:?}", event.syscall_result),
                    "event_id": event.event_id,
                    "parent_id": event.parent_event_id,
                },
            }));
        }

        let json = serde_json::Value::Array(json);

        serde_json::to_writer(writer, &json)
    }
}
