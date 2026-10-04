/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A backend output adapter must preserve the shared counter's lifecycle state.

#[path = "../../reverie-examples/counter2_tool.rs"]
mod counter2_tool;

use std::sync::Mutex;

use counter2_tool::CounterGlobal;
use counter2_tool::CounterLocal;
use reverie::ExitStatus;
use reverie::Pid;
use reverie::Tid;
use reverie_dbt::run_tool_process_exit;
use reverie_dbt::run_tool_thread_exit;

static REPORTS: Mutex<Vec<(Tid, u64)>> = Mutex::new(Vec::new());

#[test]
fn output_adapter_preserves_thread_and_global_totals_across_clone() {
    let tool = CounterLocal::default().with_thread_exit_reporter(|tid, count| {
        REPORTS.lock().unwrap().push((tid, count));
    });
    let global = CounterGlobal::default();
    let first = Pid::from_raw(41);
    let second = Pid::from_raw(42);
    run_tool_thread_exit(&tool, first, 17, &global, &(), ExitStatus::SUCCESS).unwrap();
    assert_eq!(tool.process_totals(), (17, 1));
    assert_eq!(global.totals(), (0, 0, 0));

    let copied = tool.clone();
    run_tool_thread_exit(&copied, second, 20, &global, &(), ExitStatus::SUCCESS).unwrap();
    assert_eq!(copied.process_totals(), (37, 2));
    assert_eq!(tool.process_totals(), (17, 1));
    assert_eq!(*REPORTS.lock().unwrap(), [(first, 17), (second, 20)]);

    run_tool_process_exit(copied, first, &global, &(), ExitStatus::SUCCESS).unwrap();
    assert_eq!(global.totals(), (37, 1, 2));
}
