/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A fatal default-action signal ends the whole thread group before the dying
//! task's clear_child_tid wake can let a joiner run another syscall.

use std::process::Command;
use std::sync::atomic::Ordering;

use super::*;

const PROGRAM: &str = r#"#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
static atomic_int receiver_tid;
static void *receiver(void *unused) {
  (void)unused;
  atomic_store(&receiver_tid, (int)syscall(SYS_gettid));
  for (;;) sched_yield();
  return NULL;
}
int main(void) {
  if (signal(SIGUSR1, SIG_DFL) == SIG_ERR) return 2;
  pthread_t thread;
  if (pthread_create(&thread, NULL, receiver, NULL)) return 3;
  while (!atomic_load(&receiver_tid)) sched_yield();
  if (syscall(SYS_tgkill, getpid(), atomic_load(&receiver_tid), SIGUSR1)) return 4;
  /* The receiver's default action ends the group; this join never returns
     on Linux, and nothing below runs. */
  pthread_join(thread, NULL);
  puts("joined after the group exit");
  return 0;
}
"#;

#[test]
fn a_joiner_woken_by_a_fatal_signal_exit_runs_no_further_syscall() {
    let directory =
        std::env::temp_dir().join(format!("reverie-group-exit-order-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("group-exit-order.c");
    let executable = directory.join("group-exit-order");
    std::fs::write(&source, PROGRAM).unwrap();
    let output = Command::new("/usr/bin/gcc")
        .args([
            "-O2",
            "-pthread",
            "-fno-pie",
            "-no-pie",
            "-std=gnu11",
            "-Wall",
            "-Werror",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(output.status.success(), "gcc failed: {output:?}");
    let image = std::fs::read(&executable).unwrap();
    let program = executable.to_str().unwrap();
    // Widen the window: the dying receiver sleeps after waking the joiner.
    // Without the group exit published first, the joiner's write runs.
    DELAY_AFTER_CLEAR_TID_WAKE_MS.store(200, Ordering::Relaxed);
    let mut backend = KvmBackend::new(256 * 1024 * 1024).expect("this test requires /dev/kvm");
    backend
        .install_static_elf_with_context(&image, &[program], &[], &directory)
        .unwrap();
    let result = backend.run_static_elf_captured();
    DELAY_AFTER_CLEAR_TID_WAKE_MS.store(0, Ordering::Relaxed);
    let _ = std::fs::remove_dir_all(&directory);
    let (code, stdout, stderr) = result.unwrap();
    assert_eq!(
        code,
        128 + libc::SIGUSR1,
        "stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(
        stdout.is_empty(),
        "a joiner ran a syscall after the group exit: {}",
        String::from_utf8_lossy(&stdout)
    );
}
