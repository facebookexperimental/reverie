/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Whether a dying thread is its address space's last user, which decides
//! whether Linux's mm_release stores zero into its clear_child_tid word, does
//! not depend on when the other threads' host sides finish tearing down.
//!
//! The program maps a shared file view and a shared anonymous page holding a
//! marker, and forks; a thread of the child points its clear_child_tid at the
//! marker, and the parent prints the word once it has reaped the child.

use std::process::Command;
use std::sync::atomic::Ordering;

use super::*;

const PROGRAM: &str = r#"#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static atomic_int spinner_runs;
static void *spin(void *unused) {
  (void)unused;
  atomic_store(&spinner_runs, 1);
  for (;;) sched_yield();
  return NULL;
}
static void *brief(void *unused) { return unused; }
int main(int argc, char **argv) {
  if (argc != 2) return 1;
  int fd = open("last-user.data", O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0 || ftruncate(fd, 4096)) return 2;
  volatile unsigned char *view =
      mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  volatile unsigned int *marker = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (view == MAP_FAILED || marker == MAP_FAILED) return 3;
  view[0] = 'v';
  marker[16] = 0x5eedf00d;
  pid_t child = fork();
  if (child < 0) return 4;
  if (child == 0) {
    syscall(SYS_set_tid_address, (unsigned int *)&marker[16]);
    pthread_t thread;
    if (strcmp(argv[1], "group") == 0) {
      /* The main thread ends the group while the worker runs. */
      if (pthread_create(&thread, NULL, spin, NULL)) _exit(5);
      while (!atomic_load(&spinner_runs)) sched_yield();
      syscall(SYS_exit_group, 0);
    } else {
      /* The main thread exits by itself once it has joined the worker. */
      if (pthread_create(&thread, NULL, brief, NULL) || pthread_join(thread, NULL))
        _exit(6);
      syscall(SYS_exit, 0);
    }
    _exit(7);
  }
  int status;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
    return 8;
  printf("word=%#x\n", marker[16]);
  return 0;
}
"#;

/// Runs the program in `mode` on KVM without a tool and returns its stdout.
fn run(mode: &str) -> String {
    let directory = std::env::temp_dir().join(format!(
        "reverie-clear-tid-last-user-{mode}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("last-user.c");
    let executable = directory.join("last-user");
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
    let mut backend = KvmBackend::new(256 * 1024 * 1024).expect("this test requires /dev/kvm");
    backend
        .install_static_elf_with_context(&image, &[program, mode], &[], &directory)
        .unwrap();
    let result = backend.run_static_elf_captured();
    let _ = std::fs::remove_dir_all(&directory);
    let (code, stdout, stderr) = result.unwrap();
    assert_eq!(code, 0, "stderr={}", String::from_utf8_lossy(&stderr));
    String::from_utf8(stdout).unwrap()
}

/// At a group exit the main thread, whose word is the marker, decides with
/// the answer recorded when the exit was first published, while the worker
/// was live: it stores zero, one of the outcomes Linux allows. The hold makes
/// the main thread decide only once the worker's host side has retired it,
/// where an answer read at that moment would say "last user" and leave the
/// marker.
#[test]
fn a_group_exit_decides_the_last_user_when_it_begins() {
    clear_tid_last_user_hold::arm(true);
    let stdout = run("group");
    clear_tid_last_user_hold::arm(false);
    assert_eq!(stdout, "word=0\n");
}

/// A joined thread stops counting as a user of the address space at its own
/// exit, before its clear_child_tid wake lets the joiner run, however long
/// its host side takes afterwards: here it sleeps after the wake, and the
/// main thread, now the last user, leaves the marker as Linux does.
#[test]
fn a_joined_thread_counts_no_more_however_long_its_host_side_takes() {
    DELAY_AFTER_CLEAR_TID_WAKE_MS.store(200, Ordering::Relaxed);
    let stdout = run("join");
    DELAY_AFTER_CLEAR_TID_WAKE_MS.store(0, Ordering::Relaxed);
    assert_eq!(stdout, "word=0x5eedf00d\n");
}
