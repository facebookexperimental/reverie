/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Whether a dying thread is its address space's last user, which decides
//! whether Linux's mm_release stores zero into its clear_child_tid word, does
//! not depend on when the other threads' host sides finish tearing down, nor
//! on how two exits of the same address space interleave.
//!
//! The program maps a shared file view and two shared anonymous pages, each
//! holding a marker, and forks; the child's threads point their
//! clear_child_tid words at the markers, and the parent prints both words
//! once it has reaped the child.

use std::ffi::CString;
use std::path::Path;
use std::path::PathBuf;
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
#include <time.h>
#include <unistd.h>
static volatile unsigned int *main_word, *worker_word;
static atomic_int worker_runs, release;
static const char *mode;
static void *worker(void *unused) {
  (void)unused;
  if (strcmp(mode, "join") == 0) return NULL;
  syscall(SYS_set_tid_address, (unsigned int *)worker_word);
  atomic_store(&worker_runs, 1);
  if (strcmp(mode, "group") == 0) {
    for (;;) sched_yield();
  }
  if (strcmp(mode, "ordinary-ordinary") == 0) {
    while (!atomic_load(&release)) sched_yield();
  }
  /* "ordinary-group" and "ordinary-ordinary": the worker exits by itself. */
  syscall(SYS_exit, 0);
  return NULL;
}
int main(int argc, char **argv) {
  if (argc != 2) return 1;
  mode = argv[1];
  int fd = open("last-user.data", O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0 || ftruncate(fd, 4096)) return 2;
  volatile unsigned char *view =
      mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  volatile unsigned int *one = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  volatile unsigned int *two = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (view == MAP_FAILED || one == MAP_FAILED || two == MAP_FAILED) return 3;
  view[0] = 'v';
  main_word = &one[16];
  worker_word = &two[16];
  *main_word = 0x5eedf00d;
  *worker_word = 0x5eedf00d;
  pid_t child = fork();
  if (child < 0) return 4;
  if (child == 0) {
    syscall(SYS_set_tid_address, (unsigned int *)main_word);
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL)) _exit(5);
    if (strcmp(mode, "join") == 0) {
      /* The main thread exits by itself once it has joined the worker. */
      if (pthread_join(thread, NULL)) _exit(6);
      syscall(SYS_exit, 0);
    }
    while (!atomic_load(&worker_runs)) sched_yield();
    if (strcmp(mode, "ordinary-ordinary") == 0) {
      /* Both threads exit by themselves. */
      atomic_store(&release, 1);
      syscall(SYS_exit, 0);
    }
    if (strcmp(mode, "ordinary-group") == 0) {
      /* The worker exits by itself; then the main thread ends the group. */
      struct timespec delay = {0, 100 * 1000 * 1000};
      while (nanosleep(&delay, &delay)) {
      }
    }
    /* "group" and "ordinary-group". */
    syscall(SYS_exit_group, 0);
    _exit(7);
  }
  int status;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
    return 8;
  printf("main=%#x worker=%#x\n", *main_word, *worker_word);
  return 0;
}
"#;

/// The test's own directory, made fresh by mkdtemp and removed when dropped,
/// a panicking test's included.
struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let template = std::env::temp_dir().join(format!("reverie-{name}-XXXXXX"));
        let template = CString::new(template.into_os_string().into_encoded_bytes()).unwrap();
        let raw = template.into_raw();
        // SAFETY: raw is a NUL-terminated, writable template that mkdtemp
        // fills in place; it is taken back into a CString below.
        let made = unsafe { libc::mkdtemp(raw) };
        let template = unsafe { CString::from_raw(raw) };
        assert!(
            !made.is_null(),
            "mkdtemp: {}",
            std::io::Error::last_os_error()
        );
        TestDir(PathBuf::from(template.into_string().unwrap()))
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Sets `DELAY_AFTER_CLEAR_TID_WAKE_MS` until dropped.
struct DelayAfterWake(());

impl DelayAfterWake {
    fn set(milliseconds: u64) -> Self {
        DELAY_AFTER_CLEAR_TID_WAKE_MS.store(milliseconds, Ordering::Relaxed);
        DelayAfterWake(())
    }
}

impl Drop for DelayAfterWake {
    fn drop(&mut self) {
        DELAY_AFTER_CLEAR_TID_WAKE_MS.store(0, Ordering::Relaxed);
    }
}

fn compile(directory: &Path) -> PathBuf {
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
    executable
}

/// The two words the program prints for `mode`, natively.
fn native(executable: &Path, directory: &Path, mode: &str) -> (u32, u32) {
    let output = Command::new(executable)
        .arg(mode)
        .current_dir(directory)
        .output()
        .unwrap();
    assert!(output.status.success(), "{mode} natively: {output:?}");
    words(&String::from_utf8(output.stdout).unwrap())
}

/// The two words the program prints for `mode` on KVM without a tool.
fn kvm(executable: &Path, directory: &Path, mode: &str) -> (u32, u32) {
    let image = std::fs::read(executable).unwrap();
    let program = executable.to_str().unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).expect("this test requires /dev/kvm");
    backend
        .install_static_elf_with_context(&image, &[program, mode], &[], directory)
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        0,
        "{mode}: stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    words(&String::from_utf8(stdout).unwrap())
}

/// The two words of the program's one line of output, exactly
/// `main=<word> worker=<word>\n` with each word as printf's `%#x` writes it:
/// any other label, an extra field or trailing output fails the test.
fn words(stdout: &str) -> (u32, u32) {
    let line = stdout
        .strip_suffix('\n')
        .filter(|line| !line.contains('\n'))
        .unwrap_or_else(|| panic!("expected one line of output, got {stdout:?}"));
    let word = |field: Option<&str>, label: &str| -> u32 {
        let text = field
            .and_then(|field| field.strip_prefix(label))
            .and_then(|field| field.strip_prefix('='))
            .unwrap_or_else(|| panic!("expected {label}=<word> in {stdout:?}"));
        let value = match text.strip_prefix("0x") {
            Some(hex) => u32::from_str_radix(hex, 16).ok(),
            None => text.parse().ok(),
        }
        .unwrap_or_else(|| panic!("{label} is not a word in {stdout:?}"));
        // printf's %#x: "0" for zero, else lower-case hex with no leading
        // zeros after "0x".
        let printed = if value == 0 {
            "0".to_owned()
        } else {
            format!("{value:#x}")
        };
        assert_eq!(text, printed, "{label} in {stdout:?}");
        value
    };
    let mut fields = line.split(' ');
    let main = word(fields.next(), "main");
    let worker = word(fields.next(), "worker");
    assert_eq!(fields.next(), None, "trailing output in {stdout:?}");
    (main, worker)
}

/// The output check takes exactly the program's line and nothing else.
#[test]
fn the_output_check_takes_exactly_the_two_labelled_words() {
    assert_eq!(words("main=0x5eedf00d worker=0\n"), (MARKER, 0));
    for wrong in [
        "main=0x5eedf00d worker=0",
        "main=0x5eedf00d worker=0 extra=1\n",
        "main=0x5eedf00d worker=0\nmore\n",
        "worker=0 main=0x5eedf00d\n",
        "main=0x5eedf00d other=0\n",
        "main=0x5eedf00d\n",
        "main=0x05eedf00d worker=0\n",
        "main=0x0 worker=0\n",
        "main=0x5eedf00d  worker=0\n",
    ] {
        assert!(
            std::panic::catch_unwind(|| words(wrong)).is_err(),
            "accepted {wrong:?}"
        );
    }
}

const MARKER: u32 = 0x5eed_f00d;

/// At a group exit both dying threads decide with the answer recorded when
/// the exit was first published, while the worker was live: both store zero,
/// one of the outcomes Linux allows. The hold makes each decide only once the
/// other has retired, where an answer read then, or at the later thread's own
/// retirement, would say "last user" and leave that thread's marker.
#[test]
fn a_group_exit_decides_the_last_user_when_it_begins() {
    let directory = TestDir::new("clear-tid-group");
    let executable = compile(&directory.0);
    let _hold = clear_tid_last_user_hold::arm(clear_tid_last_user_hold::Hold::Peers);
    assert_eq!(kvm(&executable, &directory.0, "group"), (0, 0));
}

/// A joined thread stops counting as a user of the address space at its own
/// exit, before its clear_child_tid wake lets the joiner run, however long
/// its host side takes afterwards: here it sleeps after the wake, and the
/// main thread, now the last user, leaves the marker as Linux does.
#[test]
fn a_joined_thread_counts_no_more_however_long_its_host_side_takes() {
    let directory = TestDir::new("clear-tid-join");
    let executable = compile(&directory.0);
    let _delay = DelayAfterWake::set(200);
    assert_eq!(kvm(&executable, &directory.0, "join").0, MARKER);
}

/// Two exits of one address space never both leave their clear_child_tid
/// words, as on Linux, where the first task to reach mm_release finds
/// mm_users above 1. "ordinary-ordinary": both threads exit by themselves,
/// and the hold makes each wait after its retirement until the other has
/// retired too, so an answer read after the retirement would find each the
/// last user. "ordinary-group": the worker exits by itself and waits after
/// its retirement until the main thread's exit_group is published, whose
/// answer, read once the worker has retired, is that no other thread is
/// live; the worker must keep the answer of its own retirement, when the
/// main thread was live. Natively either word, or both, may be cleared.
#[test]
fn two_exits_never_both_leave_their_clear_child_tid_words() {
    let directory = TestDir::new("clear-tid-two-exits");
    let executable = compile(&directory.0);
    for mode in ["ordinary-ordinary", "ordinary-group"] {
        let (main, worker) = native(&executable, &directory.0, mode);
        assert!(
            main == 0 || worker == 0,
            "{mode} natively: {main:#x} {worker:#x}"
        );
    }
    for (mode, hold) in [
        ("ordinary-ordinary", clear_tid_last_user_hold::Hold::Peers),
        (
            "ordinary-group",
            clear_tid_last_user_hold::Hold::OrdinaryThenGroup,
        ),
    ] {
        let _hold = clear_tid_last_user_hold::arm(hold);
        let (main, worker) = kvm(&executable, &directory.0, mode);
        assert!(
            main == 0 || worker == 0,
            "{mode} on KVM: {main:#x} {worker:#x}"
        );
        if mode == "ordinary-group" {
            // The worker retired while the main thread lived, so it stored;
            // the main thread was then the last user.
            assert_eq!((main, worker), (MARKER, 0), "{mode} on KVM");
        }
    }
}

/// Per process (each forked child gets its own): when the main thread of a
/// process with a worker calls exit_group, the Tool retires the worker at its
/// next sched_yield, as a Tool may retire an exit_group's siblings once it
/// has ordered the exit, and lets the exit_group run once the worker has
/// begun to retire.
#[derive(Default)]
struct RetireWorkerAtGroupExit {
    worker: std::sync::atomic::AtomicI32,
    retire: std::sync::atomic::AtomicBool,
    retiring: std::sync::atomic::AtomicBool,
}

#[reverie::tool]
impl reverie::Tool for RetireWorkerAtGroupExit {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_thread_start<G: reverie::Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> std::result::Result<(), reverie::Error> {
        if guest.pid() != guest.tid() {
            self.worker.store(guest.tid().as_raw(), Ordering::SeqCst);
        }
        Ok(())
    }

    async fn handle_syscall_event<G: reverie::Guest<Self>>(
        &self,
        guest: &mut G,
        call: reverie::syscalls::Syscall,
    ) -> std::result::Result<i64, reverie::Error> {
        use reverie::syscalls::SyscallInfo;
        use reverie::syscalls::Sysno;
        if guest.pid() != guest.tid()
            && call.number() == Sysno::sched_yield
            && self.retire.load(Ordering::SeqCst)
        {
            self.retiring.store(true, Ordering::SeqCst);
            guest.retire_current_thread().await;
        }
        if guest.pid() == guest.tid()
            && call.number() == Sysno::exit_group
            && self.worker.load(Ordering::SeqCst) != 0
        {
            self.retire.store(true, Ordering::SeqCst);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !self.retiring.load(Ordering::SeqCst) {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the worker never began to retire"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        guest.tail_inject(call).await
    }
}

/// The two words the program prints for `mode` on KVM under
/// `RetireWorkerAtGroupExit`.
fn kvm_with_retiring_tool(executable: &Path, directory: &Path, mode: &str) -> (u32, u32) {
    let image = std::fs::read(executable).unwrap();
    let program = executable.to_str().unwrap();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).expect("this test requires /dev/kvm");
    backend
        .install_static_elf_with_context(&image, &[program, mode], &[], directory)
        .unwrap();
    let (_, code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<RetireWorkerAtGroupExit>((), true),
    )
    .unwrap();
    assert_eq!(
        code,
        0,
        "{mode}: stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    words(&String::from_utf8(stdout).unwrap())
}

/// A thread its Tool retires dies in its group's death and decides with
/// that exit's answer, as the main thread does. "group": the main thread
/// calls exit_group while the worker, whose word is the second marker,
/// spins; the Tool retires the worker for that exit. The hold makes the
/// main thread publish the exit only once the worker's retirement has been
/// noted, and the worker retire from the entry gate only once the main
/// thread has retired, so the worker's own retirement would find it the
/// last user and leave its marker. With the worker live at the exit's
/// commit, both store zero, one of the outcomes Linux allows.
#[test]
fn a_thread_its_tool_retired_takes_its_group_exits_answer() {
    let directory = TestDir::new("clear-tid-tool-retired");
    let executable = compile(&directory.0);
    let _hold =
        clear_tid_last_user_hold::arm(clear_tid_last_user_hold::Hold::ToolRetiredThenPublisher);
    assert_eq!(
        kvm_with_retiring_tool(&executable, &directory.0, "group"),
        (0, 0)
    );
}
