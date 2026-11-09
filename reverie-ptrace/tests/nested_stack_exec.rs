/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Committed scratch across real successful and failed injected execs.

#![cfg(target_arch = "x86_64")]

use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use reverie::Errno;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Stack;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;
use reverie::syscalls::Sysno;
use reverie_ptrace::testing::test_fn;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
enum Seen {
    OuterCommitted,
    FailedExecRetained,
    ReplacementImage,
}

#[derive(Default)]
struct Log(Mutex<Vec<Seen>>);

#[reverie::global_tool]
impl GlobalTool for Log {
    type Config = ();
    type Request = Seen;
    type Response = ();

    async fn receive_rpc(&self, _from: Pid, seen: Seen) {
        self.0.lock().unwrap().push(seen);
    }
}

/// The flag records the real guard's lifetime, not just entry into a callback.
struct LiveGuard<G> {
    guard: Option<G>,
    live: Arc<AtomicBool>,
}

impl<G> Drop for LiveGuard<G> {
    fn drop(&mut self) {
        drop(self.guard.take());
        self.live.store(false, Ordering::SeqCst);
    }
}

#[derive(Clone, Default)]
struct ExecTool {
    outer_live: Arc<AtomicBool>,
}

#[reverie::tool]
impl Tool for ExecTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut events = Subscription::none();
        events.syscall(Sysno::execve);
        events
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert!(matches!(syscall, Syscall::Execve(_)));
        let mut outer = guest.stack().await;
        let outer_address = outer.push([0x39u8; 64]);
        let committed = outer.commit()?;
        assert!(!self.outer_live.swap(true, Ordering::SeqCst));
        let outer_guard = LiveGuard {
            guard: Some(committed),
            live: self.outer_live.clone(),
        };
        guest.send_rpc(Seen::OuterCommitted).await;

        // A successful exec never returns here. Its post-exec callback runs
        // while this future still owns outer_guard from the replaced image.
        let result = guest.inject(syscall).await;
        assert_eq!(result, Err(Errno::ENOENT));
        assert!(self.outer_live.load(Ordering::SeqCst));
        let mut bytes = [0u8; 64];
        guest
            .memory()
            .read_exact(outer_address.cast(), &mut bytes)?;
        assert_eq!(bytes, [0x39; 64]);

        // A failed exec did not replace the image or its live reservation.
        // Resetting the arena on an attempted exec would overlap these bytes.
        let mut inner = guest.stack().await;
        let inner_address = inner.push([0x5au8; 128]);
        assert!(inner_address.as_raw() + 128 <= outer_address.as_raw());
        let inner_guard = inner.commit()?;
        let mut inner_bytes = [0u8; 128];
        guest
            .memory()
            .read_exact(inner_address.cast(), &mut inner_bytes)?;
        guest
            .memory()
            .read_exact(outer_address.cast(), &mut bytes)?;
        assert_eq!(inner_bytes, [0x5a; 128]);
        assert_eq!(bytes, [0x39; 64]);
        drop(inner_guard);
        drop(outer_guard);
        assert!(!self.outer_live.load(Ordering::SeqCst));

        let mut whole = guest.stack().await;
        assert_eq!(whole.capacity(), 896);
        let whole_address = whole.push([0xa5u8; 896]);
        let whole_guard = whole.commit()?;
        let mut whole_bytes = [0u8; 896];
        guest
            .memory()
            .read_exact(whole_address.cast(), &mut whole_bytes)?;
        assert_eq!(whole_bytes, [0xa5; 896]);
        drop(whole_guard);
        guest.send_rpc(Seen::FailedExecRetained).await;
        Ok(result?)
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        assert!(
            self.outer_live.load(Ordering::SeqCst),
            "the old-image committed guard must still be held across injection"
        );
        let rsp = guest.regs().await.rsp;
        assert_eq!(guest.initial_stack_pointer(), Some(rsp));
        let mut whole = guest.stack().await;
        assert_eq!(
            whole.capacity(),
            896,
            "the new image gets the original full bound"
        );
        let address = whole.push([0x96u8; 896]);
        let guard = whole.commit()?;
        let mut bytes = [0u8; 896];
        guest.memory().read_exact(address.cast(), &mut bytes)?;
        assert_eq!(bytes, [0x96; 896]);
        assert!(self.outer_live.load(Ordering::SeqCst));
        drop(guard);
        guest.send_rpc(Seen::ReplacementImage).await;
        Ok(())
    }
}

fn exec_cell(success: bool) {
    let collector = tracing_subscriber::fmt().with_env_filter("warn").finish();
    let _ = tracing::subscriber::set_global_default(collector);
    let (output, log) = test_fn::<ExecTool, _>(move || {
        let path = if success {
            c"/bin/true"
        } else {
            c"/proc/self/fd/-1"
        };
        // SAFETY: both strings and the argv terminator are valid. A negative
        // descriptor is never an executable /proc/self/fd entry.
        let result = unsafe {
            libc::execl(
                path.as_ptr(),
                c"true".as_ptr(),
                std::ptr::null::<libc::c_char>(),
            )
        };
        assert!(!success, "the successful guest exec unexpectedly returned");
        assert_eq!(result, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOENT)
        );
    })
    .expect("actual injected exec completes");
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        *log.0.lock().unwrap(),
        [
            Seen::OuterCommitted,
            if success {
                Seen::ReplacementImage
            } else {
                Seen::FailedExecRetained
            }
        ],
    );
}

/// The unreaped leader pins this owned process-group ID until cleanup. The
/// normal wait uses WNOWAIT for this reason; no successful/failed exit bypasses
/// descendant cleanup. File capture cannot block on a descendant-held pipe.
struct Cell {
    child: Option<Child>,
    directory: PathBuf,
}

impl Drop for Cell {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.wait();
        }
        let _ = std::fs::remove_file(self.directory.join("stdout"));
        let _ = std::fs::remove_file(self.directory.join("stderr"));
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn output_file(cell: &Cell, name: &str) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(cell.directory.join(name))
        .unwrap()
}

fn captured(mut file: File) -> String {
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= 65536);
    String::from_utf8(bytes).unwrap()
}

/// Each actual trace runs in a new libtest process with the same 10s child
/// alarm and 15s outer bound as the ptracer-owner regression. Output is checked
/// against a 64KiB cap while it runs, then read from regular files after cleanup.
#[test]
fn committed_stack_frames_follow_actual_exec_lifetimes() {
    const CELL: &str = "REVERIE_STACK_EXEC_CELL";
    if let Ok(cell) = std::env::var(CELL) {
        assert!(cell == "success" || cell == "failure");
        // Confined to this re-executed cell, never the shared runner.
        unsafe { libc::alarm(10) };
        exec_cell(cell == "success");
        unsafe { libc::alarm(0) };
        println!("STACK_EXEC_CELL_PASSED {cell}");
        return;
    }
    for name in ["failure", "success"] {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "reverie-stack-exec-{}-{nonce}-{name}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let mut cell = Cell {
            child: None,
            directory,
        };
        let stdout = output_file(&cell, "stdout");
        let stderr = output_file(&cell, "stderr");
        cell.child = Some(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "committed_stack_frames_follow_actual_exec_lifetimes",
                    "--exact",
                    "--nocapture",
                ])
                .env(CELL, name)
                .process_group(0)
                .stdout(Stdio::from(stdout.try_clone().unwrap()))
                .stderr(Stdio::from(stderr.try_clone().unwrap()))
                .spawn()
                .unwrap(),
        );
        let pid = cell.child.as_ref().unwrap().id();
        let deadline = Instant::now() + Duration::from_secs(15);
        let (status, timed_out, too_much_output) = loop {
            let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
            // WNOWAIT keeps the leader, including a zombie, owned and unreaped
            // until every member of its original process group is signalled.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINTR)
                );
                continue;
            }
            let timed_out = Instant::now() >= deadline;
            let too_much_output = stdout.metadata().unwrap().len() > 65536
                || stderr.metadata().unwrap().len() > 65536;
            if unsafe { info.si_pid() } != 0 || timed_out || too_much_output {
                let killed = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
                if killed < 0 {
                    assert_eq!(
                        std::io::Error::last_os_error().raw_os_error(),
                        Some(libc::ESRCH)
                    );
                }
                let status = cell.child.as_mut().unwrap().wait().unwrap();
                cell.child = None;
                break (status, timed_out, too_much_output);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let stdout = captured(stdout);
        let stderr = captured(stderr);
        assert!(
            !timed_out,
            "stack exec cell {name} exceeded15s: {status}\n{stdout}\n{stderr}"
        );
        assert!(
            !too_much_output,
            "stack exec cell {name} exceeded64KiB of output"
        );
        assert!(status.success(), "{name}: {status}\n{stdout}\n{stderr}");
        assert_eq!(
            stdout
                .lines()
                .filter(|line| *line == format!("STACK_EXEC_CELL_PASSED {name}"))
                .count(),
            1
        );
        assert!(stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
    }
}
