/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Software breakpoints that Reverie's GDB server sets less than 8 bytes apart
//! must not disturb each other.
//!
//! The server sets a breakpoint by writing `int3` (0xcc) over the first byte
//! of an 8-byte word that it reads and writes through ptrace, so the word also
//! covers the 7 bytes after the breakpoint. Removing the breakpoint must put
//! back that one byte only. When it wrote back the whole word as it was read
//! at insertion, it also undid every change made since to those 7 bytes:
//!
//! - It erased a breakpoint inserted there later. GDB inserts breakpoints in
//!   ascending address order and steps over a breakpoint that it has hit by
//!   removing it, single-stepping and inserting it again, so stepping over a
//!   breakpoint on one short source line removed the breakpoint on the next,
//!   and the program ran past it.
//! - It wrote back the `int3` of a breakpoint there that was live when this
//!   one was inserted and was removed first, leaving a stray `int3`. Reverie
//!   suppresses a SIGTRAP that no breakpoint accounts for, so the guest ran on
//!   from the byte after the `int3`, inside an instruction.
//!
//! Each test drives the server over the GDB remote protocol, as GDB does,
//! against a guest built from `fixtures/gdbstub_adjacent_breakpoints.c`, with
//! two breakpoint sites 6 bytes apart. It checks where the guest stops and
//! reads the guest's code through `/proc/<pid>/mem`, which shows the inserted
//! `int3` bytes that the server's `m` packet hides.

#![cfg(target_arch = "x86_64")]

use std::future::Future;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;

use reverie::ExitStatus;
use reverie::Tool;
use reverie::process::Command;
use reverie_ptrace::TracerBuilder;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

#[derive(Default)]
struct NoopTool;

#[reverie::tool]
impl Tool for NoopTool {
    type GlobalState = ();
    type ThreadState = ();
}

/// Compiles `tests/fixtures/<fixture>.c` with `cc -O0 -g -no-pie` and the
/// extra `args`, and returns the guest's path and the addresses of `symbols`.
fn build_guest(fixture: &str, args: &[&str], symbols: &[&str]) -> (PathBuf, Vec<u64>) {
    // Prefer the run-time CARGO_MANIFEST_DIR, which Cargo and the fbsource
    // BUCK rule set. The compile-time value is a directory on the build
    // host and is missing on the test host when the binary was built
    // remotely.
    let source = std::env::var_os("CARGO_MANIFEST_DIR")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
        .join(format!("tests/fixtures/{fixture}.c"));
    // One guest beside the test binary, compiled by each process and
    // renamed into place, as for the trap-only parity guest.
    let directory = std::env::current_exe()
        .expect("locate the test binary")
        .parent()
        .expect("the test binary has a directory")
        .to_path_buf();
    let name = format!("reverie-{}", fixture.replace('_', "-"));
    let path = directory.join(&name);
    let staging = directory.join(format!("{name}.{}.tmp", std::process::id()));
    // -no-pie: the symbol values below are then run-time addresses.
    let status = std::process::Command::new("cc")
        .args(["-O0", "-g", "-no-pie"])
        .args(args)
        .arg(&source)
        .arg("-o")
        .arg(&staging)
        .status()
        .unwrap_or_else(|error| panic!("invoke cc for {}: {error}", source.display()));
    assert!(status.success(), "compile {}", source.display());
    std::fs::rename(&staging, &path)
        .unwrap_or_else(|error| panic!("publish {}: {error}", path.display()));

    let image = std::fs::read(&path).expect("read the guest");
    let elf = goblin::elf::Elf::parse(&image).expect("parse the guest");
    let addresses = symbols
        .iter()
        .map(|name| {
            elf.syms
                .iter()
                .find(|sym| elf.strtab.get_at(sym.st_name) == Some(name))
                .unwrap_or_else(|| panic!("the guest has no symbol {name}"))
                .st_value
        })
        .collect();
    (path, addresses)
}

/// The guest and the addresses of its two breakpoint sites.
struct Guest {
    path: PathBuf,
    /// `reverie_bkpt_a`, followed by two 3-byte nops.
    a: u64,
    /// `reverie_bkpt_b`, 6 bytes after `a`.
    b: u64,
}

fn guest() -> &'static Guest {
    static GUEST: LazyLock<Guest> = LazyLock::new(|| {
        let (path, addresses) = build_guest(
            "gdbstub_adjacent_breakpoints",
            &[],
            &["reverie_bkpt_a", "reverie_bkpt_b"],
        );
        let (a, b) = (addresses[0], addresses[1]);
        assert_eq!(
            b,
            a + 6,
            "the guest's breakpoint sites are not 6 bytes apart"
        );
        Guest { path, a, b }
    });
    &GUEST
}

/// The two-thread guest and the address of its breakpoint site, which the
/// main thread reaches after the second thread has exited.
struct ThreadGuest {
    path: PathBuf,
    /// `reverie_bkpt_main`.
    site: u64,
}

fn thread_guest() -> &'static ThreadGuest {
    static GUEST: LazyLock<ThreadGuest> = LazyLock::new(|| {
        let (path, addresses) = build_guest(
            "gdbstub_thread_breakpoint",
            &["-pthread"],
            &["reverie_bkpt_main"],
        );
        ThreadGuest {
            path,
            site: addresses[0],
        }
    });
    &GUEST
}

/// Reads guest memory through `/proc/<pid>/mem`. Unlike the `m` packet, which
/// shows the original bytes under each breakpoint, it shows the `int3` bytes
/// that the server has written.
fn guest_bytes(pid: u32, addr: u64, len: usize) -> Vec<u8> {
    let mem = std::fs::File::open(format!("/proc/{pid}/mem")).expect("open the guest's memory");
    let mut bytes = vec![0; len];
    mem.read_exact_at(&mut bytes, addr)
        .expect("read the guest's memory");
    bytes
}

/// A minimal GDB remote protocol client.
struct Remote {
    stream: UnixStream,
    received: Vec<u8>,
    /// The guest's process ID, from `qC`.
    pid: u32,
    /// The `p<pid>.<tid>` thread ID, from `qC`, in the protocol's hex.
    thread: String,
}

impl Remote {
    /// Connects once the server listens, turns acknowledgements off and asks
    /// for the stopped guest's thread.
    async fn connect(socket: &Path) -> Self {
        let mut attempts = 0;
        let stream = loop {
            match UnixStream::connect(socket).await {
                Ok(stream) => break stream,
                Err(error) => {
                    attempts += 1;
                    assert!(attempts < 3000, "connect to the GDB server: {error}");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        };
        let mut remote = Remote {
            stream,
            received: Vec::new(),
            pid: 0,
            thread: String::new(),
        };
        assert_eq!(remote.request("QStartNoAckMode").await, "OK");
        let current = remote.request("qC").await;
        let thread = current
            .strip_prefix("QC")
            .unwrap_or_else(|| panic!("unexpected qC reply {current:?}"));
        let pid = thread
            .strip_prefix('p')
            .and_then(|id| id.split('.').next())
            .and_then(|pid| u32::from_str_radix(pid, 16).ok())
            .unwrap_or_else(|| panic!("unexpected qC reply {current:?}"));
        remote.pid = pid;
        remote.thread = thread.to_owned();
        remote
    }

    async fn send(&mut self, data: &str) {
        let checksum = data.bytes().fold(0u8, |sum, byte| sum.wrapping_add(byte));
        self.stream
            .write_all(format!("${data}#{checksum:02x}").as_bytes())
            .await
            .expect("send a packet to the GDB server");
    }

    async fn recv(&mut self) -> String {
        loop {
            // Acknowledgements the server sent before no-ack mode.
            while self.received.first() == Some(&b'+') {
                self.received.remove(0);
            }
            if let Some(&first) = self.received.first() {
                assert_eq!(
                    first,
                    b'$',
                    "unexpected bytes from the GDB server: {:?}",
                    String::from_utf8_lossy(&self.received)
                );
                if let Some(hash) = self.received.iter().position(|&byte| byte == b'#')
                    && self.received.len() >= hash + 3
                {
                    let data = String::from_utf8(self.received[1..hash].to_vec())
                        .expect("the GDB server's reply is text");
                    self.received.drain(..hash + 3);
                    return data;
                }
            }
            let mut chunk = [0u8; 4096];
            let len = self
                .stream
                .read(&mut chunk)
                .await
                .expect("receive from the GDB server");
            assert!(len > 0, "the GDB server closed the connection");
            self.received.extend_from_slice(&chunk[..len]);
        }
    }

    async fn request(&mut self, data: &str) -> String {
        self.send(data).await;
        self.recv().await
    }

    async fn insert(&mut self, addr: u64) {
        assert_eq!(self.request(&format!("Z0,{addr:x},1")).await, "OK");
    }

    async fn remove(&mut self, addr: u64) {
        assert_eq!(self.request(&format!("z0,{addr:x},1")).await, "OK");
    }

    /// Resumes every thread of the guest, as GDB's `continue` does.
    async fn resume(&mut self) -> String {
        let pid = self.pid;
        self.request(&format!("vCont;c:p{pid:x}.-1")).await
    }

    async fn step(&mut self) -> String {
        let thread = self.thread.clone();
        self.request(&format!("vCont;s:{thread}")).await
    }
}

/// The %rip, register 0x10, in a SIGTRAP stop reply.
fn stop_rip(reply: &str) -> u64 {
    assert!(
        reply.starts_with("T05"),
        "expected a SIGTRAP stop, got {reply:?}"
    );
    let hex = reply
        .split(';')
        .find_map(|field| field.strip_prefix("10:"))
        .unwrap_or_else(|| panic!("no %rip in the stop reply {reply:?}"));
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex register value"))
        .collect();
    u64::from_le_bytes(bytes.try_into().expect("an 8-byte %rip"))
}

/// The reply when the guest exits with status 0.
fn assert_exited_zero(reply: &str, context: &str) {
    assert!(
        reply.starts_with("W00"),
        "{context}: expected the guest to exit 0, got {reply:?}"
    );
}

/// Runs the adjacent-breakpoints guest under Reverie's GDB server, with
/// `client` as GDB, and checks that the guest exits 0.
async fn debug_guest<F, Fut>(name: &str, client: F)
where
    F: FnOnce(Remote) -> Fut,
    Fut: Future<Output = ()>,
{
    debug(&guest().path, name, client).await
}

/// Runs `path` under Reverie's GDB server, with `client` as GDB, and checks
/// that the guest exits 0.
async fn debug<F, Fut>(path: &Path, name: &str, client: F)
where
    F: FnOnce(Remote) -> Fut,
    Fut: Future<Output = ()>,
{
    let socket = std::env::temp_dir().join(format!(
        "reverie-gdbstub-{name}-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket);
    let command = Command::new(path);
    let tracer = async {
        TracerBuilder::<NoopTool>::new(command)
            .gdbserver(socket.clone())
            .spawn()
            .await
            .expect("spawn the guest under the GDB server")
            .wait()
            .await
            .expect("wait for the guest")
            .0
    };
    let gdb = async {
        let remote = Remote::connect(&socket).await;
        client(remote).await;
    };
    let (status, ()) = tokio::time::timeout(Duration::from_secs(120), async {
        tokio::join!(tracer, gdb)
    })
    .await
    .expect("the guest and the GDB session finish");
    let _ = std::fs::remove_file(&socket);
    assert_eq!(status, ExitStatus::Exited(0));
}

/// GDB's sequence for two breakpoints 6 bytes apart: insert both in ascending
/// order, continue to the first, step over it, and continue. The guest must
/// stop at the second.
#[tokio::test]
async fn step_over_keeps_a_breakpoint_6_bytes_later() {
    let Guest { a, b, .. } = *guest();
    debug_guest("step-over", |mut remote| async move {
        let pid = remote.pid;
        remote.insert(a).await;
        remote.insert(b).await;
        assert_eq!(guest_bytes(pid, b, 1), [0xcc]);

        let stop = remote.resume().await;
        assert!(stop.starts_with("T05swbreak:"), "{stop:?}");
        assert_eq!(stop_rip(&stop), a, "stopped away from the first breakpoint");

        // GDB's step over the breakpoint it stopped at.
        remote.remove(a).await;
        let at_b_after_removing_a = guest_bytes(pid, b, 1)[0];
        let stop = remote.step().await;
        assert_eq!(
            stop_rip(&stop),
            a + 3,
            "the step did not stop after one nop"
        );
        remote.insert(a).await;

        let stop = remote.resume().await;
        assert!(
            stop.starts_with("T05swbreak:"),
            "the breakpoint at a + 6 did not trap; its byte was {at_b_after_removing_a:#04x} \
             after the breakpoint at a was removed: {stop:?}"
        );
        assert_eq!(
            stop_rip(&stop),
            b,
            "stopped away from the second breakpoint"
        );
        assert_eq!(at_b_after_removing_a, 0xcc);

        remote.remove(b).await;
        remote.remove(a).await;
        assert_exited_zero(&remote.resume().await, "after removing both breakpoints");
    })
    .await;
}

/// Inserting the first breakpoint while the second, 6 bytes later, is live
/// reads the second's `int3` into the first's saved word. Removing the
/// second and then the first must leave the guest's code as it was, with no
/// stray `int3` to trap on.
#[tokio::test]
async fn removal_does_not_restore_an_earlier_removed_breakpoint_6_bytes_later() {
    let Guest { a, b, .. } = *guest();
    debug_guest("mirror", |mut remote| async move {
        let pid = remote.pid;
        let original = guest_bytes(pid, a, 16);
        remote.insert(b).await;
        remote.insert(a).await;
        remote.remove(b).await;
        remote.remove(a).await;
        let restored = guest_bytes(pid, a, 16);
        assert_exited_zero(
            &remote.resume().await,
            &format!("after removing both breakpoints, code from a {restored:02x?}"),
        );
        assert_eq!(
            restored, original,
            "the guest's code from a was not restored"
        );
    })
    .await;
}

/// The GDB remote protocol requires `Z0` to be idempotent. Inserting a
/// breakpoint twice and removing it once must leave the guest's code as it
/// was, rather than saving the `int3` as the original byte.
#[tokio::test]
async fn inserting_a_breakpoint_twice_is_idempotent() {
    let Guest { a, .. } = *guest();
    debug_guest("twice", |mut remote| async move {
        let pid = remote.pid;
        let original = guest_bytes(pid, a, 16);
        remote.insert(a).await;
        remote.insert(a).await;
        remote.remove(a).await;
        let restored = guest_bytes(pid, a, 16);
        assert_exited_zero(
            &remote.resume().await,
            &format!("after removing the breakpoint, code from a {restored:02x?}"),
        );
        assert_eq!(restored, original, "the guest's code at a was not restored");
    })
    .await;
}

/// Each thread's task keeps its own copy of the breakpoint table, copied from
/// its parent's when the thread is created. A breakpoint removed through one
/// thread is therefore still listed in the other's copy, although its `int3`
/// is gone from the shared code. Inserting it again through the other thread
/// must write the `int3` back rather than treat the stale entry as proof
/// that the breakpoint is live; otherwise the guest runs past it.
#[tokio::test]
async fn reinserting_through_another_thread_writes_the_breakpoint_back() {
    let ThreadGuest { path, site } = thread_guest();
    let site = *site;
    debug(path, "threads", |mut remote| async move {
        let pid = remote.pid;
        let main = remote.thread.clone();
        remote.insert(site).await;

        // The stop for the second thread's creation. Both threads' tables now
        // list the breakpoint.
        let stop = remote.resume().await;
        let created = stop
            .strip_prefix("T05create:")
            .and_then(|rest| rest.split(';').next())
            .unwrap_or_else(|| panic!("expected a thread-creation stop, got {stop:?}"))
            .to_owned();
        assert_ne!(created, main, "the creation stop names the main thread");

        // Remove the breakpoint through the second thread and insert it
        // again through the main thread, whose table still lists it.
        assert_eq!(remote.request(&format!("Hg{created}")).await, "OK");
        remote.remove(site).await;
        assert_eq!(guest_bytes(pid, site, 1), [0x0f]);
        assert_eq!(remote.request(&format!("Hg{main}")).await, "OK");
        remote.insert(site).await;
        let reinserted = guest_bytes(pid, site, 1)[0];

        let stop = remote.resume().await;
        assert!(
            stop.starts_with("T05swbreak:"),
            "the main thread did not stop at the breakpoint inserted again; \
             the byte there was {reinserted:#04x}: {stop:?}"
        );
        assert_eq!(stop_rip(&stop), site, "stopped away from the breakpoint");
        assert_eq!(reinserted, 0xcc);

        remote.remove(site).await;
        assert_exited_zero(&remote.resume().await, "after removing the breakpoint");
    })
    .await;
}
