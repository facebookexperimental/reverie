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
//!
//! The file also drives GDB's interrupt (the byte 0x03 of Ctrl-C) against a
//! guest that never stops on its own (`fixtures/gdbstub_interrupt.c`), and
//! the fork, vfork and exec stops a client gets only if it asks for them in
//! its `qSupported` (`fixtures/gdbstub_fork_events.c`, `gdbstub_exec.c`).

#![cfg(target_arch = "x86_64")]

use std::future::Future;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;

use reverie::Error;
use reverie::ExitStatus;
use reverie::Guest as TracedGuest;
use reverie::Signal;
use reverie::Tool;
use reverie::process::Command;
use reverie::syscalls::Errno;
use reverie::syscalls::Getpid;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_ptrace::TracerBuilder;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

#[path = "gdbstub_breakpoints/reserved_input_signals.rs"]
mod reserved_input_signals;

#[path = "gdbstub_breakpoints/reserved_input_interrupts.rs"]
mod reserved_input_interrupts;

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
    // renamed into place.
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

    /// Lists the client's features, as GDB's first packet does, and checks
    /// that the server answers with its own. Then has SIGCHLD passed without
    /// a stop, as GDB does by default (`QPassSignals`, gdb's number 0x14).
    async fn supported(&mut self, features: &str) {
        let reply = self.request(&format!("qSupported:{features}")).await;
        assert!(reply.starts_with("PacketSize="), "{reply:?}");
        assert_eq!(self.request("QPassSignals:14").await, "OK");
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

    /// Resumes every thread of the guest without waiting for the stop.
    async fn resume_in_background(&mut self) {
        let pid = self.pid;
        self.send(&format!("vCont;c:p{pid:x}.-1")).await;
    }

    /// Sends GDB's interrupt, the byte 0x03 that GDB sends for Ctrl-C, and
    /// returns the stop that answers it.
    async fn interrupt(&mut self) -> String {
        self.stream
            .write_all(&[0x03])
            .await
            .expect("send the interrupt to the GDB server");
        self.recv().await
    }
}

/// The `p<pid>.<tid>` thread a stop reply names.
fn stop_thread(reply: &str) -> &str {
    reply
        .split(';')
        .find_map(|field| field.strip_prefix("thread:"))
        .unwrap_or_else(|| panic!("no thread in the stop reply {reply:?}"))
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
    let status = debug_to_end(path, name, client).await;
    assert_eq!(status, ExitStatus::Exited(0));
}

/// Runs `path` under Reverie's GDB server, with `client` as GDB, and returns
/// how the guest ended.
async fn debug_to_end<F, Fut>(path: &Path, name: &str, client: F) -> ExitStatus
where
    F: FnOnce(Remote) -> Fut,
    Fut: Future<Output = ()>,
{
    debug_to_end_with::<NoopTool, _, _>(path, name, false, client).await
}

/// Runs `path` under Reverie's GDB server and Tool `T`, with `client` as GDB,
/// and returns how the guest ended. `sequentialized` tells the server that
/// `T` runs one thread at a time (`TracerBuilder::sequentialized_guest`).
async fn debug_to_end_with<T, F, Fut>(
    path: &Path,
    name: &str,
    sequentialized: bool,
    client: F,
) -> ExitStatus
where
    T: Tool + Default + 'static,
    T::GlobalState: Default,
    F: FnOnce(Remote) -> Fut,
    Fut: Future<Output = ()>,
{
    debug_command_to_end::<T, _, _>(Command::new(path), name, sequentialized, client).await
}

/// `debug_to_end_with` for a `command`, which can carry arguments.
async fn debug_command_to_end<T, F, Fut>(
    command: Command,
    name: &str,
    sequentialized: bool,
    client: F,
) -> ExitStatus
where
    T: Tool + Default + 'static,
    T::GlobalState: Default,
    F: FnOnce(Remote) -> Fut,
    Fut: Future<Output = ()>,
{
    let socket = std::env::temp_dir().join(format!(
        "reverie-gdbstub-{name}-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket);
    let tracer = async {
        let builder = TracerBuilder::<T>::new(command).gdbserver(socket.clone());
        let builder = if sequentialized {
            builder.sequentialized_guest()
        } else {
            builder
        };
        builder
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
    status
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

/// The guest that executes its own `int3`, and the address just past it.
struct Int3Guest {
    path: PathBuf,
    /// `reverie_after_guest_int3`, where the guest stops after the trap.
    after: u64,
}

fn int3_guest() -> &'static Int3Guest {
    static GUEST: LazyLock<Int3Guest> = LazyLock::new(|| {
        let (path, addresses) =
            build_guest("gdbstub_guest_int3", &[], &["reverie_after_guest_int3"]);
        Int3Guest {
            path,
            after: addresses[0],
        }
    });
    &GUEST
}

/// A guest's own `int3` stops it and is reported to GDB as a SIGTRAP, not as
/// a breakpoint of GDB's, with %rip past the instruction, as natively. GDB's
/// `continue` drops the signal, so the guest runs on and exits 0. Before,
/// Reverie resumed the guest without reporting the trap
/// (https://github.com/rrnewton/hermit/issues/1715).
#[tokio::test]
async fn a_guest_int3_stops_gdb_and_continue_drops_its_signal() {
    let Int3Guest { path, after } = int3_guest();
    debug(path, "guest-int3-continue", |mut remote| async move {
        let stop = remote.resume().await;
        assert!(
            !stop.contains("swbreak"),
            "a guest int3 is not a GDB breakpoint: {stop:?}"
        );
        assert_eq!(stop_rip(&stop), *after, "stopped away from the int3");
        assert_exited_zero(&remote.resume().await, "after continuing past the int3");
    })
    .await;
}

/// GDB's `signal SIGTRAP` passes the guest's trap on, and its default action
/// kills the guest.
#[tokio::test]
async fn a_guest_int3_that_gdb_passes_on_kills_the_guest() {
    let Int3Guest { path, after } = int3_guest();
    let status = debug_to_end(path, "guest-int3-signal", |mut remote| async move {
        let stop = remote.resume().await;
        assert_eq!(stop_rip(&stop), *after, "stopped away from the int3");
        let thread = remote.thread.clone();
        let end = remote.request(&format!("vCont;C05:{thread}")).await;
        // The server reports the death by signal with an `X` packet, whose
        // signal byte carries the core-dump bit when a core was dumped
        // (`X85`); the exit status below names the signal.
        assert!(
            end.starts_with('X'),
            "expected death by a signal, got {end:?}"
        );
    })
    .await;
    assert!(
        matches!(status, ExitStatus::Signaled(reverie::Signal::SIGTRAP, _)),
        "{status:?}"
    );
}

/// A Tool whose signal callback injects `getpid` before it delivers SIGUSR1,
/// so that the thread's latest stop is the injection's, not the signal's.
#[derive(Default)]
struct InjectInSignal;

#[reverie::tool]
impl Tool for InjectInSignal {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_signal_event<G: TracedGuest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        if signal == Signal::SIGUSR1 {
            guest.inject(Getpid::new()).await?;
        }
        Ok(Some(signal))
    }
}

/// As `InjectInSignal`, but the callback first chooses SIGUSR1's siginfo
/// (`Guest::set_signal_info`): `SI_QUEUE` with value 4242.
#[derive(Default)]
struct ReplaceInSignal;

#[reverie::tool]
impl Tool for ReplaceInSignal {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_signal_event<G: TracedGuest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        if signal == Signal::SIGUSR1 {
            // SAFETY: an all-zero siginfo is valid.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            info.si_signo = libc::SIGUSR1;
            info.si_code = libc::SI_QUEUE;
            // SAFETY: both are 128 bytes of plain integers on Linux.
            let mut bytes: [u8; reverie::SIGNAL_INFO_SIZE] = unsafe { std::mem::transmute(info) };
            // `si_value` follows the sender's pid and uid in the queue
            // member, after the three leading ints and their padding.
            bytes[24..28].copy_from_slice(&4242i32.to_ne_bytes());
            guest.set_signal_info(bytes)?;
            guest.inject(Getpid::new()).await?;
        }
        Ok(Some(signal))
    }
}

/// The guest that queues itself SIGUSR1 and checks the siginfo its handler
/// gets.
fn signal_guest() -> &'static Path {
    static GUEST: LazyLock<PathBuf> =
        LazyLock::new(|| build_guest("gdbstub_guest_signal", &[], &[]).0);
    &GUEST
}

/// GDB's `stepi` at a signal stop: SIGUSR1 stops the guest and is reported
/// as `T1e` (gdb's number for it), and GDB steps with it (`vCont;S1e`).
/// The step takes the same resume as a continue, so the handler gets
/// `want`'s siginfo: the signal's own after the callback's injection, or the
/// one the callback chose. Before, a step skipped that resume, and the
/// handler got a siginfo the kernel made up.
async fn step_with_a_signal_keeps_its_siginfo<T>(name: &str, want: &str)
where
    T: Tool + Default + 'static,
    T::GlobalState: Default,
{
    let mut command = Command::new(signal_guest());
    command.arg(want);
    let status = debug_command_to_end::<T, _, _>(command, name, false, |mut remote| async move {
        let stop = remote.resume().await;
        assert!(
            stop.starts_with("T1e"),
            "expected a SIGUSR1 stop, got {stop:?}"
        );
        let thread = remote.thread.clone();
        let stepped = remote.request(&format!("vCont;S1e:{thread}")).await;
        assert!(
            stepped.starts_with("T05"),
            "expected the step's SIGTRAP stop, got {stepped:?}"
        );
        assert_exited_zero(&remote.resume().await, "after stepping into the handler");
    })
    .await;
    assert_eq!(
        status,
        ExitStatus::Exited(0),
        "the handler saw another siginfo"
    );
}

#[tokio::test]
async fn a_step_with_a_signal_keeps_its_own_siginfo_after_an_injection() {
    step_with_a_signal_keeps_its_siginfo::<InjectInSignal>("step-signal-own", "own").await;
}

#[tokio::test]
async fn a_step_with_a_signal_keeps_the_siginfo_the_tool_chose() {
    step_with_a_signal_keeps_its_siginfo::<ReplaceInSignal>("step-signal-tool", "tool").await;
}

/// The interrupt guest and the address of its `reverie_stop_worker` flag.
struct InterruptGuest {
    path: PathBuf,
    stop_worker: u64,
}

fn interrupt_guest() -> &'static InterruptGuest {
    static GUEST: LazyLock<InterruptGuest> = LazyLock::new(|| {
        let (path, addresses) =
            build_guest("gdbstub_interrupt", &["-pthread"], &["reverie_stop_worker"]);
        InterruptGuest {
            path,
            stop_worker: addresses[0],
        }
    });
    &GUEST
}

/// Arms, as the guest's image starts, a write watch on the word at the
/// configured address, and keeps every hit.
#[derive(Default)]
struct WatchStoreTool;

#[derive(Debug, Default)]
struct WatchHits(std::sync::Mutex<Vec<reverie::WatchHit>>);

#[reverie::global_tool]
impl reverie::GlobalTool for WatchHits {
    type Request = ();
    type Response = ();
    /// The watched word's address.
    type Config = u64;

    async fn receive_rpc(&self, _from: reverie::Pid, _request: ()) {}

    fn on_watchpoint_hit(&self, hit: &reverie::WatchHit) {
        self.0.lock().unwrap().push(hit.clone());
    }
}

#[reverie::tool]
impl Tool for WatchStoreTool {
    type GlobalState = WatchHits;
    type ThreadState = ();

    async fn handle_post_exec<G: reverie::Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Errno> {
        let addr = *guest.config();
        guest
            .set_watchpoints(&[reverie::WatchSpec {
                addr,
                len: 8,
                kind: reverie::WatchKind::Write,
                backtraces: 0,
            }])
            .expect("arm the watch");
        Ok(())
    }
}

/// The guest with one store to a watched word, and the addresses around it.
struct WatchedStoreGuest {
    path: PathBuf,
    /// `reverie_before_store`, a nop.
    before: u64,
    /// `reverie_store`, the store.
    store: u64,
    /// `reverie_after_store`, the instruction after it.
    after: u64,
    /// `reverie_watched`, the word.
    word: u64,
}

fn watched_store_guest() -> &'static WatchedStoreGuest {
    static GUEST: LazyLock<WatchedStoreGuest> = LazyLock::new(|| {
        let (path, addresses) = build_guest(
            "gdbstub_watched_store",
            &[],
            &[
                "reverie_before_store",
                "reverie_store",
                "reverie_after_store",
                "reverie_watched",
            ],
        );
        WatchedStoreGuest {
            path,
            before: addresses[0],
            store: addresses[1],
            after: addresses[2],
            word: addresses[3],
        }
    });
    &GUEST
}

/// Waits until process `pid` has one thread left.
async fn wait_for_one_thread(pid: u32) {
    for _ in 0..3000 {
        let threads = std::fs::read_dir(format!("/proc/{pid}/task"))
            .expect("list the guest's threads")
            .count();
        if threads == 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the guest's second thread did not exit");
}

/// Counts the threads that reached the Tool's gate (`GateTool`).
static GATE_REACHED: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(0);
/// Lets threads through the gate.
static GATE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(0);

/// A Tool that holds a thread's getppid() until the test lets it through,
/// as a Tool that runs one thread at a time holds a thread whose turn has not
/// come: the thread waits inside the Tool's callback, and no thread runs.
#[derive(Default)]
struct GateTool;

#[reverie::tool]
impl Tool for GateTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<G: reverie::Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::getppid {
            GATE_REACHED.add_permits(1);
            GATE.acquire()
                .await
                .expect("the gate is never closed")
                .forget();
        }
        guest.tail_inject(syscall).await
    }
}

/// GDB's interrupt stops a guest that never stops on its own, as Ctrl-C does
/// natively, and GDB is told of a SIGINT (`T02`) on the stopped thread. While
/// a thread runs, it stops at its next system call, and GDB can read the
/// registers of the thread that waits inside the Tool. When no thread runs,
/// because the only thread left waits inside the Tool, that thread stops where
/// it waits, and GDB can read memory through it. Each `continue` lets the
/// guest go on as before; the guest exits 0.
#[tokio::test]
async fn an_interrupt_stops_a_running_thread_or_one_that_waits_in_the_tool() {
    let InterruptGuest { path, stop_worker } = interrupt_guest();
    let stop_worker = *stop_worker;
    let status =
        debug_to_end_with::<GateTool, _, _>(path, "interrupt", true, |mut remote| async move {
            let main = remote.thread.clone();
            let stop = remote.resume().await;
            let worker = stop
                .strip_prefix("T05create:")
                .and_then(|rest| rest.split(';').next())
                .unwrap_or_else(|| panic!("expected a thread-creation stop, got {stop:?}"))
                .to_owned();

            // The worker makes system calls while main waits in the Tool.
            remote.resume_in_background().await;
            GATE_REACHED
                .acquire()
                .await
                .expect("the gate count is never closed")
                .forget();
            let stop = remote.interrupt().await;
            assert!(stop.starts_with("T02"), "expected a SIGINT stop: {stop:?}");
            assert_eq!(stop_thread(&stop), worker, "the running thread stops");
            assert_eq!(remote.request(&format!("Hg{main}")).await, "OK");
            let regs = remote.request("g").await;
            assert!(
                !regs.starts_with('E'),
                "the registers of main, which waits in the Tool: {regs:?}"
            );

            // End the worker's loop: then no thread runs.
            assert_eq!(remote.request(&format!("Hg{worker}")).await, "OK");
            assert_eq!(
                remote
                    .request(&format!("M{stop_worker:x},4:01000000"))
                    .await,
                "OK"
            );
            remote.resume_in_background().await;
            // The worker exits within a few system calls.
            wait_for_one_thread(remote.pid).await;
            for interrupt in 0..2 {
                let stop = remote.interrupt().await;
                assert!(
                    stop.starts_with("T02"),
                    "interrupt {interrupt}: expected a SIGINT stop: {stop:?}"
                );
                assert_eq!(stop_thread(&stop), main, "main stops where it waits");
                assert_eq!(
                    remote.request(&format!("m{stop_worker:x},4")).await,
                    "01000000",
                    "memory read through the thread stopped in the Tool"
                );
                remote.resume_in_background().await;
            }
            GATE.add_permits(1);
            assert_exited_zero(&remote.recv().await, "after the gate opened");
        })
        .await;
    assert_eq!(status, ExitStatus::Exited(0));
}

/// Under a Tool that lets threads run at once, the thread that takes GDB's
/// interrupt at its next system call freezes the others, as a breakpoint
/// does; GDB's kill then ends the guest.
#[tokio::test]
async fn an_interrupt_stops_a_guest_whose_threads_run_at_once_and_kill_ends_it() {
    let InterruptGuest { path, .. } = interrupt_guest();
    let status = debug_to_end(path, "interrupt-parallel", |mut remote| async move {
        let stop = remote.resume().await;
        assert!(stop.starts_with("T05create:"), "{stop:?}");
        for interrupt in 0..2 {
            remote.resume_in_background().await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            let stop = remote.interrupt().await;
            assert!(
                stop.starts_with("T02"),
                "interrupt {interrupt}: expected a SIGINT stop: {stop:?}"
            );
            let regs = remote.request("g").await;
            assert!(!regs.starts_with('E'), "{regs:?}");
        }
        let pid = remote.pid;
        assert_eq!(remote.request(&format!("vKill;{pid:x}")).await, "OK");
    })
    .await;
    assert!(
        matches!(status, ExitStatus::Signaled(reverie::Signal::SIGKILL, _)),
        "{status:?}"
    );
}

/// After an interrupt's stop, GDB's step ends at the stopped thread's next
/// stop, and GDB's `signal SIGINT` delivers the signal it was shown, whose
/// default action ends the guest, as natively.
#[tokio::test]
async fn a_step_or_a_signal_from_an_interrupt_stop_is_carried_out() {
    let InterruptGuest { path, .. } = interrupt_guest();
    let status = debug_to_end(path, "interrupt-step", |mut remote| async move {
        let stop = remote.resume().await;
        assert!(stop.starts_with("T05create:"), "{stop:?}");
        remote.resume_in_background().await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let stop = remote.interrupt().await;
        assert!(stop.starts_with("T02"), "{stop:?}");
        let thread = stop_thread(&stop).to_owned();
        let step = remote.request(&format!("vCont;s:{thread}")).await;
        assert!(step.starts_with("T05"), "the step's stop: {step:?}");
        assert_eq!(stop_thread(&step), thread, "the stepped thread stops");

        remote.resume_in_background().await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let stop = remote.interrupt().await;
        assert!(stop.starts_with("T02"), "{stop:?}");
        let thread = stop_thread(&stop).to_owned();
        let end = remote.request(&format!("vCont;C02:{thread}")).await;
        assert!(
            end.starts_with("X02"),
            "the guest dies of the SIGINT gdb passed on, without a second stop: {end:?}"
        );
    })
    .await;
    assert!(
        matches!(status, ExitStatus::Signaled(reverie::Signal::SIGINT, _)),
        "{status:?}"
    );
}

/// A guest whose only thread blocks in the kernel makes no stop of its own.
/// Under a Tool that lets threads run at once, GDB's interrupt stops it all
/// the same, as gdbserver's SIGINT does natively, and `continue` lets it
/// block again: its pause() does not return.
#[tokio::test]
async fn an_interrupt_stops_a_guest_blocked_in_the_kernel() {
    static GUEST: LazyLock<PathBuf> = LazyLock::new(|| build_guest("gdbstub_blocked", &[], &[]).0);
    let status = debug_to_end(&GUEST, "interrupt-blocked", |mut remote| async move {
        for interrupt in 0..2 {
            remote.resume_in_background().await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            let stop = remote.interrupt().await;
            assert!(
                stop.starts_with("T02"),
                "interrupt {interrupt}: expected a SIGINT stop: {stop:?}"
            );
            let regs = remote.request("g").await;
            assert!(!regs.starts_with('E'), "{regs:?}");
        }
        let pid = remote.pid;
        assert_eq!(remote.request(&format!("vKill;{pid:x}")).await, "OK");
    })
    .await;
    assert!(
        matches!(status, ExitStatus::Signaled(reverie::Signal::SIGKILL, _)),
        "{status:?}"
    );
}

/// A Tool that runs every system call the guest makes as its own injection,
/// as Detcore runs many: a fork, a vfork or an exec then happens inside the
/// Tool's callback.
#[derive(Default)]
struct InjectTool;

#[reverie::tool]
impl Tool for InjectTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<G: reverie::Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        Ok(guest.inject(syscall).await?)
    }
}

/// The fork-events guest and the address of `in_child`.
struct ForkGuest {
    path: PathBuf,
    in_child: u64,
}

fn fork_guest() -> &'static ForkGuest {
    static GUEST: LazyLock<ForkGuest> = LazyLock::new(|| {
        let (path, addresses) = build_guest("gdbstub_fork_events", &[], &["in_child"]);
        ForkGuest {
            path,
            in_child: addresses[0],
        }
    });
    &GUEST
}

/// GDB's features less the optional stop events.
const NO_EVENTS: &str = "multiprocess+;swbreak+;hwbreak+;vContSupported+;QThreadEvents+";

/// A client that follows no forks is told of none ("General Query Packets",
/// `qSupported`): the guest's vforks and fork run as if no client were
/// there. Its children run through the breakpoint the client set before
/// they were made, which a fork child carries in its copy of the memory and
/// a vfork child shares, and the breakpoint still stops the parent.
async fn a_client_that_follows_no_forks_sees_none<T>(name: &str)
where
    T: Tool + Default + 'static,
    T::GlobalState: Default,
{
    let ForkGuest { path, in_child } = fork_guest();
    let in_child = *in_child;
    let status = debug_to_end_with::<T, _, _>(path, name, false, |mut remote| async move {
        remote.supported(NO_EVENTS).await;
        remote.insert(in_child).await;
        let main = remote.thread.clone();
        let stop = remote.resume().await;
        assert!(
            stop.starts_with("T05swbreak:"),
            "the parent's own call, and no fork stop, comes first: {stop:?}"
        );
        assert_eq!(stop_thread(&stop), main);
        assert_eq!(stop_rip(&stop), in_child);
        remote.remove(in_child).await;
        assert_exited_zero(&remote.resume().await, "after the parent's breakpoint");
    })
    .await;
    assert_eq!(
        status,
        ExitStatus::Exited(0),
        "every child exited as expected"
    );
}

#[tokio::test]
async fn a_client_that_follows_no_forks_sees_none_and_its_breakpoint_stays_in_the_parent() {
    a_client_that_follows_no_forks_sees_none::<NoopTool>("no-forks").await;
}

#[tokio::test]
async fn a_client_that_follows_no_forks_sees_none_of_those_a_tool_injects() {
    a_client_that_follows_no_forks_sees_none::<InjectTool>("no-forks-injected").await;
}

/// A client that follows vforks, and not forks, is told of each vfork and,
/// once it has let the child go, of the parent's return from it
/// (`vforkdone`), which it waits for before it reports another fork: GDB
/// fails an internal assertion otherwise. The fork is not reported.
async fn a_client_that_follows_vforks_is_told_when_each_is_done<T>(name: &str)
where
    T: Tool + Default + 'static,
    T::GlobalState: Default,
{
    let ForkGuest { path, .. } = fork_guest();
    let status = debug_to_end_with::<T, _, _>(path, name, false, |mut remote| async move {
        remote
            .supported(&format!("{NO_EVENTS};vfork-events+"))
            .await;
        let main = remote.thread.clone();
        let mut stop = remote.resume().await;
        for vfork in 0..2 {
            let child = stop
                .strip_prefix("T05vfork:")
                .and_then(|rest| rest.split(';').next())
                .unwrap_or_else(|| panic!("vfork {vfork}: expected a vfork stop: {stop:?}"))
                .to_owned();
            assert_eq!(stop_thread(&stop), main);
            let pid = child
                .strip_prefix('p')
                .and_then(|id| id.split('.').next())
                .expect("the child's process");
            assert_eq!(remote.request(&format!("D;{pid}")).await, "OK");
            let done = remote.request(&format!("vCont;c:{main}")).await;
            assert!(
                done.starts_with("T05vforkdone:"),
                "vfork {vfork}: expected the parent's vforkdone: {done:?}"
            );
            assert_eq!(stop_thread(&done), main);
            stop = remote.resume().await;
        }
        assert_exited_zero(&stop, "the fork is not reported");
    })
    .await;
    assert_eq!(
        status,
        ExitStatus::Exited(0),
        "every child exited as expected"
    );
}

#[tokio::test]
async fn a_client_that_follows_vforks_is_told_when_each_vfork_is_done() {
    a_client_that_follows_vforks_is_told_when_each_is_done::<NoopTool>("vforks").await;
}

#[tokio::test]
async fn a_client_that_follows_vforks_is_told_when_each_injected_one_is_done() {
    a_client_that_follows_vforks_is_told_when_each_is_done::<InjectTool>("vforks-injected").await;
}

/// A client that follows forks, and not vforks, is told of the fork with
/// a `fork` stop naming the child, which it detaches; the vforks are not
/// reported. Nothing here yet observes the guest's `vforkdone` after a
/// vfork injected from a signal callback.
#[tokio::test]
async fn a_client_that_follows_forks_is_told_of_the_fork() {
    let ForkGuest { path, .. } = fork_guest();
    let status = debug_to_end(path, "fork-events", |mut remote| async move {
        remote.supported(&format!("{NO_EVENTS};fork-events+")).await;
        let main = remote.thread.clone();
        let stop = remote.resume().await;
        let child = stop
            .strip_prefix("T05fork:")
            .and_then(|rest| rest.split(';').next())
            .unwrap_or_else(|| panic!("expected a fork stop: {stop:?}"))
            .to_owned();
        assert_eq!(stop_thread(&stop), main);
        let pid = child
            .strip_prefix('p')
            .and_then(|id| id.split('.').next())
            .expect("the child's process");
        assert_eq!(remote.request(&format!("D;{pid}")).await, "OK");
        assert_exited_zero(&remote.resume().await, "after the fork");
    })
    .await;
    assert_eq!(
        status,
        ExitStatus::Exited(0),
        "every child exited as expected"
    );
}

/// An exec is reported as an `exec` stop only to a client that follows
/// execs; to another it is the trap that stops the thread after an exec
/// natively, when the tracer does not ask Linux for exec events.
#[tokio::test]
async fn an_exec_is_reported_as_one_only_to_a_client_that_follows_execs() {
    static GUEST: LazyLock<PathBuf> = LazyLock::new(|| build_guest("gdbstub_exec", &[], &[]).0);
    for follows in [false, true] {
        let features = if follows {
            format!("{NO_EVENTS};exec-events+")
        } else {
            NO_EVENTS.to_owned()
        };
        let name = if follows {
            "exec-events"
        } else {
            "no-exec-events"
        };
        let status = debug_to_end(&GUEST, name, |mut remote| async move {
            remote.supported(&features).await;
            let stop = remote.resume().await;
            assert!(stop.starts_with("T05"), "{stop:?}");
            assert_eq!(
                stop.contains("exec:"),
                follows,
                "the exec's stop as a client that follows execs: {follows}: {stop:?}"
            );
            assert_exited_zero(&remote.resume().await, "after the exec");
        })
        .await;
        assert_eq!(status, ExitStatus::Exited(0));
    }
}

/// A breakpoint the client inserts while a vfork child it was told of lives,
/// through the parent, is in the memory the child shares and in the child's
/// breakpoints too. Once the client has let the child go without removing it
/// (GDB removes its breakpoints first; the protocol does not require it), the
/// child runs through it, and it still stops the parent.
#[tokio::test]
async fn a_breakpoint_inserted_while_a_vfork_child_lives_is_the_childs_too() {
    let ForkGuest { path, in_child } = fork_guest();
    let in_child = *in_child;
    let status = debug_to_end(path, "vfork-insert", |mut remote| async move {
        remote
            .supported(&format!("{NO_EVENTS};vfork-events+"))
            .await;
        let main = remote.thread.clone();
        let mut stop = remote.resume().await;
        for vfork in 0..2 {
            let child = stop
                .strip_prefix("T05vfork:p")
                .and_then(|rest| rest.split('.').next())
                .unwrap_or_else(|| panic!("vfork {vfork}: expected a vfork stop: {stop:?}"))
                .to_owned();
            if vfork == 0 {
                remote.insert(in_child).await;
            }
            assert_eq!(remote.request(&format!("D;{child}")).await, "OK");
            let done = remote.request(&format!("vCont;c:{main}")).await;
            assert!(done.starts_with("T05vforkdone:"), "{done:?}");
            stop = remote.resume().await;
        }
        assert!(
            stop.starts_with("T05swbreak:"),
            "the children ran through the breakpoint, which stops the parent: {stop:?}"
        );
        assert_eq!(stop_thread(&stop), main);
        assert_eq!(stop_rip(&stop), in_child);
        remote.remove(in_child).await;
        assert_exited_zero(&remote.resume().await, "after the parent's breakpoint");
    })
    .await;
    assert_eq!(
        status,
        ExitStatus::Exited(0),
        "every child exited as expected"
    );
}

/// Runs the watched-store guest under Reverie's GDB server with a write watch
/// on its word, with `client` as GDB; checks that it exits 0 and returns the
/// hits.
async fn debug_watched<F, Fut>(name: &str, client: F) -> Vec<reverie::WatchHit>
where
    F: FnOnce(Remote) -> Fut,
    Fut: Future<Output = ()>,
{
    let guest = watched_store_guest();
    let socket = std::env::temp_dir().join(format!(
        "reverie-gdbstub-{name}-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket);
    let command = Command::new(&guest.path);
    let tracer = async {
        TracerBuilder::<WatchStoreTool>::new(command)
            .config(guest.word)
            .gdbserver(socket.clone())
            .spawn()
            .await
            .expect("spawn the guest under the GDB server")
            .wait()
            .await
            .expect("wait for the guest")
    };
    let gdb = async {
        let remote = Remote::connect(&socket).await;
        client(remote).await;
    };
    let ((status, hits), ()) = tokio::time::timeout(Duration::from_secs(120), async {
        tokio::join!(tracer, gdb)
    })
    .await
    .expect("the guest and the GDB session finish");
    let _ = std::fs::remove_file(&socket);
    assert_eq!(status, ExitStatus::Exited(0));
    hits.0.into_inner().unwrap()
}

/// GDB's step over a breakpoint on a store to a watched word: the server
/// removes nothing itself, GDB removes the breakpoint, and the server's
/// step-over runs the store. Its hit comes with the step's trap, and is
/// reported once, at the instruction after the store.
#[tokio::test]
async fn a_step_over_a_breakpoint_on_a_watched_store_reports_the_hit() {
    let WatchedStoreGuest { store, after, .. } = *watched_store_guest();
    let hits = debug_watched("watched-step-over", |mut remote| async move {
        remote.insert(store).await;
        let stop = remote.resume().await;
        assert!(stop.starts_with("T05swbreak:"), "{stop:?}");
        assert_eq!(stop_rip(&stop), store);
        remote.remove(store).await;
        let stop = remote.step().await;
        assert_eq!(stop_rip(&stop), after, "the step did not run the store");
        assert_exited_zero(&remote.resume().await, "after the step");
    })
    .await;
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].ip, after);
    assert_eq!(hits[0].sigtrap, reverie::SigtrapAtHit::Unchanged);
}

/// A plain GDB single step, not over a breakpoint, that runs a store to a
/// watched word: the step's stop is handled as any SIGTRAP of a stepped
/// thread, and the hit is reported once.
#[tokio::test]
async fn a_debugger_step_over_a_watched_store_reports_the_hit() {
    let WatchedStoreGuest {
        before,
        store,
        after,
        ..
    } = *watched_store_guest();
    let hits = debug_watched("watched-step", |mut remote| async move {
        remote.insert(before).await;
        let stop = remote.resume().await;
        assert_eq!(stop_rip(&stop), before);
        remote.remove(before).await;
        // Over the breakpoint's nop, then over the store.
        assert_eq!(stop_rip(&remote.step().await), store);
        assert_eq!(stop_rip(&remote.step().await), after);
        assert_exited_zero(&remote.resume().await, "after the steps");
    })
    .await;
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].ip, after);
    assert_eq!(hits[0].sigtrap, reverie::SigtrapAtHit::Unchanged);
}
