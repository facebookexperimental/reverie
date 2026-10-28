/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A socket the coordinator hands the in-guest tool for its own output, such
//! as Hermit's ordered DETLOG record socket.
//!
//! The coordinator passes the descriptor number in [`TOOL_OUTPUT_ENV`], with
//! the socket's identity ([`tool_output_env_value`]). The plugin takes the
//! variable out of the guest's environment, adopts the descriptor only if it
//! is still that socket (guest code that runs before the plugin, such as an
//! executable's `.preinit_array`, may have closed it and put a socket of its
//! own at that number), and moves the
//! socket to the lowest free number at or above [`TOOL_OUTPUT_FD_MIN`], above
//! the default soft `RLIMIT_NOFILE`, so a guest that never raises its limit
//! cannot name it at all. It then keeps the guest away from it in this process
//! and in every process forked from it, as from the plugin's other protected
//! descriptors: a guest `close` or `close_range` spares it, and any other
//! descriptor operation on it fails with `EBADF`. A guest `dup2`/`dup3` onto
//! its number succeeds as it would on a free number: the plugin first moves
//! the socket to another free number at or above [`TOOL_OUTPUT_FD_MIN`]
//! ([`before_guest_dup_onto`]). Tool code reaches the socket only through
//! [`with_tool_output`], which a move waits for, and which blocks signals from
//! its check that the number still names the socket until the tool's write
//! returns, so no signal handler the plugin does not mediate can replace the
//! socket in between.
//!
//! The socket stays open across a loader-mediated execve, and the plugin hands
//! the new image its current number in [`TOOL_OUTPUT_ENV`]
//! ([`exec_env_entry`]), so the new image's tool keeps writing to it.
//!
//! When a move finds no free number (the descriptor table is full), the plugin
//! gives the socket up so the guest's call keeps its native outcome: it sends
//! the message the tool chose with [`set_retirement_message`], closes the
//! socket, and [`with_tool_output`] then returns `None`.

use std::ffi::CString;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;

use crate::paths;
use crate::protected_files;

/// The private variable holding the tool-output descriptor number and the
/// socket's identity ([`tool_output_env_value`]).
pub const TOOL_OUTPUT_ENV: &str = "REVERIE_SABRE_TOOL_OUTPUT_FD";

/// The [`TOOL_OUTPUT_ENV`] value for socket `fd` whose `fstat` gives
/// `st_dev` `dev` and `st_ino` `ino`: `<fd>:<dev>:<ino>`, the identity in
/// 16 hexadecimal digits each, so the value's length (which the scrubbed
/// environment block keeps) does not depend on the host.
pub fn tool_output_env_value(fd: RawFd, dev: u64, ino: u64) -> String {
    format!("{fd}:{dev:016x}:{ino:016x}")
}

/// The descriptor and identity a [`TOOL_OUTPUT_ENV`] value names.
fn parse_tool_output_env_value(value: &[u8]) -> Option<(RawFd, (u64, u64))> {
    let value = std::str::from_utf8(value).ok()?;
    let mut fields = value.split(':');
    let fd = fields.next()?.parse::<RawFd>().ok()?;
    let hex = |field: Option<&str>| {
        field
            .filter(|field| field.len() == 16)
            .and_then(|field| u64::from_str_radix(field, 16).ok())
    };
    let dev = hex(fields.next())?;
    let ino = hex(fields.next())?;
    fields.next().is_none().then_some((fd, (dev, ino)))
}

/// The lowest number the tool-output socket takes, the range in-guest
/// LiteInst's tool output uses.
pub const TOOL_OUTPUT_FD_MIN: RawFd = 1025;

/// The socket's current number, or -1.
static TOOL_OUTPUT: AtomicI32 = AtomicI32::new(-1);
/// The adopted socket's identity (`st_dev`, `st_ino`): a send checks it, so a
/// number that no longer names the socket in this process's descriptor table
/// is never written to.
static IDENTITY_DEV: AtomicU64 = AtomicU64::new(0);
static IDENTITY_INO: AtomicU64 = AtomicU64::new(0);
/// Tool sends in progress in process [`IN_FLIGHT_PID`]; a move waits for them
/// (see [`with_tool_output`]).
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static IN_FLIGHT_PID: AtomicI32 = AtomicI32::new(0);
/// A process that shares this memory but not the descriptor table the socket
/// number refers to (a `CLONE_VM` child without `CLONE_FILES`, such as a
/// vfork child) after a guest dup onto that number replaced its copy: it no
/// longer sends. -1 when none.
static DETACHED_PID: AtomicI32 = AtomicI32::new(-1);
static INITIALIZED: OnceLock<()> = OnceLock::new();
/// The coordinator passed a socket (its variable was set), whether or not it
/// could be adopted ([`tool_output_requested`]).
static REQUESTED: AtomicBool = AtomicBool::new(false);
static RETIREMENT: OnceLock<&'static [u8]> = OnceLock::new();

/// Adopts the socket the coordinator passed, once per process image, on first
/// use. Not at plugin initialization: the loader calls the plugin before the
/// client's libc has set up its environment, where the variable is not yet
/// visible. The tool's first use comes from the first intercepted syscall,
/// before any guest code runs. A forked child inherits the adoption.
fn init_tool_output() {
    INITIALIZED.get_or_init(|| {
        if let Some((fd, (dev, ino))) = adopt() {
            IDENTITY_DEV.store(dev, SeqCst);
            IDENTITY_INO.store(ino, SeqCst);
            IN_FLIGHT_PID.store(getpid(), SeqCst);
            TOOL_OUTPUT.store(fd, SeqCst);
        }
    });
}

fn getpid() -> libc::pid_t {
    // SAFETY: getpid has no preconditions.
    unsafe { libc::getpid() }
}

/// `F_DUPFD` at or above [`TOOL_OUTPUT_FD_MIN`]. When the host's soft
/// `RLIMIT_NOFILE` is at or below that number (`EINVAL`), raises the soft limit
/// toward the hard one and retries: the guest's own limit is Detcore's virtual
/// one, so it does not change.
fn dup_reserved(fd: RawFd) -> RawFd {
    // SAFETY: F_DUPFD duplicates a descriptor this process owns; the copy is
    // left open across exec.
    let moved = unsafe { libc::fcntl(fd, libc::F_DUPFD, TOOL_OUTPUT_FD_MIN) };
    if moved >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
        return moved;
    }
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit and setrlimit read and write `limit` only.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return -1;
        }
        let wanted = (TOOL_OUTPUT_FD_MIN as libc::rlim_t + 64).min(limit.rlim_max);
        if wanted <= limit.rlim_cur {
            return -1;
        }
        limit.rlim_cur = wanted;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
            return -1;
        }
        libc::fcntl(fd, libc::F_DUPFD, TOOL_OUTPUT_FD_MIN)
    }
}

fn socket_identity(fd: RawFd) -> Option<(u64, u64)> {
    // SAFETY: fstat writes only into `metadata`.
    let mut metadata: libc::stat = unsafe { core::mem::zeroed() };
    let status = unsafe { libc::fstat(fd, &raw mut metadata) };
    (status == 0 && metadata.st_mode & libc::S_IFMT == libc::S_IFSOCK)
        .then_some((metadata.st_dev, metadata.st_ino))
}

/// Whether process `a` and `b` share `kind` (`KCMP_VM`, `KCMP_FILES`). An
/// unanswerable question (kcmp unavailable) is answered "no".
fn shares(a: libc::pid_t, b: libc::pid_t, kind: libc::c_int) -> bool {
    a == b || unsafe { libc::syscall(libc::SYS_kcmp, a, b, kind, 0, 0) } == 0
}

/// Makes [`IN_FLIGHT`] count this process's sends. A forked child that does
/// not share this memory starts with a copy of its parent's count, whose
/// senders do not exist in the child, so it resets the count; it is still
/// single-threaded when it first gets here.
fn own_in_flight_count() {
    let pid = getpid();
    let owner = IN_FLIGHT_PID.load(SeqCst);
    if owner != pid && !shares(owner, pid, KCMP_VM) {
        IN_FLIGHT.store(0, SeqCst);
        IN_FLIGHT_PID.store(pid, SeqCst);
    }
}

const KCMP_VM: libc::c_int = 1;
const KCMP_FILES: libc::c_int = 2;

/// The adopted socket's number and the identity the coordinator passed for it.
fn adopt() -> Option<(RawFd, (u64, u64))> {
    paths::private_env(TOOL_OUTPUT_ENV)?;
    REQUESTED.store(true, SeqCst);
    paths::cache_tool_env();
    // SAFETY: plugin initialization runs before guest threads exist.
    let value = unsafe { paths::take_private_env(TOOL_OUTPUT_ENV) }?;
    let (fd, identity) = parse_tool_output_env_value(value.as_os_str().as_bytes())?;
    // No signal handler (one the guest installed before the plugin ran, or
    // one that runs plugin-native) can replace the number between the checks
    // and the protection below.
    let blocked = block_signals();
    let adopted = adopt_checked(fd, identity);
    restore_signals(&blocked);
    adopted.map(|fd| (fd, identity))
}

/// Adopts `fd` only if it, and the reserved copy of it, are the socket with
/// `identity`: a number that is no longer the coordinator's socket (closed, or
/// replaced by one of the guest's own) would send the tool's records to the
/// guest.
fn adopt_checked(fd: RawFd, identity: (u64, u64)) -> Option<RawFd> {
    if socket_identity(fd) != Some(identity) {
        return None;
    }
    #[cfg(test)]
    if let Some(hook) = *tests::ADOPTION_WINDOW.lock().unwrap() {
        hook(fd);
    }
    if fd >= TOOL_OUTPUT_FD_MIN {
        // A new image of a guest whose earlier image already moved it.
        protected_files::protect_inherited_raw_fd(fd);
        return Some(fd);
    }
    let moved = dup_reserved(fd);
    if moved < 0 {
        return None;
    }
    // The copy is what is kept, so it is what must be the socket.
    if socket_identity(moved) != Some(identity) {
        // SAFETY: `moved` is this function's own duplicate.
        unsafe { libc::close(moved) };
        return None;
    }
    protected_files::protect_inherited_raw_fd(moved);
    // SAFETY: the original number is no longer used.
    unsafe { libc::close(fd) };
    Some(moved)
}

/// The tool-output socket's current number, if the coordinator passed one and
/// it was not given up. Tool code must write through [`with_tool_output`]
/// instead: the number changes when the guest duplicates onto it.
pub fn tool_output_fd() -> Option<RawFd> {
    init_tool_output();
    let fd = TOOL_OUTPUT.load(SeqCst);
    (fd >= 0).then_some(fd)
}

/// Whether the coordinator passed a tool-output socket, adopted or not. A tool
/// whose socket was requested but is unavailable (closed or replaced before
/// adoption, or given up) must not fall back to another output the guest
/// owns, such as its standard error.
pub fn tool_output_requested() -> bool {
    init_tool_output();
    REQUESTED.load(SeqCst)
}

/// Runs `f` with the tool-output socket's number, which no move or retirement
/// changes until `f` returns. Returns `None` without calling `f` when there is
/// no socket.
pub fn with_tool_output<R>(f: impl FnOnce(RawFd) -> R) -> Option<R> {
    init_tool_output();
    own_in_flight_count();
    IN_FLIGHT.fetch_add(1, SeqCst);
    // A handler the plugin does not mediate (one that runs plugin-native)
    // could otherwise dup another socket onto the number after the check and
    // before `f` writes.
    let blocked = block_signals();
    let result = tool_output_fd()
        .filter(|&fd| getpid() != DETACHED_PID.load(SeqCst) && names_the_socket(fd))
        .map(f);
    restore_signals(&blocked);
    IN_FLIGHT.fetch_sub(1, SeqCst);
    result
}

/// Blocks every signal the kernel lets this thread block and returns the mask
/// it replaced.
fn block_signals() -> libc::sigset_t {
    // SAFETY: sigfillset and rt_sigprocmask write only the given sets; the
    // kernel's sigset is 8 bytes on Linux.
    unsafe {
        let mut all: libc::sigset_t = core::mem::zeroed();
        let mut previous: libc::sigset_t = core::mem::zeroed();
        libc::sigfillset(&mut all);
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_BLOCK,
            &all as *const libc::sigset_t,
            &mut previous as *mut libc::sigset_t,
            8usize,
        );
        previous
    }
}

fn restore_signals(previous: &libc::sigset_t) {
    // SAFETY: rt_sigprocmask reads only the given set.
    unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            previous as *const libc::sigset_t,
            core::ptr::null_mut::<libc::sigset_t>(),
            8usize,
        );
    }
}

/// Whether `fd` still names the adopted socket in this process's descriptor
/// table. It does not when another process that shares this memory but has
/// its own table moved the socket there.
fn names_the_socket(fd: RawFd) -> bool {
    socket_identity(fd) == Some((IDENTITY_DEV.load(SeqCst), IDENTITY_INO.load(SeqCst)))
}

/// The message sent on the socket if the plugin ever has to give it up (see
/// the module documentation). The tool chooses one its reader treats as
/// "output incomplete".
pub fn set_retirement_message(message: &'static [u8]) {
    let _ = RETIREMENT.set(message);
}

/// What a guest `dup2`/`dup3` onto a descriptor needs, decided by
/// [`before_guest_dup_onto`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GuestDup {
    /// The call does not target the tool-output socket, or targets it from a
    /// protected source; the descriptor guards decide it.
    Unaffected,
    /// The socket moved; the call runs with the outcome it has on a free
    /// number.
    Moved,
    /// The kernel fails the call without touching the target (a source that is
    /// not open, invalid `dup3` flags), or the caller's descriptor table is
    /// not the one the socket number refers to; run it as it is.
    Native,
}

/// Whether the kernel refuses `dup3`'s `flags` with `EINVAL`. The kernel takes
/// them as a 32-bit `int`, so bits above 31 of the register are ignored, not
/// refused: `dup3(1, fd, 1 << 32)` succeeds with no flags.
fn dup3_flags_are_invalid(flags: usize) -> bool {
    (flags as u32) & !(libc::O_CLOEXEC as u32) != 0
}

/// Called before a guest `dup2`/`dup3` (`flags` is 0 for `dup2`) from `source`
/// onto `target` runs. If `target` is the tool-output socket and the call will
/// succeed, moves the socket to another free number at or above
/// [`TOOL_OUTPUT_FD_MIN`], or gives it up when there is none, so the call runs
/// with the outcome it has on a free number. A call the kernel fails is left
/// alone, so the socket keeps its number and its protection.
pub(crate) fn before_guest_dup_onto(source: RawFd, target: RawFd, flags: usize) -> GuestDup {
    init_tool_output();
    own_in_flight_count();
    let current = TOOL_OUTPUT.load(SeqCst);
    if current < 0 || target != current || source == target {
        return GuestDup::Unaffected;
    }
    if protected_files::is_protected(&source) {
        return GuestDup::Unaffected;
    }
    // SAFETY: F_GETFD only reads the descriptor's flags.
    if dup3_flags_are_invalid(flags) || unsafe { libc::fcntl(source, libc::F_GETFD) } < 0 {
        return GuestDup::Native;
    }
    // From the check that the number still names the socket until the move or
    // the retirement message is done, no signal handler can replace it.
    let blocked = block_signals();
    let outcome = move_before_guest_dup(current);
    restore_signals(&blocked);
    outcome
}

fn move_before_guest_dup(current: RawFd) -> GuestDup {
    let pid = getpid();
    let owner = IN_FLIGHT_PID.load(SeqCst);
    if !names_the_socket(current) {
        // Another process sharing this descriptor table (CLONE_FILES without
        // CLONE_VM) moved the socket, or something replaced the number: it is
        // not the socket here, so neither move nor retire it (either would
        // write to whatever is there). Stop this process sending (only this
        // one, when it shares the memory with the owner), unprotect the
        // number, and let the guest's call replace it. Its records are then
        // counted and missing, so the run is refused.
        protected_files::unprotect_inherited_raw_fd(current);
        if owner != pid && shares(owner, pid, KCMP_VM) {
            DETACHED_PID.store(pid, SeqCst);
        } else {
            TOOL_OUTPUT.store(-1, SeqCst);
        }
        return GuestDup::Native;
    }
    if owner != pid && shares(owner, pid, KCMP_VM) && !shares(owner, pid, KCMP_FILES) {
        // A vfork-style child with its own copy of the table: moving the socket
        // here would change the number its parent's table does not have. Let
        // the call replace this copy, and stop this process sending.
        protected_files::unprotect_raw_fd(current);
        DETACHED_PID.store(pid, SeqCst);
        return GuestDup::Native;
    }
    let moved = dup_reserved(current);
    if moved >= 0 {
        protected_files::protect_inherited_raw_fd(moved);
        TOOL_OUTPUT.store(moved, SeqCst);
    } else {
        TOOL_OUTPUT.store(-1, SeqCst);
    }
    // A send that read the old number before the store finishes before the
    // guest's call can replace that number.
    while IN_FLIGHT.load(SeqCst) != 0 {
        std::hint::spin_loop();
    }
    protected_files::unprotect_inherited_raw_fd(current);
    if moved < 0 {
        if let Some(message) = RETIREMENT.get() {
            send_all(current, message);
        }
        // SAFETY: the guest's call is about to take this number.
        unsafe { libc::close(current) };
    }
    // Otherwise the guest's dup2/dup3 closes the old number itself.
    GuestDup::Moved
}

fn send_all(fd: RawFd, mut message: &[u8]) {
    while !message.is_empty() {
        // SAFETY: sends from a live buffer of the given length.
        let sent = unsafe {
            libc::send(
                fd,
                message.as_ptr().cast(),
                message.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        message = &message[sent as usize..];
    }
}

/// The `TOOL_OUTPUT_ENV` entry for a loader-mediated execve: the socket's
/// current number, or nothing once it was given up.
pub(crate) fn exec_env_entry() -> Option<CString> {
    // A socket that was requested and is gone is handed on as -1, so the new
    // image knows one was requested ([`tool_output_requested`]).
    let value = match tool_output_fd() {
        Some(fd) => tool_output_env_value(fd, IDENTITY_DEV.load(SeqCst), IDENTITY_INO.load(SeqCst)),
        None if tool_output_requested() => "-1".to_owned(),
        None => return None,
    };
    Some(CString::new(format!("{TOOL_OUTPUT_ENV}={value}")).expect("a number has no NUL"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket_pair() -> (RawFd, RawFd) {
        let mut fds = [0; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) },
            0
        );
        (fds[0], fds[1])
    }

    #[test]
    fn dup3_flags_are_checked_at_the_kernels_width() {
        assert!(!dup3_flags_are_invalid(0));
        assert!(!dup3_flags_are_invalid(libc::O_CLOEXEC as usize));
        assert!(!dup3_flags_are_invalid(1 << 32));
        assert!(dup3_flags_are_invalid(0x1234));
        assert!(dup3_flags_are_invalid((1 << 32) | 0x1234));
    }

    /// Runs `check` in a forked child and requires it to return true.
    fn in_child(check: impl FnOnce() -> bool) {
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let ok = check();
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child status {status:#x}"
        );
    }

    fn receive(fd: RawFd) -> Vec<u8> {
        let mut buffer = [0u8; 256];
        let count = unsafe { libc::recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        assert!(count >= 0);
        buffer[..count as usize].to_vec()
    }

    fn env_value(fd: RawFd) -> String {
        let (dev, ino) = socket_identity(fd).unwrap();
        tool_output_env_value(fd, dev, ino)
    }

    #[test]
    fn the_env_value_is_fixed_width_and_round_trips() {
        let value = tool_output_env_value(7, 0x1d, 0x1234_5678);
        assert_eq!(value, "7:000000000000001d:0000000012345678");
        assert_eq!(
            parse_tool_output_env_value(value.as_bytes()),
            Some((7, (0x1d, 0x1234_5678)))
        );
        for bad in [
            "7",
            "7:1d:12345678",
            "7:000000000000001d",
            "x:000000000000001d:0000000012345678",
            "7:000000000000001d:0000000012345678:0",
        ] {
            assert_eq!(parse_tool_output_env_value(bad.as_bytes()), None, "{bad}");
        }
    }

    /// Runs inside adoption, between the identity check and the reservation:
    /// what a signal handler would do there if one could run.
    pub(super) static ADOPTION_WINDOW: std::sync::Mutex<Option<fn(RawFd)>> =
        std::sync::Mutex::new(None);
    static HANDLER_RAN: AtomicBool = AtomicBool::new(false);

    /// No signal handler runs inside adoption (signals are blocked), and if
    /// one had replaced the number there, the reserved copy would not be the
    /// passed socket and is refused. Fresh processes: adoption happens once.
    #[test]
    fn adoption_survives_a_signal_and_refuses_a_replacement_inside_its_window() {
        const CHILD: &str = "REVERIE_SABRE_TOOL_OUTPUT_TEST_WINDOW";
        let name = "tool_output::tests::adoption_survives_a_signal_and_refuses_a_replacement_inside_its_window";
        match std::env::var(CHILD).as_deref() {
            Err(_) => {
                for mode in ["signal", "replace"] {
                    let status = std::process::Command::new(std::env::current_exe().unwrap())
                        .args(["--exact", name])
                        .env(CHILD, mode)
                        .status()
                        .unwrap();
                    assert!(status.success(), "{mode} child failed with {status}");
                }
            }
            Ok("signal") => {
                extern "C" fn record(_: libc::c_int) {
                    HANDLER_RAN.store(true, SeqCst);
                }
                unsafe { libc::signal(libc::SIGUSR1, record as *const () as libc::sighandler_t) };
                *ADOPTION_WINDOW.lock().unwrap() = Some(|_| {
                    unsafe { libc::raise(libc::SIGUSR1) };
                    assert!(!HANDLER_RAN.load(SeqCst), "a handler ran inside adoption");
                });
                let (passed, _peer) = socket_pair();
                unsafe { std::env::set_var(TOOL_OUTPUT_ENV, env_value(passed)) };
                assert!(tool_output_fd().is_some(), "the passed socket is adopted");
                assert!(
                    HANDLER_RAN.load(SeqCst),
                    "the signal is delivered after adoption"
                );
            }
            Ok("replace") => {
                *ADOPTION_WINDOW.lock().unwrap() = Some(|fd| {
                    let (guests, _) = socket_pair();
                    assert_eq!(unsafe { libc::dup2(guests, fd) }, fd);
                });
                let (passed, _peer) = socket_pair();
                unsafe { std::env::set_var(TOOL_OUTPUT_ENV, env_value(passed)) };
                assert_eq!(tool_output_fd(), None, "a replaced number is not adopted");
                assert!(tool_output_requested());
            }
            Ok(other) => panic!("unknown mode {other}"),
        }
    }

    /// Guest code that runs before the plugin (an executable's
    /// `.preinit_array`) closed the passed socket and put a socket of its own
    /// at that number: it is not adopted, nothing is written to it, and the
    /// socket still counts as requested. Run in a fresh process, since
    /// adoption happens once per process.
    #[test]
    fn a_socket_the_guest_put_at_the_passed_number_is_not_adopted() {
        const CHILD: &str = "REVERIE_SABRE_TOOL_OUTPUT_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tool_output::tests::a_socket_the_guest_put_at_the_passed_number_is_not_adopted"])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success(), "child test failed with {status}");
            return;
        }
        let (passed, _passed_peer) = socket_pair();
        let value = env_value(passed);
        unsafe { libc::close(passed) };
        let (guests, guests_peer) = socket_pair();
        assert_eq!(unsafe { libc::dup2(guests, passed) }, passed);
        unsafe { std::env::set_var(TOOL_OUTPUT_ENV, value) };
        assert_eq!(tool_output_fd(), None);
        assert!(tool_output_requested());
        assert_eq!(with_tool_output(|fd| send_all(fd, b"record")), None);
        assert_eq!(
            exec_env_entry().unwrap().to_bytes(),
            format!("{TOOL_OUTPUT_ENV}=-1").as_bytes()
        );
        unsafe { libc::fcntl(guests_peer, libc::F_SETFL, libc::O_NONBLOCK) };
        let mut buffer = [0u8; 64];
        let read = unsafe { libc::recv(guests_peer, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        assert_eq!(read, -1, "the guest's socket received a tool record");
    }

    /// One test, because the socket's state is process-wide, run in a fresh
    /// process: it moves, replaces and closes descriptors, which other tests
    /// in the same process (the Tokio runtimes of the adapter tests) must not
    /// share.
    #[test]
    fn a_guest_dup_onto_the_socket_moves_it_and_exec_hands_on_its_number() {
        const CHILD: &str = "REVERIE_SABRE_TOOL_OUTPUT_TEST_MOVES";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tool_output::tests::a_guest_dup_onto_the_socket_moves_it_and_exec_hands_on_its_number",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success(), "child test failed with {status}");
            return;
        }
        let (sender, receiver) = socket_pair();
        unsafe { std::env::set_var(TOOL_OUTPUT_ENV, env_value(sender)) };
        init_tool_output();
        let adopted = tool_output_fd().expect("the passed socket is adopted");
        assert!(tool_output_requested());
        assert_eq!(
            before_guest_dup_onto(-1, adopted, 0),
            GuestDup::Native,
            "a dup the kernel fails moves nothing"
        );
        assert_eq!(before_guest_dup_onto(1, adopted, 0x1234), GuestDup::Native);
        assert_eq!(tool_output_fd(), Some(adopted));
        assert!(protected_files::is_protected(&adopted));
        assert!(adopted >= TOOL_OUTPUT_FD_MIN, "{adopted}");
        assert!(protected_files::is_protected(&adopted));
        // The original number was closed (another test may have reused it).
        assert_ne!(
            socket_identity(sender),
            socket_identity(adopted),
            "original closed"
        );
        assert_eq!(std::env::var_os(TOOL_OUTPUT_ENV), None);
        assert_eq!(
            exec_env_entry().unwrap().to_bytes(),
            format!("{TOOL_OUTPUT_ENV}={}", env_value(adopted)).as_bytes()
        );
        // Signals are blocked while the tool writes, and restored after.
        let mask = || unsafe {
            let mut current: libc::sigset_t = core::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_BLOCK, core::ptr::null(), &mut current);
            current
        };
        let before = unsafe { libc::sigismember(&mask(), libc::SIGUSR1) };
        assert_eq!(
            with_tool_output(|_| unsafe {
                [
                    libc::SIGUSR1,
                    libc::SIGALRM,
                    libc::SIGSEGV,
                    libc::SIGRTMIN() + 1,
                ]
                .iter()
                .all(|&signal| libc::sigismember(&mask(), signal) == 1)
            }),
            Some(true)
        );
        assert_eq!(unsafe { libc::sigismember(&mask(), libc::SIGUSR1) }, before);

        // A guest dup2 onto its number: the socket moves first, and the old
        // number is free for the guest.
        let mut pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        assert_eq!(before_guest_dup_onto(pipe[1], adopted, 0), GuestDup::Moved);
        let moved = tool_output_fd().unwrap();
        assert_ne!(moved, adopted);
        assert!(moved >= TOOL_OUTPUT_FD_MIN);
        assert!(protected_files::is_protected(&moved));
        assert!(!protected_files::is_protected(&adopted));
        assert_eq!(unsafe { libc::dup2(pipe[1], adopted) }, adopted);
        with_tool_output(|fd| send_all(fd, b"record")).unwrap();
        assert_eq!(receive(receiver), b"record");
        assert_eq!(
            exec_env_entry().unwrap().to_bytes(),
            format!("{TOOL_OUTPUT_ENV}={}", env_value(moved)).as_bytes()
        );

        // A sender in another thread when the guest forks: the child's count
        // starts at its own zero, so its move does not wait for a sender that
        // does not exist there.
        let mut fork_pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(fork_pipe.as_mut_ptr()) }, 0);
        with_tool_output(|_| {
            in_child(|| {
                unsafe { libc::alarm(5) };
                before_guest_dup_onto(fork_pipe[1], moved, 0) == GuestDup::Moved
            })
        })
        .unwrap();

        // A number that no longer names the socket, as in a process whose own
        // descriptor table another process moved the socket out of, is never
        // written to.
        in_child(|| {
            unsafe { libc::dup2(fork_pipe[1], moved) };
            with_tool_output(|_| ()).is_none()
        });

        // A host soft RLIMIT_NOFILE at or below 1025 is raised for the move.
        in_child(|| {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0
                || limit.rlim_max <= TOOL_OUTPUT_FD_MIN as libc::rlim_t
            {
                return false;
            }
            limit.rlim_cur = TOOL_OUTPUT_FD_MIN as libc::rlim_t;
            let mut lowered = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // The setup must hold, or the raise is not what made room.
            let set = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
            let read = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lowered) };
            set == 0
                && read == 0
                && lowered.rlim_cur == TOOL_OUTPUT_FD_MIN as libc::rlim_t
                && dup_reserved(moved) >= TOOL_OUTPUT_FD_MIN
        });

        // A number that no longer names the socket in this process's table
        // (a CLONE_FILES sibling moved it, or something replaced it) is neither
        // moved nor retired: nothing is written to whatever is there, even when
        // a move would have to retire (the hard limit is 1025), and the guest's
        // call runs natively.
        set_retirement_message(b"retired");
        in_child(|| {
            let mut probe = [0; 2];
            if unsafe { libc::pipe(probe.as_mut_ptr()) } != 0 {
                return false;
            }
            unsafe { libc::fcntl(probe[0], libc::F_SETFL, libc::O_NONBLOCK) };
            let lowered = libc::rlimit {
                rlim_cur: TOOL_OUTPUT_FD_MIN as libc::rlim_t,
                rlim_max: TOOL_OUTPUT_FD_MIN as libc::rlim_t,
            };
            let mut byte = 0u8;
            // Replace the number behind the plugin's back, then leave no room
            // to move to.
            let replaced = unsafe { libc::dup2(probe[1], moved) } == moved;
            let limited = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) } == 0;
            let native = before_guest_dup_onto(fork_pipe[1], moved, 0) == GuestDup::Native;
            let nothing_written = unsafe { libc::read(probe[0], (&raw mut byte).cast(), 1) } == -1;
            limited
                && replaced
                && native
                && tool_output_fd().is_none()
                && nothing_written
                && !protected_files::is_protected(&moved)
        });

        // With no free number to move to (the hard limit too is 1025), the
        // socket is given up with the tool's message.
        in_child(|| {
            let lowered = libc::rlimit {
                rlim_cur: TOOL_OUTPUT_FD_MIN as libc::rlim_t,
                rlim_max: TOOL_OUTPUT_FD_MIN as libc::rlim_t,
            };
            let set = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) };
            set == 0
                && before_guest_dup_onto(fork_pipe[1], moved, 0) == GuestDup::Moved
                && tool_output_fd().is_none()
                && exec_env_entry().is_some_and(|entry| {
                    entry.to_bytes() == format!("{TOOL_OUTPUT_ENV}=-1").as_bytes()
                })
                && tool_output_requested()
                && with_tool_output(|_| ()).is_none()
                && !protected_files::is_protected(&moved)
        });
        assert_eq!(receive(receiver), b"retired");
        unsafe {
            libc::close(fork_pipe[0]);
            libc::close(fork_pipe[1]);
        }
        unsafe {
            libc::close(adopted);
            libc::close(pipe[0]);
            libc::close(pipe[1]);
            libc::close(receiver);
        }
    }
}
