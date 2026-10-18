//! An initial-image byte write before the system interpreter starts.
//!
//! The Tool chooses the bytes. The shared launcher owns the physical child,
//! verifies the bootstrap's completed write, and permits loader transfer only
//! after that verification. The ordinary constructor redeems the completed
//! Tool input over the same parent-owned channel exactly once. This does not
//! install a Tool, service loader syscalls, or establish native-exec readiness.

use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

#[cfg(feature = "launcher")]
pub mod launch;

#[cfg(feature = "launcher")]
pub(crate) const LOADER_FD: i32 = 198;
#[cfg(feature = "launcher")]
pub(crate) const INPUT_FD: i32 = 199;
pub(crate) const CHANNEL_FD: i32 = 200;
#[cfg(feature = "launcher")]
pub(crate) const SCRATCH_BASE: usize = 0x5200_0000_0000;
#[cfg(all(test, feature = "launcher"))]
pub(crate) const SCRATCH_BYTES: usize = 512 * 1024;
pub(crate) const MAX_STATE: usize = 4096;
#[cfg(feature = "launcher")]
pub(crate) const PENDING_MAGIC: &[u8; 8] = b"HRSEEDP1";
#[cfg(feature = "launcher")]
pub(crate) const WRITE_MAGIC: &[u8; 8] = b"HRSEEDR1";
#[cfg(feature = "launcher")]
pub(crate) const GO_MAGIC: &[u8; 8] = b"HRSEEDG1";
pub(crate) const TAKE_MAGIC: &[u8; 8] = b"HRSEEDT1";
pub(crate) const STATE_MAGIC: &[u8; 8] = b"HRSEEDS1";

// This image gets one attempt, including an attempt that fails authentication.
// A real exec creates fresh static state; neither failure nor fork resets it.
static COMPLETION_ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// The per-launch correlation value carried in the ordinary sealed bootstrap.
/// It is not authority: redemption also checks the actual parent endpoint and
/// the parent's one-use, watched-child state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Token {
    pub(crate) nonce: [u8; 32],
    pub(crate) config: [u8; 32],
}

impl Token {
    pub(crate) fn encode(self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&self.nonce);
        bytes[32..].copy_from_slice(&self.config);
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != 64 {
            return Err(invalid("initial auxv token length"));
        }
        Ok(Self {
            nonce: bytes[..32].try_into().unwrap(),
            config: bytes[32..].try_into().unwrap(),
        })
    }
}

/// Facts retained after an actual complete initial-image write. Only the
/// shared launch owner creates this value, after checking the held child and
/// its kernel auxv. The Tool may then encode its completed-state handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletedWrite {
    pub(crate) pid: i32,
    pub(crate) start_time_ticks: u64,
    pub(crate) target: usize,
    pub(crate) bytes: [u8; 16],
}

impl CompletedWrite {
    /// The real initial image's process id, in the launcher's PID namespace.
    pub fn pid(self) -> i32 {
        self.pid
    }
    /// The kernel birth stamp held alongside the child's pidfd.
    pub fn start_time_ticks(self) -> u64 {
        self.start_time_ticks
    }
    /// The original kernel AT_RANDOM pointer; it was never replaced.
    pub fn target(self) -> usize {
        self.target
    }
    /// All sixteen bytes read back from the completed target.
    pub fn bytes(self) -> [u8; 16] {
        self.bytes
    }
}

/// Completed input redeemed by the actual ordinary root constructor. The
/// caller still checks its Tool-specific encoding and effective configuration.
pub struct InitialInput {
    /// Actual image identity and complete write observed by the parent.
    pub image: CompletedWrite,
    /// Tool-owned serialized state, prepared only after the physical write.
    pub state: Vec<u8>,
    /// Digest of the launcher's exact configuration wire bytes.
    pub config_digest: [u8; 32],
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn u64_at(bytes: &[u8], at: usize) -> io::Result<u64> {
    bytes
        .get(at..at + 8)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
        .ok_or_else(|| invalid("truncated initial auxv record"))
}

pub(crate) fn header(bytes: &mut [u8], magic: &[u8; 8], token: Token) {
    let len = bytes.len() as u32;
    bytes[..8].copy_from_slice(magic);
    bytes[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&len.to_le_bytes());
    bytes[16..80].copy_from_slice(&token.encode());
}

pub(crate) fn check_header(bytes: &[u8], magic: &[u8; 8], token: Token) -> io::Result<()> {
    if bytes.len() < 80
        || &bytes[..8] != magic
        || bytes[8..12] != 1_u32.to_le_bytes()
        || bytes[12..16] != (bytes.len() as u32).to_le_bytes()
        || bytes[16..80] != token.encode()
    {
        return Err(invalid(
            "initial auxv record identity, version or length differs",
        ));
    }
    Ok(())
}

/// Consume a completed startup input without using guest libc's syscall
/// wrappers. A matching seal or token alone never satisfies this operation.
/// The first attempt consumes this image even on error. Subsequent attempts
/// return the named same-image refusal before any descriptor or scratch access.
///
/// # Safety
/// On the first attempt, the caller must exclusively own the role
/// `CHANNEL_FD` slot against other threads for the whole call, which may
/// consume that endpoint. The operation masks asynchronous handlers through
/// its last descriptor access, then restores the exact incoming signal mask.
/// This does not establish single-threadedness. No seccomp filter may be active.
/// Actual launch, parent and leader identity are checked, not assumed; an
/// invalid endpoint is a legitimate refusal. Subsequent attempts require no
/// descriptor ownership or pre-filter context because they only refuse reuse.
/// This operation never accesses the retired bootstrap scratch or infers
/// current ownership of it.
pub unsafe fn take_completed(token: Token) -> io::Result<InitialInput> {
    if COMPLETION_ATTEMPTED.swap(true, Ordering::AcqRel) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "initial auxv same-image reuse is unsupported",
        ));
    }

    // A DT_NEEDED constructor may have installed a handler that replaces this
    // role slot. Block before authentication, through the final close. Use the
    // raw kernel mask so libc's reserved NPTL signals are covered too.
    let mut previous = 0;
    unsafe {
        crate::signal::raw_sigprocmask(libc::SIG_BLOCK, Some(&u64::MAX), Some(&mut previous))
    }
    .map_err(io::Error::from_raw_os_error)?;
    let result = take_completed_masked(token);
    // Restoring can deliver a pending handler immediately. No role access or
    // cleanup may follow it; that handler's replacement belongs to the guest.
    // A restoration error is a failure even if the handoff itself succeeded.
    unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, Some(&previous), None) }
        .map_err(io::Error::from_raw_os_error)?;
    result
}

fn take_completed_masked(token: Token) -> io::Result<InitialInput> {
    use crate::trap::raw_syscall6;

    // A replacement socket made by this guest has this guest's credentials,
    // not its actual parent's. Holding or echoing a nonce grants no authority.
    let parent = unsafe { raw_syscall6(libc::SYS_getppid, [0; 6]) };
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let tid = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) };
    let mut peer = core::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = core::mem::size_of::<libc::ucred>() as u32;
    let result = unsafe {
        raw_syscall6(
            libc::SYS_getsockopt,
            [
                CHANNEL_FD as u64,
                libc::SOL_SOCKET as u64,
                libc::SO_PEERCRED as u64,
                peer.as_mut_ptr() as u64,
                &mut length as *mut _ as u64,
                0,
            ],
        )
    };
    if result != 0
        || length as usize != core::mem::size_of::<libc::ucred>()
        || parent <= 0
        || pid <= 0
        || pid != tid
        || i64::from(unsafe { peer.assume_init() }.pid) != parent
    {
        return Err(invalid(
            "initial auxv channel does not belong to the actual parent",
        ));
    }
    let mut request = [0; 96];
    header(&mut request, TAKE_MAGIC, token);
    put_u64(&mut request, 80, pid as u64);
    let sent = unsafe {
        raw_syscall6(
            libc::SYS_sendto,
            [
                CHANNEL_FD as u64,
                request.as_ptr() as u64,
                request.len() as u64,
                libc::MSG_NOSIGNAL as u64,
                0,
                0,
            ],
        )
    };
    if sent != request.len() as i64 {
        return Err(invalid("initial auxv redemption send failed"));
    }
    let mut packet = [0; 128 + MAX_STATE];
    let received = unsafe {
        raw_syscall6(
            libc::SYS_recvfrom,
            [
                CHANNEL_FD as u64,
                packet.as_mut_ptr() as u64,
                packet.len() as u64,
                libc::MSG_TRUNC as u64,
                0,
                0,
            ],
        )
    };
    // Consume the endpoint even on a failed response: no retry or fallback.
    let closed = unsafe { raw_syscall6(libc::SYS_close, [CHANNEL_FD as u64, 0, 0, 0, 0, 0]) };
    if !(129..=packet.len() as i64).contains(&received) || closed != 0 {
        return Err(invalid(
            "initial auxv completion is absent, truncated or oversized",
        ));
    }
    let packet = &packet[..received as usize];
    check_header(packet, STATE_MAGIC, token)?;
    if u64_at(packet, 80)? != pid as u64
        || u64_at(packet, 88)? == 0
        || u64_at(packet, 104)? != 16
        || u64_at(packet, 96)?.checked_add(16).is_none()
        || u64_at(packet, 96)? == 0
    {
        return Err(invalid(
            "initial auxv completion does not name this initial image",
        ));
    }
    let image = CompletedWrite {
        pid: pid as i32,
        start_time_ticks: u64_at(packet, 88)?,
        target: u64_at(packet, 96)? as usize,
        bytes: packet[112..128].try_into().unwrap(),
    };
    // The bootstrap retired its scratch before entering the original loader.
    // A DT_NEEDED constructor may already have replaced any of those pages.
    // Never access or reclaim that historical address interval here: the
    // authenticated completion describes the byte write, not present ownership.
    Ok(InitialInput {
        image,
        state: packet[128..].to_vec(),
        config_digest: token.config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "launcher")]
    #[test]
    fn a_signal_cannot_replace_the_channel_until_redemption_retires_it() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixDatagram;
        use std::sync::atomic::AtomicI32;

        static REPLACEMENT: AtomicI32 = AtomicI32::new(-1);
        static DELIVERED: AtomicBool = AtomicBool::new(false);
        extern "C" fn replace_role(_: i32) {
            // Only async-signal-safe operations; the pre-opened replacement
            // must survive the redemption operation that interrupted us.
            let source = REPLACEMENT.load(Ordering::Relaxed);
            if unsafe { libc::dup2(source, CHANNEL_FD) } == CHANNEL_FD {
                DELIVERED.store(true, Ordering::Release);
            }
        }

        const TEST: &str = concat!(
            "initial_auxv::tests::",
            "a_signal_cannot_replace_the_channel_until_redemption_retires_it"
        );
        const CHILD: &str = "REVERIE_INITIAL_AUXV_SIGNAL_TEST";
        const CHECKED: &str = "initial auxv pending signal delivered after role retirement";
        if std::env::var(CHILD).ok().as_deref() != Some(TEST) {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(CHILD, TEST)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(String::from_utf8_lossy(&output.stdout).contains(CHECKED));
            return;
        }

        // As in the physical seed controls, isolate before starting any Tokio
        // runtime. This outer process is single-threaded; its fork below gives
        // the production call a genuine leader and parent-created socket.
        let result = reverie::process::Container::new().run(|| {
            let (role, parent) = UnixDatagram::pair().unwrap();
            let (replacement, replacement_peer) = UnixDatagram::pair().unwrap();
            for socket in [&role, &parent, &replacement, &replacement_peer] {
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .unwrap();
                assert_ne!(socket.as_raw_fd(), CHANNEL_FD);
            }
            let token = Token {
                nonce: [7; 32],
                config: [8; 32],
            };
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "{}", io::Error::last_os_error());
            if pid == 0 {
                let status = std::fs::read_to_string("/proc/self/status").unwrap();
                assert!(status.lines().any(|line| {
                    line.strip_prefix("Seccomp:")
                        .is_some_and(|mode| mode.trim() == "0")
                }));
                assert_eq!(
                    unsafe { libc::getpid() },
                    unsafe { libc::syscall(libc::SYS_gettid) } as i32
                );
                assert_eq!(unsafe { libc::fcntl(CHANNEL_FD, libc::F_GETFD) }, -1);
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
                assert_eq!(
                    unsafe { libc::dup2(role.as_raw_fd(), CHANNEL_FD) },
                    CHANNEL_FD
                );
                REPLACEMENT.store(replacement.as_raw_fd(), Ordering::Relaxed);
                let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                action.sa_sigaction = replace_role as *const () as usize;
                unsafe { libc::sigemptyset(&mut action.sa_mask) };
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()) },
                    0
                );
                let prior = 1_u64 << (libc::SIGUSR2 - 1);
                unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, Some(&prior), None) }
                    .unwrap();
                // This is a component control: the real parent sends a STATE
                // frame, not evidence of an actual seed write or Tool launch.
                // SAFETY: one thread, pre-filter, owns the role slot; the
                // production boundary must exclude its asynchronous handler.
                let input = unsafe { take_completed(token) }.unwrap();
                assert_eq!(input.state, b"component state");
                let mut restored = 0;
                unsafe {
                    crate::signal::raw_sigprocmask(libc::SIG_SETMASK, None, Some(&mut restored))
                }
                .unwrap();
                assert_eq!(restored, prior, "restore the exact incoming mask");
                assert!(
                    DELIVERED.load(Ordering::Acquire),
                    "pending handler was not delivered"
                );
                assert_role_fd_usable(&replacement_peer, 61);
                assert_eq!(unsafe { libc::close(CHANNEL_FD) }, 0);
                unsafe { libc::_exit(0) };
            }

            struct Child(i32);
            impl Drop for Child {
                fn drop(&mut self) {
                    if self.0 > 0 {
                        unsafe { libc::kill(self.0, libc::SIGKILL) };
                        while unsafe { libc::waitpid(self.0, std::ptr::null_mut(), 0) } == -1
                            && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                        {
                        }
                    }
                }
            }
            let mut child = Child(pid);
            let mut take = [0; 96];
            assert_eq!(parent.recv(&mut take).unwrap(), take.len());
            check_header(&take, TAKE_MAGIC, token).unwrap();
            assert_eq!(u64_at(&take, 80).unwrap(), pid as u64);
            // Receipt of TAKE proves authentication has occurred. Hold STATE,
            // queue a real signal, and inspect the kernel's pending/mask facts
            // before allowing redemption to finish: no timing sleep or skip.
            assert_eq!(unsafe { libc::kill(pid, libc::SIGUSR1) }, 0);
            let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
            let field = |name: &str| {
                u64::from_str_radix(
                    status
                        .lines()
                        .find_map(|line| line.strip_prefix(name))
                        .unwrap()
                        .trim(),
                    16,
                )
                .unwrap()
            };
            let bit = 1_u64 << (libc::SIGUSR1 - 1);
            assert_ne!(
                field("SigBlk:") & bit,
                0,
                "signal must stay blocked through STATE/close"
            );
            assert_ne!(
                (field("SigPnd:") | field("ShdPnd:")) & bit,
                0,
                "the queued signal must remain pending"
            );
            let mut state = [0; 128 + b"component state".len()];
            header(&mut state, STATE_MAGIC, token);
            put_u64(&mut state, 80, pid as u64);
            put_u64(&mut state, 88, 1);
            put_u64(&mut state, 96, 0x1000);
            put_u64(&mut state, 104, 16);
            state[128..].copy_from_slice(b"component state");
            assert_eq!(parent.send(&state).unwrap(), state.len());
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            child.0 = 0;
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
            true
        });
        assert_eq!(result, Ok(true));
        println!("{CHECKED}");
    }

    #[test]
    fn failed_take_consumes_the_image_and_reuse_never_probes_the_role_fd() {
        use std::os::fd::AsRawFd;
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixDatagram;

        const TEST: &str = concat!(
            "initial_auxv::tests::",
            "failed_take_consumes_the_image_and_reuse_never_probes_the_role_fd"
        );
        const CHILD: &str = "REVERIE_INITIAL_AUXV_REUSE_TEST";
        const CHECKED: &str = "initial auxv failed-first and same-image refusal checked";
        if std::env::var(CHILD).ok().as_deref() != Some(TEST) {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(CHILD, TEST)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains(CHECKED),
                "the isolated API control did not complete: {output:?}"
            );
            return;
        }

        // A fresh process isolates the production one-use state and role slot.
        // This is an invalid-peer API control, not a shared-seed launch or a
        // fabricated successful completion. Its first-call safety premises are
        // real: no filter, and exclusive ownership of the socket at fd 200.
        let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
        assert!(
            status.lines().any(|line| line
                .strip_prefix("Seccomp:")
                .is_some_and(|mode| mode.trim() == "0")),
            "the first API attempt requires an unfiltered test process"
        );
        let occupied = unsafe { libc::fcntl(CHANNEL_FD, libc::F_GETFD) };
        let occupied_error = io::Error::last_os_error();
        assert_eq!(occupied, -1, "the isolated role slot is already occupied");
        assert_eq!(occupied_error.raw_os_error(), Some(libc::EBADF));
        let (role, peer) = UnixDatagram::pair().unwrap();
        for socket in [&role, &peer] {
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
        }
        let role_fd = if role.as_raw_fd() == CHANNEL_FD {
            role.into_raw_fd()
        } else {
            // F_DUPFD never overwrites another owner's descriptor. The raw
            // duplicate is ours until the explicit close below; no OwnedFd
            // remains that the production API could close behind its back.
            unsafe { libc::fcntl(role.as_raw_fd(), libc::F_DUPFD_CLOEXEC, CHANNEL_FD) }
        };
        assert_eq!(role_fd, CHANNEL_FD);
        let token = Token {
            nonce: [3; 32],
            config: [4; 32],
        };
        let prior = 1_u64 << (libc::SIGUSR2 - 1);
        unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, Some(&prior), None) }.unwrap();
        // SAFETY: this isolated test owns and serializes the role slot, with
        // no filter. The socket's actual creator credentials are this process,
        // so the API must reject it rather than grant parent/launch authority.
        let first = unsafe { take_completed(token) }.err().unwrap();
        assert_eq!(first.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            first.to_string(),
            "initial auxv channel does not belong to the actual parent"
        );
        let mut restored = 0;
        unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, None, Some(&mut restored)) }
            .unwrap();
        assert_eq!(
            restored, prior,
            "failed authentication must restore the mask"
        );
        assert_role_fd_usable(&peer, 11);

        // Neither mask changes nor descriptor probes may occur on reuse. Make
        // reaching either terminal, not just check that fd 200 was not closed.
        // This filter is installed only after the real first attempt; the
        // documented repeat-refusal branch has no pre-filter requirement.
        let mut filter = [
            libc::sock_filter {
                code: 0x20, // BPF_LD | BPF_W | BPF_ABS, seccomp_data.nr.
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: 0x15, // BPF_JMP | BPF_JEQ | BPF_K.
                jt: 1,
                jf: 0,
                k: libc::SYS_getsockopt as u32,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: libc::SYS_rt_sigprocmask as u32,
            },
            libc::sock_filter {
                code: 0x06, // BPF_RET | BPF_K.
                jt: 0,
                jf: 0,
                k: 0x8000_0000, // SECCOMP_RET_KILL_PROCESS.
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x7fff_0000, // SECCOMP_RET_ALLOW.
            },
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0
        );
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_seccomp,
                    libc::SECCOMP_SET_MODE_FILTER,
                    0,
                    &program as *const libc::sock_fprog,
                )
            },
            0
        );
        for token in [
            token,
            Token {
                nonce: [5; 32],
                ..token
            },
        ] {
            // SAFETY: the production guard has consumed this image. Repeated
            // calls need neither live role ownership nor an unfiltered context.
            let repeated = unsafe { take_completed(token) }.err().unwrap();
            assert_eq!(repeated.kind(), io::ErrorKind::Unsupported);
            assert_eq!(
                repeated.to_string(),
                "initial auxv same-image reuse is unsupported"
            );
            assert_role_fd_usable(&peer, 23);
        }
        assert_eq!(unsafe { libc::close(role_fd) }, 0);
        println!("{CHECKED}");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        // The one selected child has completed every assertion. Its permanent
        // filter also rejects libtest's later thread-exit mask reset, so end
        // the isolated process directly instead of running harness teardown.
        unsafe { libc::_exit(0) };
    }

    fn assert_role_fd_usable(peer: &std::os::unix::net::UnixDatagram, marker: u8) {
        let sent = [marker];
        assert_eq!(
            unsafe { libc::write(CHANNEL_FD, sent.as_ptr().cast(), sent.len()) },
            1
        );
        let mut received = [0];
        assert_eq!(peer.recv(&mut received).unwrap(), 1);
        assert_eq!(received, sent);
        assert_eq!(peer.send(&sent).unwrap(), 1);
        assert_eq!(
            unsafe { libc::read(CHANNEL_FD, received.as_mut_ptr().cast(), received.len()) },
            1
        );
        assert_eq!(received, sent);
    }

    #[test]
    fn a_completed_frame_is_bound_to_the_whole_launch_token() {
        let token = Token {
            nonce: [1; 32],
            config: [2; 32],
        };
        let mut record = [0; 96];
        header(&mut record, TAKE_MAGIC, token);
        assert!(check_header(&record, TAKE_MAGIC, token).is_ok());
        for index in 0..80 {
            let mut bad = record;
            bad[index] ^= 1;
            assert!(
                check_header(&bad, TAKE_MAGIC, token).is_err(),
                "byte {index}"
            );
        }
        for length in 0..record.len() {
            assert!(check_header(&record[..length], TAKE_MAGIC, token).is_err());
        }
        assert!(Token::decode(&token.encode()).is_ok());
        assert!(Token::decode(&token.encode()[..63]).is_err());
    }
}
