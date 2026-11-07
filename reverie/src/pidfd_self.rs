/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! How the kernel behind a backend spells the pidfd self sentinels.
//!
//! Linux names the calling thread and its thread group without a descriptor
//! through two negative "pidfd" values, accepted by `pidfd_send_signal` and by
//! every caller of `pidfd_get_task` (`pidfd_getfd`, `process_madvise`, ...).
//! The thread sentinel is -10000 in every kernel that has them. The thread
//! group sentinel is not: Linux 6.15 and 6.16 define `PIDFD_SELF_THREAD_GROUP`
//! as -20000 (`include/uapi/linux/pidfd.h`), and Linux 6.17 and later define
//! it as -10001 (`include/uapi/linux/fcntl.h`). A value a kernel does not
//! recognise is looked up as a descriptor and fails with `EBADF`.
//!
//! A tool that forwards such a call must spell it the way the kernel that
//! physically executes it does. [`PidfdSelfSpelling`] is that fact, owned by
//! the backend that executes the physical syscall, and qualified once at its
//! own raw native leaf. Only a successful call is evidence: with signal 0 a
//! kernel answers 0 for a negative pidfd only when it recognises it as a
//! sentinel. Every other answer leaves the fact unknown, and is never read as
//! the absence of support.

use crate::Errno;

/// The thread sentinel, `PIDFD_SELF_THREAD`, in every kernel that has one.
pub const PIDFD_SELF_THREAD: i32 = -10000;
/// `PIDFD_SELF_THREAD_GROUP` in Linux 6.17 and later.
pub const PIDFD_SELF_THREAD_GROUP_MODERN: i32 = -10001;
/// `PIDFD_SELF_THREAD_GROUP` in Linux 6.15 and 6.16.
pub const PIDFD_SELF_THREAD_GROUP_LEGACY: i32 = -20000;

/// How the kernel executing a backend's physical syscalls spells the pidfd
/// self sentinels, as the backend that owns that execution states it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PidfdSelfSpelling {
    /// The thread group sentinel is -10001 (Linux 6.17 and later).
    Modern,
    /// The thread group sentinel is -20000 (Linux 6.15 and 6.16).
    Legacy,
    /// The backend executes these calls itself and implements no pidfd self
    /// sentinel: it declares so rather than having it measured.
    Unsupported,
    /// Not qualified: the backend states nothing, or its qualification could
    /// not establish a spelling. Never evidence that the kernel lacks one.
    Unknown,
}

impl PidfdSelfSpelling {
    /// The value this spelling gives `PIDFD_SELF_THREAD_GROUP`, if it has one.
    pub const fn thread_group(self) -> Option<i32> {
        match self {
            Self::Modern => Some(PIDFD_SELF_THREAD_GROUP_MODERN),
            Self::Legacy => Some(PIDFD_SELF_THREAD_GROUP_LEGACY),
            Self::Unsupported | Self::Unknown => None,
        }
    }

    /// The value this spelling gives `PIDFD_SELF_THREAD`, if it has one.
    pub const fn thread(self) -> Option<i32> {
        match self {
            Self::Modern | Self::Legacy => Some(PIDFD_SELF_THREAD),
            Self::Unsupported | Self::Unknown => None,
        }
    }
}

/// How many times a probe that a signal genuinely interrupted is repeated.
const INTERRUPTED_RETRIES: usize = 3;

/// Qualifies the spelling from a backend's own raw native leaf. A backend
/// calls this once, at an admitted point of its own lifecycle, and publishes
/// the result as a [`PidfdSelfFact`]; its `Guest::pidfd_self_spelling` only
/// reads that fact.
///
/// `admitted` is the backend's statement that nothing between this leaf and
/// the kernel can answer for it (no seccomp filter beyond any the backend
/// installed and admits this leaf through), on the thread that executes the
/// probe ([`thread_has_exactly_seccomp_filters`]). When it is false, nothing
/// is executed and the answer is [`PidfdSelfSpelling::Unknown`].
///
/// `probe(pidfd)` must execute `pidfd_send_signal(pidfd, 0, NULL, 0)` at that
/// leaf and return its raw result. Signal 0 checks permission and existence
/// and sends nothing. The thread group spellings are tried in turn: a 0 for
/// -10001 is [`PidfdSelfSpelling::Modern`]; only an `EBADF` for it permits
/// the -20000 probe, whose 0 is [`PidfdSelfSpelling::Legacy`]. Any other
/// settled outcome, including `EBADF` for both, is
/// [`PidfdSelfSpelling::Unknown`].
///
/// An interruption is not an answer. An `EINTR` is repeated a bounded number
/// of times, here; if one persists, or the leaf reports that a probe was not
/// run to completion (a restart errno), nothing was learned and the answer is
/// [`PidfdSelfSpelling::Unknown`], which the backend publishes like any other.
pub fn qualify(
    admitted: bool,
    mut probe: impl FnMut(i32) -> Result<usize, Errno>,
) -> PidfdSelfSpelling {
    if !admitted {
        return PidfdSelfSpelling::Unknown;
    }
    let mut once = |pidfd: i32| {
        let mut result = probe(pidfd);
        for _ in 0..INTERRUPTED_RETRIES {
            if result != Err(Errno::EINTR) {
                break;
            }
            result = probe(pidfd);
        }
        match result {
            Err(errno) if interrupted(errno) => None,
            settled => Some(settled),
        }
    };
    match once(PIDFD_SELF_THREAD_GROUP_MODERN) {
        Some(Ok(0)) => PidfdSelfSpelling::Modern,
        Some(Err(Errno::EBADF)) => match once(PIDFD_SELF_THREAD_GROUP_LEGACY) {
            Some(Ok(0)) => PidfdSelfSpelling::Legacy,
            _ => PidfdSelfSpelling::Unknown,
        },
        _ => PidfdSelfSpelling::Unknown,
    }
}

/// A backend's published [`PidfdSelfSpelling`]: set once by
/// [`initialize`](Self::initialize) at the backend's admitted lifecycle point
/// and read by its `Guest::pidfd_self_spelling`, which performs no I/O and no
/// probe. Before it is initialized it reads as
/// [`PidfdSelfSpelling::Unknown`]. Concurrent first initializers run one
/// qualification between them.
#[derive(Debug, Default)]
pub struct PidfdSelfFact(std::sync::OnceLock<PidfdSelfSpelling>);

impl PidfdSelfFact {
    /// An uninitialized fact.
    pub const fn new() -> Self {
        Self(std::sync::OnceLock::new())
    }

    /// Runs `qualification` if no earlier call has, publishes its result
    /// (Unknown included), and returns the published value.
    pub fn initialize(
        &self,
        qualification: impl FnOnce() -> PidfdSelfSpelling,
    ) -> PidfdSelfSpelling {
        *self.0.get_or_init(qualification)
    }

    /// The published value, or Unknown before initialization.
    pub fn get(&self) -> PidfdSelfSpelling {
        self.0.get().copied().unwrap_or(PidfdSelfSpelling::Unknown)
    }
}

/// Whether `errno` says a call was interrupted rather than answered: `EINTR`,
/// or a restart errno a backend reports for a call it did not complete.
fn interrupted(errno: Errno) -> bool {
    matches!(
        errno,
        Errno::EINTR
            | Errno::ERESTARTSYS
            | Errno::ERESTARTNOINTR
            | Errno::ERESTARTNOHAND
            | Errno::ERESTART_RESTARTBLOCK
    )
}

/// The raw arguments of the signal-0 probe [`qualify`] asks a leaf to execute.
pub const fn probe_args(pidfd: i32) -> [usize; 6] {
    [pidfd as isize as usize, 0, 0, 0, 0, 0]
}

/// Whether the calling thread carries exactly `expected` seccomp filters,
/// read from `/proc/thread-self/status` (`Seccomp:` and, from Linux 5.9,
/// `Seccomp_filters:`). Filters belong to threads, not processes: a filter
/// installed without `SECCOMP_FILTER_FLAG_TSYNC` binds only the installing
/// thread and the threads it then creates, and `/proc/self/status` reports
/// the thread group leader's. Call this on the thread that executes the probe.
/// Anything unreadable or unrecognised is `false`, so a backend that cannot
/// tell what stands between its leaf and the kernel does not qualify.
pub fn thread_has_exactly_seccomp_filters(expected: u64) -> bool {
    match std::fs::read_to_string("/proc/thread-self/status") {
        Ok(status) => status_has_exactly_seccomp_filters(&status, expected),
        Err(_) => false,
    }
}

/// [`thread_has_exactly_seccomp_filters`] for an already read `status` file,
/// for a backend that must read it through its own trusted path.
pub fn status_has_exactly_seccomp_filters(status: &str, expected: u64) -> bool {
    let field = |name: &str| {
        status.lines().find_map(|line| {
            let value = line.strip_prefix(name)?.strip_prefix(':')?;
            value.trim().parse::<u64>().ok()
        })
    };
    match (field("Seccomp"), field("Seccomp_filters")) {
        // Mode 0: no filter at all.
        (Some(0), None) => expected == 0,
        (Some(0), Some(0)) => expected == 0,
        // Mode 2: filter mode; only an exact count is trusted.
        (Some(2), Some(count)) => count == expected && expected > 0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scripted(answers: &[(i32, Result<usize, Errno>)]) -> (PidfdSelfSpelling, Vec<i32>) {
        let mut calls = Vec::new();
        let mut answers = answers.iter();
        let spelling = qualify(true, |pidfd| {
            calls.push(pidfd);
            let (expected, answer) = answers.next().expect("an unexpected extra probe");
            assert_eq!(*expected, pidfd);
            *answer
        });
        (spelling, calls)
    }

    #[test]
    fn a_kernel_accepting_the_modern_group_sentinel_is_modern_after_one_probe() {
        let (spelling, calls) = scripted(&[(-10001, Ok(0))]);
        assert_eq!(spelling, PidfdSelfSpelling::Modern);
        assert_eq!(calls, [-10001]);
        assert_eq!(PidfdSelfSpelling::Modern.thread_group(), Some(-10001));
        assert_eq!(PidfdSelfSpelling::Modern.thread(), Some(-10000));
    }

    #[test]
    fn only_ebadf_for_the_modern_value_permits_the_legacy_probe() {
        let (spelling, calls) = scripted(&[(-10001, Err(Errno::EBADF)), (-20000, Ok(0))]);
        assert_eq!(spelling, PidfdSelfSpelling::Legacy);
        assert_eq!(calls, [-10001, -20000]);
        assert_eq!(PidfdSelfSpelling::Legacy.thread_group(), Some(-20000));
        assert_eq!(PidfdSelfSpelling::Legacy.thread(), Some(-10000));
    }

    #[test]
    fn no_failure_is_read_as_absence() {
        for (answers, expected_calls) in [
            (
                vec![(-10001, Err(Errno::EBADF)), (-20000, Err(Errno::EBADF))],
                2,
            ),
            (vec![(-10001, Err(Errno::EPERM))], 1),
            (vec![(-10001, Err(Errno::ENOSYS))], 1),
            (vec![(-10001, Err(Errno::EACCES))], 1),
            (vec![(-10001, Ok(7))], 1),
            (
                vec![(-10001, Err(Errno::EBADF)), (-20000, Err(Errno::EPERM))],
                2,
            ),
        ] {
            let (spelling, calls) = scripted(&answers);
            assert_eq!(spelling, PidfdSelfSpelling::Unknown, "{answers:?}");
            assert_eq!(calls.len(), expected_calls, "{answers:?}");
        }
    }

    #[test]
    fn a_genuine_interruption_is_repeated_a_bounded_number_of_times() {
        let (spelling, calls) = scripted(&[(-10001, Err(Errno::EINTR)), (-10001, Ok(0))]);
        assert_eq!(spelling, PidfdSelfSpelling::Modern);
        assert_eq!(calls, [-10001, -10001]);
        let (spelling, calls) = scripted(&[
            (-10001, Err(Errno::EBADF)),
            (-20000, Err(Errno::EINTR)),
            (-20000, Ok(0)),
        ]);
        assert_eq!(spelling, PidfdSelfSpelling::Legacy);
        assert_eq!(calls, [-10001, -20000, -20000]);
    }

    #[test]
    fn an_interruption_that_persists_or_a_call_not_completed_settles_unknown() {
        let (spelling, calls) = scripted(&[(-10001, Err(Errno::EINTR)); 4]);
        assert_eq!(spelling, PidfdSelfSpelling::Unknown);
        assert_eq!(calls.len(), 4);
        for restart in [
            Errno::ERESTARTSYS,
            Errno::ERESTARTNOINTR,
            Errno::ERESTARTNOHAND,
            Errno::ERESTART_RESTARTBLOCK,
        ] {
            let (spelling, calls) = scripted(&[(-10001, Err(restart))]);
            assert_eq!(spelling, PidfdSelfSpelling::Unknown, "{restart:?}");
            assert_eq!(calls, [-10001]);
            let (spelling, _) = scripted(&[(-10001, Err(Errno::EBADF)), (-20000, Err(restart))]);
            assert_eq!(spelling, PidfdSelfSpelling::Unknown, "{restart:?}");
        }
    }

    #[test]
    fn an_unadmitted_leaf_executes_nothing() {
        let spelling = qualify(false, |_| panic!("an unadmitted leaf was probed"));
        assert_eq!(spelling, PidfdSelfSpelling::Unknown);
        assert_eq!(PidfdSelfSpelling::Unsupported.thread_group(), None);
    }

    #[test]
    fn the_probe_carries_a_sign_extended_pidfd_and_signal_zero() {
        assert_eq!(probe_args(-10001), [(-10001isize) as usize, 0, 0, 0, 0, 0]);
        assert_eq!(probe_args(-20000)[0] as isize, -20000);
    }

    #[test]
    fn only_an_exact_seccomp_filter_count_admits() {
        let status = |mode: &str, filters: Option<&str>| {
            let mut s = format!("Name:\tx\nSeccomp:\t{mode}\n");
            if let Some(filters) = filters {
                s.push_str(&format!("Seccomp_filters:\t{filters}\n"));
            }
            s
        };
        assert!(status_has_exactly_seccomp_filters(
            &status("0", Some("0")),
            0
        ));
        assert!(status_has_exactly_seccomp_filters(&status("0", None), 0));
        assert!(!status_has_exactly_seccomp_filters(
            &status("2", Some("1")),
            0
        ));
        assert!(status_has_exactly_seccomp_filters(
            &status("2", Some("1")),
            1
        ));
        assert!(!status_has_exactly_seccomp_filters(
            &status("2", Some("2")),
            1
        ));
        // Filter mode without a count (a kernel older than 5.9) is not trusted.
        assert!(!status_has_exactly_seccomp_filters(&status("2", None), 1));
        // Strict mode, garbage and an absent field never admit.
        assert!(!status_has_exactly_seccomp_filters(&status("1", None), 0));
        assert!(!status_has_exactly_seccomp_filters("Seccomp:\tx\n", 0));
        assert!(!status_has_exactly_seccomp_filters("Name:\tx\n", 0));
    }

    /// The admission reads the calling thread's filters, not the process
    /// leader's: a filter installed on one thread is seen there and only there.
    #[test]
    fn the_admission_reads_the_calling_threads_filters() {
        let leader = thread_has_exactly_seccomp_filters(0);
        let filtered = std::thread::spawn(|| {
            let allow = [libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            }];
            let program = libc::sock_fprog {
                len: 1,
                filter: allow.as_ptr().cast_mut(),
            };
            // SAFETY: an allow-everything filter on this thread only, after
            // no_new_privs; it ends with the thread.
            unsafe {
                assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
                assert_eq!(
                    libc::prctl(
                        libc::PR_SET_SECCOMP,
                        libc::SECCOMP_MODE_FILTER,
                        &program as *const libc::sock_fprog,
                    ),
                    0
                );
            }
            (
                thread_has_exactly_seccomp_filters(0),
                std::fs::read_to_string("/proc/self/status").unwrap(),
            )
        })
        .join()
        .unwrap();
        assert_eq!(thread_has_exactly_seccomp_filters(0), leader);
        assert!(!filtered.0, "a filtered thread was admitted");
        if leader {
            // The process's own status still shows the unfiltered leader.
            assert!(status_has_exactly_seccomp_filters(&filtered.1, 0));
        }
    }

    /// Installs `filter` (a list of BPF instructions) on the calling thread
    /// only, after no_new_privs.
    fn install_thread_filter(filter: &mut [libc::sock_filter]) {
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: a filter on this thread only, which ends with the thread.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &program as *const libc::sock_fprog,
                ),
                0
            );
        }
    }

    /// A filter that answers pidfd_send_signal with `answer` (an
    /// `SECCOMP_RET_ERRNO` data value, 0 forging success) and allows
    /// everything else.
    fn pidfd_send_signal_filter(answer: u32) -> Vec<libc::sock_filter> {
        let statement = |code: u32, k: u32| libc::sock_filter {
            code: code as u16,
            jt: 0,
            jf: 0,
            k,
        };
        vec![
            // A = seccomp_data.nr
            statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0),
            libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: 0,
                jf: 1,
                k: libc::SYS_pidfd_send_signal as u32,
            },
            statement(
                libc::BPF_RET | libc::BPF_K,
                libc::SECCOMP_RET_ERRNO | answer,
            ),
            statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW),
        ]
    }

    fn raw_probe(pidfd: i32) -> Result<usize, Errno> {
        let [a0, a1, a2, a3, _, _] = probe_args(pidfd);
        // SAFETY: signal 0 with a null siginfo reads and writes no memory.
        let result = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, a0, a1, a2, a3) };
        if result < 0 {
            Err(Errno::last())
        } else {
            Ok(result as usize)
        }
    }

    /// A thread whose filter forges pidfd_send_signal's success, or refuses
    /// it, under an unfiltered leader: the admission refuses that thread and
    /// no physical probe runs, so neither filter's answer becomes the fact.
    /// The forging filter is shown to forge: a non-sentinel answers 0.
    #[test]
    fn a_filtered_probing_thread_under_an_unfiltered_leader_probes_nothing() {
        for (answer, forges) in [(0, true), (libc::EPERM as u32, false)] {
            let (spelling, probes, forged) = std::thread::spawn(move || {
                install_thread_filter(&mut pidfd_send_signal_filter(answer));
                let mut probes = 0;
                let spelling = qualify(thread_has_exactly_seccomp_filters(0), |pidfd| {
                    probes += 1;
                    raw_probe(pidfd)
                });
                (spelling, probes, raw_probe(-10002))
            })
            .join()
            .unwrap();
            assert_eq!(spelling, PidfdSelfSpelling::Unknown, "answer {answer}");
            assert_eq!(probes, 0, "answer {answer}");
            if forges {
                assert_eq!(forged, Ok(0));
            } else {
                assert_eq!(forged, Err(Errno::EPERM));
            }
        }
    }

    /// The published fact is read without running anything again: after a
    /// success, a permanent non-success, and exhausted interruptions alike,
    /// repeated reads issue no admission read and no probe, and a later
    /// initialization does not qualify again. Before initialization it reads
    /// Unknown, also without running anything.
    #[test]
    fn a_published_fact_is_read_without_io() {
        for (answers, expected) in [
            (vec![Ok(0)], PidfdSelfSpelling::Modern),
            (
                vec![Err(Errno::EBADF), Err(Errno::EBADF)],
                PidfdSelfSpelling::Unknown,
            ),
            (vec![Err(Errno::EINTR); 4], PidfdSelfSpelling::Unknown),
        ] {
            let fact = PidfdSelfFact::new();
            assert_eq!(fact.get(), PidfdSelfSpelling::Unknown);
            let mut admissions = 0;
            let mut probes = 0;
            let mut answers = answers.into_iter();
            let published = fact.initialize(|| {
                admissions += 1;
                qualify(true, |_| {
                    probes += 1;
                    answers.next().expect("an unexpected extra probe")
                })
            });
            assert_eq!(published, expected);
            let (admitted, probed) = (admissions, probes);
            for _ in 0..3 {
                assert_eq!(fact.get(), expected);
            }
            assert_eq!(
                fact.initialize(|| panic!("a published fact was qualified again")),
                expected
            );
            assert_eq!((admissions, probes), (admitted, probed));
        }
    }

    /// Concurrent first initializers run one qualification between them.
    #[test]
    fn concurrent_first_initializers_qualify_once() {
        let fact = std::sync::Arc::new(PidfdSelfFact::new());
        let runs = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let threads = (0..8)
            .map(|_| {
                let (fact, runs) = (fact.clone(), runs.clone());
                std::thread::spawn(move || {
                    fact.initialize(|| {
                        runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        PidfdSelfSpelling::Modern
                    })
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            assert_eq!(thread.join().unwrap(), PidfdSelfSpelling::Modern);
        }
        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
