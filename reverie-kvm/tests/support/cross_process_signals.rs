/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A guest's kill and tgkill reach another process of the run when its Tool
//! asks for cross-process signals before installation
//! (`ProcessSignalControl::enable_cross_process_signals`). The target's
//! handler sees the siginfo Linux's `prepare_kill_siginfo` builds: `SI_USER`
//! for kill and `SI_TKILL` for tgkill, each with the sender's process id.
//! Without the request each send is refused by name. `pidfd_send_signal`
//! reaches the caller itself and its child through their pidfds, and answers
//! for an exited and a reaped child as Linux does. A siginfo the caller
//! passes is checked as Linux checks it, including the rest of a record whose
//! layout Linux does not know. Every observable is compared with the same
//! binary run natively, except for the self sentinels, whose spelling
//! LinuxEmu fixes at Linux 6.17's whatever the host kernel.

use super::*;

const CROSS_PROCESS_SIGNAL_SOURCE: &str = r#"#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t taken;
static volatile int numbers[2], codes[2], senders[2];
static volatile unsigned uids[2];

static void handler(int number, siginfo_t *info, void *context) {
    (void)context;
    if (taken < 2) {
        numbers[taken] = number;
        codes[taken] = info->si_code;
        senders[taken] = info->si_pid;
        uids[taken] = info->si_uid;
    }
    taken++;
}

static void say(const char *text) {
    size_t length = strlen(text);
    if (write(STDOUT_FILENO, text, length) != (ssize_t)length) _exit(120);
}

/* The child stays runnable: each nonblocking read of the control pipe is a
 * system call, at whose end a queued signal can be taken. The parent writes
 * to that pipe only when its send failed. */
static int await_signal(int count, int control) {
    char byte;
    while (taken < count)
        if (read(control, &byte, 1) == 1) return 0;
    return 1;
}

int main(void) {
    int ready[2], control[2];
    if (pipe(ready) || pipe2(control, O_NONBLOCK)) return 2;
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = handler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) || sigaction(SIGUSR2, &action, NULL)) return 3;
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) return 4;
    if (child == 0) {
        char line[160];
        for (int index = 0; index < 2; index++) {
            if (write(ready[1], "r", 1) != 1) _exit(121);
            if (await_signal(index + 1, control[0]))
                snprintf(line, sizeof line, "child: signal=%d code=%d from_parent=%d uid=%u\n",
                         numbers[index], codes[index], senders[index] == parent, uids[index]);
            else
                snprintf(line, sizeof line, "child: send %d failed\n", index + 1);
            say(line);
        }
        _exit(0);
    }
    int results[2];
    char byte;
    for (int index = 0; index < 2; index++) {
        if (read(ready[0], &byte, 1) != 1) return 5;
        int sent = index == 0 ? kill(child, SIGUSR1)
                              : (int)syscall(SYS_tgkill, child, child, SIGUSR2);
        results[index] = sent == 0 ? 0 : -errno;
        if (sent != 0 && write(control[1], "q", 1) != 1) return 6;
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) return 7;
    char line[160];
    snprintf(line, sizeof line, "parent: kill=%d tgkill=%d child_exited=%d\n", results[0],
             results[1], WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    say(line);
    return 0;
}
"#;

/// What the program prints when both signals reach the child, whose
/// handler sees `uid` as the sender's real uid.
fn delivered_stdout(uid: u32) -> String {
    format!(
        "child: signal={} code={} from_parent=1 uid={uid}\n\
         child: signal={} code={} from_parent=1 uid={uid}\n\
         parent: kill=0 tgkill=0 child_exited=0\n",
        libc::SIGUSR1,
        libc::SI_USER,
        libc::SIGUSR2,
        libc::SI_TKILL,
    )
}

const REFUSED_STDOUT: &str = "\
child: send 1 failed
child: send 2 failed
parent: kill=-38 tgkill=-38 child_exited=0
";

const PIDFD_SEND_SIGNAL_SOURCE: &str = r#"#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t taken;
static volatile int number, code, sender;

static void handler(int signal, siginfo_t *info, void *context) {
    (void)context;
    number = signal;
    code = info->si_code;
    sender = info->si_pid;
    taken++;
}

static void say(const char *text) {
    size_t length = strlen(text);
    if (write(STDOUT_FILENO, text, length) != (ssize_t)length) _exit(120);
}

static int open_pidfd(pid_t pid) { return (int)syscall(SYS_pidfd_open, pid, 0); }

/* 0, or the negated errno of a failed pidfd_send_signal. */
static int send_through(int pidfd, int signal) {
    return syscall(SYS_pidfd_send_signal, pidfd, signal, NULL, 0) == 0 ? 0 : -errno;
}

int main(void) {
    int ready[2], control[2];
    if (pipe(ready) || pipe2(control, O_NONBLOCK)) return 2;
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = handler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) || sigaction(SIGUSR2, &action, NULL)) return 3;
    char line[200];

    /* The caller's own pidfd: the signal is taken on the call's return. */
    pid_t self = getpid();
    int own = open_pidfd(self);
    if (own < 0) return 4;
    int probe = send_through(own, 0);
    int sent = send_through(own, SIGUSR1);
    snprintf(line, sizeof line, "self: probe=%d send=%d taken=%d signal=%d code=%d from_self=%d\n",
             probe, sent, (int)taken, number, code, sender == self);
    say(line);

    pid_t child = fork();
    if (child < 0) return 5;
    if (child == 0) {
        char byte;
        taken = 0;
        if (write(ready[1], "r", 1) != 1) _exit(121);
        /* Runnable until the signal arrives, or the parent's send failed. */
        while (!taken)
            if (read(control[0], &byte, 1) == 1) break;
        snprintf(line, sizeof line, "child: taken=%d signal=%d code=%d from_parent=%d\n",
                 (int)taken, number, code, sender == self);
        say(line);
        _exit(0);
    }
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 6;
    int pidfd = open_pidfd(child);
    if (pidfd < 0) return 7;
    int child_probe = send_through(pidfd, 0);
    int child_sent = send_through(pidfd, SIGUSR2);
    if (child_sent != 0 && write(control[1], "q", 1) != 1) return 8;
    /* Exited, not yet reaped: the send answers 0 and drops the signal. */
    siginfo_t exited;
    memset(&exited, 0, sizeof exited);
    if (waitid(P_PID, child, &exited, WEXITED | WNOWAIT)) return 9;
    int zombie_probe = send_through(pidfd, 0);
    int zombie_sent = send_through(pidfd, SIGUSR2);
    int status = 0;
    if (waitpid(child, &status, 0) != child) return 10;
    int reaped_probe = send_through(pidfd, 0);
    int reaped_sent = send_through(pidfd, SIGUSR2);
    snprintf(line, sizeof line,
             "parent: probe=%d send=%d zombie=%d,%d reaped=%d,%d child_exited=%d\n",
             child_probe, child_sent, zombie_probe, zombie_sent, reaped_probe, reaped_sent,
             WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    say(line);
    return 0;
}
"#;

/// What the pidfd program prints on Linux.
fn pidfd_stdout() -> String {
    format!(
        "self: probe=0 send=0 taken=1 signal={} code={} from_self=1\n\
         child: taken=1 signal={} code={} from_parent=1\n\
         parent: probe=0 send=0 zombie=0,0 reaped={esrch},{esrch} child_exited=0\n",
        libc::SIGUSR1,
        libc::SI_USER,
        libc::SIGUSR2,
        libc::SI_USER,
        esrch = -libc::ESRCH,
    )
}

const PIDFD_SELF_SOURCE: &str = r#"#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile sig_atomic_t taken;
static volatile int number, code, sender;

static void handler(int signal, siginfo_t *info, void *context) {
    (void)context;
    number = signal;
    code = info->si_code;
    sender = info->si_pid;
    taken++;
}

static void say(const char *text) {
    size_t length = strlen(text);
    if (write(STDOUT_FILENO, text, length) != (ssize_t)length) _exit(120);
}

/* 0, or the negated errno of a failed pidfd_send_signal. */
static int send_through(int pidfd, int signal) {
    return syscall(SYS_pidfd_send_signal, pidfd, signal, NULL, 0) == 0 ? 0 : -errno;
}

static void report(const char *name, int sent) {
    char line[160];
    snprintf(line, sizeof line, "%s: send=%d taken=%d signal=%d code=%d from_self=%d\n", name,
             sent, (int)taken, number, code, sender == getpid());
    say(line);
}

int main(void) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = handler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) || sigaction(SIGUSR2, &action, NULL)) return 2;
    /* PIDFD_SELF_THREAD and PIDFD_SELF_THREAD_GROUP as Linux 6.17 spells them,
     * then the thread group sentinel as Linux 6.15 and 6.16 spell it. */
    report("thread", send_through(-10000, SIGUSR1));
    report("group", send_through(-10001, SIGUSR2));
    report("legacy group", send_through(-20000, SIGUSR1));
    return 0;
}
"#;

/// What the self-sentinel program prints on Linux 6.17 and later, and under
/// LinuxEmu on any host.
fn pidfd_self_stdout() -> String {
    format!(
        "thread: send=0 taken=1 signal={} code={} from_self=1\n\
         group: send=0 taken=2 signal={} code={} from_self=1\n\
         legacy group: send={} taken=2 signal={} code={} from_self=1\n",
        libc::SIGUSR1,
        libc::SI_TKILL,
        libc::SIGUSR2,
        libc::SI_USER,
        -libc::EBADF,
        libc::SIGUSR2,
        libc::SI_USER,
    )
}

const SIGINFO_LAYOUT_SOURCE: &str = r#"#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* sizeof(struct kernel_siginfo): the part of a siginfo_t every call copies. */
#define COPIED 48
#define UNREADABLE (-2)
#define ZEROS (-1)

static long page;
static char *pages;
static int own_pidfd;

static void say(const char *text) {
    size_t length = strlen(text);
    if (write(STDOUT_FILENO, text, length) != (ssize_t)length) _exit(120);
}

/* A siginfo_t whose first COPIED bytes end where the first page does, so the
 * rest of it lies in the second page: unreadable, all zeros, or zeros with a
 * 1 at `tail` bytes past the copied part. */
static siginfo_t *place(int signo, int code, int tail) {
    char *start = pages + page - COPIED;
    if (mprotect(pages + page, page, tail == UNREADABLE ? PROT_NONE : PROT_READ | PROT_WRITE))
        _exit(121);
    memset(start, 0, COPIED);
    memcpy(start, &signo, sizeof signo);
    memcpy(start + 8, &code, sizeof code);
    if (tail != UNREADABLE) {
        memset(pages + page, 0, page);
        if (tail >= 0) pages[page + tail] = 1;
    }
    return (siginfo_t *)start;
}

/* Each sends signal 0, which only checks, and gives 0 or the negated errno. */
static int pidfd(int signo, int code, int tail) {
    siginfo_t *info = place(signo, code, tail);
    return syscall(SYS_pidfd_send_signal, own_pidfd, 0, info, 0) == 0 ? 0 : -errno;
}

static int queue(int signo, int code, int tail) {
    siginfo_t *info = place(signo, code, tail);
    return syscall(SYS_rt_sigqueueinfo, getpid(), 0, info) == 0 ? 0 : -errno;
}

static int tgqueue(int signo, int code, int tail) {
    siginfo_t *info = place(signo, code, tail);
    pid_t tid = (pid_t)syscall(SYS_gettid);
    return syscall(SYS_rt_tgsigqueueinfo, getpid(), tid, 0, info) == 0 ? 0 : -errno;
}

static void report_queue(const char *name, int (*send)(int, int, int)) {
    char line[200];
    int unreadable = send(0, -1000, UNREADABLE);
    int zeros = send(0, -1000, ZEROS);
    int first = send(0, -1000, 0);
    int known = send(0, SI_QUEUE, UNREADABLE);
    /* The layout is judged by the signal argument, which Linux stores over
     * the record's si_signo: 7 is a SIGSEGV code, but no code of signal 0. */
    int argument = send(SIGSEGV, 7, UNREADABLE);
    snprintf(line, sizeof line, "%s: unreadable=%d zeros=%d first=%d known=%d signal_argument=%d\n",
             name, unreadable, zeros, first, known, argument);
    say(line);
}

int main(void) {
    char line[200];
    page = sysconf(_SC_PAGESIZE);
    pages = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pages == MAP_FAILED) return 2;
    own_pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (own_pidfd < 0) return 3;

    /* An si_code Linux knows no layout for: the rest must be readable and
     * zero, up to the end of the 128-byte record and no further. */
    int unreadable = pidfd(0, -1000, UNREADABLE);
    int zeros = pidfd(0, -1000, ZEROS);
    int first = pidfd(0, -1000, 0);
    int last = pidfd(0, -1000, 128 - COPIED - 1);
    int beyond = pidfd(0, -1000, 128 - COPIED);
    snprintf(line, sizeof line, "pidfd unknown: unreadable=%d zeros=%d first=%d last=%d beyond=%d\n",
             unreadable, zeros, first, last, beyond);
    say(line);

    /* Codes with a known layout read nothing past the copied part. */
    int user = pidfd(0, SI_USER, UNREADABLE);
    int user_nonzero = pidfd(0, SI_USER, 0);
    int queued = pidfd(0, SI_QUEUE, UNREADABLE);
    int dethread = pidfd(0, SI_DETHREAD, UNREADABLE);
    int asyncnl = pidfd(0, SI_ASYNCNL, UNREADABLE);
    int kernel = pidfd(0, SI_KERNEL, UNREADABLE);
    int below = pidfd(0, SI_DETHREAD - 1, UNREADABLE);
    snprintf(line, sizeof line,
             "pidfd known: user=%d,%d queue=%d dethread=%d asyncnl=%d kernel=%d "
             "below_dethread=%d\n",
             user, user_nonzero, queued, dethread, asyncnl, kernel, below);
    say(line);

    /* A positive code is known up to its signal's last code (6 for SIGCHLD,
     * and for a signal with no codes of its own), judged by the record's own
     * si_signo, which then fails to match signal 0. */
    int chld = pidfd(SIGCHLD, 6, UNREADABLE);
    int chld_over = pidfd(SIGCHLD, 7, UNREADABLE);
    int usr1 = pidfd(SIGUSR1, 6, UNREADABLE);
    int usr1_over = pidfd(SIGUSR1, 7, UNREADABLE);
    int segv = pidfd(SIGSEGV, 7, UNREADABLE);
    snprintf(line, sizeof line, "pidfd limits: chld=%d,%d usr1=%d,%d segv=%d\n", chld, chld_over,
             usr1, usr1_over, segv);
    say(line);

    /* The layout is checked before si_signo is compared with the signal. */
    int unknown_mismatch = pidfd(SIGUSR1, -1000, 0);
    int known_mismatch = pidfd(SIGUSR1, SI_QUEUE, UNREADABLE);
    snprintf(line, sizeof line, "pidfd order: unknown=%d known=%d\n", unknown_mismatch,
             known_mismatch);
    say(line);

    report_queue("rt_sigqueueinfo", queue);
    report_queue("rt_tgsigqueueinfo", tgqueue);
    return 0;
}
"#;

/// What the siginfo layout program prints on Linux.
fn siginfo_layout_stdout() -> String {
    let (efault, e2big, einval) = (-libc::EFAULT, -libc::E2BIG, -libc::EINVAL);
    format!(
        "pidfd unknown: unreadable={efault} zeros=0 first={e2big} last={e2big} beyond=0\n\
         pidfd known: user=0,0 queue=0 dethread=0 asyncnl=0 kernel=0 \
         below_dethread={efault}\n\
         pidfd limits: chld={einval},{efault} usr1={einval},{efault} segv={einval}\n\
         pidfd order: unknown={e2big} known={einval}\n\
         rt_sigqueueinfo: unreadable={efault} zeros=0 first={e2big} known=0 \
         signal_argument={efault}\n\
         rt_tgsigqueueinfo: unreadable={efault} zeros=0 first={e2big} known=0 \
         signal_argument={efault}\n"
    )
}

/// What the Tool reports to its global state.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
enum CrossProcessReport {
    /// A refusal of the guest's send, as `operation: diagnostic`.
    Refusal(String),
    /// The pidfd self-sentinel spelling the guest declared at a
    /// `pidfd_send_signal`, as its `Debug` text.
    Spelling(String),
}

const OTHER_PROCESS_REFUSAL: &str =
    "Signal: KVM signal delivery refused: KVM cannot deliver a signal to another process";

/// Grants a delivery permit at every signal boundary, as a scheduler does for
/// its running task, and asks for cross-process signals when configured to.
/// It records the receipts that settle its permits, the refusals of the
/// guest's sends, and the pidfd self-sentinel spelling the backend declares.
#[derive(Debug, Default)]
struct CrossProcessGlobal {
    ask: bool,
    control: Mutex<Option<BackendSignalControl>>,
    sequence: AtomicU64,
    receipts: Mutex<Vec<reverie::SignalBoundaryReceipt>>,
    refusals: Mutex<Vec<String>>,
    spellings: Mutex<Vec<String>>,
}

#[reverie::global_tool]
impl GlobalTool for CrossProcessGlobal {
    type Request = CrossProcessReport;
    type Response = ();
    type Config = bool;

    async fn init_global_state(ask: &bool) -> Self {
        Self {
            ask: *ask,
            ..Self::default()
        }
    }

    async fn receive_rpc(&self, _: Pid, report: CrossProcessReport) {
        match report {
            CrossProcessReport::Refusal(refusal) => self.refusals.lock().unwrap().push(refusal),
            CrossProcessReport::Spelling(spelling) => self.spellings.lock().unwrap().push(spelling),
        }
    }

    fn install_backend_signal_control(
        &self,
        control: Option<BackendSignalControl>,
    ) -> Result<BackendSignalControlMode, reverie::Error> {
        let control = control.ok_or(Errno::ENOSYS)?;
        if self.ask {
            control.process.enable_cross_process_signals()?;
        }
        *self.control.lock().unwrap() = Some(control);
        Ok(BackendSignalControlMode::ToolControlled)
    }

    fn authorize_backend_signal_boundary(
        &self,
        task: reverie::SignalTaskIdentity,
    ) -> Result<Option<SignalDeliveryPermit>, reverie::Error> {
        let control = self.control.lock().unwrap().clone().unwrap();
        let permit = SignalDeliveryPermit {
            task,
            sequence: self.sequence.fetch_add(1, Ordering::SeqCst) + 1,
            site: None,
        };
        control.process.reserve_delivery(permit)?;
        Ok(Some(permit))
    }

    async fn on_backend_signal_boundary(
        &self,
        receipt: reverie::SignalBoundaryReceipt,
    ) -> Result<(), reverie::Error> {
        self.receipts.lock().unwrap().push(receipt);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct CrossProcessTool;

#[reverie::tool]
impl Tool for CrossProcessTool {
    type GlobalState = CrossProcessGlobal;
    type ThreadState = ();

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        if matches!(
            syscall.number(),
            Sysno::kill | Sysno::tgkill | Sysno::pidfd_send_signal
        ) {
            if syscall.number() == Sysno::pidfd_send_signal {
                let spelling = format!("{:?}", guest.pidfd_self_spelling());
                guest.send_rpc(CrossProcessReport::Spelling(spelling)).await;
            }
            let sent = guest.inject(syscall).await;
            if let Some(refusal) = guest.take_unsupported_refusal() {
                let refusal = format!("{:?}: {}", refusal.operation, refusal.diagnostic);
                guest.send_rpc(CrossProcessReport::Refusal(refusal)).await;
            }
            return Ok(sent?);
        }
        guest.tail_inject(syscall).await
    }
}

fn cross_process_program(
    directory: &TestDirectory,
    name: &str,
    source: &str,
) -> (PathBuf, Vec<u8>) {
    let executable = compile_c_program(&directory.0, name, source);
    let image = std::fs::read(&executable).unwrap();
    (executable, image)
}

fn run_cross_process_program(name: &str, source: &str, ask: bool) -> (String, CrossProcessGlobal) {
    let directory = TestDirectory::new();
    let (executable, image) = cross_process_program(&directory, name, source);
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            &image,
            &[executable.to_str().unwrap()],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
    let completion = futures::executor::block_on(
        backend.run_static_elf_with_tool_completion::<CrossProcessTool>(ask, true),
    )
    .unwrap();
    let (status, stdout, stderr) = completion.result.unwrap();
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(status, ExitStatus::Exited(0));
    (
        String::from_utf8_lossy(&stdout).into_owned(),
        completion.global_state,
    )
}

#[test]
fn kill_and_tgkill_reach_another_process_when_the_tool_asks() {
    if !kvm_available("kill_and_tgkill_reach_another_process_when_the_tool_asks") {
        return;
    }
    let directory = TestDirectory::new();
    let (executable, _) = cross_process_program(
        &directory,
        "cross-process-signals",
        CROSS_PROCESS_SIGNAL_SOURCE,
    );
    let native = std::process::Command::new(&executable).output().unwrap();
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        delivered_stdout(uid),
        "native Linux is the oracle; stderr={}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.status.code(), Some(0));

    let (stdout, global) =
        run_cross_process_program("cross-process-signals", CROSS_PROCESS_SIGNAL_SOURCE, true);
    // LinuxEmu's guests have the fixed real uid 0, so the sender's si_uid is
    // 0 where a native sender's is its own uid; everything else matches.
    assert_eq!(stdout, delivered_stdout(0));
    let refusals = global.refusals.lock().unwrap();
    assert!(refusals.is_empty(), "{refusals:?}");
    // The child takes each signal in its handler, at a boundary the Tool
    // permitted for the child's own task.
    let receipts = global.receipts.lock().unwrap();
    let caught = receipts
        .iter()
        .filter(|receipt| receipt.outcome == reverie::SignalBoundaryOutcome::Caught)
        .collect::<Vec<_>>();
    assert_eq!(caught.len(), 2, "receipts: {receipts:?}");
    assert!(
        caught
            .iter()
            .all(|receipt| receipt.permit.task.tid != Pid::from_raw(1)),
        "receipts: {receipts:?}"
    );
}

#[test]
fn kill_and_tgkill_to_another_process_are_refused_unless_the_tool_asks() {
    if !kvm_available("kill_and_tgkill_to_another_process_are_refused_unless_the_tool_asks") {
        return;
    }
    let (stdout, global) =
        run_cross_process_program("cross-process-signals", CROSS_PROCESS_SIGNAL_SOURCE, false);
    assert_eq!(stdout, REFUSED_STDOUT);
    assert_eq!(
        *global.refusals.lock().unwrap(),
        [OTHER_PROCESS_REFUSAL, OTHER_PROCESS_REFUSAL]
    );
    let receipts = global.receipts.lock().unwrap();
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.outcome != reverie::SignalBoundaryOutcome::Caught),
        "receipts: {receipts:?}"
    );
}

#[test]
fn pidfd_send_signal_reaches_the_caller_and_its_child_as_on_linux() {
    if !kvm_available("pidfd_send_signal_reaches_the_caller_and_its_child_as_on_linux") {
        return;
    }
    let directory = TestDirectory::new();
    let (executable, _) =
        cross_process_program(&directory, "pidfd-send-signal", PIDFD_SEND_SIGNAL_SOURCE);
    let native = std::process::Command::new(&executable).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        pidfd_stdout(),
        "native Linux is the oracle; stderr={}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.status.code(), Some(0));

    let (stdout, global) =
        run_cross_process_program("pidfd-send-signal", PIDFD_SEND_SIGNAL_SOURCE, true);
    assert_eq!(stdout, pidfd_stdout());
    let refusals = global.refusals.lock().unwrap();
    assert!(refusals.is_empty(), "{refusals:?}");
    // The caller takes its own signal, and the child its parent's, each at a
    // boundary the Tool permitted for its own task.
    let receipts = global.receipts.lock().unwrap();
    let caught = receipts
        .iter()
        .filter(|receipt| receipt.outcome == reverie::SignalBoundaryOutcome::Caught)
        .map(|receipt| receipt.permit.task.tid == Pid::from_raw(1))
        .collect::<Vec<_>>();
    assert_eq!(caught, [true, false], "receipts: {receipts:?}");
}

#[test]
fn pidfd_send_signal_takes_the_self_sentinels_as_linux_6_17_spells_them() {
    if !kvm_available("pidfd_send_signal_takes_the_self_sentinels_as_linux_6_17_spells_them") {
        return;
    }
    let (stdout, global) = run_cross_process_program("pidfd-self", PIDFD_SELF_SOURCE, false);
    assert_eq!(stdout, pidfd_self_stdout());
    let refusals = global.refusals.lock().unwrap();
    assert!(refusals.is_empty(), "{refusals:?}");
    // The backend declares the spelling its executor takes, so a Tool that
    // forwards a guest's sentinel forwards it unchanged.
    assert_eq!(*global.spellings.lock().unwrap(), ["Modern"; 3]);
}

/// A siginfo a caller passes to `pidfd_send_signal`, `rt_sigqueueinfo` or
/// `rt_tgsigqueueinfo` with an `si_code` whose layout Linux does not know for
/// its signal must be readable and zero past the 48 bytes Linux copies
/// (`post_copy_siginfo_from_user`): an unreadable rest is EFAULT and a nonzero
/// byte E2BIG, both before `pidfd_send_signal` compares `si_signo` with the
/// signal. `pidfd_send_signal` judges the layout by the record's own
/// `si_signo`, the other two by their signal argument.
#[test]
fn a_siginfo_of_unknown_layout_must_end_in_zeros_as_on_linux() {
    if !kvm_available("a_siginfo_of_unknown_layout_must_end_in_zeros_as_on_linux") {
        return;
    }
    let directory = TestDirectory::new();
    let (executable, _) =
        cross_process_program(&directory, "siginfo-layout", SIGINFO_LAYOUT_SOURCE);
    let native = std::process::Command::new(&executable).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        siginfo_layout_stdout(),
        "native Linux is the oracle; stderr={}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.status.code(), Some(0));

    let (stdout, global) =
        run_cross_process_program("siginfo-layout", SIGINFO_LAYOUT_SOURCE, false);
    assert_eq!(stdout, siginfo_layout_stdout());
    let refusals = global.refusals.lock().unwrap();
    assert!(refusals.is_empty(), "{refusals:?}");
}
