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
//! for an exited and a reaped child as Linux does. Every observable is
//! compared with the same binary run natively.

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

const OTHER_PROCESS_REFUSAL: &str =
    "Signal: KVM signal delivery refused: KVM cannot deliver a signal to another process";

/// Grants a delivery permit at every signal boundary, as a scheduler does for
/// its running task, and asks for cross-process signals when configured to.
/// It records the receipts that settle its permits and the refusals of the
/// guest's sends.
#[derive(Debug, Default)]
struct CrossProcessGlobal {
    ask: bool,
    control: Mutex<Option<BackendSignalControl>>,
    sequence: AtomicU64,
    receipts: Mutex<Vec<reverie::SignalBoundaryReceipt>>,
    refusals: Mutex<Vec<String>>,
}

#[reverie::global_tool]
impl GlobalTool for CrossProcessGlobal {
    type Request = String;
    type Response = ();
    type Config = bool;

    async fn init_global_state(ask: &bool) -> Self {
        Self {
            ask: *ask,
            ..Self::default()
        }
    }

    async fn receive_rpc(&self, _: Pid, refusal: String) {
        self.refusals.lock().unwrap().push(refusal);
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
            let sent = guest.inject(syscall).await;
            if let Some(refusal) = guest.take_unsupported_refusal() {
                guest
                    .send_rpc(format!("{:?}: {}", refusal.operation, refusal.diagnostic))
                    .await;
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
