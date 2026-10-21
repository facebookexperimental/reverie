/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! User-mode CPU exceptions become the signals Linux's x86 trap handlers raise:
//! #UD is SIGILL/ILL_ILLOPN, #DE is SIGFPE/FPE_INTDIV, and a page-zero #PF is
//! SIGSEGV/SEGV_MAPERR. Every observable is compared byte-for-byte with the
//! same binary run natively, under the direct runtime, under a Tool, and under
//! a Tool that controls signal delivery with permits.

use super::*;

const HARDWARE_TRAP_SOURCE: &str = r#"#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

extern char ud2_site[], div_site[], idiv_site[], resume_site[];

__attribute__((noinline, noclone)) static void trap_ud2(void) {
    __asm__ volatile(".globl ud2_site\nud2_site: ud2");
}

__attribute__((noinline, noclone)) static void trap_div(void) {
    __asm__ volatile(
        "xorl %%edx, %%edx\n\tmovl $1, %%eax\n\txorl %%ecx, %%ecx\n\t"
        ".globl div_site\ndiv_site: divl %%ecx"
        ::: "eax", "ecx", "edx", "cc");
}

/* INT_MIN / -1 overflows the quotient: also #DE, also FPE_INTDIV on Linux. */
__attribute__((noinline, noclone)) static void trap_idiv(void) {
    __asm__ volatile(
        "movl $0x80000000, %%eax\n\tcltd\n\tmovl $-1, %%ecx\n\t"
        ".globl idiv_site\nidiv_site: idivl %%ecx"
        ::: "eax", "ecx", "edx", "cc");
}

__attribute__((noinline, noclone)) static void trap_null(void) {
    *(volatile int *)0 = 1;
}

/* RCX and R11 hold live values across the trap. SYSRET would overwrite
 * them with RIP and RFLAGS, so a faithful return must not use it. */
__attribute__((noinline, noclone)) static int trap_resume(void) {
    unsigned long rcx, r11;
    __asm__ volatile(
        "movabs $0x1122334455667788, %%rcx\n\tmovabs $0x0123456789abcdef, %%r11\n\t"
        ".globl resume_site\nresume_site: ud2\n\t"
        "mov %%rcx, %0\n\tmov %%r11, %1"
        : "=r"(rcx), "=r"(r11) :: "rcx", "r11");
    return rcx == 0x1122334455667788UL && r11 == 0x0123456789abcdefUL;
}

/* A handler that advances RIP past the ud2 resumes after it. */
static void resume_handler(int number, siginfo_t *info, void *context) {
    greg_t *registers = ((ucontext_t *)context)->uc_mcontext.gregs;
    if (number != SIGILL || info->si_addr != resume_site ||
        (char *)registers[REG_RIP] != resume_site) _exit(127);
    registers[REG_RIP] += 2;
}

struct trap {
    const char *name;
    void (*body)(void);
    int signal;
    int code;
    int trapno;
    int err;
    const char *site; /* faulting instruction, or NULL for a data fault */
};

static const struct trap TRAPS[] = {
    {"ud2", trap_ud2, SIGILL, ILL_ILLOPN, 6, 0, ud2_site},
    {"div", trap_div, SIGFPE, FPE_INTDIV, 0, 0, div_site},
    {"idiv", trap_idiv, SIGFPE, FPE_INTDIV, 0, 0, idiv_site},
    /* write | user, not present */
    {"null", trap_null, SIGSEGV, SEGV_MAPERR, 14, 6, NULL},
};

static const struct trap *current;
static sigjmp_buf recover;
static volatile int entries;

static void say(const char *text) {
    size_t length = strlen(text);
    if (write(STDOUT_FILENO, text, length) != (ssize_t)length) _exit(120);
}

static void handler(int number, siginfo_t *info, void *context) {
    greg_t *registers = ((ucontext_t *)context)->uc_mcontext.gregs;
    const struct trap *trap = current;
    const char *expected_addr = trap->site ? trap->site : NULL;
    char line[256];
    entries++;
    snprintf(line, sizeof line,
             "%s: entry=%d signo_ok=%d code_ok=%d addr_ok=%d rip_ok=%d trapno_ok=%d err_ok=%d cr2_ok=%d\n",
             trap->name, entries, number == trap->signal, info->si_code == trap->code,
             info->si_addr == expected_addr,
             trap->site ? (char *)registers[REG_RIP] == trap->site : registers[REG_RIP] != 0,
             registers[REG_TRAPNO] == trap->trapno, registers[REG_ERR] == trap->err,
             trap->site ? 1 : registers[REG_CR2] == 0);
    say(line);
    /* The first return re-executes the faulting instruction, which therefore
     * faults again; the second entry leaves through siglongjmp. */
    if (entries == 2) siglongjmp(recover, 1);
}

static void caught(const struct trap *trap) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = handler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(trap->signal, &action, NULL)) _exit(121);
    current = trap;
    entries = 0;
    if (sigsetjmp(recover, 1) == 0) {
        trap->body();
        say("FAIL: the faulting instruction retired\n");
    }
    signal(trap->signal, SIG_DFL);
}

/* A child traps with the named disposition; the parent decodes its status. */
static void killed(const struct trap *trap, const char *how) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) _exit(122);
    if (pid == 0) {
        /* No core file, so the wait status does not depend on the host. */
        if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) _exit(123);
        if (strcmp(how, "ignored") == 0) {
            if (signal(trap->signal, SIG_IGN) == SIG_ERR) _exit(124);
        } else if (strcmp(how, "blocked") == 0) {
            struct sigaction action;
            memset(&action, 0, sizeof action);
            action.sa_sigaction = handler;
            action.sa_flags = SA_SIGINFO;
            sigemptyset(&action.sa_mask);
            sigset_t blocked;
            sigemptyset(&blocked);
            sigaddset(&blocked, trap->signal);
            if (sigaction(trap->signal, &action, NULL) ||
                sigprocmask(SIG_BLOCK, &blocked, NULL)) _exit(125);
            current = trap;
        }
        trap->body();
        _exit(99);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) _exit(126);
    char line[160];
    snprintf(line, sizeof line, "%s/%s: signaled=%d sig=%d core=%d exited=%d\n", trap->name,
             how, WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : 0,
             WIFSIGNALED(status) ? WCOREDUMP(status) != 0 : 0,
             WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    say(line);
}

int main(void) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = resume_handler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGILL, &action, NULL)) return 2;
    char line[64];
    snprintf(line, sizeof line, "resume: registers_ok=%d\n", trap_resume());
    say(line);
    signal(SIGILL, SIG_DFL);
    for (size_t index = 0; index < sizeof TRAPS / sizeof TRAPS[0]; ++index) {
        caught(&TRAPS[index]);
        killed(&TRAPS[index], "default");
        killed(&TRAPS[index], "ignored");
        killed(&TRAPS[index], "blocked");
    }
    say("done\n");
    return 0;
}
"#;

const EXPECTED_STDOUT: &str = "\
resume: registers_ok=1
ud2: entry=1 signo_ok=1 code_ok=1 addr_ok=1 rip_ok=1 trapno_ok=1 err_ok=1 cr2_ok=1
ud2: entry=2 signo_ok=1 code_ok=1 addr_ok=1 rip_ok=1 trapno_ok=1 err_ok=1 cr2_ok=1
ud2/default: signaled=1 sig=4 core=0 exited=-1
ud2/ignored: signaled=1 sig=4 core=0 exited=-1
ud2/blocked: signaled=1 sig=4 core=0 exited=-1
div: entry=1 signo_ok=1 code_ok=1 addr_ok=1 rip_ok=1 trapno_ok=1 err_ok=1 cr2_ok=1
div: entry=2 signo_ok=1 code_ok=1 addr_ok=1 rip_ok=1 trapno_ok=1 err_ok=1 cr2_ok=1
div/default: signaled=1 sig=8 core=0 exited=-1
div/ignored: signaled=1 sig=8 core=0 exited=-1
div/blocked: signaled=1 sig=8 core=0 exited=-1
idiv: entry=1 signo_ok=1 code_ok=1 addr_ok=1 rip_ok=1 trapno_ok=1 err_ok=1 cr2_ok=1
idiv: entry=2 signo_ok=1 code_ok=1 addr_ok=1 rip_ok=1 trapno_ok=1 err_ok=1 cr2_ok=1
idiv/default: signaled=1 sig=8 core=0 exited=-1
idiv/ignored: signaled=1 sig=8 core=0 exited=-1
idiv/blocked: signaled=1 sig=8 core=0 exited=-1
null: entry=1 signo_ok=1 code_ok=1 addr_ok=1 rip_ok=1 trapno_ok=1 err_ok=1 cr2_ok=1
null: entry=2 signo_ok=1 code_ok=1 addr_ok=1 rip_ok=1 trapno_ok=1 err_ok=1 cr2_ok=1
null/default: signaled=1 sig=11 core=0 exited=-1
null/ignored: signaled=1 sig=11 core=0 exited=-1
null/blocked: signaled=1 sig=11 core=0 exited=-1
done
";

fn hardware_trap_program(directory: &TestDirectory) -> (PathBuf, Vec<u8>) {
    let executable = compile_c_program(&directory.0, "hardware-traps", HARDWARE_TRAP_SOURCE);
    let image = std::fs::read(&executable).unwrap();
    (executable, image)
}

fn install_hardware_trap_program(
    backend: &mut KvmBackend,
    executable: &std::path::Path,
    image: &[u8],
    directory: &TestDirectory,
) {
    backend
        .install_static_elf_with_context(
            image,
            &[executable.to_str().unwrap()],
            &["PATH=/usr/bin:/bin"],
            &directory.0,
        )
        .unwrap();
}

#[test]
fn hardware_traps_match_native_linux() {
    if !kvm_available("hardware_traps_match_native_linux") {
        return;
    }
    let directory = TestDirectory::new();
    let (executable, image) = hardware_trap_program(&directory);

    let native = std::process::Command::new(&executable).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        EXPECTED_STDOUT,
        "native Linux is the oracle; stderr={}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.status.code(), Some(0));

    let mut direct = KvmBackend::new(256 * 1024 * 1024).unwrap();
    install_hardware_trap_program(&mut direct, &executable, &image, &directory);
    let (code, stdout, stderr) = direct.run_static_elf_captured().unwrap();
    assert_eq!(String::from_utf8_lossy(&stdout), EXPECTED_STDOUT);
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(code, 0);

    let mut tool = KvmBackend::new(256 * 1024 * 1024).unwrap();
    install_hardware_trap_program(&mut tool, &executable, &image, &directory);
    let completion = futures::executor::block_on(
        tool.run_static_elf_with_tool_completion::<StraceTool>((), true),
    )
    .unwrap();
    let (status, stdout, stderr) = completion.result.unwrap();
    assert_eq!(String::from_utf8_lossy(&stdout), EXPECTED_STDOUT);
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(status, ExitStatus::Exited(0));
}

/// Grants a delivery permit at every signal boundary, as a scheduler does for
/// its running task, and records the receipts that settle them.
#[derive(Debug, Default)]
struct TrapPermitGlobal {
    control: Mutex<Option<BackendSignalControl>>,
    sequence: AtomicU64,
    receipts: Mutex<Vec<reverie::SignalBoundaryReceipt>>,
}

#[reverie::global_tool]
impl GlobalTool for TrapPermitGlobal {
    type Request = ();
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _: Pid, _: ()) {}

    fn install_backend_signal_control(
        &self,
        control: Option<BackendSignalControl>,
    ) -> Result<BackendSignalControlMode, reverie::Error> {
        *self.control.lock().unwrap() = Some(control.ok_or(Errno::ENOSYS)?);
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
struct TrapPermitTool;

#[reverie::tool]
impl Tool for TrapPermitTool {
    type GlobalState = TrapPermitGlobal;
    type ThreadState = ();
}

#[test]
fn hardware_traps_settle_tool_delivery_permits() {
    if !kvm_available("hardware_traps_settle_tool_delivery_permits") {
        return;
    }
    let directory = TestDirectory::new();
    let (executable, image) = hardware_trap_program(&directory);
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    install_hardware_trap_program(&mut backend, &executable, &image, &directory);
    let completion = futures::executor::block_on(
        backend.run_static_elf_with_tool_completion::<TrapPermitTool>((), true),
    )
    .unwrap();
    let (status, stdout, stderr) = completion.result.unwrap();
    assert_eq!(String::from_utf8_lossy(&stdout), EXPECTED_STDOUT);
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(status, ExitStatus::Exited(0));

    let receipts = completion.global_state.receipts.lock().unwrap();
    let root = Pid::from_raw(1);
    // The resuming ud2 enters its handler once and each of the four caught
    // traps enters its handler twice. Every entry settles its permit with a
    // Caught receipt from the faulting root task.
    let caught = receipts
        .iter()
        .filter(|receipt| receipt.outcome == reverie::SignalBoundaryOutcome::Caught)
        .collect::<Vec<_>>();
    assert_eq!(caught.len(), 9, "receipts: {receipts:?}");
    assert!(caught.iter().all(|receipt| receipt.permit.task.tid == root));
    // Each of the twelve killed children reports its own death, with the wait
    // status its parent decodes, before that parent can reap it.
    let mut deaths = receipts
        .iter()
        .filter_map(|receipt| match receipt.outcome {
            reverie::SignalBoundaryOutcome::Terminated { group, wait_status } => {
                assert!(group, "a trap kills the whole thread group");
                assert_ne!(receipt.permit.task.tid, root);
                Some(wait_status)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    deaths.sort_unstable();
    let mut expected = [libc::SIGILL; 3]
        .into_iter()
        .chain([libc::SIGFPE; 6])
        .chain([libc::SIGSEGV; 3])
        .collect::<Vec<_>>();
    expected.sort_unstable();
    assert_eq!(deaths, expected, "receipts: {receipts:?}");
}
