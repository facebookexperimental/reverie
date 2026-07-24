use core::arch::global_asm;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;
use std::ffi::OsStr;
use std::io;
use std::ptr;

use crate::pun::PunProbe;

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_IP_LOW_OFFSET: u32 = 8;
const SECCOMP_DATA_IP_HIGH_OFFSET: u32 = 12;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const UNSET_RESULT: i64 = i64::MIN;
const TOOL_STRACE: u8 = 1;
const TOOL_COMPAT: u8 = 2;

static PROBE: AtomicPtr<PunProbe> = AtomicPtr::new(ptr::null_mut());
static TOOL_MODE: AtomicU8 = AtomicU8::new(0);

#[thread_local]
static mut CURRENT_EVENT: *mut SyscallEvent = ptr::null_mut();

global_asm!(
    r#"
    .text
    .p2align 4
    .global reverie_liteinst_trusted_syscall
    .hidden reverie_liteinst_trusted_syscall
    .type reverie_liteinst_trusted_syscall,@function
reverie_liteinst_trusted_syscall:
    mov rax, rdi
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov r10, r8
    mov r8, r9
    mov r9, [rsp + 8]
    .global reverie_liteinst_trusted_syscall_ip
    .hidden reverie_liteinst_trusted_syscall_ip
reverie_liteinst_trusted_syscall_ip:
    syscall
    .global reverie_liteinst_trusted_syscall_return_ip
    .hidden reverie_liteinst_trusted_syscall_return_ip
reverie_liteinst_trusted_syscall_return_ip:
    ret
    .size reverie_liteinst_trusted_syscall, .-reverie_liteinst_trusted_syscall
"#
);

unsafe extern "C" {
    fn reverie_liteinst_trusted_syscall(
        number: u64,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> i64;
    static reverie_liteinst_trusted_syscall_ip: u8;
    static reverie_liteinst_trusted_syscall_return_ip: u8;
}

#[derive(Clone, Copy)]
struct SyscallEvent {
    number: i64,
    args: [u64; 6],
    instruction_pointer: u64,
    result: i64,
}

pub(crate) fn initialize_from_environment() -> io::Result<()> {
    let mode = match std::env::var_os("REVERIE_LITEINST_TOOL").as_deref() {
        None => return Ok(()),
        Some(value) if value == OsStr::new("strace") => TOOL_STRACE,
        Some(value) if value == OsStr::new("compat") => TOOL_COMPAT,
        Some(value) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported REVERIE_LITEINST_TOOL value {value:?}"),
            ));
        }
    };
    TOOL_MODE.store(mode, Ordering::Release);

    let probe = Box::new(PunProbe::new(tool_trampoline)?);
    let probe = Box::into_raw(probe);
    PROBE.store(probe, Ordering::Release);

    install_sigsys_handler()?;
    install_seccomp_filter()
}

unsafe extern "C" fn sigsys_handler(
    signal: libc::c_int,
    _info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    if signal != libc::SIGSYS || context.is_null() {
        unsafe {
            exit_now(126);
        }
    }

    let context = unsafe { &mut *context.cast::<libc::ucontext_t>() };
    let registers = &mut context.uc_mcontext.gregs;
    let mut event = SyscallEvent {
        number: registers[libc::REG_RAX as usize],
        args: [
            registers[libc::REG_RDI as usize] as u64,
            registers[libc::REG_RSI as usize] as u64,
            registers[libc::REG_RDX as usize] as u64,
            registers[libc::REG_R10 as usize] as u64,
            registers[libc::REG_R8 as usize] as u64,
            registers[libc::REG_R9 as usize] as u64,
        ],
        instruction_pointer: registers[libc::REG_RIP as usize] as u64,
        result: UNSET_RESULT,
    };

    if unsafe { !CURRENT_EVENT.is_null() } {
        unsafe {
            exit_now(125);
        }
    }
    unsafe {
        CURRENT_EVENT = &mut event;
    }

    let probe = PROBE.load(Ordering::Acquire);
    if probe.is_null() || unsafe { (*probe).enable() }.is_err() {
        unsafe {
            exit_now(124);
        }
    }
    unsafe {
        (*probe).dispatch();
        CURRENT_EVENT = ptr::null_mut();
    }

    if event.result == UNSET_RESULT {
        event.result = -i64::from(libc::ENOSYS);
    }
    registers[libc::REG_RAX as usize] = event.result;
}

unsafe extern "C" fn tool_trampoline() {
    let event = unsafe { CURRENT_EVENT };
    if event.is_null() {
        unsafe {
            exit_now(123);
        }
    }
    unsafe {
        process_syscall(&mut *event);
    }
}

unsafe fn process_syscall(event: &mut SyscallEvent) {
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(#61): exec cannot safely cross an inherited trap filter.
    if event.number == libc::SYS_execve || event.number == libc::SYS_execveat {
        event.result = -i64::from(libc::ENOTSUP);
        unsafe {
            trace_event(event, Some(event.result));
        }
        return;
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(#61): reserve SIGSYS until disposition virtualization exists.
    if event.number == libc::SYS_rt_sigaction && event.args[0] == libc::SIGSYS as u64 {
        event.result = -i64::from(libc::EPERM);
        unsafe {
            trace_event(event, Some(event.result));
        }
        return;
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(#61): a non-null clone stack cannot resume this signal frame safely.
    if event.number == libc::SYS_clone && event.args[1] != 0 {
        event.result = -i64::from(libc::ENOTSUP);
        unsafe {
            trace_event(event, Some(event.result));
        }
        return;
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(#61): clone3 and vfork need a controller-owned child bootstrap.
    if event.number == libc::SYS_clone3 || event.number == libc::SYS_vfork {
        event.result = -i64::from(libc::ENOTSUP);
        unsafe {
            trace_event(event, Some(event.result));
        }
        return;
    }

    if event.number == libc::SYS_exit || event.number == libc::SYS_exit_group {
        unsafe {
            trace_event(event, None);
        }
    }

    event.result = unsafe { raw_syscall6(event.number, event.args) };

    if event.number != libc::SYS_exit && event.number != libc::SYS_exit_group {
        unsafe {
            trace_event(event, Some(event.result));
        }
    }
}

unsafe fn trace_event(event: &SyscallEvent, result: Option<i64>) {
    let mode = TOOL_MODE.load(Ordering::Relaxed);
    let mut line = StackLine::new();
    if mode == TOOL_COMPAT {
        line.push_bytes(b"reverie-liteinst: tool=compat syscall=");
        line.push_signed(event.number);
    } else if mode == TOOL_STRACE {
        let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
        line.push_bytes(b"[liteinst strace pid ");
        line.push_signed(pid);
        line.push_bytes(b"] syscall(");
        line.push_signed(event.number);
        line.push_bytes(b", ip=0x");
        line.push_hex(event.instruction_pointer);
        line.push_bytes(b") = ");
        match result {
            Some(result) => line.push_signed(result),
            None => line.push_bytes(b"?"),
        }
    } else {
        return;
    }
    line.push_bytes(b"\n");

    let _ = unsafe {
        raw_syscall6(
            libc::SYS_write,
            [
                libc::STDERR_FILENO as u64,
                line.bytes.as_ptr() as u64,
                line.len as u64,
                0,
                0,
                0,
            ],
        )
    };
}

unsafe fn raw_syscall6(number: i64, args: [u64; 6]) -> i64 {
    unsafe {
        reverie_liteinst_trusted_syscall(
            number as u64,
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            args[5],
        )
    }
}

unsafe fn exit_now(code: i32) -> ! {
    let _ = unsafe { raw_syscall6(libc::SYS_exit_group, [code as u64, 0, 0, 0, 0, 0]) };
    loop {
        core::hint::spin_loop();
    }
}

fn install_sigsys_handler() -> io::Result<()> {
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_flags = libc::SA_SIGINFO;
    action.sa_sigaction = sigsys_handler as *const () as usize;
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::sigaction(libc::SIGSYS, &action, ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn install_seccomp_filter() -> io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let gate_ip = ptr::addr_of!(reverie_liteinst_trusted_syscall_ip) as usize as u64;
    let return_ip = ptr::addr_of!(reverie_liteinst_trusted_syscall_return_ip) as usize as u64;
    if gate_ip >> 32 != return_ip >> 32 {
        return Err(io::Error::other(
            "trusted syscall gate crosses a 4GiB boundary",
        ));
    }

    let mut filter = [
        stmt(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
        jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        jump(BPF_JMP_JEQ_K, libc::SYS_rt_sigreturn as u32, 6, 0),
        stmt(BPF_LD_W_ABS, SECCOMP_DATA_IP_HIGH_OFFSET),
        jump(BPF_JMP_JEQ_K, (gate_ip >> 32) as u32, 0, 3),
        stmt(BPF_LD_W_ABS, SECCOMP_DATA_IP_LOW_OFFSET),
        jump(BPF_JMP_JEQ_K, gate_ip as u32, 2, 0),
        jump(BPF_JMP_JEQ_K, return_ip as u32, 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_TRAP),
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
    ];
    let program = libc::sock_fprog {
        len: u16::try_from(filter.len()).expect("small fixed seccomp filter"),
        filter: filter.as_mut_ptr(),
    };

    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &program,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

const fn stmt(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

const fn jump(code: u16, value: u32, jump_true: u8, jump_false: u8) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: jump_true,
        jf: jump_false,
        k: value,
    }
}

struct StackLine {
    bytes: [u8; 192],
    len: usize,
}

impl StackLine {
    const fn new() -> Self {
        Self {
            bytes: [0; 192],
            len: 0,
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        let available = self.bytes.len().saturating_sub(self.len);
        let count = available.min(bytes.len());
        self.bytes[self.len..self.len + count].copy_from_slice(&bytes[..count]);
        self.len += count;
    }

    fn push_signed(&mut self, value: i64) {
        if value < 0 {
            self.push_bytes(b"-");
        }
        self.push_unsigned(value.unsigned_abs());
    }

    fn push_unsigned(&mut self, mut value: u64) {
        let mut digits = [0_u8; 20];
        let mut cursor = digits.len();
        loop {
            cursor -= 1;
            digits[cursor] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.push_bytes(&digits[cursor..]);
    }

    fn push_hex(&mut self, mut value: u64) {
        let mut digits = [0_u8; 16];
        let mut cursor = digits.len();
        loop {
            cursor -= 1;
            let digit = (value & 0xf) as u8;
            digits[cursor] = if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            };
            value >>= 4;
            if value == 0 {
                break;
            }
        }
        self.push_bytes(&digits[cursor..]);
    }
}

#[cfg(test)]
mod tests {
    use super::StackLine;

    #[test]
    fn stack_line_formats_signed_and_hex_values() {
        let mut line = StackLine::new();
        line.push_signed(-123);
        line.push_bytes(b" ");
        line.push_hex(0xdead_beef);
        assert_eq!(&line.bytes[..line.len], b"-123 deadbeef");
    }
}
