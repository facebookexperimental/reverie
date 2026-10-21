/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Runtime support shared by the in-guest trap path: the opt-in stage stream
//! of diagnostic markers, an immediate process exit, the per-thread marker of
//! a running Tool callback, a fault-safe read of the process's own memory, and
//! an allocation-free scan of `/proc/self/maps`, and the kernel signal-action
//! layout with a guard that restores the signal mask. Everything here uses raw
//! syscalls and stack buffers only, so it is usable in signal context (the
//! maps scan when its callback is, too).

use core::marker::PhantomData;
use core::ptr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use crate::trap::raw_syscall6;

/// The exit status when an enabled stage marker cannot be written whole.
pub const IN_GUEST_STAGE_WRITE_FAILURE_STATUS: i32 = 123;

static IN_GUEST_STAGE_STREAM: AtomicBool = AtomicBool::new(false);

/// Turns the in-guest stage stream (see [`emit_in_guest_stage`]) on or off for
/// this process.
pub fn set_stage_stream(enabled: bool) {
    IN_GUEST_STAGE_STREAM.store(enabled, Ordering::Release);
}

/// Whether the in-guest stage stream is on.
pub fn stage_stream_enabled() -> bool {
    IN_GUEST_STAGE_STREAM.load(Ordering::Acquire)
}

/// Emit an allocation-free stage marker from the in-guest Tool process.
///
/// This is opt-in because production guests own stderr. When enabled, a short
/// write is fail-closed so an absent marker cannot be mistaken for a negative
/// observation across the host/in-guest process boundary.
pub fn emit_in_guest_stage(stage: &[u8]) {
    if !stage_stream_enabled() {
        return;
    }
    let mut line = StackLine::new();
    line.push_bytes(b"INFO reverie_liteinst::tool_host: [in-guest pid=");
    line.push_signed(unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) });
    line.push_bytes(b" tid=");
    line.push_signed(unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) });
    line.push_bytes(b"] stage=");
    line.push_bytes(stage);
    line.push_bytes(b"\n");
    let written = unsafe {
        raw_syscall6(
            libc::SYS_write,
            [
                libc::STDERR_FILENO as u64,
                line.as_bytes().as_ptr() as u64,
                line.as_bytes().len() as u64,
                0,
                0,
                0,
            ],
        )
    };
    if written != line.as_bytes().len() as i64 {
        unsafe { exit_now(IN_GUEST_STAGE_WRITE_FAILURE_STATUS) };
    }
}

/// Ends the process now with status `code`, through the trusted gate.
///
/// # Safety
///
/// No destructor, `atexit` handler or buffered output runs; the caller must not
/// need any of them (the runtime calls this where nothing else is safe, such
/// as in signal context).
pub unsafe fn exit_now(code: i32) -> ! {
    let _ = unsafe { raw_syscall6(libc::SYS_exit_group, [code as u64, 0, 0, 0, 0, 0]) };
    loop {
        core::hint::spin_loop();
    }
}

/// A fixed 512-byte line built without allocating, for diagnostics written
/// from signal context. Bytes past the capacity are dropped.
pub struct StackLine {
    bytes: [u8; 512],
    len: usize,
}

impl Default for StackLine {
    fn default() -> Self {
        Self::new()
    }
}

impl StackLine {
    /// The line's bytes so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// An empty line.
    pub const fn new() -> Self {
        Self {
            bytes: [0; 512],
            len: 0,
        }
    }

    /// Appends `bytes`, dropping what does not fit.
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        let available = self.bytes.len().saturating_sub(self.len);
        let count = available.min(bytes.len());
        self.bytes[self.len..self.len + count].copy_from_slice(&bytes[..count]);
        self.len += count;
    }

    /// Appends `value` in decimal.
    pub fn push_signed(&mut self, value: i64) {
        if value < 0 {
            self.push_bytes(b"-");
        }
        self.push_unsigned(value.unsigned_abs());
    }

    /// Appends `value` in decimal.
    pub fn push_unsigned(&mut self, mut value: u64) {
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

    /// Appends `value` in lowercase hexadecimal, without a prefix.
    pub fn push_hex(&mut self, mut value: u64) {
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

    /// Appends `value` as two lowercase hexadecimal digits.
    pub fn push_hex_byte(&mut self, value: u8) {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        self.push_bytes(&[
            DIGITS[usize::from(value >> 4)],
            DIGITS[usize::from(value & 0xf)],
        ]);
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-133): Review nested Tool syscall guards and raw forwarding.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
/// The kernel's `struct sigaction` for `rt_sigaction` on x86_64 with a 64-bit
/// signal mask, as raw syscalls pass it (not libc's layout).
pub struct KernelSigaction {
    /// The handler address, or `SIG_DFL` / `SIG_IGN`.
    pub handler: u64,
    /// The `SA_*` flags.
    pub flags: u64,
    /// The restorer the kernel returns through (`SA_RESTORER`).
    pub restorer: u64,
    /// The signals blocked while the handler runs.
    pub mask: u64,
}

/// Restores this thread's signal mask to a recorded value when dropped, and
/// ends the process with status 126 if that fails.
pub struct SignalInstallGuard {
    restore_mask: u64,
}

impl SignalInstallGuard {
    /// A guard that restores the signal mask to `restore_mask`.
    pub fn restoring(restore_mask: u64) -> Self {
        Self { restore_mask }
    }
}

impl Drop for SignalInstallGuard {
    fn drop(&mut self) {
        let result = unsafe {
            raw_syscall6(
                libc::SYS_rt_sigprocmask,
                [
                    libc::SIG_SETMASK as u64,
                    (&raw const self.restore_mask) as u64,
                    0,
                    core::mem::size_of::<u64>() as u64,
                    0,
                    0,
                ],
            )
        };
        if result < 0 {
            unsafe { exit_now(126) };
        }
    }
}

// Reentry is a property of Tool execution, not of syscall-event storage:
// instruction callbacks have no current SyscallEvent but must take the same
// native/raw bypasses while holding Tool and thread-state locks.
thread_local! {
    static TOOL_CALLBACK_ACTIVE: AtomicBool = const { AtomicBool::new(false) };
}

/// Marks the calling thread as running a Tool callback until dropped; see
/// [`tool_callback_active`]. It cannot move to another thread, so its drop
/// updates the thread that created it. Each drop restores the state its
/// [`enter`](Self::enter) found, so nested guards must be dropped in reverse
/// order of creation (as scoped guards are).
pub struct ToolCallbackGuard {
    previous: bool,
    _same_thread: PhantomData<*mut ()>,
}

impl ToolCallbackGuard {
    /// Marks the calling thread as running a Tool callback.
    pub fn enter() -> Self {
        let previous = TOOL_CALLBACK_ACTIVE.with(|active| active.swap(true, Ordering::Relaxed));
        Self {
            previous,
            _same_thread: PhantomData,
        }
    }
}

impl Drop for ToolCallbackGuard {
    fn drop(&mut self) {
        TOOL_CALLBACK_ACTIVE.with(|active| active.store(self.previous, Ordering::Relaxed));
    }
}

/// Describes `error` without asking the C library for an errno message.
///
/// `std::io::Error`'s `Display` and `Debug` render an operating-system error
/// through `strerror_r`, which can call `gettext` and allocate through the C
/// library's malloc: inside a guest, the guest's own heap. An operating-system
/// error is described by its kind and number instead; any other error, or an
/// I/O error wrapping one, as before.
pub fn describe_io_error(error: &std::io::Error) -> String {
    if let Some(code) = error.raw_os_error() {
        return format!("{:?} (errno {code})", error.kind());
    }
    match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<std::io::Error>())
    {
        Some(inner) => describe_io_error(inner),
        None => error.to_string(),
    }
}

/// This process's auxiliary vector entry `key`, read from `/proc/self/auxv`
/// with raw syscalls (not `getauxval`, which a guest can interpose), into a
/// stack buffer; allocates nothing.
pub fn auxv_entry(key: u64) -> Option<u64> {
    let mut auxv = [0_u8; 4096];
    let fd = unsafe {
        raw_syscall6(
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                c"/proc/self/auxv".as_ptr() as u64,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
            ],
        )
    };
    if fd < 0 {
        return None;
    }
    let mut filled = 0_usize;
    while filled < auxv.len() {
        let count = unsafe {
            raw_syscall6(
                libc::SYS_read,
                [
                    fd as u64,
                    auxv[filled..].as_mut_ptr() as u64,
                    (auxv.len() - filled) as u64,
                    0,
                    0,
                    0,
                ],
            )
        };
        if count == -i64::from(libc::EINTR) {
            continue;
        }
        if count <= 0 {
            break;
        }
        filled += count as usize;
    }
    unsafe { raw_syscall6(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) };
    auxv[..filled]
        .as_chunks::<16>()
        .0
        .iter()
        .map(|pair| {
            (
                u64::from_le_bytes(pair[..8].try_into().unwrap()),
                u64::from_le_bytes(pair[8..].try_into().unwrap()),
            )
        })
        .take_while(|(found, _)| *found != 0)
        .find(|(found, _)| *found == key)
        .map(|(_, value)| value)
}

/// The value of the environment variable `name` (without `=`), read from the
/// process's environment block (`environ`) itself rather than through libc's
/// `getenv`, which the program or a preloaded library may define. Call only
/// while no other thread changes the environment.
pub fn environment_value(name: &[u8]) -> Option<&'static [u8]> {
    unsafe extern "C" {
        static environ: *const *const libc::c_char;
    }
    // SAFETY: environ is a NULL-terminated array of NUL-terminated strings,
    // and the caller rules out concurrent changes.
    unsafe {
        let mut slot = environ;
        while !slot.is_null() && !(*slot).is_null() {
            let entry = core::ffi::CStr::from_ptr(*slot).to_bytes();
            if let Some(value) = entry
                .strip_prefix(name)
                .and_then(|rest| rest.strip_prefix(b"="))
            {
                return Some(value);
            }
            slot = slot.add(1);
        }
    }
    None
}

/// This process's open descriptors, listed from `/proc/self/fd` with raw
/// `openat`, `getdents64` and `close` into a stack buffer: not through
/// `std::fs::read_dir`, whose `opendir` allocates its buffer through the C
/// library's malloc (inside a guest, the guest's own heap). The listing's own
/// descriptor is left out. The returned `Vec` is a Rust allocation.
pub fn open_descriptors() -> std::io::Result<Vec<i32>> {
    let directory = raw_result(unsafe {
        raw_syscall6(
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                c"/proc/self/fd".as_ptr() as u64,
                (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
            ],
        )
    })? as i32;
    let mut descriptors = Vec::new();
    let mut buffer = [0_u8; 4096];
    let listed = loop {
        let count = unsafe {
            raw_syscall6(
                libc::SYS_getdents64,
                [
                    directory as u64,
                    buffer.as_mut_ptr() as u64,
                    buffer.len() as u64,
                    0,
                    0,
                    0,
                ],
            )
        };
        if count == 0 {
            break Ok(());
        }
        if let Err(error) = raw_result(count) {
            break Err(error);
        }
        // struct linux_dirent64 { u64 ino; i64 off; u16 reclen; u8 type; char name[]; }
        let mut offset = 0_usize;
        while offset + 19 <= count as usize {
            let reclen = u16::from_ne_bytes([buffer[offset + 16], buffer[offset + 17]]) as usize;
            if reclen == 0 || offset + reclen > count as usize {
                break;
            }
            let name = &buffer[offset + 19..offset + reclen];
            let name = &name[..name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name.len())];
            if let Some(fd) = core::str::from_utf8(name)
                .ok()
                .and_then(|name| name.parse::<i32>().ok())
                .filter(|fd| *fd != directory)
            {
                descriptors.push(fd);
            }
            offset += reclen;
        }
    };
    unsafe { raw_syscall6(libc::SYS_close, [directory as u64, 0, 0, 0, 0, 0]) };
    listed.map(|()| descriptors)
}

/// The result of a raw syscall ([`raw_syscall6`]): its value, or the error
/// its negative return names. Raw syscalls leave libc's `errno` untouched,
/// so `io::Error::last_os_error` would not describe them.
pub fn raw_result(result: i64) -> std::io::Result<u64> {
    if result < 0 && result > -4096 {
        Err(std::io::Error::from_raw_os_error(-result as i32))
    } else {
        Ok(result as u64)
    }
}

/// The result of a raw syscall whose only success value is 0 (`prctl` with
/// a setting, `fstat`, `mprotect`, `sigaltstack`, ...): any other value is
/// refused, a negative one as the error it names. [`raw_result`] would take a
/// positive return as success, which for such a call the kernel never gives.
pub fn raw_zero_result(result: i64) -> std::io::Result<()> {
    match raw_result(result)? {
        0 => Ok(()),
        other => Err(std::io::Error::other(format!(
            "a syscall that returns 0 on success returned {other}"
        ))),
    }
}

/// `AT_PAGESZ`, the auxiliary-vector key of the page size.
const AT_PAGESZ: u64 = 6;

/// The page size, from the kernel's auxiliary vector ([`auxv_entry`]). Not
/// `sysconf`, which is a dynamic symbol the program or a preloaded library may
/// define, and which the runtime would then run inside the guest.
pub fn page_size() -> std::io::Result<u64> {
    auxv_entry(AT_PAGESZ)
        .filter(|size| size.is_power_of_two())
        .ok_or_else(|| std::io::Error::other("the auxiliary vector has no valid AT_PAGESZ"))
}

/// Whether the calling thread is running a Tool callback. Syscalls and faulting
/// instructions reached from inside one bypass the Tool (they are the Tool's
/// own) and must not allocate or patch.
pub fn tool_callback_active() -> bool {
    TOOL_CALLBACK_ACTIVE.with(|active| active.load(Ordering::Relaxed))
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(liteinst-late-code-cpuid): Review the fault-safe self read of guest code.
/// Copy up to `out.len()` bytes starting at `address` from this process's own
/// memory without risking a nested fault, returning how many leading bytes
/// were readable. `process_vm_readv` reports an unmapped or unreadable page
/// (including an execute-only one) as a short count or an error instead of
/// faulting. Each byte is its own remote element, so a readable prefix that
/// ends at a mapping boundary is still returned.
///
/// # Safety
///
/// Issues raw syscalls through the trusted gate; safe in signal context.
pub unsafe fn read_own_bytes(address: u64, out: &mut [u8; 8]) -> usize {
    let mut remote = [libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    }; 8];
    let mut count = 0;
    for (index, element) in remote.iter_mut().enumerate() {
        let Some(byte) = address.checked_add(index as u64) else {
            break;
        };
        element.iov_base = byte as usize as *mut libc::c_void;
        element.iov_len = 1;
        count += 1;
    }
    if count == 0 {
        return 0;
    }
    let local = libc::iovec {
        iov_base: out.as_mut_ptr().cast(),
        iov_len: count,
    };
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let read = unsafe {
        raw_syscall6(
            libc::SYS_process_vm_readv,
            [
                pid as u64,
                (&raw const local) as u64,
                1,
                remote.as_ptr() as u64,
                count as u64,
                0,
            ],
        )
    };
    usize::try_from(read).map_or(0, |read| read.min(count))
}

/// Copy the pathname field of the `/proc/self/maps` line containing
/// `address` into `name`, truncated to its length. Returns the copied length,
/// 0 for a mapping without a pathname, or `None` when no line contains the
/// address or the file cannot be read. Uses only raw syscalls and stack
/// buffers, so it is usable in signal context.
///
/// # Safety
///
/// Issues raw syscalls through the trusted gate.
pub unsafe fn mapping_name_at(address: u64, name: &mut [u8]) -> Option<usize> {
    unsafe { scan_own_maps(|line| maps_line_name(line, address, name)) }
}

/// Feed each line of `/proc/self/maps` to `line_result` until it returns
/// `Some`, and return that. Uses only raw syscalls and stack buffers; a line
/// longer than the buffer is truncated, which keeps its leading fields.
///
/// # Safety
///
/// Issues raw syscalls through the trusted gate. Called from signal context,
/// `line_result` must itself be async-signal-safe (not allocate or take
/// locks).
pub unsafe fn scan_own_maps<R>(line_result: impl FnMut(&[u8]) -> Option<R>) -> Option<R> {
    unsafe { scan_proc_lines(c"/proc/self/maps", line_result) }
}

/// [`scan_own_maps`] over another line-oriented procfs file, such as
/// `/proc/self/smaps`.
///
/// # Safety
///
/// As [`scan_own_maps`].
pub unsafe fn scan_proc_lines<R>(
    path: &core::ffi::CStr,
    line_result: impl FnMut(&[u8]) -> Option<R>,
) -> Option<R> {
    unsafe { scan_proc_lines_checked(path, line_result) }
        .ok()
        .flatten()
}

/// [`scan_proc_lines`], telling a scan that read the whole file without a
/// result (`Ok(None)`) from one that could not open or read it (`Err` with
/// the negated errno).
///
/// # Safety
///
/// As [`scan_own_maps`].
pub unsafe fn scan_proc_lines_checked<R>(
    path: &core::ffi::CStr,
    mut line_result: impl FnMut(&[u8]) -> Option<R>,
) -> Result<Option<R>, i64> {
    let fd = unsafe {
        raw_syscall6(
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                path.as_ptr() as u64,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
            ],
        )
    };
    if fd < 0 {
        return Err(fd);
    }
    let mut chunk = [0_u8; 1024];
    let mut line = [0_u8; 512];
    let mut line_len = 0;
    let mut found = Ok(None);
    'read: loop {
        let read = unsafe {
            raw_syscall6(
                libc::SYS_read,
                [
                    fd as u64,
                    chunk.as_mut_ptr() as u64,
                    chunk.len() as u64,
                    0,
                    0,
                    0,
                ],
            )
        };
        if read == -i64::from(libc::EINTR) {
            continue;
        }
        let Ok(read) = usize::try_from(read) else {
            found = Err(read);
            break;
        };
        if read == 0 {
            break;
        }
        for byte in chunk[..read.min(chunk.len())].iter().copied() {
            if byte != b'\n' {
                if line_len < line.len() {
                    line[line_len] = byte;
                    line_len += 1;
                }
                continue;
            }
            if let Some(result) = line_result(&line[..line_len]) {
                found = Ok(Some(result));
                break 'read;
            }
            line_len = 0;
        }
    }
    let _ = unsafe { raw_syscall6(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) };
    found
}

/// Parse one `/proc/self/maps` line; when its range contains `address`, copy
/// its pathname (possibly empty) into `name` and return the copied length.
pub fn maps_line_name(line: &[u8], address: u64, name: &mut [u8]) -> Option<usize> {
    fn hex(bytes: &[u8]) -> Option<u64> {
        if bytes.is_empty() || bytes.len() > 16 {
            return None;
        }
        bytes.iter().try_fold(0_u64, |value, byte| {
            let digit = (*byte as char).to_digit(16)?;
            Some((value << 4) | u64::from(digit))
        })
    }
    let range_end = line.iter().position(|byte| *byte == b' ')?;
    let range = &line[..range_end];
    let dash = range.iter().position(|byte| *byte == b'-')?;
    let start = hex(&range[..dash])?;
    let end = hex(&range[dash + 1..])?;
    if address < start || address >= end {
        return None;
    }
    // Skip the range, permissions, offset, device and inode fields; the
    // remainder after their separating spaces is the pathname.
    let mut rest = line;
    for _ in 0..5 {
        let field_end = rest
            .iter()
            .position(|byte| *byte == b' ')
            .unwrap_or(rest.len());
        rest = &rest[field_end..];
        let spaces = rest.iter().take_while(|byte| **byte == b' ').count();
        rest = &rest[spaces..];
    }
    let len = rest.len().min(name.len());
    name[..len].copy_from_slice(&rest[..len]);
    Some(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An operating-system error is described by its kind and number, never
    /// by the C library's message (which `std::io::Error`'s own `Display`
    /// fetches through `strerror_r`), also when another I/O error wraps it.
    #[test]
    fn io_errors_are_described_without_the_c_library_message() {
        let os = std::io::Error::from_raw_os_error(libc::EACCES);
        assert!(os.to_string().contains("Permission denied"), "{os}");
        assert_eq!(describe_io_error(&os), "PermissionDenied (errno 13)");
        let wrapped = std::io::Error::other(std::io::Error::from_raw_os_error(libc::ENOENT));
        assert_eq!(describe_io_error(&wrapped), "NotFound (errno 2)");
        let custom = std::io::Error::other("no such descriptor");
        assert_eq!(describe_io_error(&custom), "no such descriptor");
    }

    #[test]
    fn stack_line_formats_signed_and_hex_values() {
        let mut line = StackLine::new();
        line.push_signed(-123);
        line.push_bytes(b" ");
        line.push_hex(0xdead_beef);
        assert_eq!(&line.bytes[..line.len], b"-123 deadbeef");
    }
    #[test]
    fn maps_line_name_extracts_the_containing_mapping_path() {
        use super::maps_line_name;
        let mut name = [0_u8; 64];
        let line = b"7f1234560000-7f1234570000 r-xp 00002000 fd:01 1234                       /usr/lib64/libcrypto.so.3";
        assert_eq!(maps_line_name(line, 0x7f12_3456_0000, &mut name), Some(25));
        assert_eq!(&name[..25], b"/usr/lib64/libcrypto.so.3");
        assert_eq!(maps_line_name(line, 0x7f12_3456_ffff, &mut name), Some(25));
        assert_eq!(maps_line_name(line, 0x7f12_3457_0000, &mut name), None);
        assert_eq!(maps_line_name(line, 0x7f12_3455_ffff, &mut name), None);
        let anonymous = b"7f0000000000-7f0000001000 rwxp 00000000 00:00 0 ";
        assert_eq!(
            maps_line_name(anonymous, 0x7f00_0000_0800, &mut name),
            Some(0)
        );
        let bare = b"7f0000000000-7f0000001000 rwxp 00000000 00:00 0";
        assert_eq!(maps_line_name(bare, 0x7f00_0000_0800, &mut name), Some(0));
        let mut short = [0_u8; 4];
        assert_eq!(maps_line_name(line, 0x7f12_3456_0000, &mut short), Some(4));
        assert_eq!(&short, b"/usr");
        assert_eq!(maps_line_name(b"garbage", 0, &mut name), None);
        assert_eq!(maps_line_name(b"", 0, &mut name), None);
    }
    #[test]
    fn mapping_name_at_reads_this_process_maps_without_allocation() {
        use super::mapping_name_at;
        let page = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        let mut name = [0_u8; 256];
        assert_eq!(
            unsafe { mapping_name_at(page as u64 + 16, &mut name) },
            Some(0)
        );
        let code = mapping_name_at as *const () as usize as u64;
        let len = unsafe { mapping_name_at(code, &mut name) }.unwrap();
        let executable = std::env::current_exe().unwrap();
        assert_eq!(
            std::str::from_utf8(&name[..len]).unwrap(),
            executable.to_str().unwrap()
        );
        // The other libtest threads may reuse an unmapped address immediately.
        // Fork while this page is still live: only this thread survives in the
        // child's private address space, and its unmap/scan/exit path uses no
        // allocation, formatting, or inherited userspace locks.
        let child = unsafe { raw_syscall6(libc::SYS_fork, [0; 6]) };
        assert!(child >= 0, "raw fork failed: {child}");
        if child == 0 {
            let unmapped =
                unsafe { raw_syscall6(libc::SYS_munmap, [page as u64, 4096, 0, 0, 0, 0]) };
            let status = if unmapped != 0 {
                101
            } else if unsafe { mapping_name_at(page as u64 + 16, &mut name) }.is_some() {
                102
            } else {
                0
            };
            unsafe { exit_now(status) };
        }
        let mut status = 0_i32;
        loop {
            let waited = unsafe {
                raw_syscall6(
                    libc::SYS_wait4,
                    [child as u64, (&raw mut status) as u64, 0, 0, 0, 0],
                )
            };
            if waited == -i64::from(libc::EINTR) {
                continue;
            }
            assert_eq!(waited, child);
            break;
        }
        assert_eq!(unsafe { libc::munmap(page, 4096) }, 0);
        assert!(libc::WIFEXITED(status), "mapping child status: {status:#x}");
        assert_eq!(libc::WEXITSTATUS(status), 0, "child unmap/absence check");
    }
    #[test]
    fn own_byte_reads_stop_at_an_unreadable_page_without_faulting() {
        use super::read_own_bytes;
        let pages = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                8192,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        }
        .cast::<u8>();
        assert_ne!(pages.cast(), libc::MAP_FAILED);
        unsafe {
            pages.add(4094).write(0x0f);
            pages.add(4095).write(0xa2);
            assert_eq!(
                libc::mprotect(pages.add(4096).cast(), 4096, libc::PROT_NONE),
                0
            );
        }
        let mut bytes = [0_u8; 8];
        assert_eq!(
            unsafe { read_own_bytes(pages as u64 + 4094, &mut bytes) },
            2
        );
        assert_eq!(&bytes[..2], &[0x0f, 0xa2]);
        assert_eq!(
            unsafe { read_own_bytes(pages as u64 + 4096, &mut bytes) },
            0
        );
        assert_eq!(unsafe { read_own_bytes(0, &mut bytes) }, 0);
        assert_eq!(unsafe { read_own_bytes(u64::MAX - 1, &mut bytes) }, 0);
        unsafe { libc::munmap(pages.cast(), 8192) };
    }
}
