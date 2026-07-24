use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;
use std::io;
use std::ptr;

const INACTIVE_OPCODE: u8 = 0xb8; // mov eax, imm32
const ACTIVE_OPCODE: u8 = 0xe9; // jmp rel32
const SITE_OFFSET: usize = 0;
const TARGET_OFFSET: usize = 64;

pub(crate) type ToolCallback = unsafe extern "C" fn();

/// A minimal W^X LiteInst-style one-byte instruction pun.
///
/// The tail bytes are both a MOV immediate and a relative JMP displacement.
/// The callback trampoline occupies the implied target in the same executable
/// page, so activation changes only the first opcode byte.
pub(crate) struct PunProbe {
    writable: *mut u8,
    executable: *mut u8,
    mapping_len: usize,
}

impl PunProbe {
    pub(crate) fn new(callback: ToolCallback) -> io::Result<Self> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return Err(io::Error::last_os_error());
        }
        let mapping_len = usize::try_from(page_size)
            .map_err(|_| io::Error::other("page size is not representable"))?;
        if TARGET_OFFSET + 32 > mapping_len {
            return Err(io::Error::other("page is too small for pun trampoline"));
        }

        let name = b"reverie-liteinst-pun\0";
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr().cast::<libc::c_char>(),
                libc::MFD_CLOEXEC,
            )
        } as libc::c_int;
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::ftruncate(fd, page_size) } != 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error);
        }

        let writable = unsafe {
            libc::mmap(
                ptr::null_mut(),
                mapping_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if writable == libc::MAP_FAILED {
            let error = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error);
        }

        let executable = unsafe {
            libc::mmap(
                ptr::null_mut(),
                mapping_len,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        let close_result = unsafe { libc::close(fd) };
        if executable == libc::MAP_FAILED {
            let error = io::Error::last_os_error();
            unsafe {
                libc::munmap(writable, mapping_len);
            }
            return Err(error);
        }
        if close_result != 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::munmap(executable, mapping_len);
                libc::munmap(writable, mapping_len);
            }
            return Err(error);
        }

        let writable = writable.cast::<u8>();
        let executable = executable.cast::<u8>();
        unsafe {
            ptr::write_bytes(writable, 0x90, mapping_len);
        }

        let site = unsafe { executable.add(SITE_OFFSET) } as usize;
        let target = unsafe { executable.add(TARGET_OFFSET) } as usize;
        let displacement = i32::try_from(target as i128 - (site + 5) as i128)
            .map_err(|_| io::Error::other("pun trampoline is outside rel32 reach"))?;

        let mut site_code = [0_u8; 6];
        site_code[0] = INACTIVE_OPCODE;
        site_code[1..5].copy_from_slice(&displacement.to_le_bytes());
        site_code[5] = 0xc3; // ret

        // sub rsp,8; movabs rax,callback; call rax; add rsp,8; ret
        let mut trampoline = [0_u8; 20];
        trampoline[0..4].copy_from_slice(&[0x48, 0x83, 0xec, 0x08]);
        trampoline[4..6].copy_from_slice(&[0x48, 0xb8]);
        trampoline[6..14].copy_from_slice(&(callback as usize as u64).to_le_bytes());
        trampoline[14..16].copy_from_slice(&[0xff, 0xd0]);
        trampoline[16..20].copy_from_slice(&[0x48, 0x83, 0xc4, 0x08]);
        let return_opcode = [0xc3_u8];

        unsafe {
            ptr::copy_nonoverlapping(
                site_code.as_ptr(),
                writable.add(SITE_OFFSET),
                site_code.len(),
            );
            ptr::copy_nonoverlapping(
                trampoline.as_ptr(),
                writable.add(TARGET_OFFSET),
                trampoline.len(),
            );
            ptr::copy_nonoverlapping(
                return_opcode.as_ptr(),
                writable.add(TARGET_OFFSET + trampoline.len()),
                return_opcode.len(),
            );
            serialize_instruction_stream();
        }

        Ok(Self {
            writable,
            executable,
            mapping_len,
        })
    }

    pub(crate) fn enable(&self) -> io::Result<()> {
        let opcode = unsafe { &*self.writable.add(SITE_OFFSET).cast::<AtomicU8>() };
        match opcode.load(Ordering::Acquire) {
            ACTIVE_OPCODE => return Ok(()),
            INACTIVE_OPCODE => {}
            _ => {
                return Err(io::Error::other("unexpected pun opcode"));
            }
        }
        opcode.store(ACTIVE_OPCODE, Ordering::Release);
        unsafe {
            serialize_instruction_stream();
        }
        Ok(())
    }

    #[cfg(test)]
    fn disable(&self) {
        let opcode = unsafe { &*self.writable.add(SITE_OFFSET).cast::<AtomicU8>() };
        opcode.store(INACTIVE_OPCODE, Ordering::Release);
        unsafe {
            serialize_instruction_stream();
        }
    }

    pub(crate) unsafe fn dispatch(&self) -> u32 {
        let function: unsafe extern "C" fn() -> u32 =
            unsafe { core::mem::transmute(self.executable.add(SITE_OFFSET)) };
        unsafe { function() }
    }

    #[cfg(test)]
    fn bytes(&self, offset: usize, len: usize) -> &[u8] {
        assert!(offset + len <= self.mapping_len);
        unsafe { core::slice::from_raw_parts(self.writable.add(offset), len) }
    }
}

unsafe impl Send for PunProbe {}
unsafe impl Sync for PunProbe {}

impl Drop for PunProbe {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.executable.cast(), self.mapping_len);
            libc::munmap(self.writable.cast(), self.mapping_len);
        }
    }
}

unsafe fn serialize_instruction_stream() {
    let _ = core::arch::x86_64::__cpuid_count(0, 0);
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use super::ACTIVE_OPCODE;
    use super::INACTIVE_OPCODE;
    use super::PunProbe;
    use super::SITE_OFFSET;

    static CALLBACKS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn count_callback() {
        CALLBACKS.fetch_add(1, Ordering::Relaxed);
    }

    fn permissions(address: usize) -> String {
        fs::read_to_string("/proc/self/maps")
            .unwrap()
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let range = fields.next()?;
                let permissions = fields.next()?;
                let (start, end) = range.split_once('-')?;
                let start = usize::from_str_radix(start, 16).ok()?;
                let end = usize::from_str_radix(end, 16).ok()?;
                (start <= address && address < end).then(|| permissions.to_owned())
            })
            .unwrap()
    }

    #[test]
    fn one_byte_pun_redirects_to_tool_trampoline() {
        CALLBACKS.store(0, Ordering::Relaxed);
        let probe = PunProbe::new(count_callback).unwrap();
        let tail = probe.bytes(SITE_OFFSET + 1, 4).to_vec();
        let writable_permissions = permissions(probe.writable as usize);
        let executable_permissions = permissions(probe.executable as usize);

        assert!(writable_permissions.starts_with("rw-"));
        assert!(!writable_permissions.contains('x'));
        assert!(executable_permissions.starts_with("r-x"));
        assert!(!executable_permissions.contains('w'));

        assert_eq!(probe.bytes(SITE_OFFSET, 1)[0], INACTIVE_OPCODE);
        unsafe {
            probe.dispatch();
        }
        assert_eq!(CALLBACKS.load(Ordering::Relaxed), 0);

        probe.enable().unwrap();
        assert_eq!(probe.bytes(SITE_OFFSET, 1)[0], ACTIVE_OPCODE);
        assert_eq!(probe.bytes(SITE_OFFSET + 1, 4), tail);
        unsafe {
            probe.dispatch();
        }
        assert_eq!(CALLBACKS.load(Ordering::Relaxed), 1);

        probe.disable();
        assert_eq!(probe.bytes(SITE_OFFSET, 1)[0], INACTIVE_OPCODE);
        assert_eq!(probe.bytes(SITE_OFFSET + 1, 4), tail);
    }
}
