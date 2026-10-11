//! Test the private pointer guard without passing invalid pointers to GlobalAlloc.

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;

reverie_liteinst::declare_legacy_private_tool_allocator!();

fn main() {
    let mode = std::env::args()
        .nth(1)
        .expect("valid, null, foreign, max or blocked-exit");
    let layout = Layout::from_size_align(128, 64).unwrap();
    match mode.as_str() {
        "valid" => {
            let pointer = unsafe { std::alloc::alloc(layout) };
            assert!(!pointer.is_null());
            unsafe { pointer.write_bytes(0x5a, layout.size()) };
            reverie_liteinst::PrivateToolAllocator::require_owned_address(pointer as usize);
            for i in 0..layout.size() {
                assert_eq!(unsafe { pointer.add(i).read() }, 0x5a);
            }
            unsafe { std::alloc::dealloc(pointer, layout) };
            println!("M1_PRIVATE_GUARD valid=1 bytes_ok=1");
        }
        "null" => reverie_liteinst::PrivateToolAllocator::require_owned_address(0),
        "max" => reverie_liteinst::PrivateToolAllocator::require_owned_address(usize::MAX),
        "blocked-exit" => {
            // Refuse exit_group so the guard must take its allocation-free
            // illegal-instruction fallback instead of returning or spinning.
            let instructions = [
                libc::sock_filter {
                    code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 1,
                    k: libc::SYS_exit_group as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ALLOW,
                },
            ];
            let program = libc::sock_fprog {
                len: instructions.len() as u16,
                filter: instructions.as_ptr().cast_mut(),
            };
            // SAFETY: fresh single-threaded child and initialized kernel ABI.
            unsafe {
                assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
                assert_eq!(
                    libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
                    0
                );
            }
            reverie_liteinst::PrivateToolAllocator::require_owned_address(0);
        }
        "foreign" => {
            // This explicit System allocation is a test-only foreign owner.
            // Never hand it to std::alloc/dealloc or the private GlobalAlloc.
            let pointer = unsafe { System.alloc(layout) };
            assert!(!pointer.is_null());
            unsafe { pointer.write_bytes(0xa5, layout.size()) };
            assert_eq!(
                reverie_liteinst::allocator_fixture::m1_probe_private(pointer),
                0
            );
            reverie_liteinst::PrivateToolAllocator::require_owned_address(pointer as usize);
            // Reached only if the guard is defective, still using its true owner.
            unsafe { System.dealloc(pointer, layout) };
            panic!("private guard admitted a foreign allocation");
        }
        _ => panic!("unknown private guard case"),
    }
    assert_eq!(mode, "valid", "invalid address guard unexpectedly returned");
}
