/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::mem;
use std::ffi::c_long;
use std::io;

use nix::sys::ptrace;
use reverie_memory::Addr;
use reverie_memory::AddrMut;
use reverie_memory::AddrSlice;
use reverie_memory::AddrSliceMut;
use reverie_memory::MemoryAccess;
use syscalls::Errno;

use super::Stopped;

impl Stopped {
    /// Does a read that is already page-aligned.
    fn read_aligned(&self, addr: Addr<u8>, buf: &mut [u8]) -> Result<usize, Errno> {
        let slice = unsafe { AddrSlice::from_raw_parts(addr, buf.len()) };
        let from = [unsafe { slice.as_ioslice() }];
        let mut to = [io::IoSliceMut::new(buf)];
        self.read_vectored(&from, &mut to)
    }

    /// Does a write that is already page-aligned.
    fn write_aligned(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        let mut slice = unsafe { AddrSliceMut::from_raw_parts(addr, buf.len()) };
        let from = [io::IoSlice::new(buf)];
        let mut to = [unsafe { slice.as_ioslice_mut() }];
        self.write_vectored(&from, &mut to)
    }

    /// Reads a single u64.
    fn read_u64(&self, addr: Addr<u64>) -> Result<u64, Errno> {
        self.1.on_held_tid(|| {
            ptrace::read(self.0.into(), unsafe {
                addr.as_ptr() as *mut ::core::ffi::c_void
            })
            .map_err(|err| Errno::new(err as i32))
            .map(|x| x as u64)
        })
    }

    /// Writes a single u64.
    fn write_u64(&mut self, addr: AddrMut<u64>, value: u64) -> Result<(), Errno> {
        self.1.on_held_tid(|| {
            unsafe {
                ptrace::write(
                    self.0.into(),
                    addr.as_mut_ptr() as *mut ::core::ffi::c_void,
                    value as c_long,
                )
            }
            .map_err(|err| Errno::new(err as i32))
        })
    }
}

impl MemoryAccess for Stopped {
    /// Does a vectored read from the remote address space. Returns the number of
    /// bytes read.
    ///
    /// Note that there is no guarantee that all of the requested buffers will be
    /// filled. See `man 2 process_vm_readv` for more information on specific
    /// behavior.
    fn read_vectored(
        &self,
        remote: &[io::IoSlice],
        local: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        self.1
            .on_held_tid(|| {
                Errno::result(unsafe {
                    libc::process_vm_readv(
                        self.0.as_raw(),
                        local.as_ptr() as *const libc::iovec,
                        local.len() as libc::c_ulong,
                        remote.as_ptr() as *const libc::iovec,
                        remote.len() as libc::c_ulong,
                        0,
                    )
                })
                .map(|x| x as usize)
            })
            .or_else(|err| {
                if err == Errno::EFAULT {
                    // Treat page faults as an EOF.
                    Ok(0)
                } else {
                    Err(err)
                }
            })
    }

    /// Does a vectored writes to the address space. Returns the number of bytes
    /// written.
    ///
    /// Note that there is no guarantee that all of the requested buffers will
    /// be written. See `man 2 process_vm_writev` for more information on
    /// specific behavior.
    fn write_vectored(
        &mut self,
        local: &[io::IoSlice],
        remote: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        self.1
            .on_held_tid(|| {
                Errno::result(unsafe {
                    libc::process_vm_writev(
                        self.0.as_raw(),
                        local.as_ptr() as *const libc::iovec,
                        local.len() as libc::c_ulong,
                        remote.as_ptr() as *const libc::iovec,
                        remote.len() as libc::c_ulong,
                        0,
                    )
                })
                .map(|x| x as usize)
            })
            .or_else(|err| {
                if err == Errno::EFAULT {
                    // Treat page faults as an EOF.
                    Ok(0)
                } else {
                    Err(err)
                }
            })
    }

    /// Performs a read starting at the given address. The number of bytes read
    /// is returned. The buffer is not guaranteed to be completely filled.
    fn read<'a, A>(&self, addr: A, buf: &mut [u8]) -> Result<usize, Errno>
    where
        A: Into<Addr<'a, u8>>,
    {
        let addr = addr.into();
        let size = buf.len();
        if size == 0 {
            return Ok(0);
        } else if size <= mem::size_of::<u64>() {
            // This needs to be benchmarked, but according to @wangbj
            // PTRACE_PEEKDATA is faster than `process_vm_readv` for small
            // reads.
            let value = self.read_u64(addr.cast::<u64>())?;
            let bytes = value.to_ne_bytes();
            buf.copy_from_slice(&bytes[0..size]);
            return Ok(size);
        }

        let addr_slice = unsafe { AddrSlice::from_raw_parts(addr, buf.len()) };

        // Since process_vm_readv partial transfers apply at the granularity of
        // the iovec elements, we need to know if the address range spans a page
        // boundary and split the remote read if it does. This helps ensure that
        // we get a read length >0 while there is still more data to read.
        if let Some((first, second)) = addr_slice.split_at_page_boundary() {
            let remote = unsafe { [first.as_ioslice(), second.as_ioslice()] };

            // The two remote reads are merged into a single local buffer.
            let mut local = [io::IoSliceMut::new(buf)];

            self.read_vectored(&remote, &mut local)
        } else {
            // The address range fits into one page. Nothing special to do.
            self.read_aligned(addr, buf)
        }
    }

    fn read_exact_with_user_access<'a, A>(&self, addr: A, buf: &mut [u8]) -> Result<(), Errno>
    where
        A: Into<Addr<'a, u8>>,
    {
        let addr = addr.into();
        addr.as_raw().checked_add(buf.len()).ok_or(Errno::EFAULT)?;

        let remote = unsafe { AddrSlice::from_raw_parts(addr, buf.len()) };
        let remote = [unsafe { remote.as_ioslice() }];
        let mut local = [io::IoSliceMut::new(buf)];

        if self.read_vectored(&remote, &mut local)? == buf.len() {
            Ok(())
        } else {
            Err(Errno::EFAULT)
        }
    }

    fn write(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        let size = buf.len();
        if size == 0 {
            return Ok(0);
        } else if size == mem::size_of::<u64>() {
            let value = u64::from_ne_bytes(buf.try_into().unwrap());
            self.write_u64(addr.cast::<u64>(), value)?;
            return Ok(size);
        }

        let mut addr_slice = unsafe { AddrSliceMut::from_raw_parts(addr, buf.len()) };

        // Since process_vm_writev partial transfers apply at the granularity of
        // the iovec elements, we need to know if the address range spans a page
        // boundary and split the remote write if it does. This helps ensure that
        // we get a write length >0 before we hit a protected page.
        if let Some((mut first, mut second)) = addr_slice.split_at_page_boundary() {
            let mut remote = unsafe { [first.as_ioslice_mut(), second.as_ioslice_mut()] };

            // The two remote writes come from a single local buffer.
            let local = [io::IoSlice::new(buf)];

            self.write_vectored(&local, &mut remote)
        } else {
            // The address range fits into one page. Nothing special to do.
            self.write_aligned(addr, buf)
        }
    }

    fn write_with_user_access(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(0);
        }
        addr.as_raw().checked_add(buf.len()).ok_or(Errno::EFAULT)?;
        let local = libc::iovec {
            iov_base: buf.as_ptr().cast_mut().cast(),
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: addr.as_raw() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        // SAFETY: local describes the live source slice. The remote address is
        // only a numeric kernel operand; no Rust reference is formed from it.
        // Unlike POKEDATA, process_vm_writev checks writable VMA permissions.
        let written = self.1.on_held_tid(|| {
            Errno::result(unsafe {
                libc::process_vm_writev(self.0.as_raw(), &local, 1, &remote, 1, 0)
            })
        })? as usize;
        if written == 0 {
            Err(Errno::EFAULT)
        } else {
            Ok(written)
        }
    }
}

#[cfg(test)]
mod test {
    use std::ffi::CString;

    use nix::sys::ptrace;
    use nix::sys::signal::Signal;
    use nix::sys::signal::raise;
    use nix::sys::wait::WaitStatus;
    use nix::sys::wait::waitpid;
    use nix::unistd::ForkResult;
    use nix::unistd::fork;
    use quickcheck::QuickCheck;
    use quickcheck_macros::quickcheck;
    use reverie_process::Pid;

    use super::*;

    // Helper function for spawning a child process in a stopped state. The
    // value `T` will be in the child's address space allowing us to read or
    // modify it from the parent.
    fn fork_helper<P, C, T>(mut value: T, parent: P, child: C) -> bool
    where
        P: FnOnce(Pid, T) -> bool,
        C: FnOnce(&mut T),
    {
        match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child, .. } => {
                assert_eq!(
                    waitpid(child, None).unwrap(),
                    WaitStatus::Stopped(child, Signal::SIGTRAP)
                );

                let result = parent(child.into(), value);

                // Allow child to exit.
                ptrace::cont(child, None).unwrap();
                assert_eq!(waitpid(child, None).unwrap(), WaitStatus::Exited(child, 0));

                result
            }
            ForkResult::Child => {
                ptrace::traceme().unwrap();

                // Give us a chance to modify if needed.
                child(&mut value);

                // Allow parent to control when we exit. While stopped here, the
                // parent can mess with the child's memory.
                raise(Signal::SIGTRAP).unwrap();

                // Can't use the normal exit function here because we don't want
                // to call atexit handlers since `execve` was never called.
                unsafe {
                    ::libc::_exit(0);
                }
            }
        }
    }

    fn prop_remote_read_exact(buf: Vec<u8>) -> bool {
        fork_helper(
            buf,
            move |child, mut buf| {
                let copied = buf.clone();

                let memory = Stopped::new_unchecked(child);
                let addr = Addr::from_ptr(buf.as_ptr()).unwrap();

                // Zero out the buffer just to show that we are really reading from
                // the child process and not our own process.
                for byte in buf.iter_mut() {
                    *byte = 0;
                }

                memory.read_exact(addr, &mut buf).unwrap();

                buf == copied
            },
            |_| {},
        )
    }

    fn prop_remote_write_exact(buf: Vec<u8>) -> bool {
        fork_helper(
            buf,
            move |child, mut buf| {
                let copied = buf.clone();

                let mut memory = Stopped::new_unchecked(child);
                let addr = AddrMut::from_ptr(buf.as_ptr()).unwrap();

                memory.write_exact(addr, &copied).unwrap();
                memory.read_exact(addr, &mut buf).unwrap();

                buf == copied
            },
            |buf| {
                // Zero out the buffer before the parent gets a chance to write
                // to it to demonstrate that writes by the parent are actually
                // working.
                for byte in buf.iter_mut() {
                    *byte = 0;
                }
            },
        )
    }

    #[test]
    fn remote_write_exact_accepts_unaligned_eight_byte_source() {
        #[repr(align(8))]
        struct Aligned([u8; 9]);

        assert!(fork_helper(
            vec![0; 8],
            move |child, mut remote_buf| {
                let source = Aligned([0, 1, 2, 3, 4, 5, 6, 7, 8]);
                let source = &source.0[1..];
                assert_ne!(source.as_ptr() as usize % mem::align_of::<u64>(), 0);

                let mut memory = Stopped::new_unchecked(child);
                let addr = AddrMut::from_ptr(remote_buf.as_ptr()).unwrap();
                memory.write_exact(addr, source).unwrap();
                memory.read_exact(addr, &mut remote_buf).unwrap();

                remote_buf == source
            },
            |_| {},
        ));
    }

    fn page_size() -> usize {
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(size > 0);
        size as usize
    }

    fn map_pages(count: usize) -> (*mut u8, usize) {
        let length = page_size().checked_mul(count).unwrap();
        let mapping = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        (mapping.cast(), length)
    }

    fn unmap_pages(mapping: *mut u8, length: usize) {
        assert_eq!(unsafe { libc::munmap(mapping.cast(), length) }, 0);
    }

    fn assert_user_copy_bytes(
        memory: &Stopped,
        address: usize,
        total: usize,
        offset: usize,
        source: &[u8],
        copied: usize,
    ) {
        for at in (0..total).step_by(8) {
            // PEEK can inspect canaries even on the child's PROT_NONE page.
            let actual = memory
                .read_u64(Addr::from_raw(address + at).unwrap())
                .unwrap()
                .to_ne_bytes();
            for (index, byte) in actual.into_iter().enumerate() {
                let index = at + index;
                let expected = if index >= offset && index - offset < copied {
                    source[index - offset]
                } else {
                    0xa5
                };
                assert_eq!(byte, expected, "destination byte {index}");
            }
        }
    }

    #[test]
    fn remote_user_copy_checks_permissions_at_every_size_and_preserves_prefixes() {
        let page = page_size();
        for protection in [libc::PROT_READ, libc::PROT_NONE] {
            for offset in [0, page - 3, page] {
                for length in [0, 1, 7, 8, 9, page + 8] {
                    let (mapping, total) = map_pages(3);
                    unsafe { core::ptr::write_bytes(mapping, 0xa5, total) };
                    let passed = fork_helper(
                        mapping as usize,
                        move |child, address| {
                            let mut memory = Stopped::new_unchecked(child);
                            let source: Vec<_> =
                                (0..length + 1).map(|i| (19 + i * 37) as u8).collect();
                            let source = &source[1..];
                            let destination = AddrMut::from_raw(address + offset).unwrap();
                            let expected = if offset < page {
                                (page - offset).min(length)
                            } else {
                                0
                            };
                            assert_eq!(
                                memory.write_with_user_access(destination, source),
                                if expected != 0 || length == 0 {
                                    Ok(expected)
                                } else {
                                    Err(Errno::EFAULT)
                                },
                                "protection={protection} offset={offset} length={length}"
                            );
                            assert_user_copy_bytes(
                                &memory, address, total, offset, source, expected,
                            );
                            true
                        },
                        move |address| {
                            assert_eq!(
                                unsafe {
                                    libc::mprotect(
                                        (*address as *mut u8).add(page).cast(),
                                        page,
                                        protection,
                                    )
                                },
                                0
                            );
                        },
                    );
                    unmap_pages(mapping, total);
                    assert!(passed);
                }
            }
        }
    }

    #[test]
    fn remote_user_copy_does_not_change_the_eight_byte_debugger_contract() {
        let (mapping, length) = map_pages(1);
        let passed = fork_helper(
            mapping as usize,
            move |child, address| {
                let mut memory = Stopped::new_unchecked(child);
                let destination = AddrMut::from_raw(address).unwrap();
                let original = *b"debugger";
                assert_eq!(memory.write(destination, &original), Ok(8));
                assert_eq!(
                    memory.write_with_user_access(destination, b"rejected"),
                    Err(Errno::EFAULT)
                );
                assert_eq!(
                    memory
                        .read_u64(Addr::from_raw(address).unwrap())
                        .unwrap()
                        .to_ne_bytes(),
                    original
                );
                true
            },
            move |address| {
                assert_eq!(
                    unsafe {
                        libc::mprotect(*address as *mut libc::c_void, length, libc::PROT_READ)
                    },
                    0
                );
            },
        );
        unmap_pages(mapping, length);
        assert!(passed);
    }

    #[test]
    fn remote_user_copy_empty_and_invalid_addresses_preserve_memory() {
        let (mapping, total) = map_pages(1);
        unsafe { core::ptr::write_bytes(mapping, 0xa5, total) };
        let passed = fork_helper(
            mapping as usize,
            move |child, address| {
                let mut memory = Stopped::new_unchecked(child);
                for invalid in [1, usize::MAX - 3, usize::MAX] {
                    let destination = AddrMut::from_raw(invalid).unwrap();
                    assert_eq!(memory.write_with_user_access(destination, &[]), Ok(0));
                    for source in [&b"x"[..], &b"rejected"[..]] {
                        assert_eq!(
                            memory.write_with_user_access(destination, source),
                            Err(Errno::EFAULT)
                        );
                        assert_user_copy_bytes(&memory, address, total, 0, &[], 0);
                    }
                }
                true
            },
            |_| {},
        );
        unmap_pages(mapping, total);
        assert!(passed);
    }

    #[test]
    fn remote_user_copy_preserves_non_fault_errno() {
        // An invalid PID cannot be recycled into a live target. The unchecked
        // handle deliberately exercises a kernel error, not a stopped child.
        let mut memory = Stopped::new_unchecked(Pid::from_raw(-1));
        let mut destination = [0xa5; 8];
        let address = AddrMut::from_ptr(destination.as_mut_ptr()).unwrap();
        assert_eq!(
            memory.write_with_user_access(address, b"rejected"),
            Err(Errno::ESRCH)
        );
        assert_eq!(destination, [0xa5; 8]);
        assert_eq!(
            memory.write_with_user_access(AddrMut::from_raw(usize::MAX).unwrap(), &[]),
            Ok(0)
        );
    }

    #[test]
    fn remote_read_exact_with_user_access_reads_eight_bytes() {
        let expected = [1, 2, 3, 4, 5, 6, 7, 8];
        let (mapping, length) = map_pages(1);
        unsafe { core::ptr::copy_nonoverlapping(expected.as_ptr(), mapping, expected.len()) };

        let passed = fork_helper(
            mapping as usize,
            move |child, address| {
                let memory = Stopped::new_unchecked(child);
                let address = Addr::from_raw(address).unwrap();
                let mut observed = [0; 8];
                memory
                    .read_exact_with_user_access(address, &mut observed)
                    .unwrap();
                observed == expected
            },
            |_| {},
        );

        unmap_pages(mapping, length);
        assert!(passed);
    }

    #[test]
    fn remote_read_exact_with_user_access_rejects_prot_none() {
        let (mapping, length) = map_pages(1);
        let passed = fork_helper(
            mapping as usize,
            move |child, address| {
                let memory = Stopped::new_unchecked(child);
                let address = Addr::from_raw(address).unwrap();
                let mut observed = [0; 8];
                memory.read_exact_with_user_access(address, &mut observed) == Err(Errno::EFAULT)
            },
            move |address| {
                assert_eq!(
                    unsafe {
                        libc::mprotect(*address as *mut libc::c_void, length, libc::PROT_NONE)
                    },
                    0
                );
            },
        );

        unmap_pages(mapping, length);
        assert!(passed);
    }

    #[test]
    fn remote_read_exact_with_user_access_rejects_cross_page_partial_read() {
        let page_size = page_size();
        let (mapping, length) = map_pages(2);
        let start = unsafe { mapping.add(page_size - 4) };
        let expected = [1, 2, 3, 4, 5, 6, 7, 8];
        unsafe { core::ptr::copy_nonoverlapping(expected.as_ptr(), start, expected.len()) };

        let passed = fork_helper(
            start as usize,
            move |child, address| {
                let memory = Stopped::new_unchecked(child);
                let address = Addr::from_raw(address).unwrap();
                let mut observed = [0; 8];
                memory.read_exact_with_user_access(address, &mut observed) == Err(Errno::EFAULT)
            },
            move |_| {
                assert_eq!(
                    unsafe {
                        libc::mprotect(mapping.add(page_size).cast(), page_size, libc::PROT_NONE)
                    },
                    0
                );
            },
        );

        unmap_pages(mapping, length);
        assert!(passed);
    }

    #[test]
    fn test_remote_memory() {
        // We need our generator to produce vectors that are at least one page
        // in size, ideally larger. By default, quickcheck uses a max size of
        // 100 which is far too small. Here, we use 4 pages in size.
        //
        // FIXME: Because of the issue [1], u8::arbitrary() only ever generates
        // zeros when size % u8::MAX == 0.
        //
        // [1] https://github.com/BurntSushi/quickcheck/issues/119
        let mut qc = QuickCheck::new().rng(quickcheck::Gen::new(0x4000 + u8::MAX as usize));

        qc.quickcheck(prop_remote_read_exact as fn(Vec<u8>) -> bool);

        // Check with some known small reads. Quickcheck probably won't always
        // cover these cases due to random chance.
        assert!(prop_remote_read_exact(vec![]));
        assert!(prop_remote_read_exact(vec![1]));
        assert!(prop_remote_read_exact(vec![1, 2]));
        assert!(prop_remote_read_exact(vec![1, 2, 3]));
        assert!(prop_remote_read_exact(vec![1, 2, 3, 4]));
        assert!(prop_remote_read_exact(vec![1, 2, 3, 4, 5, 6, 7, 8]));

        qc.quickcheck(prop_remote_write_exact as fn(Vec<u8>) -> bool);

        // Check with some known small reads. Quickcheck probably won't always
        // cover these cases due to random chance.
        assert!(prop_remote_write_exact(vec![]));
        assert!(prop_remote_write_exact(vec![1]));
        assert!(prop_remote_write_exact(vec![1, 2]));
        assert!(prop_remote_write_exact(vec![1, 2, 3]));
        assert!(prop_remote_write_exact(vec![1, 2, 3, 4]));
        assert!(prop_remote_write_exact(vec![1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[quickcheck]
    fn prop_remote_read_cstring(s: String) -> bool {
        // quickcheck doesn't support CString :-(
        let s = CString::new(
            s.into_bytes()
                .into_iter()
                .filter(|&x| x != 0)
                .collect::<Vec<_>>(),
        )
        .unwrap();

        fork_helper(
            s,
            move |child, s| {
                let memory = Stopped::new_unchecked(child);
                let addr = Addr::from_ptr(s.as_bytes().as_ptr()).unwrap();

                let remote_string = memory.read_cstring(addr).unwrap();

                remote_string == s
            },
            |_| {},
        )
    }
}
