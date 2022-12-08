/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::mem;
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
        ptrace::read(self.0.into(), unsafe {
            addr.as_ptr() as *mut ::core::ffi::c_void
        })
        .map_err(|err| Errno::new(err as i32))
        .map(|x| x as u64)
    }

    /// Writes a single u64.
    fn write_u64(&mut self, addr: AddrMut<u64>, value: u64) -> Result<(), Errno> {
        unsafe {
            ptrace::write(
                self.0.into(),
                addr.as_mut_ptr() as *mut ::core::ffi::c_void,
                value as *mut ::core::ffi::c_void,
            )
        }
        .map_err(|err| Errno::new(err as i32))
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

    fn write(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        let size = buf.len();
        if size == 0 {
            return Ok(0);
        } else if size == mem::size_of::<u64>() {
            #[allow(clippy::cast_ptr_alignment)]
            let value = unsafe { *(buf.as_ptr() as *const u64) };
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
}

#[cfg(test)]
mod test {
    use std::ffi::CString;

    use nix::sys::ptrace;
    use nix::sys::signal::raise;
    use nix::sys::signal::Signal;
    use nix::sys::wait::waitpid;
    use nix::sys::wait::WaitStatus;
    use nix::unistd::fork;
    use nix::unistd::ForkResult;
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
    fn test_remote_memory() {
        // We need our generator to produce vectors that are at least one page
        // in size, ideally larger. By default, quickcheck uses a max size of
        // 100 which is far too small. Here, we use 4 pages in size.
        //
        // FIXME: Because of the issue [1], u8::arbitrary() only ever generates
        // zeros when size % u8::max_value() == 0.
        //
        // [1] https://github.com/BurntSushi/quickcheck/issues/119
        let mut qc = QuickCheck::new().gen(quickcheck::Gen::new(0x4000 + u8::max_value() as usize));

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
