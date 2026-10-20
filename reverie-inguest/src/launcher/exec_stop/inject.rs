/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A stopped-task mapping transaction. Only its initial, no-replace reservation
//! authorizes replacing PROT_NONE pages. Every failure keeps the task owned by
//! the outer cancellation guard; it never detaches a partially armed guest.

use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;

use reverie_loader::artifact::TOOL_REGION;
use reverie_loader::image::PAGE_SIZE;
#[cfg(feature = "stage1a-probe")]
use reverie_loader::image::ValidatedImage;
use safeptrace::Event;
use safeptrace::Regs;
use safeptrace::Signal;
use safeptrace::Stopped;

use super::Result;
#[cfg(feature = "stage1a-probe")]
use super::images::SealedImage;
use super::mapping_plan::Source;
use super::mapping_plan::Step;
use super::mapping_plan::{self};
pub use super::trace::read;
pub use super::trace::stopped;
#[cfg(feature = "stage1a-probe")]
pub use super::trace::wait;
pub use super::trace::write;

/// Injected syscall number, six arguments, and the observed return value.
pub type InjectedCall = (u64, [u64; 6], u64);

/// An owned stopped-task injection transaction; errors prohibit successful finish.
pub struct Injector {
    task: Option<Stopped>,
    entry: Regs,
    original: Vec<u8>,
    reservation: bool,
    arbitrary_syscall_used: bool,
    poisoned: bool,
    mapped: Vec<std::ops::Range<u64>>,
    #[cfg(feature = "loader-private-runtime")]
    ledger: Vec<[u64; 4]>,
    #[cfg(feature = "loader-private-runtime")]
    filter_installed: bool,
    /// Actual completed injected calls, retained even on a later refusal.
    pub calls: Vec<InjectedCall>,
}

impl Injector {
    /// Save and temporarily patch this actual stop's entry for syscall injection.
    pub fn new(mut task: Stopped) -> Result<Self> {
        let entry = task.getregs()?;
        let original = read(&task, entry.rip, 8)?;
        let mut injected = original.clone();
        injected[..3].copy_from_slice(&[0x0f, 0x05, 0xcc]);
        write(&mut task, entry.rip, &injected)?;
        Ok(Self {
            task: Some(task),
            entry,
            original,
            reservation: false,
            arbitrary_syscall_used: false,
            poisoned: false,
            mapped: Vec::new(),
            #[cfg(feature = "loader-private-runtime")]
            ledger: Vec::new(),
            #[cfg(feature = "loader-private-runtime")]
            filter_installed: false,
            calls: Vec::new(),
        })
    }

    /// Borrow the owned stop without resuming or transferring its authority.
    pub fn stopped(&self) -> Result<&Stopped> {
        self.task
            .as_ref()
            .ok_or_else(|| "lost stopped injection owner".into())
    }

    /// Write/read a saved test slot while this transaction alone owns the stop.
    #[cfg(feature = "stage1a-probe")]
    pub fn stopped_mut(&mut self) -> Result<&mut Stopped> {
        self.task
            .as_mut()
            .ok_or_else(|| "lost stopped injection owner".into())
    }

    /// Execute one tool syscall in a transaction that cannot own mappings.
    ///
    /// An arbitrary call could replace a reservation or a validated image fd.
    /// Keep this diagnostic transaction disjoint from mapping authority.
    #[cfg(feature = "stage1a-probe")]
    pub fn syscall(&mut self, number: u64, args: [u64; 6]) -> Result<u64> {
        if self.reservation {
            self.poisoned = true;
            return Err(
                "loader refused: arbitrary syscall during owned mapping transaction".into(),
            );
        }
        self.arbitrary_syscall_used = true;
        self.checked_syscall(number, args)
    }

    fn checked_syscall(&mut self, number: u64, args: [u64; 6]) -> Result<u64> {
        #[cfg(feature = "loader-private-runtime")]
        if self.filter_installed {
            self.poisoned = true;
            return Err("mapped_filter_last_forbids_further_injected_syscall".into());
        }
        if self.poisoned {
            return Err("loader refused: poisoned injection transaction".into());
        }
        let result = self.syscall_inner(number, args);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn syscall_inner(&mut self, number: u64, args: [u64; 6]) -> Result<u64> {
        let task = self.task.take().ok_or("lost stopped injection owner")?;
        let mut regs = self.entry;
        regs.rax = number;
        regs.orig_rax = u64::MAX;
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.r10 = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];
        task.setregs(&regs)?;
        let (task, event) = stopped(task.resume(None)?, "injected syscall completion")?;
        let completed = task.getregs()?;
        let marker =
            matches!(event, Event::Signal(Signal::SIGTRAP)) && completed.rip == self.entry.rip + 3;
        self.task = Some(task);
        if !marker {
            return Err(
                format!("loader refused: injection stopped outside its marker: {event:?}").into(),
            );
        }
        self.calls.push((number, args, completed.rax));
        if (completed.rax as i64) < 0 && completed.rax >= (-4095_i64) as u64 {
            return Err(format!(
                "loader injected syscall {number} refused with errno {}",
                -(completed.rax as i64)
            )
            .into());
        }
        Ok(completed.rax)
    }

    /// Acquire the complete fixed tool reservation without replacing guest pages.
    pub fn reserve(&mut self) -> Result<()> {
        if self.reservation || self.poisoned || self.arbitrary_syscall_used {
            self.poisoned = true;
            return Err("loader refused: reservation transaction already used".into());
        }
        let actual = self
            .checked_syscall(
                libc::SYS_mmap as u64,
                [
                    TOOL_REGION.start,
                    TOOL_REGION.end - TOOL_REGION.start,
                    libc::PROT_NONE as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as u64,
                    u64::MAX,
                    0,
                ],
            )
            .map_err(|error| {
                if self
                    .calls
                    .last()
                    .is_some_and(|(_, _, result)| *result == (-libc::EEXIST as i64) as u64)
                {
                    "tool_region_collision: no-replace reservation encountered an existing mapping"
                        .into()
                } else {
                    error
                }
            })?;
        if actual != TOOL_REGION.start {
            self.poisoned = true;
            return Err(
                "loader refused: kernel did not honor the fixed no-replace reservation".into(),
            );
        }
        self.reservation = true;
        Ok(())
    }

    fn owned(&self, start: u64, length: u64) -> Result<()> {
        if !self.reservation
            || length == 0
            || !start.is_multiple_of(PAGE_SIZE)
            || !length.is_multiple_of(PAGE_SIZE)
            || start < TOOL_REGION.start
            || start
                .checked_add(length)
                .is_none_or(|end| end > TOOL_REGION.end)
        {
            return Err("loader refused: mapping does not belong to its fresh reservation".into());
        }
        Ok(())
    }

    fn map_pages(
        &mut self,
        start: u64,
        length: u64,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: u64,
    ) -> Result<()> {
        if self.poisoned {
            return Err("loader refused: poisoned injection transaction".into());
        }
        let validation = (|| -> Result<()> {
            self.owned(start, length)?;
            let end = start.checked_add(length).ok_or("mapping overflow")?;
            if self
                .mapped
                .iter()
                .any(|range| start < range.end && range.start < end)
            {
                return Err("loader refused: mapping overlaps a live bootstrap mapping".into());
            }
            if protection & libc::PROT_WRITE != 0 && protection & libc::PROT_EXEC != 0 {
                return Err("loader refused: writable executable mapping".into());
            }
            if flags & !(libc::MAP_PRIVATE | libc::MAP_SHARED | libc::MAP_ANONYMOUS) != 0
                || (flags & (libc::MAP_PRIVATE | libc::MAP_SHARED)).count_ones() != 1
            {
                return Err("loader refused: unsupported bootstrap mapping flags".into());
            }
            Ok(())
        })();
        if let Err(error) = validation {
            self.poisoned = true;
            return Err(error);
        }
        let actual = self.checked_syscall(
            libc::SYS_mmap as u64,
            [
                start,
                length,
                protection as u64,
                mapping_plan::effective_flags(flags) as u64,
                fd as u64,
                offset,
            ],
        )?;
        if actual != start {
            self.poisoned = true;
            return Err("loader refused: mapping returned the wrong address".into());
        }
        self.mapped.push(start..start + length);
        #[cfg(feature = "loader-private-runtime")]
        self.ledger
            .push(mapping_plan::mapping_row(start, length, protection, flags)?);
        Ok(())
    }

    /// Map exactly the immutable descriptor whose sealed bytes were validated.
    #[cfg(feature = "stage1a-probe")]
    pub fn map_image(&mut self, image: &SealedImage) -> Result<()> {
        if self.poisoned {
            return Err("loader refused: poisoned injection transaction".into());
        }
        let result = (|| {
            let checked = image.checked()?;
            self.map_checked_image(&checked, image.fd())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    #[cfg(feature = "loader-private-runtime")]
    pub(super) fn map_production_plan(
        &mut self,
        steps: &[Step],
        runtime_fd: BorrowedFd<'_>,
        handoff_fd: BorrowedFd<'_>,
    ) -> Result<()> {
        let result = self.apply_steps(steps, runtime_fd.as_raw_fd(), Some(handoff_fd));
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    #[cfg(feature = "loader-private-runtime")]
    pub(super) fn mapping_ledger(&self) -> Vec<[u64; 4]> {
        let mut ledger = self.ledger.clone();
        ledger.sort_unstable_by_key(|row| row[0]);
        ledger
    }

    #[cfg(feature = "stage1a-probe")]
    fn map_checked_image(&mut self, image: &ValidatedImage<'_>, fd: i32) -> Result<()> {
        let steps = mapping_plan::image_steps(image)?;
        self.apply_steps(&steps, fd, None)
    }

    fn apply_steps(
        &mut self,
        steps: &[Step],
        runtime_fd: i32,
        handoff_fd: Option<BorrowedFd<'_>>,
    ) -> Result<()> {
        #[cfg(not(feature = "loader-private-runtime"))]
        let _ = handoff_fd;
        for step in steps {
            match *step {
                Step::Map(mapping) => match mapping.source {
                    Source::ImageFile | Source::ImageAnonymous => self.map_pages(
                        mapping.start,
                        mapping.length,
                        mapping.protection,
                        mapping.flags,
                        if mapping.source == Source::ImageFile {
                            runtime_fd
                        } else {
                            -1
                        },
                        mapping.offset,
                    )?,
                    #[cfg(feature = "loader-private-runtime")]
                    Source::StorageAnonymous | Source::Handoff => self.map_storage(
                        mapping.start,
                        mapping.length,
                        mapping.protection,
                        mapping.flags,
                        if mapping.source == Source::Handoff {
                            Some(handoff_fd.ok_or("mapped_preparation_missing_handoff_backing")?)
                        } else {
                            None
                        },
                        mapping.offset,
                    )?,
                },
                Step::ZeroTail { start, length } => {
                    // Same ptrace private-page write after this load's maps:
                    // never grant write permission to executable mappings.
                    let zeros = vec![0; length];
                    write(
                        self.task.as_mut().ok_or("lost stopped owner")?,
                        start,
                        &zeros,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Map non-executable bootstrap data/stack storage in the owned reservation.
    /// A file-backed mapping borrows its exact descriptor for this operation;
    /// the caller retains its launch lease through physical child retirement.
    pub fn map_storage(
        &mut self,
        start: u64,
        length: u64,
        protection: i32,
        flags: i32,
        fd: Option<BorrowedFd<'_>>,
        offset: u64,
    ) -> Result<()> {
        let validation = (|| -> Result<()> {
            if protection & !(libc::PROT_READ | libc::PROT_WRITE) != 0 {
                return Err("loader refused: bootstrap storage must not be executable".into());
            }
            if (flags & libc::MAP_ANONYMOUS != 0) != fd.is_none() {
                return Err("loader refused: bootstrap storage backing mismatch".into());
            }
            if let Some(fd) = fd {
                let stat = nix::sys::stat::fstat(fd)?;
                if stat.st_size < 0
                    || offset
                        .checked_add(length)
                        .is_none_or(|end| end > stat.st_size as u64)
                {
                    return Err("loader refused: bootstrap storage exceeds file backing".into());
                }
            } else if offset != 0 {
                return Err("loader refused: anonymous bootstrap storage offset".into());
            }
            Ok(())
        })();
        if let Err(error) = validation {
            self.poisoned = true;
            return Err(error);
        }
        self.map_pages(
            start,
            length,
            protection,
            flags,
            fd.map_or(-1, |fd| fd.as_raw_fd()),
            offset,
        )
    }

    /// Final production operation. No arbitrary syscall or mapping can follow.
    #[cfg(feature = "loader-private-runtime")]
    pub(super) fn install_filter_last(&mut self, scratch: u64, program: &[u8]) -> Result<()> {
        let result = (|| -> Result<()> {
            if !self.reservation
                || self.filter_installed
                || self.poisoned
                || program.len() != 23 * 8
            {
                return Err("mapped_filter_last_invalid_transaction".into());
            }
            let staging = super::physical::filter_staging(scratch, program)?;
            let end = scratch
                .checked_add(staging.len() as u64)
                .ok_or("mapped_filter_staging_overflow")?;
            if !self.ledger.iter().any(|row| {
                row[0] <= scratch
                    && end <= row[1]
                    && row[2] == (libc::PROT_READ | libc::PROT_WRITE) as u64
            }) {
                return Err("mapped_filter_staging_not_owned_rw".into());
            }
            // PreparedExec already set this BEFORE genuine exec, preserving real
            // secure aux facts. Here only query the same kernel state.
            if self.checked_syscall(
                libc::SYS_prctl as u64,
                [libc::PR_GET_NO_NEW_PRIVS as u64, 0, 0, 0, 0, 0],
            )? != 1
            {
                return Err("mapped_filter_no_new_privs_readback".into());
            }
            write(
                self.task.as_mut().ok_or("lost stopped owner")?,
                scratch,
                &staging,
            )?;
            if read(self.stopped()?, scratch, staging.len())? != staging {
                return Err("mapped_filter_staging_readback".into());
            }
            let result = self.checked_syscall(
                libc::SYS_seccomp as u64,
                [
                    libc::SECCOMP_SET_MODE_FILTER as u64,
                    libc::SECCOMP_FILTER_FLAG_TSYNC,
                    scratch,
                    0,
                    0,
                    0,
                ],
            )?;
            if result != 0 {
                return Err("mapped_filter_tsync_did_not_install".into());
            }
            // checked_syscall observed the completed syscall and exact INT3.
            // No new child syscall is needed to restore bytes/registers.
            self.filter_installed = true;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Restore entry bytes/registers; a poisoned transaction cannot finish.
    pub fn finish(mut self) -> Result<(Stopped, Vec<InjectedCall>)> {
        if self.poisoned {
            return Err("loader refused: poisoned injection transaction".into());
        }
        let mut task = self.task.take().ok_or("lost stopped owner")?;
        write(&mut task, self.entry.rip, &self.original)?;
        if read(&task, self.entry.rip, self.original.len())? != self.original {
            return Err("loader refused: original entry bytes did not restore".into());
        }
        task.setregs(&self.entry)?;
        Ok((task, self.calls))
    }
}
