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

use reverie_loader::artifact::TOOL_REGION;
use reverie_loader::image::PAGE_SIZE;
use reverie_loader::image::ValidatedImage;
use reverie_memory::Addr;
use reverie_memory::AddrMut;
use reverie_memory::MemoryAccess;
use safeptrace::Event;
use safeptrace::Regs;
use safeptrace::Running;
use safeptrace::Signal;
use safeptrace::Stopped;
use safeptrace::Wait;

use super::Result;

pub fn wait(running: Running) -> Result<Wait> {
    Ok(running.wait_sync_on_ptracer_thread().wait()?)
}

pub fn stopped(running: Running, expected: &str) -> Result<(Stopped, Event)> {
    match wait(running)? {
        Wait::Stopped(task, event) => Ok((task, event)),
        other => Err(format!("loader refused: expected {expected}, got {other:?}").into()),
    }
}

pub fn read(task: &Stopped, address: u64, length: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; length];
    task.read_exact(
        Addr::from_raw(address as usize).ok_or("null remote address")?,
        &mut bytes,
    )?;
    Ok(bytes)
}

pub fn write(task: &mut Stopped, address: u64, bytes: &[u8]) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let cursor = address
            .checked_add(offset as u64)
            .ok_or("remote write overflow")?;
        let aligned = cursor & !7;
        let first = (cursor - aligned) as usize;
        let count = (8 - first).min(bytes.len() - offset);
        let mut word = read(task, aligned, 8)?;
        word[first..first + count].copy_from_slice(&bytes[offset..offset + count]);
        // An exact eight-byte safeptrace write uses POKEDATA. Larger writes
        // use process_vm_writev, which correctly refuses an RX page. The
        // stopped mapping transaction needs private-page writes, not W+X.
        task.write_exact(
            AddrMut::from_raw(aligned as usize).ok_or("null remote address")?,
            &word,
        )?;
        offset += count;
    }
    Ok(())
}

/// Injected syscall number, six arguments, and the observed return value.
pub type InjectedCall = (u64, [u64; 6], u64);

pub struct Injector {
    task: Option<Stopped>,
    entry: Regs,
    original: Vec<u8>,
    reservation: bool,
    pub calls: Vec<InjectedCall>,
}

impl Injector {
    pub fn new(mut task: Stopped, entry: Regs) -> Result<Self> {
        let original = read(&task, entry.rip, 8)?;
        let mut injected = original.clone();
        injected[..3].copy_from_slice(&[0x0f, 0x05, 0xcc]);
        write(&mut task, entry.rip, &injected)?;
        Ok(Self {
            task: Some(task),
            entry,
            original,
            reservation: false,
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
    pub fn stopped_mut(&mut self) -> Result<&mut Stopped> {
        self.task
            .as_mut()
            .ok_or_else(|| "lost stopped injection owner".into())
    }

    pub fn syscall(&mut self, number: u64, args: [u64; 6]) -> Result<u64> {
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

    pub fn reserve(&mut self) -> Result<()> {
        let actual = self
            .syscall(
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

    pub fn map(
        &mut self,
        start: u64,
        length: u64,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: u64,
    ) -> Result<()> {
        self.owned(start, length)?;
        if protection & libc::PROT_WRITE != 0 && protection & libc::PROT_EXEC != 0 {
            return Err("loader refused: writable executable mapping".into());
        }
        let actual = self.syscall(
            libc::SYS_mmap as u64,
            [
                start,
                length,
                protection as u64,
                (flags | libc::MAP_FIXED) as u64,
                fd as u64,
                offset,
            ],
        )?;
        if actual != start {
            return Err("loader refused: mapping returned the wrong address".into());
        }
        Ok(())
    }

    pub fn map_image(&mut self, image: &ValidatedImage<'_>, fd: i32) -> Result<()> {
        for segment in image.segments() {
            let pages = segment.pages().map_err(|e| format!("segment: {e:?}"))?;
            let permissions = segment.permissions;
            let protection = (if permissions.read { libc::PROT_READ } else { 0 })
                | (if permissions.write {
                    libc::PROT_WRITE
                } else {
                    0
                })
                | (if permissions.execute {
                    libc::PROT_EXEC
                } else {
                    0
                });
            let file_bytes = segment.file.end - segment.file.start;
            let file_pages = file_bytes.div_ceil(PAGE_SIZE) * PAGE_SIZE;
            if file_pages != 0 {
                self.map(
                    pages.start,
                    file_pages,
                    protection,
                    libc::MAP_PRIVATE,
                    fd,
                    segment.file.start,
                )?;
            }
            let memory_pages = pages.end - pages.start;
            if memory_pages > file_pages {
                self.map(
                    pages.start + file_pages,
                    memory_pages - file_pages,
                    protection,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )?;
            }
            // Kernel file mappings expose a whole final page. The ELF contract
            // requires zero after p_filesz; use ptrace's private-page write
            // while stopped, without ever granting W to executable mappings.
            if file_bytes != file_pages {
                let zeros = vec![0; (file_pages - file_bytes) as usize];
                write(
                    self.task.as_mut().ok_or("lost stopped owner")?,
                    pages.start + file_bytes,
                    &zeros,
                )?;
            }
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(Stopped, Vec<InjectedCall>)> {
        let mut task = self.task.take().ok_or("lost stopped owner")?;
        write(&mut task, self.entry.rip, &self.original)?;
        if read(&task, self.entry.rip, self.original.len())? != self.original {
            return Err("loader refused: original entry bytes did not restore".into());
        }
        task.setregs(&self.entry)?;
        Ok((task, self.calls))
    }
}
