// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the LICENSE file.

//! Internal observation primitives; no public production resume capability.
use reverie_memory::Addr;
#[cfg(feature = "stage1a-probe")]
use reverie_memory::AddrMut;
use reverie_memory::MemoryAccess;
use safeptrace::Event;
use safeptrace::Running;
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

#[cfg(feature = "stage1a-probe")]
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
